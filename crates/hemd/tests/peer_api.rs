use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chrono::Utc;
use hem_core::{
    envelope_decrypt_for_node, peer_transport_auth_statement_bytes, ClusterConfig,
    EnvelopeEncryptedValue, HemStore, IssueOfflineLeaseInput, LedgerOperationInput, NodeIdentity,
    PeerConfig, SecretPolicyTier, SecretScope as CoreSecretScope,
};
use serde_json::json;
use tokio::time::sleep;
use tonic::{transport::Endpoint, Code, Request};

pub mod proto {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("valhall.hem.v1");
}

use proto::{
    get_secret_request, get_secret_response, hem_runtime_client::HemRuntimeClient,
    AddToGroupRequest, DeleteSecretRequest, ExportSecretsRequest, GetSecretRequest, HealthRequest,
    ImportSecretsRequest, InitHemRequest, IssueServiceTokenRequest, PeerAckOperationsRequest,
    PeerHelloRequest, PeerListOperationsRequest, RemoveFromGroupRequest, ResolveApprovalRequest,
    RevokeAccessRequest, RotateMasterKeyRequest, ScopeSelector, SecretRef, SecretScope,
    SecretValue, SetGroupRequest, SetSecretRequest,
};

struct TestDaemon {
    child: Child,
    endpoint: String,
}

impl TestDaemon {
    async fn start(data_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_env(data_dir, &[]).await
    }

    async fn start_with_env(
        data_dir: &Path,
        envs: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);

        let bind = addr.to_string();
        let endpoint = format!("http://{bind}");

        let mut command = Command::new(env!("CARGO_BIN_EXE_hemd"));
        command
            .arg("--bind")
            .arg(bind)
            .arg("--data-dir")
            .arg(data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in envs {
            command.env(key, value);
        }
        let child = command.spawn()?;

        let daemon = Self { child, endpoint };
        daemon.wait_until_ready().await?;
        Ok(daemon)
    }

    async fn wait_until_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        let started = Instant::now();
        loop {
            if started.elapsed() > Duration::from_secs(10) {
                return Err("hemd did not become ready within timeout".into());
            }
            if let Ok(mut client) = connect_client(self.endpoint.as_str()).await {
                if client.health(HealthRequest {}).await.is_ok() {
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(75)).await;
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn connect_client(
    endpoint: &str,
) -> Result<HemRuntimeClient<tonic::transport::Channel>, Box<dyn std::error::Error>> {
    let channel = Endpoint::from_shared(endpoint.to_string())?
        .connect()
        .await?;
    Ok(HemRuntimeClient::new(channel))
}

fn authorized<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn signed_peer_request<T>(
    message: T,
    identity: &NodeIdentity,
    cluster_id: &str,
    method: &str,
    nonce: &str,
    timestamp_unix: i64,
) -> Request<T> {
    signed_peer_request_with_node_id(
        message,
        identity,
        identity.node_id.as_str(),
        cluster_id,
        method,
        nonce,
        timestamp_unix,
    )
}

fn signed_peer_request_with_node_id<T>(
    message: T,
    signer: &NodeIdentity,
    asserted_node_id: &str,
    cluster_id: &str,
    method: &str,
    nonce: &str,
    timestamp_unix: i64,
) -> Request<T> {
    let statement = peer_transport_auth_statement_bytes(
        cluster_id,
        asserted_node_id,
        method,
        nonce,
        timestamp_unix,
    )
    .expect("serialize peer auth statement");
    let signature = signer
        .sign_statement(statement.as_slice())
        .expect("sign peer auth statement");

    let mut request = Request::new(message);
    let metadata = request.metadata_mut();
    metadata.insert("x-hem-peer-cluster-id", cluster_id.parse().unwrap());
    metadata.insert("x-hem-peer-node-id", asserted_node_id.parse().unwrap());
    metadata.insert("x-hem-peer-method", method.parse().unwrap());
    metadata.insert("x-hem-peer-nonce", nonce.parse().unwrap());
    metadata.insert(
        "x-hem-peer-timestamp",
        timestamp_unix.to_string().parse().unwrap(),
    );
    metadata.insert("x-hem-peer-signature", signature.parse().unwrap());
    request
}

fn proto_global_scope() -> ScopeSelector {
    ScopeSelector {
        scope: SecretScope::Global as i32,
        project: String::new(),
        identity_id: String::new(),
    }
}

fn proto_secret_ref(name: &str) -> SecretRef {
    SecretRef {
        scope: Some(proto_global_scope()),
        name: name.to_string(),
    }
}

#[tokio::test]
async fn peer_api_reports_cluster_and_lists_signed_operations() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    HemStore::init(data_dir.path(), false).expect("init store");
    let identity = NodeIdentity::generate("hmn_local", "local").expect("identity");
    let config = ClusterConfig {
        enabled: true,
        cluster_id: "hmc_test".to_string(),
        node_id: "hmn_local".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 1,
        master_node_id: Some("hmn_local".to_string()),
        peers: Vec::new(),
    };
    config
        .save(&data_dir.path().join("cluster.toml"))
        .expect("save config");
    identity
        .save(&data_dir.path().join("node-identity.json"))
        .expect("save identity");

    let store = HemStore::open(data_dir.path()).expect("open store");
    let ledger = store.ledger_store().expect("ledger");
    let envelope = ledger
        .sign_next(
            &identity,
            LedgerOperationInput {
                operation_id: "hop_peer_a".to_string(),
                cluster_id: "hmc_test".to_string(),
                node_id: "hmn_local".to_string(),
                node_seq: 1,
                op_type: "secret.metadata.set".to_string(),
                payload_json: json!({
                    "scope": "global",
                    "name": "demo",
                    "description": "peer api",
                    "requires_approval": false,
                    "actor": "test",
                }),
                created_at: Utc::now(),
            },
        )
        .expect("sign");
    ledger.append_signed(&envelope).expect("append");
    let envelope_b = ledger
        .sign_next(
            &identity,
            LedgerOperationInput {
                operation_id: "hop_peer_b".to_string(),
                cluster_id: "hmc_test".to_string(),
                node_id: "hmn_local".to_string(),
                node_seq: 2,
                op_type: "secret.metadata.set".to_string(),
                payload_json: json!({
                    "scope": "global",
                    "name": "demo-b",
                    "description": "peer api b",
                    "requires_approval": false,
                    "actor": "test",
                }),
                created_at: Utc::now(),
            },
        )
        .expect("sign b");
    ledger.append_signed(&envelope_b).expect("append b");

    let daemon = TestDaemon::start(data_dir.path()).await.expect("daemon");
    let mut client = connect_client(daemon.endpoint.as_str())
        .await
        .expect("connect");

    let hello = client
        .peer_hello(PeerHelloRequest {
            cluster_id: "hmc_test".to_string(),
            node_id: "hmn_peer".to_string(),
            public_key: "peer-public-key".to_string(),
        })
        .await
        .expect("peer hello")
        .into_inner();
    assert!(hello.accepted);
    assert_eq!(hello.cluster_id, "hmc_test");
    assert_eq!(hello.node_id, "hmn_local");
    assert_eq!(hello.latest_position, 2);
    assert_eq!(hello.latest_body_hash_b64, envelope_b.body_hash_b64);

    let operations = client
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await
        .expect("list operations")
        .into_inner();
    assert_eq!(operations.latest_position, 2);
    assert_eq!(operations.operations.len(), 2);
    assert_eq!(
        operations.operations[0]
            .body
            .as_ref()
            .expect("operation body")
            .operation_id,
        "hop_peer_a"
    );
    assert_eq!(
        operations.operations[0].body_hash_b64,
        envelope.body_hash_b64
    );

    let cursor_batch = client
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 1,
            peer_node_id: "hmn_peer".to_string(),
            use_recorded_cursor: true,
        })
        .await
        .expect("cursor list")
        .into_inner();
    assert_eq!(cursor_batch.operations.len(), 1);
    assert_eq!(
        cursor_batch.operations[0].body_hash_b64,
        envelope.body_hash_b64
    );

    let ack = client
        .peer_ack_operations(PeerAckOperationsRequest {
            peer_node_id: "hmn_peer".to_string(),
            position: 1,
            body_hash_b64: envelope.body_hash_b64.clone(),
        })
        .await
        .expect("ack")
        .into_inner();
    assert!(ack.recorded);
    assert_eq!(ack.next_position, 2);

    let catch_up = client
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: "hmn_peer".to_string(),
            use_recorded_cursor: true,
        })
        .await
        .expect("catch up")
        .into_inner();
    assert_eq!(catch_up.operations.len(), 1);
    assert_eq!(
        catch_up.operations[0].body_hash_b64,
        envelope_b.body_hash_b64
    );
}

#[tokio::test]
async fn peer_transport_auth_rejects_unknown_wrong_key_and_replayed_nonce() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    HemStore::init(data_dir.path(), false).expect("init store");
    let local = NodeIdentity::generate("hmn_local", "local").expect("local identity");
    let peer = NodeIdentity::generate("hmn_peer", "peer").expect("peer identity");
    let wrong = NodeIdentity::generate("hmn_wrong", "wrong").expect("wrong identity");
    ClusterConfig {
        enabled: true,
        cluster_id: "hmc_auth".to_string(),
        node_id: "hmn_local".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 2,
        master_node_id: Some("hmn_local".to_string()),
        peers: vec![PeerConfig {
            node_id: peer.node_id.clone(),
            endpoint: "http://127.0.0.1:1".to_string(),
            public_key: peer.signing_public_key_b64.clone(),
            wrap_public_key: peer.wrap_public_key_b64.clone(),
        }],
    }
    .save(&data_dir.path().join("cluster.toml"))
    .expect("save config");
    local
        .save(&data_dir.path().join("node-identity.json"))
        .expect("save identity");

    let daemon = TestDaemon::start(data_dir.path()).await.expect("daemon");
    let mut client = connect_client(daemon.endpoint.as_str())
        .await
        .expect("connect");

    let unauthenticated = client
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: peer.node_id.clone(),
            use_recorded_cursor: false,
        })
        .await
        .expect_err("unsigned peer list must fail");
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);

    let unknown_peer = signed_peer_request(
        PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: wrong.node_id.clone(),
            use_recorded_cursor: false,
        },
        &wrong,
        "hmc_auth",
        "PeerListOperations",
        "nonce-unknown-peer",
        Utc::now().timestamp(),
    );
    let unknown_rejected = client
        .peer_list_operations(unknown_peer)
        .await
        .expect_err("unknown peer must fail");
    assert_eq!(unknown_rejected.code(), Code::Unauthenticated);

    let valid = signed_peer_request(
        PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: peer.node_id.clone(),
            use_recorded_cursor: false,
        },
        &peer,
        "hmc_auth",
        "PeerListOperations",
        "nonce-valid",
        Utc::now().timestamp(),
    );
    let response = client
        .peer_list_operations(valid)
        .await
        .expect("signed peer list");
    assert_eq!(response.into_inner().latest_position, 0);

    let replay = signed_peer_request(
        PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: peer.node_id.clone(),
            use_recorded_cursor: false,
        },
        &peer,
        "hmc_auth",
        "PeerListOperations",
        "nonce-valid",
        Utc::now().timestamp(),
    );
    let replayed = client
        .peer_list_operations(replay)
        .await
        .expect_err("replayed nonce must fail");
    assert_eq!(replayed.code(), Code::Unauthenticated);

    let stale = signed_peer_request(
        PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: peer.node_id.clone(),
            use_recorded_cursor: false,
        },
        &peer,
        "hmc_auth",
        "PeerListOperations",
        "nonce-stale",
        Utc::now().timestamp() - 600,
    );
    let stale_rejected = client
        .peer_list_operations(stale)
        .await
        .expect_err("stale timestamp must fail");
    assert_eq!(stale_rejected.code(), Code::Unauthenticated);

    let wrong_key = signed_peer_request_with_node_id(
        PeerListOperationsRequest {
            after_position: 0,
            limit: 10,
            peer_node_id: peer.node_id.clone(),
            use_recorded_cursor: false,
        },
        &wrong,
        peer.node_id.as_str(),
        "hmc_auth",
        "PeerListOperations",
        "nonce-wrong-key",
        Utc::now().timestamp(),
    );
    let rejected = client
        .peer_list_operations(wrong_key)
        .await
        .expect_err("wrong key must fail");
    assert_eq!(rejected.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn read_receipts_survive_restart_and_are_listed_for_replication(
) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = tempfile::tempdir()?;
    let identity = NodeIdentity::generate("hmn_local", "local")?;
    let config = ClusterConfig {
        enabled: true,
        cluster_id: "hmc_read_receipts".to_string(),
        node_id: "hmn_local".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 1,
        master_node_id: Some("hmn_local".to_string()),
        peers: Vec::new(),
    };
    config.save(&data_dir.path().join("cluster.toml"))?;
    identity.save(&data_dir.path().join("node-identity.json"))?;

    let daemon = TestDaemon::start(data_dir.path()).await?;
    let mut client = connect_client(daemon.endpoint.as_str()).await?;
    let init = client
        .init_hem(InitHemRequest { force: false })
        .await?
        .into_inner();
    client
        .set_secret(authorized(
            init.operator_token.as_str(),
            SetSecretRequest {
                secret: Some(proto_secret_ref("read-receipt-demo")),
                values: vec![SecretValue {
                    key: "api_key".to_string(),
                    value: "super-secret-read-value".to_string(),
                }],
                description: String::new(),
                requires_approval: false,
                group: String::new(),
                actor: "receipt-test".to_string(),
                approval_receipt: String::new(),
                reason: String::new(),
            },
        ))
        .await?;
    let read = client
        .get_secret(authorized(
            init.operator_token.as_str(),
            GetSecretRequest {
                lookup: Some(get_secret_request::Lookup::Secret(proto_secret_ref(
                    "read-receipt-demo",
                ))),
                context: None,
                key: "api_key".to_string(),
                async_read: false,
                wait_timeout_ms: 0,
                reason: String::new(),
                approval_receipt: String::new(),
            },
        ))
        .await?
        .into_inner();
    match read.result {
        Some(get_secret_response::Result::Secret(secret)) => {
            assert_eq!(
                secret.values.get("api_key").map(String::as_str),
                Some("super-secret-read-value")
            );
        }
        _ => panic!("expected secret read"),
    }
    drop(client);
    drop(daemon);

    let restarted = TestDaemon::start(data_dir.path()).await?;
    let mut peer = connect_client(restarted.endpoint.as_str()).await?;
    let operations = peer
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 100,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner();

    let mut requested_payload = None;
    let mut fulfilled_payload = None;
    for operation in operations.operations {
        let body = operation.body.as_ref().expect("operation body");
        match body.op_type.as_str() {
            "read.requested" => {
                assert!(!operation.signature_b64.trim().is_empty());
                assert!(!body.payload_json.contains("super-secret-read-value"));
                requested_payload = Some(body.payload_json.clone());
            }
            "read.fulfilled" => {
                assert!(!operation.signature_b64.trim().is_empty());
                assert!(!body.payload_json.contains("super-secret-read-value"));
                fulfilled_payload = Some(body.payload_json.clone());
            }
            _ => {}
        }
    }
    let requested_payload = requested_payload.expect("read.requested operation");
    assert!(requested_payload.contains("\"secret_name\":\"read-receipt-demo\""));
    assert!(requested_payload.contains("\"keys\":[\"api_key\"]"));
    assert!(requested_payload.contains("\"policy_decision\":\"local_logged\""));
    let fulfilled_payload = fulfilled_payload.expect("read.fulfilled operation");
    assert!(fulfilled_payload.contains("\"read_request_operation_id\""));
    assert!(fulfilled_payload.contains("\"released_key_count\":1"));
    Ok(())
}

#[tokio::test]
async fn offline_read_policies_fail_closed_or_consume_leases(
) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = tempfile::tempdir()?;
    let identity = NodeIdentity::generate("hmn_local", "local")?;
    let config = ClusterConfig {
        enabled: true,
        cluster_id: "hmc_offline_policies".to_string(),
        node_id: "hmn_local".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 1,
        master_node_id: Some("hmn_local".to_string()),
        peers: Vec::new(),
    };
    config.save(&data_dir.path().join("cluster.toml"))?;
    identity.save(&data_dir.path().join("node-identity.json"))?;

    let daemon =
        TestDaemon::start_with_env(data_dir.path(), &[("VALHALL_HEM_FORCE_OFFLINE", "1")]).await?;
    let mut client = connect_client(daemon.endpoint.as_str()).await?;
    let init = client
        .init_hem(InitHemRequest { force: false })
        .await?
        .into_inner();
    let issued = client
        .issue_service_token(authorized(
            init.operator_token.as_str(),
            IssueServiceTokenRequest {
                service_name: "offline-test".to_string(),
                ttl_seconds: 0,
                issued_by: "itest".to_string(),
            },
        ))
        .await?
        .into_inner();
    let service_token = issued.token;
    let requester = format!(
        "token:{}",
        issued.info.as_ref().expect("token info").token_id.as_str()
    );

    for name in ["low-local", "medium-lease", "high-quorum", "highest-master"] {
        client
            .set_secret(authorized(
                init.operator_token.as_str(),
                SetSecretRequest {
                    secret: Some(proto_secret_ref(name)),
                    values: vec![SecretValue {
                        key: "api_key".to_string(),
                        value: format!("{name}-value"),
                    }],
                    description: String::new(),
                    requires_approval: false,
                    group: String::new(),
                    actor: "policy-test".to_string(),
                    approval_receipt: String::new(),
                    reason: String::new(),
                },
            ))
            .await?;
    }

    let store = HemStore::open(data_dir.path())?;
    let policies = store.policy_store()?;
    let global = hem_core::SecretScope::Global;
    policies.set_default_policy(SecretPolicyTier::LocalLogged)?;
    policies.set_secret_policy(&global, "medium-lease", SecretPolicyTier::OfflineLease)?;
    policies.set_secret_policy(&global, "high-quorum", SecretPolicyTier::PeerQuorum)?;
    policies.set_secret_policy(&global, "highest-master", SecretPolicyTier::MasterBiometric)?;
    let lease = policies.issue_offline_lease(IssueOfflineLeaseInput {
        scope: global,
        name: "medium-lease".to_string(),
        requester,
        node_id: "hmn_local".to_string(),
        max_uses: 1,
        ttl_seconds: 60,
    })?;
    assert_eq!(lease.remaining_uses, 1);

    assert_eq!(
        read_api_key(&mut client, service_token.as_str(), "low-local").await?,
        "low-local-value"
    );
    assert_eq!(
        read_api_key(&mut client, service_token.as_str(), "medium-lease").await?,
        "medium-lease-value"
    );
    let medium_again = read_api_key(&mut client, service_token.as_str(), "medium-lease")
        .await
        .expect_err("lease use should be consumed");
    assert_eq!(medium_again.code(), Code::FailedPrecondition);

    let high = read_api_key(&mut client, service_token.as_str(), "high-quorum")
        .await
        .expect_err("peer quorum must fail offline");
    assert_eq!(high.code(), Code::FailedPrecondition);
    assert!(high.message().contains("peer_quorum"));

    let highest = read_api_key(&mut client, service_token.as_str(), "highest-master")
        .await
        .expect_err("master policy must fail offline");
    assert_eq!(highest.code(), Code::FailedPrecondition);
    assert!(highest.message().contains("master_biometric"));
    Ok(())
}

#[tokio::test]
async fn peer_quorum_policy_requires_signed_online_peer_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let local_dir = tempfile::tempdir()?;
    let peer_dir = tempfile::tempdir()?;
    let cluster_id = "hmc_peer_quorum_policy";
    let local_identity = NodeIdentity::generate("hmn_local", "local")?;
    let peer_identity = NodeIdentity::generate("hmn_peer", "peer")?;

    HemStore::init(peer_dir.path(), false)?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: peer_identity.node_id.clone(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 2,
        master_node_id: Some(local_identity.node_id.clone()),
        peers: vec![PeerConfig {
            node_id: local_identity.node_id.clone(),
            endpoint: "http://127.0.0.1:0".to_string(),
            public_key: local_identity.signing_public_key_b64.clone(),
            wrap_public_key: local_identity.wrap_public_key_b64.clone(),
        }],
    }
    .save(&peer_dir.path().join("cluster.toml"))?;
    peer_identity.save(&peer_dir.path().join("node-identity.json"))?;
    let peer_daemon =
        TestDaemon::start_with_env(peer_dir.path(), &[("VALHALL_HEM_CLUSTER_SYNC", "0")]).await?;

    HemStore::init(local_dir.path(), false)?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: local_identity.node_id.clone(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 2,
        master_node_id: Some(local_identity.node_id.clone()),
        peers: vec![PeerConfig {
            node_id: peer_identity.node_id.clone(),
            endpoint: peer_daemon.endpoint.clone(),
            public_key: peer_identity.signing_public_key_b64.clone(),
            wrap_public_key: peer_identity.wrap_public_key_b64.clone(),
        }],
    }
    .save(&local_dir.path().join("cluster.toml"))?;
    local_identity.save(&local_dir.path().join("node-identity.json"))?;
    let local_daemon =
        TestDaemon::start_with_env(local_dir.path(), &[("VALHALL_HEM_CLUSTER_SYNC", "0")]).await?;
    let mut client = connect_client(local_daemon.endpoint.as_str()).await?;
    let operator_token = HemStore::open(local_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;
    let service = client
        .issue_service_token(authorized(
            operator_token.as_str(),
            IssueServiceTokenRequest {
                service_name: "quorum-reader".to_string(),
                ttl_seconds: 0,
                issued_by: "itest".to_string(),
            },
        ))
        .await?
        .into_inner();

    client
        .set_secret(authorized(
            operator_token.as_str(),
            SetSecretRequest {
                secret: Some(proto_secret_ref("quorum-demo")),
                values: vec![SecretValue {
                    key: "api_key".to_string(),
                    value: "quorum-value".to_string(),
                }],
                description: String::new(),
                requires_approval: false,
                group: String::new(),
                actor: "quorum-test".to_string(),
                approval_receipt: String::new(),
                reason: String::new(),
            },
        ))
        .await?;
    HemStore::open(local_dir.path())?
        .policy_store()?
        .set_secret_policy(
            &CoreSecretScope::Global,
            "quorum-demo",
            SecretPolicyTier::PeerQuorum,
        )?;

    assert_eq!(
        read_api_key(&mut client, service.token.as_str(), "quorum-demo").await?,
        "quorum-value"
    );

    let fulfilled_payload = read_fulfilled_payload_for(local_dir.path(), "quorum-demo")?;
    assert_eq!(fulfilled_payload["policy_decision"], "peer_quorum");
    let evidence: serde_json::Value = serde_json::from_str(
        fulfilled_payload["approval_reference"]
            .as_str()
            .expect("approval reference"),
    )?;
    assert_eq!(evidence["kind"], "peer_quorum_v1");
    assert_eq!(evidence["required_peer_acks"], 1);
    let accepted = evidence["accepted"].as_array().expect("accepted array");
    assert_eq!(accepted.len(), 1);
    assert_eq!(
        accepted[0]["peer_node_id"].as_str(),
        Some(peer_identity.node_id.as_str())
    );
    assert_eq!(
        accepted[0]["statement"]["approver_node_id"].as_str(),
        Some(peer_identity.node_id.as_str())
    );
    assert!(!accepted[0]["signature_b64"]
        .as_str()
        .expect("signature")
        .is_empty());
    let report = HemStore::open(local_dir.path())?
        .ledger_store()?
        .verify_integrity()?;
    assert!(report.ok, "ledger report: {report:?}");

    drop(peer_daemon);
    let offline = read_api_key(&mut client, service.token.as_str(), "quorum-demo")
        .await
        .expect_err("peer quorum must fail without reachable peer");
    assert_eq!(offline.code(), Code::FailedPrecondition);
    assert!(offline.message().contains("peer_quorum"));
    assert!(offline.message().contains("reachable peer approval"));
    Ok(())
}

#[tokio::test]
async fn peer_quorum_policy_rejects_invalid_peer_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let local_dir = tempfile::tempdir()?;
    let wrong_peer_dir = tempfile::tempdir()?;
    let cluster_id = "hmc_peer_quorum_invalid";
    let local_identity = NodeIdentity::generate("hmn_local", "local")?;
    let expected_peer_identity = NodeIdentity::generate("hmn_peer", "expected peer")?;
    let wrong_peer_identity = NodeIdentity::generate("hmn_wrong", "wrong peer")?;

    HemStore::init(wrong_peer_dir.path(), false)?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: wrong_peer_identity.node_id.clone(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 2,
        master_node_id: Some(local_identity.node_id.clone()),
        peers: vec![PeerConfig {
            node_id: local_identity.node_id.clone(),
            endpoint: "http://127.0.0.1:0".to_string(),
            public_key: local_identity.signing_public_key_b64.clone(),
            wrap_public_key: local_identity.wrap_public_key_b64.clone(),
        }],
    }
    .save(&wrong_peer_dir.path().join("cluster.toml"))?;
    wrong_peer_identity.save(&wrong_peer_dir.path().join("node-identity.json"))?;
    let wrong_peer_daemon =
        TestDaemon::start_with_env(wrong_peer_dir.path(), &[("VALHALL_HEM_CLUSTER_SYNC", "0")])
            .await?;

    HemStore::init(local_dir.path(), false)?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: local_identity.node_id.clone(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 2,
        master_node_id: Some(local_identity.node_id.clone()),
        peers: vec![PeerConfig {
            node_id: expected_peer_identity.node_id.clone(),
            endpoint: wrong_peer_daemon.endpoint.clone(),
            public_key: wrong_peer_identity.signing_public_key_b64.clone(),
            wrap_public_key: wrong_peer_identity.wrap_public_key_b64.clone(),
        }],
    }
    .save(&local_dir.path().join("cluster.toml"))?;
    local_identity.save(&local_dir.path().join("node-identity.json"))?;
    let local_daemon =
        TestDaemon::start_with_env(local_dir.path(), &[("VALHALL_HEM_CLUSTER_SYNC", "0")]).await?;
    let mut client = connect_client(local_daemon.endpoint.as_str()).await?;
    let operator_token = HemStore::open(local_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;
    let service = client
        .issue_service_token(authorized(
            operator_token.as_str(),
            IssueServiceTokenRequest {
                service_name: "invalid-quorum-reader".to_string(),
                ttl_seconds: 0,
                issued_by: "itest".to_string(),
            },
        ))
        .await?
        .into_inner();
    client
        .set_secret(authorized(
            operator_token.as_str(),
            SetSecretRequest {
                secret: Some(proto_secret_ref("invalid-quorum-demo")),
                values: vec![SecretValue {
                    key: "api_key".to_string(),
                    value: "invalid-quorum-value".to_string(),
                }],
                description: String::new(),
                requires_approval: false,
                group: String::new(),
                actor: "quorum-test".to_string(),
                approval_receipt: String::new(),
                reason: String::new(),
            },
        ))
        .await?;
    HemStore::open(local_dir.path())?
        .policy_store()?
        .set_secret_policy(
            &CoreSecretScope::Global,
            "invalid-quorum-demo",
            SecretPolicyTier::PeerQuorum,
        )?;

    let err = read_api_key(&mut client, service.token.as_str(), "invalid-quorum-demo")
        .await
        .expect_err("invalid peer identity must fail quorum");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("node_id mismatch"));
    Ok(())
}

#[tokio::test]
async fn clustered_daemon_mutations_append_signed_ledger_operations(
) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = tempfile::tempdir()?;
    HemStore::init(data_dir.path(), false)?;
    let identity = NodeIdentity::generate("hmn_live", "live").expect("identity");
    let peer_identity = NodeIdentity::generate("hmn_peer", "peer").expect("peer identity");
    let unauthorized_identity =
        NodeIdentity::generate("hmn_blocked", "blocked").expect("blocked identity");
    ClusterConfig {
        enabled: true,
        cluster_id: "hmc_live_mutations".to_string(),
        node_id: "hmn_live".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 1,
        master_node_id: Some("hmn_live".to_string()),
        peers: vec![PeerConfig {
            node_id: peer_identity.node_id.clone(),
            endpoint: "http://127.0.0.1:59999".to_string(),
            public_key: peer_identity.signing_public_key_b64.clone(),
            wrap_public_key: peer_identity.wrap_public_key_b64.clone(),
        }],
    }
    .save(&data_dir.path().join("cluster.toml"))?;
    identity.save(&data_dir.path().join("node-identity.json"))?;

    let daemon =
        TestDaemon::start_with_env(data_dir.path(), &[("VALHALL_HEM_CLUSTER_SYNC", "0")]).await?;
    let mut client = connect_client(daemon.endpoint.as_str()).await?;
    let operator_token = HemStore::open(data_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;

    client
        .set_secret(authorized(
            operator_token.as_str(),
            SetSecretRequest {
                secret: Some(proto_secret_ref("live-secret")),
                values: vec![SecretValue {
                    key: "api_key".to_string(),
                    value: "live-value".to_string(),
                }],
                description: "live mutation".to_string(),
                requires_approval: false,
                group: String::new(),
                actor: "itest".to_string(),
                approval_receipt: String::new(),
                reason: String::new(),
            },
        ))
        .await?;
    assert_operation_count(data_dir.path(), "secret.metadata.set", 1)?;
    assert_operation_count(data_dir.path(), "secret.value.set", 1)?;
    let envelope = ledger_envelope_for_key(data_dir.path(), "live-secret", "api_key")?;
    let peer_plain = envelope_decrypt_for_node(
        &envelope,
        b"global:live-secret:api_key",
        peer_identity.node_id.as_str(),
        peer_identity
            .wrap_private_key_b64
            .as_deref()
            .expect("peer wrap private"),
    )?;
    assert_eq!(peer_plain, "live-value");
    assert!(envelope_decrypt_for_node(
        &envelope,
        b"global:live-secret:api_key",
        unauthorized_identity.node_id.as_str(),
        unauthorized_identity
            .wrap_private_key_b64
            .as_deref()
            .expect("unauthorized wrap private"),
    )
    .is_err());

    client
        .set_group(authorized(
            operator_token.as_str(),
            SetGroupRequest {
                name: "ops".to_string(),
                description: "operations".to_string(),
            },
        ))
        .await?;
    client
        .add_to_group(authorized(
            operator_token.as_str(),
            AddToGroupRequest {
                secret: Some(proto_secret_ref("live-secret")),
                group: "ops".to_string(),
            },
        ))
        .await?;
    client
        .remove_from_group(authorized(
            operator_token.as_str(),
            RemoveFromGroupRequest {
                secret: Some(proto_secret_ref("live-secret")),
            },
        ))
        .await?;
    assert_operation_count(data_dir.path(), "group.set", 1)?;
    assert_operation_count(data_dir.path(), "secret.metadata.set", 3)?;

    client
        .grant_access(authorized(
            operator_token.as_str(),
            proto::GrantAccessRequest {
                secret: Some(proto_secret_ref("live-secret")),
                grantee_scope: Some(proto_global_scope()),
                grantee_id: "smi".to_string(),
                actor: "itest".to_string(),
            },
        ))
        .await?;
    client
        .revoke_access(authorized(
            operator_token.as_str(),
            RevokeAccessRequest {
                secret: Some(proto_secret_ref("live-secret")),
                grantee_scope: Some(proto_global_scope()),
                grantee_id: "smi".to_string(),
                actor: "itest".to_string(),
            },
        ))
        .await?;
    assert_operation_count(data_dir.path(), "grant.access", 1)?;
    assert_operation_count(data_dir.path(), "grant.revoked", 1)?;

    let bundle = client
        .export_secrets(authorized(
            operator_token.as_str(),
            ExportSecretsRequest { scope: None },
        ))
        .await?
        .into_inner()
        .encrypted_bundle;
    HemStore::open(data_dir.path())?.delete_secret(&CoreSecretScope::Global, "live-secret")?;
    client
        .import_secrets(authorized(
            operator_token.as_str(),
            ImportSecretsRequest {
                encrypted_bundle: bundle,
                merge: false,
                actor: "itest".to_string(),
            },
        ))
        .await?;
    assert_operation_count(data_dir.path(), "secrets.imported", 1)?;

    let pending_delete = client
        .delete_secret(authorized(
            operator_token.as_str(),
            DeleteSecretRequest {
                secret: Some(proto_secret_ref("live-secret")),
                actor: "itest".to_string(),
                approval_receipt: String::new(),
                reason: "test delete".to_string(),
            },
        ))
        .await?
        .into_inner();
    let approved = client
        .approve_access(authorized(
            operator_token.as_str(),
            ResolveApprovalRequest {
                request_id: pending_delete.approval_request_id,
                actor: "itest".to_string(),
                message: "approved".to_string(),
            },
        ))
        .await?
        .into_inner();
    client
        .delete_secret(authorized(
            operator_token.as_str(),
            DeleteSecretRequest {
                secret: Some(proto_secret_ref("live-secret")),
                actor: "itest".to_string(),
                approval_receipt: approved.approval_receipt,
                reason: "test delete approved".to_string(),
            },
        ))
        .await?;
    assert_operation_count(data_dir.path(), "secret.deleted", 1)?;

    client
        .rotate_master_key(authorized(
            operator_token.as_str(),
            RotateMasterKeyRequest {
                actor: "itest".to_string(),
            },
        ))
        .await?;
    assert_operation_count(data_dir.path(), "master_key.rotated", 1)?;

    let report = HemStore::open(data_dir.path())?
        .ledger_store()?
        .verify_integrity()?;
    assert!(report.ok, "ledger report: {report:?}");
    Ok(())
}

#[tokio::test]
async fn master_biometric_policy_requires_configured_master_peer(
) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = tempfile::tempdir()?;
    let identity = NodeIdentity::generate("hmn_worker", "worker")?;
    let config = ClusterConfig {
        enabled: true,
        cluster_id: "hmc_master_policy".to_string(),
        node_id: "hmn_worker".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 1,
        master_node_id: Some("hmn_master".to_string()),
        peers: Vec::new(),
    };
    config.save(&data_dir.path().join("cluster.toml"))?;
    identity.save(&data_dir.path().join("node-identity.json"))?;

    let daemon = TestDaemon::start(data_dir.path()).await?;
    let mut client = connect_client(daemon.endpoint.as_str()).await?;
    let init = client
        .init_hem(InitHemRequest { force: false })
        .await?
        .into_inner();
    let service = client
        .issue_service_token(authorized(
            init.operator_token.as_str(),
            IssueServiceTokenRequest {
                service_name: "master-policy-reader".to_string(),
                ttl_seconds: 0,
                issued_by: "itest".to_string(),
            },
        ))
        .await?
        .into_inner();

    client
        .set_secret(authorized(
            init.operator_token.as_str(),
            SetSecretRequest {
                secret: Some(proto_secret_ref("root-cloud")),
                values: vec![SecretValue {
                    key: "api_key".to_string(),
                    value: "root-cloud-value".to_string(),
                }],
                description: String::new(),
                requires_approval: false,
                group: String::new(),
                actor: "master-policy-test".to_string(),
                approval_receipt: String::new(),
                reason: String::new(),
            },
        ))
        .await?;

    let store = HemStore::open(data_dir.path())?;
    let policies = store.policy_store()?;
    let global = hem_core::SecretScope::Global;
    policies.set_secret_policy(&global, "root-cloud", SecretPolicyTier::MasterBiometric)?;

    let err = client
        .get_secret(authorized(
            service.token.as_str(),
            GetSecretRequest {
                lookup: Some(get_secret_request::Lookup::Secret(proto_secret_ref(
                    "root-cloud",
                ))),
                context: None,
                key: "api_key".to_string(),
                async_read: true,
                wait_timeout_ms: 0,
                reason: "need root cloud".to_string(),
                approval_receipt: String::new(),
            },
        ))
        .await
        .expect_err("worker must fail closed without configured master peer");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("master node hmn_master"));
    Ok(())
}

async fn read_api_key(
    client: &mut HemRuntimeClient<tonic::transport::Channel>,
    token: &str,
    name: &str,
) -> Result<String, tonic::Status> {
    read_api_key_with_receipt(client, token, name, "").await
}

async fn read_api_key_with_receipt(
    client: &mut HemRuntimeClient<tonic::transport::Channel>,
    token: &str,
    name: &str,
    approval_receipt: &str,
) -> Result<String, tonic::Status> {
    let read = client
        .get_secret(authorized(
            token,
            GetSecretRequest {
                lookup: Some(get_secret_request::Lookup::Secret(proto_secret_ref(name))),
                context: None,
                key: "api_key".to_string(),
                async_read: false,
                wait_timeout_ms: 0,
                reason: String::new(),
                approval_receipt: approval_receipt.to_string(),
            },
        ))
        .await?
        .into_inner();
    match read.result {
        Some(get_secret_response::Result::Secret(secret)) => secret
            .values
            .get("api_key")
            .cloned()
            .ok_or_else(|| tonic::Status::not_found("api_key missing")),
        _ => Err(tonic::Status::internal("expected secret result")),
    }
}

fn assert_operation_count(
    data_dir: &Path,
    op_type: &str,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let ledger = HemStore::open(data_dir)?.ledger_store()?;
    let count = ledger
        .list_after(0, 1000)?
        .iter()
        .filter(|operation| operation.op_type == op_type)
        .count();
    assert_eq!(count, expected, "operation count for {op_type}");
    Ok(())
}

fn read_fulfilled_payload_for(
    data_dir: &Path,
    name: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let ledger = HemStore::open(data_dir)?.ledger_store()?;
    ledger
        .list_after(0, 1000)?
        .into_iter()
        .rev()
        .find(|operation| {
            operation.op_type == "read.fulfilled"
                && operation.payload_json["secret_name"].as_str() == Some(name)
        })
        .map(|operation| operation.payload_json)
        .ok_or_else(|| format!("missing read.fulfilled payload for {name}").into())
}

fn ledger_envelope_for_key(
    data_dir: &Path,
    name: &str,
    key: &str,
) -> Result<EnvelopeEncryptedValue, Box<dyn std::error::Error>> {
    let ledger = HemStore::open(data_dir)?.ledger_store()?;
    let operation = ledger
        .list_after(0, 1000)?
        .into_iter()
        .find(|operation| operation.op_type == "secret.value.set")
        .expect("value operation");
    Ok(
        serde_json::from_value(operation.payload_json["values"][key].clone())
            .unwrap_or_else(|err| panic!("envelope for {name}/{key}: {err}")),
    )
}
