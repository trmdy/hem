use std::{
    collections::HashMap,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chrono::Utc;
use hem_core::{
    node_statement_hash_b64, peer_transport_auth_statement_bytes, verify_node_statement_signature,
    ClusterConfig, CollisionAgreementStatement, HemStore, LedgerCheckpoint, LedgerCollision,
    LedgerOperationBody, LedgerOperationEnvelope, LedgerOperationInput, LedgerStore,
    LocalStoreLedgerMigrationInput, NodeIdentity, PeerConfig, SecretPolicyTier,
    SecretScope as CoreSecretScope, SetSecretInput,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::time::sleep;
use tonic::{transport::Endpoint, Code, Request};

pub mod proto {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("valhall.hem.v1");
}

use proto::{
    get_secret_request, get_secret_response, hem_runtime_client::HemRuntimeClient,
    GetSecretRequest, HealthRequest, IssueServiceTokenRequest, ListPendingApprovalsRequest,
    PeerApproveCollisionRequest, PeerCosignCheckpointRequest, PeerListOperationsRequest,
    PeerPushOperationsRequest, ResolveApprovalRequest, ScopeSelector, SecretRef,
    SecretScope as ProtoSecretScope, SecretValue, SetSecretRequest,
};

struct TestDaemon {
    child: Child,
    endpoint: String,
}

impl TestDaemon {
    async fn start(data_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);
        Self::start_at(data_dir, addr.to_string().as_str(), &[]).await
    }

    async fn start_at(
        data_dir: &Path,
        bind: &str,
        envs: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
                return Err(format!("hemd at {} did not become ready", self.endpoint).into());
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

struct ClusterNode {
    data_dir: TempDir,
    identity: NodeIdentity,
    daemon: TestDaemon,
}

impl ClusterNode {
    async fn start(
        cluster_id: &str,
        node_id: &str,
        peers: Vec<PeerConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let data_dir = tempfile::tempdir()?;
        HemStore::init(data_dir.path(), false)?;
        let identity = NodeIdentity::generate(node_id, node_id)?;
        ClusterConfig {
            enabled: true,
            cluster_id: cluster_id.to_string(),
            node_id: node_id.to_string(),
            listen: "127.0.0.1:0".to_string(),
            quorum: 2,
            master_node_id: Some("hmn_a".to_string()),
            peers,
        }
        .save(&data_dir.path().join("cluster.toml"))?;
        identity.save(&data_dir.path().join("node-identity.json"))?;
        let daemon = TestDaemon::start(data_dir.path()).await?;
        Ok(Self {
            data_dir,
            identity,
            daemon,
        })
    }

    async fn client(
        &self,
    ) -> Result<HemRuntimeClient<tonic::transport::Channel>, Box<dyn std::error::Error>> {
        connect_client(self.daemon.endpoint.as_str()).await
    }

    fn ledger(&self) -> Result<LedgerStore, Box<dyn std::error::Error>> {
        Ok(HemStore::open(self.data_dir.path())?.ledger_store()?)
    }

    fn path(&self) -> &Path {
        self.data_dir.path()
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
) -> Request<T> {
    let nonce = format!(
        "hpt_{}",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    );
    let timestamp_unix = Utc::now().timestamp();
    let statement = peer_transport_auth_statement_bytes(
        cluster_id,
        identity.node_id.as_str(),
        method,
        nonce.as_str(),
        timestamp_unix,
    )
    .expect("serialize peer auth statement");
    let signature = identity
        .sign_statement(statement.as_slice())
        .expect("sign peer auth statement");

    let mut request = Request::new(message);
    let metadata = request.metadata_mut();
    metadata.insert("x-hem-peer-cluster-id", cluster_id.parse().unwrap());
    metadata.insert("x-hem-peer-node-id", identity.node_id.parse().unwrap());
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
        scope: ProtoSecretScope::Global as i32,
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

fn reserve_bind() -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

async fn wait_for_ledger_position(
    data_dir: &Path,
    min_position: i64,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    loop {
        let position = HemStore::open(data_dir)?
            .ledger_store()?
            .latest_position()?;
        if position >= min_position {
            return Ok(());
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "ledger at {} did not reach position {min_position}; latest={position}",
                data_dir.display()
            )
            .into());
        }
        sleep(Duration::from_millis(75)).await;
    }
}

async fn wait_for_peer_cursor(
    data_dir: &Path,
    peer_node_id: &str,
    min_position: i64,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    loop {
        let cursor = HemStore::open(data_dir)?
            .ledger_store()?
            .get_peer_cursor(peer_node_id)?;
        if cursor
            .as_ref()
            .map(|item| item.last_position >= min_position)
            .unwrap_or(false)
        {
            return Ok(());
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "cursor {peer_node_id} at {} did not reach position {min_position}; latest={cursor:?}",
                data_dir.display()
            )
            .into());
        }
        sleep(Duration::from_millis(75)).await;
    }
}

async fn wait_for_checkpoint_cosignature(
    data_dir: &Path,
    signer_node_id: &str,
    min_position: i64,
    timeout: Duration,
) -> Result<LedgerCheckpoint, Box<dyn std::error::Error>> {
    let started = Instant::now();
    loop {
        let ledger = HemStore::open(data_dir)?.ledger_store()?;
        for checkpoint in ledger.list_checkpoints()? {
            if checkpoint.body.to_position < min_position {
                continue;
            }
            let cosignatures =
                ledger.list_checkpoint_cosignatures(checkpoint.body.checkpoint_id.as_str())?;
            if cosignatures
                .iter()
                .any(|cosignature| cosignature.body.signer_node_id == signer_node_id)
            {
                return Ok(checkpoint);
            }
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "checkpoint at {} did not receive cosignature from {signer_node_id}",
                data_dir.display()
            )
            .into());
        }
        sleep(Duration::from_millis(75)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn request_collision_approval_evidence(
    peer: &PeerConfig,
    config: &ClusterConfig,
    requester_identity: &NodeIdentity,
    collision: &LedgerCollision,
    resolution: &str,
    nonce: &str,
    requester_latest_position: i64,
    requester_latest_body_hash_b64: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut client = connect_client(peer.endpoint.as_str()).await?;
    let response = client
        .peer_approve_collision(signed_peer_request(
            PeerApproveCollisionRequest {
                cluster_id: config.cluster_id.clone(),
                requester_node_id: requester_identity.node_id.clone(),
                requester_public_key: requester_identity.signing_public_key_b64.clone(),
                nonce: nonce.to_string(),
                collision_id: collision.collision_id.clone(),
                scope: collision.scope.clone(),
                name: collision.name.clone(),
                key: collision.key.clone(),
                current_operation_id: collision.current_operation_id.clone(),
                incoming_operation_id: collision.incoming_operation_id.clone(),
                base_version_seq: collision.base_version_seq,
                current_version_seq: collision.current_version_seq,
                resolution: resolution.to_string(),
                requester_latest_position,
                requester_latest_body_hash_b64: requester_latest_body_hash_b64.to_string(),
            },
            requester_identity,
            config.cluster_id.as_str(),
            "PeerApproveCollision",
        ))
        .await?
        .into_inner();
    assert!(response.accepted);
    assert_eq!(response.cluster_id, config.cluster_id);
    assert_eq!(response.node_id, peer.node_id);
    assert_eq!(response.signing_public_key_b64, peer.public_key);

    let statement = CollisionAgreementStatement {
        version: "hem-collision-agreement-v1",
        cluster_id: config.cluster_id.as_str(),
        requester_node_id: requester_identity.node_id.as_str(),
        approver_node_id: response.node_id.as_str(),
        nonce,
        collision_id: collision.collision_id.as_str(),
        scope: collision.scope.as_str(),
        name: collision.name.as_str(),
        key: collision.key.as_str(),
        current_operation_id: collision.current_operation_id.as_str(),
        incoming_operation_id: collision.incoming_operation_id.as_str(),
        base_version_seq: collision.base_version_seq,
        current_version_seq: collision.current_version_seq,
        resolution,
        requester_latest_position,
        requester_latest_body_hash_b64,
        approver_latest_position: response.latest_position,
        approver_latest_body_hash_b64: response.latest_body_hash_b64.as_str(),
    };
    let statement_bytes = serde_json::to_vec(&statement)?;
    assert_eq!(
        response.statement_hash_b64,
        node_statement_hash_b64(statement_bytes.as_slice())
    );
    verify_node_statement_signature(
        peer.public_key.as_str(),
        statement_bytes.as_slice(),
        response.signature_b64.as_str(),
    )?;
    let statement_json = serde_json::to_value(&statement)?;
    Ok(serde_json::json!({
        "peer_node_id": response.node_id,
        "endpoint": peer.endpoint.as_str(),
        "latest_position": response.latest_position,
        "latest_body_hash_b64": response.latest_body_hash_b64,
        "statement_hash_b64": response.statement_hash_b64,
        "signing_public_key_b64": response.signing_public_key_b64,
        "signature_b64": response.signature_b64,
        "statement": statement_json,
    }))
}

fn proto_checkpoint(checkpoint: &LedgerCheckpoint) -> proto::LedgerCheckpoint {
    proto::LedgerCheckpoint {
        body: Some(proto::LedgerCheckpointBody {
            checkpoint_id: checkpoint.body.checkpoint_id.clone(),
            cluster_id: checkpoint.body.cluster_id.clone(),
            to_position: checkpoint.body.to_position,
            operation_count: checkpoint.body.operation_count,
            merkle_root_b64: checkpoint.body.merkle_root_b64.clone(),
            created_at: checkpoint.body.created_at.to_rfc3339(),
        }),
        body_hash_b64: checkpoint.body_hash_b64.clone(),
        signer_node_id: checkpoint.signer_node_id.clone(),
        signing_public_key_b64: checkpoint.signing_public_key_b64.clone(),
        signature_b64: checkpoint.signature_b64.clone(),
    }
}

#[tokio::test]
async fn automatic_sync_catches_up_after_peer_returns_online_and_cursor_survives_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_auto_sync";
    let node_a_dir = tempfile::tempdir()?;
    let node_b_dir = tempfile::tempdir()?;
    HemStore::init(node_a_dir.path(), false)?;
    HemStore::init(node_b_dir.path(), false)?;

    let identity_a = NodeIdentity::generate("hmn_a", "node a")?;
    let identity_b = NodeIdentity::generate("hmn_b", "node b")?;
    let bind_a = reserve_bind()?;
    let bind_b = reserve_bind()?;
    let endpoint_a = format!("http://{bind_a}");
    let endpoint_b = format!("http://{bind_b}");

    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_a".to_string(),
        listen: endpoint_a.clone(),
        quorum: 2,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_b".to_string(),
            endpoint: endpoint_b.clone(),
            public_key: identity_b.signing_public_key_b64.clone(),
            wrap_public_key: identity_b.wrap_public_key_b64.clone(),
        }],
    }
    .save(&node_a_dir.path().join("cluster.toml"))?;
    identity_a.save(&node_a_dir.path().join("node-identity.json"))?;

    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_b".to_string(),
        listen: endpoint_b.clone(),
        quorum: 2,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_a".to_string(),
            endpoint: endpoint_a.clone(),
            public_key: identity_a.signing_public_key_b64.clone(),
            wrap_public_key: identity_a.wrap_public_key_b64.clone(),
        }],
    }
    .save(&node_b_dir.path().join("cluster.toml"))?;
    identity_b.save(&node_b_dir.path().join("node-identity.json"))?;

    append_metadata(
        &HemStore::open(node_b_dir.path())?.ledger_store()?,
        &identity_b,
        cluster_id,
        1,
        "hop_b_offline_meta",
        "offline-source",
    )?;

    let daemon_a = TestDaemon::start_at(
        node_a_dir.path(),
        bind_a.as_str(),
        &[
            ("VALHALL_HEM_CLUSTER_SYNC_INTERVAL_MS", "100"),
            ("VALHALL_HEM_CLUSTER_SYNC_MAX_BACKOFF_MS", "200"),
            ("VALHALL_HEM_CLUSTER_SYNC_BATCH_LIMIT", "50"),
        ],
    )
    .await?;
    sleep(Duration::from_millis(250)).await;
    let mut client_a = connect_client(daemon_a.endpoint.as_str()).await?;
    let health = client_a.health(HealthRequest {}).await?.into_inner();
    assert!(
        health.status.contains("sync_enabled=true"),
        "{}",
        health.status
    );

    let daemon_b = TestDaemon::start_at(
        node_b_dir.path(),
        bind_b.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;

    wait_for_ledger_position(node_a_dir.path(), 1, Duration::from_secs(5)).await?;
    let report_a = HemStore::open(node_a_dir.path())?
        .ledger_store()?
        .verify_integrity()?;
    assert!(report_a.ok, "node a integrity report: {report_a:?}");

    wait_for_peer_cursor(node_b_dir.path(), "hmn_a", 1, Duration::from_secs(5)).await?;
    let checkpoint =
        wait_for_checkpoint_cosignature(node_a_dir.path(), "hmn_b", 1, Duration::from_secs(5))
            .await?;
    assert_eq!(checkpoint.body.to_position, 1);
    let checkpoint_on_b = HemStore::open(node_b_dir.path())?
        .ledger_store()?
        .get_checkpoint(checkpoint.body.checkpoint_id.as_str())?
        .expect("peer stores cosigned checkpoint proposal");
    assert_eq!(checkpoint_on_b.body_hash_b64, checkpoint.body_hash_b64);
    drop(daemon_b);
    let daemon_b = TestDaemon::start_at(
        node_b_dir.path(),
        bind_b.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let cursor = HemStore::open(node_b_dir.path())?
        .ledger_store()?
        .get_peer_cursor("hmn_a")?
        .expect("cursor survives daemon restart");
    assert_eq!(cursor.last_position, 1);

    drop(daemon_b);
    drop(daemon_a);
    Ok(())
}

#[tokio::test]
async fn replicated_ledger_secret_can_be_read_from_peer_without_local_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_peer_read_fallback";
    let node_a_dir = tempfile::tempdir()?;
    let node_b_dir = tempfile::tempdir()?;
    HemStore::init(node_a_dir.path(), false)?;
    HemStore::init(node_b_dir.path(), false)?;

    let identity_a = NodeIdentity::generate("hmn_a", "node a")?;
    let identity_b = NodeIdentity::generate("hmn_b", "node b")?;
    let bind_a = reserve_bind()?;
    let bind_b = reserve_bind()?;
    let endpoint_a = format!("http://{bind_a}");
    let endpoint_b = format!("http://{bind_b}");

    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_a".to_string(),
        listen: endpoint_a.clone(),
        quorum: 2,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_b".to_string(),
            endpoint: endpoint_b.clone(),
            public_key: identity_b.signing_public_key_b64.clone(),
            wrap_public_key: identity_b.wrap_public_key_b64.clone(),
        }],
    }
    .save(&node_a_dir.path().join("cluster.toml"))?;
    identity_a.save(&node_a_dir.path().join("node-identity.json"))?;

    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_b".to_string(),
        listen: endpoint_b.clone(),
        quorum: 2,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_a".to_string(),
            endpoint: endpoint_a.clone(),
            public_key: identity_a.signing_public_key_b64.clone(),
            wrap_public_key: identity_a.wrap_public_key_b64.clone(),
        }],
    }
    .save(&node_b_dir.path().join("cluster.toml"))?;
    identity_b.save(&node_b_dir.path().join("node-identity.json"))?;

    let daemon_a = TestDaemon::start_at(
        node_a_dir.path(),
        bind_a.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let daemon_b = TestDaemon::start_at(
        node_b_dir.path(),
        bind_b.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let operator_a = HemStore::open(node_a_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;
    let operator_b = HemStore::open(node_b_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;

    let mut client_a = connect_client(daemon_a.endpoint.as_str()).await?;
    client_a
        .set_secret(authorized(
            operator_a.as_str(),
            SetSecretRequest {
                secret: Some(proto_secret_ref("replicated-live")),
                values: vec![SecretValue {
                    key: "api_key".to_string(),
                    value: "ledger-readable".to_string(),
                }],
                description: "replicated read fallback".to_string(),
                requires_approval: false,
                group: String::new(),
                actor: "itest".to_string(),
                approval_receipt: String::new(),
                reason: String::new(),
            },
        ))
        .await?;

    let operations = client_a
        .peer_list_operations(signed_peer_request(
            PeerListOperationsRequest {
                after_position: 0,
                limit: 100,
                peer_node_id: String::new(),
                use_recorded_cursor: false,
            },
            &identity_b,
            cluster_id,
            "PeerListOperations",
        ))
        .await?
        .into_inner()
        .operations;
    assert_eq!(operations.len(), 2);

    let mut client_b = connect_client(daemon_b.endpoint.as_str()).await?;
    let pushed = client_b
        .peer_push_operations(signed_peer_request(
            PeerPushOperationsRequest { operations },
            &identity_a,
            cluster_id,
            "PeerPushOperations",
        ))
        .await?
        .into_inner();
    assert_eq!(pushed.accepted_count, 2);
    assert_eq!(pushed.latest_position, 2);

    for lookup in [
        get_secret_request::Lookup::Secret(proto_secret_ref("replicated-live")),
        get_secret_request::Lookup::Name("replicated-live".to_string()),
    ] {
        let response = client_b
            .get_secret(authorized(
                operator_b.as_str(),
                GetSecretRequest {
                    lookup: Some(lookup),
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
        match response.result {
            Some(get_secret_response::Result::Secret(secret)) => {
                assert_eq!(
                    secret.values.get("api_key").map(String::as_str),
                    Some("ledger-readable")
                );
            }
            other => panic!("expected replicated secret, got {other:?}"),
        }
    }

    drop(daemon_b);
    drop(daemon_a);
    Ok(())
}

#[tokio::test]
async fn two_node_replication_catchup_duplicate_delivery_and_invalid_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_distributed_two";
    let node_a = ClusterNode::start(cluster_id, "hmn_a", Vec::new()).await?;
    let node_b = ClusterNode::start(cluster_id, "hmn_b", Vec::new()).await?;
    let ledger_a = node_a.ledger()?;
    append_metadata(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        1,
        "hop_a_meta",
        "alpha",
    )?;
    append_value(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        2,
        "hop_a_value",
        "alpha",
        "ciphertext-alpha",
        0,
    )?;

    let mut client_a = node_a.client().await?;
    let mut client_b = node_b.client().await?;
    let first_batch = client_a
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 100,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner();
    assert_eq!(
        first_batch.operations.len(),
        2,
        "node hmn_a should expose two source operations"
    );

    let pushed = client_b
        .peer_push_operations(PeerPushOperationsRequest {
            operations: first_batch.operations.clone(),
        })
        .await?
        .into_inner();
    assert_eq!(pushed.accepted_count, 2, "node hmn_b initial push");
    assert_eq!(pushed.latest_position, 2);

    let duplicate = client_b
        .peer_push_operations(PeerPushOperationsRequest {
            operations: first_batch.operations.clone(),
        })
        .await?
        .into_inner();
    assert_eq!(
        duplicate.accepted_count, 0,
        "duplicate delivery is idempotent"
    );
    assert_eq!(duplicate.latest_position, 2);

    append_metadata(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        3,
        "hop_a_beta",
        "beta",
    )?;
    let catch_up = client_a
        .peer_list_operations(PeerListOperationsRequest {
            after_position: pushed.latest_position,
            limit: 100,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner();
    assert_eq!(catch_up.operations.len(), 1, "node hmn_b catch-up batch");
    let pushed_catch_up = client_b
        .peer_push_operations(PeerPushOperationsRequest {
            operations: catch_up.operations,
        })
        .await?
        .into_inner();
    assert_eq!(pushed_catch_up.accepted_count, 1);
    assert_eq!(pushed_catch_up.latest_position, 3);

    append_metadata(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        4,
        "hop_a_bad",
        "bad",
    )?;
    let mut invalid = client_a
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 3,
            limit: 1,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner()
        .operations;
    invalid[0].signature_b64 = "not-a-valid-signature".to_string();
    let rejected = client_b
        .peer_push_operations(PeerPushOperationsRequest {
            operations: invalid,
        })
        .await
        .expect_err("node hmn_b must reject invalid signatures");
    assert_eq!(rejected.code(), Code::InvalidArgument);

    let report_b = node_b.ledger()?.verify_integrity()?;
    assert!(report_b.ok, "node hmn_b integrity report: {report_b:?}");
    assert_eq!(report_b.latest_position, 3);
    Ok(())
}

#[tokio::test]
async fn fresh_node_bootstraps_verified_ledger_history_from_peer(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_bootstrap_two";
    let node_a = ClusterNode::start(cluster_id, "hmn_a", Vec::new()).await?;
    let ledger_a = node_a.ledger()?;
    append_metadata(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        1,
        "hop_bootstrap_meta",
        "bootstrapped",
    )?;
    append_value(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        2,
        "hop_bootstrap_value",
        "bootstrapped",
        "ciphertext-bootstrap",
        0,
    )?;

    let node_b_dir = tempfile::tempdir()?;
    HemStore::init(node_b_dir.path(), false)?;
    let identity_b = NodeIdentity::generate("hmn_b", "node b")?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_b".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 2,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_a".to_string(),
            endpoint: node_a.daemon.endpoint.clone(),
            public_key: node_a.identity.signing_public_key_b64.clone(),
            wrap_public_key: node_a.identity.wrap_public_key_b64.clone(),
        }],
    }
    .save(&node_b_dir.path().join("cluster.toml"))?;
    identity_b.save(&node_b_dir.path().join("node-identity.json"))?;
    let ledger_b = HemStore::open(node_b_dir.path())?.ledger_store()?;

    let mut client_a = node_a.client().await?;
    let first = client_a
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 1,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner();
    let first_envelopes = first
        .operations
        .iter()
        .cloned()
        .map(test_core_envelope_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    let first_report = ledger_b.bootstrap_from_peer_operations(cluster_id, &first_envelopes)?;
    assert_eq!(first_report.accepted_operations, 1);
    assert_eq!(first_report.latest_position, 1);

    let rest = client_a
        .peer_list_operations(PeerListOperationsRequest {
            after_position: first_report.latest_position,
            limit: 100,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner();
    let rest_envelopes = rest
        .operations
        .iter()
        .cloned()
        .map(test_core_envelope_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    let rest_report = ledger_b.bootstrap_from_peer_operations(cluster_id, &rest_envelopes)?;
    assert_eq!(rest_report.accepted_operations, 1);
    assert_eq!(rest_report.latest_position, ledger_a.latest_position()?);
    assert_eq!(
        rest_report.latest_body_hash_b64,
        ledger_a.latest_body_hash()?.unwrap_or_default()
    );

    let metadata = ledger_b
        .get_materialized_secret_metadata(cluster_id, "global", "bootstrapped")
        .expect("metadata")
        .expect("metadata exists");
    assert_eq!(metadata.description, "metadata for bootstrapped");
    let values = ledger_b
        .list_secret_value_versions(cluster_id, "global", "bootstrapped", "api_key")
        .expect("values");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].operation_id, "hop_bootstrap_value");
    let report_b = ledger_b.verify_integrity()?;
    assert!(report_b.ok, "node hmn_b integrity report: {report_b:?}");
    Ok(())
}

#[tokio::test]
async fn peer_checkpoint_cosignature_rejects_divergent_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_checkpoint_divergence";
    let node_a_dir = tempfile::tempdir()?;
    let node_b_dir = tempfile::tempdir()?;
    HemStore::init(node_a_dir.path(), false)?;
    HemStore::init(node_b_dir.path(), false)?;
    let identity_a = NodeIdentity::generate("hmn_a", "node a")?;
    let identity_b = NodeIdentity::generate("hmn_b", "node b")?;
    let bind_b = reserve_bind()?;
    let endpoint_b = format!("http://{bind_b}");
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_b".to_string(),
        listen: endpoint_b.clone(),
        quorum: 2,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_a".to_string(),
            endpoint: "http://127.0.0.1:1".to_string(),
            public_key: identity_a.signing_public_key_b64.clone(),
            wrap_public_key: identity_a.wrap_public_key_b64.clone(),
        }],
    }
    .save(&node_b_dir.path().join("cluster.toml"))?;
    identity_b.save(&node_b_dir.path().join("node-identity.json"))?;

    let ledger_a = HemStore::open(node_a_dir.path())?.ledger_store()?;
    let ledger_b = HemStore::open(node_b_dir.path())?.ledger_store()?;
    append_metadata(
        &ledger_a,
        &identity_a,
        cluster_id,
        1,
        "hop_checkpoint_a",
        "alpha",
    )?;
    append_metadata(
        &ledger_b,
        &identity_b,
        cluster_id,
        1,
        "hop_checkpoint_b",
        "beta",
    )?;
    let checkpoint = ledger_a.create_checkpoint(&identity_a, cluster_id, 1)?;
    let _daemon_b = TestDaemon::start_at(
        node_b_dir.path(),
        bind_b.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;

    let mut client_b = connect_client(endpoint_b.as_str()).await?;
    let rejected = client_b
        .peer_cosign_checkpoint(signed_peer_request(
            PeerCosignCheckpointRequest {
                requester_node_id: identity_a.node_id.clone(),
                requester_public_key: identity_a.signing_public_key_b64.clone(),
                checkpoint: Some(proto_checkpoint(&checkpoint)),
            },
            &identity_a,
            cluster_id,
            "PeerCosignCheckpoint",
        ))
        .await
        .expect_err("divergent prefix must not be cosigned");
    assert_eq!(rejected.code(), Code::FailedPrecondition);
    assert!(
        rejected
            .message()
            .contains("checkpoint merkle root mismatch"),
        "{rejected}"
    );
    assert!(ledger_b
        .list_checkpoints()?
        .iter()
        .all(|item| item.body.checkpoint_id != checkpoint.body.checkpoint_id));
    Ok(())
}

#[tokio::test]
async fn three_node_conflict_migration_fork_and_divergence_detection(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_distributed_three";
    let node_a = ClusterNode::start(cluster_id, "hmn_a", Vec::new()).await?;
    let node_b = ClusterNode::start(cluster_id, "hmn_b", Vec::new()).await?;
    let node_c = ClusterNode::start(cluster_id, "hmn_c", Vec::new()).await?;

    let store_c = HemStore::open(node_c.path())?;
    store_c.set_secret(SetSecretInput {
        scope: CoreSecretScope::Global,
        name: "migrated-secret".to_string(),
        values: HashMap::from([("api_key".to_string(), "local-before-ledger".to_string())]),
        description: "migration suite".to_string(),
        requires_approval: false,
        group: None,
        actor: "itest".to_string(),
    })?;
    let migration = store_c.migrate_local_store_to_ledger(LocalStoreLedgerMigrationInput {
        cluster_id,
        identity: &node_c.identity,
        dry_run: true,
    })?;
    assert_eq!(migration.secrets_scanned, 1);
    assert_eq!(migration.operations_planned, 2);

    let ledger_a = node_a.ledger()?;
    append_value(
        &ledger_a,
        &node_a.identity,
        cluster_id,
        1,
        "hop_conflict_a",
        "shared",
        "ciphertext-a",
        0,
    )?;
    append_value(
        &ledger_a,
        &node_c.identity,
        cluster_id,
        1,
        "hop_conflict_c",
        "shared",
        "ciphertext-c",
        0,
    )?;

    let mut client_a = node_a.client().await?;
    let mut client_b = node_b.client().await?;
    let operations = client_a
        .peer_list_operations(PeerListOperationsRequest {
            after_position: 0,
            limit: 100,
            peer_node_id: String::new(),
            use_recorded_cursor: false,
        })
        .await?
        .into_inner()
        .operations;
    let pushed = client_b
        .peer_push_operations(PeerPushOperationsRequest { operations })
        .await?
        .into_inner();
    assert_eq!(pushed.accepted_count, 2);

    let ledger_b = node_b.ledger()?;
    ledger_b.materialize_secret_value_versions()?;
    let collisions = ledger_b.list_open_collisions(cluster_id)?;
    assert_eq!(collisions.len(), 1, "node hmn_b conflict count");
    assert_eq!(collisions[0].incoming_operation_id, "hop_conflict_c");

    let checkpoint = ledger_b.create_checkpoint(&node_b.identity, cluster_id, 2)?;
    let fork = ledger_b.declare_hard_fork(
        &node_b.identity,
        cluster_id,
        Some(checkpoint.body.checkpoint_id.as_str()),
        "operator",
        "integration fork after conflict",
    )?;
    assert_eq!(fork.parent_checkpoint_id, checkpoint.body.checkpoint_id);

    let conn = rusqlite::Connection::open(ledger_b.path())?;
    conn.execute(
        "INSERT INTO ledger_peer_cursors (
            peer_node_id,
            last_position,
            last_body_hash_b64,
            updated_at
         ) VALUES (?1, ?2, ?3, ?4)",
        (
            "hmn_c",
            99_i64,
            "quorum-head-not-present-locally",
            Utc::now().to_rfc3339(),
        ),
    )?;
    let report = ledger_b.verify_integrity()?;
    assert!(report.ok, "node hmn_b report: {report:?}");
    assert_eq!(report.forks_declared, 1);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "divergence" && issue.reference == "peer:hmn_c"));
    Ok(())
}

#[tokio::test]
async fn three_node_collision_resolution_requires_quorum_signatures_and_converges(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_collision_quorum";
    let node_a_dir = tempfile::tempdir()?;
    let node_b_dir = tempfile::tempdir()?;
    let node_c_dir = tempfile::tempdir()?;
    HemStore::init(node_a_dir.path(), false)?;
    HemStore::init(node_b_dir.path(), false)?;
    HemStore::init(node_c_dir.path(), false)?;
    let identity_a = NodeIdentity::generate("hmn_a", "node a")?;
    let identity_b = NodeIdentity::generate("hmn_b", "node b")?;
    let identity_c = NodeIdentity::generate("hmn_c", "node c")?;
    let bind_a = reserve_bind()?;
    let bind_b = reserve_bind()?;
    let bind_c = reserve_bind()?;
    let endpoint_a = format!("http://{bind_a}");
    let endpoint_b = format!("http://{bind_b}");
    let endpoint_c = format!("http://{bind_c}");
    let peer_a = PeerConfig {
        node_id: "hmn_a".to_string(),
        endpoint: endpoint_a.clone(),
        public_key: identity_a.signing_public_key_b64.clone(),
        wrap_public_key: identity_a.wrap_public_key_b64.clone(),
    };
    let peer_b = PeerConfig {
        node_id: "hmn_b".to_string(),
        endpoint: endpoint_b.clone(),
        public_key: identity_b.signing_public_key_b64.clone(),
        wrap_public_key: identity_b.wrap_public_key_b64.clone(),
    };
    let peer_c = PeerConfig {
        node_id: "hmn_c".to_string(),
        endpoint: endpoint_c.clone(),
        public_key: identity_c.signing_public_key_b64.clone(),
        wrap_public_key: identity_c.wrap_public_key_b64.clone(),
    };
    let config_a = ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_a".to_string(),
        listen: endpoint_a.clone(),
        quorum: 3,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![peer_b.clone(), peer_c.clone()],
    };
    config_a.save(&node_a_dir.path().join("cluster.toml"))?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_b".to_string(),
        listen: endpoint_b.clone(),
        quorum: 3,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![peer_a.clone(), peer_c.clone()],
    }
    .save(&node_b_dir.path().join("cluster.toml"))?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: "hmn_c".to_string(),
        listen: endpoint_c.clone(),
        quorum: 3,
        master_node_id: Some("hmn_a".to_string()),
        peers: vec![peer_a.clone(), peer_b.clone()],
    }
    .save(&node_c_dir.path().join("cluster.toml"))?;
    identity_a.save(&node_a_dir.path().join("node-identity.json"))?;
    identity_b.save(&node_b_dir.path().join("node-identity.json"))?;
    identity_c.save(&node_c_dir.path().join("node-identity.json"))?;
    let _daemon_a = TestDaemon::start_at(
        node_a_dir.path(),
        bind_a.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let _daemon_b = TestDaemon::start_at(
        node_b_dir.path(),
        bind_b.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let _daemon_c = TestDaemon::start_at(
        node_c_dir.path(),
        bind_c.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;

    let ledger_a = HemStore::open(node_a_dir.path())?.ledger_store()?;
    append_value(
        &ledger_a,
        &identity_a,
        cluster_id,
        1,
        "hop_quorum_conflict_a",
        "shared",
        "ciphertext-a",
        0,
    )?;
    append_value(
        &ledger_a,
        &identity_b,
        cluster_id,
        1,
        "hop_quorum_conflict_b",
        "shared",
        "ciphertext-b",
        0,
    )?;
    ledger_a.materialize_secret_value_versions()?;
    let collision = ledger_a
        .list_open_collisions(cluster_id)?
        .pop()
        .expect("collision");
    assert_eq!(collision.incoming_operation_id, "hop_quorum_conflict_b");
    let required_peer_acks = usize::from(config_a.quorum.saturating_sub(1));
    let requester_latest_position = ledger_a.latest_position()?;
    let requester_latest_body_hash_b64 = ledger_a.latest_body_hash()?.unwrap_or_default();
    let nonce = "hca_test_quorum";

    let first_ack = request_collision_approval_evidence(
        &peer_b,
        &config_a,
        &identity_a,
        &collision,
        "accept-incoming",
        nonce,
        requester_latest_position,
        requester_latest_body_hash_b64.as_str(),
    )
    .await?;
    assert!(
        required_peer_acks > 1,
        "one signature must not satisfy quorum=3"
    );
    assert_eq!(
        ledger_a
            .list_secret_value_versions(cluster_id, "global", "shared", "api_key")?
            .len(),
        1,
        "incoming value must not materialize before resolution"
    );

    let second_ack = request_collision_approval_evidence(
        &peer_c,
        &config_a,
        &identity_a,
        &collision,
        "accept-incoming",
        nonce,
        requester_latest_position,
        requester_latest_body_hash_b64.as_str(),
    )
    .await?;
    let agreement = serde_json::json!({
        "kind": "collision_quorum_v1",
        "cluster_id": cluster_id,
        "requester_node_id": identity_a.node_id.as_str(),
        "collision_id": collision.collision_id.as_str(),
        "scope": collision.scope.as_str(),
        "name": collision.name.as_str(),
        "key": collision.key.as_str(),
        "current_operation_id": collision.current_operation_id.as_str(),
        "incoming_operation_id": collision.incoming_operation_id.as_str(),
        "resolution": "accept-incoming",
        "required_cluster_quorum": config_a.quorum,
        "required_peer_acks": required_peer_acks,
        "nonce": nonce,
        "requester_latest_position": requester_latest_position,
        "requester_latest_body_hash_b64": requester_latest_body_hash_b64,
        "accepted": [first_ack, second_ack],
        "failures": [],
    });
    ledger_a.append_collision_resolution_with_agreement(
        &identity_a,
        collision.collision_id.as_str(),
        "itest",
        "accept-incoming",
        Some(agreement),
    )?;
    ledger_a.materialize_secret_value_versions()?;
    let versions_a =
        ledger_a.list_secret_value_versions(cluster_id, "global", "shared", "api_key")?;
    assert_eq!(versions_a.len(), 2);
    assert_eq!(versions_a[1].operation_id, "hop_quorum_conflict_b");
    assert_eq!(ledger_a.list_open_collisions(cluster_id)?.len(), 0);
    assert!(ledger_a.verify_integrity()?.ok);

    let mut client_a = connect_client(endpoint_a.as_str()).await?;
    let operations = client_a
        .peer_list_operations(signed_peer_request(
            PeerListOperationsRequest {
                after_position: 0,
                limit: 100,
                peer_node_id: String::new(),
                use_recorded_cursor: false,
            },
            &identity_b,
            cluster_id,
            "PeerListOperations",
        ))
        .await?
        .into_inner()
        .operations;
    for endpoint in [endpoint_b.as_str(), endpoint_c.as_str()] {
        let mut peer_client = connect_client(endpoint).await?;
        peer_client
            .peer_push_operations(signed_peer_request(
                PeerPushOperationsRequest {
                    operations: operations.clone(),
                },
                &identity_a,
                cluster_id,
                "PeerPushOperations",
            ))
            .await?;
    }
    for dir in [node_b_dir.path(), node_c_dir.path()] {
        let ledger = HemStore::open(dir)?.ledger_store()?;
        ledger.materialize_secret_value_versions()?;
        let versions =
            ledger.list_secret_value_versions(cluster_id, "global", "shared", "api_key")?;
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[1].operation_id, "hop_quorum_conflict_b");
        assert_eq!(ledger.list_open_collisions(cluster_id)?.len(), 0);
        assert!(ledger.verify_integrity()?.ok);
    }
    Ok(())
}

#[tokio::test]
async fn master_biometric_routes_to_master_and_consumes_receipts_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_id = "hmc_master_approval_route";
    let worker_dir = tempfile::tempdir()?;
    let master_dir = tempfile::tempdir()?;
    HemStore::init(worker_dir.path(), false)?;
    HemStore::init(master_dir.path(), false)?;
    let worker_identity = NodeIdentity::generate("hmn_worker", "worker")?;
    let master_identity = NodeIdentity::generate("hmn_master", "master")?;
    let worker_bind = reserve_bind()?;
    let master_bind = reserve_bind()?;
    let worker_endpoint = format!("http://{worker_bind}");
    let master_endpoint = format!("http://{master_bind}");
    let worker_peer = PeerConfig {
        node_id: worker_identity.node_id.clone(),
        endpoint: worker_endpoint.clone(),
        public_key: worker_identity.signing_public_key_b64.clone(),
        wrap_public_key: worker_identity.wrap_public_key_b64.clone(),
    };
    let master_peer = PeerConfig {
        node_id: master_identity.node_id.clone(),
        endpoint: master_endpoint.clone(),
        public_key: master_identity.signing_public_key_b64.clone(),
        wrap_public_key: master_identity.wrap_public_key_b64.clone(),
    };
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: worker_identity.node_id.clone(),
        listen: worker_endpoint.clone(),
        quorum: 2,
        master_node_id: Some(master_identity.node_id.clone()),
        peers: vec![master_peer.clone()],
    }
    .save(&worker_dir.path().join("cluster.toml"))?;
    ClusterConfig {
        enabled: true,
        cluster_id: cluster_id.to_string(),
        node_id: master_identity.node_id.clone(),
        listen: master_endpoint.clone(),
        quorum: 2,
        master_node_id: Some(master_identity.node_id.clone()),
        peers: vec![worker_peer.clone()],
    }
    .save(&master_dir.path().join("cluster.toml"))?;
    worker_identity.save(&worker_dir.path().join("node-identity.json"))?;
    master_identity.save(&master_dir.path().join("node-identity.json"))?;
    let _worker_daemon = TestDaemon::start_at(
        worker_dir.path(),
        worker_bind.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let _master_daemon = TestDaemon::start_at(
        master_dir.path(),
        master_bind.as_str(),
        &[("VALHALL_HEM_CLUSTER_SYNC", "0")],
    )
    .await?;
    let mut worker_client = connect_client(worker_endpoint.as_str()).await?;
    let mut master_client = connect_client(master_endpoint.as_str()).await?;
    let worker_operator = HemStore::open(worker_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;
    let master_operator = HemStore::open(master_dir.path())?
        .token_manager()?
        .issue_operator_token(Duration::from_secs(600), "itest")?
        .token;
    let service = worker_client
        .issue_service_token(authorized(
            worker_operator.as_str(),
            IssueServiceTokenRequest {
                service_name: "master-route-reader".to_string(),
                ttl_seconds: 0,
                issued_by: "itest".to_string(),
            },
        ))
        .await?
        .into_inner();
    let other_service = worker_client
        .issue_service_token(authorized(
            worker_operator.as_str(),
            IssueServiceTokenRequest {
                service_name: "wrong-reader".to_string(),
                ttl_seconds: 0,
                issued_by: "itest".to_string(),
            },
        ))
        .await?
        .into_inner();

    for (name, value) in [
        ("root-secret", "must-not-release-without-master"),
        ("other-root-secret", "other-root-value"),
        ("deny-secret", "deny-value"),
        ("timeout-secret", "timeout-value"),
    ] {
        worker_client
            .set_secret(authorized(
                worker_operator.as_str(),
                SetSecretRequest {
                    secret: Some(proto_secret_ref(name)),
                    values: vec![SecretValue {
                        key: "api_key".to_string(),
                        value: value.to_string(),
                    }],
                    description: String::new(),
                    requires_approval: false,
                    group: String::new(),
                    actor: "policy-itest".to_string(),
                    approval_receipt: String::new(),
                    reason: String::new(),
                },
            ))
            .await?;
    }

    let worker_store = HemStore::open(worker_dir.path())?;
    let policies = worker_store.policy_store()?;
    for name in [
        "root-secret",
        "other-root-secret",
        "deny-secret",
        "timeout-secret",
    ] {
        policies.set_secret_policy(
            &CoreSecretScope::Global,
            name,
            SecretPolicyTier::MasterBiometric,
        )?;
    }

    let response = worker_client
        .get_secret(authorized(
            service.token.as_str(),
            GetSecretRequest {
                lookup: Some(get_secret_request::Lookup::Secret(proto_secret_ref(
                    "root-secret",
                ))),
                context: None,
                key: "api_key".to_string(),
                async_read: true,
                wait_timeout_ms: 0,
                reason: "attempt without master approval".to_string(),
                approval_receipt: String::new(),
            },
        ))
        .await?
        .into_inner();
    let request_id = match response.result {
        Some(get_secret_response::Result::Pending(pending)) => {
            assert_eq!(pending.message, "secret read requires master approval");
            pending.request_id
        }
        other => panic!("master_biometric read must route to master: {other:?}"),
    };
    let inbox = master_client
        .list_pending_approvals(authorized(
            master_operator.as_str(),
            ListPendingApprovalsRequest { limit: 20 },
        ))
        .await?
        .into_inner();
    assert!(inbox
        .requests
        .iter()
        .any(|request| request.request_id == request_id));

    let approved = master_client
        .approve_access(authorized(
            master_operator.as_str(),
            ResolveApprovalRequest {
                request_id: request_id.clone(),
                actor: "master-human".to_string(),
                message: "approved".to_string(),
            },
        ))
        .await?
        .into_inner();
    let receipt = approved.approval_receipt;
    assert!(!receipt.trim().is_empty());

    let wrong_requester = read_api_key_with_receipt(
        &mut worker_client,
        other_service.token.as_str(),
        "root-secret",
        receipt.as_str(),
        0,
    )
    .await
    .expect_err("receipt is requester-bound");
    assert_eq!(wrong_requester.code(), Code::PermissionDenied);

    let wrong_secret = read_api_key_with_receipt(
        &mut worker_client,
        service.token.as_str(),
        "other-root-secret",
        receipt.as_str(),
        0,
    )
    .await
    .expect_err("receipt is secret-bound");
    assert_eq!(wrong_secret.code(), Code::PermissionDenied);

    assert_eq!(
        read_api_key_with_receipt(
            &mut worker_client,
            service.token.as_str(),
            "root-secret",
            receipt.as_str(),
            0,
        )
        .await?,
        "must-not-release-without-master"
    );
    let reused = read_api_key_with_receipt(
        &mut worker_client,
        service.token.as_str(),
        "root-secret",
        receipt.as_str(),
        0,
    )
    .await
    .expect_err("receipt is one-time");
    assert_eq!(reused.code(), Code::FailedPrecondition);

    let mut deny_worker = connect_client(worker_endpoint.as_str()).await?;
    let deny_token = service.token.clone();
    let deny_handle = tokio::spawn(async move {
        read_api_key_with_receipt(
            &mut deny_worker,
            deny_token.as_str(),
            "deny-secret",
            "",
            5_000,
        )
        .await
    });
    let deny_request = wait_for_pending_approval_reason(
        &mut master_client,
        master_operator.as_str(),
        "deny this read",
        Duration::from_secs(5),
    )
    .await?;
    master_client
        .deny_access(authorized(
            master_operator.as_str(),
            ResolveApprovalRequest {
                request_id: deny_request,
                actor: "master-human".to_string(),
                message: "denied".to_string(),
            },
        ))
        .await?;
    let denied = deny_handle
        .await?
        .expect_err("denial propagates to requester");
    assert_eq!(denied.code(), Code::PermissionDenied);

    let timed_out = read_api_key_with_receipt(
        &mut worker_client,
        service.token.as_str(),
        "timeout-secret",
        "",
        100,
    )
    .await
    .expect_err("master approval wait timeout propagates");
    assert_eq!(timed_out.code(), Code::DeadlineExceeded);
    Ok(())
}

async fn read_api_key_with_receipt(
    client: &mut HemRuntimeClient<tonic::transport::Channel>,
    token: &str,
    name: &str,
    approval_receipt: &str,
    wait_timeout_ms: u64,
) -> Result<String, tonic::Status> {
    let response = client
        .get_secret(authorized(
            token,
            GetSecretRequest {
                lookup: Some(get_secret_request::Lookup::Secret(proto_secret_ref(name))),
                context: None,
                key: "api_key".to_string(),
                async_read: false,
                wait_timeout_ms,
                reason: if name == "deny-secret" {
                    "deny this read".to_string()
                } else {
                    String::new()
                },
                approval_receipt: approval_receipt.to_string(),
            },
        ))
        .await?
        .into_inner();
    match response.result {
        Some(get_secret_response::Result::Secret(secret)) => secret
            .values
            .get("api_key")
            .cloned()
            .ok_or_else(|| tonic::Status::not_found("api_key missing")),
        other => Err(tonic::Status::internal(format!(
            "expected secret result, got {other:?}"
        ))),
    }
}

async fn wait_for_pending_approval_reason(
    client: &mut HemRuntimeClient<tonic::transport::Channel>,
    token: &str,
    reason: &str,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let started = Instant::now();
    loop {
        let response = client
            .list_pending_approvals(authorized(token, ListPendingApprovalsRequest { limit: 50 }))
            .await?
            .into_inner();
        if let Some(request) = response
            .requests
            .into_iter()
            .find(|request| request.reason == reason)
        {
            return Ok(request.request_id);
        }
        if started.elapsed() > timeout {
            return Err(format!("pending approval with reason {reason:?} did not appear").into());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn append_metadata(
    ledger: &LedgerStore,
    identity: &NodeIdentity,
    cluster_id: &str,
    node_seq: i64,
    operation_id: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = ledger.sign_next(
        identity,
        LedgerOperationInput {
            operation_id: operation_id.to_string(),
            cluster_id: cluster_id.to_string(),
            node_id: identity.node_id.clone(),
            node_seq,
            op_type: "secret.metadata.set".to_string(),
            payload_json: json!({
                "scope": "global",
                "name": name,
                "description": format!("metadata for {name}"),
                "requires_approval": false,
                "actor": "distributed-itest",
            }),
            created_at: Utc::now(),
        },
    )?;
    ledger.append_signed(&envelope)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_value(
    ledger: &LedgerStore,
    identity: &NodeIdentity,
    cluster_id: &str,
    node_seq: i64,
    operation_id: &str,
    name: &str,
    ciphertext_b64: &str,
    base_version_seq: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = ledger.sign_next(
        identity,
        LedgerOperationInput {
            operation_id: operation_id.to_string(),
            cluster_id: cluster_id.to_string(),
            node_id: identity.node_id.clone(),
            node_seq,
            op_type: "secret.value.set".to_string(),
            payload_json: json!({
                "scope": "global",
                "name": name,
                "values": {
                    "api_key": {
                        "alg": "xchacha20poly1305",
                        "key_id": "mk-itest",
                        "nonce_b64": "nonce",
                        "ciphertext_b64": ciphertext_b64,
                    }
                },
                "base_version_seq": base_version_seq,
                "actor": identity.node_id,
            }),
            created_at: Utc::now(),
        },
    )?;
    ledger.append_signed(&envelope)?;
    Ok(())
}

fn test_core_envelope_from_proto(
    operation: proto::LedgerOperationEnvelope,
) -> Result<LedgerOperationEnvelope, Box<dyn std::error::Error>> {
    let body = operation.body.ok_or("ledger operation body is required")?;
    Ok(LedgerOperationEnvelope {
        body: LedgerOperationBody {
            operation_id: body.operation_id,
            cluster_id: body.cluster_id,
            node_id: body.node_id,
            node_seq: body.node_seq,
            op_type: body.op_type,
            payload_json: serde_json::from_str(body.payload_json.as_str())?,
            created_at: chrono::DateTime::parse_from_rfc3339(body.created_at.as_str())?
                .with_timezone(&chrono::Utc),
            prev_hash_b64: body.prev_hash_b64,
        },
        body_hash_b64: operation.body_hash_b64,
        signing_public_key_b64: operation.signing_public_key_b64,
        signature_b64: operation.signature_b64,
    })
}
