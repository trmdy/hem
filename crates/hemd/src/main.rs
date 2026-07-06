#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]

use std::{
    collections::hash_map::DefaultHasher,
    collections::{HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use hem_core::{
    authorize_admin, authorize_read, envelope_decrypt_for_node,
    model::{resolution_chain, ApprovalState as CoreApprovalState},
    node_statement_hash_b64, peer_transport_auth_statement_bytes, verify_node_statement_signature,
    AuditClientInfo as CoreAuditClientInfo, AuditEntry as CoreAuditEntry,
    AuditTokenInfo as CoreAuditTokenInfo, AuditTransportInfo as CoreAuditTransportInfo,
    ClusterConfig, CollisionAgreementStatement, DeleteApprovalRecord,
    DeleteApprovalStore, EnvelopeEncryptedValue, GrantInfo as CoreGrantInfo,
    GroupInfo as CoreGroupInfo, HemError, HemStore, LedgerCheckpoint as CoreLedgerCheckpoint,
    LedgerCheckpointBody as CoreLedgerCheckpointBody,
    LedgerCheckpointCosignature as CoreLedgerCheckpointCosignature,
    LedgerCheckpointCosignatureBody as CoreLedgerCheckpointCosignatureBody,
    LedgerOperationBody as CoreLedgerOperationBody,
    LedgerOperationEnvelope as CoreLedgerOperationEnvelope,
    LedgerOperationInput as CoreLedgerOperationInput,
    LedgerSecretMetadata as CoreLedgerSecretMetadata, NodeIdentity, NodeKeyRecipient, PeerConfig,
    ScopeResolutionContext, SecretInfo as CoreSecretInfo, SecretPolicyTier, SecretScope,
    SecretWithValues as CoreSecretWithValues, SetSecretInput, TokenClaims, TokenType,
};
use serde::Serialize;
use tonic::{
    metadata::MetadataMap,
    transport::{Endpoint, Server},
    Code, Request, Response, Status,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use valhall_events::topics;
use valhall_net::{Mesh, MeshConfig};

pub mod proto {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("valhall.hem.v1");
}

use proto::{
    get_secret_info_request, get_secret_request, get_secret_response,
    hem_runtime_client::HemRuntimeClient,
    hem_runtime_server::{HemRuntime, HemRuntimeServer},
    secret_batch_request_item, secret_batch_result, AddToGroupRequest, ApprovalStatusResponse,
    DeleteSecretRequest, DeleteSecretResponse, ExportSecretsRequest, ExportSecretsResponse,
    GetApprovalStatusRequest, GetAuditLogRequest, GetAuditLogResponse, GetSecretInfoRequest,
    GetSecretRequest, GetSecretResponse, GetSecretsRequest, GetSecretsResponse, GrantAccessRequest,
    GrantInfo, HealthRequest, HealthResponse, ImportSecretsRequest, ImportSecretsResponse,
    InitHemRequest, InitHemResponse, IssueAgentTokenRequest, IssueServiceTokenRequest,
    IssueTokenResponse, ListActiveTokensRequest, ListActiveTokensResponse, ListGrantsRequest,
    ListGrantsResponse, ListGroupSecretsRequest, ListGroupSecretsResponse, ListGroupsRequest,
    ListGroupsResponse, ListPendingApprovalsRequest, ListPendingApprovalsResponse,
    ListSecretsRequest, ListSecretsResponse, PeerAckOperationsRequest, PeerAckOperationsResponse,
    PeerApproveCollisionRequest, PeerApproveCollisionResponse, PeerApproveReadRequest,
    PeerApproveReadResponse, PeerConsumeMasterApprovalReceiptRequest,
    PeerConsumeMasterApprovalReceiptResponse, PeerCosignCheckpointRequest,
    PeerCosignCheckpointResponse, PeerGetMasterApprovalStatusRequest,
    PeerGetMasterApprovalStatusResponse, PeerHelloRequest, PeerHelloResponse,
    PeerListOperationsRequest, PeerListOperationsResponse, PeerPushOperationsRequest,
    PeerPushOperationsResponse, PeerRouteMasterApprovalRequest, PeerRouteMasterApprovalResponse,
    RemoveFromGroupRequest, RemoveFromGroupResponse, ResolveApprovalRequest,
    ResolveApprovalResponse, RevokeAccessRequest, RevokeAccessResponse, RevokeTokenRequest,
    RevokeTokenResponse, RotateMasterKeyRequest, RotateMasterKeyResponse, ScanForSecretsRequest,
    ScanForSecretsResponse, SecretInfo, SetGroupRequest, SetSecretRequest, TokenInfo,
};

const DEFAULT_BIND: &str = "127.0.0.1:50091";
const DEFAULT_HEM_SUBDIR: &str = ".valhall/hem";
const CLUSTER_CONFIG_FILE: &str = "cluster.toml";
const NODE_IDENTITY_FILE: &str = "node-identity.json";
const DEFAULT_AGENT_TOKEN_TTL_SECS: u64 = 60 * 60;
const DEFAULT_SERVICE_TOKEN_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_OPERATOR_TOKEN_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const DEFAULT_APPROVAL_WAIT_TIMEOUT_MS: u64 = 5 * 60 * 1_000;
const APPROVAL_WAIT_POLL_INTERVAL_MS: u64 = 200;
const AUTHORIZATION_METADATA_KEY: &str = "authorization";
const APPROVAL_RECEIPT_METADATA_KEY: &str = "x-hem-approval-receipt";
const CLIENT_NAME_METADATA_KEY: &str = "x-hem-client-name";
const CLIENT_VERSION_METADATA_KEY: &str = "x-hem-client-version";
const CLIENT_PID_METADATA_KEY: &str = "x-hem-client-pid";
const CLIENT_CONTEXT_METADATA_KEY: &str = "x-hem-client-context";
const CLIENT_REQUEST_ID_METADATA_KEY: &str = "x-hem-request-id";
const CALLER_FINGERPRINT_METADATA_KEY: &str = "x-hem-caller-fingerprint";
const USER_AGENT_METADATA_KEY: &str = "user-agent";
const CLIENT_METADATA_VALUE_MAX_LEN: usize = 256;
const DEFAULT_GET_APPROVAL_REASON: &str = "read requires approval";
const DEFAULT_SET_APPROVAL_REASON: &str = "write requires approval";
const DEFAULT_SCAN_MIN_VALUE_LENGTH: u32 = 8;
const DEFAULT_CLUSTER_SYNC_INTERVAL_MS: u64 = 5_000;
const DEFAULT_CLUSTER_SYNC_BATCH_LIMIT: u32 = 1_000;
const DEFAULT_CLUSTER_SYNC_MAX_BACKOFF_MS: u64 = 30_000;
const CLUSTER_SYNC_CONNECT_TIMEOUT_SECS: u64 = 3;
const CLUSTER_SYNC_RPC_TIMEOUT_SECS: u64 = 10;
const READ_RECEIPT_MASTER_RETRY_ATTEMPTS: usize = 5;
const READ_RECEIPT_MASTER_RETRY_BACKOFF_MS: u64 = 200;
const PEER_TRANSPORT_AUTH_CLUSTER_ID_METADATA_KEY: &str = "x-hem-peer-cluster-id";
const PEER_TRANSPORT_AUTH_NODE_ID_METADATA_KEY: &str = "x-hem-peer-node-id";
const PEER_TRANSPORT_AUTH_METHOD_METADATA_KEY: &str = "x-hem-peer-method";
const PEER_TRANSPORT_AUTH_NONCE_METADATA_KEY: &str = "x-hem-peer-nonce";
const PEER_TRANSPORT_AUTH_TIMESTAMP_METADATA_KEY: &str = "x-hem-peer-timestamp";
const PEER_TRANSPORT_AUTH_SIGNATURE_METADATA_KEY: &str = "x-hem-peer-signature";
const PEER_TRANSPORT_AUTH_MAX_SKEW_SECS: i64 = 5 * 60;
const PEER_METHOD_APPROVE_COLLISION: &str = "PeerApproveCollision";
const PEER_METHOD_APPROVE_READ: &str = "PeerApproveRead";
const PEER_METHOD_CONSUME_MASTER_APPROVAL_RECEIPT: &str = "PeerConsumeMasterApprovalReceipt";
const PEER_METHOD_COSIGN_CHECKPOINT: &str = "PeerCosignCheckpoint";
const PEER_METHOD_GET_MASTER_APPROVAL_STATUS: &str = "PeerGetMasterApprovalStatus";
const PEER_METHOD_HELLO: &str = "PeerHello";
const PEER_METHOD_LIST_OPERATIONS: &str = "PeerListOperations";
const PEER_METHOD_PUSH_OPERATIONS: &str = "PeerPushOperations";
const PEER_METHOD_ACK_OPERATIONS: &str = "PeerAckOperations";
const PEER_METHOD_ROUTE_MASTER_APPROVAL: &str = "PeerRouteMasterApproval";

#[derive(Debug, Parser)]
#[command(name = "hemd", about = "Valhall Hem daemon")]
struct Cli {
    #[arg(long, default_value = DEFAULT_BIND)]
    bind: String,
    #[arg(long)]
    data_dir: Option<String>,
    #[arg(long)]
    once: bool,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    #[command(visible_alias = "u")]
    Usage,
}

#[derive(Clone)]
struct HemRuntimeService {
    data_dir: PathBuf,
    approval_provider: Arc<dyn ApprovalProvider>,
    mesh: Option<Arc<Mesh>>,
    cluster_runtime: ClusterRuntimeInfo,
    peer_nonce_cache: Arc<Mutex<HashMap<String, i64>>>,
}

impl HemRuntimeService {
    fn new(
        data_dir: PathBuf,
        mesh: Option<Arc<Mesh>>,
        cluster_runtime: ClusterRuntimeInfo,
    ) -> Self {
        let approval_provider = Arc::new(LocalApprovalProvider::new(data_dir.clone()));
        Self {
            data_dir,
            approval_provider,
            mesh,
            cluster_runtime,
            peer_nonce_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn open_store(&self) -> Result<HemStore, Status> {
        HemStore::open(self.data_dir.as_path()).map_err(status_from_hem)
    }

    fn require_cluster_identity(&self) -> Result<(String, String), Status> {
        if !self.cluster_runtime.enabled {
            return Err(Status::failed_precondition("hem cluster is not enabled"));
        }
        let cluster_id = self
            .cluster_runtime
            .cluster_id
            .clone()
            .ok_or_else(|| Status::failed_precondition("hem cluster_id is unavailable"))?;
        let node_id = self
            .cluster_runtime
            .node_id
            .clone()
            .ok_or_else(|| Status::failed_precondition("hem cluster node_id is unavailable"))?;
        Ok((cluster_id, node_id))
    }

    fn require_master_approval_node(&self, node_id: &str) -> Result<(), Status> {
        if self.cluster_runtime.master_node_id.as_deref() != Some(node_id) {
            return Err(Status::failed_precondition(format!(
                "local node {node_id} is not the cluster master approval node"
            )));
        }
        Ok(())
    }

    fn require_configured_peer_requester(
        &self,
        request_cluster_id: &str,
        requester_node_id: &str,
        requester_public_key: &str,
    ) -> Result<(), Status> {
        validate_peer_request_subject("requester node_id", requester_node_id)?;
        validate_peer_request_subject("requester public_key", requester_public_key)?;
        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        if config.cluster_id != request_cluster_id {
            return Err(Status::permission_denied(format!(
                "request cluster_id {request_cluster_id} does not match local cluster_id {}",
                config.cluster_id
            )));
        }
        let requester = config
            .peers
            .iter()
            .find(|peer| peer.node_id == requester_node_id)
            .ok_or_else(|| {
                Status::permission_denied(format!(
                    "requester node {requester_node_id} is not a configured cluster peer"
                ))
            })?;
        if requester.public_key != requester_public_key {
            return Err(Status::permission_denied(format!(
                "requester public key mismatch for node {requester_node_id}"
            )));
        }
        Ok(())
    }

    fn verify_peer_transport_auth<T>(
        &self,
        request: &Request<T>,
        method: &str,
    ) -> Result<Option<PeerConfig>, Status> {
        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        if config.peers.is_empty() {
            return Ok(None);
        }

        let metadata = request.metadata();
        let cluster_id =
            required_peer_metadata(metadata, PEER_TRANSPORT_AUTH_CLUSTER_ID_METADATA_KEY)?;
        let node_id = required_peer_metadata(metadata, PEER_TRANSPORT_AUTH_NODE_ID_METADATA_KEY)?;
        let signed_method =
            required_peer_metadata(metadata, PEER_TRANSPORT_AUTH_METHOD_METADATA_KEY)?;
        let nonce = required_peer_metadata(metadata, PEER_TRANSPORT_AUTH_NONCE_METADATA_KEY)?;
        let timestamp =
            required_peer_metadata(metadata, PEER_TRANSPORT_AUTH_TIMESTAMP_METADATA_KEY)?;
        let signature =
            required_peer_metadata(metadata, PEER_TRANSPORT_AUTH_SIGNATURE_METADATA_KEY)?;

        validate_peer_request_subject("peer auth cluster_id", cluster_id)?;
        validate_peer_request_subject("peer auth node_id", node_id)?;
        validate_peer_request_subject("peer auth method", signed_method)?;
        validate_peer_request_subject("peer auth nonce", nonce)?;
        if cluster_id != config.cluster_id {
            return Err(Status::unauthenticated(format!(
                "peer auth cluster_id {cluster_id} does not match local cluster_id {}",
                config.cluster_id
            )));
        }
        if signed_method != method {
            return Err(Status::unauthenticated(format!(
                "peer auth method {signed_method} does not match rpc method {method}"
            )));
        }

        let timestamp_unix = timestamp.parse::<i64>().map_err(|err| {
            Status::unauthenticated(format!("peer auth timestamp is invalid: {err}"))
        })?;
        let now = Utc::now().timestamp();
        if timestamp_unix < now - PEER_TRANSPORT_AUTH_MAX_SKEW_SECS
            || timestamp_unix > now + PEER_TRANSPORT_AUTH_MAX_SKEW_SECS
        {
            return Err(Status::unauthenticated(
                "peer auth timestamp is stale or from the future",
            ));
        }

        let peer = config
            .peers
            .iter()
            .find(|peer| peer.node_id == node_id)
            .cloned()
            .ok_or_else(|| {
                Status::unauthenticated(format!(
                    "peer auth node {node_id} is not a configured cluster peer"
                ))
            })?;
        let statement_bytes = peer_transport_auth_statement_bytes(
            cluster_id,
            node_id,
            signed_method,
            nonce,
            timestamp_unix,
        )
        .map_err(status_from_hem)?;
        verify_node_statement_signature(
            peer.public_key.as_str(),
            statement_bytes.as_slice(),
            signature,
        )
        .map_err(|err| Status::unauthenticated(format!("peer auth signature invalid: {err}")))?;

        let nonce_key = format!("{cluster_id}\0{node_id}\0{signed_method}\0{nonce}");
        let mut nonce_cache = self
            .peer_nonce_cache
            .lock()
            .map_err(|_| Status::internal("peer auth nonce cache poisoned"))?;
        let oldest_allowed = now - PEER_TRANSPORT_AUTH_MAX_SKEW_SECS;
        nonce_cache.retain(|_, seen_timestamp| *seen_timestamp >= oldest_allowed);
        if nonce_cache.contains_key(nonce_key.as_str()) {
            return Err(Status::unauthenticated("replayed peer request nonce"));
        }
        nonce_cache.insert(nonce_key, timestamp_unix);

        Ok(Some(peer))
    }

    fn require_authenticated_peer_subject(
        &self,
        authenticated_peer: Option<&PeerConfig>,
        requester_node_id: &str,
        requester_public_key: &str,
    ) -> Result<(), Status> {
        if let Some(peer) = authenticated_peer {
            if requester_node_id != peer.node_id {
                return Err(Status::unauthenticated(format!(
                    "requester node_id {requester_node_id} does not match authenticated peer {}",
                    peer.node_id
                )));
            }
            if requester_public_key != peer.public_key {
                return Err(Status::unauthenticated(format!(
                    "requester public key mismatch for authenticated peer {}",
                    peer.node_id
                )));
            }
        }
        Ok(())
    }

    fn parse_secret_ref(
        &self,
        secret: Option<proto::SecretRef>,
    ) -> Result<(SecretScope, String), Status> {
        let secret = secret.ok_or_else(|| Status::invalid_argument("missing secret ref"))?;
        let scope = parse_scope_selector_or_global(secret.scope)?;
        let name = parse_secret_name(secret.name.as_str())?;
        Ok((scope, name))
    }

    fn get_secret_with_distributed_fallback(
        &self,
        store: &HemStore,
        scope: &SecretScope,
        name: &str,
        actor: Option<&str>,
    ) -> Result<CoreSecretWithValues, Status> {
        match store.get_secret(scope, name, actor) {
            Ok(secret) => Ok(secret),
            Err(HemError::SecretNotFound(_)) => {
                self.get_distributed_secret_from_ledger(store, scope, name)
            }
            Err(err) => Err(status_from_hem(err)),
        }
    }

    fn get_distributed_secret_from_ledger(
        &self,
        store: &HemStore,
        scope: &SecretScope,
        name: &str,
    ) -> Result<CoreSecretWithValues, Status> {
        if !self.cluster_runtime.enabled {
            return Err(secret_not_found_status(scope, name));
        }
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let identity = NodeIdentity::load(self.data_dir.join(NODE_IDENTITY_FILE).as_path())
            .map_err(status_from_hem)?;
        if identity.node_id != node_id {
            return Err(Status::failed_precondition(format!(
                "hem cluster node identity mismatch: runtime={} identity={}",
                node_id, identity.node_id
            )));
        }
        let private_key = identity.wrap_private_key_b64.as_deref().ok_or_else(|| {
            Status::failed_precondition(format!(
                "node {node_id} cannot decrypt distributed ledger secrets without a wrap private key"
            ))
        })?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        ledger
            .materialize_secret_metadata()
            .map_err(status_from_hem)?;
        ledger
            .materialize_secret_value_versions()
            .map_err(status_from_hem)?;

        let scope = scope.clone();
        let scope_label = scope_label(&scope);
        let metadata = ledger
            .get_materialized_secret_metadata(cluster_id.as_str(), scope_label.as_str(), name)
            .map_err(status_from_hem)?
            .ok_or_else(|| secret_not_found_status(&scope, name))?;
        let versions = ledger
            .list_latest_secret_value_versions(cluster_id.as_str(), scope_label.as_str(), name)
            .map_err(status_from_hem)?;
        let mut values = HashMap::new();
        for version in versions {
            let envelope: EnvelopeEncryptedValue =
                serde_json::from_value(version.encrypted_value_json.clone()).map_err(|err| {
                    Status::failed_precondition(format!(
                        "distributed secret value {} is not node-envelope encrypted: {err}",
                        version.key
                    ))
                })?;
            let aad = format!("{}:{name}:{}", scope_label, version.key);
            let plain =
                envelope_decrypt_for_node(&envelope, aad.as_bytes(), node_id.as_str(), private_key)
                    .map_err(status_from_hem)?;
            values.insert(version.key, plain);
        }

        Ok(CoreSecretWithValues {
            info: CoreSecretInfo {
                scope,
                name: metadata.name,
                description: metadata.description,
                requires_approval: metadata.requires_approval,
                group: metadata.group,
                created_at: metadata.updated_at,
                updated_at: metadata.updated_at,
                created_by: metadata.updated_by,
                last_accessed_at: None,
                last_accessed_by: None,
            },
            values,
        })
    }

    fn list_distributed_secret_infos(
        &self,
        store: &HemStore,
        scope: Option<&SecretScope>,
    ) -> Result<Vec<CoreSecretInfo>, Status> {
        if !self.cluster_runtime.enabled {
            return Ok(Vec::new());
        }
        let (cluster_id, _) = self.require_cluster_identity()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        ledger
            .materialize_secret_metadata()
            .map_err(status_from_hem)?;
        let scope_label = scope.map(scope_label);
        let metadata = ledger
            .list_materialized_secret_metadata(cluster_id.as_str(), scope_label.as_deref())
            .map_err(status_from_hem)?;
        metadata
            .into_iter()
            .map(secret_info_from_ledger_metadata)
            .collect()
    }

    fn resolve_secret_by_name(
        &self,
        store: &HemStore,
        name: &str,
        context: Option<proto::ScopeResolutionContext>,
        actor: Option<&str>,
        claims: Option<&TokenClaims>,
    ) -> Result<CoreSecretWithValues, Status> {
        let context = to_resolution_context(context);
        let mut denied = false;
        for scope in resolution_chain(&context) {
            if let Some(claims) = claims {
                let has_grant = self.has_explicit_read_grant(store, claims, &scope, name)?;
                if authorize_read(claims, &scope, has_grant).is_err() {
                    denied = true;
                    continue;
                }
            }
            match self.get_secret_with_distributed_fallback(store, &scope, name, actor) {
                Ok(secret) => return Ok(secret),
                Err(status) if status.code() == tonic::Code::NotFound => continue,
                Err(status) => return Err(status),
            }
        }

        if denied {
            return Err(Status::permission_denied(format!(
                "not authorized to read secret: {name}"
            )));
        }
        Err(Status::not_found(format!("secret not found: {name}")))
    }

    fn resolve_lookup_secret(
        &self,
        store: &HemStore,
        lookup: Option<get_secret_request::Lookup>,
        context: Option<proto::ScopeResolutionContext>,
        actor: Option<&str>,
        claims: Option<&TokenClaims>,
    ) -> Result<CoreSecretWithValues, Status> {
        match lookup.ok_or_else(|| Status::invalid_argument("missing secret lookup"))? {
            get_secret_request::Lookup::Secret(secret_ref) => {
                let (scope, name) = self.parse_secret_ref(Some(secret_ref))?;
                if let Some(claims) = claims {
                    let has_grant =
                        self.has_explicit_read_grant(store, claims, &scope, name.as_str())?;
                    authorize_read(claims, &scope, has_grant).map_err(status_from_hem)?;
                }
                self.get_secret_with_distributed_fallback(store, &scope, name.as_str(), actor)
            }
            get_secret_request::Lookup::Name(name) => {
                let name = parse_secret_name(name.as_str())?;
                self.resolve_secret_by_name(store, name.as_str(), context, actor, claims)
            }
        }
    }

    fn resolve_lookup_secret_info(
        &self,
        store: &HemStore,
        lookup: Option<get_secret_info_request::Lookup>,
        context: Option<proto::ScopeResolutionContext>,
        claims: Option<&TokenClaims>,
    ) -> Result<CoreSecretInfo, Status> {
        match lookup.ok_or_else(|| Status::invalid_argument("missing secret lookup"))? {
            get_secret_info_request::Lookup::Secret(secret_ref) => {
                let (scope, name) = self.parse_secret_ref(Some(secret_ref))?;
                if let Some(claims) = claims {
                    let has_grant =
                        self.has_explicit_read_grant(store, claims, &scope, name.as_str())?;
                    authorize_read(claims, &scope, has_grant).map_err(status_from_hem)?;
                }
                store
                    .get_secret_info(&scope, name.as_str())
                    .map_err(status_from_hem)
            }
            get_secret_info_request::Lookup::Name(name) => {
                let name = parse_secret_name(name.as_str())?;
                resolve_secret_info_by_name(store, name.as_str(), context, claims)
            }
        }
    }

    fn require_caller<T>(
        &self,
        store: &HemStore,
        request: &Request<T>,
    ) -> Result<CallerPrincipal, Status> {
        let token = parse_authorization_header(request.metadata())?;
        let manager = store.token_manager().map_err(status_from_hem)?;
        let claims = manager
            .verify_token(token.as_str())
            .map_err(status_from_hem)?;
        let token_id = claims.token_id.clone();
        let is_operator = matches!(claims.token_type, TokenType::Operator);
        Ok(CallerPrincipal {
            actor: format!("token:{token_id}"),
            token_id,
            claims,
            is_operator,
            client: parse_client_metadata(request.metadata()),
            transport: Some(CoreAuditTransportInfo {
                kind: Some("tcp".to_string()),
                remote_addr: request.remote_addr().map(|addr| addr.to_string()),
                user_agent: metadata_string(request.metadata(), USER_AGENT_METADATA_KEY),
            }),
        })
    }

    fn has_explicit_read_grant(
        &self,
        store: &HemStore,
        claims: &TokenClaims,
        secret_scope: &SecretScope,
        secret_name: &str,
    ) -> Result<bool, Status> {
        has_explicit_read_grant(store, claims, secret_scope, secret_name)
    }

    fn audit(
        &self,
        store: &HemStore,
        caller: Option<&CallerPrincipal>,
        action: &str,
        secret: Option<(&SecretScope, &str)>,
        result: &str,
        details: &str,
    ) {
        self.audit_with_key(store, caller, action, secret, None, result, details);
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_with_key(
        &self,
        store: &HemStore,
        caller: Option<&CallerPrincipal>,
        action: &str,
        secret: Option<(&SecretScope, &str)>,
        key: Option<&str>,
        result: &str,
        details: &str,
    ) {
        let audit_store = match store.audit_store() {
            Ok(value) => value,
            Err(err) => {
                warn!(error = %err, "failed to open audit store");
                return;
            }
        };

        let (secret_scope, secret_name) = match secret {
            Some((scope, name)) => (Some(scope.clone()), name.to_string()),
            None => (None, String::new()),
        };
        let (actor, token_id) = match caller {
            Some(caller) => (caller.actor.clone(), caller.token_id.clone()),
            None => ("unknown".to_string(), String::new()),
        };
        let token = caller.map(|caller| CoreAuditTokenInfo {
            token_type: caller.claims.token_type.clone(),
            service_name: caller.claims.service_name.clone(),
            identity_id: caller.claims.identity_id.clone(),
            project: caller.claims.project.clone(),
            issued_by: caller.claims.issued_by.clone(),
            issued_at: caller.claims.issued_at,
            expires_at: caller.claims.expires_at,
        });
        let client = caller.and_then(|caller| caller.client.clone());
        let transport = caller.and_then(|caller| caller.transport.clone());
        let warnings = audit_warnings(action, caller);
        let entry = CoreAuditEntry {
            schema_version: hem_core::AUDIT_SCHEMA_VERSION,
            audit_id: valhall_config::ids::generate_prefixed_entropy_id("aud"),
            ts: Utc::now(),
            action: action.to_string(),
            actor,
            token_id,
            token,
            client,
            transport,
            secret_scope,
            secret_name,
            key: key.map(str::to_string),
            result: result.to_string(),
            details: details.to_string(),
            warnings,
        };

        if let Err(err) = audit_store.append(&entry) {
            warn!(error = %err, "failed to append audit entry");
        }
    }

    async fn append_signed_read_receipts(
        &self,
        store: &HemStore,
        caller: &CallerPrincipal,
        secret: &CoreSecretWithValues,
        policy_decision: &str,
        approval_reference: &str,
    ) -> Result<(), Status> {
        if !self.cluster_runtime.enabled {
            return Ok(());
        }
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let identity_path = self.data_dir.join(NODE_IDENTITY_FILE);
        let identity = NodeIdentity::load(identity_path.as_path()).map_err(status_from_hem)?;
        if identity.node_id != node_id {
            return Err(Status::failed_precondition(format!(
                "hem cluster node identity mismatch: runtime={} identity={}",
                node_id, identity.node_id
            )));
        }
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        let keys = sorted_secret_keys(secret.values.keys());
        let receipt_id = format!(
            "hrr_{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        );
        if !self.cluster_runtime.is_master_node() {
            self.submit_read_receipts_to_master(
                &ledger,
                &identity,
                cluster_id.as_str(),
                ReadReceiptDraft {
                    caller,
                    secret,
                    policy_decision,
                    approval_reference,
                    receipt_id: receipt_id.as_str(),
                    keys: keys.as_slice(),
                },
            )
            .await?;
            return Ok(());
        }
        let requested_payload = serde_json::json!({
            "receipt_id": receipt_id,
            "requester": caller.actor.as_str(),
            "token_id": caller.token_id.as_str(),
            "secret_scope": scope_label(&secret.info.scope),
            "secret_name": secret.info.name.as_str(),
            "keys": keys.clone(),
            "version": secret.info.updated_at.to_rfc3339(),
            "policy_decision": policy_decision,
            "approval_reference": approval_reference,
            "plaintext_included": false,
        });
        let node_seq = ledger
            .node_high_watermark(identity.node_id.as_str())
            .map_err(status_from_hem)?
            + 1;
        let requested_input = self.cluster_ledger_operation_input(
            &identity,
            cluster_id.as_str(),
            node_seq,
            "read.requested",
            requested_payload,
        );
        let requested = ledger
            .sign_next(&identity, requested_input)
            .map_err(status_from_hem)?;
        let fulfilled_payload = serde_json::json!({
            "receipt_id": receipt_id,
            "read_request_operation_id": requested.body.operation_id,
            "requester": caller.actor.as_str(),
            "token_id": caller.token_id.as_str(),
            "secret_scope": scope_label(&secret.info.scope),
            "secret_name": secret.info.name.as_str(),
            "keys": sorted_secret_keys(secret.values.keys()),
            "version": secret.info.updated_at.to_rfc3339(),
            "policy_decision": policy_decision,
            "approval_reference": approval_reference,
            "released_key_count": secret.values.len(),
            "plaintext_included": false,
        });
        let fulfilled_input = self.cluster_ledger_operation_input(
            &identity,
            cluster_id.as_str(),
            node_seq + 1,
            "read.fulfilled",
            fulfilled_payload,
        );
        let fulfilled = hem_core::LedgerStore::sign_after(
            &identity,
            fulfilled_input,
            requested.body_hash_b64.clone(),
        )
        .map_err(status_from_hem)?;
        self.append_or_confirm_signed(&ledger, &requested)?;
        self.append_or_confirm_signed(&ledger, &fulfilled)?;
        Ok(())
    }

    fn cluster_ledger_operation_input(
        &self,
        identity: &NodeIdentity,
        cluster_id: &str,
        node_seq: i64,
        op_type: &str,
        payload_json: serde_json::Value,
    ) -> CoreLedgerOperationInput {
        CoreLedgerOperationInput {
            operation_id: format!(
                "hop_{}",
                valhall_config::ids::generate_entropy_prefixed_ulid()
            ),
            cluster_id: cluster_id.to_string(),
            node_id: identity.node_id.clone(),
            node_seq,
            op_type: op_type.to_string(),
            payload_json,
            created_at: Utc::now(),
        }
    }

    fn append_or_confirm_signed(
        &self,
        ledger: &hem_core::LedgerStore,
        envelope: &CoreLedgerOperationEnvelope,
    ) -> Result<(), Status> {
        if let Some(existing) = ledger
            .get_by_operation_id(envelope.body.operation_id.as_str())
            .map_err(status_from_hem)?
        {
            if existing.body_hash_b64 == envelope.body_hash_b64 {
                return Ok(());
            }
            return Err(Status::already_exists(format!(
                "ledger operation {} already exists with a different hash",
                envelope.body.operation_id
            )));
        }
        ledger.append_signed(envelope).map_err(status_from_hem)?;
        Ok(())
    }

    async fn submit_read_receipts_to_master(
        &self,
        ledger: &hem_core::LedgerStore,
        identity: &NodeIdentity,
        cluster_id: &str,
        draft: ReadReceiptDraft<'_>,
    ) -> Result<(), Status> {
        let (master_cluster_id, master_identity, master_peer) = self.remote_master_peer()?;
        if master_cluster_id != cluster_id {
            return Err(Status::failed_precondition(
                "remote master cluster_id changed while appending read receipt",
            ));
        }
        if master_identity.node_id != identity.node_id {
            return Err(Status::failed_precondition(
                "local node identity changed while appending read receipt",
            ));
        }
        let mut pending_envelopes: Option<Vec<CoreLedgerOperationEnvelope>> = None;
        let mut last_error: Option<Status> = None;
        for attempt in 0..READ_RECEIPT_MASTER_RETRY_ATTEMPTS {
            let mut client = match self.connect_cluster_peer(&master_peer).await {
                Ok(client) => client,
                Err(err) => {
                    last_error = Some(err);
                    self.delay_master_read_receipt_retry(
                        attempt,
                        &last_error,
                        cluster_id,
                        identity,
                        &master_peer,
                    )
                    .await;
                    continue;
                }
            };
            if let Err(err) = self
                .pull_master_ledger_operations(&mut client, ledger, identity, cluster_id)
                .await
            {
                last_error = Some(err);
                self.delay_master_read_receipt_retry(
                    attempt,
                    &last_error,
                    cluster_id,
                    identity,
                    &master_peer,
                )
                .await;
                continue;
            }
            if let Some(envelopes) = pending_envelopes.as_ref() {
                if self.signed_envelopes_are_local(ledger, envelopes)? {
                    return Ok(());
                }
            }

            let envelopes = match pending_envelopes.take() {
                Some(envelopes) => envelopes,
                None => self.sign_read_receipt_envelopes(ledger, identity, cluster_id, &draft)?,
            };
            let response = client
                .peer_push_operations(
                    signed_peer_transport_request(
                        PeerPushOperationsRequest {
                            operations: envelopes.iter().map(to_proto_ledger_envelope).collect(),
                        },
                        identity,
                        cluster_id,
                        PEER_METHOD_PUSH_OPERATIONS,
                    )
                    .map_err(status_from_hem)?,
                )
                .await;
            match response {
                Ok(_) => match self
                    .append_master_accepted_read_receipts(
                        ledger,
                        identity,
                        cluster_id,
                        &master_peer,
                        &envelopes,
                    )
                    .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        pending_envelopes = Some(envelopes);
                        last_error = Some(err);
                    }
                },
                Err(err) => {
                    if read_receipt_push_error_requires_resign(&err) {
                        pending_envelopes = None;
                    } else {
                        pending_envelopes = Some(envelopes);
                    }
                    last_error = Some(err);
                }
            }
            self.delay_master_read_receipt_retry(
                attempt,
                &last_error,
                cluster_id,
                identity,
                &master_peer,
            )
            .await;
        }
        Err(last_error.unwrap_or_else(|| {
            Status::aborted("master read receipt append failed without a transport status")
        }))
    }

    async fn delay_master_read_receipt_retry(
        &self,
        attempt: usize,
        last_error: &Option<Status>,
        cluster_id: &str,
        identity: &NodeIdentity,
        master_peer: &PeerConfig,
    ) {
        if attempt + 1 >= READ_RECEIPT_MASTER_RETRY_ATTEMPTS {
            return;
        }
        let backoff = Duration::from_millis(
            READ_RECEIPT_MASTER_RETRY_BACKOFF_MS.saturating_mul((attempt as u64) + 1),
        );
        if let Some(err) = last_error {
            warn!(
                cluster_id = %cluster_id,
                node_id = %identity.node_id,
                master_node_id = %master_peer.node_id,
                master_endpoint = %master_peer.endpoint,
                attempt = attempt + 1,
                max_attempts = READ_RECEIPT_MASTER_RETRY_ATTEMPTS,
                backoff_ms = duration_millis_u64(backoff),
                error = %err,
                "hem master read receipt append attempt failed"
            );
        }
        tokio::time::sleep(backoff).await;
    }

    fn signed_envelopes_are_local(
        &self,
        ledger: &hem_core::LedgerStore,
        envelopes: &[CoreLedgerOperationEnvelope],
    ) -> Result<bool, Status> {
        for envelope in envelopes {
            if let Some(existing) = ledger
                .get_by_operation_id(envelope.body.operation_id.as_str())
                .map_err(status_from_hem)?
            {
                if existing.body_hash_b64 == envelope.body_hash_b64 {
                    continue;
                }
                return Err(Status::already_exists(format!(
                    "ledger operation {} already exists with a different hash",
                    envelope.body.operation_id
                )));
            }
            return Ok(false);
        }
        Ok(true)
    }

    async fn append_master_accepted_read_receipts(
        &self,
        ledger: &hem_core::LedgerStore,
        identity: &NodeIdentity,
        cluster_id: &str,
        master_peer: &PeerConfig,
        envelopes: &[CoreLedgerOperationEnvelope],
    ) -> Result<(), Status> {
        for envelope in envelopes {
            if let Err(err) = self.append_or_confirm_signed(ledger, envelope) {
                let mut refresh_client = self.connect_cluster_peer(master_peer).await?;
                self.pull_master_ledger_operations(
                    &mut refresh_client,
                    ledger,
                    identity,
                    cluster_id,
                )
                .await?;
                self.append_or_confirm_signed(ledger, envelope)
                    .map_err(|_| err)?;
            }
        }
        Ok(())
    }

    fn sign_read_receipt_envelopes(
        &self,
        ledger: &hem_core::LedgerStore,
        identity: &NodeIdentity,
        cluster_id: &str,
        draft: &ReadReceiptDraft<'_>,
    ) -> Result<Vec<CoreLedgerOperationEnvelope>, Status> {
        let node_seq = ledger
            .node_high_watermark(identity.node_id.as_str())
            .map_err(status_from_hem)?
            + 1;
        let requested_payload = serde_json::json!({
            "receipt_id": draft.receipt_id,
            "requester": draft.caller.actor.as_str(),
            "token_id": draft.caller.token_id.as_str(),
            "secret_scope": scope_label(&draft.secret.info.scope),
            "secret_name": draft.secret.info.name.as_str(),
            "keys": draft.keys,
            "version": draft.secret.info.updated_at.to_rfc3339(),
            "policy_decision": draft.policy_decision,
            "approval_reference": draft.approval_reference,
            "plaintext_included": false,
        });
        let requested = ledger
            .sign_next(
                identity,
                self.cluster_ledger_operation_input(
                    identity,
                    cluster_id,
                    node_seq,
                    "read.requested",
                    requested_payload,
                ),
            )
            .map_err(status_from_hem)?;
        let fulfilled_payload = serde_json::json!({
            "receipt_id": draft.receipt_id,
            "read_request_operation_id": requested.body.operation_id,
            "requester": draft.caller.actor.as_str(),
            "token_id": draft.caller.token_id.as_str(),
            "secret_scope": scope_label(&draft.secret.info.scope),
            "secret_name": draft.secret.info.name.as_str(),
            "keys": draft.keys,
            "version": draft.secret.info.updated_at.to_rfc3339(),
            "policy_decision": draft.policy_decision,
            "approval_reference": draft.approval_reference,
            "released_key_count": draft.secret.values.len(),
            "plaintext_included": false,
        });
        let fulfilled = hem_core::LedgerStore::sign_after(
            identity,
            self.cluster_ledger_operation_input(
                identity,
                cluster_id,
                node_seq + 1,
                "read.fulfilled",
                fulfilled_payload,
            ),
            requested.body_hash_b64.clone(),
        )
        .map_err(status_from_hem)?;
        Ok(vec![requested, fulfilled])
    }

    async fn pull_master_ledger_operations(
        &self,
        client: &mut HemRuntimeClient<tonic::transport::Channel>,
        ledger: &hem_core::LedgerStore,
        identity: &NodeIdentity,
        cluster_id: &str,
    ) -> Result<(), Status> {
        loop {
            let after_position = ledger.latest_position().map_err(status_from_hem)?;
            let response = client
                .peer_list_operations(
                    signed_peer_transport_request(
                        PeerListOperationsRequest {
                            after_position,
                            limit: DEFAULT_CLUSTER_SYNC_BATCH_LIMIT,
                            peer_node_id: identity.node_id.clone(),
                            use_recorded_cursor: false,
                        },
                        identity,
                        cluster_id,
                        PEER_METHOD_LIST_OPERATIONS,
                    )
                    .map_err(status_from_hem)?,
                )
                .await?
                .into_inner();
            if response.operations.is_empty() {
                return Ok(());
            }
            let operation_count = response.operations.len();
            let envelopes = response
                .operations
                .into_iter()
                .map(from_proto_ledger_operation)
                .collect::<Result<Vec<_>, _>>()?;
            ledger
                .bootstrap_from_peer_operations(cluster_id, &envelopes)
                .map_err(status_from_hem)?;
            if operation_count < DEFAULT_CLUSTER_SYNC_BATCH_LIMIT as usize {
                return Ok(());
            }
        }
    }

    fn cluster_ledger_context(&self) -> Result<Option<(String, NodeIdentity)>, Status> {
        if !self.cluster_runtime.enabled {
            return Ok(None);
        }
        let cluster_id = self
            .cluster_runtime
            .cluster_id
            .clone()
            .ok_or_else(|| Status::failed_precondition("hem cluster_id is unavailable"))?;
        let expected_node_id = self
            .cluster_runtime
            .node_id
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("hem cluster node_id is unavailable"))?;
        let identity = NodeIdentity::load(self.data_dir.join(NODE_IDENTITY_FILE).as_path())
            .map_err(status_from_hem)?;
        if identity.node_id != expected_node_id {
            return Err(Status::failed_precondition(format!(
                "node identity mismatch: runtime node_id={} identity node_id={}",
                expected_node_id, identity.node_id
            )));
        }
        Ok(Some((cluster_id, identity)))
    }

    fn append_cluster_secret_set(
        &self,
        store: &HemStore,
        scope: &SecretScope,
        name: &str,
        actor: &str,
    ) -> Result<(), Status> {
        let Some((cluster_id, identity)) = self.cluster_ledger_context()? else {
            return Ok(());
        };
        let recipients = self.cluster_key_recipients(&identity)?;
        store
            .append_secret_set_to_ledger_for_nodes(
                cluster_id.as_str(),
                &identity,
                scope,
                name,
                actor,
                recipients.as_slice(),
            )
            .map_err(status_from_hem)?;
        Ok(())
    }

    fn cluster_key_recipients(
        &self,
        identity: &NodeIdentity,
    ) -> Result<Vec<NodeKeyRecipient>, Status> {
        let mut recipients = Vec::new();
        if let Some(public_key) = identity.wrap_public_key_b64.as_ref() {
            recipients.push(NodeKeyRecipient {
                node_id: identity.node_id.clone(),
                public_key_b64: public_key.clone(),
            });
        }
        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        for peer in &config.peers {
            if let Some(public_key) = peer.wrap_public_key.as_ref() {
                recipients.push(NodeKeyRecipient {
                    node_id: peer.node_id.clone(),
                    public_key_b64: public_key.clone(),
                });
            }
        }
        Ok(recipients)
    }

    fn append_cluster_secret_metadata(
        &self,
        store: &HemStore,
        scope: &SecretScope,
        name: &str,
        actor: &str,
    ) -> Result<(), Status> {
        let Some((cluster_id, identity)) = self.cluster_ledger_context()? else {
            return Ok(());
        };
        store
            .append_secret_metadata_to_ledger(cluster_id.as_str(), &identity, scope, name, actor)
            .map_err(status_from_hem)?;
        Ok(())
    }

    fn append_cluster_event_operation(
        &self,
        store: &HemStore,
        op_type: &str,
        payload_json: serde_json::Value,
    ) -> Result<(), Status> {
        let Some((cluster_id, identity)) = self.cluster_ledger_context()? else {
            return Ok(());
        };
        store
            .append_signed_ledger_operation(
                cluster_id.as_str(),
                &identity,
                op_type,
                payload_json,
                Utc::now(),
            )
            .map_err(status_from_hem)?;
        Ok(())
    }

    async fn enforce_read_policy(
        &self,
        store: &HemStore,
        caller: &CallerPrincipal,
        secret: &CoreSecretWithValues,
        approval_reference: &str,
    ) -> Result<ReadPolicyOutcome, Status> {
        if !self.cluster_runtime.enabled {
            return Ok(ReadPolicyOutcome {
                decision: if secret.info.requires_approval {
                    if caller.is_operator {
                        "operator".to_string()
                    } else {
                        "approval_receipt".to_string()
                    }
                } else {
                    "authorized".to_string()
                },
                reference: approval_reference.to_string(),
            });
        }

        let policy_store = store.policy_store().map_err(status_from_hem)?;
        let tier = policy_store
            .effective_policy(&secret.info.scope, secret.info.name.as_str())
            .map_err(status_from_hem)?;
        if !self.cluster_runtime.force_offline {
            if tier == SecretPolicyTier::PeerQuorum {
                let reference = self
                    .require_peer_quorum(store, caller, secret, approval_reference)
                    .await?;
                return Ok(ReadPolicyOutcome {
                    decision: tier.as_str().to_string(),
                    reference,
                });
            }
            return Ok(ReadPolicyOutcome {
                decision: tier.as_str().to_string(),
                reference: approval_reference.to_string(),
            });
        }

        match tier {
            SecretPolicyTier::LocalLogged => Ok(ReadPolicyOutcome {
                decision: SecretPolicyTier::LocalLogged.as_str().to_string(),
                reference: approval_reference.to_string(),
            }),
            SecretPolicyTier::OfflineLease => {
                let node_id =
                    self.cluster_runtime.node_id.as_deref().ok_or_else(|| {
                        Status::failed_precondition("hem cluster node_id missing")
                    })?;
                let lease = policy_store
                    .consume_offline_lease(
                        &secret.info.scope,
                        secret.info.name.as_str(),
                        caller.actor.as_str(),
                        node_id,
                    )
                    .map_err(|err| Status::failed_precondition(err.to_string()))?;
                Ok(ReadPolicyOutcome {
                    decision: SecretPolicyTier::OfflineLease.as_str().to_string(),
                    reference: lease.lease_id,
                })
            }
            SecretPolicyTier::PeerQuorum => Err(Status::failed_precondition(
                "secret read policy peer_quorum requires reachable peer quorum",
            )),
            SecretPolicyTier::MasterBiometric => Err(Status::failed_precondition(
                "secret read policy master_biometric requires reachable master approval",
            )),
        }
    }

    async fn require_peer_quorum(
        &self,
        store: &HemStore,
        caller: &CallerPrincipal,
        secret: &CoreSecretWithValues,
        upstream_approval_reference: &str,
    ) -> Result<String, Status> {
        let Some((cluster_id, identity)) = self.cluster_ledger_context()? else {
            return Err(Status::failed_precondition("hem cluster is not enabled"));
        };
        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        if config.cluster_id != cluster_id || config.node_id != identity.node_id {
            return Err(Status::failed_precondition(
                "hem cluster config does not match active node identity",
            ));
        }

        let required_peer_acks = usize::from(config.quorum.saturating_sub(1));
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        let requester_latest_position = ledger.latest_position().map_err(status_from_hem)?;
        let requester_latest_body_hash_b64 = ledger
            .latest_body_hash()
            .map_err(status_from_hem)?
            .unwrap_or_default();
        let nonce = format!(
            "hqn_{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        );
        let secret_scope = scope_label(&secret.info.scope);
        let secret_name = secret.info.name.as_str();
        let policy_decision = SecretPolicyTier::PeerQuorum.as_str();
        let mut accepted = Vec::new();
        let mut failures = Vec::new();

        if required_peer_acks > 0 {
            for peer in &config.peers {
                match self
                    .request_peer_read_approval(
                        &cluster_id,
                        &identity,
                        peer,
                        nonce.as_str(),
                        secret_scope.as_str(),
                        secret_name,
                        caller,
                        policy_decision,
                        requester_latest_position,
                        requester_latest_body_hash_b64.as_str(),
                    )
                    .await
                {
                    Ok(evidence) => {
                        accepted.push(evidence);
                        if accepted.len() >= required_peer_acks {
                            break;
                        }
                    }
                    Err(err) => failures.push(serde_json::json!({
                        "peer_node_id": peer.node_id.as_str(),
                        "endpoint": peer.endpoint.as_str(),
                        "error": err,
                    })),
                }
            }
        }

        if accepted.len() < required_peer_acks {
            let first_failure = failures
                .first()
                .and_then(|failure| failure.get("error"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            warn!(
                cluster_id = %cluster_id,
                node_id = %identity.node_id,
                secret_scope = %secret_scope,
                secret_name = %secret_name,
                required_peer_acks,
                accepted = accepted.len(),
                configured_peers = config.peers.len(),
                failures = failures.len(),
                first_failure,
                "hem peer quorum approval failed"
            );
            return Err(Status::failed_precondition(format!(
                "secret read policy peer_quorum requires {required_peer_acks} reachable peer approval(s); accepted={} configured_peers={} failures={} first_failure={}",
                accepted.len(),
                config.peers.len(),
                failures.len(),
                first_failure
            )));
        }

        info!(
            cluster_id = %cluster_id,
            node_id = %identity.node_id,
            secret_scope = %secret_scope,
            secret_name = %secret_name,
            required_peer_acks,
            accepted = accepted.len(),
            configured_peers = config.peers.len(),
            requester_latest_position,
            "hem peer quorum approval satisfied"
        );

        let evidence = serde_json::json!({
            "kind": "peer_quorum_v1",
            "cluster_id": cluster_id,
            "requester_node_id": identity.node_id,
            "secret_scope": secret_scope,
            "secret_name": secret_name,
            "requester_actor": caller.actor.as_str(),
            "token_id": caller.token_id.as_str(),
            "policy_decision": policy_decision,
            "upstream_approval_reference": upstream_approval_reference,
            "required_cluster_quorum": config.quorum,
            "required_peer_acks": required_peer_acks,
            "nonce": nonce,
            "requester_latest_position": requester_latest_position,
            "requester_latest_body_hash_b64": requester_latest_body_hash_b64,
            "accepted": accepted,
            "failures": failures,
        });
        serde_json::to_string(&evidence).map_err(|err| {
            Status::internal(format!("peer quorum evidence serialize failed: {err}"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_peer_read_approval(
        &self,
        cluster_id: &str,
        identity: &NodeIdentity,
        peer: &PeerConfig,
        nonce: &str,
        secret_scope: &str,
        secret_name: &str,
        caller: &CallerPrincipal,
        policy_decision: &str,
        requester_latest_position: i64,
        requester_latest_body_hash_b64: &str,
    ) -> Result<serde_json::Value, String> {
        let channel = Endpoint::from_shared(peer.endpoint.clone())
            .map_err(|err| format!("invalid peer endpoint: {err}"))?
            .connect_timeout(Duration::from_secs(CLUSTER_SYNC_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(CLUSTER_SYNC_RPC_TIMEOUT_SECS))
            .connect()
            .await
            .map_err(|err| format!("connect failed: {err}"))?;
        let mut client = HemRuntimeClient::new(channel);
        let response = client
            .peer_approve_read(
                signed_peer_transport_request(
                    PeerApproveReadRequest {
                        cluster_id: cluster_id.to_string(),
                        requester_node_id: identity.node_id.clone(),
                        requester_public_key: identity.signing_public_key_b64.clone(),
                        nonce: nonce.to_string(),
                        secret_scope: secret_scope.to_string(),
                        secret_name: secret_name.to_string(),
                        requester_actor: caller.actor.clone(),
                        token_id: caller.token_id.clone(),
                        policy_decision: policy_decision.to_string(),
                        requester_latest_position,
                        requester_latest_body_hash_b64: requester_latest_body_hash_b64.to_string(),
                    },
                    identity,
                    cluster_id,
                    PEER_METHOD_APPROVE_READ,
                )
                .map_err(|err| format!("peer auth sign failed: {err}"))?,
            )
            .await
            .map_err(|err| format!("approval rpc failed: {err}"))?
            .into_inner();

        if !response.accepted {
            let reason = if response.reason.trim().is_empty() {
                "-"
            } else {
                response.reason.as_str()
            };
            return Err(format!("peer rejected read approval: {}", reason));
        }
        if response.cluster_id != cluster_id {
            return Err(format!(
                "cluster_id mismatch expected={} actual={}",
                cluster_id, response.cluster_id
            ));
        }
        if response.node_id != peer.node_id {
            return Err(format!(
                "node_id mismatch expected={} actual={}",
                peer.node_id, response.node_id
            ));
        }
        if response.signing_public_key_b64 != peer.public_key {
            return Err("signing public key mismatch".to_string());
        }

        let statement = PeerReadQuorumStatement {
            version: "hem-peer-read-quorum-v1",
            cluster_id,
            requester_node_id: identity.node_id.as_str(),
            approver_node_id: response.node_id.as_str(),
            nonce,
            secret_scope,
            secret_name,
            requester_actor: caller.actor.as_str(),
            token_id: caller.token_id.as_str(),
            policy_decision,
            requester_latest_position,
            requester_latest_body_hash_b64,
            approver_latest_position: response.latest_position,
            approver_latest_body_hash_b64: response.latest_body_hash_b64.as_str(),
        };
        let statement_bytes = serde_json::to_vec(&statement)
            .map_err(|err| format!("statement serialize failed: {err}"))?;
        let expected_hash = node_statement_hash_b64(statement_bytes.as_slice());
        if response.statement_hash_b64 != expected_hash {
            return Err(format!(
                "statement hash mismatch expected={} actual={}",
                expected_hash, response.statement_hash_b64
            ));
        }
        verify_node_statement_signature(
            peer.public_key.as_str(),
            statement_bytes.as_slice(),
            response.signature_b64.as_str(),
        )
        .map_err(|err| err.to_string())?;

        let statement_json = serde_json::to_value(&statement)
            .map_err(|err| format!("statement evidence serialize failed: {err}"))?;
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

    fn requires_remote_master_approval(
        &self,
        store: &HemStore,
        secret: &CoreSecretWithValues,
    ) -> Result<bool, Status> {
        if !self.cluster_runtime.enabled
            || self.cluster_runtime.force_offline
            || self.cluster_runtime.is_master_node()
        {
            return Ok(false);
        }
        let policy = store
            .policy_store()
            .map_err(status_from_hem)?
            .effective_policy(&secret.info.scope, secret.info.name.as_str())
            .map_err(status_from_hem)?;
        Ok(policy == SecretPolicyTier::MasterBiometric)
    }

    fn remote_master_peer(&self) -> Result<(String, NodeIdentity, PeerConfig), Status> {
        let Some((cluster_id, identity)) = self.cluster_ledger_context()? else {
            return Err(Status::failed_precondition("hem cluster is not enabled"));
        };
        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        let master_node_id = config
            .master_node_id
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("hem cluster master_node_id missing"))?;
        if master_node_id == identity.node_id {
            return Err(Status::failed_precondition(
                "local node is the master approval node",
            ));
        }
        let peer = config
            .peers
            .iter()
            .find(|peer| peer.node_id == master_node_id)
            .cloned()
            .ok_or_else(|| {
                Status::failed_precondition(format!(
                    "master node {master_node_id} is not configured as a peer"
                ))
            })?;
        Ok((cluster_id, identity, peer))
    }

    async fn connect_cluster_peer(
        &self,
        peer: &PeerConfig,
    ) -> Result<HemRuntimeClient<tonic::transport::Channel>, Status> {
        let channel = Endpoint::from_shared(peer.endpoint.clone())
            .map_err(|err| Status::invalid_argument(format!("invalid peer endpoint: {err}")))?
            .connect_timeout(Duration::from_secs(CLUSTER_SYNC_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(CLUSTER_SYNC_RPC_TIMEOUT_SECS))
            .connect()
            .await
            .map_err(|err| {
                Status::unavailable(format!(
                    "peer connect failed endpoint={} error={err} debug={err:?}",
                    peer.endpoint
                ))
            })?;
        Ok(HemRuntimeClient::new(channel))
    }

    #[allow(clippy::too_many_arguments)]
    async fn route_remote_master_approval(
        &self,
        peer: &PeerConfig,
        cluster_id: &str,
        identity: &NodeIdentity,
        secret: &CoreSecretWithValues,
        secret_version: &str,
        caller: &CallerPrincipal,
        reason: &str,
    ) -> Result<proto::ApprovalRequestInfo, Status> {
        let mut client = self.connect_cluster_peer(peer).await?;
        let response = client
            .peer_route_master_approval(
                signed_peer_transport_request(
                    PeerRouteMasterApprovalRequest {
                        cluster_id: cluster_id.to_string(),
                        requester_node_id: identity.node_id.clone(),
                        requester_public_key: identity.signing_public_key_b64.clone(),
                        scope: Some(to_proto_secret_scope_selector(&secret.info.scope)),
                        secret_name: secret.info.name.clone(),
                        secret_version: secret_version.to_string(),
                        action: "get_secret".to_string(),
                        requested_by: caller.actor.clone(),
                        reason: reason.to_string(),
                        default_reason: DEFAULT_GET_APPROVAL_REASON.to_string(),
                    },
                    identity,
                    cluster_id,
                    PEER_METHOD_ROUTE_MASTER_APPROVAL,
                )
                .map_err(status_from_hem)?,
            )
            .await?
            .into_inner();
        if !response.accepted {
            return Err(Status::failed_precondition(format!(
                "master approval rejected: {}",
                response.reason
            )));
        }
        self.validate_master_peer_response(
            peer,
            cluster_id,
            response.cluster_id.as_str(),
            response.node_id.as_str(),
        )?;
        response
            .request
            .ok_or_else(|| Status::internal("master approval response missing request"))
    }

    async fn get_remote_master_approval_status(
        &self,
        peer: &PeerConfig,
        cluster_id: &str,
        identity: &NodeIdentity,
        request_id: &str,
    ) -> Result<RemoteMasterApprovalStatus, Status> {
        let mut client = self.connect_cluster_peer(peer).await?;
        let response = client
            .peer_get_master_approval_status(
                signed_peer_transport_request(
                    PeerGetMasterApprovalStatusRequest {
                        cluster_id: cluster_id.to_string(),
                        requester_node_id: identity.node_id.clone(),
                        requester_public_key: identity.signing_public_key_b64.clone(),
                        request_id: request_id.to_string(),
                    },
                    identity,
                    cluster_id,
                    PEER_METHOD_GET_MASTER_APPROVAL_STATUS,
                )
                .map_err(status_from_hem)?,
            )
            .await?
            .into_inner();
        if !response.found {
            return Err(Status::not_found(format!(
                "master approval request not found: {request_id}"
            )));
        }
        self.validate_master_peer_response(
            peer,
            cluster_id,
            response.cluster_id.as_str(),
            response.node_id.as_str(),
        )?;
        let request = response
            .request
            .ok_or_else(|| Status::internal("master approval status missing request"))?;
        let state = proto::ApprovalState::try_from(request.state)
            .map_err(|_| Status::internal("invalid approval state from master"))?;
        Ok(RemoteMasterApprovalStatus {
            request_id: request.request_id,
            state: proto_approval_state_to_core(state),
            resolve_message: request.resolve_message,
            approval_receipt: response.approval_receipt,
        })
    }

    async fn wait_for_remote_master_approval(
        &self,
        peer: &PeerConfig,
        cluster_id: &str,
        identity: &NodeIdentity,
        request_id: &str,
        timeout_ms: u64,
    ) -> Result<RemoteMasterApprovalStatus, Status> {
        let timeout_ms = if timeout_ms == 0 {
            DEFAULT_APPROVAL_WAIT_TIMEOUT_MS
        } else {
            timeout_ms
        };
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let status = self
                .get_remote_master_approval_status(peer, cluster_id, identity, request_id)
                .await?;
            if !matches!(status.state, CoreApprovalState::Pending) {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(format!(
                    "master approval wait timed out: request_id={request_id}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(APPROVAL_WAIT_POLL_INTERVAL_MS)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn consume_remote_master_approval_receipt(
        &self,
        peer: &PeerConfig,
        cluster_id: &str,
        identity: &NodeIdentity,
        scope: &SecretScope,
        secret_name: &str,
        secret_version: &str,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String, Status> {
        let mut client = self.connect_cluster_peer(peer).await?;
        let response = client
            .peer_consume_master_approval_receipt(
                signed_peer_transport_request(
                    PeerConsumeMasterApprovalReceiptRequest {
                        cluster_id: cluster_id.to_string(),
                        requester_node_id: identity.node_id.clone(),
                        requester_public_key: identity.signing_public_key_b64.clone(),
                        scope: Some(to_proto_secret_scope_selector(scope)),
                        secret_name: secret_name.to_string(),
                        secret_version: secret_version.to_string(),
                        action: action.to_string(),
                        approval_receipt: receipt.to_string(),
                        actor: actor.to_string(),
                    },
                    identity,
                    cluster_id,
                    PEER_METHOD_CONSUME_MASTER_APPROVAL_RECEIPT,
                )
                .map_err(status_from_hem)?,
            )
            .await?
            .into_inner();
        if !response.consumed {
            return Err(Status::failed_precondition(
                "master approval receipt was not consumed",
            ));
        }
        self.validate_master_peer_response(
            peer,
            cluster_id,
            response.cluster_id.as_str(),
            response.node_id.as_str(),
        )?;
        Ok(response.request_id)
    }

    fn validate_master_peer_response(
        &self,
        peer: &PeerConfig,
        cluster_id: &str,
        response_cluster_id: &str,
        response_node_id: &str,
    ) -> Result<(), Status> {
        if response_cluster_id != cluster_id {
            return Err(Status::failed_precondition(format!(
                "master cluster_id mismatch expected={cluster_id} actual={response_cluster_id}"
            )));
        }
        if response_node_id != peer.node_id {
            return Err(Status::failed_precondition(format!(
                "master node_id mismatch expected={} actual={response_node_id}",
                peer.node_id
            )));
        }
        if self.cluster_runtime.cluster_id.as_deref() != Some(cluster_id) {
            return Err(Status::failed_precondition(
                "local cluster runtime changed during master approval routing",
            ));
        }
        Ok(())
    }

    async fn emit_event_payload(&self, topic: &str, payload: impl Serialize) {
        let Some(mesh) = &self.mesh else {
            return;
        };
        match serde_json::to_vec(&payload) {
            Ok(bytes) => {
                if let Err(err) = mesh.emit(topic, bytes.as_slice()).await {
                    warn!(error = %err, topic = topic, "failed to emit hem event");
                }
            }
            Err(err) => warn!(error = %err, topic = topic, "failed to encode hem event payload"),
        }
    }

    async fn wait_for_approval_record(
        &self,
        request_id: &str,
        timeout_ms: u64,
    ) -> Result<DeleteApprovalRecord, Status> {
        let timeout_ms = if timeout_ms == 0 {
            DEFAULT_APPROVAL_WAIT_TIMEOUT_MS
        } else {
            timeout_ms
        };
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);

        loop {
            let record = self
                .approval_provider
                .get_request(request_id)
                .map_err(status_from_hem)?;
            if !matches!(record.state, CoreApprovalState::Pending) {
                return Ok(record);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(format!(
                    "approval wait timed out: request_id={request_id}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(APPROVAL_WAIT_POLL_INTERVAL_MS)).await;
        }
    }
}

#[derive(Debug, Clone)]
struct CallerPrincipal {
    actor: String,
    token_id: String,
    claims: TokenClaims,
    is_operator: bool,
    client: Option<CoreAuditClientInfo>,
    transport: Option<CoreAuditTransportInfo>,
}

#[derive(Debug, Clone)]
struct ScanCandidate {
    secret_ref: String,
    key: String,
    value: String,
}

#[derive(Debug, Clone)]
struct ScanMatchRecord {
    secret_ref: String,
    key: String,
    offset: u32,
}

#[derive(Debug, Clone)]
struct ReadPolicyOutcome {
    decision: String,
    reference: String,
}

#[derive(Debug, Clone, Copy)]
struct ReadReceiptDraft<'a> {
    caller: &'a CallerPrincipal,
    secret: &'a CoreSecretWithValues,
    policy_decision: &'a str,
    approval_reference: &'a str,
    receipt_id: &'a str,
    keys: &'a [String],
}

#[derive(Debug, Clone)]
struct RemoteMasterApprovalStatus {
    request_id: String,
    state: CoreApprovalState,
    resolve_message: String,
    approval_receipt: String,
}

#[derive(Debug, Serialize)]
struct PeerReadQuorumStatement<'a> {
    version: &'static str,
    cluster_id: &'a str,
    requester_node_id: &'a str,
    approver_node_id: &'a str,
    nonce: &'a str,
    secret_scope: &'a str,
    secret_name: &'a str,
    requester_actor: &'a str,
    token_id: &'a str,
    policy_decision: &'a str,
    requester_latest_position: i64,
    requester_latest_body_hash_b64: &'a str,
    approver_latest_position: i64,
    approver_latest_body_hash_b64: &'a str,
}

trait ApprovalProvider: Send + Sync + std::fmt::Debug {
    fn request_action(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        action: &str,
        requested_by: &str,
        reason: &str,
        default_reason: &str,
    ) -> Result<DeleteApprovalRecord, HemError>;

    #[allow(clippy::too_many_arguments)]
    fn request_action_for_version(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        secret_version: Option<&str>,
        action: &str,
        requested_by: &str,
        reason: &str,
        default_reason: &str,
    ) -> Result<DeleteApprovalRecord, HemError>;

    fn list_pending(&self, limit: usize) -> Result<Vec<DeleteApprovalRecord>, HemError>;

    fn resolve_request(
        &self,
        request_id: &str,
        approve: bool,
        actor: &str,
        message: &str,
    ) -> Result<(DeleteApprovalRecord, Option<String>), HemError>;

    fn consume_receipt(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String, HemError>;

    fn consume_receipt_for_version(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        secret_version: Option<&str>,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String, HemError>;

    fn get_request(&self, request_id: &str) -> Result<DeleteApprovalRecord, HemError>;
}

#[derive(Debug, Clone)]
struct LocalApprovalProvider {
    data_dir: PathBuf,
}

impl LocalApprovalProvider {
    fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn open_store(&self) -> Result<DeleteApprovalStore, HemError> {
        DeleteApprovalStore::open(self.data_dir.as_path())
    }
}

impl ApprovalProvider for LocalApprovalProvider {
    fn request_action(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        action: &str,
        requested_by: &str,
        reason: &str,
        default_reason: &str,
    ) -> Result<DeleteApprovalRecord, HemError> {
        self.open_store()?.request_action(
            secret_scope,
            secret_name,
            action,
            requested_by,
            reason,
            default_reason,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn request_action_for_version(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        secret_version: Option<&str>,
        action: &str,
        requested_by: &str,
        reason: &str,
        default_reason: &str,
    ) -> Result<DeleteApprovalRecord, HemError> {
        self.open_store()?.request_action_for_version(
            secret_scope,
            secret_name,
            secret_version,
            action,
            requested_by,
            reason,
            default_reason,
        )
    }

    fn list_pending(&self, limit: usize) -> Result<Vec<DeleteApprovalRecord>, HemError> {
        self.open_store()?.list_pending(limit)
    }

    fn resolve_request(
        &self,
        request_id: &str,
        approve: bool,
        actor: &str,
        message: &str,
    ) -> Result<(DeleteApprovalRecord, Option<String>), HemError> {
        self.open_store()?
            .resolve_request(request_id, approve, actor, message)
    }

    fn consume_receipt(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String, HemError> {
        self.open_store()?
            .consume_receipt(secret_scope, secret_name, action, receipt, actor)
    }

    fn consume_receipt_for_version(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        secret_version: Option<&str>,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String, HemError> {
        self.open_store()?.consume_receipt_for_version(
            secret_scope,
            secret_name,
            secret_version,
            action,
            receipt,
            actor,
        )
    }

    fn get_request(&self, request_id: &str) -> Result<DeleteApprovalRecord, HemError> {
        self.open_store()?.get_request(request_id)
    }
}

#[tonic::async_trait]
impl HemRuntime for HemRuntimeService {
    async fn set_secret(
        &self,
        request: Request<SetSecretRequest>,
    ) -> Result<Response<SecretInfo>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let metadata_approval_receipt = parse_optional_metadata_receipt(request.metadata())?;
        let req = request.into_inner();
        let (scope, name) = self.parse_secret_ref(req.secret)?;
        let has_grant =
            self.has_explicit_read_grant(&store, &caller.claims, &scope, name.as_str())?;
        authorize_read(&caller.claims, &scope, has_grant).map_err(status_from_hem)?;

        let existing = store.get_secret_info(&scope, name.as_str()).ok();
        let set_reason = normalize_optional_string(req.reason)
            .unwrap_or_else(|| DEFAULT_SET_APPROVAL_REASON.to_string());
        let approval_receipt = normalize_optional_string(req.approval_receipt)
            .or(metadata_approval_receipt)
            .unwrap_or_default();

        if existing
            .as_ref()
            .map(|item| item.requires_approval)
            .unwrap_or(false)
            && !caller.is_operator
        {
            if approval_receipt.trim().is_empty() {
                let pending = self
                    .approval_provider
                    .request_action(
                        scope.clone(),
                        name.clone(),
                        "set_secret",
                        caller.actor.as_str(),
                        set_reason.as_str(),
                        DEFAULT_SET_APPROVAL_REASON,
                    )
                    .map_err(status_from_hem)?;
                self.audit(
                    &store,
                    Some(&caller),
                    "set_secret",
                    Some((&scope, name.as_str())),
                    "pending_approval",
                    format!("request_id={}", pending.request_id).as_str(),
                );
                self.emit_event_payload(
                    topics::HEM_APPROVAL_REQUESTED,
                    serde_json::json!({
                        "request_id": pending.request_id.as_str(),
                        "action": "set_secret",
                        "secret_scope": scope_label(&scope),
                        "secret_name": name.as_str(),
                        "requested_by": caller.actor.as_str(),
                    }),
                )
                .await;
                return Err(Status::failed_precondition(format!(
                    "approval required for set_secret request_id={}",
                    pending.request_id
                )));
            }

            self.approval_provider
                .consume_receipt(
                    &scope,
                    name.as_str(),
                    "set_secret",
                    approval_receipt.as_str(),
                    caller.actor.as_str(),
                )
                .map_err(status_from_hem)?;
        }

        let mut values = HashMap::new();
        for item in req.values {
            if item.key.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "secret value key must not be empty",
                ));
            }
            values.insert(item.key, item.value);
        }

        let input = SetSecretInput {
            scope: scope.clone(),
            name: name.clone(),
            values,
            description: req.description,
            requires_approval: req.requires_approval,
            group: normalize_optional_string(req.group),
            actor: caller.actor.clone(),
        };

        let info = store.set_secret(input).map_err(status_from_hem)?;
        self.append_cluster_secret_set(&store, &scope, name.as_str(), caller.actor.as_str())?;
        self.audit(
            &store,
            Some(&caller),
            "set_secret",
            Some((&scope, name.as_str())),
            "ok",
            "",
        );
        self.emit_event_payload(
            topics::HEM_SECRET_WRITTEN,
            serde_json::json!({
                "scope": scope_label(&scope),
                "name": name.as_str(),
                "actor": caller.actor.as_str(),
            }),
        )
        .await;
        Ok(Response::new(to_proto_secret_info(info)))
    }

    async fn get_secret(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<GetSecretResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let metadata_approval_receipt = parse_optional_metadata_receipt(request.metadata())?;
        let req = request.into_inner();
        let approval_reason = normalize_optional_string(req.reason)
            .unwrap_or_else(|| DEFAULT_GET_APPROVAL_REASON.to_string());
        let approval_receipt = normalize_optional_string(req.approval_receipt)
            .or(metadata_approval_receipt)
            .unwrap_or_default();
        let mut approval_reference = String::new();

        let mut secret = self.resolve_lookup_secret(
            &store,
            req.lookup,
            req.context,
            Some(caller.actor.as_str()),
            Some(&caller.claims),
        )?;

        if secret.info.requires_approval && !caller.is_operator {
            if approval_receipt.trim().is_empty() {
                let pending = self
                    .approval_provider
                    .request_action(
                        secret.info.scope.clone(),
                        secret.info.name.clone(),
                        "get_secret",
                        caller.actor.as_str(),
                        approval_reason.as_str(),
                        DEFAULT_GET_APPROVAL_REASON,
                    )
                    .map_err(status_from_hem)?;
                let request_id = pending.request_id.clone();
                self.audit(
                    &store,
                    Some(&caller),
                    "get_secret",
                    Some((&secret.info.scope, secret.info.name.as_str())),
                    "pending_approval",
                    format!("request_id={request_id}").as_str(),
                );
                self.emit_event_payload(
                    topics::HEM_APPROVAL_REQUESTED,
                    serde_json::json!({
                        "request_id": request_id.as_str(),
                        "action": "get_secret",
                        "secret_scope": scope_label(&secret.info.scope),
                        "secret_name": secret.info.name.as_str(),
                        "requested_by": caller.actor.as_str(),
                    }),
                )
                .await;

                if req.async_read {
                    return Ok(Response::new(GetSecretResponse {
                        result: Some(get_secret_response::Result::Pending(
                            proto::PendingApproval {
                                request_id,
                                state: proto::ApprovalState::Pending as i32,
                                message: "secret read requires approval".to_string(),
                            },
                        )),
                    }));
                }

                let resolved = match self
                    .wait_for_approval_record(request_id.as_str(), req.wait_timeout_ms)
                    .await
                {
                    Ok(record) => record,
                    Err(err) => {
                        self.audit(
                            &store,
                            Some(&caller),
                            "get_secret",
                            Some((&secret.info.scope, secret.info.name.as_str())),
                            "approval_wait_timeout",
                            format!("request_id={request_id}").as_str(),
                        );
                        return Err(err);
                    }
                };

                match resolved.state {
                    CoreApprovalState::Approved => {
                        let receipt = resolved
                            .approval_receipt
                            .as_deref()
                            .ok_or_else(|| Status::failed_precondition("approval receipt missing"))?
                            .to_string();
                        approval_reference = receipt.clone();
                        self.approval_provider
                            .consume_receipt(
                                &secret.info.scope,
                                secret.info.name.as_str(),
                                "get_secret",
                                receipt.as_str(),
                                caller.actor.as_str(),
                            )
                            .map_err(status_from_hem)?;
                    }
                    CoreApprovalState::Denied => {
                        self.audit(
                            &store,
                            Some(&caller),
                            "get_secret",
                            Some((&secret.info.scope, secret.info.name.as_str())),
                            "approval_denied",
                            format!("request_id={}", resolved.request_id).as_str(),
                        );
                        return Err(Status::permission_denied(format!(
                            "approval denied: request_id={} message={}",
                            resolved.request_id, resolved.resolve_message
                        )));
                    }
                    CoreApprovalState::TimedOut => {
                        self.audit(
                            &store,
                            Some(&caller),
                            "get_secret",
                            Some((&secret.info.scope, secret.info.name.as_str())),
                            "approval_timed_out",
                            format!("request_id={}", resolved.request_id).as_str(),
                        );
                        return Err(Status::deadline_exceeded(format!(
                            "approval timed out: request_id={}",
                            resolved.request_id
                        )));
                    }
                    CoreApprovalState::Pending => {
                        return Err(Status::deadline_exceeded(format!(
                            "approval wait timed out: request_id={}",
                            resolved.request_id
                        )));
                    }
                }
            } else {
                self.approval_provider
                    .consume_receipt(
                        &secret.info.scope,
                        secret.info.name.as_str(),
                        "get_secret",
                        approval_receipt.as_str(),
                        caller.actor.as_str(),
                    )
                    .map_err(status_from_hem)?;
                approval_reference = approval_receipt.clone();
            }
        }

        if self.requires_remote_master_approval(&store, &secret)? {
            let secret_version = secret.info.updated_at.to_rfc3339();
            let (cluster_id, identity, master_peer) = self.remote_master_peer()?;
            if approval_receipt.trim().is_empty() {
                let pending = self
                    .route_remote_master_approval(
                        &master_peer,
                        cluster_id.as_str(),
                        &identity,
                        &secret,
                        secret_version.as_str(),
                        &caller,
                        approval_reason.as_str(),
                    )
                    .await?;
                let request_id = pending.request_id.clone();
                self.audit(
                    &store,
                    Some(&caller),
                    "get_secret",
                    Some((&secret.info.scope, secret.info.name.as_str())),
                    "pending_master_approval",
                    format!(
                        "request_id={request_id} master_node_id={}",
                        self.cluster_runtime.master_node_id.as_deref().unwrap_or("")
                    )
                    .as_str(),
                );
                self.emit_event_payload(
                    topics::HEM_APPROVAL_REQUESTED,
                    serde_json::json!({
                        "request_id": request_id.as_str(),
                        "action": "get_secret",
                        "secret_scope": scope_label(&secret.info.scope),
                        "secret_name": secret.info.name.as_str(),
                        "requested_by": caller.actor.as_str(),
                        "routed_to": self.cluster_runtime.master_node_id.as_deref().unwrap_or(""),
                    }),
                )
                .await;
                if req.async_read {
                    return Ok(Response::new(GetSecretResponse {
                        result: Some(get_secret_response::Result::Pending(
                            proto::PendingApproval {
                                request_id,
                                state: proto::ApprovalState::Pending as i32,
                                message: "secret read requires master approval".to_string(),
                            },
                        )),
                    }));
                }

                let resolved = match self
                    .wait_for_remote_master_approval(
                        &master_peer,
                        cluster_id.as_str(),
                        &identity,
                        request_id.as_str(),
                        req.wait_timeout_ms,
                    )
                    .await
                {
                    Ok(record) => record,
                    Err(err) => {
                        self.audit(
                            &store,
                            Some(&caller),
                            "get_secret",
                            Some((&secret.info.scope, secret.info.name.as_str())),
                            "master_approval_wait_timeout",
                            format!("request_id={request_id}").as_str(),
                        );
                        return Err(err);
                    }
                };

                match resolved.state {
                    CoreApprovalState::Approved => {
                        if resolved.approval_receipt.trim().is_empty() {
                            return Err(Status::failed_precondition(
                                "master approval receipt missing",
                            ));
                        }
                        self.consume_remote_master_approval_receipt(
                            &master_peer,
                            cluster_id.as_str(),
                            &identity,
                            &secret.info.scope,
                            secret.info.name.as_str(),
                            secret_version.as_str(),
                            "get_secret",
                            resolved.approval_receipt.as_str(),
                            caller.actor.as_str(),
                        )
                        .await?;
                        approval_reference = resolved.approval_receipt;
                    }
                    CoreApprovalState::Denied => {
                        self.audit(
                            &store,
                            Some(&caller),
                            "get_secret",
                            Some((&secret.info.scope, secret.info.name.as_str())),
                            "master_approval_denied",
                            format!("request_id={}", resolved.request_id).as_str(),
                        );
                        return Err(Status::permission_denied(format!(
                            "master approval denied: request_id={} message={}",
                            resolved.request_id, resolved.resolve_message
                        )));
                    }
                    CoreApprovalState::TimedOut => {
                        self.audit(
                            &store,
                            Some(&caller),
                            "get_secret",
                            Some((&secret.info.scope, secret.info.name.as_str())),
                            "master_approval_timed_out",
                            format!("request_id={}", resolved.request_id).as_str(),
                        );
                        return Err(Status::deadline_exceeded(format!(
                            "master approval timed out: request_id={}",
                            resolved.request_id
                        )));
                    }
                    CoreApprovalState::Pending => {
                        return Err(Status::deadline_exceeded(format!(
                            "master approval wait timed out: request_id={}",
                            request_id,
                        )));
                    }
                }
            }

            if !approval_receipt.trim().is_empty() {
                self.consume_remote_master_approval_receipt(
                    &master_peer,
                    cluster_id.as_str(),
                    &identity,
                    &secret.info.scope,
                    secret.info.name.as_str(),
                    secret_version.as_str(),
                    "get_secret",
                    approval_receipt.as_str(),
                    caller.actor.as_str(),
                )
                .await?;
                approval_reference = approval_receipt.clone();
            }
        }

        let requested_key = normalize_optional_string(req.key);
        if let Some(key) = requested_key.clone() {
            let value =
                secret.values.get(key.as_str()).cloned().ok_or_else(|| {
                    Status::not_found(format!("secret value key not found: {key}"))
                })?;
            secret.values = HashMap::from([(key, value)]);
        }

        let policy = self
            .enforce_read_policy(&store, &caller, &secret, approval_reference.as_str())
            .await?;
        self.append_signed_read_receipts(
            &store,
            &caller,
            &secret,
            policy.decision.as_str(),
            policy.reference.as_str(),
        )
        .await?;

        self.audit_with_key(
            &store,
            Some(&caller),
            "get_secret",
            Some((&secret.info.scope, secret.info.name.as_str())),
            requested_key.as_deref(),
            "ok",
            "",
        );
        self.emit_event_payload(
            topics::HEM_SECRET_READ,
            serde_json::json!({
                "scope": scope_label(&secret.info.scope),
                "name": secret.info.name.as_str(),
                "actor": caller.actor.as_str(),
            }),
        )
        .await;

        Ok(Response::new(GetSecretResponse {
            result: Some(get_secret_response::Result::Secret(
                to_proto_secret_with_values(secret),
            )),
        }))
    }

    async fn get_secret_info(
        &self,
        request: Request<GetSecretInfoRequest>,
    ) -> Result<Response<SecretInfo>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let req = request.into_inner();
        let info =
            self.resolve_lookup_secret_info(&store, req.lookup, req.context, Some(&caller.claims))?;
        Ok(Response::new(to_proto_secret_info(info)))
    }

    async fn delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<DeleteSecretResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let metadata_approval_receipt = parse_optional_metadata_receipt(request.metadata())?;
        let req = request.into_inner();
        let (scope, name) = self.parse_secret_ref(req.secret)?;
        let has_grant =
            self.has_explicit_read_grant(&store, &caller.claims, &scope, name.as_str())?;
        authorize_read(&caller.claims, &scope, has_grant).map_err(status_from_hem)?;
        let actor = caller.actor.clone();
        let reason =
            normalize_optional_string(req.reason).unwrap_or_else(|| "delete requested".to_string());

        store
            .get_secret_info(&scope, name.as_str())
            .map_err(status_from_hem)?;
        let approval_receipt = normalize_optional_string(req.approval_receipt)
            .or(metadata_approval_receipt)
            .unwrap_or_default();

        if !approval_receipt.trim().is_empty() {
            let request_id = self
                .approval_provider
                .consume_receipt(
                    &scope,
                    name.as_str(),
                    "delete_secret",
                    approval_receipt.as_str(),
                    actor.as_str(),
                )
                .map_err(status_from_hem)?;
            let deleted = store
                .delete_secret(&scope, name.as_str())
                .map_err(status_from_hem)?;
            if deleted {
                self.append_cluster_event_operation(
                    &store,
                    "secret.deleted",
                    serde_json::json!({
                        "scope": scope_label(&scope),
                        "name": name.as_str(),
                        "actor": actor.as_str(),
                        "approval_request_id": request_id.as_str(),
                    }),
                )?;
            }
            self.audit(
                &store,
                Some(&caller),
                "delete_secret",
                Some((&scope, name.as_str())),
                if deleted { "deleted" } else { "not_found" },
                format!("request_id={request_id}").as_str(),
            );
            if deleted {
                self.emit_event_payload(
                    topics::HEM_SECRET_DELETED,
                    serde_json::json!({
                        "scope": scope_label(&scope),
                        "name": name.as_str(),
                        "actor": caller.actor.as_str(),
                    }),
                )
                .await;
            }
            return Ok(Response::new(DeleteSecretResponse {
                deleted,
                approval_request_id: request_id,
                approval_state: proto::ApprovalState::Approved as i32,
            }));
        }

        let pending = self
            .approval_provider
            .request_action(
                scope.clone(),
                name.clone(),
                "delete_secret",
                caller.actor.as_str(),
                reason.as_str(),
                "delete requested",
            )
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "delete_secret",
            Some((&scope, name.as_str())),
            "pending_approval",
            format!("request_id={}", pending.request_id).as_str(),
        );
        self.emit_event_payload(
            topics::HEM_APPROVAL_REQUESTED,
            serde_json::json!({
                "request_id": pending.request_id.as_str(),
                "action": "delete_secret",
                "secret_scope": scope_label(&scope),
                "secret_name": name.as_str(),
                "requested_by": caller.token_id.as_str(),
            }),
        )
        .await;
        Ok(Response::new(DeleteSecretResponse {
            deleted: false,
            approval_request_id: pending.request_id,
            approval_state: proto::ApprovalState::Pending as i32,
        }))
    }

    async fn list_secrets(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<ListSecretsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let req = request.into_inner();
        let scope = parse_optional_scope_selector(req.scope)?;

        let local_secrets = match scope.as_ref() {
            Some(scope) => store.list_secrets(Some(scope)).map_err(status_from_hem)?,
            None => store.list_secrets(None).map_err(status_from_hem)?,
        };
        let distributed_secrets = self.list_distributed_secret_infos(&store, scope.as_ref())?;
        let mut secrets = merge_secret_infos(local_secrets, distributed_secrets);

        if !caller.is_operator {
            secrets.retain(|item| {
                let has_grant = self
                    .has_explicit_read_grant(
                        &store,
                        &caller.claims,
                        &item.scope,
                        item.name.as_str(),
                    )
                    .unwrap_or(false);
                authorize_read(&caller.claims, &item.scope, has_grant).is_ok()
            });
        }

        if let Some(group) = normalize_optional_string(req.group) {
            secrets.retain(|item| item.group.as_deref() == Some(group.as_str()));
        }
        if let Some(prefix) = normalize_optional_string(req.prefix) {
            secrets.retain(|item| item.name.starts_with(prefix.as_str()));
        }
        if req.limit > 0 {
            secrets.truncate(req.limit as usize);
        }

        Ok(Response::new(ListSecretsResponse {
            secrets: secrets.into_iter().map(to_proto_secret_info).collect(),
        }))
    }

    async fn get_secrets(
        &self,
        request: Request<GetSecretsRequest>,
    ) -> Result<Response<GetSecretsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let metadata_approval_receipt = parse_optional_metadata_receipt(request.metadata())?;
        let req = request.into_inner();
        let approval_receipt = metadata_approval_receipt.unwrap_or_default();

        let mut results = Vec::with_capacity(req.requests.len());
        for item in req.requests {
            let async_read = item.async_read;
            let wait_timeout_ms = item.wait_timeout_ms;
            let approval_reason = normalize_optional_string(item.reason.clone())
                .unwrap_or_else(|| DEFAULT_GET_APPROVAL_REASON.to_string());
            let result = match resolve_batch_secret_request(
                &store,
                item,
                Some(caller.actor.as_str()),
                Some(&caller.claims),
            ) {
                Ok(secret) => {
                    if secret.info.requires_approval && !caller.is_operator {
                        if approval_receipt.trim().is_empty() {
                            let pending = self
                                .approval_provider
                                .request_action(
                                    secret.info.scope.clone(),
                                    secret.info.name.clone(),
                                    "get_secret",
                                    caller.actor.as_str(),
                                    approval_reason.as_str(),
                                    DEFAULT_GET_APPROVAL_REASON,
                                )
                                .map_err(status_from_hem)?;
                            let request_id = pending.request_id.clone();
                            self.emit_event_payload(
                                topics::HEM_APPROVAL_REQUESTED,
                                serde_json::json!({
                                    "request_id": request_id.as_str(),
                                    "action": "get_secret",
                                    "secret_scope": scope_label(&secret.info.scope),
                                    "secret_name": secret.info.name.as_str(),
                                    "requested_by": caller.actor.as_str(),
                                }),
                            )
                            .await;
                            if async_read {
                                secret_batch_result::Result::Pending(proto::PendingApproval {
                                    request_id,
                                    state: proto::ApprovalState::Pending as i32,
                                    message: "secret read requires approval".to_string(),
                                })
                            } else {
                                let resolved = self
                                    .wait_for_approval_record(request_id.as_str(), wait_timeout_ms)
                                    .await;
                                match resolved {
                                    Ok(record) => match record.state {
                                        CoreApprovalState::Approved => {
                                            let receipt = record
                                                .approval_receipt
                                                .as_deref()
                                                .ok_or_else(|| {
                                                    Status::failed_precondition(
                                                        "approval receipt missing",
                                                    )
                                                })?;
                                            self.approval_provider
                                                .consume_receipt(
                                                    &secret.info.scope,
                                                    secret.info.name.as_str(),
                                                    "get_secret",
                                                    receipt,
                                                    caller.actor.as_str(),
                                                )
                                                .map_err(status_from_hem)?;
                                            let policy = self
                                                .enforce_read_policy(
                                                    &store, &caller, &secret, receipt,
                                                )
                                                .await?;
                                            self.append_signed_read_receipts(
                                                &store,
                                                &caller,
                                                &secret,
                                                policy.decision.as_str(),
                                                policy.reference.as_str(),
                                            )
                                            .await?;
                                            secret_batch_result::Result::Secret(
                                                to_proto_secret_with_values(secret),
                                            )
                                        }
                                        CoreApprovalState::Denied => {
                                            results.push(proto::SecretBatchResult {
                                                result: None,
                                                error: format!(
                                                    "approval denied: request_id={} message={}",
                                                    record.request_id, record.resolve_message
                                                ),
                                            });
                                            continue;
                                        }
                                        CoreApprovalState::TimedOut
                                        | CoreApprovalState::Pending => {
                                            results.push(proto::SecretBatchResult {
                                                result: None,
                                                error: format!(
                                                    "approval wait timed out: request_id={}",
                                                    record.request_id
                                                ),
                                            });
                                            continue;
                                        }
                                    },
                                    Err(err) => {
                                        results.push(proto::SecretBatchResult {
                                            result: None,
                                            error: err.message().to_string(),
                                        });
                                        continue;
                                    }
                                }
                            }
                        } else {
                            self.approval_provider
                                .consume_receipt(
                                    &secret.info.scope,
                                    secret.info.name.as_str(),
                                    "get_secret",
                                    approval_receipt.as_str(),
                                    caller.actor.as_str(),
                                )
                                .map_err(status_from_hem)?;
                            let policy = self
                                .enforce_read_policy(
                                    &store,
                                    &caller,
                                    &secret,
                                    approval_receipt.as_str(),
                                )
                                .await?;
                            self.append_signed_read_receipts(
                                &store,
                                &caller,
                                &secret,
                                policy.decision.as_str(),
                                policy.reference.as_str(),
                            )
                            .await?;
                            secret_batch_result::Result::Secret(to_proto_secret_with_values(secret))
                        }
                    } else {
                        let policy = self
                            .enforce_read_policy(&store, &caller, &secret, "")
                            .await?;
                        self.append_signed_read_receipts(
                            &store,
                            &caller,
                            &secret,
                            policy.decision.as_str(),
                            policy.reference.as_str(),
                        )
                        .await?;
                        secret_batch_result::Result::Secret(to_proto_secret_with_values(secret))
                    }
                }
                Err(err) => {
                    results.push(proto::SecretBatchResult {
                        result: None,
                        error: err.message().to_string(),
                    });
                    continue;
                }
            };
            results.push(proto::SecretBatchResult {
                result: Some(result),
                error: String::new(),
            });
        }

        Ok(Response::new(GetSecretsResponse { results }))
    }

    async fn scan_for_secrets(
        &self,
        request: Request<ScanForSecretsRequest>,
    ) -> Result<Response<ScanForSecretsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let req = request.into_inner();
        let scope = parse_optional_scope_selector(req.scope)?;
        let min_value_length = if req.min_value_length == 0 {
            DEFAULT_SCAN_MIN_VALUE_LENGTH
        } else {
            req.min_value_length
        } as usize;

        let mut secrets = store
            .list_secrets(scope.as_ref())
            .map_err(status_from_hem)?;
        if !caller.is_operator {
            secrets.retain(|item| {
                let has_grant = self
                    .has_explicit_read_grant(
                        &store,
                        &caller.claims,
                        &item.scope,
                        item.name.as_str(),
                    )
                    .unwrap_or(false);
                authorize_read(&caller.claims, &item.scope, has_grant).is_ok()
            });
        }

        let mut candidates = Vec::new();
        for info in secrets {
            let secret_ref = format!("{}/{}", scope_label(&info.scope), info.name);
            let values = store
                .get_secret_values_without_access_update(&info.scope, info.name.as_str())
                .map_err(status_from_hem)?;
            for (key, value) in values {
                if value.len() < min_value_length {
                    continue;
                }
                candidates.push(ScanCandidate {
                    secret_ref: secret_ref.clone(),
                    key,
                    value,
                });
            }
        }

        let matches = collect_scan_matches(req.text.as_str(), candidates.as_slice());
        let scope_label = scope
            .as_ref()
            .map(scope_label)
            .unwrap_or_else(|| "all".to_string());
        self.audit(
            &store,
            Some(&caller),
            "scan_for_secrets",
            None,
            if matches.is_empty() {
                "clean"
            } else {
                "detected"
            },
            format!(
                "matches={} secrets_checked={} scope={scope_label}",
                matches.len(),
                candidates.len()
            )
            .as_str(),
        );

        Ok(Response::new(ScanForSecretsResponse {
            clean: matches.is_empty(),
            matches: matches
                .into_iter()
                .map(|item| proto::ScanMatch {
                    secret_ref: item.secret_ref,
                    key: item.key,
                    offset: item.offset,
                })
                .collect(),
            scanned_length: req.text.len().min(u32::MAX as usize) as u32,
            secrets_checked: candidates.len().min(u32::MAX as usize) as u32,
        }))
    }

    async fn set_group(
        &self,
        request: Request<SetGroupRequest>,
    ) -> Result<Response<proto::GroupInfo>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let name = parse_group_name(req.name.as_str())?;
        let groups = store.group_store().map_err(status_from_hem)?;
        let info = groups
            .set_group(name.as_str(), req.description.as_str())
            .map_err(status_from_hem)?;
        self.append_cluster_event_operation(
            &store,
            "group.set",
            serde_json::json!({
                "name": info.name.as_str(),
                "description": info.description.as_str(),
                "created_at": info.created_at.to_rfc3339(),
                "updated_at": info.updated_at.to_rfc3339(),
                "actor": caller.actor.as_str(),
            }),
        )?;
        Ok(Response::new(to_proto_group_info(info)))
    }

    async fn add_to_group(
        &self,
        request: Request<AddToGroupRequest>,
    ) -> Result<Response<proto::GroupInfo>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let (scope, name) = self.parse_secret_ref(req.secret)?;
        let group = parse_group_name(req.group.as_str())?;

        store
            .set_secret_group(&scope, name.as_str(), Some(group.clone()))
            .map_err(status_from_hem)?;

        let groups = store.group_store().map_err(status_from_hem)?;
        let mut group_created = false;
        let info = match groups.get_group(group.as_str()) {
            Ok(info) => info,
            Err(HemError::GroupNotFound(_)) => {
                group_created = true;
                groups
                    .set_group(group.as_str(), "")
                    .map_err(status_from_hem)?
            }
            Err(err) => return Err(status_from_hem(err)),
        };
        if group_created {
            self.append_cluster_event_operation(
                &store,
                "group.set",
                serde_json::json!({
                    "name": info.name.as_str(),
                    "description": info.description.as_str(),
                    "created_at": info.created_at.to_rfc3339(),
                    "updated_at": info.updated_at.to_rfc3339(),
                    "actor": caller.actor.as_str(),
                }),
            )?;
        }
        self.append_cluster_secret_metadata(&store, &scope, name.as_str(), caller.actor.as_str())?;

        Ok(Response::new(to_proto_group_info(info)))
    }

    async fn remove_from_group(
        &self,
        request: Request<RemoveFromGroupRequest>,
    ) -> Result<Response<RemoveFromGroupResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let (scope, name) = self.parse_secret_ref(req.secret)?;

        store
            .set_secret_group(&scope, name.as_str(), None)
            .map_err(status_from_hem)?;
        self.append_cluster_secret_metadata(&store, &scope, name.as_str(), caller.actor.as_str())?;

        Ok(Response::new(RemoveFromGroupResponse { updated: true }))
    }

    async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<ListGroupsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let groups = store.group_store().map_err(status_from_hem)?;
        let listed = groups.list_groups().map_err(status_from_hem)?;
        Ok(Response::new(ListGroupsResponse {
            groups: listed.into_iter().map(to_proto_group_info).collect(),
        }))
    }

    async fn list_group_secrets(
        &self,
        request: Request<ListGroupSecretsRequest>,
    ) -> Result<Response<ListGroupSecretsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        let req = request.into_inner();
        let group = parse_group_name(req.group.as_str())?;
        let mut secrets = store
            .list_group_secrets(group.as_str())
            .map_err(status_from_hem)?;
        if !caller.is_operator {
            secrets.retain(|item| {
                let has_grant = self
                    .has_explicit_read_grant(
                        &store,
                        &caller.claims,
                        &item.scope,
                        item.name.as_str(),
                    )
                    .unwrap_or(false);
                authorize_read(&caller.claims, &item.scope, has_grant).is_ok()
            });
        }
        Ok(Response::new(ListGroupSecretsResponse {
            secrets: secrets.into_iter().map(to_proto_secret_info).collect(),
        }))
    }

    async fn issue_agent_token(
        &self,
        request: Request<IssueAgentTokenRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let manager = store.token_manager().map_err(status_from_hem)?;

        let scopes = parse_agent_requested_scopes(&req)?;
        let ttl_secs = if req.ttl_seconds == 0 {
            DEFAULT_AGENT_TOKEN_TTL_SECS
        } else {
            req.ttl_seconds
        };
        let issued_by = normalize_optional_string(req.issued_by_service)
            .unwrap_or_else(|| "unknown-service".to_string());

        let issued = manager
            .issue_agent_token(
                normalize_optional_string(req.identity_id),
                normalize_optional_string(req.project),
                scopes,
                Duration::from_secs(ttl_secs),
                issued_by.as_str(),
            )
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "issue_agent_token",
            None,
            "ok",
            format!("token_id={}", issued.claims.token_id).as_str(),
        );
        self.emit_event_payload(
            topics::HEM_TOKEN_ISSUED,
            serde_json::json!({
                "token_id": issued.claims.token_id.as_str(),
                "token_type": "agent_run",
                "actor": caller.actor.as_str(),
            }),
        )
        .await;

        Ok(Response::new(IssueTokenResponse {
            token: issued.token,
            info: Some(to_proto_token_info(&issued.claims)),
        }))
    }

    async fn issue_service_token(
        &self,
        request: Request<IssueServiceTokenRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let service_name = normalize_optional_string(req.service_name)
            .ok_or_else(|| Status::invalid_argument("service_name must not be empty"))?;
        let ttl_secs = if req.ttl_seconds == 0 {
            DEFAULT_SERVICE_TOKEN_TTL_SECS
        } else {
            req.ttl_seconds
        };
        let issued_by =
            normalize_optional_string(req.issued_by).unwrap_or_else(|| "unknown".to_string());

        let manager = store.token_manager().map_err(status_from_hem)?;
        let issued = manager
            .issue_service_token(
                service_name,
                Duration::from_secs(ttl_secs),
                issued_by.as_str(),
            )
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "issue_service_token",
            None,
            "ok",
            format!("token_id={}", issued.claims.token_id).as_str(),
        );
        self.emit_event_payload(
            topics::HEM_TOKEN_ISSUED,
            serde_json::json!({
                "token_id": issued.claims.token_id.as_str(),
                "token_type": "service",
                "actor": caller.actor.as_str(),
            }),
        )
        .await;

        Ok(Response::new(IssueTokenResponse {
            token: issued.token,
            info: Some(to_proto_token_info(&issued.claims)),
        }))
    }

    async fn revoke_token(
        &self,
        request: Request<RevokeTokenRequest>,
    ) -> Result<Response<RevokeTokenResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let token_id = req.token_id.trim();
        if token_id.is_empty() {
            return Err(Status::invalid_argument("token_id must not be empty"));
        }
        let actor = caller.actor.clone();

        let manager = store.token_manager().map_err(status_from_hem)?;
        let revoked = manager
            .revoke_token(token_id, actor.as_str())
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "revoke_token",
            None,
            if revoked { "revoked" } else { "not_found" },
            format!("token_id={token_id}").as_str(),
        );
        if revoked {
            self.emit_event_payload(
                topics::HEM_TOKEN_REVOKED,
                serde_json::json!({
                    "token_id": token_id,
                    "actor": caller.actor.as_str(),
                }),
            )
            .await;
        }

        Ok(Response::new(RevokeTokenResponse { revoked }))
    }

    async fn list_active_tokens(
        &self,
        request: Request<ListActiveTokensRequest>,
    ) -> Result<Response<ListActiveTokensResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let token_type = parse_optional_token_type(req.token_type)?;
        let service_name = normalize_optional_string(req.service_name);
        let identity_id = normalize_optional_string(req.identity_id);

        let manager = store.token_manager().map_err(status_from_hem)?;
        let mut tokens = manager
            .list_active_tokens(token_type)
            .map_err(status_from_hem)?;

        if let Some(service_name) = service_name {
            tokens.retain(|item| item.service_name.as_deref() == Some(service_name.as_str()));
        }
        if let Some(identity_id) = identity_id {
            tokens.retain(|item| item.identity_id.as_deref() == Some(identity_id.as_str()));
        }
        if req.limit > 0 {
            tokens.truncate(req.limit as usize);
        }

        Ok(Response::new(ListActiveTokensResponse {
            tokens: tokens
                .iter()
                .map(to_proto_token_info)
                .collect::<Vec<TokenInfo>>(),
        }))
    }

    async fn grant_access(
        &self,
        request: Request<GrantAccessRequest>,
    ) -> Result<Response<GrantInfo>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;

        let req = request.into_inner();
        let (secret_scope, secret_name) = self.parse_secret_ref(req.secret)?;
        let grantee_scope = parse_scope_selector_or_global(req.grantee_scope)?;
        let grantee_id = normalize_optional_string(req.grantee_id)
            .ok_or_else(|| Status::invalid_argument("grantee_id must not be empty"))?;

        let grant = store
            .grant_access(
                &secret_scope,
                secret_name.as_str(),
                &grantee_scope,
                grantee_id.as_str(),
                caller.actor.as_str(),
            )
            .map_err(status_from_hem)?;
        self.append_cluster_event_operation(
            &store,
            "grant.access",
            serde_json::json!({
                "scope": scope_label(&secret_scope),
                "name": secret_name.as_str(),
                "grantee_scope": format_scope(&grantee_scope),
                "grantee_id": grantee_id.as_str(),
                "created_at": grant.created_at.to_rfc3339(),
                "created_by": grant.created_by.as_str(),
                "actor": caller.actor.as_str(),
            }),
        )?;
        self.audit(
            &store,
            Some(&caller),
            "grant_access",
            Some((&secret_scope, secret_name.as_str())),
            "ok",
            format!(
                "grantee_scope={} grantee_id={}",
                format_scope(&grantee_scope),
                grantee_id
            )
            .as_str(),
        );
        Ok(Response::new(to_proto_grant_info(&grant)))
    }

    async fn revoke_access(
        &self,
        request: Request<RevokeAccessRequest>,
    ) -> Result<Response<RevokeAccessResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;

        let req = request.into_inner();
        let (secret_scope, secret_name) = self.parse_secret_ref(req.secret)?;
        let grantee_scope = parse_scope_selector_or_global(req.grantee_scope)?;
        let grantee_id = normalize_optional_string(req.grantee_id)
            .ok_or_else(|| Status::invalid_argument("grantee_id must not be empty"))?;

        let revoked = store
            .revoke_access(
                &secret_scope,
                secret_name.as_str(),
                &grantee_scope,
                grantee_id.as_str(),
            )
            .map_err(status_from_hem)?;
        if revoked {
            self.append_cluster_event_operation(
                &store,
                "grant.revoked",
                serde_json::json!({
                    "scope": scope_label(&secret_scope),
                    "name": secret_name.as_str(),
                    "grantee_scope": format_scope(&grantee_scope),
                    "grantee_id": grantee_id.as_str(),
                    "actor": caller.actor.as_str(),
                }),
            )?;
        }
        self.audit(
            &store,
            Some(&caller),
            "revoke_access",
            Some((&secret_scope, secret_name.as_str())),
            if revoked { "revoked" } else { "not_found" },
            format!(
                "grantee_scope={} grantee_id={}",
                format_scope(&grantee_scope),
                grantee_id
            )
            .as_str(),
        );
        Ok(Response::new(RevokeAccessResponse { revoked }))
    }

    async fn list_grants(
        &self,
        request: Request<ListGrantsRequest>,
    ) -> Result<Response<ListGrantsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;

        let req = request.into_inner();
        let (secret_scope, secret_name) = self.parse_secret_ref(req.secret)?;
        let grants = store
            .list_grants(&secret_scope, secret_name.as_str())
            .map_err(status_from_hem)?;
        Ok(Response::new(ListGrantsResponse {
            grants: grants.iter().map(to_proto_grant_info).collect(),
        }))
    }

    async fn list_pending_approvals(
        &self,
        request: Request<ListPendingApprovalsRequest>,
    ) -> Result<Response<ListPendingApprovalsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let limit = if req.limit == 0 {
            200
        } else {
            req.limit as usize
        };
        let listed = self
            .approval_provider
            .list_pending(limit)
            .map_err(status_from_hem)?;
        Ok(Response::new(ListPendingApprovalsResponse {
            requests: listed.iter().map(to_proto_approval_request_info).collect(),
        }))
    }

    async fn approve_access(
        &self,
        request: Request<ResolveApprovalRequest>,
    ) -> Result<Response<ResolveApprovalResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let request_id = req.request_id.trim();
        if request_id.is_empty() {
            return Err(Status::invalid_argument("request_id must not be empty"));
        }

        let current = self
            .approval_provider
            .get_request(request_id)
            .map_err(status_from_hem)?;
        enforce_approval_action_policy(&caller, &current)?;

        let actor = caller.actor.clone();
        let (record, receipt) = self
            .approval_provider
            .resolve_request(request_id, true, actor.as_str(), req.message.as_str())
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "approve_access",
            Some((&record.secret_scope, record.secret_name.as_str())),
            "approved",
            format!("request_id={} action={}", record.request_id, record.action).as_str(),
        );
        self.emit_event_payload(
            topics::HEM_APPROVAL_RESOLVED,
            serde_json::json!({
                "request_id": record.request_id.as_str(),
                "state": "approved",
                "action": record.action.as_str(),
                "secret_scope": scope_label(&record.secret_scope),
                "secret_name": record.secret_name.as_str(),
                "actor": caller.actor.as_str(),
            }),
        )
        .await;

        Ok(Response::new(ResolveApprovalResponse {
            request: Some(to_proto_approval_request_info(&record)),
            approval_receipt: receipt.unwrap_or_default(),
        }))
    }

    async fn deny_access(
        &self,
        request: Request<ResolveApprovalRequest>,
    ) -> Result<Response<ResolveApprovalResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let request_id = req.request_id.trim();
        if request_id.is_empty() {
            return Err(Status::invalid_argument("request_id must not be empty"));
        }

        let current = self
            .approval_provider
            .get_request(request_id)
            .map_err(status_from_hem)?;
        enforce_approval_action_policy(&caller, &current)?;

        let actor = caller.actor.clone();
        let (record, _receipt) = self
            .approval_provider
            .resolve_request(request_id, false, actor.as_str(), req.message.as_str())
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "deny_access",
            Some((&record.secret_scope, record.secret_name.as_str())),
            "denied",
            format!("request_id={} action={}", record.request_id, record.action).as_str(),
        );
        self.emit_event_payload(
            topics::HEM_APPROVAL_RESOLVED,
            serde_json::json!({
                "request_id": record.request_id.as_str(),
                "state": "denied",
                "action": record.action.as_str(),
                "secret_scope": scope_label(&record.secret_scope),
                "secret_name": record.secret_name.as_str(),
                "actor": caller.actor.as_str(),
            }),
        )
        .await;

        Ok(Response::new(ResolveApprovalResponse {
            request: Some(to_proto_approval_request_info(&record)),
            approval_receipt: String::new(),
        }))
    }

    async fn get_approval_status(
        &self,
        request: Request<GetApprovalStatusRequest>,
    ) -> Result<Response<ApprovalStatusResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let request_id = req.request_id.trim();
        if request_id.is_empty() {
            return Err(Status::invalid_argument("request_id must not be empty"));
        }

        let record = self
            .approval_provider
            .get_request(request_id)
            .map_err(status_from_hem)?;
        Ok(Response::new(ApprovalStatusResponse {
            request: Some(to_proto_approval_request_info(&record)),
        }))
    }

    async fn get_audit_log(
        &self,
        request: Request<GetAuditLogRequest>,
    ) -> Result<Response<GetAuditLogResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();

        let scope = parse_optional_scope_selector(req.scope)?;
        let since = parse_optional_rfc3339("since", req.since)?;
        let until = parse_optional_rfc3339("until", req.until)?;
        let limit = if req.limit == 0 {
            200
        } else {
            req.limit as usize
        };

        let audit_store = store.audit_store().map_err(status_from_hem)?;
        let entries = audit_store
            .list(scope.as_ref(), since, until, limit)
            .map_err(status_from_hem)?;
        Ok(Response::new(GetAuditLogResponse {
            entries: entries.iter().map(to_proto_audit_entry).collect(),
        }))
    }

    async fn peer_hello(
        &self,
        request: Request<PeerHelloRequest>,
    ) -> Result<Response<PeerHelloResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer = self.verify_peer_transport_auth(&request, PEER_METHOD_HELLO)?;
        let req = request.into_inner();
        validate_peer_request_subject("peer node_id", req.node_id.as_str())?;
        validate_peer_request_subject("peer public_key", req.public_key.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.node_id.as_str(),
            req.public_key.as_str(),
        )?;
        if req.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "peer cluster_id {} does not match local cluster_id {}",
                req.cluster_id, cluster_id
            )));
        }

        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        Ok(Response::new(PeerHelloResponse {
            accepted: true,
            cluster_id,
            node_id,
            latest_position: ledger.latest_position().map_err(status_from_hem)?,
            latest_body_hash_b64: ledger
                .latest_body_hash()
                .map_err(status_from_hem)?
                .unwrap_or_default(),
        }))
    }

    async fn peer_approve_read(
        &self,
        request: Request<PeerApproveReadRequest>,
    ) -> Result<Response<PeerApproveReadResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_APPROVE_READ)?;
        let req = request.into_inner();
        validate_peer_request_subject("requester node_id", req.requester_node_id.as_str())?;
        validate_peer_request_subject("requester public_key", req.requester_public_key.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        validate_peer_request_subject("quorum nonce", req.nonce.as_str())?;
        validate_peer_request_subject("secret scope", req.secret_scope.as_str())?;
        validate_peer_request_subject("secret name", req.secret_name.as_str())?;
        validate_peer_request_subject("requester actor", req.requester_actor.as_str())?;
        validate_peer_request_subject("token id", req.token_id.as_str())?;
        if req.requester_latest_position < 0 {
            return Err(Status::invalid_argument(
                "requester_latest_position must not be negative",
            ));
        }
        if req.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "peer cluster_id {} does not match local cluster_id {}",
                req.cluster_id, cluster_id
            )));
        }
        if req.policy_decision != SecretPolicyTier::PeerQuorum.as_str() {
            return Err(Status::invalid_argument(
                "peer read approval only supports peer_quorum policy decisions",
            ));
        }

        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        let requester = config
            .peers
            .iter()
            .find(|peer| peer.node_id == req.requester_node_id)
            .ok_or_else(|| {
                Status::permission_denied(format!(
                    "requester node {} is not a configured cluster peer",
                    req.requester_node_id
                ))
            })?;
        if requester.public_key != req.requester_public_key {
            return Err(Status::permission_denied(format!(
                "requester public key mismatch for node {}",
                req.requester_node_id
            )));
        }

        let identity = NodeIdentity::load(self.data_dir.join(NODE_IDENTITY_FILE).as_path())
            .map_err(status_from_hem)?;
        if identity.node_id != node_id {
            return Err(Status::failed_precondition(format!(
                "hem cluster node identity mismatch: runtime={} identity={}",
                node_id, identity.node_id
            )));
        }

        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        let latest_position = ledger.latest_position().map_err(status_from_hem)?;
        let latest_body_hash_b64 = ledger
            .latest_body_hash()
            .map_err(status_from_hem)?
            .unwrap_or_default();
        let statement = PeerReadQuorumStatement {
            version: "hem-peer-read-quorum-v1",
            cluster_id: cluster_id.as_str(),
            requester_node_id: req.requester_node_id.as_str(),
            approver_node_id: node_id.as_str(),
            nonce: req.nonce.as_str(),
            secret_scope: req.secret_scope.as_str(),
            secret_name: req.secret_name.as_str(),
            requester_actor: req.requester_actor.as_str(),
            token_id: req.token_id.as_str(),
            policy_decision: req.policy_decision.as_str(),
            requester_latest_position: req.requester_latest_position,
            requester_latest_body_hash_b64: req.requester_latest_body_hash_b64.as_str(),
            approver_latest_position: latest_position,
            approver_latest_body_hash_b64: latest_body_hash_b64.as_str(),
        };
        let statement_bytes = serde_json::to_vec(&statement).map_err(|err| {
            Status::internal(format!(
                "peer read approval statement serialize failed: {err}"
            ))
        })?;
        let statement_hash_b64 = node_statement_hash_b64(statement_bytes.as_slice());
        let signature_b64 = identity
            .sign_statement(statement_bytes.as_slice())
            .map_err(status_from_hem)?;

        Ok(Response::new(PeerApproveReadResponse {
            accepted: true,
            cluster_id,
            node_id,
            latest_position,
            latest_body_hash_b64,
            statement_hash_b64,
            signing_public_key_b64: identity.signing_public_key_b64,
            signature_b64,
            reason: String::new(),
        }))
    }

    async fn peer_approve_collision(
        &self,
        request: Request<PeerApproveCollisionRequest>,
    ) -> Result<Response<PeerApproveCollisionResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_APPROVE_COLLISION)?;
        let req = request.into_inner();
        validate_peer_request_subject("requester node_id", req.requester_node_id.as_str())?;
        validate_peer_request_subject("requester public_key", req.requester_public_key.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        validate_peer_request_subject("quorum nonce", req.nonce.as_str())?;
        validate_peer_request_subject("collision id", req.collision_id.as_str())?;
        validate_peer_request_subject("scope", req.scope.as_str())?;
        validate_peer_request_subject("name", req.name.as_str())?;
        validate_peer_request_subject("key", req.key.as_str())?;
        validate_peer_request_subject("current operation id", req.current_operation_id.as_str())?;
        validate_peer_request_subject("incoming operation id", req.incoming_operation_id.as_str())?;
        validate_peer_request_subject("resolution", req.resolution.as_str())?;
        if req.base_version_seq < 0
            || req.current_version_seq < 0
            || req.requester_latest_position < 0
        {
            return Err(Status::invalid_argument(
                "version and position fields must not be negative",
            ));
        }
        if req.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "peer cluster_id {} does not match local cluster_id {}",
                req.cluster_id, cluster_id
            )));
        }

        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        let requester = config
            .peers
            .iter()
            .find(|peer| peer.node_id == req.requester_node_id)
            .ok_or_else(|| {
                Status::permission_denied(format!(
                    "requester node {} is not a configured cluster peer",
                    req.requester_node_id
                ))
            })?;
        if requester.public_key != req.requester_public_key {
            return Err(Status::permission_denied(format!(
                "requester public key mismatch for node {}",
                req.requester_node_id
            )));
        }

        let identity = NodeIdentity::load(self.data_dir.join(NODE_IDENTITY_FILE).as_path())
            .map_err(status_from_hem)?;
        if identity.node_id != node_id {
            return Err(Status::failed_precondition(format!(
                "hem cluster node identity mismatch: runtime={} identity={}",
                node_id, identity.node_id
            )));
        }

        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        let latest_position = ledger.latest_position().map_err(status_from_hem)?;
        let latest_body_hash_b64 = ledger
            .latest_body_hash()
            .map_err(status_from_hem)?
            .unwrap_or_default();
        let statement = CollisionAgreementStatement {
            version: "hem-collision-agreement-v1",
            cluster_id: cluster_id.as_str(),
            requester_node_id: req.requester_node_id.as_str(),
            approver_node_id: node_id.as_str(),
            nonce: req.nonce.as_str(),
            collision_id: req.collision_id.as_str(),
            scope: req.scope.as_str(),
            name: req.name.as_str(),
            key: req.key.as_str(),
            current_operation_id: req.current_operation_id.as_str(),
            incoming_operation_id: req.incoming_operation_id.as_str(),
            base_version_seq: req.base_version_seq,
            current_version_seq: req.current_version_seq,
            resolution: req.resolution.as_str(),
            requester_latest_position: req.requester_latest_position,
            requester_latest_body_hash_b64: req.requester_latest_body_hash_b64.as_str(),
            approver_latest_position: latest_position,
            approver_latest_body_hash_b64: latest_body_hash_b64.as_str(),
        };
        let statement_bytes = serde_json::to_vec(&statement).map_err(|err| {
            Status::internal(format!(
                "peer collision approval statement serialize failed: {err}"
            ))
        })?;
        let statement_hash_b64 = node_statement_hash_b64(statement_bytes.as_slice());
        let signature_b64 = identity
            .sign_statement(statement_bytes.as_slice())
            .map_err(status_from_hem)?;

        info!(
            cluster_id = %cluster_id,
            node_id = %node_id,
            requester_node_id = %req.requester_node_id,
            collision_id = %req.collision_id,
            resolution = %req.resolution,
            latest_position,
            "hem peer collision approval signed"
        );

        Ok(Response::new(PeerApproveCollisionResponse {
            accepted: true,
            cluster_id,
            node_id,
            latest_position,
            latest_body_hash_b64,
            statement_hash_b64,
            signing_public_key_b64: identity.signing_public_key_b64,
            signature_b64,
            reason: String::new(),
        }))
    }

    async fn peer_route_master_approval(
        &self,
        request: Request<PeerRouteMasterApprovalRequest>,
    ) -> Result<Response<PeerRouteMasterApprovalResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_ROUTE_MASTER_APPROVAL)?;
        let req = request.into_inner();
        self.require_master_approval_node(node_id.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        self.require_configured_peer_requester(
            req.cluster_id.as_str(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        if req.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "peer cluster_id {} does not match local cluster_id {}",
                req.cluster_id, cluster_id
            )));
        }
        let scope = parse_scope_selector_or_global(req.scope)?;
        let record = self
            .approval_provider
            .request_action_for_version(
                scope,
                req.secret_name,
                normalize_optional_string(req.secret_version).as_deref(),
                req.action.as_str(),
                req.requested_by.as_str(),
                req.reason.as_str(),
                req.default_reason.as_str(),
            )
            .map_err(status_from_hem)?;
        info!(
            cluster_id = %cluster_id,
            node_id = %node_id,
            requester_node_id = %req.requester_node_id,
            request_id = %record.request_id,
            action = %req.action,
            "hem master approval routed"
        );
        Ok(Response::new(PeerRouteMasterApprovalResponse {
            accepted: true,
            cluster_id,
            node_id,
            request: Some(to_proto_approval_request_info(&record)),
            reason: String::new(),
        }))
    }

    async fn peer_get_master_approval_status(
        &self,
        request: Request<PeerGetMasterApprovalStatusRequest>,
    ) -> Result<Response<PeerGetMasterApprovalStatusResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_GET_MASTER_APPROVAL_STATUS)?;
        let req = request.into_inner();
        self.require_master_approval_node(node_id.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        self.require_configured_peer_requester(
            req.cluster_id.as_str(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        if req.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "peer cluster_id {} does not match local cluster_id {}",
                req.cluster_id, cluster_id
            )));
        }
        validate_peer_request_subject("request_id", req.request_id.as_str())?;
        let record = self
            .approval_provider
            .get_request(req.request_id.as_str())
            .map_err(status_from_hem)?;
        Ok(Response::new(PeerGetMasterApprovalStatusResponse {
            found: true,
            cluster_id,
            node_id,
            request: Some(to_proto_approval_request_info(&record)),
            approval_receipt: record.approval_receipt.unwrap_or_default(),
        }))
    }

    async fn peer_consume_master_approval_receipt(
        &self,
        request: Request<PeerConsumeMasterApprovalReceiptRequest>,
    ) -> Result<Response<PeerConsumeMasterApprovalReceiptResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_CONSUME_MASTER_APPROVAL_RECEIPT)?;
        let req = request.into_inner();
        self.require_master_approval_node(node_id.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        self.require_configured_peer_requester(
            req.cluster_id.as_str(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;
        if req.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "peer cluster_id {} does not match local cluster_id {}",
                req.cluster_id, cluster_id
            )));
        }
        let scope = parse_scope_selector_or_global(req.scope)?;
        let request_id = self
            .approval_provider
            .consume_receipt_for_version(
                &scope,
                req.secret_name.as_str(),
                normalize_optional_string(req.secret_version).as_deref(),
                req.action.as_str(),
                req.approval_receipt.as_str(),
                req.actor.as_str(),
            )
            .map_err(status_from_hem)?;
        info!(
            cluster_id = %cluster_id,
            node_id = %node_id,
            requester_node_id = %req.requester_node_id,
            request_id = %request_id,
            action = %req.action,
            "hem master approval receipt consumed"
        );
        Ok(Response::new(PeerConsumeMasterApprovalReceiptResponse {
            consumed: true,
            cluster_id,
            node_id,
            request_id,
        }))
    }

    async fn peer_list_operations(
        &self,
        request: Request<PeerListOperationsRequest>,
    ) -> Result<Response<PeerListOperationsResponse>, Status> {
        let _ = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_LIST_OPERATIONS)?;
        let req = request.into_inner();
        if let Some(peer) = authenticated_peer.as_ref() {
            if !req.peer_node_id.is_empty() && req.peer_node_id != peer.node_id {
                return Err(Status::unauthenticated(format!(
                    "peer_node_id {} does not match authenticated peer {}",
                    req.peer_node_id, peer.node_id
                )));
            }
        }
        if req.after_position < 0 {
            return Err(Status::invalid_argument(
                "after_position must not be negative",
            ));
        }
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit.min(1_000) as usize
        };
        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        let after_position = if req.use_recorded_cursor {
            validate_peer_request_subject("peer node_id", req.peer_node_id.as_str())?;
            ledger
                .get_peer_cursor(req.peer_node_id.as_str())
                .map_err(status_from_hem)?
                .map(|cursor| cursor.last_position)
                .unwrap_or(0)
        } else {
            req.after_position
        };
        let operations = ledger
            .list_after(after_position, limit)
            .map_err(status_from_hem)?;
        Ok(Response::new(PeerListOperationsResponse {
            operations: operations.iter().map(to_proto_ledger_operation).collect(),
            latest_position: ledger.latest_position().map_err(status_from_hem)?,
            latest_body_hash_b64: ledger
                .latest_body_hash()
                .map_err(status_from_hem)?
                .unwrap_or_default(),
        }))
    }

    async fn peer_ack_operations(
        &self,
        request: Request<PeerAckOperationsRequest>,
    ) -> Result<Response<PeerAckOperationsResponse>, Status> {
        let _ = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_ACK_OPERATIONS)?;
        let req = request.into_inner();
        validate_peer_request_subject("peer node_id", req.peer_node_id.as_str())?;
        if let Some(peer) = authenticated_peer.as_ref() {
            if req.peer_node_id != peer.node_id {
                return Err(Status::unauthenticated(format!(
                    "peer_node_id {} does not match authenticated peer {}",
                    req.peer_node_id, peer.node_id
                )));
            }
        }
        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        ledger
            .record_peer_cursor(
                req.peer_node_id.as_str(),
                req.position,
                req.body_hash_b64.as_str(),
            )
            .map_err(status_from_hem)?;
        Ok(Response::new(PeerAckOperationsResponse {
            recorded: true,
            next_position: req.position + 1,
        }))
    }

    async fn peer_push_operations(
        &self,
        request: Request<PeerPushOperationsRequest>,
    ) -> Result<Response<PeerPushOperationsResponse>, Status> {
        let _ = self.require_cluster_identity()?;
        self.verify_peer_transport_auth(&request, PEER_METHOD_PUSH_OPERATIONS)?;
        let req = request.into_inner();
        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        let mut accepted_count = 0_u32;
        for envelope in req.operations {
            let envelope = from_proto_ledger_operation(envelope)?;
            envelope.verify().map_err(status_from_hem)?;
            if let Some(existing) = ledger
                .get_by_operation_id(envelope.body.operation_id.as_str())
                .map_err(status_from_hem)?
            {
                if existing.body_hash_b64 == envelope.body_hash_b64 {
                    continue;
                }
                return Err(Status::already_exists(format!(
                    "ledger operation {} already exists with a different hash",
                    envelope.body.operation_id
                )));
            }
            ledger.append_signed(&envelope).map_err(status_from_hem)?;
            accepted_count += 1;
        }
        Ok(Response::new(PeerPushOperationsResponse {
            accepted_count,
            latest_position: ledger.latest_position().map_err(status_from_hem)?,
            latest_body_hash_b64: ledger
                .latest_body_hash()
                .map_err(status_from_hem)?
                .unwrap_or_default(),
        }))
    }

    async fn peer_cosign_checkpoint(
        &self,
        request: Request<PeerCosignCheckpointRequest>,
    ) -> Result<Response<PeerCosignCheckpointResponse>, Status> {
        let (cluster_id, node_id) = self.require_cluster_identity()?;
        let authenticated_peer =
            self.verify_peer_transport_auth(&request, PEER_METHOD_COSIGN_CHECKPOINT)?;
        let req = request.into_inner();
        validate_peer_request_subject("requester node_id", req.requester_node_id.as_str())?;
        validate_peer_request_subject("requester public_key", req.requester_public_key.as_str())?;
        self.require_authenticated_peer_subject(
            authenticated_peer.as_ref(),
            req.requester_node_id.as_str(),
            req.requester_public_key.as_str(),
        )?;

        let config = ClusterConfig::load(self.data_dir.join(CLUSTER_CONFIG_FILE).as_path())
            .map_err(status_from_hem)?;
        let requester = config
            .peers
            .iter()
            .find(|peer| peer.node_id == req.requester_node_id)
            .ok_or_else(|| {
                Status::permission_denied(format!(
                    "requester node {} is not a configured cluster peer",
                    req.requester_node_id
                ))
            })?;
        if requester.public_key != req.requester_public_key {
            return Err(Status::permission_denied(format!(
                "requester public key mismatch for node {}",
                req.requester_node_id
            )));
        }

        let checkpoint = from_proto_checkpoint(
            req.checkpoint
                .ok_or_else(|| Status::invalid_argument("checkpoint is required"))?,
        )?;
        if checkpoint.body.cluster_id != cluster_id {
            return Err(Status::permission_denied(format!(
                "checkpoint cluster_id {} does not match local cluster_id {}",
                checkpoint.body.cluster_id, cluster_id
            )));
        }
        if checkpoint.signing_public_key_b64 != req.requester_public_key {
            return Err(Status::permission_denied(format!(
                "checkpoint signer public key does not match requester {}",
                req.requester_node_id
            )));
        }
        if checkpoint.signer_node_id != req.requester_node_id {
            return Err(Status::permission_denied(format!(
                "checkpoint signer node_id does not match requester {}",
                req.requester_node_id
            )));
        }

        let identity = NodeIdentity::load(self.data_dir.join(NODE_IDENTITY_FILE).as_path())
            .map_err(status_from_hem)?;
        if identity.node_id != node_id {
            return Err(Status::failed_precondition(format!(
                "hem cluster node identity mismatch: runtime={} identity={}",
                node_id, identity.node_id
            )));
        }

        let store = self.open_store()?;
        let ledger = store.ledger_store().map_err(status_from_hem)?;
        ledger
            .ingest_checkpoint(&checkpoint)
            .map_err(checkpoint_cosign_status_from_hem)?;
        let cosignature = ledger
            .cosign_checkpoint(&identity, checkpoint.body.checkpoint_id.as_str())
            .map_err(status_from_hem)?;

        Ok(Response::new(PeerCosignCheckpointResponse {
            accepted: true,
            cluster_id,
            node_id,
            cosignature: Some(to_proto_checkpoint_cosignature(&cosignature)),
            reason: String::new(),
        }))
    }

    async fn init_hem(
        &self,
        request: Request<InitHemRequest>,
    ) -> Result<Response<InitHemResponse>, Status> {
        let req = request.into_inner();
        HemStore::init(self.data_dir.as_path(), req.force).map_err(status_from_hem)?;
        let store = self.open_store()?;
        let manager = store.token_manager().map_err(status_from_hem)?;
        let issued = manager
            .issue_operator_token(
                Duration::from_secs(DEFAULT_OPERATOR_TOKEN_TTL_SECS),
                "hemd:init",
            )
            .map_err(status_from_hem)?;
        write_operator_token(self.data_dir.as_path(), issued.token.as_str())?;

        Ok(Response::new(InitHemResponse {
            initialized: true,
            operator_token: issued.token,
        }))
    }

    async fn rotate_master_key(
        &self,
        request: Request<RotateMasterKeyRequest>,
    ) -> Result<Response<RotateMasterKeyResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let actor = normalize_optional_string(req.actor).unwrap_or_else(|| caller.actor.clone());
        let (new_key_id, rotated_secret_count) =
            store.rotate_master_key().map_err(status_from_hem)?;
        self.append_cluster_event_operation(
            &store,
            "master_key.rotated",
            serde_json::json!({
                "actor": actor.as_str(),
                "new_key_id": new_key_id.as_str(),
                "rotated_secret_count": rotated_secret_count,
            }),
        )?;
        if let Ok(refreshed) = HemStore::open(self.data_dir.as_path()) {
            if let Ok(manager) = refreshed.token_manager() {
                if let Ok(operator) = manager.issue_operator_token(
                    Duration::from_secs(DEFAULT_OPERATOR_TOKEN_TTL_SECS),
                    "hemd:rotate",
                ) {
                    let _ = write_operator_token(self.data_dir.as_path(), operator.token.as_str());
                }
            }
        }
        self.audit(
            &store,
            Some(&caller),
            "rotate_master_key",
            None,
            "ok",
            format!(
                "actor={} new_key_id={new_key_id} rotated_secret_count={rotated_secret_count}",
                actor
            )
            .as_str(),
        );
        Ok(Response::new(RotateMasterKeyResponse {
            new_key_id,
            rotated_secret_count,
        }))
    }

    async fn export_secrets(
        &self,
        request: Request<ExportSecretsRequest>,
    ) -> Result<Response<ExportSecretsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let scope = parse_optional_scope_selector(req.scope)?;
        let bundle = store
            .export_secrets_bundle(scope.as_ref())
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "export_secrets",
            None,
            "ok",
            format!(
                "scope={} bundle_bytes={}",
                scope
                    .as_ref()
                    .map(scope_label)
                    .unwrap_or_else(|| "all".to_string()),
                bundle.len()
            )
            .as_str(),
        );
        Ok(Response::new(ExportSecretsResponse {
            encrypted_bundle: bundle,
        }))
    }

    async fn import_secrets(
        &self,
        request: Request<ImportSecretsRequest>,
    ) -> Result<Response<ImportSecretsResponse>, Status> {
        let store = self.open_store()?;
        let caller = self.require_caller(&store, &request)?;
        authorize_admin(&caller.claims).map_err(status_from_hem)?;
        let req = request.into_inner();
        let actor = normalize_optional_string(req.actor).unwrap_or_else(|| caller.actor.clone());
        let report = store
            .import_secrets_bundle_with_report(req.encrypted_bundle.as_slice(), req.merge)
            .map_err(status_from_hem)?;
        for secret in &report.imported_secrets {
            self.append_cluster_secret_set(
                &store,
                &secret.scope,
                secret.name.as_str(),
                actor.as_str(),
            )?;
        }
        self.append_cluster_event_operation(
            &store,
            "secrets.imported",
            serde_json::json!({
                "actor": actor.as_str(),
                "merge": req.merge,
                "imported_secret_count": report.imported_secret_count,
                "imported": report.imported_secrets.iter().map(|secret| {
                    serde_json::json!({
                        "scope": scope_label(&secret.scope),
                        "name": secret.name.as_str(),
                    })
                }).collect::<Vec<_>>(),
            }),
        )?;
        self.audit(
            &store,
            Some(&caller),
            "import_secrets",
            None,
            "ok",
            format!(
                "actor={} merge={} imported_secret_count={}",
                actor, req.merge, report.imported_secret_count
            )
            .as_str(),
        );
        Ok(Response::new(ImportSecretsResponse {
            imported_secret_count: report.imported_secret_count,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: self.cluster_runtime.health_status(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClusterSyncSettings {
    enabled: bool,
    interval: Duration,
    batch_limit: u32,
    max_backoff: Duration,
}

impl ClusterSyncSettings {
    fn from_env(cluster_enabled: bool, force_offline: bool) -> Self {
        let mut settings = Self::from_values(
            cluster_enabled,
            force_offline,
            std::env::var("VALHALL_HEM_CLUSTER_SYNC").ok().as_deref(),
            std::env::var("VALHALL_HEM_CLUSTER_SYNC_INTERVAL_MS")
                .ok()
                .as_deref(),
            std::env::var("VALHALL_HEM_CLUSTER_SYNC_MAX_BACKOFF_MS")
                .ok()
                .as_deref(),
        );
        settings.batch_limit = parse_u32_value(
            std::env::var("VALHALL_HEM_CLUSTER_SYNC_BATCH_LIMIT")
                .ok()
                .as_deref(),
            DEFAULT_CLUSTER_SYNC_BATCH_LIMIT,
            1,
            10_000,
        );
        settings
    }

    fn from_values(
        cluster_enabled: bool,
        force_offline: bool,
        enabled_value: Option<&str>,
        interval_ms_value: Option<&str>,
        max_backoff_ms_value: Option<&str>,
    ) -> Self {
        let requested_enabled = enabled_value.map(parse_bool_like).unwrap_or(true);
        Self {
            enabled: cluster_enabled && !force_offline && requested_enabled,
            interval: parse_duration_ms_value(
                interval_ms_value,
                DEFAULT_CLUSTER_SYNC_INTERVAL_MS,
                50,
                60_000,
            ),
            batch_limit: DEFAULT_CLUSTER_SYNC_BATCH_LIMIT,
            max_backoff: parse_duration_ms_value(
                max_backoff_ms_value,
                DEFAULT_CLUSTER_SYNC_MAX_BACKOFF_MS,
                50,
                300_000,
            ),
        }
    }

    fn backoff_for_failure(&self, peer_node_id: &str, failure_count: u32) -> Duration {
        if failure_count == 0 {
            return Duration::ZERO;
        }

        let base_ms = duration_millis_u64(self.interval);
        let max_ms = duration_millis_u64(self.max_backoff).max(base_ms);
        let multiplier = 1_u64 << failure_count.saturating_sub(1).min(10);
        let raw_ms = base_ms.saturating_mul(multiplier).min(max_ms);
        let jitter_window = (base_ms / 4).clamp(1, 250);
        let jitter_ms = stable_jitter_ms(peer_node_id, failure_count) % (jitter_window + 1);
        Duration::from_millis(raw_ms.saturating_add(jitter_ms).min(max_ms))
    }
}

#[derive(Debug, Default, Clone)]
struct PeerSyncState {
    failures: u32,
    next_attempt: Option<Instant>,
}

#[derive(Debug)]
struct ClusterPeerSyncReport {
    accepted: bool,
    peer_latest_position: i64,
    pulled_operations: usize,
    pushed_operations: u32,
    local_latest_position: i64,
    checkpoint_id: Option<String>,
    checkpoint_position: Option<i64>,
    checkpoint_cosigned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClusterRuntimeInfo {
    enabled: bool,
    cluster_id: Option<String>,
    node_id: Option<String>,
    master_node_id: Option<String>,
    peer_count: usize,
    force_offline: bool,
    sync_enabled: bool,
}

impl ClusterRuntimeInfo {
    fn disabled() -> Self {
        Self {
            enabled: false,
            cluster_id: None,
            node_id: None,
            master_node_id: None,
            peer_count: 0,
            force_offline: false,
            sync_enabled: false,
        }
    }

    fn is_master_node(&self) -> bool {
        self.enabled
            && self.node_id.is_some()
            && self.node_id.as_deref() == self.master_node_id.as_deref()
    }

    fn health_status(&self) -> String {
        match (self.enabled, self.node_id.as_ref()) {
            (true, Some(node_id)) => format!(
                "ok cluster_enabled=true cluster_node_id={node_id} cluster_peers={} force_offline={} sync_enabled={}",
                self.peer_count, self.force_offline, self.sync_enabled
            ),
            _ => "ok cluster_enabled=false".to_string(),
        }
    }
}

fn parse_agent_requested_scopes(
    request: &IssueAgentTokenRequest,
) -> Result<Vec<SecretScope>, Status> {
    let identity_id = normalize_optional_string(request.identity_id.clone());
    let project = normalize_optional_string(request.project.clone());

    let mut scopes = Vec::with_capacity(request.scopes.len());
    for item in &request.scopes {
        let scope = proto::SecretScope::try_from(*item)
            .map_err(|_| Status::invalid_argument("invalid secret scope enum"))?;
        match scope {
            proto::SecretScope::Unspecified => {
                return Err(Status::invalid_argument("unspecified scope not allowed"));
            }
            proto::SecretScope::Global => scopes.push(SecretScope::Global),
            proto::SecretScope::Project => {
                let project = project.clone().ok_or_else(|| {
                    Status::invalid_argument("project required for project scope")
                })?;
                scopes.push(SecretScope::Project { project });
            }
            proto::SecretScope::Identity => {
                let identity_id = identity_id.clone().ok_or_else(|| {
                    Status::invalid_argument("identity_id required for identity scope")
                })?;
                scopes.push(SecretScope::Identity { identity_id });
            }
        }
    }
    Ok(scopes)
}

fn resolve_batch_secret_request(
    store: &HemStore,
    request: proto::SecretBatchRequestItem,
    actor: Option<&str>,
    claims: Option<&TokenClaims>,
) -> Result<CoreSecretWithValues, Status> {
    match request
        .lookup
        .ok_or_else(|| Status::invalid_argument("missing secret lookup"))?
    {
        secret_batch_request_item::Lookup::Secret(secret_ref) => {
            let scope = parse_scope_selector_or_global(secret_ref.scope)?;
            let name = parse_secret_name(secret_ref.name.as_str())?;
            if let Some(claims) = claims {
                let has_grant = has_explicit_read_grant(store, claims, &scope, name.as_str())?;
                authorize_read(claims, &scope, has_grant).map_err(status_from_hem)?;
            }
            store
                .get_secret(&scope, name.as_str(), actor)
                .map_err(status_from_hem)
        }
        secret_batch_request_item::Lookup::Name(name) => {
            let name = parse_secret_name(name.as_str())?;
            resolve_secret_by_name(store, name.as_str(), request.context, actor, claims)
        }
    }
}

fn resolve_secret_by_name(
    store: &HemStore,
    name: &str,
    context: Option<proto::ScopeResolutionContext>,
    actor: Option<&str>,
    claims: Option<&TokenClaims>,
) -> Result<CoreSecretWithValues, Status> {
    let context = to_resolution_context(context);
    let mut denied = false;
    for scope in resolution_chain(&context) {
        if let Some(claims) = claims {
            let has_grant = has_explicit_read_grant(store, claims, &scope, name)?;
            if authorize_read(claims, &scope, has_grant).is_err() {
                denied = true;
                continue;
            }
        }
        match store.get_secret(&scope, name, actor) {
            Ok(secret) => return Ok(secret),
            Err(HemError::SecretNotFound(_)) => continue,
            Err(err) => return Err(status_from_hem(err)),
        }
    }

    if denied {
        return Err(Status::permission_denied(format!(
            "not authorized to read secret: {name}"
        )));
    }
    Err(Status::not_found(format!("secret not found: {name}")))
}

fn resolve_secret_info_by_name(
    store: &HemStore,
    name: &str,
    context: Option<proto::ScopeResolutionContext>,
    claims: Option<&TokenClaims>,
) -> Result<CoreSecretInfo, Status> {
    let context = to_resolution_context(context);
    let mut denied = false;
    for scope in resolution_chain(&context) {
        if let Some(claims) = claims {
            let has_grant = has_explicit_read_grant(store, claims, &scope, name)?;
            if authorize_read(claims, &scope, has_grant).is_err() {
                denied = true;
                continue;
            }
        }
        match store.get_secret_info(&scope, name) {
            Ok(secret) => return Ok(secret),
            Err(HemError::SecretNotFound(_)) => continue,
            Err(err) => return Err(status_from_hem(err)),
        }
    }

    if denied {
        return Err(Status::permission_denied(format!(
            "not authorized to read secret info: {name}"
        )));
    }
    Err(Status::not_found(format!("secret not found: {name}")))
}

fn parse_authorization_header(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
    let raw = metadata
        .get(AUTHORIZATION_METADATA_KEY)
        .ok_or_else(|| {
            Status::unauthenticated(
                "missing authorization metadata; expected 'authorization: Bearer <token>'",
            )
        })?
        .to_str()
        .map_err(|_| Status::unauthenticated("authorization metadata must be valid ascii"))?;

    let (scheme, token) = raw
        .split_once(' ')
        .ok_or_else(|| Status::unauthenticated("invalid authorization metadata format"))?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Status::unauthenticated(
            "invalid authorization scheme; expected Bearer",
        ));
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(Status::unauthenticated(
            "authorization bearer token is empty",
        ));
    }
    Ok(token.to_string())
}

fn sanitize_metadata_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(CLIENT_METADATA_VALUE_MAX_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

fn metadata_string(metadata: &tonic::metadata::MetadataMap, key: &str) -> Option<String> {
    let value = metadata.get(key)?.to_str().ok()?;
    let sanitized = sanitize_metadata_value(value);
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

fn parse_client_metadata(metadata: &tonic::metadata::MetadataMap) -> Option<CoreAuditClientInfo> {
    let mut client = CoreAuditClientInfo {
        name: metadata_string(metadata, CLIENT_NAME_METADATA_KEY),
        version: metadata_string(metadata, CLIENT_VERSION_METADATA_KEY),
        pid: metadata_string(metadata, CLIENT_PID_METADATA_KEY)
            .and_then(|value| value.parse().ok()),
        context: metadata_string(metadata, CLIENT_CONTEXT_METADATA_KEY),
        request_id: metadata_string(metadata, CLIENT_REQUEST_ID_METADATA_KEY),
        ..CoreAuditClientInfo::default()
    };
    // Fingerprint format (all parts optional):
    //   classification=agent:claude-code;markers=ancestor:claude,env:CLAUDECODE;tty=false;session=<id>
    if let Some(fingerprint) = metadata_string(metadata, CALLER_FINGERPRINT_METADATA_KEY) {
        for part in fingerprint.split(';') {
            let Some((field, value)) = part.split_once('=') else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match field.trim() {
                "classification" => client.classification = Some(value.to_string()),
                "markers" => {
                    client.markers = value
                        .split(',')
                        .map(str::trim)
                        .filter(|marker| !marker.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                "tty" => client.tty = value.parse().ok(),
                "session" => client.agent_session = Some(value.to_string()),
                _ => {}
            }
        }
    }
    if client == CoreAuditClientInfo::default() {
        return None;
    }
    client.reported = true;
    Some(client)
}

fn audit_warnings(action: &str, caller: Option<&CallerPrincipal>) -> Vec<String> {
    let mut warnings = Vec::new();
    if action != "get_secret" {
        return warnings;
    }
    let Some(caller) = caller else {
        return warnings;
    };
    if caller.is_operator {
        warnings.push("operator_token_read".to_string());
        let agent_classified = caller
            .client
            .as_ref()
            .and_then(|client| client.classification.as_deref())
            .is_some_and(|classification| classification.starts_with("agent:"));
        if agent_classified {
            warnings.push("unattributed_agent_read".to_string());
        }
    }
    warnings
}

fn parse_optional_metadata_receipt(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<Option<String>, Status> {
    let Some(value) = metadata.get(APPROVAL_RECEIPT_METADATA_KEY) else {
        return Ok(None);
    };
    let parsed = value
        .to_str()
        .map_err(|_| Status::invalid_argument("x-hem-approval-receipt metadata must be ascii"))?;
    let trimmed = parsed.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_optional_token_type(value: i32) -> Result<Option<TokenType>, Status> {
    let token_type = proto::TokenType::try_from(value)
        .map_err(|_| Status::invalid_argument("invalid token_type enum"))?;
    Ok(match token_type {
        proto::TokenType::Unspecified => None,
        proto::TokenType::Operator => Some(TokenType::Operator),
        proto::TokenType::Service => Some(TokenType::Service),
        proto::TokenType::AgentRun => Some(TokenType::AgentRun),
    })
}

fn has_explicit_read_grant(
    store: &HemStore,
    claims: &TokenClaims,
    secret_scope: &SecretScope,
    secret_name: &str,
) -> Result<bool, Status> {
    if matches!(claims.token_type, TokenType::Operator) {
        return Ok(true);
    }

    let subjects = grant_subjects_for_claims(claims);
    for (grantee_scope, grantee_id) in subjects {
        let has = store
            .has_grant(
                secret_scope,
                secret_name,
                &grantee_scope,
                grantee_id.as_str(),
            )
            .map_err(status_from_hem)?;
        if has {
            return Ok(true);
        }
    }
    Ok(false)
}

fn grant_subjects_for_claims(claims: &TokenClaims) -> Vec<(SecretScope, String)> {
    let mut out = Vec::new();
    let mut seen: HashSet<(SecretScope, String)> = HashSet::new();

    let mut push = |scope: SecretScope, grantee_id: &str| {
        let id = grantee_id.trim();
        if id.is_empty() {
            return;
        }
        let candidate = (scope, id.to_string());
        if seen.insert(candidate.clone()) {
            out.push(candidate);
        }
    };

    push(SecretScope::Global, claims.token_id.as_str());

    if let Some(service_name) = claims.service_name.as_ref() {
        push(SecretScope::Global, service_name.as_str());
    }
    if let Some(project) = claims.project.as_ref() {
        push(
            SecretScope::Project {
                project: project.clone(),
            },
            project.as_str(),
        );
        push(SecretScope::Global, project.as_str());
    }
    if let Some(identity_id) = claims.identity_id.as_ref() {
        push(
            SecretScope::Identity {
                identity_id: identity_id.clone(),
            },
            identity_id.as_str(),
        );
        push(SecretScope::Global, identity_id.as_str());
    }

    out
}

fn enforce_approval_action_policy(
    caller: &CallerPrincipal,
    record: &DeleteApprovalRecord,
) -> Result<(), Status> {
    if !caller.is_operator {
        return Err(Status::permission_denied(
            "approval resolution requires operator token",
        ));
    }

    let action = record.action.trim();
    if action.is_empty() {
        return Err(Status::failed_precondition(
            "approval request action is empty",
        ));
    }
    if !matches!(action, "get_secret" | "set_secret" | "delete_secret") {
        return Err(Status::failed_precondition(format!(
            "unsupported approval action: {action}"
        )));
    }

    Ok(())
}

fn parse_optional_rfc3339(field: &str, value: String) -> Result<Option<DateTime<Utc>>, Status> {
    let Some(value) = normalize_optional_string(value) else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(value.as_str())
        .map_err(|_| Status::invalid_argument(format!("{field} must be RFC3339 timestamp")))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

fn parse_required_rfc3339(field: &str, value: &str) -> Result<DateTime<Utc>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{field} must not be empty"
        )));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| Status::invalid_argument(format!("{field} must be RFC3339 timestamp")))
}

fn validate_peer_request_subject(label: &str, value: &str) -> Result<(), Status> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{label} must not be empty"
        )));
    }
    if trimmed != value {
        return Err(Status::invalid_argument(format!(
            "{label} must not have leading/trailing whitespace"
        )));
    }
    Ok(())
}

fn required_peer_metadata<'a>(
    metadata: &'a MetadataMap,
    key: &'static str,
) -> Result<&'a str, Status> {
    metadata
        .get(key)
        .ok_or_else(|| Status::unauthenticated(format!("missing peer auth metadata {key}")))?
        .to_str()
        .map_err(|err| {
            Status::unauthenticated(format!("peer auth metadata {key} is not ASCII: {err}"))
        })
}

fn signed_peer_transport_request<T>(
    message: T,
    identity: &NodeIdentity,
    cluster_id: &str,
    method: &str,
) -> hem_core::Result<Request<T>> {
    let nonce = format!(
        "hpt_{}",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    );
    let timestamp_unix = Utc::now().timestamp();
    let statement_bytes = peer_transport_auth_statement_bytes(
        cluster_id,
        identity.node_id.as_str(),
        method,
        nonce.as_str(),
        timestamp_unix,
    )?;
    let signature = identity.sign_statement(statement_bytes.as_slice())?;

    let mut request = Request::new(message);
    let metadata = request.metadata_mut();
    metadata.insert(
        PEER_TRANSPORT_AUTH_CLUSTER_ID_METADATA_KEY,
        cluster_id.parse().map_err(|err| {
            HemError::InvalidArgument(format!("peer auth cluster_id metadata invalid: {err}"))
        })?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_NODE_ID_METADATA_KEY,
        identity.node_id.parse().map_err(|err| {
            HemError::InvalidArgument(format!("peer auth node_id metadata invalid: {err}"))
        })?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_METHOD_METADATA_KEY,
        method.parse().map_err(|err| {
            HemError::InvalidArgument(format!("peer auth method metadata invalid: {err}"))
        })?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_NONCE_METADATA_KEY,
        nonce.parse().map_err(|err| {
            HemError::InvalidArgument(format!("peer auth nonce metadata invalid: {err}"))
        })?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_TIMESTAMP_METADATA_KEY,
        timestamp_unix.to_string().parse().map_err(|err| {
            HemError::InvalidArgument(format!("peer auth timestamp metadata invalid: {err}"))
        })?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_SIGNATURE_METADATA_KEY,
        signature.parse().map_err(|err| {
            HemError::InvalidArgument(format!("peer auth signature metadata invalid: {err}"))
        })?,
    );
    Ok(request)
}

fn to_proto_ledger_operation(
    operation: &hem_core::LedgerOperation,
) -> proto::LedgerOperationEnvelope {
    proto::LedgerOperationEnvelope {
        body: Some(proto::LedgerOperationBody {
            operation_id: operation.operation_id.clone(),
            cluster_id: operation.cluster_id.clone(),
            node_id: operation.node_id.clone(),
            node_seq: operation.node_seq,
            op_type: operation.op_type.clone(),
            payload_json: operation.payload_json.to_string(),
            created_at: operation.created_at.to_rfc3339(),
            prev_hash_b64: operation.prev_hash_b64.clone(),
        }),
        body_hash_b64: operation.body_hash_b64.clone(),
        signing_public_key_b64: operation.signing_public_key_b64.clone(),
        signature_b64: operation.signature_b64.clone(),
        position: operation.position,
    }
}

fn to_proto_ledger_envelope(
    envelope: &CoreLedgerOperationEnvelope,
) -> proto::LedgerOperationEnvelope {
    proto::LedgerOperationEnvelope {
        body: Some(proto::LedgerOperationBody {
            operation_id: envelope.body.operation_id.clone(),
            cluster_id: envelope.body.cluster_id.clone(),
            node_id: envelope.body.node_id.clone(),
            node_seq: envelope.body.node_seq,
            op_type: envelope.body.op_type.clone(),
            payload_json: envelope.body.payload_json.to_string(),
            created_at: envelope.body.created_at.to_rfc3339(),
            prev_hash_b64: envelope.body.prev_hash_b64.clone(),
        }),
        body_hash_b64: envelope.body_hash_b64.clone(),
        signing_public_key_b64: envelope.signing_public_key_b64.clone(),
        signature_b64: envelope.signature_b64.clone(),
        position: 0,
    }
}

fn from_proto_ledger_operation(
    operation: proto::LedgerOperationEnvelope,
) -> Result<CoreLedgerOperationEnvelope, Status> {
    let body = operation
        .body
        .ok_or_else(|| Status::invalid_argument("ledger operation body is required"))?;
    let payload_json = serde_json::from_str(body.payload_json.as_str())
        .map_err(|err| Status::invalid_argument(format!("payload_json must be JSON: {err}")))?;
    Ok(CoreLedgerOperationEnvelope {
        body: CoreLedgerOperationBody {
            operation_id: body.operation_id,
            cluster_id: body.cluster_id,
            node_id: body.node_id,
            node_seq: body.node_seq,
            op_type: body.op_type,
            payload_json,
            created_at: parse_required_rfc3339("created_at", body.created_at.as_str())?,
            prev_hash_b64: body.prev_hash_b64,
        },
        body_hash_b64: operation.body_hash_b64,
        signing_public_key_b64: operation.signing_public_key_b64,
        signature_b64: operation.signature_b64,
    })
}

fn to_proto_checkpoint(checkpoint: &CoreLedgerCheckpoint) -> proto::LedgerCheckpoint {
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

fn from_proto_checkpoint(
    checkpoint: proto::LedgerCheckpoint,
) -> Result<CoreLedgerCheckpoint, Status> {
    let body = checkpoint
        .body
        .ok_or_else(|| Status::invalid_argument("checkpoint body is required"))?;
    Ok(CoreLedgerCheckpoint {
        body: CoreLedgerCheckpointBody {
            checkpoint_id: body.checkpoint_id,
            cluster_id: body.cluster_id,
            to_position: body.to_position,
            operation_count: body.operation_count,
            merkle_root_b64: body.merkle_root_b64,
            created_at: parse_required_rfc3339("created_at", body.created_at.as_str())?,
        },
        body_hash_b64: checkpoint.body_hash_b64,
        signer_node_id: checkpoint.signer_node_id,
        signing_public_key_b64: checkpoint.signing_public_key_b64,
        signature_b64: checkpoint.signature_b64,
    })
}

fn to_proto_checkpoint_cosignature(
    cosignature: &CoreLedgerCheckpointCosignature,
) -> proto::LedgerCheckpointCosignature {
    proto::LedgerCheckpointCosignature {
        body: Some(proto::LedgerCheckpointCosignatureBody {
            checkpoint_id: cosignature.body.checkpoint_id.clone(),
            checkpoint_body_hash_b64: cosignature.body.checkpoint_body_hash_b64.clone(),
            signer_node_id: cosignature.body.signer_node_id.clone(),
            signed_at: cosignature.body.signed_at.to_rfc3339(),
        }),
        signing_public_key_b64: cosignature.signing_public_key_b64.clone(),
        signature_b64: cosignature.signature_b64.clone(),
    }
}

fn from_proto_checkpoint_cosignature(
    cosignature: proto::LedgerCheckpointCosignature,
) -> Result<CoreLedgerCheckpointCosignature, Status> {
    let body = cosignature
        .body
        .ok_or_else(|| Status::invalid_argument("checkpoint cosignature body is required"))?;
    Ok(CoreLedgerCheckpointCosignature {
        body: CoreLedgerCheckpointCosignatureBody {
            checkpoint_id: body.checkpoint_id,
            checkpoint_body_hash_b64: body.checkpoint_body_hash_b64,
            signer_node_id: body.signer_node_id,
            signed_at: parse_required_rfc3339("signed_at", body.signed_at.as_str())?,
        },
        signing_public_key_b64: cosignature.signing_public_key_b64,
        signature_b64: cosignature.signature_b64,
    })
}

fn to_proto_token_info(claims: &TokenClaims) -> TokenInfo {
    TokenInfo {
        token_id: claims.token_id.clone(),
        token_type: to_proto_token_type(claims.token_type.clone()),
        issued_at: claims.issued_at.to_rfc3339(),
        expires_at: claims.expires_at.to_rfc3339(),
        issued_by: claims.issued_by.clone(),
        service_name: claims.service_name.clone().unwrap_or_default(),
        identity_id: claims.identity_id.clone().unwrap_or_default(),
        project: claims.project.clone().unwrap_or_default(),
        scopes: claims
            .scopes
            .iter()
            .map(to_proto_secret_scope_kind)
            .collect(),
    }
}

fn to_proto_token_type(token_type: TokenType) -> i32 {
    match token_type {
        TokenType::Operator => proto::TokenType::Operator as i32,
        TokenType::Service => proto::TokenType::Service as i32,
        TokenType::AgentRun => proto::TokenType::AgentRun as i32,
    }
}

fn to_resolution_context(context: Option<proto::ScopeResolutionContext>) -> ScopeResolutionContext {
    match context {
        Some(context) => ScopeResolutionContext {
            identity_id: normalize_optional_string(context.identity_id),
            project: normalize_optional_string(context.project),
        },
        None => ScopeResolutionContext::default(),
    }
}

fn merge_secret_infos(
    local: Vec<CoreSecretInfo>,
    distributed: Vec<CoreSecretInfo>,
) -> Vec<CoreSecretInfo> {
    let mut by_ref = HashMap::new();
    for item in local {
        by_ref.insert(secret_info_key(&item), item);
    }
    for item in distributed {
        by_ref.insert(secret_info_key(&item), item);
    }

    let mut out = by_ref.into_values().collect::<Vec<_>>();
    out.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| scope_label(&left.scope).cmp(&scope_label(&right.scope)))
    });
    out
}

fn secret_info_key(info: &CoreSecretInfo) -> (String, String) {
    (scope_label(&info.scope), info.name.clone())
}

fn secret_info_from_ledger_metadata(
    metadata: CoreLedgerSecretMetadata,
) -> Result<CoreSecretInfo, Status> {
    Ok(CoreSecretInfo {
        scope: secret_scope_from_label(metadata.scope.as_str())?,
        name: metadata.name,
        description: metadata.description,
        requires_approval: metadata.requires_approval,
        group: metadata.group,
        created_at: metadata.updated_at,
        updated_at: metadata.updated_at,
        created_by: metadata.updated_by,
        last_accessed_at: None,
        last_accessed_by: None,
    })
}

fn secret_scope_from_label(value: &str) -> Result<SecretScope, Status> {
    match value.split('/').collect::<Vec<_>>().as_slice() {
        ["global"] => Ok(SecretScope::Global),
        ["project", project] => Ok(SecretScope::Project {
            project: parse_subject("project", project)?,
        }),
        ["identity", identity_id] => Ok(SecretScope::Identity {
            identity_id: parse_subject("identity_id", identity_id)?,
        }),
        _ => Err(Status::failed_precondition(format!(
            "ledger secret metadata has invalid scope: {value}"
        ))),
    }
}

fn parse_optional_scope_selector(
    scope: Option<proto::ScopeSelector>,
) -> Result<Option<SecretScope>, Status> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    let kind = proto::SecretScope::try_from(scope.scope)
        .map_err(|_| Status::invalid_argument("invalid secret scope enum"))?;
    match kind {
        proto::SecretScope::Unspecified => Ok(None),
        proto::SecretScope::Global => Ok(Some(SecretScope::Global)),
        proto::SecretScope::Project => Ok(Some(SecretScope::Project {
            project: parse_subject("project", scope.project.as_str())?,
        })),
        proto::SecretScope::Identity => Ok(Some(SecretScope::Identity {
            identity_id: parse_subject("identity_id", scope.identity_id.as_str())?,
        })),
    }
}

fn parse_scope_selector_or_global(
    scope: Option<proto::ScopeSelector>,
) -> Result<SecretScope, Status> {
    Ok(parse_optional_scope_selector(scope)?.unwrap_or(SecretScope::Global))
}

fn scope_label(scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project { project } => format!("project/{project}"),
        SecretScope::Identity { identity_id } => format!("identity/{identity_id}"),
    }
}

fn secret_not_found_status(scope: &SecretScope, name: &str) -> Status {
    Status::not_found(format!("secret not found: {}/{}", scope_label(scope), name))
}

fn sorted_secret_keys<'a>(keys: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut keys = keys.cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

fn parse_secret_name(name: &str) -> Result<String, Status> {
    parse_subject("name", name)
}

fn parse_group_name(name: &str) -> Result<String, Status> {
    parse_subject("group", name)
}

fn parse_subject(label: &str, value: &str) -> Result<String, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{label} must not be empty"
        )));
    }
    Ok(value.to_string())
}

fn collect_scan_matches(text: &str, candidates: &[ScanCandidate]) -> Vec<ScanMatchRecord> {
    let mut out = Vec::new();
    for candidate in candidates {
        if candidate.value.is_empty() {
            continue;
        }
        for (offset, _) in text.match_indices(candidate.value.as_str()) {
            out.push(ScanMatchRecord {
                secret_ref: candidate.secret_ref.clone(),
                key: candidate.key.clone(),
                offset: offset.min(u32::MAX as usize) as u32,
            });
        }
    }
    out.sort_by(|left, right| {
        left.offset
            .cmp(&right.offset)
            .then(left.secret_ref.cmp(&right.secret_ref))
            .then(left.key.cmp(&right.key))
    });
    out
}

fn normalize_optional_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_bool_env(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| parse_bool_like(value.as_str()))
        .unwrap_or(false)
}

fn parse_bool_like(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_duration_ms_value(
    value: Option<&str>,
    default_ms: u64,
    min_ms: u64,
    max_ms: u64,
) -> Duration {
    Duration::from_millis(parse_u64_value(value, default_ms, min_ms, max_ms))
}

fn parse_u32_value(value: Option<&str>, default: u32, min: u32, max: u32) -> u32 {
    value
        .and_then(|item| item.trim().parse::<u32>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn parse_u64_value(value: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    value
        .and_then(|item| item.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn stable_jitter_ms(peer_node_id: &str, failure_count: u32) -> u64 {
    let mut hasher = DefaultHasher::new();
    peer_node_id.hash(&mut hasher);
    failure_count.hash(&mut hasher);
    hasher.finish()
}

fn to_proto_secret_scope_selector(scope: &SecretScope) -> proto::ScopeSelector {
    match scope {
        SecretScope::Global => proto::ScopeSelector {
            scope: proto::SecretScope::Global as i32,
            project: String::new(),
            identity_id: String::new(),
        },
        SecretScope::Project { project } => proto::ScopeSelector {
            scope: proto::SecretScope::Project as i32,
            project: project.clone(),
            identity_id: String::new(),
        },
        SecretScope::Identity { identity_id } => proto::ScopeSelector {
            scope: proto::SecretScope::Identity as i32,
            project: String::new(),
            identity_id: identity_id.clone(),
        },
    }
}

fn to_proto_secret_scope_kind(scope: &SecretScope) -> i32 {
    match scope {
        SecretScope::Global => proto::SecretScope::Global as i32,
        SecretScope::Project { .. } => proto::SecretScope::Project as i32,
        SecretScope::Identity { .. } => proto::SecretScope::Identity as i32,
    }
}

fn format_scope(scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project { project } => format!("project/{project}"),
        SecretScope::Identity { identity_id } => format!("identity/{identity_id}"),
    }
}

fn to_proto_grant_info(info: &CoreGrantInfo) -> GrantInfo {
    GrantInfo {
        secret: Some(proto::SecretRef {
            scope: Some(to_proto_secret_scope_selector(&info.secret_scope)),
            name: info.secret_name.clone(),
        }),
        grantee_scope: Some(to_proto_secret_scope_selector(&info.grantee_scope)),
        grantee_id: info.grantee_id.clone(),
        created_at: info.created_at.to_rfc3339(),
        created_by: info.created_by.clone(),
    }
}

fn to_proto_audit_entry(entry: &CoreAuditEntry) -> proto::AuditEntry {
    let secret = entry.secret_scope.as_ref().map(|scope| proto::SecretRef {
        scope: Some(to_proto_secret_scope_selector(scope)),
        name: entry.secret_name.clone(),
    });
    proto::AuditEntry {
        audit_id: entry.audit_id.clone(),
        ts: entry.ts.to_rfc3339(),
        action: entry.action.clone(),
        actor: entry.actor.clone(),
        token_id: entry.token_id.clone(),
        secret,
        result: entry.result.clone(),
        details: entry.details.clone(),
    }
}

fn to_proto_secret_info(info: CoreSecretInfo) -> SecretInfo {
    SecretInfo {
        scope: Some(to_proto_secret_scope_selector(&info.scope)),
        name: info.name,
        description: info.description,
        requires_approval: info.requires_approval,
        group: info.group.unwrap_or_default(),
        created_at: info.created_at.to_rfc3339(),
        updated_at: info.updated_at.to_rfc3339(),
        created_by: info.created_by,
        last_accessed_at: info
            .last_accessed_at
            .map(|item| item.to_rfc3339())
            .unwrap_or_default(),
        last_accessed_by: info.last_accessed_by.unwrap_or_default(),
    }
}

fn to_proto_secret_with_values(secret: CoreSecretWithValues) -> proto::SecretWithValues {
    proto::SecretWithValues {
        info: Some(to_proto_secret_info(secret.info)),
        values: secret.values,
    }
}

fn to_proto_group_info(info: CoreGroupInfo) -> proto::GroupInfo {
    proto::GroupInfo {
        name: info.name,
        description: info.description,
        created_at: info.created_at.to_rfc3339(),
        updated_at: info.updated_at.to_rfc3339(),
    }
}

fn to_proto_approval_request_info(record: &DeleteApprovalRecord) -> proto::ApprovalRequestInfo {
    proto::ApprovalRequestInfo {
        request_id: record.request_id.clone(),
        state: to_proto_approval_state(record.state.clone()),
        secret: Some(proto::SecretRef {
            scope: Some(to_proto_secret_scope_selector(&record.secret_scope)),
            name: record.secret_name.clone(),
        }),
        requester_token_id: record.requested_by.clone(),
        requester_identity_id: String::new(),
        requester_project: String::new(),
        reason: record.reason.clone(),
        created_at: record.created_at.to_rfc3339(),
        resolved_at: record
            .resolved_at
            .map(|item| item.to_rfc3339())
            .unwrap_or_default(),
        resolved_by: record.resolved_by.clone().unwrap_or_default(),
        resolve_message: record.resolve_message.clone(),
        action: record.action.clone(),
        secret_version: record.secret_version.clone().unwrap_or_default(),
    }
}

fn to_proto_approval_state(state: CoreApprovalState) -> i32 {
    match state {
        CoreApprovalState::Pending => proto::ApprovalState::Pending as i32,
        CoreApprovalState::Approved => proto::ApprovalState::Approved as i32,
        CoreApprovalState::Denied => proto::ApprovalState::Denied as i32,
        CoreApprovalState::TimedOut => proto::ApprovalState::TimedOut as i32,
    }
}

fn proto_approval_state_to_core(state: proto::ApprovalState) -> CoreApprovalState {
    match state {
        proto::ApprovalState::Pending => CoreApprovalState::Pending,
        proto::ApprovalState::Approved => CoreApprovalState::Approved,
        proto::ApprovalState::Denied => CoreApprovalState::Denied,
        proto::ApprovalState::TimedOut => CoreApprovalState::TimedOut,
        proto::ApprovalState::Unspecified => CoreApprovalState::Pending,
    }
}

fn status_from_hem(err: HemError) -> Status {
    match err {
        HemError::InvalidArgument(message) => Status::invalid_argument(message),
        HemError::MissingMasterKey(_) | HemError::InsecureMasterKeyPermissions(_) => {
            Status::failed_precondition(err.to_string())
        }
        HemError::SecretNotFound(_)
        | HemError::GroupNotFound(_)
        | HemError::ApprovalRequestNotFound(_) => Status::not_found(err.to_string()),
        HemError::ApprovalAlreadyResolved(_)
        | HemError::ApprovalReceiptRequired
        | HemError::ApprovalReceiptExpired
        | HemError::ApprovalReceiptConsumed => Status::failed_precondition(err.to_string()),
        HemError::ApprovalReceiptInvalid => Status::permission_denied(err.to_string()),
        HemError::TokenMalformed
        | HemError::TokenSignatureInvalid
        | HemError::TokenExpired
        | HemError::TokenRevoked(_) => Status::unauthenticated(err.to_string()),
        HemError::TokenTtlExceeded => Status::invalid_argument(err.to_string()),
        HemError::AuthorizationDenied(_) => Status::permission_denied(err.to_string()),
        HemError::Io(_)
        | HemError::Serde(_)
        | HemError::Sqlite(_)
        | HemError::MasterKeyParse(_)
        | HemError::Crypto(_) => Status::internal(err.to_string()),
    }
}

fn read_receipt_push_error_requires_resign(err: &Status) -> bool {
    matches!(
        err.code(),
        Code::AlreadyExists | Code::FailedPrecondition | Code::InvalidArgument
    )
}

fn checkpoint_cosign_status_from_hem(err: HemError) -> Status {
    match err {
        HemError::InvalidArgument(message)
            if message.contains("checkpoint position")
                || message.contains("checkpoint operation count mismatch") =>
        {
            Status::failed_precondition(message)
        }
        HemError::Crypto(message) if message.contains("checkpoint merkle root mismatch") => {
            Status::failed_precondition(message)
        }
        other => status_from_hem(other),
    }
}

fn write_operator_token(data_dir: &Path, token: &str) -> Result<(), Status> {
    let path = data_dir.join("operator.token");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| Status::internal(err.to_string()))?;
    }
    let temp = path.with_extension("tmp");
    fs::write(temp.as_path(), token.as_bytes()).map_err(|err| Status::internal(err.to_string()))?;
    fs::rename(temp.as_path(), path.as_path()).map_err(|err| Status::internal(err.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path.as_path(), fs::Permissions::from_mode(0o600))
            .map_err(|err| Status::internal(err.to_string()))?;
    }

    Ok(())
}

fn resolve_data_dir(override_value: Option<String>) -> PathBuf {
    if let Some(value) = normalize_optional_string(override_value.unwrap_or_default()) {
        return PathBuf::from(value);
    }
    if let Ok(value) = std::env::var("HEM_DATA_DIR") {
        if let Some(value) = normalize_optional_string(value) {
            return PathBuf::from(value);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(DEFAULT_HEM_SUBDIR);
    }
    PathBuf::from(DEFAULT_HEM_SUBDIR)
}

fn load_cluster_runtime(data_dir: &Path) -> Result<ClusterRuntimeInfo, Box<dyn std::error::Error>> {
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    if !config_path.exists() {
        return Ok(ClusterRuntimeInfo::disabled());
    }

    let config = ClusterConfig::load(config_path.as_path())?;
    if !config.enabled {
        return Ok(ClusterRuntimeInfo::disabled());
    }

    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    let identity = NodeIdentity::load(identity_path.as_path())?;
    if identity.node_id != config.node_id {
        return Err(HemError::InvalidArgument(format!(
            "cluster node_id {} does not match node identity {}",
            config.node_id, identity.node_id
        ))
        .into());
    }

    let force_offline = parse_bool_env("VALHALL_HEM_FORCE_OFFLINE");
    let sync_settings = ClusterSyncSettings::from_env(true, force_offline);
    Ok(ClusterRuntimeInfo {
        enabled: true,
        cluster_id: Some(config.cluster_id),
        node_id: Some(config.node_id),
        master_node_id: config.master_node_id,
        peer_count: config.peers.len(),
        force_offline,
        sync_enabled: sync_settings.enabled,
    })
}

fn spawn_cluster_sync_loop(
    data_dir: PathBuf,
    runtime: &ClusterRuntimeInfo,
) -> Option<tokio::task::JoinHandle<()>> {
    let settings = ClusterSyncSettings::from_env(runtime.enabled, runtime.force_offline);
    if !settings.enabled {
        return None;
    }
    Some(tokio::spawn(async move {
        run_cluster_sync_loop(data_dir, settings).await;
    }))
}

async fn run_cluster_sync_loop(data_dir: PathBuf, settings: ClusterSyncSettings) {
    let mut peer_states: HashMap<String, PeerSyncState> = HashMap::new();
    let mut interval = tokio::time::interval(settings.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let now = Instant::now();
        let config = match ClusterConfig::load(data_dir.join(CLUSTER_CONFIG_FILE).as_path()) {
            Ok(config) if config.enabled => config,
            Ok(_) => continue,
            Err(err) => {
                warn!(
                    error = %err,
                    data_dir = %data_dir.display(),
                    "hem cluster sync config load failed"
                );
                continue;
            }
        };
        let identity = match NodeIdentity::load(data_dir.join(NODE_IDENTITY_FILE).as_path()) {
            Ok(identity) => identity,
            Err(err) => {
                warn!(
                    error = %err,
                    data_dir = %data_dir.display(),
                    "hem cluster sync identity load failed"
                );
                continue;
            }
        };
        if identity.node_id != config.node_id {
            warn!(
                cluster_node_id = %config.node_id,
                identity_node_id = %identity.node_id,
                "hem cluster sync identity mismatch"
            );
            continue;
        }
        match ensure_latest_cluster_checkpoint(data_dir.as_path(), &config, &identity) {
            Ok(Some(checkpoint)) => {
                info!(
                    cluster_id = %config.cluster_id,
                    node_id = %config.node_id,
                    checkpoint_id = %checkpoint.body.checkpoint_id,
                    checkpoint_position = checkpoint.body.to_position,
                    "hem cluster checkpoint available"
                );
            }
            Ok(None) => {}
            Err(err) => {
                warn!(
                    cluster_id = %config.cluster_id,
                    node_id = %config.node_id,
                    error = %err,
                    "hem cluster checkpoint creation failed"
                );
            }
        }

        for peer in config.peers.clone() {
            let state = peer_states.entry(peer.node_id.clone()).or_default();
            if state
                .next_attempt
                .map(|next_attempt| now < next_attempt)
                .unwrap_or(false)
            {
                continue;
            }

            info!(
                cluster_id = %config.cluster_id,
                node_id = %config.node_id,
                peer_node_id = %peer.node_id,
                peer_endpoint = %peer.endpoint,
                "hem cluster sync peer start"
            );
            match sync_configured_peer_once(
                data_dir.as_path(),
                &config,
                &identity,
                &peer,
                settings.batch_limit,
            )
            .await
            {
                Ok(report) => {
                    state.failures = 0;
                    state.next_attempt = Some(Instant::now() + settings.interval);
                    let lag = report
                        .peer_latest_position
                        .saturating_sub(report.local_latest_position)
                        .max(0);
                    info!(
                        cluster_id = %config.cluster_id,
                        node_id = %config.node_id,
                        peer_node_id = %peer.node_id,
                        peer_endpoint = %peer.endpoint,
                        peer_accepted = report.accepted,
                        peer_latest_position = report.peer_latest_position,
                        pulled_operations = report.pulled_operations,
                        pushed_operations = report.pushed_operations,
                        local_latest_position = report.local_latest_position,
                        checkpoint_id = report.checkpoint_id.as_deref().unwrap_or(""),
                        checkpoint_position = report.checkpoint_position.unwrap_or(0),
                        checkpoint_cosigned = report.checkpoint_cosigned,
                        lag,
                        "hem cluster sync peer success"
                    );
                }
                Err(err) => {
                    state.failures = state.failures.saturating_add(1);
                    let backoff =
                        settings.backoff_for_failure(peer.node_id.as_str(), state.failures);
                    state.next_attempt = Some(Instant::now() + backoff);
                    warn!(
                        cluster_id = %config.cluster_id,
                        node_id = %config.node_id,
                        peer_node_id = %peer.node_id,
                        peer_endpoint = %peer.endpoint,
                        failures = state.failures,
                        backoff_ms = duration_millis_u64(backoff),
                        error = %err,
                        "hem cluster sync peer failure"
                    );
                }
            }
        }
    }
}

async fn sync_configured_peer_once(
    data_dir: &Path,
    config: &ClusterConfig,
    identity: &NodeIdentity,
    peer: &PeerConfig,
    batch_limit: u32,
) -> Result<ClusterPeerSyncReport, Box<dyn std::error::Error + Send + Sync>> {
    let channel = Endpoint::from_shared(peer.endpoint.clone())?
        .connect_timeout(Duration::from_secs(CLUSTER_SYNC_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(CLUSTER_SYNC_RPC_TIMEOUT_SECS))
        .connect()
        .await?;
    let mut client = HemRuntimeClient::new(channel);
    let hello = client
        .peer_hello(signed_peer_transport_request(
            PeerHelloRequest {
                cluster_id: config.cluster_id.clone(),
                node_id: config.node_id.clone(),
                public_key: identity.signing_public_key_b64.clone(),
            },
            identity,
            config.cluster_id.as_str(),
            PEER_METHOD_HELLO,
        )?)
        .await?
        .into_inner();
    if !hello.accepted {
        return Err(format!("peer {} rejected hello", peer.node_id).into());
    }
    if hello.node_id != peer.node_id {
        return Err(format!(
            "peer hello node_id mismatch expected={} actual={}",
            peer.node_id, hello.node_id
        )
        .into());
    }
    if hello.cluster_id != config.cluster_id {
        return Err(format!(
            "peer hello cluster_id mismatch expected={} actual={}",
            config.cluster_id, hello.cluster_id
        )
        .into());
    }

    let ledger = hem_core::LedgerStore::open(data_dir)?;
    let remote = client
        .peer_list_operations(signed_peer_transport_request(
            PeerListOperationsRequest {
                after_position: 0,
                limit: batch_limit,
                peer_node_id: config.node_id.clone(),
                use_recorded_cursor: true,
            },
            identity,
            config.cluster_id.as_str(),
            PEER_METHOD_LIST_OPERATIONS,
        )?)
        .await?
        .into_inner();
    let pulled_operations = remote.operations.len();
    if !remote.operations.is_empty() {
        let envelopes = remote
            .operations
            .iter()
            .cloned()
            .map(from_proto_ledger_operation)
            .collect::<Result<Vec<_>, _>>()?;
        ledger
            .bootstrap_from_peer_operations(config.cluster_id.as_str(), &envelopes)
            .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
        if let Some(last) = remote.operations.last() {
            client
                .peer_ack_operations(signed_peer_transport_request(
                    PeerAckOperationsRequest {
                        peer_node_id: config.node_id.clone(),
                        position: last.position,
                        body_hash_b64: last.body_hash_b64.clone(),
                    },
                    identity,
                    config.cluster_id.as_str(),
                    PEER_METHOD_ACK_OPERATIONS,
                )?)
                .await?;
        }
    }

    let peer_cursor = ledger
        .get_peer_cursor(peer.node_id.as_str())
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?
        .map(|cursor| cursor.last_position)
        .unwrap_or(0);
    let local_batch = ledger
        .list_after(peer_cursor, batch_limit as usize)
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
    let pushed_operations = if local_batch.is_empty() {
        0
    } else {
        let last_sent = local_batch.last().cloned();
        let pushed = client
            .peer_push_operations(signed_peer_transport_request(
                PeerPushOperationsRequest {
                    operations: local_batch.iter().map(to_proto_ledger_operation).collect(),
                },
                identity,
                config.cluster_id.as_str(),
                PEER_METHOD_PUSH_OPERATIONS,
            )?)
            .await?
            .into_inner();
        if let Some(last_sent) = last_sent {
            ledger
                .record_peer_cursor(
                    peer.node_id.as_str(),
                    last_sent.position,
                    last_sent.body_hash_b64.as_str(),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
        }
        pushed.accepted_count
    };
    let local_latest_position = ledger
        .latest_position()
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
    let shared_position = ledger
        .get_peer_cursor(peer.node_id.as_str())
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?
        .map(|cursor| cursor.last_position.min(local_latest_position))
        .unwrap_or(0);
    let mut checkpoint_id = None;
    let mut checkpoint_position = None;
    let mut checkpoint_cosigned = false;
    if let Some(checkpoint) = ensure_checkpoint_at_position(
        &ledger,
        identity,
        config.cluster_id.as_str(),
        shared_position,
    )
    .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?
    {
        let response = client
            .peer_cosign_checkpoint(signed_peer_transport_request(
                PeerCosignCheckpointRequest {
                    requester_node_id: config.node_id.clone(),
                    requester_public_key: identity.signing_public_key_b64.clone(),
                    checkpoint: Some(to_proto_checkpoint(&checkpoint)),
                },
                identity,
                config.cluster_id.as_str(),
                PEER_METHOD_COSIGN_CHECKPOINT,
            )?)
            .await?
            .into_inner();
        if !response.accepted {
            return Err(format!(
                "peer {} rejected checkpoint cosignature: {}",
                peer.node_id, response.reason
            )
            .into());
        }
        if response.cluster_id != config.cluster_id {
            return Err(format!(
                "checkpoint cosignature cluster_id mismatch expected={} actual={}",
                config.cluster_id, response.cluster_id
            )
            .into());
        }
        if response.node_id != peer.node_id {
            return Err(format!(
                "checkpoint cosignature node_id mismatch expected={} actual={}",
                peer.node_id, response.node_id
            )
            .into());
        }
        let cosignature =
            from_proto_checkpoint_cosignature(response.cosignature.ok_or_else(|| {
                "peer checkpoint cosignature response missing cosignature".to_string()
            })?)?;
        if cosignature.body.signer_node_id != peer.node_id {
            return Err(format!(
                "checkpoint cosignature signer mismatch expected={} actual={}",
                peer.node_id, cosignature.body.signer_node_id
            )
            .into());
        }
        if cosignature.signing_public_key_b64 != peer.public_key {
            return Err(format!(
                "checkpoint cosignature public key mismatch for peer {}",
                peer.node_id
            )
            .into());
        }
        ledger
            .ingest_checkpoint_cosignature(&cosignature)
            .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
        checkpoint_id = Some(checkpoint.body.checkpoint_id.clone());
        checkpoint_position = Some(checkpoint.body.to_position);
        checkpoint_cosigned = true;
    }

    Ok(ClusterPeerSyncReport {
        accepted: hello.accepted,
        peer_latest_position: hello.latest_position,
        pulled_operations,
        pushed_operations,
        local_latest_position,
        checkpoint_id,
        checkpoint_position,
        checkpoint_cosigned,
    })
}

fn ensure_checkpoint_at_position(
    ledger: &hem_core::LedgerStore,
    identity: &NodeIdentity,
    cluster_id: &str,
    to_position: i64,
) -> hem_core::Result<Option<CoreLedgerCheckpoint>> {
    if to_position < 1 {
        return Ok(None);
    }
    if let Some(existing) = ledger.list_checkpoints()?.into_iter().find(|checkpoint| {
        checkpoint.body.cluster_id == cluster_id
            && checkpoint.body.to_position == to_position
            && checkpoint.signer_node_id == identity.node_id
            && checkpoint.signing_public_key_b64 == identity.signing_public_key_b64
    }) {
        return Ok(Some(existing));
    }
    ledger
        .create_checkpoint(identity, cluster_id, to_position)
        .map(Some)
}

fn ensure_latest_cluster_checkpoint(
    data_dir: &Path,
    config: &ClusterConfig,
    identity: &NodeIdentity,
) -> hem_core::Result<Option<CoreLedgerCheckpoint>> {
    let ledger = hem_core::LedgerStore::open(data_dir)?;
    let latest_position = ledger.latest_position()?;
    ensure_checkpoint_at_position(
        &ledger,
        identity,
        config.cluster_id.as_str(),
        latest_position,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    if matches!(cli.command, Some(CliCommand::Usage)) {
        print_usage();
        return Ok(());
    }
    let data_dir = resolve_data_dir(cli.data_dir);
    let initialized = match HemStore::open(data_dir.as_path()) {
        Ok(_) => true,
        Err(HemError::MissingMasterKey(_)) => {
            info!(
                data_dir = %data_dir.display(),
                "hemd data dir ready; master key missing (run `hem init`)"
            );
            false
        }
        Err(err) => return Err(Box::new(err) as Box<dyn std::error::Error>),
    };
    let cluster_runtime = load_cluster_runtime(data_dir.as_path())?;
    let mut mesh = match Mesh::connect("hemd", MeshConfig::from_env().unwrap_or_default()).await {
        Ok(mesh) => Some(Arc::new(mesh)),
        Err(err) => {
            warn!(error = %err, "mesh unavailable; continuing without hem event emission");
            None
        }
    };

    if cli.once {
        println!(
            "hemd_once initialized={} {} data_dir={}",
            initialized,
            cluster_runtime.health_status(),
            data_dir.display()
        );
        info!(
            bind = %cli.bind,
            data_dir = %data_dir.display(),
            initialized,
            cluster_enabled = cluster_runtime.enabled,
            cluster_node_id = cluster_runtime.node_id.as_deref().unwrap_or(""),
            cluster_peers = cluster_runtime.peer_count,
            cluster_sync_enabled = cluster_runtime.sync_enabled,
            "hemd bootstrap check complete"
        );
        if let Some(mesh_handle) = mesh.take() {
            if let Ok(mesh_owned) = Arc::try_unwrap(mesh_handle) {
                let _ = mesh_owned.shutdown().await;
            }
        }
        return Ok(());
    }

    let addr: SocketAddr = cli.bind.parse()?;
    info!(
        bind = %addr,
        data_dir = %data_dir.display(),
        initialized,
        cluster_enabled = cluster_runtime.enabled,
        cluster_node_id = cluster_runtime.node_id.as_deref().unwrap_or(""),
        cluster_peers = cluster_runtime.peer_count,
        cluster_sync_enabled = cluster_runtime.sync_enabled,
        "starting hemd"
    );

    let sync_loop = spawn_cluster_sync_loop(data_dir.clone(), &cluster_runtime);
    Server::builder()
        .add_service(HemRuntimeServer::new(HemRuntimeService::new(
            data_dir,
            mesh.clone(),
            cluster_runtime,
        )))
        .serve(addr)
        .await?;
    if let Some(sync_loop) = sync_loop {
        sync_loop.abort();
        let _ = sync_loop.await;
    }

    if let Some(mesh_handle) = mesh.take() {
        if let Ok(mesh_owned) = Arc::try_unwrap(mesh_handle) {
            let _ = mesh_owned.shutdown().await;
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Hemd usage");
    println!("  Shorthand: u usage");
    println!("  hemd --bind 127.0.0.1:50091");
    println!("  hemd --data-dir ~/.valhall/hem");
    println!("  hemd --once");
    println!("  hemd u");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_scan_matches_reports_offsets_and_sorts() {
        let candidates = vec![
            ScanCandidate {
                secret_ref: "global/openai-prod".to_string(),
                key: "api_key".to_string(),
                value: "abc123".to_string(),
            },
            ScanCandidate {
                secret_ref: "global/tobber-telegram".to_string(),
                key: "bot_token".to_string(),
                value: "xyz".to_string(),
            },
        ];
        let matches =
            collect_scan_matches("prefix xyz and abc123 then abc123", candidates.as_slice());
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].secret_ref, "global/tobber-telegram");
        assert_eq!(matches[0].offset, 7);
        assert_eq!(matches[1].secret_ref, "global/openai-prod");
        assert_eq!(matches[1].offset, 15);
        assert_eq!(matches[2].secret_ref, "global/openai-prod");
        assert_eq!(matches[2].offset, 27);
    }

    #[test]
    fn collect_scan_matches_skips_empty_values() {
        let candidates = vec![ScanCandidate {
            secret_ref: "global/empty".to_string(),
            key: "value".to_string(),
            value: String::new(),
        }];
        let matches = collect_scan_matches("any text", candidates.as_slice());
        assert!(matches.is_empty());
    }

    #[test]
    fn cluster_sync_settings_disable_with_env_or_offline_mode() {
        assert!(!ClusterSyncSettings::from_values(true, true, None, None, None,).enabled);
        assert!(!ClusterSyncSettings::from_values(true, false, Some("0"), None, None,).enabled);
        assert!(!ClusterSyncSettings::from_values(false, false, Some("1"), None, None,).enabled);
    }

    #[test]
    fn cluster_sync_backoff_is_bounded_and_peer_stable() {
        let settings =
            ClusterSyncSettings::from_values(true, false, Some("1"), Some("100"), Some("1000"));
        assert!(settings.enabled);
        assert_eq!(settings.interval, Duration::from_millis(100));
        assert_eq!(settings.max_backoff, Duration::from_millis(1000));

        let first = settings.backoff_for_failure("hmn_peer", 1);
        let second = settings.backoff_for_failure("hmn_peer", 2);
        let capped = settings.backoff_for_failure("hmn_peer", 20);
        assert!(first >= Duration::from_millis(100));
        assert!(second >= first);
        assert!(capped <= Duration::from_millis(1000));
        assert_eq!(first, settings.backoff_for_failure("hmn_peer", 1));
    }

    #[test]
    fn merge_secret_infos_adds_distributed_and_overrides_local() {
        let merged = merge_secret_infos(
            vec![
                test_secret_info(SecretScope::Global, "shared", "local"),
                test_secret_info(
                    SecretScope::Project {
                        project: "demo".to_string(),
                    },
                    "local-only",
                    "local project",
                ),
            ],
            vec![
                test_secret_info(SecretScope::Global, "shared", "distributed"),
                test_secret_info(
                    SecretScope::Identity {
                        identity_id: "agent-a".to_string(),
                    },
                    "distributed-only",
                    "distributed identity",
                ),
            ],
        );

        assert_eq!(merged.len(), 3);
        let shared = merged
            .iter()
            .find(|item| item.name == "shared")
            .expect("shared secret");
        assert_eq!(shared.description, "distributed");
        assert!(merged.iter().any(|item| item.name == "local-only"));
        assert!(merged.iter().any(|item| item.name == "distributed-only"));
    }

    #[test]
    fn secret_scope_from_label_roundtrips_supported_scopes() {
        assert_eq!(
            secret_scope_from_label("global").expect("global"),
            SecretScope::Global
        );
        assert_eq!(
            secret_scope_from_label("project/demo").expect("project"),
            SecretScope::Project {
                project: "demo".to_string()
            }
        );
        assert_eq!(
            secret_scope_from_label("identity/agent-a").expect("identity"),
            SecretScope::Identity {
                identity_id: "agent-a".to_string()
            }
        );
        assert_eq!(
            secret_scope_from_label("team/demo")
                .expect_err("unsupported scope")
                .code(),
            Code::FailedPrecondition
        );
    }

    fn test_secret_info(scope: SecretScope, name: &str, description: &str) -> CoreSecretInfo {
        let now = Utc::now();
        CoreSecretInfo {
            scope,
            name: name.to_string(),
            description: description.to_string(),
            requires_approval: false,
            group: None,
            created_at: now,
            updated_at: now,
            created_by: "tester".to_string(),
            last_accessed_at: None,
            last_accessed_by: None,
        }
    }
}
