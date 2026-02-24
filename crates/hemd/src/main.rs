#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use hem_core::{
    authorize_admin, authorize_read,
    model::{resolution_chain, ApprovalState as CoreApprovalState},
    AuditEntry as CoreAuditEntry, DeleteApprovalRecord, DeleteApprovalStore,
    GrantInfo as CoreGrantInfo, GroupInfo as CoreGroupInfo, HemError, HemStore,
    ScopeResolutionContext, SecretInfo as CoreSecretInfo, SecretScope,
    SecretWithValues as CoreSecretWithValues, SetSecretInput, TokenClaims, TokenType,
};
use serde::Serialize;
use tonic::{transport::Server, Request, Response, Status};
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
    ListSecretsRequest, ListSecretsResponse, RemoveFromGroupRequest, RemoveFromGroupResponse,
    ResolveApprovalRequest, ResolveApprovalResponse, RevokeAccessRequest, RevokeAccessResponse,
    RevokeTokenRequest, RevokeTokenResponse, RotateMasterKeyRequest, RotateMasterKeyResponse,
    SecretInfo, SetGroupRequest, SetSecretRequest, TokenInfo,
};

const DEFAULT_BIND: &str = "127.0.0.1:50091";
const DEFAULT_HEM_SUBDIR: &str = ".valhall/hem";
const DEFAULT_AGENT_TOKEN_TTL_SECS: u64 = 60 * 60;
const DEFAULT_SERVICE_TOKEN_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_OPERATOR_TOKEN_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const DEFAULT_APPROVAL_WAIT_TIMEOUT_MS: u64 = 5 * 60 * 1_000;
const APPROVAL_WAIT_POLL_INTERVAL_MS: u64 = 200;
const AUTHORIZATION_METADATA_KEY: &str = "authorization";
const APPROVAL_RECEIPT_METADATA_KEY: &str = "x-hem-approval-receipt";
const DEFAULT_GET_APPROVAL_REASON: &str = "read requires approval";
const DEFAULT_SET_APPROVAL_REASON: &str = "write requires approval";

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
}

impl HemRuntimeService {
    fn new(data_dir: PathBuf, mesh: Option<Arc<Mesh>>) -> Self {
        let approval_provider = Arc::new(LocalApprovalProvider::new(data_dir.clone()));
        Self {
            data_dir,
            approval_provider,
            mesh,
        }
    }

    fn open_store(&self) -> Result<HemStore, Status> {
        HemStore::open(self.data_dir.as_path()).map_err(status_from_hem)
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
                store
                    .get_secret(&scope, name.as_str(), actor)
                    .map_err(status_from_hem)
            }
            get_secret_request::Lookup::Name(name) => {
                let name = parse_secret_name(name.as_str())?;
                resolve_secret_by_name(store, name.as_str(), context, actor, claims)
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
        let entry = CoreAuditEntry {
            audit_id: valhall_config::ids::generate_prefixed_entropy_id("aud"),
            ts: Utc::now(),
            action: action.to_string(),
            actor,
            token_id,
            secret_scope,
            secret_name,
            result: result.to_string(),
            details: details.to_string(),
        };

        if let Err(err) = audit_store.append(&entry) {
            warn!(error = %err, "failed to append audit entry");
        }
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
                        caller.token_id.as_str(),
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
                        "requested_by": caller.token_id.as_str(),
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
                        caller.token_id.as_str(),
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
                        "requested_by": caller.token_id.as_str(),
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
            }
        }

        if let Some(key) = normalize_optional_string(req.key) {
            let value =
                secret.values.get(key.as_str()).cloned().ok_or_else(|| {
                    Status::not_found(format!("secret value key not found: {key}"))
                })?;
            secret.values = HashMap::from([(key, value)]);
        }

        self.audit(
            &store,
            Some(&caller),
            "get_secret",
            Some((&secret.info.scope, secret.info.name.as_str())),
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
                caller.token_id.as_str(),
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

        let mut secrets = match scope.as_ref() {
            Some(scope) => store.list_secrets(Some(scope)).map_err(status_from_hem)?,
            None => store.list_secrets(None).map_err(status_from_hem)?,
        };

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
                                    caller.token_id.as_str(),
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
                                    "requested_by": caller.token_id.as_str(),
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
                            secret_batch_result::Result::Secret(to_proto_secret_with_values(secret))
                        }
                    } else {
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
        let info = match groups.get_group(group.as_str()) {
            Ok(info) => info,
            Err(HemError::GroupNotFound(_)) => groups
                .set_group(group.as_str(), "")
                .map_err(status_from_hem)?,
            Err(err) => return Err(status_from_hem(err)),
        };

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
        let imported_secret_count = store
            .import_secrets_bundle(req.encrypted_bundle.as_slice(), req.merge)
            .map_err(status_from_hem)?;
        self.audit(
            &store,
            Some(&caller),
            "import_secrets",
            None,
            "ok",
            format!(
                "actor={} merge={} imported_secret_count={}",
                actor, req.merge, imported_secret_count
            )
            .as_str(),
        );
        Ok(Response::new(ImportSecretsResponse {
            imported_secret_count,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
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

fn normalize_optional_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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
        | HemError::MasterKeyParse(_)
        | HemError::Crypto(_) => Status::internal(err.to_string()),
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
    let mut mesh = match Mesh::connect("hemd", MeshConfig::from_env().unwrap_or_default()).await {
        Ok(mesh) => Some(Arc::new(mesh)),
        Err(err) => {
            warn!(error = %err, "mesh unavailable; continuing without hem event emission");
            None
        }
    };

    if cli.once {
        info!(
            bind = %cli.bind,
            data_dir = %data_dir.display(),
            initialized,
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
        "starting hemd"
    );

    Server::builder()
        .add_service(HemRuntimeServer::new(HemRuntimeService::new(
            data_dir,
            mesh.clone(),
        )))
        .serve(addr)
        .await?;

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
