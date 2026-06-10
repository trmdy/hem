use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
    Code, Request, Status,
};

pub mod proto {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("valhall.hem.v1");
}

use proto::{
    get_secret_request, get_secret_response, hem_runtime_client::HemRuntimeClient as RpcClient,
    GetSecretRequest, IssueAgentTokenRequest, ScopeResolutionContext, ScopeSelector, SecretInfo,
    SecretRef, SecretScope, SecretValue, SetSecretRequest,
};

pub const DEFAULT_HEMD_ENDPOINT: &str = "http://127.0.0.1:50091";
const OPERATOR_TOKEN_FILE: &str = "operator.token";
const DEFAULT_HEM_SUBDIR: &str = ".valhall/hem";
const DEFAULT_HEM_SYSTEM_DAEMONS_SUBDIR: &str = ".valhall/system-daemons/data/hem";

#[derive(Debug, Clone, Default)]
pub struct HemScopeContext {
    pub identity_id: Option<String>,
    pub project: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HemRuntimeClient {
    endpoint: String,
    token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HemSecretRecord {
    pub info: SecretMetadata,
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub description: String,
    pub requires_approval: bool,
    pub group: String,
}

#[derive(Debug, Error)]
pub enum HemClientError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid token header: {0}")]
    InvalidToken(String),
    #[error("invalid secret reference: {0}")]
    InvalidSecretReference(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc status {0}: {1}")]
    Rpc(Code, String),
    #[error("approval pending: request_id={request_id}")]
    ApprovalPending { request_id: String },
    #[error("rpc response missing expected payload: {0}")]
    ResponseShape(String),
}

impl HemRuntimeClient {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            endpoint: resolve_endpoint_from_env(),
            token: resolve_token_from_env_or_default_files(),
        }
    }

    #[must_use]
    pub fn from_overrides(endpoint: Option<String>, token: Option<String>) -> Self {
        let endpoint = endpoint
            .and_then(|value| normalize_optional(value.as_str()).map(ToString::to_string))
            .map(|value| normalize_endpoint(value.as_str()))
            .unwrap_or_else(resolve_endpoint_from_env);
        let token = token
            .and_then(|value| normalize_optional(value.as_str()).map(ToString::to_string))
            .or_else(resolve_token_from_env_or_default_files);
        Self { endpoint, token }
    }

    pub async fn get_secret_key(
        &self,
        secret_ref: &str,
        key: &str,
        context: Option<HemScopeContext>,
    ) -> Result<Option<String>, HemClientError> {
        let key = normalize_optional(key).ok_or_else(|| {
            HemClientError::InvalidSecretReference("secret key must not be empty".to_string())
        })?;
        let mut client = self.connect().await?;
        let lookup = get_secret_request::Lookup::Secret(parse_secret_ref_or_global(secret_ref)?);
        let request = self.authorize_request(GetSecretRequest {
            lookup: Some(lookup),
            context: Some(ScopeResolutionContext {
                identity_id: context
                    .as_ref()
                    .and_then(|value| value.identity_id.as_ref())
                    .cloned()
                    .unwrap_or_default(),
                project: context
                    .as_ref()
                    .and_then(|value| value.project.as_ref())
                    .cloned()
                    .unwrap_or_default(),
            }),
            key: key.to_string(),
            async_read: true,
            wait_timeout_ms: 0,
            reason: String::new(),
            approval_receipt: String::new(),
        })?;

        let response = match client.get_secret(request).await {
            Ok(response) => response,
            Err(status) if status.code() == Code::NotFound => return Ok(None),
            Err(status) => return Err(map_status(status)),
        };
        let payload = response.into_inner();
        match payload.result {
            Some(get_secret_response::Result::Secret(secret)) => {
                Ok(secret.values.get(key).cloned())
            }
            Some(get_secret_response::Result::Pending(pending)) => {
                Err(HemClientError::ApprovalPending {
                    request_id: pending.request_id,
                })
            }
            None => Err(HemClientError::ResponseShape(
                "missing get_secret result".to_string(),
            )),
        }
    }

    pub async fn get_secret(
        &self,
        secret_ref: &str,
        context: Option<HemScopeContext>,
    ) -> Result<Option<HemSecretRecord>, HemClientError> {
        let mut client = self.connect().await?;
        let lookup = get_secret_request::Lookup::Secret(parse_secret_ref_or_global(secret_ref)?);
        let request = self.authorize_request(GetSecretRequest {
            lookup: Some(lookup),
            context: Some(ScopeResolutionContext {
                identity_id: context
                    .as_ref()
                    .and_then(|value| value.identity_id.as_ref())
                    .cloned()
                    .unwrap_or_default(),
                project: context
                    .as_ref()
                    .and_then(|value| value.project.as_ref())
                    .cloned()
                    .unwrap_or_default(),
            }),
            key: String::new(),
            async_read: true,
            wait_timeout_ms: 0,
            reason: String::new(),
            approval_receipt: String::new(),
        })?;

        let response = match client.get_secret(request).await {
            Ok(response) => response,
            Err(status) if status.code() == Code::NotFound => return Ok(None),
            Err(status) => return Err(map_status(status)),
        };
        let payload = response.into_inner();
        match payload.result {
            Some(get_secret_response::Result::Secret(secret)) => Ok(Some(HemSecretRecord {
                info: SecretMetadata {
                    description: secret
                        .info
                        .as_ref()
                        .map(|info| info.description.clone())
                        .unwrap_or_default(),
                    requires_approval: secret
                        .info
                        .as_ref()
                        .map(|info| info.requires_approval)
                        .unwrap_or(false),
                    group: secret
                        .info
                        .as_ref()
                        .map(|info| info.group.clone())
                        .unwrap_or_default(),
                },
                values: secret.values,
            })),
            Some(get_secret_response::Result::Pending(pending)) => {
                Err(HemClientError::ApprovalPending {
                    request_id: pending.request_id,
                })
            }
            None => Err(HemClientError::ResponseShape(
                "missing get_secret result".to_string(),
            )),
        }
    }

    pub async fn set_secret(
        &self,
        secret_ref: &str,
        values: HashMap<String, String>,
        metadata: SecretMetadata,
        actor: Option<&str>,
    ) -> Result<SecretMetadata, HemClientError> {
        let mut client = self.connect().await?;
        let request = self.authorize_request(SetSecretRequest {
            secret: Some(parse_secret_ref_or_global(secret_ref)?),
            values: values
                .into_iter()
                .map(|(key, value)| SecretValue { key, value })
                .collect(),
            description: metadata.description.clone(),
            requires_approval: metadata.requires_approval,
            group: metadata.group.clone(),
            actor: normalize_optional(actor.unwrap_or_default())
                .unwrap_or("hem-client")
                .to_string(),
            approval_receipt: String::new(),
            reason: String::new(),
        })?;

        let response = client.set_secret(request).await.map_err(map_status)?;
        Ok(secret_metadata_from_proto(response.into_inner()))
    }

    pub async fn issue_agent_token(
        &self,
        identity_id: Option<&str>,
        project: Option<&str>,
        scopes: &[SecretScope],
        ttl_seconds: u64,
        issued_by_service: &str,
    ) -> Result<String, HemClientError> {
        let mut client = self.connect().await?;
        let request = self.authorize_request(IssueAgentTokenRequest {
            identity_id: normalize_optional(identity_id.unwrap_or_default())
                .unwrap_or_default()
                .to_string(),
            project: normalize_optional(project.unwrap_or_default())
                .unwrap_or_default()
                .to_string(),
            scopes: scopes.iter().map(|item| *item as i32).collect(),
            ttl_seconds,
            issued_by_service: normalize_optional(issued_by_service)
                .unwrap_or("unknown-service")
                .to_string(),
        })?;
        let response = client
            .issue_agent_token(request)
            .await
            .map_err(map_status)?;
        Ok(response.into_inner().token)
    }

    async fn connect(&self) -> Result<RpcClient<Channel>, HemClientError> {
        let endpoint = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|err| HemClientError::InvalidEndpoint(err.to_string()))?;
        let channel = endpoint.connect().await?;
        Ok(RpcClient::new(channel))
    }

    fn authorize_request<T>(&self, payload: T) -> Result<Request<T>, HemClientError> {
        let mut request = Request::new(payload);
        if let Some(token) = self.token.as_ref() {
            let header = format!("Bearer {token}");
            let metadata = MetadataValue::try_from(header.as_str())
                .map_err(|err| HemClientError::InvalidToken(err.to_string()))?;
            request.metadata_mut().insert("authorization", metadata);
        }
        Ok(request)
    }
}

#[must_use]
pub fn resolve_endpoint_from_env() -> String {
    env::var("VALHALL_HEM_ADDR")
        .ok()
        .and_then(|value| normalize_optional(value.as_str()).map(ToString::to_string))
        .or_else(|| {
            env::var("VALHALL_HEMD_ENDPOINT")
                .ok()
                .and_then(|value| normalize_optional(value.as_str()).map(ToString::to_string))
        })
        .map(|value| normalize_endpoint(value.as_str()))
        .unwrap_or_else(|| DEFAULT_HEMD_ENDPOINT.to_string())
}

#[must_use]
pub fn resolve_token_from_env_or_default_files() -> Option<String> {
    if let Ok(value) = env::var("VALHALL_HEM_TOKEN") {
        if let Some(trimmed) = normalize_optional(value.as_str()) {
            return Some(trimmed.to_string());
        }
    }

    for path in operator_token_file_candidates() {
        if let Some(token) = read_token_file(path.as_path()) {
            return Some(token);
        }
    }

    None
}

fn operator_token_file_candidates() -> Vec<PathBuf> {
    let hem_data_dir = env::var("HEM_DATA_DIR").ok();
    let system_daemons_dir = env::var("VALHALL_SYSTEM_DAEMONS_DIR").ok();
    let home = env::var("HOME").ok();
    operator_token_file_candidates_from_values(
        hem_data_dir.as_deref(),
        system_daemons_dir.as_deref(),
        home.as_deref(),
    )
}

fn operator_token_file_candidates_from_values(
    hem_data_dir: Option<&str>,
    system_daemons_dir: Option<&str>,
    home: Option<&str>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Some(value) = hem_data_dir.and_then(normalize_optional) {
        out.push(PathBuf::from(value).join(OPERATOR_TOKEN_FILE));
    }
    if let Some(value) = system_daemons_dir.and_then(normalize_optional) {
        out.push(
            PathBuf::from(value)
                .join("data")
                .join("hem")
                .join(OPERATOR_TOKEN_FILE),
        );
    }
    if let Some(home) = home.and_then(normalize_optional) {
        out.push(
            PathBuf::from(home)
                .join(DEFAULT_HEM_SUBDIR)
                .join(OPERATOR_TOKEN_FILE),
        );
        out.push(
            PathBuf::from(home)
                .join(DEFAULT_HEM_SYSTEM_DAEMONS_SUBDIR)
                .join(OPERATOR_TOKEN_FILE),
        );
    }

    out
}

fn read_token_file(path: &Path) -> Option<String> {
    let body = fs::read_to_string(path).ok()?;
    normalize_optional(body.as_str()).map(ToString::to_string)
}

fn normalize_endpoint(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    format!("http://{trimmed}")
}

fn parse_secret_ref_or_global(value: &str) -> Result<SecretRef, HemClientError> {
    let trimmed = normalize_optional(value).ok_or_else(|| {
        HemClientError::InvalidSecretReference("secret reference must not be empty".to_string())
    })?;
    let parts = trimmed.split('/').collect::<Vec<_>>();
    if parts.len() == 1 {
        return Ok(SecretRef {
            scope: Some(ScopeSelector {
                scope: SecretScope::Global as i32,
                project: String::new(),
                identity_id: String::new(),
            }),
            name: parts[0].to_string(),
        });
    }

    match parts.as_slice() {
        ["global", name] => Ok(SecretRef {
            scope: Some(ScopeSelector {
                scope: SecretScope::Global as i32,
                project: String::new(),
                identity_id: String::new(),
            }),
            name: (*name).to_string(),
        }),
        ["project", project, name] => Ok(SecretRef {
            scope: Some(ScopeSelector {
                scope: SecretScope::Project as i32,
                project: (*project).to_string(),
                identity_id: String::new(),
            }),
            name: (*name).to_string(),
        }),
        ["identity", identity_id, name] => Ok(SecretRef {
            scope: Some(ScopeSelector {
                scope: SecretScope::Identity as i32,
                project: String::new(),
                identity_id: (*identity_id).to_string(),
            }),
            name: (*name).to_string(),
        }),
        _ => Err(HemClientError::InvalidSecretReference(format!(
            "expected <name>, global/<name>, project/<project>/<name>, or identity/<identity_id>/<name>; got {trimmed}"
        ))),
    }
}

fn normalize_optional(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn map_status(status: Status) -> HemClientError {
    HemClientError::Rpc(status.code(), status.message().to_string())
}

fn secret_metadata_from_proto(info: SecretInfo) -> SecretMetadata {
    SecretMetadata {
        description: info.description,
        requires_approval: info.requires_approval,
        group: info.group,
    }
}

#[cfg(test)]
mod tests {
    use super::{operator_token_file_candidates_from_values, OPERATOR_TOKEN_FILE};
    use std::path::PathBuf;

    #[test]
    fn token_file_candidates_match_cli_fallback_order() {
        let candidates = operator_token_file_candidates_from_values(
            Some("/custom/hem"),
            Some("/custom/system-daemons"),
            Some("/home/alice"),
        );

        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/custom/hem").join(OPERATOR_TOKEN_FILE),
                PathBuf::from("/custom/system-daemons")
                    .join("data")
                    .join("hem")
                    .join(OPERATOR_TOKEN_FILE),
                PathBuf::from("/home/alice")
                    .join(".valhall/hem")
                    .join(OPERATOR_TOKEN_FILE),
                PathBuf::from("/home/alice")
                    .join(".valhall/system-daemons/data/hem")
                    .join(OPERATOR_TOKEN_FILE),
            ]
        );
    }
}
