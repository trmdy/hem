use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{HemError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretScope {
    Global,
    Project { project: String },
    Identity { identity_id: String },
}

impl SecretScope {
    #[must_use]
    pub fn path_segments(&self) -> Vec<String> {
        match self {
            Self::Global => vec!["global".to_string()],
            Self::Project { project } => vec!["project".to_string(), project.clone()],
            Self::Identity { identity_id } => vec!["identity".to_string(), identity_id.clone()],
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Global => Ok(()),
            Self::Project { project } => validate_scope_component("project", project),
            Self::Identity { identity_id } => validate_scope_component("identity_id", identity_id),
        }
    }

    #[must_use]
    pub fn matches_context(&self, context: &ScopeResolutionContext) -> bool {
        match self {
            Self::Global => true,
            Self::Project { project } => context
                .project
                .as_ref()
                .map(|value| value == project)
                .unwrap_or(false),
            Self::Identity { identity_id } => context
                .identity_id
                .as_ref()
                .map(|value| value == identity_id)
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScopeResolutionContext {
    pub identity_id: Option<String>,
    pub project: Option<String>,
}

#[must_use]
pub fn resolution_chain(context: &ScopeResolutionContext) -> Vec<SecretScope> {
    let mut chain = Vec::new();
    if let Some(identity_id) = context.identity_id.as_ref() {
        chain.push(SecretScope::Identity {
            identity_id: identity_id.clone(),
        });
    }
    if let Some(project) = context.project.as_ref() {
        chain.push(SecretScope::Project {
            project: project.clone(),
        });
    }
    chain.push(SecretScope::Global);
    chain
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInfo {
    pub scope: SecretScope,
    pub name: String,
    pub description: String,
    pub requires_approval: bool,
    pub group: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub last_accessed_at: Option<DateTime<Utc>>,
    pub last_accessed_by: Option<String>,
}

impl SecretInfo {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        validate_secret_name(self.name.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretWithValues {
    pub info: SecretInfo,
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SetSecretInput {
    pub scope: SecretScope,
    pub name: String,
    pub values: HashMap<String, String>,
    pub description: String,
    pub requires_approval: bool,
    pub group: Option<String>,
    pub actor: String,
}

impl SetSecretInput {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        validate_secret_name(self.name.as_str())?;
        if self.values.is_empty() {
            return Err(HemError::InvalidArgument(
                "secret must contain at least one key/value pair".to_string(),
            ));
        }
        for key in self.values.keys() {
            validate_value_key(key.as_str())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Operator,
    Service,
    AgentRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub token_id: String,
    pub token_type: TokenType,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issued_by: String,
    pub service_name: Option<String>,
    pub identity_id: Option<String>,
    pub project: Option<String>,
    pub scopes: Vec<SecretScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantInfo {
    pub secret_scope: SecretScope,
    pub secret_name: String,
    pub grantee_scope: SecretScope,
    pub grantee_id: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub state: ApprovalState,
    pub secret_scope: SecretScope,
    pub secret_name: String,
    pub requester_token_id: String,
    pub requester_identity_id: Option<String>,
    pub requester_project: Option<String>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub resolve_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: String,
    pub ts: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub token_id: String,
    pub secret_scope: Option<SecretScope>,
    pub secret_name: String,
    pub result: String,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub fn validate_secret_name(name: &str) -> Result<()> {
    validate_slug(name, "secret name")
}

pub fn validate_group_name(name: &str) -> Result<()> {
    validate_slug(name, "group name")
}

fn validate_slug(name: &str, label: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not be empty"
        )));
    }
    if trimmed != name {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not have leading/trailing whitespace"
        )));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(HemError::InvalidArgument(format!(
            "invalid {label} {name:?}; expected lowercase alnum + hyphen"
        )));
    }
    Ok(())
}

fn validate_scope_component(label: &str, value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not be empty"
        )));
    }
    if trimmed != value {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not have leading/trailing whitespace"
        )));
    }
    if value.contains('/') || value.contains('\0') || value.contains("..") {
        return Err(HemError::InvalidArgument(format!(
            "{label} contains invalid path characters"
        )));
    }
    Ok(())
}

fn validate_value_key(key: &str) -> Result<()> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(HemError::InvalidArgument(
            "secret value key must not be empty".to_string(),
        ));
    }
    if trimmed != key {
        return Err(HemError::InvalidArgument(
            "secret value key must not have leading/trailing whitespace".to_string(),
        ));
    }
    if key.contains('/') || key.contains('\0') || key.contains("..") {
        return Err(HemError::InvalidArgument(
            "secret value key contains invalid path characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_chain_prefers_identity_then_project_then_global() {
        let chain = resolution_chain(&ScopeResolutionContext {
            identity_id: Some("id-1".to_string()),
            project: Some("proj-a".to_string()),
        });
        assert_eq!(
            chain,
            vec![
                SecretScope::Identity {
                    identity_id: "id-1".to_string()
                },
                SecretScope::Project {
                    project: "proj-a".to_string()
                },
                SecretScope::Global
            ]
        );
    }

    #[test]
    fn resolution_chain_without_identity_starts_at_project() {
        let chain = resolution_chain(&ScopeResolutionContext {
            identity_id: None,
            project: Some("proj-a".to_string()),
        });
        assert_eq!(
            chain,
            vec![
                SecretScope::Project {
                    project: "proj-a".to_string()
                },
                SecretScope::Global
            ]
        );
    }

    #[test]
    fn secret_name_validation_rejects_uppercase() {
        let err = validate_secret_name("OpenAI").expect_err("must reject uppercase");
        assert!(err.to_string().contains("invalid secret name"));
    }
}
