use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    crypto::MasterKey,
    fs_security::{ensure_private_dir, set_owner_read_write_only},
    model::{resolution_chain, ScopeResolutionContext, SecretScope, TokenClaims, TokenType},
    HemError, Result,
};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_DERIVATION_LABEL: &[u8] = b"hem-token-v1";
const ISSUED_TOKENS_FILE: &str = "issued.json";
const REVOKED_TOKENS_FILE: &str = "revoked.json";
const DEFAULT_MAX_AGENT_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct TokenManagerConfig {
    pub max_agent_ttl_secs: u64,
}

impl Default for TokenManagerConfig {
    fn default() -> Self {
        Self {
            max_agent_ttl_secs: DEFAULT_MAX_AGENT_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token: String,
    pub claims: TokenClaims,
}

#[derive(Debug, Clone)]
pub struct TokenManager {
    sign_key: [u8; 32],
    tokens_dir: PathBuf,
    config: TokenManagerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IssuedTokenFile {
    claims: Vec<TokenClaims>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RevokedTokenFile {
    entries: Vec<RevokedTokenEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevokedTokenEntry {
    token_id: String,
    expires_at: DateTime<Utc>,
    revoked_at: DateTime<Utc>,
    revoked_by: String,
}

#[derive(Debug)]
struct IssueTokenInput {
    token_type: TokenType,
    ttl: Duration,
    issued_by: String,
    service_name: Option<String>,
    identity_id: Option<String>,
    project: Option<String>,
    scopes: Vec<SecretScope>,
}

impl TokenManager {
    pub fn from_master_key(
        master_key: &MasterKey,
        data_dir: impl Into<PathBuf>,
        config: TokenManagerConfig,
    ) -> Result<Self> {
        let mut mac = HmacSha256::new_from_slice(master_key.key_bytes.as_slice())
            .map_err(|_| HemError::Crypto("invalid token derivation key".to_string()))?;
        mac.update(TOKEN_DERIVATION_LABEL);
        let digest = mac.finalize().into_bytes();

        let mut sign_key = [0_u8; 32];
        sign_key.copy_from_slice(digest.as_slice());

        let tokens_dir = data_dir.into().join("tokens");
        ensure_private_dir(tokens_dir.as_path())?;

        Ok(Self {
            sign_key,
            tokens_dir,
            config,
        })
    }

    pub fn issue_operator_token(&self, ttl: Duration, issued_by: &str) -> Result<IssuedToken> {
        self.issue_token(IssueTokenInput {
            token_type: TokenType::Operator,
            ttl,
            issued_by: issued_by.to_string(),
            service_name: None,
            identity_id: None,
            project: None,
            scopes: vec![SecretScope::Global],
        })
    }

    pub fn issue_service_token(
        &self,
        service_name: String,
        ttl: Duration,
        issued_by: &str,
    ) -> Result<IssuedToken> {
        validate_subject("service_name", service_name.as_str())?;
        self.issue_token(IssueTokenInput {
            token_type: TokenType::Service,
            ttl,
            issued_by: issued_by.to_string(),
            service_name: Some(service_name),
            identity_id: None,
            project: None,
            scopes: vec![SecretScope::Global],
        })
    }

    pub fn issue_agent_token(
        &self,
        identity_id: Option<String>,
        project: Option<String>,
        mut scopes: Vec<SecretScope>,
        ttl: Duration,
        issued_by_service: &str,
    ) -> Result<IssuedToken> {
        if ttl.as_secs() > self.config.max_agent_ttl_secs {
            return Err(HemError::TokenTtlExceeded);
        }

        if let Some(value) = identity_id.as_ref() {
            validate_subject("identity_id", value.as_str())?;
        }
        if let Some(value) = project.as_ref() {
            validate_subject("project", value.as_str())?;
        }

        if scopes.is_empty() {
            let context = ScopeResolutionContext {
                identity_id: identity_id.clone(),
                project: project.clone(),
            };
            scopes = resolution_chain(&context);
        }
        for scope in &scopes {
            scope.validate()?;
        }

        self.issue_token(IssueTokenInput {
            token_type: TokenType::AgentRun,
            ttl,
            issued_by: issued_by_service.to_string(),
            service_name: None,
            identity_id,
            project,
            scopes,
        })
    }

    pub fn verify_token(&self, token: &str) -> Result<TokenClaims> {
        let (payload_b64, signature_b64) = split_token(token)?;
        verify_signature(payload_b64, signature_b64, self.sign_key.as_slice())?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64.as_bytes())
            .map_err(|_| HemError::TokenMalformed)?;
        let claims: TokenClaims = serde_json::from_slice(payload.as_slice())?;

        let now = Utc::now();
        self.prune_expired_revocations(now)?;
        if claims.expires_at <= now {
            return Err(HemError::TokenExpired);
        }
        if self.is_revoked(claims.token_id.as_str(), now)? {
            return Err(HemError::TokenRevoked(claims.token_id));
        }
        Ok(claims)
    }

    pub fn revoke_token(&self, token_id: &str, actor: &str) -> Result<bool> {
        let token_id = normalized_subject("token_id", token_id)?;
        let actor = normalized_actor(actor);
        let now = Utc::now();

        let mut issued_file = self.load_issued_file()?;
        prune_expired_claims(&mut issued_file.claims, now);
        write_json_atomic(self.issued_tokens_path().as_path(), &issued_file)?;

        let Some(claims) = issued_file
            .claims
            .iter()
            .find(|claims| claims.token_id == token_id)
            .cloned()
        else {
            return Ok(false);
        };

        let mut revoked_file = self.load_revoked_file()?;
        prune_expired_revocations(&mut revoked_file.entries, now);
        if revoked_file
            .entries
            .iter()
            .any(|entry| entry.token_id == token_id)
        {
            return Ok(false);
        }

        revoked_file.entries.push(RevokedTokenEntry {
            token_id: token_id.to_string(),
            expires_at: claims.expires_at,
            revoked_at: now,
            revoked_by: actor,
        });
        write_json_atomic(self.revoked_tokens_path().as_path(), &revoked_file)?;
        Ok(true)
    }

    pub fn list_active_tokens(&self, token_type: Option<TokenType>) -> Result<Vec<TokenClaims>> {
        let now = Utc::now();

        let mut issued_file = self.load_issued_file()?;
        prune_expired_claims(&mut issued_file.claims, now);
        write_json_atomic(self.issued_tokens_path().as_path(), &issued_file)?;

        let mut revoked_file = self.load_revoked_file()?;
        prune_expired_revocations(&mut revoked_file.entries, now);
        write_json_atomic(self.revoked_tokens_path().as_path(), &revoked_file)?;
        let revoked: HashSet<&str> = revoked_file
            .entries
            .iter()
            .map(|entry| entry.token_id.as_str())
            .collect();

        let mut active: Vec<TokenClaims> = issued_file
            .claims
            .into_iter()
            .filter(|claims| !revoked.contains(claims.token_id.as_str()))
            .collect();

        if let Some(selector) = token_type {
            active.retain(|claims| claims.token_type == selector);
        }

        active.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
        Ok(active)
    }

    pub fn prune_expired_revocations(&self, now: DateTime<Utc>) -> Result<()> {
        let mut revoked = self.load_revoked_file()?;
        prune_expired_revocations(&mut revoked.entries, now);
        write_json_atomic(self.revoked_tokens_path().as_path(), &revoked)
    }

    fn issue_token(&self, input: IssueTokenInput) -> Result<IssuedToken> {
        let now = Utc::now();
        self.issue_token_at(input, now)
    }

    fn issue_token_at(&self, input: IssueTokenInput, now: DateTime<Utc>) -> Result<IssuedToken> {
        let issued_by = normalized_actor(input.issued_by.as_str());
        let ttl_chrono =
            chrono::Duration::from_std(input.ttl).map_err(|_| HemError::TokenTtlExceeded)?;
        let claims = TokenClaims {
            token_id: hem_config::ids::generate_prefixed_entropy_id("tok"),
            token_type: input.token_type,
            issued_at: now,
            expires_at: now + ttl_chrono,
            issued_by,
            service_name: input.service_name,
            identity_id: input.identity_id,
            project: input.project,
            scopes: input.scopes,
        };

        let token = sign_claims(&claims, self.sign_key.as_slice())?;
        let mut issued = self.load_issued_file()?;
        prune_expired_claims(&mut issued.claims, now);
        issued.claims.push(claims.clone());
        write_json_atomic(self.issued_tokens_path().as_path(), &issued)?;

        Ok(IssuedToken { token, claims })
    }

    fn is_revoked(&self, token_id: &str, now: DateTime<Utc>) -> Result<bool> {
        let mut revoked = self.load_revoked_file()?;
        prune_expired_revocations(&mut revoked.entries, now);
        write_json_atomic(self.revoked_tokens_path().as_path(), &revoked)?;
        Ok(revoked
            .entries
            .iter()
            .any(|entry| entry.token_id == token_id))
    }

    fn load_issued_file(&self) -> Result<IssuedTokenFile> {
        load_json_or_default(self.issued_tokens_path().as_path())
    }

    fn load_revoked_file(&self) -> Result<RevokedTokenFile> {
        load_json_or_default(self.revoked_tokens_path().as_path())
    }

    fn issued_tokens_path(&self) -> PathBuf {
        self.tokens_dir.join(ISSUED_TOKENS_FILE)
    }

    fn revoked_tokens_path(&self) -> PathBuf {
        self.tokens_dir.join(REVOKED_TOKENS_FILE)
    }
}

pub fn authorize_admin(claims: &TokenClaims) -> Result<()> {
    if claims.token_type == TokenType::Operator {
        return Ok(());
    }
    Err(HemError::AuthorizationDenied(
        "admin action requires operator token".to_string(),
    ))
}

pub fn authorize_read(
    claims: &TokenClaims,
    target_scope: &SecretScope,
    has_explicit_grant: bool,
) -> Result<()> {
    match claims.token_type {
        TokenType::Operator => Ok(()),
        TokenType::Service => {
            if matches!(target_scope, SecretScope::Global) || has_explicit_grant {
                Ok(())
            } else {
                Err(HemError::AuthorizationDenied(format!(
                    "service token has no grant for scope {}",
                    scope_label(target_scope)
                )))
            }
        }
        TokenType::AgentRun => {
            if has_explicit_grant || claims.scopes.iter().any(|scope| scope == target_scope) {
                Ok(())
            } else {
                Err(HemError::AuthorizationDenied(format!(
                    "agent token cannot read scope {}",
                    scope_label(target_scope)
                )))
            }
        }
    }
}

fn split_token(token: &str) -> Result<(&str, &str)> {
    let mut parts = token.split('.');
    let payload_b64 = parts.next().ok_or(HemError::TokenMalformed)?;
    let signature_b64 = parts.next().ok_or(HemError::TokenMalformed)?;
    if payload_b64.is_empty() || signature_b64.is_empty() || parts.next().is_some() {
        return Err(HemError::TokenMalformed);
    }
    Ok((payload_b64, signature_b64))
}

fn sign_claims(claims: &TokenClaims, sign_key: &[u8]) -> Result<String> {
    let payload = serde_json::to_vec(claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

    let mut mac = HmacSha256::new_from_slice(sign_key)
        .map_err(|_| HemError::Crypto("invalid token signing key".to_string()))?;
    mac.update(payload_b64.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{payload_b64}.{signature_b64}"))
}

fn verify_signature(payload_b64: &str, signature_b64: &str, sign_key: &[u8]) -> Result<()> {
    let provided_signature = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|_| HemError::TokenMalformed)?;
    if provided_signature.len() != 32 {
        return Err(HemError::TokenMalformed);
    }

    let mut mac = HmacSha256::new_from_slice(sign_key)
        .map_err(|_| HemError::Crypto("invalid token signing key".to_string()))?;
    mac.update(payload_b64.as_bytes());
    let expected_signature = mac.finalize().into_bytes();

    let equal = provided_signature
        .as_slice()
        .ct_eq(expected_signature.as_slice())
        .unwrap_u8();
    if equal == 1 {
        Ok(())
    } else {
        Err(HemError::TokenSignatureInvalid)
    }
}

fn prune_expired_claims(claims: &mut Vec<TokenClaims>, now: DateTime<Utc>) {
    claims.retain(|item| item.expires_at > now);
}

fn prune_expired_revocations(entries: &mut Vec<RevokedTokenEntry>, now: DateTime<Utc>) {
    entries.retain(|item| item.expires_at > now);
}

fn scope_label(scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project { project } => format!("project/{project}"),
        SecretScope::Identity { identity_id } => format!("identity/{identity_id}"),
    }
}

fn validate_subject(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not be empty"
        )));
    }
    if value != value.trim() {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not have leading/trailing whitespace"
        )));
    }
    Ok(())
}

fn normalized_subject<'a>(label: &str, value: &'a str) -> Result<&'a str> {
    validate_subject(label, value)?;
    Ok(value.trim())
}

fn normalized_actor(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn load_json_or_default<T>(path: &Path) -> Result<T>
where
    T: Default + for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(body.as_str())?)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let temp = path.with_extension(format!(
        "tmp-{}.json",
        hem_config::ids::generate_entropy_prefixed_ulid()
    ));
    let body = serde_json::to_vec_pretty(value)?;
    fs::write(temp.as_path(), body)?;
    set_owner_read_write_only(temp.as_path())?;
    fs::rename(temp.as_path(), path)?;
    set_owner_read_write_only(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_manager() -> (TokenManager, tempfile::TempDir) {
        let root = tempfile::tempdir().expect("tempdir");
        let mut key = [0_u8; 32];
        key[0] = 42;
        let master_key = MasterKey {
            key_id: "mk-test".to_string(),
            key_bytes: key,
        };
        let manager =
            TokenManager::from_master_key(&master_key, root.path(), TokenManagerConfig::default())
                .expect("manager");
        (manager, root)
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (manager, _root) = setup_manager();
        let issued = manager
            .issue_service_token(
                "smi".to_string(),
                Duration::from_secs(600),
                "bootstrap-operator",
            )
            .expect("issue");
        let claims = manager.verify_token(issued.token.as_str()).expect("verify");
        assert_eq!(claims.token_type, TokenType::Service);
        assert_eq!(claims.service_name.as_deref(), Some("smi"));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (manager, _root) = setup_manager();
        let issued = manager
            .issue_operator_token(Duration::from_secs(600), "operator")
            .expect("issue");

        let (payload_b64, signature_b64) =
            split_token(issued.token.as_str()).expect("valid token shape");
        let mut signature = URL_SAFE_NO_PAD
            .decode(signature_b64.as_bytes())
            .expect("decode signature");
        signature[0] ^= 0x01;
        let tampered = format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(signature));

        let err = manager
            .verify_token(tampered.as_str())
            .expect_err("must fail");
        assert!(matches!(err, HemError::TokenSignatureInvalid));
    }

    #[test]
    fn expired_token_is_rejected() {
        let (manager, _root) = setup_manager();
        let issued = manager
            .issue_token_at(
                IssueTokenInput {
                    token_type: TokenType::Operator,
                    ttl: Duration::from_secs(10),
                    issued_by: "operator".to_string(),
                    service_name: None,
                    identity_id: None,
                    project: None,
                    scopes: vec![SecretScope::Global],
                },
                Utc::now() - chrono::Duration::hours(2),
            )
            .expect("issue");

        let err = manager
            .verify_token(issued.token.as_str())
            .expect_err("must fail");
        assert!(matches!(err, HemError::TokenExpired));
    }

    #[test]
    fn agent_ttl_cap_is_enforced() {
        let (manager, _root) = setup_manager();
        let err = manager
            .issue_agent_token(
                Some("id-1".to_string()),
                Some("proj".to_string()),
                Vec::new(),
                Duration::from_secs(24 * 60 * 60 + 1),
                "smi",
            )
            .expect_err("must fail");
        assert!(matches!(err, HemError::TokenTtlExceeded));
    }

    #[test]
    fn revoked_token_is_rejected() {
        let (manager, _root) = setup_manager();
        let issued = manager
            .issue_service_token("smi".to_string(), Duration::from_secs(600), "operator")
            .expect("issue");
        assert!(manager
            .revoke_token(issued.claims.token_id.as_str(), "operator")
            .expect("revoke"));

        let err = manager
            .verify_token(issued.token.as_str())
            .expect_err("must fail");
        assert!(matches!(err, HemError::TokenRevoked(_)));
    }

    #[test]
    fn list_active_tokens_excludes_revoked_and_expired() {
        let (manager, _root) = setup_manager();
        let active = manager
            .issue_service_token("smi".to_string(), Duration::from_secs(600), "operator")
            .expect("issue active");
        let expired = manager
            .issue_token_at(
                IssueTokenInput {
                    token_type: TokenType::Service,
                    ttl: Duration::from_secs(120),
                    issued_by: "operator".to_string(),
                    service_name: Some("vis".to_string()),
                    identity_id: None,
                    project: None,
                    scopes: vec![SecretScope::Global],
                },
                Utc::now() - chrono::Duration::hours(1),
            )
            .expect("issue expired");
        let revoked = manager
            .issue_service_token("skip".to_string(), Duration::from_secs(600), "operator")
            .expect("issue revoked");
        assert!(manager
            .revoke_token(revoked.claims.token_id.as_str(), "operator")
            .expect("revoke"));

        let listed = manager.list_active_tokens(None).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].token_id, active.claims.token_id);
        assert_ne!(listed[0].token_id, expired.claims.token_id);
    }

    #[test]
    fn authorize_matrix() {
        let operator = TokenClaims {
            token_id: "01".to_string(),
            token_type: TokenType::Operator,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            issued_by: "operator".to_string(),
            service_name: None,
            identity_id: None,
            project: None,
            scopes: vec![SecretScope::Global],
        };
        assert!(authorize_admin(&operator).is_ok());
        assert!(authorize_read(
            &operator,
            &SecretScope::Project {
                project: "p1".to_string(),
            },
            false
        )
        .is_ok());

        let service = TokenClaims {
            token_type: TokenType::Service,
            service_name: Some("smi".to_string()),
            ..operator.clone()
        };
        assert!(authorize_read(&service, &SecretScope::Global, false).is_ok());
        assert!(authorize_read(
            &service,
            &SecretScope::Project {
                project: "p1".to_string(),
            },
            false
        )
        .is_err());
        assert!(authorize_read(
            &service,
            &SecretScope::Project {
                project: "p1".to_string(),
            },
            true
        )
        .is_ok());

        let agent = TokenClaims {
            token_type: TokenType::AgentRun,
            service_name: None,
            scopes: vec![
                SecretScope::Global,
                SecretScope::Project {
                    project: "p1".to_string(),
                },
            ],
            ..operator
        };
        assert!(authorize_read(
            &agent,
            &SecretScope::Project {
                project: "p1".to_string(),
            },
            false
        )
        .is_ok());
        assert!(authorize_read(
            &agent,
            &SecretScope::Project {
                project: "p2".to_string(),
            },
            false
        )
        .is_err());
    }
}
