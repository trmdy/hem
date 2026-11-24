use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    crypto::generate_node_wrap_keypair, fs_security::ensure_private_dir, HemError, Result,
};

const INVITE_PREFIX: &str = "hem-invite-v1.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub cluster_id: String,
    pub node_id: String,
    pub listen: String,
    pub quorum: u16,
    pub master_node_id: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub node_id: String,
    pub endpoint: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterInviteBody {
    pub cluster_id: String,
    pub inviter_node_id: String,
    pub inviter_endpoint: String,
    pub inviter_public_key_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inviter_wrap_public_key_b64: Option<String>,
    pub quorum: u16,
    pub master_node_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterInvite {
    pub body: ClusterInviteBody,
    pub body_hash_b64: String,
    pub signing_public_key_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollisionAgreementStatement<'a> {
    pub version: &'static str,
    pub cluster_id: &'a str,
    pub requester_node_id: &'a str,
    pub approver_node_id: &'a str,
    pub nonce: &'a str,
    pub collision_id: &'a str,
    pub scope: &'a str,
    pub name: &'a str,
    pub key: &'a str,
    pub current_operation_id: &'a str,
    pub incoming_operation_id: &'a str,
    pub base_version_seq: i64,
    pub current_version_seq: i64,
    pub resolution: &'a str,
    pub requester_latest_position: i64,
    pub requester_latest_body_hash_b64: &'a str,
    pub approver_latest_position: i64,
    pub approver_latest_body_hash_b64: &'a str,
}

pub const PEER_TRANSPORT_AUTH_VERSION: &str = "hem-peer-transport-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerTransportAuthStatement<'a> {
    pub version: &'static str,
    pub cluster_id: &'a str,
    pub node_id: &'a str,
    pub method: &'a str,
    pub nonce: &'a str,
    pub timestamp_unix: i64,
}

pub fn peer_transport_auth_statement_bytes(
    cluster_id: &str,
    node_id: &str,
    method: &str,
    nonce: &str,
    timestamp_unix: i64,
) -> Result<Vec<u8>> {
    let statement = PeerTransportAuthStatement {
        version: PEER_TRANSPORT_AUTH_VERSION,
        cluster_id,
        node_id,
        method,
        nonce,
        timestamp_unix,
    };
    Ok(serde_json::to_vec(&statement)?)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub label: Option<String>,
    pub signing_public_key_b64: String,
    pub signing_private_key_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_private_key_b64: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("label", &self.label)
            .field("signing_public_key_b64", &self.signing_public_key_b64)
            .field("signing_private_key_b64", &"<redacted>")
            .field("wrap_public_key_b64", &self.wrap_public_key_b64)
            .field("wrap_private_key_b64", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl ClusterConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let body = fs::read_to_string(path)?;
        let config: Self = toml::from_str(body.as_str()).map_err(|err| {
            HemError::InvalidArgument(format!(
                "cluster config parse failed at {}: {err}",
                path.display()
            ))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let body = toml::to_string_pretty(self).map_err(|err| {
            HemError::InvalidArgument(format!("cluster config serialize failed: {err}"))
        })?;
        write_atomic(path, body.as_bytes(), Some(0o600))
    }

    pub fn validate(&self) -> Result<()> {
        validate_subject("cluster_id", self.cluster_id.as_str())?;
        validate_subject("node_id", self.node_id.as_str())?;
        validate_non_empty("listen", self.listen.as_str())?;
        if self.quorum == 0 {
            return Err(HemError::InvalidArgument(
                "cluster quorum must be at least 1".to_string(),
            ));
        }
        if let Some(master_node_id) = self.master_node_id.as_ref() {
            validate_subject("master_node_id", master_node_id)?;
        }
        for peer in &self.peers {
            peer.validate()?;
            if peer.node_id == self.node_id {
                return Err(HemError::InvalidArgument(
                    "peer node_id must not match local node_id".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl PeerConfig {
    pub fn validate(&self) -> Result<()> {
        validate_subject("peer node_id", self.node_id.as_str())?;
        validate_non_empty("peer endpoint", self.endpoint.as_str())?;
        validate_non_empty("peer public_key", self.public_key.as_str())?;
        if let Some(wrap_public_key) = self.wrap_public_key.as_ref() {
            validate_base64_key("peer wrap_public_key", wrap_public_key.as_str(), 32)?;
        }
        Ok(())
    }
}

impl NodeIdentity {
    pub fn generate(node_id: &str, label: &str) -> Result<Self> {
        validate_subject("node_id", node_id)?;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let wrap_keypair = generate_node_wrap_keypair();
        Ok(Self {
            node_id: node_id.to_string(),
            label: normalize_optional(label),
            signing_public_key_b64: STANDARD_NO_PAD.encode(verifying_key.to_bytes()),
            signing_private_key_b64: STANDARD_NO_PAD.encode(signing_key.to_bytes()),
            wrap_public_key_b64: Some(wrap_keypair.public_key_b64),
            wrap_private_key_b64: Some(wrap_keypair.private_key_b64),
            created_at: Utc::now(),
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        ensure_strict_identity_permissions(path)?;
        let body = fs::read_to_string(path)?;
        let identity: Self = serde_json::from_str(body.as_str())?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let body = serde_json::to_vec_pretty(self)?;
        write_atomic(path, body.as_slice(), Some(0o600))
    }

    pub fn validate(&self) -> Result<()> {
        validate_subject("node_id", self.node_id.as_str())?;
        validate_base64_key(
            "signing_public_key_b64",
            self.signing_public_key_b64.as_str(),
            32,
        )?;
        validate_base64_key(
            "signing_private_key_b64",
            self.signing_private_key_b64.as_str(),
            32,
        )?;
        match (
            self.wrap_public_key_b64.as_ref(),
            self.wrap_private_key_b64.as_ref(),
        ) {
            (Some(public_key), Some(private_key)) => {
                validate_base64_key("wrap_public_key_b64", public_key.as_str(), 32)?;
                validate_base64_key("wrap_private_key_b64", private_key.as_str(), 32)
            }
            (None, None) => Ok(()),
            _ => Err(HemError::InvalidArgument(
                "wrap_public_key_b64 and wrap_private_key_b64 must be provided together"
                    .to_string(),
            )),
        }
    }

    pub fn sign_statement(&self, statement: &[u8]) -> Result<String> {
        let signing_key = decode_signing_key(self.signing_private_key_b64.as_str())?;
        let public_key = decode_verifying_key(self.signing_public_key_b64.as_str())?;
        if signing_key.verifying_key() != public_key {
            return Err(HemError::Crypto(
                "node identity private key does not match public key".to_string(),
            ));
        }
        let signature = signing_key.sign(statement);
        Ok(STANDARD_NO_PAD.encode(signature.to_bytes()))
    }
}

impl ClusterInvite {
    pub fn create(
        config: &ClusterConfig,
        identity: &NodeIdentity,
        ttl_seconds: u64,
    ) -> Result<Self> {
        if config.node_id != identity.node_id {
            return Err(HemError::InvalidArgument(format!(
                "invite node_id {} does not match identity node_id {}",
                config.node_id, identity.node_id
            )));
        }
        let now = Utc::now();
        let ttl = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
        let body = ClusterInviteBody {
            cluster_id: config.cluster_id.clone(),
            inviter_node_id: config.node_id.clone(),
            inviter_endpoint: config.listen.clone(),
            inviter_public_key_b64: identity.signing_public_key_b64.clone(),
            inviter_wrap_public_key_b64: identity.wrap_public_key_b64.clone(),
            quorum: config.quorum,
            master_node_id: config.master_node_id.clone(),
            created_at: now,
            expires_at: now + Duration::seconds(ttl),
        };
        Self::sign(body, identity)
    }

    pub fn encode(&self) -> Result<String> {
        self.verify_at(Utc::now())?;
        let body = serde_json::to_vec(self)?;
        Ok(format!("{}{}", INVITE_PREFIX, URL_SAFE_NO_PAD.encode(body)))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let encoded = token.trim().strip_prefix(INVITE_PREFIX).ok_or_else(|| {
            HemError::InvalidArgument("cluster invite has invalid prefix".to_string())
        })?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|err| {
            HemError::InvalidArgument(format!("cluster invite is not valid base64url: {err}"))
        })?;
        let invite: Self = serde_json::from_slice(bytes.as_slice()).map_err(|err| {
            HemError::InvalidArgument(format!("cluster invite JSON invalid: {err}"))
        })?;
        invite.verify_at(Utc::now())?;
        Ok(invite)
    }

    pub fn peer_config(&self) -> PeerConfig {
        PeerConfig {
            node_id: self.body.inviter_node_id.clone(),
            endpoint: self.body.inviter_endpoint.clone(),
            public_key: self.body.inviter_public_key_b64.clone(),
            wrap_public_key: self.body.inviter_wrap_public_key_b64.clone(),
        }
    }

    pub fn verify_at(&self, now: DateTime<Utc>) -> Result<()> {
        if now > self.body.expires_at {
            return Err(HemError::InvalidArgument(
                "cluster invite has expired".to_string(),
            ));
        }
        validate_subject("cluster_id", self.body.cluster_id.as_str())?;
        validate_subject("inviter_node_id", self.body.inviter_node_id.as_str())?;
        validate_non_empty("inviter_endpoint", self.body.inviter_endpoint.as_str())?;
        validate_base64_key(
            "inviter_public_key_b64",
            self.body.inviter_public_key_b64.as_str(),
            32,
        )?;
        if let Some(wrap_public_key) = self.body.inviter_wrap_public_key_b64.as_ref() {
            validate_base64_key("inviter_wrap_public_key_b64", wrap_public_key.as_str(), 32)?;
        }
        if self.body.inviter_public_key_b64 != self.signing_public_key_b64 {
            return Err(HemError::InvalidArgument(
                "cluster invite signing key does not match inviter public key".to_string(),
            ));
        }
        if self.body.quorum == 0 {
            return Err(HemError::InvalidArgument(
                "cluster invite quorum must be at least 1".to_string(),
            ));
        }
        if let Some(master_node_id) = self.body.master_node_id.as_ref() {
            validate_subject("master_node_id", master_node_id)?;
        }

        let expected_hash = invite_body_hash_b64(&self.body)?;
        if expected_hash != self.body_hash_b64 {
            return Err(HemError::InvalidArgument(
                "cluster invite body hash mismatch".to_string(),
            ));
        }
        let public_key = decode_verifying_key(self.signing_public_key_b64.as_str())?;
        let signature = decode_signature(self.signature_b64.as_str())?;
        public_key
            .verify(self.body_hash_b64.as_bytes(), &signature)
            .map_err(|_| HemError::InvalidArgument("cluster invite signature invalid".to_string()))
    }

    fn sign(body: ClusterInviteBody, identity: &NodeIdentity) -> Result<Self> {
        let signing_key = decode_signing_key(identity.signing_private_key_b64.as_str())?;
        let body_hash_b64 = invite_body_hash_b64(&body)?;
        let signature = signing_key.sign(body_hash_b64.as_bytes());
        Ok(Self {
            body,
            body_hash_b64,
            signing_public_key_b64: identity.signing_public_key_b64.clone(),
            signature_b64: STANDARD_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

fn invite_body_hash_b64(body: &ClusterInviteBody) -> Result<String> {
    let encoded = serde_json::to_vec(body)?;
    let hash: [u8; 32] = Sha256::digest(encoded).into();
    Ok(STANDARD_NO_PAD.encode(hash))
}

pub fn node_statement_hash_b64(statement: &[u8]) -> String {
    let hash: [u8; 32] = Sha256::digest(statement).into();
    STANDARD_NO_PAD.encode(hash)
}

pub fn verify_node_statement_signature(
    public_key_b64: &str,
    statement: &[u8],
    signature_b64: &str,
) -> Result<()> {
    let public_key = decode_verifying_key(public_key_b64)?;
    let signature = decode_signature(signature_b64)?;
    public_key
        .verify(statement, &signature)
        .map_err(|err| HemError::Crypto(format!("node statement signature invalid: {err}")))
}

fn decode_signing_key(value: &str) -> Result<SigningKey> {
    let bytes = STANDARD_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        HemError::InvalidArgument(format!(
            "signing_private_key_b64 must be base64-no-pad: {err}"
        ))
    })?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        HemError::InvalidArgument(
            "signing_private_key_b64 decoded length must be 32 bytes".to_string(),
        )
    })?;
    Ok(SigningKey::from_bytes(&key))
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        HemError::InvalidArgument(format!(
            "signing_public_key_b64 must be base64-no-pad: {err}"
        ))
    })?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        HemError::InvalidArgument(
            "signing_public_key_b64 decoded length must be 32 bytes".to_string(),
        )
    })?;
    VerifyingKey::from_bytes(&key)
        .map_err(|err| HemError::InvalidArgument(format!("signing_public_key_b64 invalid: {err}")))
}

fn decode_signature(value: &str) -> Result<Signature> {
    let bytes = STANDARD_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        HemError::InvalidArgument(format!("signature_b64 must be base64-no-pad: {err}"))
    })?;
    let signature: [u8; 64] = bytes.try_into().map_err(|_| {
        HemError::InvalidArgument("signature_b64 decoded length must be 64 bytes".to_string())
    })?;
    Ok(Signature::from_bytes(&signature))
}

fn validate_subject(label: &str, value: &str) -> Result<()> {
    validate_non_empty(label, value)?;
    if value.contains('/') || value.contains('\0') || value.contains("..") {
        return Err(HemError::InvalidArgument(format!(
            "{label} contains invalid path characters"
        )));
    }
    Ok(())
}

fn validate_non_empty(label: &str, value: &str) -> Result<()> {
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
    Ok(())
}

fn validate_base64_key(label: &str, value: &str, expected_len: usize) -> Result<()> {
    validate_non_empty(label, value)?;
    let bytes = STANDARD_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        HemError::InvalidArgument(format!("{label} must be base64-no-pad: {err}"))
    })?;
    if bytes.len() != expected_len {
        return Err(HemError::InvalidArgument(format!(
            "{label} decoded length must be {expected_len} bytes"
        )));
    }
    Ok(())
}

fn normalize_optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn write_atomic(path: &Path, body: &[u8], mode: Option<u32>) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let temp = temp_path(path);
    fs::write(temp.as_path(), body)?;
    if let Some(mode) = mode {
        set_file_mode(temp.as_path(), mode)?;
    }
    fs::rename(temp.as_path(), path)?;
    if let Some(mode) = mode {
        set_file_mode(path, mode)?;
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let ext = format!(
        "tmp-{}",
        hem_config::ids::generate_entropy_prefixed_ulid()
    );
    path.with_extension(ext)
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_strict_identity_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(HemError::InvalidArgument(format!(
            "insecure node identity permissions (expected 0600): {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_strict_identity_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    #[test]
    fn cluster_config_roundtrip_preserves_static_peers() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("cluster.toml");
        let config = ClusterConfig {
            enabled: true,
            cluster_id: "hmc_test".to_string(),
            node_id: "hmn_local".to_string(),
            listen: "127.0.0.1:50191".to_string(),
            quorum: 2,
            master_node_id: Some("hmn_master".to_string()),
            peers: vec![PeerConfig {
                node_id: "hmn_peer".to_string(),
                endpoint: "https://peer.example:50191".to_string(),
                public_key: "peer-public-key".to_string(),
                wrap_public_key: None,
            }],
        };

        config.save(path.as_path()).expect("save config");
        let loaded = ClusterConfig::load(path.as_path()).expect("load config");

        assert_eq!(loaded, config);
    }

    #[test]
    fn cluster_config_rejects_empty_peer_identity() {
        let config = ClusterConfig {
            enabled: true,
            cluster_id: "hmc_test".to_string(),
            node_id: "hmn_local".to_string(),
            listen: "127.0.0.1:50191".to_string(),
            quorum: 1,
            master_node_id: None,
            peers: vec![PeerConfig {
                node_id: String::new(),
                endpoint: "https://peer.example:50191".to_string(),
                public_key: "peer-public-key".to_string(),
                wrap_public_key: None,
            }],
        };

        let err = config.validate().expect_err("peer node_id must fail");

        assert!(err.to_string().contains("peer node_id"));
    }

    #[test]
    fn node_identity_generate_save_load_uses_strict_permissions() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("node-identity.json");
        let identity = NodeIdentity::generate("hmn_local", "local machine").expect("generate");

        identity.save(path.as_path()).expect("save identity");
        let loaded = NodeIdentity::load(path.as_path()).expect("load identity");

        assert_eq!(loaded.node_id, "hmn_local");
        assert_eq!(loaded.label.as_deref(), Some("local machine"));
        assert_eq!(
            loaded.signing_public_key_b64,
            identity.signing_public_key_b64
        );
        assert_eq!(
            loaded.signing_private_key_b64,
            identity.signing_private_key_b64
        );
        assert_strict_file_mode(path.as_path());
    }

    #[test]
    fn node_identity_load_rejects_insecure_permissions() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("node-identity.json");
        let identity = NodeIdentity::generate("hmn_local", "").expect("generate");
        identity.save(path.as_path()).expect("save identity");

        make_insecure(path.as_path());
        let err = NodeIdentity::load(path.as_path()).expect_err("insecure permissions must fail");

        assert!(err
            .to_string()
            .contains("insecure node identity permissions"));
    }

    #[cfg(unix)]
    fn assert_strict_file_mode(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(not(unix))]
    fn assert_strict_file_mode(_path: &Path) {}

    #[cfg(unix)]
    fn make_insecure(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("chmod");
    }

    #[cfg(not(unix))]
    fn make_insecure(_path: &Path) {}
}
