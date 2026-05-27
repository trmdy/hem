use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    fs_security::{ensure_private_dir, set_owner_read_write_only},
    HemError, Result, SecretScope,
};

const POLICY_DIR: &str = "policies";
const POLICY_FILE: &str = "read-policy.json";
const LEASE_DIR: &str = "offline-leases";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPolicyTier {
    #[default]
    LocalLogged,
    OfflineLease,
    PeerQuorum,
    MasterBiometric,
}

impl SecretPolicyTier {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalLogged => "local_logged",
            Self::OfflineLease => "offline_lease",
            Self::PeerQuorum => "peer_quorum",
            Self::MasterBiometric => "master_biometric",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "local_logged" => Ok(Self::LocalLogged),
            "offline_lease" => Ok(Self::OfflineLease),
            "peer_quorum" => Ok(Self::PeerQuorum),
            "master_biometric" => Ok(Self::MasterBiometric),
            other => Err(HemError::InvalidArgument(format!(
                "unsupported policy tier {other:?}; expected local_logged | offline_lease | peer_quorum | master_biometric"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineLease {
    pub lease_id: String,
    pub scope: SecretScope,
    pub name: String,
    pub requester: String,
    pub node_id: String,
    pub max_uses: u32,
    pub remaining_uses: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IssueOfflineLeaseInput {
    pub scope: SecretScope,
    pub name: String,
    pub requester: String,
    pub node_id: String,
    pub max_uses: u32,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub default_tier: SecretPolicyTier,
    pub scope_tiers: Vec<PolicyBinding>,
    pub secret_tiers: Vec<PolicyBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBinding {
    pub target: String,
    pub tier: SecretPolicyTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyFile {
    default_tier: SecretPolicyTier,
    #[serde(default)]
    scope_tiers: BTreeMap<String, SecretPolicyTier>,
    #[serde(default)]
    secret_tiers: BTreeMap<String, SecretPolicyTier>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            default_tier: SecretPolicyTier::LocalLogged,
            scope_tiers: BTreeMap::new(),
            secret_tiers: BTreeMap::new(),
        }
    }
}

impl PolicyStore {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let root = data_dir.into().join(POLICY_DIR);
        ensure_private_dir(root.as_path())?;
        ensure_private_dir(root.join(LEASE_DIR).as_path())?;
        let store = Self { root };
        if !store.policy_path().exists() {
            store.write_policy_file(&PolicyFile::default())?;
        }
        Ok(store)
    }

    pub fn effective_policy(&self, scope: &SecretScope, name: &str) -> Result<SecretPolicyTier> {
        validate_secret_name(name)?;
        let policies = self.read_policy_file()?;
        let secret_key = secret_policy_key(scope, name);
        if let Some(tier) = policies.secret_tiers.get(secret_key.as_str()) {
            return Ok(*tier);
        }
        let scope_key = scope_policy_key(scope);
        if let Some(tier) = policies.scope_tiers.get(scope_key.as_str()) {
            return Ok(*tier);
        }
        Ok(policies.default_tier)
    }

    pub fn snapshot(&self) -> Result<PolicySnapshot> {
        let policies = self.read_policy_file()?;
        Ok(PolicySnapshot {
            default_tier: policies.default_tier,
            scope_tiers: policies
                .scope_tiers
                .into_iter()
                .map(|(target, tier)| PolicyBinding { target, tier })
                .collect(),
            secret_tiers: policies
                .secret_tiers
                .into_iter()
                .map(|(target, tier)| PolicyBinding { target, tier })
                .collect(),
        })
    }

    pub fn set_default_policy(&self, tier: SecretPolicyTier) -> Result<()> {
        let mut policies = self.read_policy_file()?;
        policies.default_tier = tier;
        self.write_policy_file(&policies)
    }

    pub fn set_scope_policy(&self, scope: &SecretScope, tier: SecretPolicyTier) -> Result<()> {
        let mut policies = self.read_policy_file()?;
        policies.scope_tiers.insert(scope_policy_key(scope), tier);
        self.write_policy_file(&policies)
    }

    pub fn set_secret_policy(
        &self,
        scope: &SecretScope,
        name: &str,
        tier: SecretPolicyTier,
    ) -> Result<()> {
        validate_secret_name(name)?;
        let mut policies = self.read_policy_file()?;
        policies.insert_secret(scope, name, tier);
        self.write_policy_file(&policies)
    }

    pub fn issue_offline_lease(&self, input: IssueOfflineLeaseInput) -> Result<OfflineLease> {
        input.validate()?;
        let issued_at = Utc::now();
        let lease = OfflineLease {
            lease_id: format!(
                "hol_{}",
                valhall_config::ids::generate_entropy_prefixed_ulid()
            ),
            scope: input.scope,
            name: input.name,
            requester: input.requester,
            node_id: input.node_id,
            max_uses: input.max_uses,
            remaining_uses: input.max_uses,
            issued_at,
            expires_at: issued_at + Duration::seconds(input.ttl_seconds),
            revoked_at: None,
            revoked_by: None,
        };
        self.write_lease(&lease)?;
        Ok(lease)
    }

    pub fn list_offline_leases(&self) -> Result<Vec<OfflineLease>> {
        let mut leases = self.read_leases()?;
        leases.sort_by(|left, right| {
            left.expires_at
                .cmp(&right.expires_at)
                .then_with(|| left.lease_id.cmp(&right.lease_id))
        });
        Ok(leases)
    }

    pub fn revoke_offline_lease(&self, lease_id: &str, actor: &str) -> Result<OfflineLease> {
        let lease_id = validate_non_empty("lease_id", lease_id)?;
        let actor = validate_non_empty("actor", actor)?;
        let path = self.lease_path(lease_id);
        if !path.exists() {
            return Err(HemError::InvalidArgument(format!(
                "offline lease not found: {lease_id}"
            )));
        }
        let body = fs::read_to_string(path.as_path())?;
        let mut lease: OfflineLease = serde_json::from_str(body.as_str())?;
        lease.remaining_uses = 0;
        lease.revoked_at = Some(Utc::now());
        lease.revoked_by = Some(actor.to_string());
        self.write_lease(&lease)?;
        Ok(lease)
    }

    pub fn consume_offline_lease(
        &self,
        scope: &SecretScope,
        name: &str,
        requester: &str,
        node_id: &str,
    ) -> Result<OfflineLease> {
        validate_secret_name(name)?;
        validate_non_empty("requester", requester)?;
        validate_non_empty("node_id", node_id)?;
        let now = Utc::now();
        let mut leases = self.read_leases()?;
        leases.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
        for mut lease in leases {
            if lease.scope == *scope
                && lease.name == name
                && lease.requester == requester
                && lease.node_id == node_id
                && lease.expires_at > now
                && lease.revoked_at.is_none()
                && lease.remaining_uses > 0
            {
                lease.remaining_uses -= 1;
                self.write_lease(&lease)?;
                return Ok(lease);
            }
        }
        Err(HemError::InvalidArgument(format!(
            "valid offline lease not found for {}/{} requester={} node_id={}",
            scope_policy_key(scope),
            name,
            requester,
            node_id
        )))
    }

    fn policy_path(&self) -> PathBuf {
        self.root.join(POLICY_FILE)
    }

    fn lease_dir(&self) -> PathBuf {
        self.root.join(LEASE_DIR)
    }

    fn lease_path(&self, lease_id: &str) -> PathBuf {
        self.lease_dir().join(format!("{lease_id}.json"))
    }

    fn read_policy_file(&self) -> Result<PolicyFile> {
        let body = fs::read_to_string(self.policy_path())?;
        serde_json::from_str(body.as_str()).map_err(HemError::from)
    }

    fn write_policy_file(&self, policies: &PolicyFile) -> Result<()> {
        let body = serde_json::to_vec_pretty(policies)?;
        write_atomic(self.policy_path().as_path(), body.as_slice())
    }

    fn read_leases(&self) -> Result<Vec<OfflineLease>> {
        let mut leases = Vec::new();
        for entry in fs::read_dir(self.lease_dir())? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let body = fs::read_to_string(entry.path())?;
                leases.push(serde_json::from_str(body.as_str())?);
            }
        }
        Ok(leases)
    }

    fn write_lease(&self, lease: &OfflineLease) -> Result<()> {
        let body = serde_json::to_vec_pretty(lease)?;
        write_atomic(
            self.lease_path(lease.lease_id.as_str()).as_path(),
            body.as_slice(),
        )
    }
}

impl PolicyFile {
    fn insert_secret(&mut self, scope: &SecretScope, name: &str, tier: SecretPolicyTier) {
        self.secret_tiers
            .insert(secret_policy_key(scope, name), tier);
    }
}

impl IssueOfflineLeaseInput {
    fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        validate_secret_name(self.name.as_str())?;
        validate_non_empty("requester", self.requester.as_str())?;
        validate_non_empty("node_id", self.node_id.as_str())?;
        if self.max_uses == 0 {
            return Err(HemError::InvalidArgument(
                "offline lease max_uses must be at least 1".to_string(),
            ));
        }
        if self.ttl_seconds <= 0 {
            return Err(HemError::InvalidArgument(
                "offline lease ttl_seconds must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

fn scope_policy_key(scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project { project } => format!("project/{project}"),
        SecretScope::Identity { identity_id } => format!("identity/{identity_id}"),
    }
}

fn secret_policy_key(scope: &SecretScope, name: &str) -> String {
    format!("{}/{}", scope_policy_key(scope), name)
}

fn validate_secret_name(name: &str) -> Result<()> {
    validate_non_empty("secret name", name).map(|_| ())
}

fn validate_non_empty<'a>(label: &str, value: &'a str) -> Result<&'a str> {
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
    Ok(trimmed)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        HemError::InvalidArgument(format!("path has no parent: {}", path.display()))
    })?;
    ensure_private_dir(parent)?;
    let tmp = path.with_extension("tmp");
    fs::write(tmp.as_path(), bytes)?;
    set_owner_read_write_only(tmp.as_path())?;
    fs::rename(tmp, path)?;
    set_owner_read_write_only(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_inherits_default_scope_then_secret() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = PolicyStore::open(root.path()).expect("store");
        let global = SecretScope::Global;
        assert_eq!(
            store.effective_policy(&global, "demo").expect("default"),
            SecretPolicyTier::LocalLogged
        );
        store
            .set_default_policy(SecretPolicyTier::PeerQuorum)
            .expect("set default");
        assert_eq!(
            store.effective_policy(&global, "demo").expect("default"),
            SecretPolicyTier::PeerQuorum
        );
        store
            .set_scope_policy(&global, SecretPolicyTier::OfflineLease)
            .expect("set scope");
        assert_eq!(
            store.effective_policy(&global, "demo").expect("scope"),
            SecretPolicyTier::OfflineLease
        );
        store
            .set_secret_policy(&global, "demo", SecretPolicyTier::MasterBiometric)
            .expect("set secret");
        assert_eq!(
            store.effective_policy(&global, "demo").expect("secret"),
            SecretPolicyTier::MasterBiometric
        );
    }

    #[test]
    fn policy_snapshot_lists_default_scope_and_secret_tiers() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = PolicyStore::open(root.path()).expect("store");
        let global = SecretScope::Global;
        store
            .set_default_policy(SecretPolicyTier::OfflineLease)
            .expect("set default");
        store
            .set_scope_policy(&global, SecretPolicyTier::PeerQuorum)
            .expect("set scope");
        store
            .set_secret_policy(&global, "demo", SecretPolicyTier::MasterBiometric)
            .expect("set secret");

        let snapshot = store.snapshot().expect("snapshot");

        assert_eq!(snapshot.default_tier, SecretPolicyTier::OfflineLease);
        assert_eq!(snapshot.scope_tiers[0].target, "global");
        assert_eq!(snapshot.scope_tiers[0].tier, SecretPolicyTier::PeerQuorum);
        assert_eq!(snapshot.secret_tiers[0].target, "global/demo");
        assert_eq!(
            snapshot.secret_tiers[0].tier,
            SecretPolicyTier::MasterBiometric
        );
    }

    #[test]
    fn offline_lease_consumes_uses_and_expires() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = PolicyStore::open(root.path()).expect("store");
        let global = SecretScope::Global;
        let lease = store
            .issue_offline_lease(IssueOfflineLeaseInput {
                scope: global.clone(),
                name: "demo".to_string(),
                requester: "token:abc".to_string(),
                node_id: "hmn_local".to_string(),
                max_uses: 1,
                ttl_seconds: 60,
            })
            .expect("lease");
        assert_eq!(lease.remaining_uses, 1);
        let consumed = store
            .consume_offline_lease(&global, "demo", "token:abc", "hmn_local")
            .expect("consume");
        assert_eq!(consumed.remaining_uses, 0);
        assert!(store
            .consume_offline_lease(&global, "demo", "token:abc", "hmn_local")
            .is_err());
        store
            .issue_offline_lease(IssueOfflineLeaseInput {
                scope: global.clone(),
                name: "demo".to_string(),
                requester: "token:abc".to_string(),
                node_id: "hmn_local".to_string(),
                max_uses: 1,
                ttl_seconds: -1,
            })
            .expect_err("expired lease cannot be issued");
    }

    #[test]
    fn offline_lease_revoke_keeps_audit_metadata_and_prevents_consumption() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = PolicyStore::open(root.path()).expect("store");
        let global = SecretScope::Global;
        let lease = store
            .issue_offline_lease(IssueOfflineLeaseInput {
                scope: global.clone(),
                name: "demo".to_string(),
                requester: "token:abc".to_string(),
                node_id: "hmn_local".to_string(),
                max_uses: 2,
                ttl_seconds: 60,
            })
            .expect("lease");

        let revoked = store
            .revoke_offline_lease(lease.lease_id.as_str(), "hem-cli")
            .expect("revoke");

        assert_eq!(revoked.remaining_uses, 0);
        assert_eq!(revoked.revoked_by.as_deref(), Some("hem-cli"));
        assert!(revoked.revoked_at.is_some());
        assert!(store
            .consume_offline_lease(&global, "demo", "token:abc", "hmn_local")
            .is_err());

        let listed = store.list_offline_leases().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].lease_id, lease.lease_id);
        assert_eq!(listed[0].revoked_by.as_deref(), Some("hem-cli"));
    }
}
