use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    fs_security::{ensure_private_dir, set_owner_read_write_only},
    model::ApprovalState,
    HemError, Result, SecretScope,
};

const DELETE_APPROVAL_RECEIPT_TTL_MINS: i64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteApprovalRecord {
    pub request_id: String,
    pub action: String,
    pub state: ApprovalState,
    pub secret_scope: SecretScope,
    pub secret_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<String>,
    pub requested_by: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub resolve_message: String,
    pub approval_receipt: Option<String>,
    pub approval_receipt_expires_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub consumed_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeleteApprovalStore {
    pending_dir: PathBuf,
    resolved_dir: PathBuf,
}

impl DeleteApprovalStore {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let approvals_root = data_dir.into().join("approvals");
        let pending_dir = approvals_root.join("pending");
        let resolved_dir = approvals_root.join("resolved");
        ensure_private_dir(approvals_root.as_path())?;
        ensure_private_dir(pending_dir.as_path())?;
        ensure_private_dir(resolved_dir.as_path())?;
        Ok(Self {
            pending_dir,
            resolved_dir,
        })
    }

    pub fn request_delete(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        requested_by: &str,
        reason: &str,
    ) -> Result<DeleteApprovalRecord> {
        self.request_action(
            secret_scope,
            secret_name,
            "delete_secret",
            requested_by,
            reason,
            "delete requested",
        )
    }

    pub fn request_action(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        action: &str,
        requested_by: &str,
        reason: &str,
        default_reason: &str,
    ) -> Result<DeleteApprovalRecord> {
        self.request_action_for_version(
            secret_scope,
            secret_name,
            None,
            action,
            requested_by,
            reason,
            default_reason,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_action_for_version(
        &self,
        secret_scope: SecretScope,
        secret_name: String,
        secret_version: Option<&str>,
        action: &str,
        requested_by: &str,
        reason: &str,
        default_reason: &str,
    ) -> Result<DeleteApprovalRecord> {
        secret_scope.validate()?;
        let secret_name = normalize_secret_name(secret_name.as_str())?.to_string();
        let secret_version = normalize_optional_version(secret_version)?;
        let action = normalize_action(action)?.to_string();
        let reason = normalize_reason(reason, default_reason);
        let requested_by = normalize_actor(requested_by);

        if let Some(existing) = self.find_pending_by_secret_action(
            &secret_scope,
            secret_name.as_str(),
            secret_version.as_deref(),
            action.as_str(),
            requested_by.as_str(),
        )? {
            return Ok(existing);
        }

        let now = Utc::now();
        let record = DeleteApprovalRecord {
            request_id: hem_config::ids::generate_prefixed_entropy_id("apr"),
            action,
            state: ApprovalState::Pending,
            secret_scope,
            secret_name,
            secret_version,
            requested_by,
            reason,
            created_at: now,
            resolved_at: None,
            resolved_by: None,
            resolve_message: String::new(),
            approval_receipt: None,
            approval_receipt_expires_at: None,
            consumed_at: None,
            consumed_by: None,
        };

        let pending_path = self.pending_path(record.request_id.as_str());
        write_json_atomic(pending_path.as_path(), &record)?;
        Ok(record)
    }

    pub fn list_pending(&self, limit: usize) -> Result<Vec<DeleteApprovalRecord>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.pending_dir.as_path())? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|item| item.to_str()) != Some("json") {
                continue;
            }
            out.push(read_record(path.as_path())?);
        }
        out.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        if limit > 0 {
            out.truncate(limit);
        }
        Ok(out)
    }

    pub fn get_request(&self, request_id: &str) -> Result<DeleteApprovalRecord> {
        let request_id = normalize_request_id(request_id)?;
        if let Some(path) = self.find_request_path(request_id) {
            return read_record(path.as_path());
        }
        Err(HemError::ApprovalRequestNotFound(request_id.to_string()))
    }

    pub fn resolve_request(
        &self,
        request_id: &str,
        approve: bool,
        actor: &str,
        message: &str,
    ) -> Result<(DeleteApprovalRecord, Option<String>)> {
        let request_id = normalize_request_id(request_id)?;
        let pending_path = self.pending_path(request_id);
        if !pending_path.exists() {
            if self.resolved_path(request_id).exists() {
                return Err(HemError::ApprovalAlreadyResolved(request_id.to_string()));
            }
            return Err(HemError::ApprovalRequestNotFound(request_id.to_string()));
        }

        let mut record = read_record(pending_path.as_path())?;
        if record.state != ApprovalState::Pending {
            return Err(HemError::ApprovalAlreadyResolved(request_id.to_string()));
        }

        let now = Utc::now();
        let actor = normalize_actor(actor);
        record.state = if approve {
            ApprovalState::Approved
        } else {
            ApprovalState::Denied
        };
        record.resolved_at = Some(now);
        record.resolved_by = Some(actor);
        record.resolve_message = normalize_message(message);

        let mut receipt = None;
        if approve {
            let issued = format!(
                "dar1:{}:{}",
                record.request_id,
                hem_config::ids::generate_entropy_prefixed_ulid()
            );
            record.approval_receipt = Some(issued.clone());
            record.approval_receipt_expires_at =
                Some(now + Duration::minutes(DELETE_APPROVAL_RECEIPT_TTL_MINS));
            receipt = Some(issued);
        }

        let resolved_path = self.resolved_path(record.request_id.as_str());
        write_json_atomic(resolved_path.as_path(), &record)?;
        fs::remove_file(pending_path.as_path())?;
        Ok((record, receipt))
    }

    pub fn consume_receipt(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String> {
        self.consume_receipt_for_version(secret_scope, secret_name, None, action, receipt, actor)
    }

    pub fn consume_receipt_for_version(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        secret_version: Option<&str>,
        action: &str,
        receipt: &str,
        actor: &str,
    ) -> Result<String> {
        secret_scope.validate()?;
        let secret_name = normalize_secret_name(secret_name)?;
        let secret_version = normalize_optional_version(secret_version)?;
        let action = normalize_action(action)?;
        let receipt = normalize_receipt(receipt)?;
        let actor = normalize_actor(actor);

        let request_id = parse_request_id_from_receipt(receipt)?;
        let resolved_path = self.resolved_path(request_id);
        if !resolved_path.exists() {
            return Err(HemError::ApprovalRequestNotFound(request_id.to_string()));
        }

        let mut record = read_record(resolved_path.as_path())?;
        if record.state != ApprovalState::Approved {
            return Err(HemError::AuthorizationDenied(format!(
                "approval request is not approved: {}",
                record.request_id
            )));
        }
        if &record.secret_scope != secret_scope || record.secret_name.as_str() != secret_name {
            return Err(HemError::ApprovalReceiptInvalid);
        }
        if record.action.as_str() != action {
            return Err(HemError::ApprovalReceiptInvalid);
        }
        if record.requested_by != actor {
            return Err(HemError::ApprovalReceiptInvalid);
        }
        if record.secret_version != secret_version {
            return Err(HemError::ApprovalReceiptInvalid);
        }
        let expected = record
            .approval_receipt
            .as_ref()
            .ok_or(HemError::ApprovalReceiptRequired)?;
        if expected != receipt {
            return Err(HemError::ApprovalReceiptInvalid);
        }

        let now = Utc::now();
        let expires_at = record
            .approval_receipt_expires_at
            .ok_or(HemError::ApprovalReceiptExpired)?;
        if expires_at <= now {
            return Err(HemError::ApprovalReceiptExpired);
        }
        if record.consumed_at.is_some() {
            return Err(HemError::ApprovalReceiptConsumed);
        }

        record.consumed_at = Some(now);
        record.consumed_by = Some(actor);
        write_json_atomic(resolved_path.as_path(), &record)?;
        Ok(record.request_id)
    }

    fn find_pending_by_secret_action(
        &self,
        scope: &SecretScope,
        name: &str,
        version: Option<&str>,
        action: &str,
        requested_by: &str,
    ) -> Result<Option<DeleteApprovalRecord>> {
        let records = self.list_pending(usize::MAX)?;
        Ok(records.into_iter().find(|item| {
            &item.secret_scope == scope
                && item.secret_name == name
                && item.secret_version.as_deref() == version
                && item.action.as_str() == action
                && item.requested_by == requested_by
        }))
    }

    fn find_request_path(&self, request_id: &str) -> Option<PathBuf> {
        let pending = self.pending_path(request_id);
        if pending.exists() {
            return Some(pending);
        }
        let resolved = self.resolved_path(request_id);
        if resolved.exists() {
            return Some(resolved);
        }
        None
    }

    fn pending_path(&self, request_id: &str) -> PathBuf {
        self.pending_dir.join(format!("{request_id}.json"))
    }

    fn resolved_path(&self, request_id: &str) -> PathBuf {
        self.resolved_dir.join(format!("{request_id}.json"))
    }
}

fn normalize_secret_name(name: &str) -> Result<&str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(HemError::InvalidArgument(
            "secret name must not be empty".to_string(),
        ));
    }
    if trimmed != name {
        return Err(HemError::InvalidArgument(
            "secret name must not have leading/trailing whitespace".to_string(),
        ));
    }
    Ok(trimmed)
}

fn normalize_request_id(value: &str) -> Result<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(HemError::InvalidArgument(
            "request_id must not be empty".to_string(),
        ));
    }
    Ok(trimmed)
}

fn normalize_receipt(value: &str) -> Result<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(HemError::ApprovalReceiptRequired);
    }
    Ok(trimmed)
}

fn normalize_action(value: &str) -> Result<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(HemError::InvalidArgument(
            "approval action must not be empty".to_string(),
        ));
    }
    Ok(trimmed)
}

fn normalize_optional_version(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed != value {
        return Err(HemError::InvalidArgument(
            "secret version must not have leading/trailing whitespace".to_string(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_request_id_from_receipt(receipt: &str) -> Result<&str> {
    let mut parts = receipt.split(':');
    let version = parts.next().ok_or(HemError::ApprovalReceiptInvalid)?;
    let request_id = parts.next().ok_or(HemError::ApprovalReceiptInvalid)?;
    let random = parts.next().ok_or(HemError::ApprovalReceiptInvalid)?;
    if version != "dar1" || request_id.trim().is_empty() || random.trim().is_empty() {
        return Err(HemError::ApprovalReceiptInvalid);
    }
    if parts.next().is_some() {
        return Err(HemError::ApprovalReceiptInvalid);
    }
    Ok(request_id)
}

fn normalize_actor(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_reason(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_message(value: &str) -> String {
    value.trim().to_string()
}

fn read_record(path: &Path) -> Result<DeleteApprovalRecord> {
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

    #[test]
    fn request_and_list_pending() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");

        let request = approvals
            .request_delete(
                SecretScope::Global,
                "openai-prod".to_string(),
                "operator",
                "cleanup",
            )
            .expect("request");
        assert_eq!(request.state, ApprovalState::Pending);

        let listed = approvals.list_pending(10).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].request_id, request.request_id);
    }

    #[test]
    fn request_id_uses_shared_prefixed_entropy_shape() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");

        let request = approvals
            .request_action(
                SecretScope::Global,
                "openai-prod".to_string(),
                "get_secret",
                "operator",
                "reason",
                "fallback",
            )
            .expect("request");

        assert!(request.request_id.starts_with("apr_"));
        let suffix = request
            .request_id
            .split_once('_')
            .map(|(_, tail)| tail)
            .expect("request id separator");
        assert_eq!(suffix.len(), hem_config::ids::CANONICAL_ULID_LENGTH);
        assert!(suffix
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()));
    }

    #[test]
    fn approve_then_consume_receipt_once() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");
        let request = approvals
            .request_delete(
                SecretScope::Global,
                "openai-prod".to_string(),
                "operator",
                "cleanup",
            )
            .expect("request");

        let (_resolved, receipt) = approvals
            .resolve_request(request.request_id.as_str(), true, "human", "approved")
            .expect("approve");
        let receipt = receipt.expect("receipt");
        assert!(approvals.list_pending(10).expect("list").is_empty());

        let consumed = approvals
            .consume_receipt(
                &SecretScope::Global,
                "openai-prod",
                "delete_secret",
                receipt.as_str(),
                "operator",
            )
            .expect("consume");
        assert_eq!(consumed, request.request_id);

        let err = approvals
            .consume_receipt(
                &SecretScope::Global,
                "openai-prod",
                "delete_secret",
                receipt.as_str(),
                "operator",
            )
            .expect_err("must fail second consume");
        assert!(matches!(err, HemError::ApprovalReceiptConsumed));
    }

    #[test]
    fn deny_has_no_receipt() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");
        let request = approvals
            .request_delete(
                SecretScope::Global,
                "openai-prod".to_string(),
                "operator",
                "cleanup",
            )
            .expect("request");

        let (resolved, receipt) = approvals
            .resolve_request(request.request_id.as_str(), false, "human", "denied")
            .expect("deny");
        assert_eq!(resolved.state, ApprovalState::Denied);
        assert!(receipt.is_none());
    }

    #[test]
    fn request_action_defaults_reason_and_dedupes_by_action() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");

        let get_request = approvals
            .request_action(
                SecretScope::Global,
                "openai-prod".to_string(),
                "get_secret",
                "agent-token",
                "",
                "read requires approval",
            )
            .expect("request get");
        assert_eq!(get_request.reason, "read requires approval");
        assert_eq!(get_request.action, "get_secret");

        let get_request_2 = approvals
            .request_action(
                SecretScope::Global,
                "openai-prod".to_string(),
                "get_secret",
                "agent-token",
                "ignored",
                "read requires approval",
            )
            .expect("request duplicate");
        assert_eq!(get_request_2.request_id, get_request.request_id);

        let set_request = approvals
            .request_action(
                SecretScope::Global,
                "openai-prod".to_string(),
                "set_secret",
                "agent-token",
                "",
                "write requires approval",
            )
            .expect("request set");
        assert_ne!(set_request.request_id, get_request.request_id);
    }

    #[test]
    fn receipt_cannot_be_reused_for_different_action() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");
        let request = approvals
            .request_action(
                SecretScope::Global,
                "openai-prod".to_string(),
                "get_secret",
                "agent-token",
                "need read",
                "read requires approval",
            )
            .expect("request");

        let (_resolved, receipt) = approvals
            .resolve_request(request.request_id.as_str(), true, "human", "approved")
            .expect("approve");
        let receipt = receipt.expect("receipt");

        let err = approvals
            .consume_receipt(
                &SecretScope::Global,
                "openai-prod",
                "delete_secret",
                receipt.as_str(),
                "agent-token",
            )
            .expect_err("must reject wrong action");
        assert!(matches!(err, HemError::ApprovalReceiptInvalid));
    }

    #[test]
    fn receipt_rejects_wrong_requester_secret_version_and_expiry() {
        let root = tempfile::tempdir().expect("tempdir");
        let approvals = DeleteApprovalStore::open(root.path()).expect("store");
        let request = approvals
            .request_action_for_version(
                SecretScope::Global,
                "openai-prod".to_string(),
                Some("version-a"),
                "get_secret",
                "token:reader",
                "need read",
                "read requires approval",
            )
            .expect("request");

        let (_resolved, receipt) = approvals
            .resolve_request(request.request_id.as_str(), true, "human", "approved")
            .expect("approve");
        let receipt = receipt.expect("receipt");

        let wrong_requester = approvals
            .consume_receipt_for_version(
                &SecretScope::Global,
                "openai-prod",
                Some("version-a"),
                "get_secret",
                receipt.as_str(),
                "token:other",
            )
            .expect_err("must reject wrong requester");
        assert!(matches!(wrong_requester, HemError::ApprovalReceiptInvalid));

        let wrong_secret = approvals
            .consume_receipt_for_version(
                &SecretScope::Global,
                "other-prod",
                Some("version-a"),
                "get_secret",
                receipt.as_str(),
                "token:reader",
            )
            .expect_err("must reject wrong secret");
        assert!(matches!(wrong_secret, HemError::ApprovalReceiptInvalid));

        let wrong_version = approvals
            .consume_receipt_for_version(
                &SecretScope::Global,
                "openai-prod",
                Some("version-b"),
                "get_secret",
                receipt.as_str(),
                "token:reader",
            )
            .expect_err("must reject wrong version");
        assert!(matches!(wrong_version, HemError::ApprovalReceiptInvalid));

        let resolved_path = approvals.resolved_path(request.request_id.as_str());
        let mut record = read_record(resolved_path.as_path()).expect("read resolved");
        record.approval_receipt_expires_at = Some(Utc::now() - Duration::minutes(1));
        write_json_atomic(resolved_path.as_path(), &record).expect("expire");

        let expired = approvals
            .consume_receipt_for_version(
                &SecretScope::Global,
                "openai-prod",
                Some("version-a"),
                "get_secret",
                receipt.as_str(),
                "token:reader",
            )
            .expect_err("must reject expired receipt");
        assert!(matches!(expired, HemError::ApprovalReceiptExpired));
    }
}
