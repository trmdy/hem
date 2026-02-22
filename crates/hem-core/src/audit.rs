use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;

use crate::{AuditEntry, Result, SecretScope};

const AUDIT_FILE: &str = "entries.jsonl";
const AUDIT_LOCK_FILE: &str = "entries.lock";
const DEFAULT_AUDIT_RETENTION_DAYS: u64 = 90;

#[derive(Debug, Clone)]
pub struct AuditStore {
    path: PathBuf,
    lock_path: PathBuf,
    retention_days: u64,
}

impl AuditStore {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_retention_days(data_dir, DEFAULT_AUDIT_RETENTION_DAYS)
    }

    pub fn open_with_retention_days(
        data_dir: impl Into<PathBuf>,
        retention_days: u64,
    ) -> Result<Self> {
        let audit_dir = data_dir.into().join("audit");
        fs::create_dir_all(audit_dir.as_path())?;
        Ok(Self {
            path: audit_dir.join(AUDIT_FILE),
            lock_path: audit_dir.join(AUDIT_LOCK_FILE),
            retention_days,
        })
    }

    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        let _lock = self.acquire_lock()?;
        self.prune_expired_locked(Utc::now())?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.as_path())?;
        let body = serde_json::to_string(entry)?;
        file.write_all(body.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    pub fn list(
        &self,
        scope: Option<&SecretScope>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        let _lock = self.acquire_lock()?;
        self.prune_expired_locked(Utc::now())?;
        let mut out = self.read_all_entries_locked()?;

        out.retain(|entry| {
            if let Some(scope) = scope {
                if entry.secret_scope.as_ref() != Some(scope) {
                    return false;
                }
            }
            if let Some(since) = since {
                if entry.ts < since {
                    return false;
                }
            }
            if let Some(until) = until {
                if entry.ts > until {
                    return false;
                }
            }
            true
        });

        out.sort_by(|left, right| right.ts.cmp(&left.ts));
        if limit > 0 {
            out.truncate(limit);
        }
        Ok(out)
    }

    fn acquire_lock(&self) -> Result<AuditLockGuard> {
        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(self.lock_path.as_path())?;
        file.lock_exclusive()?;
        Ok(AuditLockGuard { file: Some(file) })
    }

    fn read_all_entries_locked(&self) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let body = fs::read_to_string(self.path.as_path())?;
        let mut out = Vec::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            out.push(serde_json::from_str::<AuditEntry>(trimmed)?);
        }
        Ok(out)
    }

    fn prune_expired_locked(&self, now: DateTime<Utc>) -> Result<()> {
        if self.retention_days == 0 {
            return Ok(());
        }
        let cutoff = now - Duration::days(self.retention_days as i64);
        let entries = self.read_all_entries_locked()?;
        let kept = entries
            .into_iter()
            .filter(|entry| entry.ts >= cutoff)
            .collect::<Vec<_>>();
        self.write_entries_locked(kept.as_slice())
    }

    fn write_entries_locked(&self, entries: &[AuditEntry]) -> Result<()> {
        if entries.is_empty() {
            if self.path.exists() {
                fs::remove_file(self.path.as_path())?;
            }
            return Ok(());
        }
        write_jsonl_atomic(self.path.as_path(), entries)
    }
}

#[derive(Debug)]
struct AuditLockGuard {
    file: Option<std::fs::File>,
}

impl Drop for AuditLockGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
        }
    }
}

fn write_jsonl_atomic(path: &Path, entries: &[AuditEntry]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!(
        "tmp-{}.jsonl",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    ));
    let mut body = String::new();
    for entry in entries {
        body.push_str(serde_json::to_string(entry)?.as_str());
        body.push('\n');
    }
    fs::write(temp.as_path(), body.as_bytes())?;
    fs::rename(temp.as_path(), path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn append_and_filter_audit_entries() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = AuditStore::open(root.path()).expect("open");
        let now = Utc::now();

        let a = AuditEntry {
            audit_id: "a".to_string(),
            ts: now - Duration::minutes(2),
            action: "get_secret".to_string(),
            actor: "token:a".to_string(),
            token_id: "a".to_string(),
            secret_scope: Some(SecretScope::Global),
            secret_name: "openai-prod".to_string(),
            result: "ok".to_string(),
            details: String::new(),
        };
        let b = AuditEntry {
            audit_id: "b".to_string(),
            ts: now - Duration::minutes(1),
            action: "set_secret".to_string(),
            actor: "token:b".to_string(),
            token_id: "b".to_string(),
            secret_scope: Some(SecretScope::Project {
                project: "proj-1".to_string(),
            }),
            secret_name: "cfg".to_string(),
            result: "ok".to_string(),
            details: String::new(),
        };

        store.append(&a).expect("append a");
        store.append(&b).expect("append b");

        let listed = store
            .list(Some(&SecretScope::Global), None, None, 10)
            .expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].audit_id, "a");

        let listed = store
            .list(None, Some(now - Duration::seconds(90)), None, 10)
            .expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].audit_id, "b");
    }

    #[test]
    fn append_prunes_expired_entries() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = AuditStore::open_with_retention_days(root.path(), 90).expect("open");
        let now = Utc::now();

        store
            .append(&AuditEntry {
                audit_id: "old".to_string(),
                ts: now - Duration::days(120),
                action: "set_secret".to_string(),
                actor: "token:old".to_string(),
                token_id: "old".to_string(),
                secret_scope: Some(SecretScope::Global),
                secret_name: "old-secret".to_string(),
                result: "ok".to_string(),
                details: String::new(),
            })
            .expect("append old");
        store
            .append(&AuditEntry {
                audit_id: "new".to_string(),
                ts: now - Duration::minutes(1),
                action: "set_secret".to_string(),
                actor: "token:new".to_string(),
                token_id: "new".to_string(),
                secret_scope: Some(SecretScope::Global),
                secret_name: "new-secret".to_string(),
                result: "ok".to_string(),
                details: String::new(),
            })
            .expect("append new");

        let listed = store.list(None, None, None, 10).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].audit_id, "new");
    }
}
