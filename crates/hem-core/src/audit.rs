use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use chrono::{DateTime, Utc};

use crate::{AuditEntry, Result, SecretScope};

const AUDIT_FILE: &str = "entries.jsonl";

#[derive(Debug, Clone)]
pub struct AuditStore {
    path: PathBuf,
}

impl AuditStore {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let audit_dir = data_dir.into().join("audit");
        fs::create_dir_all(audit_dir.as_path())?;
        Ok(Self {
            path: audit_dir.join(AUDIT_FILE),
        })
    }

    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
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
            let entry: AuditEntry = serde_json::from_str(trimmed)?;
            if let Some(scope) = scope {
                if entry.secret_scope.as_ref() != Some(scope) {
                    continue;
                }
            }
            if let Some(since) = since {
                if entry.ts < since {
                    continue;
                }
            }
            if let Some(until) = until {
                if entry.ts > until {
                    continue;
                }
            }
            out.push(entry);
        }

        out.sort_by(|left, right| right.ts.cmp(&left.ts));
        if limit > 0 {
            out.truncate(limit);
        }
        Ok(out)
    }
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
}
