use std::{fs, path::PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    fs_security::{ensure_private_dir, set_owner_read_write_only},
    model::validate_group_name,
    GroupInfo, HemError, Result,
};

#[derive(Debug, Clone)]
pub struct GroupStore {
    groups_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupFile {
    info: GroupInfo,
}

impl GroupStore {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let groups_dir = data_dir.into().join("groups");
        ensure_private_dir(groups_dir.as_path())?;
        Ok(Self { groups_dir })
    }

    pub fn set_group(&self, name: &str, description: &str) -> Result<GroupInfo> {
        validate_group_name(name)?;
        let path = self.group_path(name);
        let now = Utc::now();

        let mut info = GroupInfo {
            name: name.to_string(),
            description: description.to_string(),
            created_at: now,
            updated_at: now,
        };

        if path.exists() {
            let current = self.get_group(name)?;
            info.created_at = current.created_at;
        }

        let file = GroupFile { info: info.clone() };
        write_json_atomic(path.as_path(), &file)?;
        Ok(info)
    }

    pub fn get_group(&self, name: &str) -> Result<GroupInfo> {
        validate_group_name(name)?;
        let path = self.group_path(name);
        if !path.exists() {
            return Err(HemError::GroupNotFound(name.to_string()));
        }
        let body = fs::read_to_string(path.as_path())?;
        let file: GroupFile = serde_json::from_str(body.as_str())?;
        Ok(file.info)
    }

    pub fn list_groups(&self) -> Result<Vec<GroupInfo>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.groups_dir.as_path())? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let body = fs::read_to_string(path.as_path())?;
            let file: GroupFile = serde_json::from_str(body.as_str())?;
            out.push(file.info);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn group_path(&self, name: &str) -> PathBuf {
        self.groups_dir.join(format!("{name}.json"))
    }
}

fn write_json_atomic<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let temp = path.with_extension(format!(
        "tmp-{}.json",
        valhall_config::ids::generate_entropy_prefixed_ulid()
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
    fn set_and_list_groups() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = GroupStore::open(root.path()).expect("open");

        store
            .set_group("prod", "production credentials")
            .expect("set group");
        store
            .set_group("dev", "development keys")
            .expect("set group");

        let listed = store.list_groups().expect("list groups");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "dev");
        assert_eq!(listed[1].name, "prod");
    }

    #[test]
    fn invalid_group_name_is_rejected() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = GroupStore::open(root.path()).expect("open");

        let err = store
            .set_group("Prod Keys", "bad")
            .expect_err("invalid group name");
        assert!(err.to_string().contains("group name"));
    }
}
