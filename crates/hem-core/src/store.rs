use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chrono::Utc;
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::{
    audit::AuditStore,
    crypto::{decrypt_value, encrypt_value, generate_master_key, EncryptedValue, MasterKey},
    group::GroupStore,
    model::{
        validate_group_name, validate_secret_name, GrantInfo, SecretInfo, SecretScope,
        SecretWithValues, SetSecretInput,
    },
    token::{TokenManager, TokenManagerConfig},
    HemError, Result,
};

const MASTER_KEY_FILE: &str = "master.key";
const EXPORT_BUNDLE_VERSION: &str = "hem-export-v1";
const MASTER_KEYSET_VERSION: &str = "hem-master-keyset-v1";
const ROTATION_JOURNAL_VERSION: &str = "hem-rotation-journal-v1";
const ROTATION_JOURNAL_FILE: &str = "master-key-rotation.json";
const STORE_LOCK_FILE: &str = "store.lock";

#[derive(Debug, Clone)]
pub struct HemStore {
    data_dir: PathBuf,
    master_keyset: MasterKeySet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyMasterKeyFile {
    key_id: String,
    key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MasterKeyFile {
    version: String,
    primary_key_id: String,
    keys: Vec<MasterKeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MasterKeyRecord {
    key_id: String,
    key_b64: String,
}

#[derive(Debug, Clone)]
struct MasterKeySet {
    primary_key_id: String,
    keys: HashMap<String, MasterKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RotationJournal {
    version: String,
    old_primary_key_id: String,
    new_key_id: String,
    started_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug)]
struct StoreWriteLockGuard {
    file: Option<std::fs::File>,
}

impl Drop for StoreWriteLockGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretFile {
    info: SecretInfo,
    values: HashMap<String, EncryptedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GrantFile {
    grants: Vec<GrantInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportBundle {
    version: String,
    master_key_id: String,
    exported_at: chrono::DateTime<Utc>,
    secrets: Vec<SecretFile>,
}

impl MasterKeySet {
    fn with_primary(master_key: MasterKey) -> Self {
        let primary_key_id = master_key.key_id.clone();
        let mut keys = HashMap::new();
        keys.insert(master_key.key_id.clone(), master_key);
        Self {
            primary_key_id,
            keys,
        }
    }

    fn primary(&self) -> Result<&MasterKey> {
        self.keys.get(self.primary_key_id.as_str()).ok_or_else(|| {
            HemError::MasterKeyParse(format!("missing primary key {}", self.primary_key_id))
        })
    }

    fn key_by_id(&self, key_id: &str) -> Result<&MasterKey> {
        self.keys
            .get(key_id)
            .ok_or_else(|| HemError::MasterKeyParse(format!("missing key_id {key_id}")))
    }

    fn upsert_key(&mut self, key: MasterKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    fn set_primary_key_id(&mut self, key_id: &str) -> Result<()> {
        if !self.keys.contains_key(key_id) {
            return Err(HemError::MasterKeyParse(format!(
                "cannot set unknown primary key_id {key_id}"
            )));
        }
        self.primary_key_id = key_id.to_string();
        Ok(())
    }

    fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
}

impl HemStore {
    pub fn init(data_dir: impl Into<PathBuf>, force: bool) -> Result<MasterKey> {
        let data_dir = data_dir.into();
        fs::create_dir_all(data_dir.as_path())?;
        ensure_layout(data_dir.as_path())?;

        let key_path = master_key_path(data_dir.as_path());
        if key_path.exists() && !force {
            return Err(HemError::InvalidArgument(format!(
                "master key already exists at {}",
                key_path.display()
            )));
        }

        let master_key = generate_master_key();
        let keyset = MasterKeySet::with_primary(master_key.clone());
        write_master_key_file(key_path.as_path(), &keyset)?;
        Ok(master_key)
    }

    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();
        ensure_layout(data_dir.as_path())?;

        let key_path = master_key_path(data_dir.as_path());
        if !key_path.exists() {
            return Err(HemError::MissingMasterKey(key_path));
        }
        ensure_master_key_permissions(key_path.as_path())?;

        let keyset = read_master_key_file(key_path.as_path())?;
        let mut store = Self {
            data_dir,
            master_keyset: keyset,
        };
        store.recover_rotation_if_needed()?;
        let reloaded = read_master_key_file(key_path.as_path())?;
        store.master_keyset = reloaded;
        Ok(store)
    }

    #[must_use]
    pub fn master_key_id(&self) -> &str {
        self.master_keyset.primary_key_id.as_str()
    }

    pub fn group_store(&self) -> Result<GroupStore> {
        GroupStore::open(self.data_dir.as_path())
    }

    pub fn audit_store(&self) -> Result<AuditStore> {
        AuditStore::open(self.data_dir.as_path())
    }

    pub fn token_manager(&self) -> Result<TokenManager> {
        let primary = self.master_keyset.primary()?;
        TokenManager::from_master_key(
            primary,
            self.data_dir.as_path(),
            TokenManagerConfig::default(),
        )
    }

    pub fn set_secret(&self, input: SetSecretInput) -> Result<SecretInfo> {
        input.validate()?;
        let _lock = self.acquire_write_lock()?;
        let path = self.secret_file_path(&input.scope, input.name.as_str());

        let existing = if path.exists() {
            Some(read_secret_file(path.as_path())?)
        } else {
            None
        };

        let now = Utc::now();
        let actor = if input.actor.trim().is_empty() {
            "unknown".to_string()
        } else {
            input.actor.trim().to_string()
        };
        let mut info = SecretInfo {
            scope: input.scope.clone(),
            name: input.name.clone(),
            description: input.description,
            requires_approval: input.requires_approval,
            group: input.group,
            created_at: now,
            updated_at: now,
            created_by: actor.clone(),
            last_accessed_at: None,
            last_accessed_by: None,
        };

        if let Some(current) = existing.as_ref() {
            info.created_at = current.info.created_at;
            info.created_by = current.info.created_by.clone();
        }

        let mut encrypted = HashMap::new();
        let primary = self.master_keyset.primary()?;
        for (key, value) in input.values {
            let aad = self.value_aad(&info.scope, info.name.as_str(), key.as_str());
            let cipher = encrypt_value(primary, value.as_str(), aad.as_bytes())?;
            encrypted.insert(key, cipher);
        }

        let file = SecretFile {
            info: info.clone(),
            values: encrypted,
        };
        write_json_atomic(path.as_path(), &file)?;
        Ok(info)
    }

    pub fn get_secret(
        &self,
        scope: &SecretScope,
        name: &str,
        actor: Option<&str>,
    ) -> Result<SecretWithValues> {
        scope.validate()?;
        validate_secret_name(name)?;
        let _lock = self.acquire_write_lock()?;
        let path = self.secret_file_path(scope, name);
        if !path.exists() {
            return Err(HemError::SecretNotFound(format!(
                "{}/{}",
                scope_label(scope),
                name
            )));
        }

        let mut file = read_secret_file(path.as_path())?;
        let mut values = HashMap::new();
        for (key, cipher) in &file.values {
            let plain = self.decrypt_secret_value(scope, name, key.as_str(), cipher)?;
            values.insert(key.clone(), plain);
        }

        file.info.last_accessed_at = Some(Utc::now());
        file.info.last_accessed_by = Some(
            actor
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .unwrap_or_else(|| "unknown".to_string()),
        );
        file.info.updated_at = Utc::now();
        write_json_atomic(path.as_path(), &file)?;

        Ok(SecretWithValues {
            info: file.info,
            values,
        })
    }

    pub fn get_secret_values_without_access_update(
        &self,
        scope: &SecretScope,
        name: &str,
    ) -> Result<HashMap<String, String>> {
        scope.validate()?;
        validate_secret_name(name)?;
        let path = self.secret_file_path(scope, name);
        if !path.exists() {
            return Err(HemError::SecretNotFound(format!(
                "{}/{}",
                scope_label(scope),
                name
            )));
        }
        let file = read_secret_file(path.as_path())?;
        let mut values = HashMap::new();
        for (key, cipher) in &file.values {
            let plain = self.decrypt_secret_value(scope, name, key.as_str(), cipher)?;
            values.insert(key.clone(), plain);
        }
        Ok(values)
    }

    pub fn get_secret_info(&self, scope: &SecretScope, name: &str) -> Result<SecretInfo> {
        scope.validate()?;
        validate_secret_name(name)?;
        let path = self.secret_file_path(scope, name);
        if !path.exists() {
            return Err(HemError::SecretNotFound(format!(
                "{}/{}",
                scope_label(scope),
                name
            )));
        }
        Ok(read_secret_file(path.as_path())?.info)
    }

    pub fn set_secret_group(
        &self,
        scope: &SecretScope,
        name: &str,
        group: Option<String>,
    ) -> Result<SecretInfo> {
        scope.validate()?;
        validate_secret_name(name)?;
        let _lock = self.acquire_write_lock()?;
        if let Some(value) = group.as_ref() {
            validate_group_name(value.as_str())?;
        }

        let path = self.secret_file_path(scope, name);
        if !path.exists() {
            return Err(HemError::SecretNotFound(format!(
                "{}/{}",
                scope_label(scope),
                name
            )));
        }

        let mut file = read_secret_file(path.as_path())?;
        file.info.group = group;
        file.info.updated_at = Utc::now();
        write_json_atomic(path.as_path(), &file)?;
        Ok(file.info)
    }

    pub fn delete_secret(&self, scope: &SecretScope, name: &str) -> Result<bool> {
        scope.validate()?;
        validate_secret_name(name)?;
        let _lock = self.acquire_write_lock()?;
        let path = self.secret_file_path(scope, name);
        if !path.exists() {
            return Ok(false);
        }
        fs::remove_file(path.as_path())?;
        Ok(true)
    }

    pub fn grant_access(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        grantee_scope: &SecretScope,
        grantee_id: &str,
        actor: &str,
    ) -> Result<GrantInfo> {
        secret_scope.validate()?;
        validate_secret_name(secret_name)?;
        grantee_scope.validate()?;
        let _lock = self.acquire_write_lock()?;
        let grantee_id = normalize_subject("grantee_id", grantee_id)?.to_string();
        let actor = normalize_actor(actor);

        let secret_path = self.secret_file_path(secret_scope, secret_name);
        if !secret_path.exists() {
            return Err(HemError::SecretNotFound(format!(
                "{}/{}",
                scope_label(secret_scope),
                secret_name
            )));
        }

        let path = self.grant_file_path(secret_scope, secret_name);
        let mut file: GrantFile = load_json_or_default(path.as_path())?;
        if let Some(existing) = file.grants.iter().find(|item| {
            item.grantee_scope == *grantee_scope && item.grantee_id.as_str() == grantee_id.as_str()
        }) {
            return Ok(existing.clone());
        }

        let grant = GrantInfo {
            secret_scope: secret_scope.clone(),
            secret_name: secret_name.to_string(),
            grantee_scope: grantee_scope.clone(),
            grantee_id,
            created_at: Utc::now(),
            created_by: actor,
        };
        file.grants.push(grant.clone());
        file.grants
            .sort_by(|left, right| left.created_at.cmp(&right.created_at));
        write_json_atomic(path.as_path(), &file)?;
        Ok(grant)
    }

    pub fn revoke_access(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        grantee_scope: &SecretScope,
        grantee_id: &str,
    ) -> Result<bool> {
        secret_scope.validate()?;
        validate_secret_name(secret_name)?;
        grantee_scope.validate()?;
        let _lock = self.acquire_write_lock()?;
        let grantee_id = normalize_subject("grantee_id", grantee_id)?;

        let path = self.grant_file_path(secret_scope, secret_name);
        if !path.exists() {
            return Ok(false);
        }
        let mut file: GrantFile = load_json_or_default(path.as_path())?;
        let before = file.grants.len();
        file.grants.retain(|item| {
            !(item.grantee_scope == *grantee_scope && item.grantee_id.as_str() == grantee_id)
        });
        if file.grants.len() == before {
            return Ok(false);
        }
        if file.grants.is_empty() {
            fs::remove_file(path.as_path())?;
            return Ok(true);
        }
        write_json_atomic(path.as_path(), &file)?;
        Ok(true)
    }

    pub fn list_grants(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
    ) -> Result<Vec<GrantInfo>> {
        secret_scope.validate()?;
        validate_secret_name(secret_name)?;

        let path = self.grant_file_path(secret_scope, secret_name);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut file: GrantFile = load_json_or_default(path.as_path())?;
        file.grants
            .sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(file.grants)
    }

    pub fn has_grant(
        &self,
        secret_scope: &SecretScope,
        secret_name: &str,
        grantee_scope: &SecretScope,
        grantee_id: &str,
    ) -> Result<bool> {
        let grantee_id = normalize_subject("grantee_id", grantee_id)?;
        let grants = self.list_grants(secret_scope, secret_name)?;
        Ok(grants.iter().any(|item| {
            item.grantee_scope == *grantee_scope && item.grantee_id.as_str() == grantee_id
        }))
    }

    pub fn list_secrets(&self, scope: Option<&SecretScope>) -> Result<Vec<SecretInfo>> {
        match scope {
            Some(selector) => self.list_scope_secrets(selector),
            None => {
                let mut out = Vec::new();
                out.extend(self.list_global_secrets()?);
                out.extend(self.list_nested_scope_secrets("project")?);
                out.extend(self.list_nested_scope_secrets("identity")?);
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            }
        }
    }

    pub fn list_group_secrets(&self, group: &str) -> Result<Vec<SecretInfo>> {
        validate_group_name(group)?;
        let mut out = self.list_secrets(None)?;
        out.retain(|item| item.group.as_deref() == Some(group));
        out.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(out)
    }

    pub fn export_secrets_bundle(&self, scope: Option<&SecretScope>) -> Result<Vec<u8>> {
        let infos = self.list_secrets(scope)?;
        let mut files = Vec::with_capacity(infos.len());
        for info in infos {
            let path = self.secret_file_path(&info.scope, info.name.as_str());
            files.push(read_secret_file(path.as_path())?);
        }
        files.sort_by(|left, right| left.info.name.cmp(&right.info.name));
        let bundle = ExportBundle {
            version: EXPORT_BUNDLE_VERSION.to_string(),
            master_key_id: self.master_key_id().to_string(),
            exported_at: Utc::now(),
            secrets: files,
        };
        Ok(serde_json::to_vec_pretty(&bundle)?)
    }

    pub fn import_secrets_bundle(&self, bundle: &[u8], merge: bool) -> Result<u32> {
        if bundle.is_empty() {
            return Err(HemError::InvalidArgument(
                "encrypted_bundle must not be empty".to_string(),
            ));
        }
        let _lock = self.acquire_write_lock()?;
        let parsed: ExportBundle = serde_json::from_slice(bundle)?;
        if parsed.version != EXPORT_BUNDLE_VERSION {
            return Err(HemError::InvalidArgument(format!(
                "unsupported export bundle version {}",
                parsed.version
            )));
        }
        if !self.master_keyset.has_key(parsed.master_key_id.as_str()) {
            return Err(HemError::InvalidArgument(format!(
                "bundle master_key_id {} is not present in current keyset",
                parsed.master_key_id,
            )));
        }

        let mut imported = 0_u32;
        for mut item in parsed.secrets {
            item.info.validate()?;
            if let Some(group) = item.info.group.as_ref() {
                validate_group_name(group.as_str())?;
            }
            let path = self.secret_file_path(&item.info.scope, item.info.name.as_str());
            if merge && path.exists() {
                continue;
            }
            item.info.updated_at = Utc::now();
            write_json_atomic(path.as_path(), &item)?;
            imported = imported.saturating_add(1);
        }
        Ok(imported)
    }

    pub fn rotate_master_key(&self) -> Result<(String, u32)> {
        let _lock = self.acquire_write_lock()?;
        let mut keyset = self.master_keyset.clone();
        if let Some(journal) = self.load_rotation_journal()? {
            let rotated = self.finalize_rotation(&journal, &mut keyset)?;
            return Ok((journal.new_key_id, rotated));
        }

        let old_primary_key_id = keyset.primary_key_id.clone();
        let new_master_key = generate_master_key();
        keyset.upsert_key(new_master_key.clone());
        self.write_master_keyset(&keyset)?;

        let now = Utc::now();
        let journal = RotationJournal {
            version: ROTATION_JOURNAL_VERSION.to_string(),
            old_primary_key_id,
            new_key_id: new_master_key.key_id.clone(),
            started_at: now,
            updated_at: now,
        };
        self.write_rotation_journal(&journal)?;

        let rotated_secret_count = self.finalize_rotation(&journal, &mut keyset)?;
        Ok((journal.new_key_id, rotated_secret_count))
    }

    fn recover_rotation_if_needed(&mut self) -> Result<()> {
        let Some(journal) = self.load_rotation_journal()? else {
            return Ok(());
        };

        let mut keyset = self.master_keyset.clone();
        self.finalize_rotation(&journal, &mut keyset)?;
        self.master_keyset = keyset;
        Ok(())
    }

    fn finalize_rotation(
        &self,
        journal: &RotationJournal,
        keyset: &mut MasterKeySet,
    ) -> Result<u32> {
        if journal.version != ROTATION_JOURNAL_VERSION {
            return Err(HemError::MasterKeyParse(format!(
                "unsupported rotation journal version {}",
                journal.version
            )));
        }
        if !keyset.has_key(journal.old_primary_key_id.as_str()) {
            return Err(HemError::MasterKeyParse(format!(
                "rotation journal references unknown old key {}",
                journal.old_primary_key_id
            )));
        }
        if !keyset.has_key(journal.new_key_id.as_str()) {
            return Err(HemError::MasterKeyParse(format!(
                "rotation journal references unknown new key {}",
                journal.new_key_id
            )));
        }

        let rotated_secret_count =
            self.reencrypt_all_secrets_to_key(keyset, journal.new_key_id.as_str())?;
        keyset.set_primary_key_id(journal.new_key_id.as_str())?;
        self.write_master_keyset(keyset)?;
        self.delete_rotation_journal()?;
        Ok(rotated_secret_count)
    }

    fn reencrypt_all_secrets_to_key(
        &self,
        keyset: &MasterKeySet,
        target_key_id: &str,
    ) -> Result<u32> {
        let target_key = keyset.key_by_id(target_key_id)?;
        let infos = self.list_secrets(None)?;
        let mut rotated_secret_count = 0_u32;

        for info in infos {
            let path = self.secret_file_path(&info.scope, info.name.as_str());
            let mut file = read_secret_file(path.as_path())?;
            let mut rotated_values = HashMap::with_capacity(file.values.len());
            let mut changed = false;

            for (key, cipher) in &file.values {
                if cipher.key_id == target_key_id {
                    rotated_values.insert(key.clone(), cipher.clone());
                    continue;
                }

                let plaintext = self.decrypt_secret_value_with_keyset(
                    keyset,
                    &file.info.scope,
                    file.info.name.as_str(),
                    key.as_str(),
                    cipher,
                )?;
                let rotated = encrypt_value(
                    target_key,
                    plaintext.as_str(),
                    self.value_aad(&file.info.scope, file.info.name.as_str(), key.as_str())
                        .as_bytes(),
                )?;
                rotated_values.insert(key.clone(), rotated);
                changed = true;
            }

            if changed {
                file.values = rotated_values;
                file.info.updated_at = Utc::now();
                write_json_atomic(path.as_path(), &file)?;
                rotated_secret_count = rotated_secret_count.saturating_add(1);
            }
        }

        Ok(rotated_secret_count)
    }

    fn decrypt_secret_value(
        &self,
        scope: &SecretScope,
        name: &str,
        key: &str,
        cipher: &EncryptedValue,
    ) -> Result<String> {
        self.decrypt_secret_value_with_keyset(&self.master_keyset, scope, name, key, cipher)
    }

    fn decrypt_secret_value_with_keyset(
        &self,
        keyset: &MasterKeySet,
        scope: &SecretScope,
        name: &str,
        key: &str,
        cipher: &EncryptedValue,
    ) -> Result<String> {
        let decrypt_key = keyset.key_by_id(cipher.key_id.as_str())?;
        let aad = self.value_aad(scope, name, key);
        decrypt_value(decrypt_key, cipher, aad.as_bytes())
    }

    fn load_rotation_journal(&self) -> Result<Option<RotationJournal>> {
        let path = rotation_journal_path(self.data_dir.as_path());
        if !path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(path.as_path())?;
        let parsed: RotationJournal = serde_json::from_str(body.as_str())?;
        Ok(Some(parsed))
    }

    fn write_rotation_journal(&self, journal: &RotationJournal) -> Result<()> {
        write_json_atomic(
            rotation_journal_path(self.data_dir.as_path()).as_path(),
            journal,
        )
    }

    fn delete_rotation_journal(&self) -> Result<()> {
        let path = rotation_journal_path(self.data_dir.as_path());
        if path.exists() {
            fs::remove_file(path.as_path())?;
        }
        Ok(())
    }

    fn write_master_keyset(&self, keyset: &MasterKeySet) -> Result<()> {
        let path = master_key_path(self.data_dir.as_path());
        write_master_key_file(path.as_path(), keyset)
    }

    fn acquire_write_lock(&self) -> Result<StoreWriteLockGuard> {
        let path = store_lock_path(self.data_dir.as_path());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.as_path())?;
        file.lock_exclusive()?;
        Ok(StoreWriteLockGuard { file: Some(file) })
    }

    fn list_scope_secrets(&self, scope: &SecretScope) -> Result<Vec<SecretInfo>> {
        let dir = self.scope_dir(scope);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(dir.as_path())? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            out.push(read_secret_file(path.as_path())?.info);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn list_global_secrets(&self) -> Result<Vec<SecretInfo>> {
        self.list_scope_secrets(&SecretScope::Global)
    }

    fn list_nested_scope_secrets(&self, scope_root: &str) -> Result<Vec<SecretInfo>> {
        let root = self.data_dir.join("secrets").join(scope_root);
        if !root.exists() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        for scope_dir in fs::read_dir(root.as_path())? {
            let scope_dir = scope_dir?;
            if !scope_dir.path().is_dir() {
                continue;
            }
            for entry in fs::read_dir(scope_dir.path().as_path())? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                out.push(read_secret_file(path.as_path())?.info);
            }
        }
        Ok(out)
    }

    fn value_aad(&self, scope: &SecretScope, name: &str, key: &str) -> String {
        format!("{}:{name}:{key}", scope_label(scope))
    }

    fn scope_dir(&self, scope: &SecretScope) -> PathBuf {
        let mut path = self.data_dir.join("secrets");
        for segment in scope.path_segments() {
            path = path.join(segment);
        }
        path
    }

    fn secret_file_path(&self, scope: &SecretScope, name: &str) -> PathBuf {
        self.scope_dir(scope).join(format!("{name}.json"))
    }

    fn grants_scope_dir(&self, scope: &SecretScope) -> PathBuf {
        let mut path = self.data_dir.join("grants");
        for segment in scope.path_segments() {
            path = path.join(segment);
        }
        path
    }

    fn grant_file_path(&self, scope: &SecretScope, name: &str) -> PathBuf {
        self.grants_scope_dir(scope).join(format!("{name}.json"))
    }
}

fn read_secret_file(path: &Path) -> Result<SecretFile> {
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(body.as_str())?)
}

fn read_master_key_file(path: &Path) -> Result<MasterKeySet> {
    let body = fs::read_to_string(path)?;
    let raw: serde_json::Value = serde_json::from_str(body.as_str())?;

    if raw.get("primary_key_id").is_some() || raw.get("version").is_some() {
        let parsed: MasterKeyFile = serde_json::from_value(raw)?;
        if parsed.version != MASTER_KEYSET_VERSION {
            return Err(HemError::MasterKeyParse(format!(
                "unsupported keyset version {}",
                parsed.version
            )));
        }
        if parsed.keys.is_empty() {
            return Err(HemError::MasterKeyParse(
                "master keyset must contain at least one key".to_string(),
            ));
        }

        let mut keys = HashMap::new();
        for item in parsed.keys {
            let key_bytes = decode_master_key_bytes(item.key_b64.as_str())?;
            if keys
                .insert(
                    item.key_id.clone(),
                    MasterKey {
                        key_id: item.key_id.clone(),
                        key_bytes,
                    },
                )
                .is_some()
            {
                return Err(HemError::MasterKeyParse(format!(
                    "duplicate key_id in keyset {}",
                    item.key_id
                )));
            }
        }
        if !keys.contains_key(parsed.primary_key_id.as_str()) {
            return Err(HemError::MasterKeyParse(format!(
                "primary key {} not present in keyset",
                parsed.primary_key_id
            )));
        }
        return Ok(MasterKeySet {
            primary_key_id: parsed.primary_key_id,
            keys,
        });
    }

    let parsed: LegacyMasterKeyFile = serde_json::from_value(raw)?;
    let key_bytes = decode_master_key_bytes(parsed.key_b64.as_str())?;
    Ok(MasterKeySet::with_primary(MasterKey {
        key_id: parsed.key_id,
        key_bytes,
    }))
}

fn write_master_key_file(path: &Path, keyset: &MasterKeySet) -> Result<()> {
    let mut keys = keyset
        .keys
        .values()
        .map(|item| MasterKeyRecord {
            key_id: item.key_id.clone(),
            key_b64: STANDARD_NO_PAD.encode(item.key_bytes),
        })
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));

    let file = MasterKeyFile {
        version: MASTER_KEYSET_VERSION.to_string(),
        primary_key_id: keyset.primary_key_id.clone(),
        keys,
    };
    write_json_atomic(path, &file)?;
    set_owner_read_write_only(path)?;
    ensure_master_key_permissions(path)?;
    Ok(())
}

fn decode_master_key_bytes(key_b64: &str) -> Result<[u8; 32]> {
    let decoded = STANDARD_NO_PAD
        .decode(key_b64.as_bytes())
        .map_err(|err| HemError::MasterKeyParse(format!("invalid base64 key: {err}")))?;
    if decoded.len() != 32 {
        return Err(HemError::MasterKeyParse(format!(
            "invalid key length {}; expected 32",
            decoded.len()
        )));
    }
    let mut key_bytes = [0_u8; 32];
    key_bytes.copy_from_slice(decoded.as_slice());
    Ok(key_bytes)
}

fn master_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MASTER_KEY_FILE)
}

fn rotation_journal_path(data_dir: &Path) -> PathBuf {
    data_dir.join("rotation").join(ROTATION_JOURNAL_FILE)
}

fn store_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join("locks").join(STORE_LOCK_FILE)
}

fn ensure_layout(data_dir: &Path) -> Result<()> {
    fs::create_dir_all(data_dir.join("secrets").join("global"))?;
    fs::create_dir_all(data_dir.join("secrets").join("project"))?;
    fs::create_dir_all(data_dir.join("secrets").join("identity"))?;
    fs::create_dir_all(data_dir.join("groups"))?;
    fs::create_dir_all(data_dir.join("grants"))?;
    fs::create_dir_all(data_dir.join("tokens"))?;
    fs::create_dir_all(data_dir.join("approvals").join("pending"))?;
    fs::create_dir_all(data_dir.join("approvals").join("resolved"))?;
    fs::create_dir_all(data_dir.join("service-tokens"))?;
    fs::create_dir_all(data_dir.join("audit"))?;
    fs::create_dir_all(data_dir.join("rotation"))?;
    fs::create_dir_all(data_dir.join("locks"))?;
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!(
        "tmp-{}.json",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    ));
    let body = serde_json::to_vec_pretty(value)?;
    fs::write(temp.as_path(), body)?;
    fs::rename(temp.as_path(), path)?;
    Ok(())
}

fn scope_label(scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project { project } => format!("project/{project}"),
        SecretScope::Identity { identity_id } => format!("identity/{identity_id}"),
    }
}

fn normalize_subject<'a>(label: &str, value: &'a str) -> Result<&'a str> {
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

fn normalize_actor(value: &str) -> String {
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

fn set_owner_read_write_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn ensure_master_key_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(HemError::InsecureMasterKeyPermissions(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn set_and_get_secret_roundtrip() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        let mut values = HashMap::new();
        values.insert("api_key".to_string(), "sk-test-123".to_string());
        values.insert("org".to_string(), "acme".to_string());

        let info = store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "openai-prod".to_string(),
                values,
                description: "OpenAI production key".to_string(),
                requires_approval: false,
                group: Some("llm".to_string()),
                actor: "tester".to_string(),
            })
            .expect("set");
        assert_eq!(info.name, "openai-prod");

        let secret = store
            .get_secret(&SecretScope::Global, "openai-prod", Some("reader"))
            .expect("get");
        assert_eq!(
            secret.values.get("api_key"),
            Some(&"sk-test-123".to_string())
        );
        assert_eq!(secret.values.get("org"), Some(&"acme".to_string()));
    }

    #[test]
    fn get_secret_values_without_access_update_does_not_touch_metadata() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "scan-target".to_string(),
                values: HashMap::from([("api_key".to_string(), "sk-test-123".to_string())]),
                description: "scan target".to_string(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("set");
        let before = store
            .get_secret_info(&SecretScope::Global, "scan-target")
            .expect("info before");
        let values = store
            .get_secret_values_without_access_update(&SecretScope::Global, "scan-target")
            .expect("values");
        assert_eq!(values.get("api_key"), Some(&"sk-test-123".to_string()));
        let after = store
            .get_secret_info(&SecretScope::Global, "scan-target")
            .expect("info after");
        assert_eq!(before.last_accessed_at, after.last_accessed_at);
        assert_eq!(before.last_accessed_by, after.last_accessed_by);
        assert_eq!(before.updated_at, after.updated_at);
    }

    #[test]
    fn secret_file_does_not_contain_plaintext_value() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        let mut values = HashMap::new();
        values.insert("password".to_string(), "super-secret-password".to_string());

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Project {
                    project: "demo".to_string(),
                },
                name: "db-prod".to_string(),
                values,
                description: String::new(),
                requires_approval: true,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("set");

        let file = root
            .path()
            .join("secrets")
            .join("project")
            .join("demo")
            .join("db-prod.json");
        let body = fs::read_to_string(file.as_path()).expect("read file");
        assert!(!body.contains("super-secret-password"));
        assert!(body.contains("ciphertext_b64"));
    }

    #[test]
    fn list_secrets_returns_all_scopes() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        let mut base_values = HashMap::new();
        base_values.insert("k".to_string(), "v".to_string());

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "g-1".to_string(),
                values: base_values.clone(),
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("global");

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Project {
                    project: "p1".to_string(),
                },
                name: "p-1".to_string(),
                values: base_values.clone(),
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("project");

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Identity {
                    identity_id: "id-1".to_string(),
                },
                name: "i-1".to_string(),
                values: base_values,
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("identity");

        let listed = store.list_secrets(None).expect("list");
        assert_eq!(listed.len(), 3);
    }

    #[test]
    fn secret_group_can_be_set_and_listed() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        let mut values = HashMap::new();
        values.insert("api_key".to_string(), "secret".to_string());

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "anthropic-prod".to_string(),
                values,
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "operator".to_string(),
            })
            .expect("set");

        let updated = store
            .set_secret_group(
                &SecretScope::Global,
                "anthropic-prod",
                Some("llm".to_string()),
            )
            .expect("set group");
        assert_eq!(updated.group.as_deref(), Some("llm"));

        let grouped = store.list_group_secrets("llm").expect("list group");
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].name, "anthropic-prod");
    }

    #[test]
    fn token_manager_derives_from_store_master_key() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        let manager = store.token_manager().expect("token manager");
        let issued = manager
            .issue_service_token(
                "smi".to_string(),
                std::time::Duration::from_secs(60),
                "operator",
            )
            .expect("issue service token");
        let claims = manager
            .verify_token(issued.token.as_str())
            .expect("verify issued token");
        assert_eq!(claims.token_type, crate::model::TokenType::Service);
        assert_eq!(claims.service_name.as_deref(), Some("smi"));
    }

    #[test]
    fn master_key_permissions_must_be_strict() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let key_path = root.path().join("master.key");
            fs::set_permissions(key_path.as_path(), fs::Permissions::from_mode(0o644))
                .expect("set perms");
            let err = HemStore::open(root.path()).expect_err("must reject weak perms");
            assert!(matches!(err, HemError::InsecureMasterKeyPermissions(_)));
        }
    }

    #[test]
    fn grant_lifecycle_roundtrip() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        let mut values = HashMap::new();
        values.insert("api_key".to_string(), "secret".to_string());
        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Project {
                    project: "proj-1".to_string(),
                },
                name: "deploy".to_string(),
                values,
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "operator".to_string(),
            })
            .expect("set");

        let grant = store
            .grant_access(
                &SecretScope::Project {
                    project: "proj-1".to_string(),
                },
                "deploy",
                &SecretScope::Global,
                "smi",
                "operator",
            )
            .expect("grant");
        assert_eq!(grant.grantee_id, "smi");

        assert!(store
            .has_grant(
                &SecretScope::Project {
                    project: "proj-1".to_string(),
                },
                "deploy",
                &SecretScope::Global,
                "smi"
            )
            .expect("has"));

        let listed = store
            .list_grants(
                &SecretScope::Project {
                    project: "proj-1".to_string(),
                },
                "deploy",
            )
            .expect("list");
        assert_eq!(listed.len(), 1);

        assert!(store
            .revoke_access(
                &SecretScope::Project {
                    project: "proj-1".to_string(),
                },
                "deploy",
                &SecretScope::Global,
                "smi"
            )
            .expect("revoke"));
        assert!(store
            .list_grants(
                &SecretScope::Project {
                    project: "proj-1".to_string(),
                },
                "deploy",
            )
            .expect("list after revoke")
            .is_empty());
    }

    #[test]
    fn export_and_import_bundle_roundtrip() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "openai-prod".to_string(),
                values: HashMap::from([("api_key".to_string(), "sk-test".to_string())]),
                description: "OpenAI".to_string(),
                requires_approval: false,
                group: Some("llm".to_string()),
                actor: "tester".to_string(),
            })
            .expect("set");

        let bundle = store
            .export_secrets_bundle(None)
            .expect("export bundle bytes");
        assert!(!bundle.is_empty());

        assert!(store
            .delete_secret(&SecretScope::Global, "openai-prod")
            .expect("delete"));

        let imported = store
            .import_secrets_bundle(bundle.as_slice(), false)
            .expect("import");
        assert_eq!(imported, 1);

        let restored = store
            .get_secret(&SecretScope::Global, "openai-prod", Some("reader"))
            .expect("get imported");
        assert_eq!(restored.values.get("api_key"), Some(&"sk-test".to_string()));
    }

    #[test]
    fn import_accepts_bundle_encrypted_with_retained_old_key() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "legacy-key-secret".to_string(),
                values: HashMap::from([("token".to_string(), "v1".to_string())]),
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("set");

        let old_bundle = store.export_secrets_bundle(None).expect("export old");
        let old_bundle_parsed: ExportBundle =
            serde_json::from_slice(old_bundle.as_slice()).expect("parse old bundle");

        store.rotate_master_key().expect("rotate");
        store
            .delete_secret(&SecretScope::Global, "legacy-key-secret")
            .expect("delete");
        let imported = store
            .import_secrets_bundle(old_bundle.as_slice(), false)
            .expect("import old bundle");
        assert_eq!(imported, 1);

        let restored = store
            .get_secret(&SecretScope::Global, "legacy-key-secret", Some("reader"))
            .expect("get restored");
        assert_eq!(restored.values.get("token"), Some(&"v1".to_string()));

        let keyset = read_master_key_file(master_key_path(root.path()).as_path()).expect("keyset");
        assert!(keyset.has_key(old_bundle_parsed.master_key_id.as_str()));
    }

    #[test]
    fn rotate_master_key_reencrypts_and_updates_key_id() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");
        let old_key_id = store.master_key_id().to_string();

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "rotate-me".to_string(),
                values: HashMap::from([("token".to_string(), "before".to_string())]),
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("set");

        let (new_key_id, rotated_count) = store.rotate_master_key().expect("rotate");
        assert_ne!(old_key_id, new_key_id);
        assert_eq!(rotated_count, 1);

        let keyset = read_master_key_file(master_key_path(root.path()).as_path()).expect("keyset");
        assert_eq!(keyset.primary_key_id, new_key_id);
        assert!(keyset.has_key(old_key_id.as_str()));
        assert!(keyset.has_key(new_key_id.as_str()));

        let reopened = HemStore::open(root.path()).expect("reopen");
        assert_eq!(reopened.master_key_id(), new_key_id.as_str());
        let secret = reopened
            .get_secret(&SecretScope::Global, "rotate-me", Some("reader"))
            .expect("get");
        assert_eq!(secret.values.get("token"), Some(&"before".to_string()));
    }

    #[test]
    fn open_supports_legacy_master_key_file() {
        let root = tempfile::tempdir().expect("tempdir");
        ensure_layout(root.path()).expect("layout");
        let master_key = generate_master_key();
        let legacy = LegacyMasterKeyFile {
            key_id: master_key.key_id.clone(),
            key_b64: STANDARD_NO_PAD.encode(master_key.key_bytes),
        };
        let key_path = master_key_path(root.path());
        write_json_atomic(key_path.as_path(), &legacy).expect("write key");
        set_owner_read_write_only(key_path.as_path()).expect("chmod");

        let store = HemStore::open(root.path()).expect("open");
        assert_eq!(store.master_key_id(), master_key.key_id.as_str());
    }

    #[test]
    fn open_recovers_crashed_rotation_journal() {
        let root = tempfile::tempdir().expect("tempdir");
        HemStore::init(root.path(), false).expect("init");
        let store = HemStore::open(root.path()).expect("open");

        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "alpha".to_string(),
                values: HashMap::from([("token".to_string(), "one".to_string())]),
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("set alpha");
        store
            .set_secret(SetSecretInput {
                scope: SecretScope::Global,
                name: "beta".to_string(),
                values: HashMap::from([("token".to_string(), "two".to_string())]),
                description: String::new(),
                requires_approval: false,
                group: None,
                actor: "tester".to_string(),
            })
            .expect("set beta");

        let old_key_id = store.master_key_id().to_string();
        let new_master_key = generate_master_key();
        let key_path = master_key_path(root.path());
        let mut keyset = read_master_key_file(key_path.as_path()).expect("read keyset");
        keyset.upsert_key(new_master_key.clone());
        write_master_key_file(key_path.as_path(), &keyset).expect("write dual keyset");

        let started = Utc::now();
        let journal = RotationJournal {
            version: ROTATION_JOURNAL_VERSION.to_string(),
            old_primary_key_id: old_key_id,
            new_key_id: new_master_key.key_id.clone(),
            started_at: started,
            updated_at: started,
        };
        write_json_atomic(rotation_journal_path(root.path()).as_path(), &journal)
            .expect("write journal");

        let alpha_path = root
            .path()
            .join("secrets")
            .join("global")
            .join("alpha.json");
        let mut alpha = read_secret_file(alpha_path.as_path()).expect("read alpha");
        let mut rotated_values = HashMap::new();
        for (key, cipher) in &alpha.values {
            let plain = store
                .decrypt_secret_value_with_keyset(
                    &keyset,
                    &alpha.info.scope,
                    alpha.info.name.as_str(),
                    key.as_str(),
                    cipher,
                )
                .expect("decrypt alpha");
            let aad = store.value_aad(&alpha.info.scope, alpha.info.name.as_str(), key.as_str());
            let encrypted =
                encrypt_value(&new_master_key, plain.as_str(), aad.as_bytes()).expect("encrypt");
            rotated_values.insert(key.clone(), encrypted);
        }
        alpha.values = rotated_values;
        write_json_atomic(alpha_path.as_path(), &alpha).expect("rewrite alpha");

        let recovered = HemStore::open(root.path()).expect("reopen");
        assert_eq!(recovered.master_key_id(), new_master_key.key_id.as_str());
        assert!(!rotation_journal_path(root.path()).exists());

        let alpha_secret = recovered
            .get_secret(&SecretScope::Global, "alpha", Some("reader"))
            .expect("get alpha");
        assert_eq!(alpha_secret.values.get("token"), Some(&"one".to_string()));

        let beta_secret = recovered
            .get_secret(&SecretScope::Global, "beta", Some("reader"))
            .expect("get beta");
        assert_eq!(beta_secret.values.get("token"), Some(&"two".to_string()));

        let recovered_keyset =
            read_master_key_file(master_key_path(root.path()).as_path()).expect("read keyset");
        assert_eq!(recovered_keyset.primary_key_id, new_master_key.key_id);
        assert!(recovered_keyset.has_key(journal.old_primary_key_id.as_str()));
        assert!(recovered_keyset.has_key(journal.new_key_id.as_str()));
    }
}
