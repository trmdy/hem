use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, PoisonError, Weak},
    time::Duration,
};

use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    fs_security::{ensure_private_dir, set_owner_read_write_only},
    HemError, NodeIdentity, Result,
};

const LEDGER_DIR: &str = "distributed";
const LEDGER_FILE: &str = "ledger.sqlite3";
const BUSY_TIMEOUT_SECONDS: u64 = 5;
const LEDGER_SCHEMA_VERSION: i64 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerOperationInput {
    pub operation_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub node_seq: i64,
    pub op_type: String,
    pub payload_json: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerOperationBody {
    pub operation_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub node_seq: i64,
    pub op_type: String,
    pub payload_json: Value,
    pub created_at: DateTime<Utc>,
    pub prev_hash_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerOperationEnvelope {
    pub body: LedgerOperationBody,
    pub body_hash_b64: String,
    pub signing_public_key_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpointBody {
    pub checkpoint_id: String,
    pub cluster_id: String,
    pub to_position: i64,
    pub operation_count: i64,
    pub merkle_root_b64: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpoint {
    pub body: LedgerCheckpointBody,
    pub body_hash_b64: String,
    pub signer_node_id: String,
    pub signing_public_key_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpointCosignatureBody {
    pub checkpoint_id: String,
    pub checkpoint_body_hash_b64: String,
    pub signer_node_id: String,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpointCosignature {
    pub body: LedgerCheckpointCosignatureBody,
    pub signing_public_key_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSecretMetadata {
    pub cluster_id: String,
    pub scope: String,
    pub name: String,
    pub description: String,
    pub requires_approval: bool,
    pub group: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub last_operation_id: String,
    pub last_position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPeerCursor {
    pub peer_node_id: String,
    pub last_position: i64,
    pub last_body_hash_b64: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSecretValueVersion {
    pub cluster_id: String,
    pub scope: String,
    pub name: String,
    pub key: String,
    pub version_seq: i64,
    pub encrypted_value_json: Value,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub operation_id: String,
    pub position: i64,
    pub base_version_seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCollision {
    pub collision_id: String,
    pub cluster_id: String,
    pub scope: String,
    pub name: String,
    pub key: String,
    pub current_operation_id: String,
    pub incoming_operation_id: String,
    pub base_version_seq: i64,
    pub current_version_seq: i64,
    pub state: String,
    pub resolution: Option<String>,
    pub resolved_by: Option<String>,
    pub resolution_operation_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerForkRecord {
    pub fork_id: String,
    pub cluster_id: String,
    pub epoch: i64,
    pub parent_checkpoint_id: String,
    pub parent_checkpoint_body_hash_b64: String,
    pub parent_position: i64,
    pub declared_by: String,
    pub reason: String,
    pub operation_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerForkReplayInput<'a> {
    pub fork_id: &'a str,
    pub actor: &'a str,
    pub backup_reference: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerForkReplayRecord {
    pub replay_id: String,
    pub fork_id: String,
    pub cluster_id: String,
    pub parent_checkpoint_id: String,
    pub parent_position: i64,
    pub fork_position: i64,
    pub replay_policy: String,
    pub operation_id: String,
    pub replayed_by: String,
    pub backup_reference: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerForkReplayReport {
    pub replay_id: String,
    pub fork_id: String,
    pub parent_position: i64,
    pub fork_position: i64,
    pub latest_position: i64,
    pub replay_operation_id: String,
    pub operations_replayed: usize,
    pub operations_skipped: usize,
    pub materializer_records_rebuilt: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerBootstrapReport {
    pub accepted_operations: usize,
    pub duplicate_operations: usize,
    pub latest_position: i64,
    pub latest_body_hash_b64: String,
    pub materialized_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIntegrityIssue {
    pub severity: String,
    pub category: String,
    pub reference: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIntegrityReport {
    pub ok: bool,
    pub latest_position: i64,
    pub latest_body_hash_b64: String,
    pub operations_checked: usize,
    pub value_blobs_checked: usize,
    pub checkpoints_checked: usize,
    pub checkpoint_cosignatures_checked: usize,
    pub peer_cursors_checked: usize,
    pub forks_declared: usize,
    pub fork_replays_declared: usize,
    pub issues: Vec<LedgerIntegrityIssue>,
}

struct LedgerCollisionResolution {
    collision_id: String,
    resolution: String,
    resolved_by: String,
    operation_id: String,
    resolved_at: DateTime<Utc>,
}

struct LedgerForkReplayRebuild {
    operations_replayed: usize,
    operations_skipped: usize,
    materializer_records_rebuilt: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerOperation {
    pub position: i64,
    pub operation_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub node_seq: i64,
    pub op_type: String,
    pub payload_json: Value,
    pub created_at: DateTime<Utc>,
    pub prev_hash_b64: String,
    pub body_hash_b64: String,
    pub signing_public_key_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone)]
pub struct LedgerStore {
    path: PathBuf,
    _anchor: Arc<LedgerAnchor>,
}

/// One connection held open per ledger file while any `LedgerStore` for it is alive.
///
/// Every method opens a short-lived connection. Without an anchor each of those is the
/// last connection on close, so SQLite checkpoints and deletes `-wal`/`-shm` and the next
/// call recreates them: a read-only request then costs file creates, unlinks and fsyncs.
/// The anchor also records that the file is already migrated and permissioned, so repeated
/// `LedgerStore::open` calls for the same file do no schema work.
struct LedgerAnchor {
    file_id: Option<(u64, u64)>,
    _conn: Mutex<Connection>,
}

impl fmt::Debug for LedgerAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerAnchor")
            .field("file_id", &self.file_id)
            .finish_non_exhaustive()
    }
}

fn ledger_anchors() -> &'static Mutex<HashMap<PathBuf, Weak<LedgerAnchor>>> {
    static ANCHORS: OnceLock<Mutex<HashMap<PathBuf, Weak<LedgerAnchor>>>> = OnceLock::new();
    ANCHORS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(unix)]
fn create_private_file_if_missing(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(not(unix))]
fn create_private_file_if_missing(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ledger_file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn ledger_file_id(_path: &Path) -> Option<(u64, u64)> {
    None
}

impl LedgerStore {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let ledger_dir = data_dir.into().join(LEDGER_DIR);
        let path = ledger_dir.join(LEDGER_FILE);
        let mut anchors = ledger_anchors()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(anchor) = anchors.get(&path).and_then(Weak::upgrade) {
            // Reuse only while the anchored file is still the one at `path`; a replaced or
            // deleted ledger gets a fresh migration below.
            if anchor.file_id.is_some() && anchor.file_id == ledger_file_id(path.as_path()) {
                return Ok(Self {
                    path,
                    _anchor: anchor,
                });
            }
        }

        ensure_private_dir(ledger_dir.as_path())?;
        create_private_file_if_missing(path.as_path())?;
        let conn = open_connection(path.as_path())?;
        migrate(&conn)?;
        set_owner_read_write_only(path.as_path())?;
        // The anchor keeps -wal/-shm on disk; SQLite copies the database file's mode when it
        // creates them, but tighten any left behind by an older, broader database file.
        for sidecar in [
            path.with_extension("sqlite3-wal"),
            path.with_extension("sqlite3-shm"),
        ] {
            if sidecar.exists() {
                set_owner_read_write_only(sidecar.as_path())?;
            }
        }
        let anchor = Arc::new(LedgerAnchor {
            file_id: ledger_file_id(path.as_path()),
            _conn: Mutex::new(conn),
        });
        anchors.retain(|_, anchor| anchor.strong_count() > 0);
        anchors.insert(path.clone(), Arc::downgrade(&anchor));
        Ok(Self {
            path,
            _anchor: anchor,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn sign_next(
        &self,
        identity: &NodeIdentity,
        input: LedgerOperationInput,
    ) -> Result<LedgerOperationEnvelope> {
        if input.node_id != identity.node_id {
            return Err(HemError::InvalidArgument(format!(
                "ledger node_id {} does not match identity node_id {}",
                input.node_id, identity.node_id
            )));
        }
        let prev_hash_b64 = self.latest_body_hash()?.unwrap_or_default();
        Self::sign_after(identity, input, prev_hash_b64)
    }

    pub fn sign_after(
        identity: &NodeIdentity,
        input: LedgerOperationInput,
        prev_hash_b64: String,
    ) -> Result<LedgerOperationEnvelope> {
        if input.node_id != identity.node_id {
            return Err(HemError::InvalidArgument(format!(
                "ledger node_id {} does not match identity node_id {}",
                input.node_id, identity.node_id
            )));
        }
        let body = LedgerOperationBody::from_input(input, prev_hash_b64)?;
        LedgerOperationEnvelope::sign(body, identity)
    }

    pub fn append_signed(&self, envelope: &LedgerOperationEnvelope) -> Result<LedgerOperation> {
        envelope.verify()?;
        let expected_prev_hash = self.latest_body_hash()?.unwrap_or_default();
        if envelope.body.prev_hash_b64 != expected_prev_hash {
            return Err(HemError::InvalidArgument(format!(
                "ledger previous hash mismatch expected={} actual={}",
                blank_dash(expected_prev_hash.as_str()),
                blank_dash(envelope.body.prev_hash_b64.as_str())
            )));
        }

        let payload = serde_json::to_string(&envelope.body.payload_json)?;
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_operations (
                operation_id,
                cluster_id,
                node_id,
                node_seq,
                op_type,
                payload_json,
                created_at,
                prev_hash_b64,
                body_hash_b64,
                signing_public_key_b64,
                signature_b64
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                envelope.body.operation_id,
                envelope.body.cluster_id,
                envelope.body.node_id,
                envelope.body.node_seq,
                envelope.body.op_type,
                payload,
                envelope.body.created_at.to_rfc3339(),
                envelope.body.prev_hash_b64,
                envelope.body_hash_b64,
                envelope.signing_public_key_b64,
                envelope.signature_b64,
            ],
        )?;
        let position = conn.last_insert_rowid();
        self.get_by_position(position)?.ok_or_else(|| {
            HemError::InvalidArgument(format!("ledger append lost position {position}"))
        })
    }

    pub fn get_by_operation_id(&self, operation_id: &str) -> Result<Option<LedgerOperation>> {
        validate_non_empty("operation_id", operation_id)?;
        let conn = self.connect()?;
        query_optional_operation(
            &conn,
            "SELECT position, operation_id, cluster_id, node_id, node_seq, op_type, payload_json, created_at,
                    prev_hash_b64, body_hash_b64, signing_public_key_b64, signature_b64
             FROM ledger_operations WHERE operation_id = ?1",
            params![operation_id],
        )
    }

    pub fn list_after(&self, position: i64, limit: usize) -> Result<Vec<LedgerOperation>> {
        if position < 0 {
            return Err(HemError::InvalidArgument(
                "ledger cursor position must not be negative".to_string(),
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT position, operation_id, cluster_id, node_id, node_seq, op_type, payload_json, created_at,
                    prev_hash_b64, body_hash_b64, signing_public_key_b64, signature_b64
             FROM ledger_operations
             WHERE position > ?1
             ORDER BY position ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![position, limit], operation_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn latest_position(&self) -> Result<i64> {
        let conn = self.connect()?;
        Ok(conn.query_row(
            "SELECT COALESCE(MAX(position), 0) FROM ledger_operations",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn latest_body_hash(&self) -> Result<Option<String>> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT body_hash_b64 FROM ledger_operations ORDER BY position DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn verify_integrity(&self) -> Result<LedgerIntegrityReport> {
        let latest_position = self.latest_position()?;
        let latest_body_hash_b64 = self.latest_body_hash()?.unwrap_or_default();
        let checkpoints = self.list_checkpoints()?;
        let checkpoint_positions = checkpoints
            .iter()
            .filter_map(|checkpoint| {
                (checkpoint.body.to_position > 0 && checkpoint.body.to_position <= latest_position)
                    .then_some(checkpoint.body.to_position)
            })
            .collect::<BTreeSet<_>>();
        let mut checkpoint_positions = checkpoint_positions.into_iter().peekable();
        let mut checkpoint_summaries = BTreeMap::new();
        let mut merkle = MerkleAccumulator::default();
        let mut report = LedgerIntegrityReport {
            ok: true,
            latest_position,
            latest_body_hash_b64,
            operations_checked: 0,
            value_blobs_checked: 0,
            checkpoints_checked: 0,
            checkpoint_cosignatures_checked: 0,
            peer_cursors_checked: 0,
            forks_declared: self.list_forks()?.len(),
            fork_replays_declared: self.list_fork_replays()?.len(),
            issues: Vec::new(),
        };

        let mut expected_prev_hash = String::new();
        for operation in self.list_after(0, usize::MAX)? {
            while checkpoint_positions
                .peek()
                .is_some_and(|position| *position < operation.position)
            {
                let position = checkpoint_positions.next().expect("peeked position");
                checkpoint_summaries.insert(position, merkle.summary());
            }
            report.operations_checked += 1;
            if operation.prev_hash_b64 != expected_prev_hash {
                report.issues.push(integrity_issue(
                    "error",
                    "hash_chain",
                    format!("operation:{}", operation.operation_id),
                    format!(
                        "previous hash mismatch expected={} actual={}",
                        blank_dash(expected_prev_hash.as_str()),
                        blank_dash(operation.prev_hash_b64.as_str())
                    ),
                ));
            }

            let envelope = LedgerOperationEnvelope {
                body: LedgerOperationBody {
                    operation_id: operation.operation_id.clone(),
                    cluster_id: operation.cluster_id.clone(),
                    node_id: operation.node_id.clone(),
                    node_seq: operation.node_seq,
                    op_type: operation.op_type.clone(),
                    payload_json: operation.payload_json.clone(),
                    created_at: operation.created_at,
                    prev_hash_b64: operation.prev_hash_b64.clone(),
                },
                body_hash_b64: operation.body_hash_b64.clone(),
                signing_public_key_b64: operation.signing_public_key_b64.clone(),
                signature_b64: operation.signature_b64.clone(),
            };
            if let Err(err) = envelope.verify() {
                report.issues.push(integrity_issue(
                    "error",
                    "signature",
                    format!("operation:{}", operation.operation_id),
                    err.to_string(),
                ));
            }
            inspect_known_operation_payload(&operation, &mut report.issues);
            report.value_blobs_checked += inspect_value_blobs(&operation, &mut report.issues);
            merkle.push(decode_base64_exact::<32>(
                "body_hash_b64",
                operation.body_hash_b64.as_str(),
            )?);
            while checkpoint_positions
                .peek()
                .is_some_and(|position| *position == operation.position)
            {
                let position = checkpoint_positions.next().expect("peeked position");
                checkpoint_summaries.insert(position, merkle.summary());
            }
            expected_prev_hash = operation.body_hash_b64;
        }
        for position in checkpoint_positions {
            checkpoint_summaries.insert(position, merkle.summary());
        }

        for checkpoint in checkpoints {
            report.checkpoints_checked += 1;
            if let Err(err) = checkpoint.verify() {
                report.issues.push(integrity_issue(
                    "error",
                    "checkpoint_signature",
                    format!("checkpoint:{}", checkpoint.body.checkpoint_id),
                    err.to_string(),
                ));
            }
            if checkpoint.body.to_position > latest_position {
                report.issues.push(integrity_issue(
                    "warning",
                    "divergence",
                    format!("checkpoint:{}", checkpoint.body.checkpoint_id),
                    format!(
                        "checkpoint position {} is ahead of local head {}",
                        checkpoint.body.to_position, latest_position
                    ),
                ));
            } else if checkpoint.body.to_position > 0 {
                verify_checkpoint_merkle_summary(
                    &checkpoint,
                    checkpoint_summaries.get(&checkpoint.body.to_position),
                    &mut report,
                );
            }

            for cosignature in
                self.list_checkpoint_cosignatures(checkpoint.body.checkpoint_id.as_str())?
            {
                report.checkpoint_cosignatures_checked += 1;
                if let Err(err) = cosignature.verify(&checkpoint) {
                    report.issues.push(integrity_issue(
                        "error",
                        "checkpoint_cosignature",
                        format!(
                            "checkpoint:{} signer:{}",
                            checkpoint.body.checkpoint_id, cosignature.body.signer_node_id
                        ),
                        err.to_string(),
                    ));
                }
            }
        }

        for cursor in self.list_peer_cursors()? {
            report.peer_cursors_checked += 1;
            if cursor.last_position > latest_position {
                report.issues.push(integrity_issue(
                    "warning",
                    "divergence",
                    format!("peer:{}", cursor.peer_node_id),
                    format!(
                        "peer cursor position {} is ahead of local head {}",
                        cursor.last_position, latest_position
                    ),
                ));
                continue;
            }
            if cursor.last_position > 0 {
                match self.get_by_position(cursor.last_position)? {
                    Some(operation) if operation.body_hash_b64 == cursor.last_body_hash_b64 => {}
                    Some(operation) => report.issues.push(integrity_issue(
                        "warning",
                        "divergence",
                        format!("peer:{}", cursor.peer_node_id),
                        format!(
                            "peer cursor hash mismatch at position {} expected={} actual={}",
                            cursor.last_position,
                            operation.body_hash_b64,
                            cursor.last_body_hash_b64
                        ),
                    )),
                    None => report.issues.push(integrity_issue(
                        "warning",
                        "divergence",
                        format!("peer:{}", cursor.peer_node_id),
                        format!(
                            "peer cursor references missing position {}",
                            cursor.last_position
                        ),
                    )),
                }
            }
        }

        for replay in self.list_fork_replays()? {
            self.inspect_fork_replay(&replay, &mut report)?;
        }

        report.ok = !report.issues.iter().any(|issue| issue.severity == "error");
        Ok(report)
    }

    pub fn repair_materializers(&self) -> Result<usize> {
        let metadata = self.materialize_secret_metadata()?;
        let values = self.materialize_secret_value_versions()?;
        Ok(metadata + values)
    }

    pub fn bootstrap_from_peer_operations(
        &self,
        cluster_id: &str,
        operations: &[LedgerOperationEnvelope],
    ) -> Result<LedgerBootstrapReport> {
        validate_non_empty("cluster_id", cluster_id)?;
        let mut accepted_operations = 0_usize;
        let mut duplicate_operations = 0_usize;

        for envelope in operations {
            envelope.verify()?;
            if envelope.body.cluster_id != cluster_id {
                return Err(HemError::InvalidArgument(format!(
                    "bootstrap operation {} cluster_id {} does not match expected cluster_id {}",
                    envelope.body.operation_id, envelope.body.cluster_id, cluster_id
                )));
            }
            if let Some(existing) = self.get_by_operation_id(envelope.body.operation_id.as_str())? {
                if existing.body_hash_b64 != envelope.body_hash_b64 {
                    return Err(HemError::InvalidArgument(format!(
                        "local ledger already has operation {} with a different hash",
                        envelope.body.operation_id
                    )));
                }
                duplicate_operations += 1;
                continue;
            }
            self.append_signed(envelope)?;
            accepted_operations += 1;
        }

        // append_signed verifies every imported envelope, including its signature and
        // link to the current local head. Re-verifying the complete historical ledger
        // here made every peer batch proportional to all operations and checkpoints.
        // Full historical verification remains available through verify_integrity().
        let materialized_records = self.repair_materializers()?;

        Ok(LedgerBootstrapReport {
            accepted_operations,
            duplicate_operations,
            latest_position: self.latest_position()?,
            latest_body_hash_b64: self.latest_body_hash()?.unwrap_or_default(),
            materialized_records,
        })
    }

    pub fn create_checkpoint(
        &self,
        identity: &NodeIdentity,
        cluster_id: &str,
        to_position: i64,
    ) -> Result<LedgerCheckpoint> {
        validate_non_empty("cluster_id", cluster_id)?;
        if to_position < 1 {
            return Err(HemError::InvalidArgument(
                "checkpoint to_position must be at least 1".to_string(),
            ));
        }

        let leaf_hashes = self.operation_hashes_up_to(to_position)?;
        if leaf_hashes.is_empty() {
            return Err(HemError::InvalidArgument(format!(
                "checkpoint has no ledger operations up to position={to_position}"
            )));
        }
        let merkle_root = merkle_root(leaf_hashes.as_slice())?;
        let body = LedgerCheckpointBody {
            checkpoint_id: format!(
                "hcp_{}",
                valhall_config::ids::generate_entropy_prefixed_ulid()
            ),
            cluster_id: cluster_id.to_string(),
            to_position,
            operation_count: i64::try_from(leaf_hashes.len()).map_err(|_| {
                HemError::InvalidArgument("checkpoint operation count overflow".to_string())
            })?,
            merkle_root_b64: STANDARD_NO_PAD.encode(merkle_root),
            created_at: Utc::now(),
        };
        let body_hash = canonical_hash_bytes(&body)?;
        let signature = sign_hash(identity, &body_hash)?;
        let checkpoint = LedgerCheckpoint {
            body,
            body_hash_b64: STANDARD_NO_PAD.encode(body_hash),
            signer_node_id: identity.node_id.clone(),
            signing_public_key_b64: signature.public_key_b64,
            signature_b64: signature.signature_b64,
        };
        checkpoint.verify()?;
        self.insert_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    pub fn get_checkpoint(&self, checkpoint_id: &str) -> Result<Option<LedgerCheckpoint>> {
        validate_non_empty("checkpoint_id", checkpoint_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT checkpoint_id, cluster_id, to_position, operation_count, merkle_root_b64, created_at,
                    body_hash_b64, signer_node_id, signing_public_key_b64, signature_b64
             FROM ledger_checkpoints WHERE checkpoint_id = ?1",
            params![checkpoint_id],
            checkpoint_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn list_checkpoints(&self) -> Result<Vec<LedgerCheckpoint>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT checkpoint_id, cluster_id, to_position, operation_count, merkle_root_b64, created_at,
                    body_hash_b64, signer_node_id, signing_public_key_b64, signature_b64
             FROM ledger_checkpoints
             ORDER BY to_position ASC, created_at ASC",
        )?;
        let rows = stmt.query_map([], checkpoint_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn latest_checkpoint_for_signer(
        &self,
        cluster_id: &str,
        signer_node_id: &str,
    ) -> Result<Option<LedgerCheckpoint>> {
        validate_non_empty("cluster_id", cluster_id)?;
        validate_non_empty("signer_node_id", signer_node_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT checkpoint_id, cluster_id, to_position, operation_count, merkle_root_b64, created_at,
                    body_hash_b64, signer_node_id, signing_public_key_b64, signature_b64
             FROM ledger_checkpoints
             WHERE cluster_id = ?1 AND signer_node_id = ?2
             ORDER BY to_position DESC, created_at DESC
             LIMIT 1",
            params![cluster_id, signer_node_id],
            checkpoint_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn cosign_checkpoint(
        &self,
        identity: &NodeIdentity,
        checkpoint_id: &str,
    ) -> Result<LedgerCheckpointCosignature> {
        let checkpoint = self.get_checkpoint(checkpoint_id)?.ok_or_else(|| {
            HemError::InvalidArgument(format!("checkpoint not found: {checkpoint_id}"))
        })?;
        checkpoint.verify()?;
        if let Some(existing) =
            self.get_checkpoint_cosignature(checkpoint_id, identity.node_id.as_str())?
        {
            existing.verify(&checkpoint)?;
            if existing.signing_public_key_b64 != identity.signing_public_key_b64 {
                return Err(HemError::Crypto(format!(
                    "checkpoint cosignature public key mismatch for signer {}",
                    identity.node_id
                )));
            }
            return Ok(existing);
        }
        let body = LedgerCheckpointCosignatureBody {
            checkpoint_id: checkpoint.body.checkpoint_id.clone(),
            checkpoint_body_hash_b64: checkpoint.body_hash_b64.clone(),
            signer_node_id: identity.node_id.clone(),
            signed_at: Utc::now(),
        };
        let body_hash = canonical_hash_bytes(&body)?;
        let signature = sign_hash(identity, &body_hash)?;
        let cosignature = LedgerCheckpointCosignature {
            body,
            signing_public_key_b64: signature.public_key_b64,
            signature_b64: signature.signature_b64,
        };
        cosignature.verify(&checkpoint)?;
        self.insert_checkpoint_cosignature(&cosignature)?;
        Ok(cosignature)
    }

    pub fn ingest_checkpoint(&self, checkpoint: &LedgerCheckpoint) -> Result<()> {
        self.validate_checkpoint_matches_local(checkpoint)?;
        if let Some(existing) = self.get_checkpoint(checkpoint.body.checkpoint_id.as_str())? {
            if existing.body_hash_b64 == checkpoint.body_hash_b64 {
                return Ok(());
            }
            return Err(HemError::InvalidArgument(format!(
                "checkpoint id collision for {}: existing hash {} differs from incoming hash {}",
                checkpoint.body.checkpoint_id, existing.body_hash_b64, checkpoint.body_hash_b64
            )));
        }
        self.insert_checkpoint(checkpoint)
    }

    pub fn ingest_checkpoint_cosignature(
        &self,
        cosignature: &LedgerCheckpointCosignature,
    ) -> Result<()> {
        let checkpoint = self
            .get_checkpoint(cosignature.body.checkpoint_id.as_str())?
            .ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "checkpoint not found: {}",
                    cosignature.body.checkpoint_id
                ))
            })?;
        cosignature.verify(&checkpoint)?;
        if let Some(existing) = self.get_checkpoint_cosignature(
            cosignature.body.checkpoint_id.as_str(),
            cosignature.body.signer_node_id.as_str(),
        )? {
            existing.verify(&checkpoint)?;
            if existing.signing_public_key_b64 != cosignature.signing_public_key_b64 {
                return Err(HemError::Crypto(format!(
                    "checkpoint cosignature public key mismatch for signer {}",
                    cosignature.body.signer_node_id
                )));
            }
            return Ok(());
        }
        self.insert_checkpoint_cosignature(cosignature)
    }

    pub fn list_checkpoint_cosignatures(
        &self,
        checkpoint_id: &str,
    ) -> Result<Vec<LedgerCheckpointCosignature>> {
        validate_non_empty("checkpoint_id", checkpoint_id)?;
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT checkpoint_id, checkpoint_body_hash_b64, signer_node_id, signed_at,
                    signing_public_key_b64, signature_b64
             FROM ledger_checkpoint_cosignatures
             WHERE checkpoint_id = ?1
             ORDER BY signer_node_id ASC",
        )?;
        let rows = stmt.query_map(params![checkpoint_id], checkpoint_cosignature_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn latest_checkpoint(&self, cluster_id: &str) -> Result<Option<LedgerCheckpoint>> {
        validate_non_empty("cluster_id", cluster_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT checkpoint_id, cluster_id, to_position, operation_count, merkle_root_b64, created_at,
                    body_hash_b64, signer_node_id, signing_public_key_b64, signature_b64
             FROM ledger_checkpoints
             WHERE cluster_id = ?1
             ORDER BY to_position DESC, created_at DESC
             LIMIT 1",
            params![cluster_id],
            checkpoint_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn materialize_secret_metadata(&self) -> Result<usize> {
        let mut cursor = self.materializer_position("secret_metadata")?;
        let mut applied = 0_usize;
        loop {
            let operations = self.list_after(cursor, 1000)?;
            if operations.is_empty() {
                return Ok(applied);
            }
            for operation in &operations {
                if let Some(metadata) = metadata_from_operation(operation)? {
                    self.upsert_secret_metadata(&metadata)?;
                    applied += 1;
                }
                cursor = operation.position;
            }
            self.set_materializer_position("secret_metadata", cursor)?;
            if operations.len() < 1000 {
                return Ok(applied);
            }
        }
    }

    pub fn get_materialized_secret_metadata(
        &self,
        cluster_id: &str,
        scope: &str,
        name: &str,
    ) -> Result<Option<LedgerSecretMetadata>> {
        validate_non_empty("cluster_id", cluster_id)?;
        validate_non_empty("scope", scope)?;
        validate_non_empty("name", name)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT cluster_id, scope, name, description, requires_approval, group_name,
                    updated_at, updated_by, last_operation_id, last_position
             FROM ledger_secret_metadata
             WHERE cluster_id = ?1 AND scope = ?2 AND name = ?3",
            params![cluster_id, scope, name],
            secret_metadata_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn list_materialized_secret_metadata(
        &self,
        cluster_id: &str,
        scope: Option<&str>,
    ) -> Result<Vec<LedgerSecretMetadata>> {
        validate_non_empty("cluster_id", cluster_id)?;
        let conn = self.connect()?;
        match scope {
            Some(scope) => {
                validate_non_empty("scope", scope)?;
                let mut stmt = conn.prepare(
                    "SELECT cluster_id, scope, name, description, requires_approval, group_name,
                            updated_at, updated_by, last_operation_id, last_position
                     FROM ledger_secret_metadata
                     WHERE cluster_id = ?1 AND scope = ?2
                     ORDER BY scope ASC, name ASC",
                )?;
                let rows = stmt.query_map(params![cluster_id, scope], secret_metadata_from_row)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(HemError::from)
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT cluster_id, scope, name, description, requires_approval, group_name,
                            updated_at, updated_by, last_operation_id, last_position
                     FROM ledger_secret_metadata
                     WHERE cluster_id = ?1
                     ORDER BY scope ASC, name ASC",
                )?;
                let rows = stmt.query_map(params![cluster_id], secret_metadata_from_row)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(HemError::from)
            }
        }
    }

    pub fn materialize_secret_value_versions(&self) -> Result<usize> {
        let mut cursor = self.materializer_position("secret_value_versions")?;
        let mut applied = 0_usize;
        loop {
            let operations = self.list_after(cursor, 1000)?;
            if operations.is_empty() {
                return Ok(applied);
            }
            for operation in &operations {
                for version in value_versions_from_operation(operation)? {
                    self.insert_secret_value_version(&version)?;
                    applied += 1;
                }
                if let Some(resolution) = collision_resolution_from_operation(operation)? {
                    self.apply_collision_resolution(&resolution)?;
                    applied += 1;
                }
                cursor = operation.position;
            }
            self.set_materializer_position("secret_value_versions", cursor)?;
            if operations.len() < 1000 {
                return Ok(applied);
            }
        }
    }

    pub fn list_secret_value_versions(
        &self,
        cluster_id: &str,
        scope: &str,
        name: &str,
        key: &str,
    ) -> Result<Vec<LedgerSecretValueVersion>> {
        validate_non_empty("cluster_id", cluster_id)?;
        validate_non_empty("scope", scope)?;
        validate_non_empty("name", name)?;
        validate_non_empty("key", key)?;
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT cluster_id, scope, name, key_name, version_seq, encrypted_value_json,
                    created_at, created_by, operation_id, position, base_version_seq
             FROM ledger_secret_value_versions
             WHERE cluster_id = ?1 AND scope = ?2 AND name = ?3 AND key_name = ?4
             ORDER BY version_seq ASC",
        )?;
        let rows = stmt.query_map(
            params![cluster_id, scope, name, key],
            secret_value_version_from_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn list_latest_secret_value_versions(
        &self,
        cluster_id: &str,
        scope: &str,
        name: &str,
    ) -> Result<Vec<LedgerSecretValueVersion>> {
        validate_non_empty("cluster_id", cluster_id)?;
        validate_non_empty("scope", scope)?;
        validate_non_empty("name", name)?;
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT v.cluster_id, v.scope, v.name, v.key_name, v.version_seq,
                    v.encrypted_value_json, v.created_at, v.created_by, v.operation_id,
                    v.position, v.base_version_seq
             FROM ledger_secret_value_versions v
             JOIN (
                 SELECT key_name, MAX(version_seq) AS version_seq
                 FROM ledger_secret_value_versions
                 WHERE cluster_id = ?1 AND scope = ?2 AND name = ?3
                 GROUP BY key_name
             ) latest
               ON latest.key_name = v.key_name
              AND latest.version_seq = v.version_seq
             WHERE v.cluster_id = ?1 AND v.scope = ?2 AND v.name = ?3
             ORDER BY v.key_name ASC",
        )?;
        let rows = stmt.query_map(
            params![cluster_id, scope, name],
            secret_value_version_from_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn list_latest_secret_value_versions_for_cluster(
        &self,
        cluster_id: &str,
    ) -> Result<Vec<LedgerSecretValueVersion>> {
        validate_non_empty("cluster_id", cluster_id)?;
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT v.cluster_id, v.scope, v.name, v.key_name, v.version_seq,
                    v.encrypted_value_json, v.created_at, v.created_by, v.operation_id,
                    v.position, v.base_version_seq
             FROM ledger_secret_value_versions v
             JOIN (
                 SELECT scope, name, key_name, MAX(version_seq) AS version_seq
                 FROM ledger_secret_value_versions
                 WHERE cluster_id = ?1
                 GROUP BY scope, name, key_name
             ) latest
               ON latest.scope = v.scope
              AND latest.name = v.name
              AND latest.key_name = v.key_name
              AND latest.version_seq = v.version_seq
             WHERE v.cluster_id = ?1
             ORDER BY v.scope ASC, v.name ASC, v.key_name ASC",
        )?;
        let rows = stmt.query_map(params![cluster_id], secret_value_version_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn list_open_collisions(&self, cluster_id: &str) -> Result<Vec<LedgerCollision>> {
        validate_non_empty("cluster_id", cluster_id)?;
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT collision_id, cluster_id, scope, name, key_name, current_operation_id,
                    incoming_operation_id, base_version_seq, current_version_seq, state,
                    resolution, resolved_by, resolution_operation_id, created_at, resolved_at
             FROM ledger_collisions
             WHERE cluster_id = ?1 AND state = 'open'
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![cluster_id], collision_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn get_collision(&self, collision_id: &str) -> Result<Option<LedgerCollision>> {
        validate_non_empty("collision_id", collision_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT collision_id, cluster_id, scope, name, key_name, current_operation_id,
                    incoming_operation_id, base_version_seq, current_version_seq, state,
                    resolution, resolved_by, resolution_operation_id, created_at, resolved_at
             FROM ledger_collisions
             WHERE collision_id = ?1",
            params![collision_id],
            collision_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn append_collision_resolution(
        &self,
        identity: &NodeIdentity,
        collision_id: &str,
        resolved_by: &str,
        resolution: &str,
    ) -> Result<LedgerOperation> {
        self.append_collision_resolution_with_agreement(
            identity,
            collision_id,
            resolved_by,
            resolution,
            None,
        )
    }

    pub fn append_collision_resolution_with_agreement(
        &self,
        identity: &NodeIdentity,
        collision_id: &str,
        resolved_by: &str,
        resolution: &str,
        agreement: Option<Value>,
    ) -> Result<LedgerOperation> {
        validate_non_empty("collision_id", collision_id)?;
        validate_non_empty("resolved_by", resolved_by)?;
        validate_non_empty("resolution", resolution)?;
        let collision = self.get_collision(collision_id)?.ok_or_else(|| {
            HemError::InvalidArgument(format!("open collision not found: {collision_id}"))
        })?;
        if collision.state != "open" {
            return Err(HemError::InvalidArgument(format!(
                "open collision not found: {collision_id}"
            )));
        }
        let mut payload_json = json!({
            "collision_id": collision.collision_id.as_str(),
            "scope": collision.scope.as_str(),
            "name": collision.name.as_str(),
            "key": collision.key.as_str(),
            "current_operation_id": collision.current_operation_id.as_str(),
            "incoming_operation_id": collision.incoming_operation_id.as_str(),
            "base_version_seq": collision.base_version_seq,
            "current_version_seq": collision.current_version_seq,
            "resolution": resolution,
            "resolved_by": resolved_by,
        });
        if let Some(agreement) = agreement {
            payload_json["agreement"] = agreement;
        }
        let input = LedgerOperationInput {
            operation_id: format!(
                "hop_{}",
                valhall_config::ids::generate_entropy_prefixed_ulid()
            ),
            cluster_id: collision.cluster_id.clone(),
            node_id: identity.node_id.clone(),
            node_seq: self.node_high_watermark(identity.node_id.as_str())? + 1,
            op_type: "collision.resolved".to_string(),
            payload_json,
            created_at: Utc::now(),
        };
        let envelope = self.sign_next(identity, input)?;
        self.append_signed(&envelope)
    }

    pub fn declare_hard_fork(
        &self,
        identity: &NodeIdentity,
        cluster_id: &str,
        parent_checkpoint_id: Option<&str>,
        declared_by: &str,
        reason: &str,
    ) -> Result<LedgerForkRecord> {
        validate_non_empty("cluster_id", cluster_id)?;
        validate_non_empty("declared_by", declared_by)?;
        validate_non_empty("reason", reason)?;
        let parent_checkpoint = match parent_checkpoint_id {
            Some(checkpoint_id) if !checkpoint_id.trim().is_empty() => {
                self.get_checkpoint(checkpoint_id)?.ok_or_else(|| {
                    HemError::InvalidArgument(format!("checkpoint not found: {checkpoint_id}"))
                })?
            }
            _ => self.latest_checkpoint(cluster_id)?.ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "hard fork requires a parent checkpoint for cluster {cluster_id}"
                ))
            })?,
        };
        parent_checkpoint.verify()?;
        if parent_checkpoint.body.cluster_id != cluster_id {
            return Err(HemError::InvalidArgument(format!(
                "parent checkpoint cluster_id {} does not match requested cluster_id {}",
                parent_checkpoint.body.cluster_id, cluster_id
            )));
        }

        let latest_position = self.latest_position()?;
        let latest_hash = self.latest_body_hash()?.unwrap_or_default();
        let epoch = self.next_fork_epoch(cluster_id)?;
        let fork_id = format!(
            "hfork_{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        );
        let operation_id = format!(
            "hop_{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        );
        let created_at = Utc::now();
        let input = LedgerOperationInput {
            operation_id: operation_id.clone(),
            cluster_id: cluster_id.to_string(),
            node_id: identity.node_id.clone(),
            node_seq: self.node_high_watermark(identity.node_id.as_str())? + 1,
            op_type: "ledger.hard_fork".to_string(),
            payload_json: json!({
                "fork_id": fork_id.as_str(),
                "epoch": epoch,
                "parent_checkpoint_id": parent_checkpoint.body.checkpoint_id.as_str(),
                "parent_checkpoint_body_hash_b64": parent_checkpoint.body_hash_b64.as_str(),
                "parent_position": parent_checkpoint.body.to_position,
                "previous_head_position": latest_position,
                "previous_head_body_hash_b64": latest_hash.as_str(),
                "declared_by": declared_by,
                "reason": reason,
            }),
            created_at,
        };
        let envelope = self.sign_next(identity, input)?;
        self.append_signed(&envelope)?;

        let record = LedgerForkRecord {
            fork_id,
            cluster_id: cluster_id.to_string(),
            epoch,
            parent_checkpoint_id: parent_checkpoint.body.checkpoint_id,
            parent_checkpoint_body_hash_b64: parent_checkpoint.body_hash_b64,
            parent_position: parent_checkpoint.body.to_position,
            declared_by: declared_by.to_string(),
            reason: reason.to_string(),
            operation_id,
            created_at,
        };
        self.insert_fork(&record)?;
        Ok(record)
    }

    pub fn list_forks(&self) -> Result<Vec<LedgerForkRecord>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT fork_id, cluster_id, epoch, parent_checkpoint_id,
                    parent_checkpoint_body_hash_b64, parent_position, declared_by, reason,
                    operation_id, created_at
             FROM ledger_forks
             ORDER BY epoch ASC, created_at ASC",
        )?;
        let rows = stmt.query_map([], fork_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn get_fork(&self, fork_id: &str) -> Result<Option<LedgerForkRecord>> {
        validate_non_empty("fork_id", fork_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT fork_id, cluster_id, epoch, parent_checkpoint_id,
                    parent_checkpoint_body_hash_b64, parent_position, declared_by, reason,
                    operation_id, created_at
             FROM ledger_forks
             WHERE fork_id = ?1",
            params![fork_id],
            fork_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn list_fork_replays(&self) -> Result<Vec<LedgerForkReplayRecord>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT replay_id, fork_id, cluster_id, parent_checkpoint_id, parent_position,
                    fork_position, replay_policy, operation_id, replayed_by, backup_reference,
                    created_at
             FROM ledger_fork_replays
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], fork_replay_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn execute_hard_fork_replay(
        &self,
        identity: &NodeIdentity,
        input: LedgerForkReplayInput<'_>,
    ) -> Result<LedgerForkReplayReport> {
        validate_non_empty("fork_id", input.fork_id)?;
        validate_non_empty("actor", input.actor)?;
        validate_non_empty("backup_reference", input.backup_reference)?;

        let fork = self.get_fork(input.fork_id)?.ok_or_else(|| {
            HemError::InvalidArgument(format!("fork not found: {}", input.fork_id))
        })?;
        let checkpoint = self
            .get_checkpoint(fork.parent_checkpoint_id.as_str())?
            .ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "parent checkpoint not found: {}",
                    fork.parent_checkpoint_id
                ))
            })?;
        checkpoint.verify()?;
        if checkpoint.body_hash_b64 != fork.parent_checkpoint_body_hash_b64 {
            return Err(HemError::InvalidArgument(format!(
                "parent checkpoint hash mismatch for fork {}",
                fork.fork_id
            )));
        }
        let fork_operation = self
            .get_by_operation_id(fork.operation_id.as_str())?
            .ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "fork operation not found: {}",
                    fork.operation_id
                ))
            })?;
        let replay_policy = "checkpoint_then_after_fork";
        let replay_id = format!(
            "hrpl_{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        );
        let operation_id = format!(
            "hop_{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        );
        let created_at = Utc::now();
        let operation_input = LedgerOperationInput {
            operation_id: operation_id.clone(),
            cluster_id: fork.cluster_id.clone(),
            node_id: identity.node_id.clone(),
            node_seq: self.node_high_watermark(identity.node_id.as_str())? + 1,
            op_type: "ledger.replay".to_string(),
            payload_json: json!({
                "replay_id": replay_id.as_str(),
                "fork_id": fork.fork_id.as_str(),
                "parent_checkpoint_id": fork.parent_checkpoint_id.as_str(),
                "parent_position": fork.parent_position,
                "fork_position": fork_operation.position,
                "replay_policy": replay_policy,
                "backup_reference": input.backup_reference,
                "replayed_by": input.actor,
            }),
            created_at,
        };
        let envelope = self.sign_next(identity, operation_input)?;
        let replay_operation = self.append_signed(&envelope)?;

        let record = LedgerForkReplayRecord {
            replay_id: replay_id.clone(),
            fork_id: fork.fork_id.clone(),
            cluster_id: fork.cluster_id.clone(),
            parent_checkpoint_id: fork.parent_checkpoint_id.clone(),
            parent_position: fork.parent_position,
            fork_position: fork_operation.position,
            replay_policy: replay_policy.to_string(),
            operation_id: operation_id.clone(),
            replayed_by: input.actor.to_string(),
            backup_reference: input.backup_reference.to_string(),
            created_at,
        };
        self.insert_fork_replay(&record)?;

        let rebuild = self.rebuild_materializers_for_fork(
            fork.parent_position,
            fork_operation.position,
            replay_operation.position,
        )?;
        Ok(LedgerForkReplayReport {
            replay_id,
            fork_id: fork.fork_id,
            parent_position: fork.parent_position,
            fork_position: fork_operation.position,
            latest_position: replay_operation.position,
            replay_operation_id: operation_id,
            operations_replayed: rebuild.operations_replayed,
            operations_skipped: rebuild.operations_skipped,
            materializer_records_rebuilt: rebuild.materializer_records_rebuilt,
        })
    }

    pub fn get_peer_cursor(&self, peer_node_id: &str) -> Result<Option<LedgerPeerCursor>> {
        validate_non_empty("peer_node_id", peer_node_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT peer_node_id, last_position, last_body_hash_b64, updated_at
             FROM ledger_peer_cursors
             WHERE peer_node_id = ?1",
            params![peer_node_id],
            peer_cursor_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    pub fn list_peer_cursors(&self) -> Result<Vec<LedgerPeerCursor>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT peer_node_id, last_position, last_body_hash_b64, updated_at
             FROM ledger_peer_cursors
             ORDER BY peer_node_id ASC",
        )?;
        let rows = stmt.query_map([], peer_cursor_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(HemError::from)
    }

    pub fn record_peer_cursor(
        &self,
        peer_node_id: &str,
        position: i64,
        body_hash_b64: &str,
    ) -> Result<LedgerPeerCursor> {
        validate_non_empty("peer_node_id", peer_node_id)?;
        if position < 0 {
            return Err(HemError::InvalidArgument(
                "peer cursor position must not be negative".to_string(),
            ));
        }
        if position > 0 {
            validate_hash("body_hash_b64", body_hash_b64)?;
            let operation = self.get_by_position(position)?.ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "cannot record peer cursor at missing position {position}"
                ))
            })?;
            if operation.body_hash_b64 != body_hash_b64 {
                return Err(HemError::InvalidArgument(format!(
                    "peer cursor body hash mismatch at position {position}"
                )));
            }
        }
        let cursor = LedgerPeerCursor {
            peer_node_id: peer_node_id.to_string(),
            last_position: position,
            last_body_hash_b64: body_hash_b64.to_string(),
            updated_at: Utc::now(),
        };
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_peer_cursors (
                peer_node_id,
                last_position,
                last_body_hash_b64,
                updated_at
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_node_id) DO UPDATE SET
                last_position = excluded.last_position,
                last_body_hash_b64 = excluded.last_body_hash_b64,
                updated_at = excluded.updated_at",
            params![
                cursor.peer_node_id,
                cursor.last_position,
                cursor.last_body_hash_b64,
                cursor.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(cursor)
    }

    pub fn node_high_watermark(&self, node_id: &str) -> Result<i64> {
        validate_non_empty("node_id", node_id)?;
        let conn = self.connect()?;
        Ok(conn.query_row(
            "SELECT COALESCE(MAX(node_seq), 0) FROM ledger_operations WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )?)
    }

    fn get_by_position(&self, position: i64) -> Result<Option<LedgerOperation>> {
        let conn = self.connect()?;
        query_optional_operation(
            &conn,
            "SELECT position, operation_id, cluster_id, node_id, node_seq, op_type, payload_json, created_at,
                    prev_hash_b64, body_hash_b64, signing_public_key_b64, signature_b64
             FROM ledger_operations WHERE position = ?1",
            params![position],
        )
    }

    fn operation_hashes_up_to(&self, to_position: i64) -> Result<Vec<[u8; 32]>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT body_hash_b64
             FROM ledger_operations
             WHERE position <= ?1
             ORDER BY position ASC",
        )?;
        let rows = stmt.query_map(params![to_position], |row| row.get::<_, String>(0))?;
        let hashes = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        hashes
            .iter()
            .map(|hash| decode_base64_exact::<32>("body_hash_b64", hash.as_str()))
            .collect()
    }

    fn insert_checkpoint(&self, checkpoint: &LedgerCheckpoint) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_checkpoints (
                checkpoint_id,
                cluster_id,
                to_position,
                operation_count,
                merkle_root_b64,
                created_at,
                body_hash_b64,
                signer_node_id,
                signing_public_key_b64,
                signature_b64
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                checkpoint.body.checkpoint_id,
                checkpoint.body.cluster_id,
                checkpoint.body.to_position,
                checkpoint.body.operation_count,
                checkpoint.body.merkle_root_b64,
                checkpoint.body.created_at.to_rfc3339(),
                checkpoint.body_hash_b64,
                checkpoint.signer_node_id,
                checkpoint.signing_public_key_b64,
                checkpoint.signature_b64,
            ],
        )?;
        Ok(())
    }

    fn insert_checkpoint_cosignature(
        &self,
        cosignature: &LedgerCheckpointCosignature,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_checkpoint_cosignatures (
                checkpoint_id,
                checkpoint_body_hash_b64,
                signer_node_id,
                signed_at,
                signing_public_key_b64,
                signature_b64
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                cosignature.body.checkpoint_id,
                cosignature.body.checkpoint_body_hash_b64,
                cosignature.body.signer_node_id,
                cosignature.body.signed_at.to_rfc3339(),
                cosignature.signing_public_key_b64,
                cosignature.signature_b64,
            ],
        )?;
        Ok(())
    }

    fn get_checkpoint_cosignature(
        &self,
        checkpoint_id: &str,
        signer_node_id: &str,
    ) -> Result<Option<LedgerCheckpointCosignature>> {
        validate_non_empty("checkpoint_id", checkpoint_id)?;
        validate_non_empty("signer_node_id", signer_node_id)?;
        let conn = self.connect()?;
        conn.query_row(
            "SELECT checkpoint_id, checkpoint_body_hash_b64, signer_node_id, signed_at,
                    signing_public_key_b64, signature_b64
             FROM ledger_checkpoint_cosignatures
             WHERE checkpoint_id = ?1 AND signer_node_id = ?2",
            params![checkpoint_id, signer_node_id],
            checkpoint_cosignature_from_row,
        )
        .optional()
        .map_err(HemError::from)
    }

    fn validate_checkpoint_matches_local(&self, checkpoint: &LedgerCheckpoint) -> Result<()> {
        checkpoint.verify()?;
        let latest_position = self.latest_position()?;
        if checkpoint.body.to_position > latest_position {
            return Err(HemError::InvalidArgument(format!(
                "checkpoint position {} is ahead of local head {}",
                checkpoint.body.to_position, latest_position
            )));
        }
        let leaf_hashes = self.operation_hashes_up_to(checkpoint.body.to_position)?;
        let actual_count = i64::try_from(leaf_hashes.len()).map_err(|_| {
            HemError::InvalidArgument("checkpoint operation count overflow".to_string())
        })?;
        if actual_count != checkpoint.body.operation_count {
            return Err(HemError::InvalidArgument(format!(
                "checkpoint operation count mismatch expected={} actual={actual_count}",
                checkpoint.body.operation_count
            )));
        }
        if leaf_hashes.is_empty() {
            return Err(HemError::InvalidArgument(
                "checkpoint has no local ledger operations".to_string(),
            ));
        }
        let merkle_root_b64 = STANDARD_NO_PAD.encode(merkle_root(leaf_hashes.as_slice())?);
        if merkle_root_b64 != checkpoint.body.merkle_root_b64 {
            return Err(HemError::Crypto(format!(
                "checkpoint merkle root mismatch expected={} actual={}",
                checkpoint.body.merkle_root_b64, merkle_root_b64
            )));
        }
        Ok(())
    }

    fn next_fork_epoch(&self, cluster_id: &str) -> Result<i64> {
        let conn = self.connect()?;
        Ok(conn.query_row(
            "SELECT COALESCE(MAX(epoch), 0) + 1 FROM ledger_forks WHERE cluster_id = ?1",
            params![cluster_id],
            |row| row.get(0),
        )?)
    }

    fn insert_fork(&self, record: &LedgerForkRecord) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_forks (
                fork_id,
                cluster_id,
                epoch,
                parent_checkpoint_id,
                parent_checkpoint_body_hash_b64,
                parent_position,
                declared_by,
                reason,
                operation_id,
                created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.fork_id,
                record.cluster_id,
                record.epoch,
                record.parent_checkpoint_id,
                record.parent_checkpoint_body_hash_b64,
                record.parent_position,
                record.declared_by,
                record.reason,
                record.operation_id,
                record.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn insert_fork_replay(&self, record: &LedgerForkReplayRecord) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_fork_replays (
                replay_id,
                fork_id,
                cluster_id,
                parent_checkpoint_id,
                parent_position,
                fork_position,
                replay_policy,
                operation_id,
                replayed_by,
                backup_reference,
                created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.replay_id,
                record.fork_id,
                record.cluster_id,
                record.parent_checkpoint_id,
                record.parent_position,
                record.fork_position,
                record.replay_policy,
                record.operation_id,
                record.replayed_by,
                record.backup_reference,
                record.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn rebuild_materializers_for_fork(
        &self,
        parent_position: i64,
        fork_position: i64,
        latest_position: i64,
    ) -> Result<LedgerForkReplayRebuild> {
        self.reset_materializers()?;

        let mut operations_replayed = 0_usize;
        let mut operations_skipped = 0_usize;
        let mut materializer_records_rebuilt = 0_usize;
        for operation in self.list_after(0, usize::MAX)? {
            if operation.position > parent_position && operation.position <= fork_position {
                operations_skipped += 1;
                continue;
            }
            operations_replayed += 1;
            materializer_records_rebuilt += self.apply_operation_to_materializers(&operation)?;
        }

        self.set_materializer_position("secret_metadata", latest_position)?;
        self.set_materializer_position("secret_value_versions", latest_position)?;
        Ok(LedgerForkReplayRebuild {
            operations_replayed,
            operations_skipped,
            materializer_records_rebuilt,
        })
    }

    fn reset_materializers(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            "
            DELETE FROM ledger_secret_metadata;
            DELETE FROM ledger_secret_value_versions;
            DELETE FROM ledger_collisions;
            DELETE FROM ledger_materializer_state;
            ",
        )?;
        Ok(())
    }

    fn apply_operation_to_materializers(&self, operation: &LedgerOperation) -> Result<usize> {
        let mut applied = 0_usize;
        if let Some(metadata) = metadata_from_operation(operation)? {
            self.upsert_secret_metadata(&metadata)?;
            applied += 1;
        }
        for version in value_versions_from_operation(operation)? {
            self.insert_secret_value_version(&version)?;
            applied += 1;
        }
        if let Some(resolution) = collision_resolution_from_operation(operation)? {
            self.apply_collision_resolution(&resolution)?;
            applied += 1;
        }
        Ok(applied)
    }

    fn inspect_fork_replay(
        &self,
        replay: &LedgerForkReplayRecord,
        report: &mut LedgerIntegrityReport,
    ) -> Result<()> {
        let reference = format!("fork_replay:{}", replay.replay_id);
        if self.get_fork(replay.fork_id.as_str())?.is_none() {
            report.issues.push(integrity_issue(
                "error",
                "fork_replay",
                reference.clone(),
                format!("fork not found: {}", replay.fork_id),
            ));
        }
        match self.get_checkpoint(replay.parent_checkpoint_id.as_str())? {
            Some(checkpoint) if checkpoint.body.to_position == replay.parent_position => {}
            Some(checkpoint) => report.issues.push(integrity_issue(
                "error",
                "fork_replay",
                reference.clone(),
                format!(
                    "parent checkpoint position mismatch expected={} actual={}",
                    replay.parent_position, checkpoint.body.to_position
                ),
            )),
            None => report.issues.push(integrity_issue(
                "error",
                "fork_replay",
                reference.clone(),
                format!(
                    "parent checkpoint not found: {}",
                    replay.parent_checkpoint_id
                ),
            )),
        }
        match self.get_by_operation_id(replay.operation_id.as_str())? {
            Some(operation) if operation.op_type == "ledger.replay" => {}
            Some(operation) => report.issues.push(integrity_issue(
                "error",
                "fork_replay",
                reference,
                format!("replay operation has unexpected type {}", operation.op_type),
            )),
            None => report.issues.push(integrity_issue(
                "error",
                "fork_replay",
                reference,
                format!("replay operation not found: {}", replay.operation_id),
            )),
        }
        Ok(())
    }

    fn materializer_position(&self, name: &str) -> Result<i64> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT last_position FROM ledger_materializer_state WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
        .optional()
        .map(|value| value.unwrap_or(0))
        .map_err(HemError::from)
    }

    fn set_materializer_position(&self, name: &str, position: i64) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_materializer_state (name, last_position, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET
                last_position = excluded.last_position,
                updated_at = excluded.updated_at",
            params![name, position, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    fn upsert_secret_metadata(&self, metadata: &LedgerSecretMetadata) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ledger_secret_metadata (
                cluster_id,
                scope,
                name,
                description,
                requires_approval,
                group_name,
                updated_at,
                updated_by,
                last_operation_id,
                last_position
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(cluster_id, scope, name) DO UPDATE SET
                description = excluded.description,
                requires_approval = excluded.requires_approval,
                group_name = excluded.group_name,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by,
                last_operation_id = excluded.last_operation_id,
                last_position = excluded.last_position",
            params![
                metadata.cluster_id,
                metadata.scope,
                metadata.name,
                metadata.description,
                metadata.requires_approval,
                metadata.group,
                metadata.updated_at.to_rfc3339(),
                metadata.updated_by,
                metadata.last_operation_id,
                metadata.last_position,
            ],
        )?;
        Ok(())
    }

    fn insert_secret_value_version(&self, version: &LedgerSecretValueVersion) -> Result<()> {
        let conn = self.connect()?;
        let (current_version_seq, current_operation_id) = conn
            .query_row(
                "SELECT version_seq, operation_id
                 FROM ledger_secret_value_versions
                 WHERE cluster_id = ?1 AND scope = ?2 AND name = ?3 AND key_name = ?4
                 ORDER BY version_seq DESC
                 LIMIT 1",
                params![version.cluster_id, version.scope, version.name, version.key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .unwrap_or((0, String::new()));
        if version.base_version_seq != current_version_seq {
            self.insert_collision(
                version,
                current_operation_id.as_str(),
                version.base_version_seq,
                current_version_seq,
            )?;
            return Ok(());
        }
        let version_seq = conn.query_row(
            "SELECT COALESCE(MAX(version_seq), 0) + 1
             FROM ledger_secret_value_versions
             WHERE cluster_id = ?1 AND scope = ?2 AND name = ?3 AND key_name = ?4",
            params![version.cluster_id, version.scope, version.name, version.key],
            |row| row.get::<_, i64>(0),
        )?;
        conn.execute(
            "INSERT INTO ledger_secret_value_versions (
                cluster_id,
                scope,
                name,
                key_name,
                version_seq,
                encrypted_value_json,
                created_at,
                created_by,
                operation_id,
                position,
                base_version_seq
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                version.cluster_id,
                version.scope,
                version.name,
                version.key,
                version_seq,
                serde_json::to_string(&version.encrypted_value_json)?,
                version.created_at.to_rfc3339(),
                version.created_by,
                version.operation_id,
                version.position,
                version.base_version_seq,
            ],
        )?;
        Ok(())
    }

    fn insert_collision(
        &self,
        version: &LedgerSecretValueVersion,
        current_operation_id: &str,
        base_version_seq: i64,
        current_version_seq: i64,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR IGNORE INTO ledger_collisions (
                collision_id,
                cluster_id,
                scope,
                name,
                key_name,
                current_operation_id,
                incoming_operation_id,
                base_version_seq,
                current_version_seq,
                state,
                created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', ?10)",
            params![
                deterministic_collision_id(
                    version.cluster_id.as_str(),
                    version.scope.as_str(),
                    version.name.as_str(),
                    version.key.as_str(),
                    current_operation_id,
                    version.operation_id.as_str(),
                    base_version_seq,
                    current_version_seq,
                ),
                version.cluster_id,
                version.scope,
                version.name,
                version.key,
                current_operation_id,
                version.operation_id,
                base_version_seq,
                current_version_seq,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn apply_collision_resolution(&self, resolution: &LedgerCollisionResolution) -> Result<()> {
        let collision = self
            .get_collision(resolution.collision_id.as_str())?
            .ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "open collision not found: {}",
                    resolution.collision_id
                ))
            })?;
        if collision.state != "open" {
            return Err(HemError::InvalidArgument(format!(
                "open collision not found: {}",
                resolution.collision_id
            )));
        }
        let incoming_winner = if resolution_accepts_incoming(
            resolution.resolution.as_str(),
            collision.incoming_operation_id.as_str(),
        ) {
            Some(self.resolved_incoming_value_version(&collision)?)
        } else {
            None
        };
        let conn = self.connect()?;
        let updated = conn.execute(
            "UPDATE ledger_collisions
             SET state = 'resolved',
                 resolution = ?2,
                 resolved_by = ?3,
                 resolution_operation_id = ?4,
                 resolved_at = ?5
             WHERE collision_id = ?1 AND state = 'open'",
            params![
                resolution.collision_id,
                resolution.resolution,
                resolution.resolved_by,
                resolution.operation_id,
                resolution.resolved_at.to_rfc3339(),
            ],
        )?;
        if updated == 0 {
            return Err(HemError::InvalidArgument(format!(
                "open collision not found: {}",
                resolution.collision_id
            )));
        }
        drop(conn);
        if let Some(incoming_winner) = incoming_winner {
            self.insert_resolved_secret_value_version(&incoming_winner)?;
        }
        Ok(())
    }

    fn resolved_incoming_value_version(
        &self,
        collision: &LedgerCollision,
    ) -> Result<LedgerSecretValueVersion> {
        let incoming = self
            .get_by_operation_id(collision.incoming_operation_id.as_str())?
            .ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "collision incoming operation not found: {}",
                    collision.incoming_operation_id
                ))
            })?;
        let mut version = value_versions_from_operation(&incoming)?
            .into_iter()
            .find(|version| {
                version.cluster_id == collision.cluster_id
                    && version.scope == collision.scope
                    && version.name == collision.name
                    && version.key == collision.key
            })
            .ok_or_else(|| {
                HemError::InvalidArgument(format!(
                    "collision incoming operation {} does not contain value for {}/{}/{}",
                    collision.incoming_operation_id, collision.scope, collision.name, collision.key
                ))
            })?;
        version.base_version_seq = collision.current_version_seq;
        Ok(version)
    }

    fn insert_resolved_secret_value_version(
        &self,
        version: &LedgerSecretValueVersion,
    ) -> Result<()> {
        let conn = self.connect()?;
        let already_inserted = conn
            .query_row(
                "SELECT 1
                 FROM ledger_secret_value_versions
                 WHERE operation_id = ?1 AND key_name = ?2",
                params![version.operation_id, version.key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if already_inserted {
            return Ok(());
        }
        let version_seq = conn.query_row(
            "SELECT COALESCE(MAX(version_seq), 0) + 1
             FROM ledger_secret_value_versions
             WHERE cluster_id = ?1 AND scope = ?2 AND name = ?3 AND key_name = ?4",
            params![version.cluster_id, version.scope, version.name, version.key],
            |row| row.get::<_, i64>(0),
        )?;
        conn.execute(
            "INSERT INTO ledger_secret_value_versions (
                cluster_id,
                scope,
                name,
                key_name,
                version_seq,
                encrypted_value_json,
                created_at,
                created_by,
                operation_id,
                position,
                base_version_seq
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                version.cluster_id,
                version.scope,
                version.name,
                version.key,
                version_seq,
                serde_json::to_string(&version.encrypted_value_json)?,
                version.created_at.to_rfc3339(),
                version.created_by,
                version.operation_id,
                version.position,
                version.base_version_seq,
            ],
        )?;
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        open_connection(self.path.as_path())
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(BUSY_TIMEOUT_SECONDS))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(conn)
}

impl LedgerOperationInput {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty("operation_id", self.operation_id.as_str())?;
        validate_non_empty("cluster_id", self.cluster_id.as_str())?;
        validate_non_empty("node_id", self.node_id.as_str())?;
        validate_non_empty("op_type", self.op_type.as_str())?;
        if self.node_seq < 1 {
            return Err(HemError::InvalidArgument(
                "ledger node_seq must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

impl LedgerOperationBody {
    fn from_input(input: LedgerOperationInput, prev_hash_b64: String) -> Result<Self> {
        input.validate()?;
        validate_hash_or_empty("prev_hash_b64", prev_hash_b64.as_str())?;
        Ok(Self {
            operation_id: input.operation_id,
            cluster_id: input.cluster_id,
            node_id: input.node_id,
            node_seq: input.node_seq,
            op_type: input.op_type,
            payload_json: input.payload_json,
            created_at: input.created_at,
            prev_hash_b64,
        })
    }

    fn validate(&self) -> Result<()> {
        validate_non_empty("operation_id", self.operation_id.as_str())?;
        validate_non_empty("cluster_id", self.cluster_id.as_str())?;
        validate_non_empty("node_id", self.node_id.as_str())?;
        validate_non_empty("op_type", self.op_type.as_str())?;
        validate_hash_or_empty("prev_hash_b64", self.prev_hash_b64.as_str())?;
        if self.node_seq < 1 {
            return Err(HemError::InvalidArgument(
                "ledger node_seq must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

impl LedgerOperationEnvelope {
    fn sign(body: LedgerOperationBody, identity: &NodeIdentity) -> Result<Self> {
        body.validate()?;
        let public_key = decode_base64_exact::<32>(
            "signing_public_key_b64",
            identity.signing_public_key_b64.as_str(),
        )?;
        let private_key = decode_base64_exact::<32>(
            "signing_private_key_b64",
            identity.signing_private_key_b64.as_str(),
        )?;
        let signing_key = SigningKey::from_bytes(&private_key);
        if signing_key.verifying_key().to_bytes() != public_key {
            return Err(HemError::Crypto(
                "node identity private key does not match public key".to_string(),
            ));
        }

        let hash = body_hash_bytes(&body)?;
        let signature: Signature = signing_key.sign(&hash);
        Ok(Self {
            body,
            body_hash_b64: STANDARD_NO_PAD.encode(hash),
            signing_public_key_b64: identity.signing_public_key_b64.clone(),
            signature_b64: STANDARD_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        let expected_hash = body_hash_bytes(&self.body)?;
        let expected_hash_b64 = STANDARD_NO_PAD.encode(expected_hash);
        if self.body_hash_b64 != expected_hash_b64 {
            return Err(HemError::Crypto(format!(
                "ledger envelope hash mismatch expected={} actual={}",
                expected_hash_b64, self.body_hash_b64
            )));
        }

        let public_key = decode_base64_exact::<32>(
            "signing_public_key_b64",
            self.signing_public_key_b64.as_str(),
        )?;
        let signature = decode_base64_exact::<64>("signature_b64", self.signature_b64.as_str())?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|err| HemError::Crypto(format!("invalid ledger public key: {err}")))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|err| HemError::Crypto(format!("invalid ledger signature: {err}")))?;
        verifying_key
            .verify(&expected_hash, &signature)
            .map_err(|err| HemError::Crypto(format!("ledger signature invalid: {err}")))?;
        Ok(())
    }
}

impl LedgerCheckpoint {
    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        validate_non_empty("signer_node_id", self.signer_node_id.as_str())?;
        let expected_hash = canonical_hash_bytes(&self.body)?;
        let expected_hash_b64 = STANDARD_NO_PAD.encode(expected_hash);
        if self.body_hash_b64 != expected_hash_b64 {
            return Err(HemError::Crypto(format!(
                "ledger checkpoint hash mismatch expected={} actual={}",
                expected_hash_b64, self.body_hash_b64
            )));
        }
        verify_hash_signature(
            self.signing_public_key_b64.as_str(),
            self.signature_b64.as_str(),
            &expected_hash,
        )
    }
}

impl LedgerCheckpointBody {
    fn validate(&self) -> Result<()> {
        validate_non_empty("checkpoint_id", self.checkpoint_id.as_str())?;
        validate_non_empty("cluster_id", self.cluster_id.as_str())?;
        validate_hash("merkle_root_b64", self.merkle_root_b64.as_str())?;
        if self.to_position < 1 {
            return Err(HemError::InvalidArgument(
                "checkpoint to_position must be at least 1".to_string(),
            ));
        }
        if self.operation_count < 1 {
            return Err(HemError::InvalidArgument(
                "checkpoint operation_count must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

impl LedgerCheckpointCosignature {
    pub fn verify(&self, checkpoint: &LedgerCheckpoint) -> Result<()> {
        self.body.validate()?;
        if self.body.checkpoint_id != checkpoint.body.checkpoint_id {
            return Err(HemError::Crypto(format!(
                "checkpoint cosignature id mismatch expected={} actual={}",
                checkpoint.body.checkpoint_id, self.body.checkpoint_id
            )));
        }
        if self.body.checkpoint_body_hash_b64 != checkpoint.body_hash_b64 {
            return Err(HemError::Crypto(format!(
                "checkpoint cosignature hash mismatch expected={} actual={}",
                checkpoint.body_hash_b64, self.body.checkpoint_body_hash_b64
            )));
        }
        let body_hash = canonical_hash_bytes(&self.body)?;
        verify_hash_signature(
            self.signing_public_key_b64.as_str(),
            self.signature_b64.as_str(),
            &body_hash,
        )
    }
}

impl LedgerCheckpointCosignatureBody {
    fn validate(&self) -> Result<()> {
        validate_non_empty("checkpoint_id", self.checkpoint_id.as_str())?;
        validate_hash(
            "checkpoint_body_hash_b64",
            self.checkpoint_body_hash_b64.as_str(),
        )?;
        validate_non_empty("signer_node_id", self.signer_node_id.as_str())
    }
}

fn migrate(conn: &Connection) -> Result<()> {
    // Setting user_version is a write transaction, so only run the idempotent schema batch
    // when the file is behind. A current ledger must open without writing.
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version >= LEDGER_SCHEMA_VERSION {
        return Ok(());
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS ledger_operations (
            position INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL UNIQUE,
            cluster_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            node_seq INTEGER NOT NULL,
            op_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            prev_hash_b64 TEXT NOT NULL DEFAULT '',
            body_hash_b64 TEXT NOT NULL DEFAULT '',
            signing_public_key_b64 TEXT NOT NULL DEFAULT '',
            signature_b64 TEXT NOT NULL DEFAULT '',
            UNIQUE(node_id, node_seq)
        );

        CREATE TABLE IF NOT EXISTS ledger_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            to_position INTEGER NOT NULL,
            operation_count INTEGER NOT NULL,
            merkle_root_b64 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            body_hash_b64 TEXT NOT NULL UNIQUE,
            signer_node_id TEXT NOT NULL,
            signing_public_key_b64 TEXT NOT NULL,
            signature_b64 TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ledger_checkpoint_cosignatures (
            checkpoint_id TEXT NOT NULL,
            checkpoint_body_hash_b64 TEXT NOT NULL,
            signer_node_id TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            signing_public_key_b64 TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            PRIMARY KEY (checkpoint_id, signer_node_id),
            FOREIGN KEY (checkpoint_id) REFERENCES ledger_checkpoints(checkpoint_id)
        );

        CREATE TABLE IF NOT EXISTS ledger_secret_metadata (
            cluster_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            requires_approval INTEGER NOT NULL,
            group_name TEXT,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            last_operation_id TEXT NOT NULL,
            last_position INTEGER NOT NULL,
            PRIMARY KEY (cluster_id, scope, name)
        );

        CREATE TABLE IF NOT EXISTS ledger_materializer_state (
            name TEXT PRIMARY KEY,
            last_position INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ledger_peer_cursors (
            peer_node_id TEXT PRIMARY KEY,
            last_position INTEGER NOT NULL,
            last_body_hash_b64 TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ledger_secret_value_versions (
            cluster_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            name TEXT NOT NULL,
            key_name TEXT NOT NULL,
            version_seq INTEGER NOT NULL,
            encrypted_value_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            base_version_seq INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (cluster_id, scope, name, key_name, version_seq),
            UNIQUE (operation_id, key_name)
        );

        CREATE TABLE IF NOT EXISTS ledger_collisions (
            collision_id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            name TEXT NOT NULL,
            key_name TEXT NOT NULL,
            current_operation_id TEXT NOT NULL,
            incoming_operation_id TEXT NOT NULL,
            base_version_seq INTEGER NOT NULL,
            current_version_seq INTEGER NOT NULL,
            state TEXT NOT NULL,
            resolution TEXT,
            resolved_by TEXT,
            resolution_operation_id TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            UNIQUE (incoming_operation_id, key_name)
        );

        CREATE TABLE IF NOT EXISTS ledger_forks (
            fork_id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            parent_checkpoint_id TEXT NOT NULL,
            parent_checkpoint_body_hash_b64 TEXT NOT NULL,
            parent_position INTEGER NOT NULL,
            declared_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            operation_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            UNIQUE (cluster_id, epoch),
            FOREIGN KEY (operation_id) REFERENCES ledger_operations(operation_id)
        );

        CREATE TABLE IF NOT EXISTS ledger_fork_replays (
            replay_id TEXT PRIMARY KEY,
            fork_id TEXT NOT NULL,
            cluster_id TEXT NOT NULL,
            parent_checkpoint_id TEXT NOT NULL,
            parent_position INTEGER NOT NULL,
            fork_position INTEGER NOT NULL,
            replay_policy TEXT NOT NULL,
            operation_id TEXT NOT NULL UNIQUE,
            replayed_by TEXT NOT NULL,
            backup_reference TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (fork_id) REFERENCES ledger_forks(fork_id),
            FOREIGN KEY (operation_id) REFERENCES ledger_operations(operation_id)
        );
        ",
    )?;
    ensure_column(
        conn,
        "ledger_operations",
        "prev_hash_b64",
        "ALTER TABLE ledger_operations ADD COLUMN prev_hash_b64 TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "ledger_operations",
        "body_hash_b64",
        "ALTER TABLE ledger_operations ADD COLUMN body_hash_b64 TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "ledger_operations",
        "signing_public_key_b64",
        "ALTER TABLE ledger_operations ADD COLUMN signing_public_key_b64 TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "ledger_operations",
        "signature_b64",
        "ALTER TABLE ledger_operations ADD COLUMN signature_b64 TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "ledger_secret_value_versions",
        "base_version_seq",
        "ALTER TABLE ledger_secret_value_versions ADD COLUMN base_version_seq INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "ledger_collisions",
        "resolution_operation_id",
        "ALTER TABLE ledger_collisions ADD COLUMN resolution_operation_id TEXT",
    )?;
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_ledger_operations_cluster_position
            ON ledger_operations(cluster_id, position);
        CREATE INDEX IF NOT EXISTS idx_ledger_operations_node_seq
            ON ledger_operations(node_id, node_seq);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_operations_body_hash
            ON ledger_operations(body_hash_b64)
            WHERE body_hash_b64 != '';
        CREATE INDEX IF NOT EXISTS idx_ledger_checkpoints_cluster_position
            ON ledger_checkpoints(cluster_id, to_position);
        CREATE INDEX IF NOT EXISTS idx_ledger_checkpoint_cosignatures_checkpoint
            ON ledger_checkpoint_cosignatures(checkpoint_id);
        CREATE INDEX IF NOT EXISTS idx_ledger_secret_metadata_cluster
            ON ledger_secret_metadata(cluster_id, scope, name);
        CREATE INDEX IF NOT EXISTS idx_ledger_secret_value_versions_secret
            ON ledger_secret_value_versions(cluster_id, scope, name, key_name, version_seq);
        CREATE INDEX IF NOT EXISTS idx_ledger_collisions_open
            ON ledger_collisions(cluster_id, state, created_at);
        CREATE INDEX IF NOT EXISTS idx_ledger_forks_cluster_epoch
            ON ledger_forks(cluster_id, epoch);
        CREATE INDEX IF NOT EXISTS idx_ledger_fork_replays_fork
            ON ledger_fork_replays(fork_id, created_at);
        ",
    )?;
    conn.pragma_update(None, "user_version", LEDGER_SCHEMA_VERSION)?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, sql: &str) -> Result<()> {
    if table_columns(conn, table)?.contains(column) {
        return Ok(());
    }
    conn.execute(sql, [])?;
    Ok(())
}

fn table_columns(conn: &Connection, table: &str) -> Result<BTreeSet<String>> {
    let mut stmt = conn.prepare(format!("PRAGMA table_info({table})").as_str())?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect::<std::result::Result<BTreeSet<_>, _>>()
        .map_err(HemError::from)
}

fn query_optional_operation<P>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<Option<LedgerOperation>>
where
    P: rusqlite::Params,
{
    conn.query_row(sql, params, operation_from_row)
        .optional()
        .map_err(HemError::from)
}

fn operation_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerOperation> {
    let payload: String = row.get(6)?;
    let created_at: String = row.get(7)?;
    Ok(LedgerOperation {
        position: row.get(0)?,
        operation_id: row.get(1)?,
        cluster_id: row.get(2)?,
        node_id: row.get(3)?,
        node_seq: row.get(4)?,
        op_type: row.get(5)?,
        payload_json: serde_json::from_str(payload.as_str()).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(err))
        })?,
        created_at: DateTime::parse_from_rfc3339(created_at.as_str())
            .map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?
            .with_timezone(&Utc),
        prev_hash_b64: row.get(8)?,
        body_hash_b64: row.get(9)?,
        signing_public_key_b64: row.get(10)?,
        signature_b64: row.get(11)?,
    })
}

fn checkpoint_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerCheckpoint> {
    let created_at: String = row.get(5)?;
    Ok(LedgerCheckpoint {
        body: LedgerCheckpointBody {
            checkpoint_id: row.get(0)?,
            cluster_id: row.get(1)?,
            to_position: row.get(2)?,
            operation_count: row.get(3)?,
            merkle_root_b64: row.get(4)?,
            created_at: parse_sqlite_datetime(5, created_at.as_str())?,
        },
        body_hash_b64: row.get(6)?,
        signer_node_id: row.get(7)?,
        signing_public_key_b64: row.get(8)?,
        signature_b64: row.get(9)?,
    })
}

fn checkpoint_cosignature_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerCheckpointCosignature> {
    let signed_at: String = row.get(3)?;
    Ok(LedgerCheckpointCosignature {
        body: LedgerCheckpointCosignatureBody {
            checkpoint_id: row.get(0)?,
            checkpoint_body_hash_b64: row.get(1)?,
            signer_node_id: row.get(2)?,
            signed_at: parse_sqlite_datetime(3, signed_at.as_str())?,
        },
        signing_public_key_b64: row.get(4)?,
        signature_b64: row.get(5)?,
    })
}

fn secret_metadata_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerSecretMetadata> {
    let updated_at: String = row.get(6)?;
    Ok(LedgerSecretMetadata {
        cluster_id: row.get(0)?,
        scope: row.get(1)?,
        name: row.get(2)?,
        description: row.get(3)?,
        requires_approval: row.get::<_, bool>(4)?,
        group: row.get(5)?,
        updated_at: parse_sqlite_datetime(6, updated_at.as_str())?,
        updated_by: row.get(7)?,
        last_operation_id: row.get(8)?,
        last_position: row.get(9)?,
    })
}

fn peer_cursor_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerPeerCursor> {
    let updated_at: String = row.get(3)?;
    Ok(LedgerPeerCursor {
        peer_node_id: row.get(0)?,
        last_position: row.get(1)?,
        last_body_hash_b64: row.get(2)?,
        updated_at: parse_sqlite_datetime(3, updated_at.as_str())?,
    })
}

fn secret_value_version_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerSecretValueVersion> {
    let encrypted_value_json: String = row.get(5)?;
    let created_at: String = row.get(6)?;
    Ok(LedgerSecretValueVersion {
        cluster_id: row.get(0)?,
        scope: row.get(1)?,
        name: row.get(2)?,
        key: row.get(3)?,
        version_seq: row.get(4)?,
        encrypted_value_json: serde_json::from_str(encrypted_value_json.as_str()).map_err(
            |err| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            },
        )?,
        created_at: parse_sqlite_datetime(6, created_at.as_str())?,
        created_by: row.get(7)?,
        operation_id: row.get(8)?,
        position: row.get(9)?,
        base_version_seq: row.get(10)?,
    })
}

fn collision_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerCollision> {
    let created_at: String = row.get(13)?;
    let resolved_at: Option<String> = row.get(14)?;
    Ok(LedgerCollision {
        collision_id: row.get(0)?,
        cluster_id: row.get(1)?,
        scope: row.get(2)?,
        name: row.get(3)?,
        key: row.get(4)?,
        current_operation_id: row.get(5)?,
        incoming_operation_id: row.get(6)?,
        base_version_seq: row.get(7)?,
        current_version_seq: row.get(8)?,
        state: row.get(9)?,
        resolution: row.get(10)?,
        resolved_by: row.get(11)?,
        resolution_operation_id: row.get(12)?,
        created_at: parse_sqlite_datetime(13, created_at.as_str())?,
        resolved_at: resolved_at
            .as_deref()
            .map(|value| parse_sqlite_datetime(14, value))
            .transpose()?,
    })
}

fn fork_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerForkRecord> {
    let created_at: String = row.get(9)?;
    Ok(LedgerForkRecord {
        fork_id: row.get(0)?,
        cluster_id: row.get(1)?,
        epoch: row.get(2)?,
        parent_checkpoint_id: row.get(3)?,
        parent_checkpoint_body_hash_b64: row.get(4)?,
        parent_position: row.get(5)?,
        declared_by: row.get(6)?,
        reason: row.get(7)?,
        operation_id: row.get(8)?,
        created_at: parse_sqlite_datetime(9, created_at.as_str())?,
    })
}

fn fork_replay_from_row(row: &Row<'_>) -> rusqlite::Result<LedgerForkReplayRecord> {
    let created_at: String = row.get(10)?;
    Ok(LedgerForkReplayRecord {
        replay_id: row.get(0)?,
        fork_id: row.get(1)?,
        cluster_id: row.get(2)?,
        parent_checkpoint_id: row.get(3)?,
        parent_position: row.get(4)?,
        fork_position: row.get(5)?,
        replay_policy: row.get(6)?,
        operation_id: row.get(7)?,
        replayed_by: row.get(8)?,
        backup_reference: row.get(9)?,
        created_at: parse_sqlite_datetime(10, created_at.as_str())?,
    })
}

fn metadata_from_operation(operation: &LedgerOperation) -> Result<Option<LedgerSecretMetadata>> {
    if !matches!(
        operation.op_type.as_str(),
        "secret.metadata.set" | "secret.set"
    ) {
        return Ok(None);
    }
    let payload = operation.payload_json.as_object().ok_or_else(|| {
        HemError::InvalidArgument(format!(
            "ledger operation {} metadata payload must be a JSON object",
            operation.operation_id
        ))
    })?;
    let scope = required_payload_string(payload, "scope")?;
    let name = required_payload_string(payload, "name")?;
    let description = optional_payload_string(payload, "description")?.unwrap_or_default();
    let requires_approval = payload
        .get("requires_approval")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let group = optional_payload_string(payload, "group")?;
    let updated_by = optional_payload_string(payload, "actor")?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| operation.node_id.clone());

    Ok(Some(LedgerSecretMetadata {
        cluster_id: operation.cluster_id.clone(),
        scope,
        name,
        description,
        requires_approval,
        group,
        updated_at: operation.created_at,
        updated_by,
        last_operation_id: operation.operation_id.clone(),
        last_position: operation.position,
    }))
}

fn value_versions_from_operation(
    operation: &LedgerOperation,
) -> Result<Vec<LedgerSecretValueVersion>> {
    if operation.op_type != "secret.value.set" {
        return Ok(Vec::new());
    }
    let payload = operation.payload_json.as_object().ok_or_else(|| {
        HemError::InvalidArgument(format!(
            "ledger operation {} value payload must be a JSON object",
            operation.operation_id
        ))
    })?;
    let scope = required_payload_string(payload, "scope")?;
    let name = required_payload_string(payload, "name")?;
    let values = payload
        .get("values")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            HemError::InvalidArgument("value payload missing values object".to_string())
        })?;
    let created_by = optional_payload_string(payload, "actor")?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| operation.node_id.clone());
    let base_version_seq = payload
        .get("base_version_seq")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            HemError::InvalidArgument(format!(
                "ledger operation {} value payload missing integer field base_version_seq",
                operation.operation_id
            ))
        })?;
    if base_version_seq < 0 {
        return Err(HemError::InvalidArgument(format!(
            "ledger operation {} value payload base_version_seq must not be negative",
            operation.operation_id
        )));
    }
    let mut versions = Vec::with_capacity(values.len());
    for (key, encrypted_value_json) in values {
        validate_non_empty("value key", key.as_str())?;
        if !encrypted_value_json.is_object() {
            return Err(HemError::InvalidArgument(format!(
                "encrypted value for key {key} must be a JSON object"
            )));
        }
        versions.push(LedgerSecretValueVersion {
            cluster_id: operation.cluster_id.clone(),
            scope: scope.clone(),
            name: name.clone(),
            key: key.clone(),
            version_seq: 0,
            encrypted_value_json: encrypted_value_json.clone(),
            created_at: operation.created_at,
            created_by: created_by.clone(),
            operation_id: operation.operation_id.clone(),
            position: operation.position,
            base_version_seq,
        });
    }
    Ok(versions)
}

fn collision_resolution_from_operation(
    operation: &LedgerOperation,
) -> Result<Option<LedgerCollisionResolution>> {
    if operation.op_type != "collision.resolved" {
        return Ok(None);
    }
    let payload = operation.payload_json.as_object().ok_or_else(|| {
        HemError::InvalidArgument(format!(
            "ledger operation {} collision resolution payload must be a JSON object",
            operation.operation_id
        ))
    })?;
    Ok(Some(LedgerCollisionResolution {
        collision_id: required_payload_string(payload, "collision_id")?,
        resolution: required_payload_string(payload, "resolution")?,
        resolved_by: required_payload_string(payload, "resolved_by")?,
        operation_id: operation.operation_id.clone(),
        resolved_at: operation.created_at,
    }))
}

fn resolution_accepts_incoming(resolution: &str, incoming_operation_id: &str) -> bool {
    matches!(
        resolution.trim(),
        "incoming" | "accept-incoming" | "keep-incoming" | "use-incoming"
    ) || resolution.trim() == incoming_operation_id
}

#[allow(clippy::too_many_arguments)]
fn deterministic_collision_id(
    cluster_id: &str,
    scope: &str,
    name: &str,
    key: &str,
    current_operation_id: &str,
    incoming_operation_id: &str,
    base_version_seq: i64,
    current_version_seq: i64,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "hem-collision-v1",
        cluster_id,
        scope,
        name,
        key,
        current_operation_id,
        incoming_operation_id,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher.update(base_version_seq.to_be_bytes());
    hasher.update(current_version_seq.to_be_bytes());
    let digest = hasher.finalize();
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    format!("hcol_{}", &encoded[..26])
}

fn inspect_known_operation_payload(
    operation: &LedgerOperation,
    issues: &mut Vec<LedgerIntegrityIssue>,
) {
    let reference = format!("operation:{}", operation.operation_id);
    let required_fields: &[&str] = match operation.op_type.as_str() {
        "secret.metadata.set" | "secret.set" => &["scope", "name"],
        "secret.value.set" => &["scope", "name"],
        "secret.deleted" => &["scope", "name", "actor"],
        "grant.access" | "grant.revoked" => {
            &["scope", "name", "grantee_scope", "grantee_id", "actor"]
        }
        "group.set" => &["name", "actor"],
        "secrets.imported" => &["actor"],
        "master_key.rotated" => &["actor", "new_key_id"],
        "collision.resolved" => &["collision_id", "resolution", "resolved_by"],
        "read.requested" | "read.fulfilled" | "ledger.hard_fork" => &[],
        "ledger.replay" => &[
            "replay_id",
            "fork_id",
            "replay_policy",
            "backup_reference",
            "replayed_by",
        ],
        _ => return,
    };
    let Some(payload) = operation.payload_json.as_object() else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            format!("{} payload is not a JSON object", operation.op_type),
        ));
        return;
    };
    for field in required_fields {
        match payload.get(*field).and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() => {}
            _ => issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                format!("{} payload missing string field {field}", operation.op_type),
            )),
        }
    }
    if operation.op_type == "read.fulfilled" {
        inspect_read_fulfilled_payload(payload, reference.clone(), issues);
    }
    if operation.op_type == "collision.resolved" {
        inspect_collision_resolved_payload(payload, reference.clone(), issues);
    }
    match operation.op_type.as_str() {
        "secret.value.set" => {
            if payload
                .get("base_version_seq")
                .and_then(Value::as_i64)
                .is_none()
            {
                issues.push(integrity_issue(
                    "error",
                    "payload",
                    reference,
                    "secret.value.set payload missing integer field base_version_seq",
                ));
            }
        }
        "secrets.imported" => {
            if payload
                .get("imported_secret_count")
                .and_then(Value::as_u64)
                .is_none()
            {
                issues.push(integrity_issue(
                    "error",
                    "payload",
                    reference,
                    "secrets.imported payload missing imported_secret_count",
                ));
            }
        }
        "master_key.rotated" => {
            if payload
                .get("rotated_secret_count")
                .and_then(Value::as_u64)
                .is_none()
            {
                issues.push(integrity_issue(
                    "error",
                    "payload",
                    reference,
                    "master_key.rotated payload missing rotated_secret_count",
                ));
            }
        }
        "ledger.replay" => {
            for field in ["parent_position", "fork_position"] {
                if payload.get(field).and_then(Value::as_i64).is_none() {
                    issues.push(integrity_issue(
                        "error",
                        "payload",
                        reference.clone(),
                        format!("ledger.replay payload missing integer field {field}"),
                    ));
                }
            }
        }
        _ => {}
    }
}

fn inspect_read_fulfilled_payload(
    payload: &serde_json::Map<String, Value>,
    reference: String,
    issues: &mut Vec<LedgerIntegrityIssue>,
) {
    if payload.get("policy_decision").and_then(Value::as_str) != Some("peer_quorum") {
        return;
    }

    let Some(approval_reference) = payload.get("approval_reference").and_then(Value::as_str) else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            "peer_quorum read.fulfilled payload missing approval_reference",
        ));
        return;
    };
    let Ok(evidence) = serde_json::from_str::<Value>(approval_reference) else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            "peer_quorum approval_reference is not JSON evidence",
        ));
        return;
    };
    let Some(evidence) = evidence.as_object() else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            "peer_quorum approval_reference must be a JSON object",
        ));
        return;
    };
    if evidence.get("kind").and_then(Value::as_str) != Some("peer_quorum_v1") {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference.clone(),
            "peer_quorum approval_reference kind must be peer_quorum_v1",
        ));
    }
    let required_peer_acks = match evidence.get("required_peer_acks").and_then(Value::as_u64) {
        Some(value) => value,
        None => {
            issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                "peer_quorum approval_reference missing required_peer_acks",
            ));
            0
        }
    };
    let Some(accepted) = evidence.get("accepted").and_then(Value::as_array) else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            "peer_quorum approval_reference missing accepted array",
        ));
        return;
    };
    if accepted.len() < usize::try_from(required_peer_acks).unwrap_or(usize::MAX) {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference.clone(),
            "peer_quorum approval_reference accepted array is below required_peer_acks",
        ));
    }
    for item in accepted {
        let Some(item) = item.as_object() else {
            issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                "peer_quorum accepted evidence item must be a JSON object",
            ));
            continue;
        };
        for field in [
            "peer_node_id",
            "statement_hash_b64",
            "signing_public_key_b64",
            "signature_b64",
        ] {
            match item.get(field).and_then(Value::as_str) {
                Some(value) if !value.trim().is_empty() => {}
                _ => issues.push(integrity_issue(
                    "error",
                    "payload",
                    reference.clone(),
                    format!("peer_quorum accepted evidence missing string field {field}"),
                )),
            }
        }
        if item.get("statement").and_then(Value::as_object).is_none() {
            issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                "peer_quorum accepted evidence missing statement object",
            ));
        }
    }
}

fn inspect_collision_resolved_payload(
    payload: &serde_json::Map<String, Value>,
    reference: String,
    issues: &mut Vec<LedgerIntegrityIssue>,
) {
    let Some(agreement) = payload.get("agreement") else {
        return;
    };
    let Some(agreement) = agreement.as_object() else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            "collision.resolved agreement must be a JSON object",
        ));
        return;
    };
    match agreement.get("kind").and_then(Value::as_str) {
        Some("collision_quorum_v1") => {}
        Some("local_manual_v1") => return,
        _ => issues.push(integrity_issue(
            "error",
            "payload",
            reference.clone(),
            "collision.resolved agreement kind must be collision_quorum_v1 or local_manual_v1",
        )),
    }
    let required_peer_acks = match agreement.get("required_peer_acks").and_then(Value::as_u64) {
        Some(value) => value,
        None => {
            issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                "collision.resolved agreement missing required_peer_acks",
            ));
            0
        }
    };
    let Some(accepted) = agreement.get("accepted").and_then(Value::as_array) else {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference,
            "collision.resolved agreement missing accepted array",
        ));
        return;
    };
    if accepted.len() < usize::try_from(required_peer_acks).unwrap_or(usize::MAX) {
        issues.push(integrity_issue(
            "error",
            "payload",
            reference.clone(),
            "collision.resolved agreement accepted array is below required_peer_acks",
        ));
    }
    for item in accepted {
        let Some(item) = item.as_object() else {
            issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                "collision agreement item must be a JSON object",
            ));
            continue;
        };
        for field in [
            "peer_node_id",
            "statement_hash_b64",
            "signing_public_key_b64",
            "signature_b64",
        ] {
            match item.get(field).and_then(Value::as_str) {
                Some(value) if !value.trim().is_empty() => {}
                _ => issues.push(integrity_issue(
                    "error",
                    "payload",
                    reference.clone(),
                    format!("collision agreement item missing string field {field}"),
                )),
            }
        }
        if item.get("statement").and_then(Value::as_object).is_none() {
            issues.push(integrity_issue(
                "error",
                "payload",
                reference.clone(),
                "collision agreement item missing statement object",
            ));
        }
    }
}

fn inspect_value_blobs(
    operation: &LedgerOperation,
    issues: &mut Vec<LedgerIntegrityIssue>,
) -> usize {
    if operation.op_type != "secret.value.set" {
        return 0;
    }
    let reference = format!("operation:{}", operation.operation_id);
    let Some(payload) = operation.payload_json.as_object() else {
        issues.push(integrity_issue(
            "error",
            "blob",
            reference,
            "secret.value.set payload is not a JSON object",
        ));
        return 0;
    };
    let Some(values) = payload.get("values").and_then(Value::as_object) else {
        issues.push(integrity_issue(
            "error",
            "blob",
            reference,
            "secret.value.set payload missing values object",
        ));
        return 0;
    };

    let mut checked = 0_usize;
    for (key, value) in values {
        checked += 1;
        let value_ref = format!("operation:{} key:{key}", operation.operation_id);
        let Some(encrypted) = value.as_object() else {
            issues.push(integrity_issue(
                "error",
                "blob",
                value_ref,
                "encrypted value is not a JSON object",
            ));
            continue;
        };
        let alg = encrypted
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let required_fields: &[&str] = if alg == "hem-node-envelope-v1" {
            &["alg", "data_key_id", "nonce_b64", "ciphertext_b64"]
        } else {
            &["alg", "key_id", "nonce_b64", "ciphertext_b64"]
        };
        for field in required_fields {
            match encrypted.get(*field).and_then(Value::as_str) {
                Some(item) if !item.trim().is_empty() => {}
                _ => issues.push(integrity_issue(
                    "error",
                    "blob",
                    value_ref.clone(),
                    format!("encrypted value missing non-empty field {field}"),
                )),
            }
        }
        if alg == "hem-node-envelope-v1" {
            let Some(wraps) = encrypted.get("wraps").and_then(Value::as_array) else {
                issues.push(integrity_issue(
                    "error",
                    "blob",
                    value_ref,
                    "envelope value missing wraps array",
                ));
                continue;
            };
            if wraps.is_empty() {
                issues.push(integrity_issue(
                    "error",
                    "blob",
                    value_ref,
                    "envelope value wraps array must not be empty",
                ));
            }
        }
    }
    checked
}

fn integrity_issue(
    severity: impl Into<String>,
    category: impl Into<String>,
    reference: impl Into<String>,
    message: impl Into<String>,
) -> LedgerIntegrityIssue {
    LedgerIntegrityIssue {
        severity: severity.into(),
        category: category.into(),
        reference: reference.into(),
        message: message.into(),
    }
}

fn required_payload_string(payload: &serde_json::Map<String, Value>, key: &str) -> Result<String> {
    let value = optional_payload_string(payload, key)?.ok_or_else(|| {
        HemError::InvalidArgument(format!("metadata payload missing string field {key}"))
    })?;
    validate_non_empty(key, value.as_str())?;
    Ok(value)
}

fn optional_payload_string(
    payload: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>> {
    let Some(value) = payload.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value.as_str().ok_or_else(|| {
        HemError::InvalidArgument(format!("metadata payload field {key} must be a string"))
    })?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn parse_sqlite_datetime(index: usize, value: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })
        .map(|value| value.with_timezone(&Utc))
}

fn body_hash_bytes(body: &LedgerOperationBody) -> Result<[u8; 32]> {
    canonical_hash_bytes(body)
}

fn canonical_hash_bytes<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    let canonical = serde_json::to_vec(value)?;
    let digest = Sha256::digest(canonical.as_slice());
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_slice());
    Ok(out)
}

#[derive(Debug)]
struct SignedHash {
    public_key_b64: String,
    signature_b64: String,
}

fn sign_hash(identity: &NodeIdentity, hash: &[u8; 32]) -> Result<SignedHash> {
    let public_key = decode_base64_exact::<32>(
        "signing_public_key_b64",
        identity.signing_public_key_b64.as_str(),
    )?;
    let private_key = decode_base64_exact::<32>(
        "signing_private_key_b64",
        identity.signing_private_key_b64.as_str(),
    )?;
    let signing_key = SigningKey::from_bytes(&private_key);
    if signing_key.verifying_key().to_bytes() != public_key {
        return Err(HemError::Crypto(
            "node identity private key does not match public key".to_string(),
        ));
    }
    let signature: Signature = signing_key.sign(hash);
    Ok(SignedHash {
        public_key_b64: identity.signing_public_key_b64.clone(),
        signature_b64: STANDARD_NO_PAD.encode(signature.to_bytes()),
    })
}

fn verify_hash_signature(public_key_b64: &str, signature_b64: &str, hash: &[u8; 32]) -> Result<()> {
    let public_key = decode_base64_exact::<32>("signing_public_key_b64", public_key_b64)?;
    let signature = decode_base64_exact::<64>("signature_b64", signature_b64)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|err| HemError::Crypto(format!("invalid ledger public key: {err}")))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|err| HemError::Crypto(format!("invalid ledger signature: {err}")))?;
    verifying_key
        .verify(hash, &signature)
        .map_err(|err| HemError::Crypto(format!("ledger signature invalid: {err}")))?;
    Ok(())
}

fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
    if leaves.is_empty() {
        return Err(HemError::InvalidArgument(
            "merkle root requires at least one leaf".to_string(),
        ));
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            next.push(hash_merkle_pair(left, right));
        }
        level = next;
    }
    Ok(level[0])
}

#[derive(Debug, Clone, Default)]
struct MerkleAccumulator {
    operation_count: i64,
    peaks: Vec<Option<[u8; 32]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MerkleSummary {
    operation_count: i64,
    root: Option<[u8; 32]>,
}

impl MerkleAccumulator {
    fn push(&mut self, leaf: [u8; 32]) {
        self.operation_count = self.operation_count.saturating_add(1);
        let mut height = 0_usize;
        let mut node = leaf;
        loop {
            if height == self.peaks.len() {
                self.peaks.push(Some(node));
                break;
            }
            match self.peaks[height].take() {
                Some(left) => {
                    node = hash_merkle_pair(left, node);
                    height += 1;
                }
                None => {
                    self.peaks[height] = Some(node);
                    break;
                }
            }
        }
    }

    fn summary(&self) -> MerkleSummary {
        MerkleSummary {
            operation_count: self.operation_count,
            root: self.root(),
        }
    }

    fn root(&self) -> Option<[u8; 32]> {
        let mut accumulated: Option<([u8; 32], usize)> = None;
        for (height, peak) in self.peaks.iter().enumerate() {
            let Some(left) = peak else {
                continue;
            };
            accumulated = Some(match accumulated {
                None => (*left, height),
                Some((mut right, mut right_height)) => {
                    while right_height < height {
                        right = hash_merkle_pair(right, right);
                        right_height += 1;
                    }
                    (hash_merkle_pair(*left, right), height + 1)
                }
            });
        }
        accumulated.map(|(root, _)| root)
    }
}

fn hash_merkle_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut parent = [0_u8; 32];
    parent.copy_from_slice(digest.as_slice());
    parent
}

fn verify_checkpoint_merkle_summary(
    checkpoint: &LedgerCheckpoint,
    summary: Option<&MerkleSummary>,
    report: &mut LedgerIntegrityReport,
) {
    let actual_count = summary.map_or(0, |summary| summary.operation_count);
    if actual_count != checkpoint.body.operation_count {
        report.issues.push(integrity_issue(
            "error",
            "checkpoint_merkle",
            format!("checkpoint:{}", checkpoint.body.checkpoint_id),
            format!(
                "operation count mismatch expected={} actual={actual_count}",
                checkpoint.body.operation_count
            ),
        ));
    }
    if let Some(root) = summary.and_then(|summary| summary.root) {
        let merkle_root_b64 = STANDARD_NO_PAD.encode(root);
        if merkle_root_b64 != checkpoint.body.merkle_root_b64 {
            report.issues.push(integrity_issue(
                "error",
                "checkpoint_merkle",
                format!("checkpoint:{}", checkpoint.body.checkpoint_id),
                format!(
                    "merkle root mismatch expected={} actual={merkle_root_b64}",
                    checkpoint.body.merkle_root_b64
                ),
            ));
        }
    }
}

fn decode_base64_exact<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let bytes = STANDARD_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        HemError::InvalidArgument(format!("{label} must be base64-no-pad: {err}"))
    })?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        HemError::InvalidArgument(format!(
            "{label} decoded length must be {N} bytes, got {len}"
        ))
    })
}

fn validate_hash_or_empty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    decode_base64_exact::<32>(label, value).map(|_| ())
}

fn validate_hash(label: &str, value: &str) -> Result<()> {
    validate_non_empty(label, value)?;
    decode_base64_exact::<32>(label, value).map(|_| ())
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

fn blank_dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_accumulator_matches_batch_roots_for_every_prefix() {
        let leaves = (0_u32..257)
            .map(|value| {
                let digest = Sha256::digest(value.to_be_bytes());
                let mut leaf = [0_u8; 32];
                leaf.copy_from_slice(digest.as_slice());
                leaf
            })
            .collect::<Vec<_>>();
        let mut accumulator = MerkleAccumulator::default();
        for (index, leaf) in leaves.iter().copied().enumerate() {
            accumulator.push(leaf);
            assert_eq!(
                accumulator.root().expect("accumulator root"),
                merkle_root(&leaves[..=index]).expect("batch root"),
                "prefix length {}",
                index + 1
            );
        }
    }

    #[test]
    fn integrity_verification_checks_many_checkpoint_prefixes_in_one_pass() {
        let root = tempfile::tempdir().expect("tempdir");
        let ledger = LedgerStore::open(root.path()).expect("open ledger");
        let identity = NodeIdentity::generate("hmn_a", "node a").expect("identity");

        for position in 1_i64..=64 {
            append_metadata_operation(
                &ledger,
                &identity,
                format!("hop_{position}").as_str(),
                "hmc_a",
                position,
                "global",
                format!("secret_{position}").as_str(),
            );
            ledger
                .create_checkpoint(&identity, "hmc_a", position)
                .expect("create checkpoint");
        }

        let report = ledger.verify_integrity().expect("verify integrity");
        assert!(report.ok, "integrity issues: {:?}", report.issues);
        assert_eq!(report.operations_checked, 64);
        assert_eq!(report.checkpoints_checked, 64);
        assert_eq!(
            ledger
                .latest_checkpoint_for_signer("hmc_a", "hmn_a")
                .expect("latest checkpoint")
                .expect("checkpoint")
                .body
                .to_position,
            64
        );
    }

    #[test]
    fn list_materialized_secret_metadata_filters_by_cluster_and_scope() {
        let root = tempfile::tempdir().expect("tempdir");
        let ledger = LedgerStore::open(root.path()).expect("open ledger");
        let identity = NodeIdentity::generate("hmn_a", "node a").expect("identity");

        append_metadata_operation(
            &ledger,
            &identity,
            "hop_global",
            "hmc_a",
            1,
            "global",
            "alpha",
        );
        append_metadata_operation(
            &ledger,
            &identity,
            "hop_project",
            "hmc_a",
            2,
            "project/demo",
            "bravo",
        );
        append_metadata_operation(
            &ledger,
            &identity,
            "hop_other_cluster",
            "hmc_b",
            3,
            "global",
            "charlie",
        );

        assert_eq!(
            ledger.materialize_secret_metadata().expect("materialize"),
            3
        );

        let all = ledger
            .list_materialized_secret_metadata("hmc_a", None)
            .expect("list all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "alpha");
        assert_eq!(all[1].name, "bravo");

        let global = ledger
            .list_materialized_secret_metadata("hmc_a", Some("global"))
            .expect("list global");
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].name, "alpha");
    }

    fn append_metadata_operation(
        ledger: &LedgerStore,
        identity: &NodeIdentity,
        operation_id: &str,
        cluster_id: &str,
        node_seq: i64,
        scope: &str,
        name: &str,
    ) {
        let input = LedgerOperationInput {
            operation_id: operation_id.to_string(),
            cluster_id: cluster_id.to_string(),
            node_id: identity.node_id.clone(),
            node_seq,
            op_type: "secret.metadata.set".to_string(),
            payload_json: json!({
                "scope": scope,
                "name": name,
                "description": format!("metadata for {name}"),
                "requires_approval": false,
                "actor": "tester",
            }),
            created_at: Utc::now(),
        };
        let envelope = ledger.sign_next(identity, input).expect("sign");
        ledger.append_signed(&envelope).expect("append");
    }
}
