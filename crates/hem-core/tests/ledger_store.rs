use std::collections::HashMap;

use chrono::Utc;
use hem_core::{
    HemStore, LedgerForkReplayInput, LedgerOperation, LedgerOperationBody, LedgerOperationEnvelope,
    LedgerOperationInput, LedgerStore, LocalStoreLedgerMigrationInput, NodeIdentity, SecretScope,
    SetSecretInput,
};
use rusqlite::Connection;
use serde_json::json;

#[test]
fn ledger_appends_operations_and_lists_after_cursor() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");

    let first = append_signed_operation(&store, &identity, "hop_a", 1, 1);
    let second = append_signed_operation(&store, &identity, "hop_b", 2, 2);

    assert_eq!(first.position, 1);
    assert_eq!(second.position, 2);
    assert_eq!(store.latest_position().expect("latest"), 2);
    assert_eq!(
        store
            .node_high_watermark("hmn_a")
            .expect("node high watermark"),
        2
    );

    let after_first = store.list_after(first.position, 10).expect("list");
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].operation_id, "hop_b");
    assert_eq!(after_first[0].payload_json["version"], 2);
}

#[test]
fn ledger_open_and_peer_sync_reads_do_not_commit() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");
    append_signed_operation(&store, &identity, "hop_a", 1, 1);
    let ledger_path = store.path().to_path_buf();
    drop(store);

    let observer = Connection::open(ledger_path.as_path()).expect("observer");
    let data_version = || -> i64 {
        observer
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .expect("data_version")
    };
    let before = data_version();

    // The calls hemd makes per peer_hello / peer_list_operations / sync tick, including
    // a fresh open of an already-migrated ledger.
    let store = LedgerStore::open(root.path()).expect("reopen ledger");
    let reopened = LedgerStore::open(root.path()).expect("reopen ledger again");
    assert_eq!(store.latest_position().expect("latest"), 1);
    assert!(store.latest_body_hash().expect("hash").is_some());
    assert_eq!(reopened.list_after(0, 1_000).expect("list").len(), 1);
    assert!(reopened.get_peer_cursor("hmn_b").expect("cursor").is_none());
    assert!(reopened
        .latest_checkpoint_for_signer("hmc_a", "hmn_a")
        .expect("checkpoint")
        .is_none());
    assert!(reopened.list_checkpoints().expect("checkpoints").is_empty());

    assert_eq!(
        data_version(),
        before,
        "read-only ledger calls committed a write"
    );
}

#[cfg(unix)]
#[test]
fn ledger_keeps_wal_open_between_calls_while_a_store_is_alive() {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");
    append_signed_operation(&store, &identity, "hop_a", 1, 1);
    let wal_path = store.path().with_extension("sqlite3-wal");
    let wal_inode = std::fs::metadata(wal_path.as_path())
        .expect("wal exists while store is alive")
        .ino();

    for _ in 0..3 {
        let per_request = LedgerStore::open(root.path()).expect("per-request open");
        assert_eq!(per_request.latest_position().expect("latest"), 1);
        store.list_after(0, 10).expect("list");
    }
    assert_eq!(
        std::fs::metadata(wal_path.as_path())
            .expect("wal still exists")
            .ino(),
        wal_inode,
        "WAL was deleted and recreated between calls"
    );
    for sidecar in [wal_path.clone(), store.path().with_extension("sqlite3-shm")] {
        let mode = std::fs::metadata(sidecar.as_path())
            .expect("sidecar")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{} is not owner-only", sidecar.display());
    }

    drop(store);
    assert!(
        !wal_path.exists(),
        "closing the last store should checkpoint and remove the WAL"
    );
}

#[test]
fn ledger_open_migrates_a_replaced_file_while_old_store_is_alive() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");
    append_signed_operation(&store, &identity, "hop_a", 1, 1);
    let ledger_path = store.path().to_path_buf();
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", ledger_path.display());
        let _ = std::fs::remove_file(path);
    }

    let replacement = LedgerStore::open(root.path()).expect("open replaced ledger");
    assert_eq!(replacement.latest_position().expect("latest"), 0);
    append_signed_operation(&replacement, &identity, "hop_b", 1, 1);
    assert_eq!(replacement.latest_position().expect("latest"), 1);
    drop(store);
}

#[test]
fn ledger_rejects_duplicate_node_sequence_without_reordering_log() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");
    append_signed_operation(&store, &identity, "hop_a", 1, 1);

    let duplicate_seq = store
        .sign_next(&identity, operation_input("hop_b", 1, 2))
        .expect("sign duplicate seq");
    let err = store
        .append_signed(&duplicate_seq)
        .expect_err("duplicate node sequence must fail");

    assert!(err.to_string().to_ascii_lowercase().contains("unique"));
    assert_eq!(store.latest_position().expect("latest"), 1);
    assert_eq!(store.list_after(0, 10).expect("list").len(), 1);
}

#[test]
fn hem_store_exposes_ledger_under_distributed_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    HemStore::init(root.path(), false).expect("init hem store");
    let store = HemStore::open(root.path()).expect("open hem store");

    let ledger = store.ledger_store().expect("ledger store");

    assert_eq!(
        ledger.path(),
        root.path()
            .join("distributed")
            .join("ledger.sqlite3")
            .as_path()
    );
    assert!(ledger.path().exists());
}

#[test]
fn local_store_migration_dry_run_reports_counts_without_creating_ledger() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = seeded_store(root.path());
    let identity = NodeIdentity::generate("hmn_migrator", "migration").expect("identity");

    let report = store
        .migrate_local_store_to_ledger(LocalStoreLedgerMigrationInput {
            cluster_id: "hmc_test",
            identity: &identity,
            dry_run: true,
        })
        .expect("dry-run migration");

    assert!(report.dry_run);
    assert_eq!(report.groups_scanned, 1);
    assert_eq!(report.secrets_scanned, 2);
    assert_eq!(report.value_keys_scanned, 3);
    assert_eq!(report.grants_scanned, 1);
    assert_eq!(report.operations_planned, 6);
    assert_eq!(report.operations_appended, 0);
    assert!(report.unsupported_records.is_empty());
    assert!(!root
        .path()
        .join("distributed")
        .join("ledger.sqlite3")
        .exists());
}

#[test]
fn local_store_migration_appends_signed_ledger_and_preserves_local_store() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = seeded_store(root.path());
    let identity = NodeIdentity::generate("hmn_migrator", "migration").expect("identity");

    let report = store
        .migrate_local_store_to_ledger(LocalStoreLedgerMigrationInput {
            cluster_id: "hmc_test",
            identity: &identity,
            dry_run: false,
        })
        .expect("migration");

    assert!(!report.dry_run);
    assert_eq!(report.operations_appended, report.operations_planned);
    assert_eq!(report.ledger_start_position, 0);
    assert_eq!(report.ledger_end_position, 6);

    let ledger = store.ledger_store().expect("ledger");
    let metadata = ledger
        .get_materialized_secret_metadata("hmc_test", "global", "openai-prod")
        .expect("metadata query")
        .expect("metadata");
    assert_eq!(metadata.description, "prod model key");
    assert_eq!(metadata.group.as_deref(), Some("prod"));
    assert!(metadata.requires_approval);

    let versions = ledger
        .list_secret_value_versions("hmc_test", "global", "openai-prod", "api-key")
        .expect("versions");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version_seq, 1);
    assert_eq!(versions[0].base_version_seq, 0);

    let operations = ledger.list_after(0, 20).expect("operations");
    assert_eq!(operations.len(), 6);
    assert!(operations.iter().any(|item| item.op_type == "grant.access"));
    assert!(operations.iter().any(|item| item.op_type == "group.set"));

    let values = store
        .get_secret_values_without_access_update(&SecretScope::Global, "openai-prod")
        .expect("local secret still readable");
    assert_eq!(values.get("api-key").map(String::as_str), Some("sk-live"));
    assert_eq!(
        store
            .list_grants(&SecretScope::Global, "openai-prod")
            .expect("local grants")
            .len(),
        1
    );
}

#[test]
fn local_store_migration_refuses_non_empty_ledger() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = seeded_store(root.path());
    let identity = NodeIdentity::generate("hmn_a", "migration").expect("identity");
    let ledger = store.ledger_store().expect("ledger");
    append_signed_operation(&ledger, &identity, "hop_existing", 1, 1);

    let err = store
        .migrate_local_store_to_ledger(LocalStoreLedgerMigrationInput {
            cluster_id: "hmc_test",
            identity: &identity,
            dry_run: false,
        })
        .expect_err("non-empty ledger must be rejected");

    assert!(err
        .to_string()
        .contains("requires an empty distributed ledger"));
}

#[test]
fn signed_envelopes_verify_and_chain_to_previous_hash() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");

    let first = store
        .sign_next(&identity, operation_input("hop_a", 1, 1))
        .expect("sign first");
    first.verify().expect("verify first");
    assert_eq!(first.body.prev_hash_b64, "");

    let first_record = store.append_signed(&first).expect("append first");
    assert_eq!(first_record.body_hash_b64, first.body_hash_b64);

    let second = store
        .sign_next(&identity, operation_input("hop_b", 2, 2))
        .expect("sign second");
    second.verify().expect("verify second");
    assert_eq!(second.body.prev_hash_b64, first_record.body_hash_b64);

    let second_record = store.append_signed(&second).expect("append second");
    assert_eq!(second_record.prev_hash_b64, first_record.body_hash_b64);
    assert_ne!(second_record.body_hash_b64, first_record.body_hash_b64);
}

#[test]
fn signed_envelope_rejects_payload_tampering() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");

    let mut envelope = store
        .sign_next(&identity, operation_input("hop_a", 1, 1))
        .expect("sign");
    envelope.body.payload_json = json!({"secret":"global/demo","version":99});

    let err = envelope.verify().expect_err("tampering must fail");
    assert!(err.to_string().contains("hash mismatch"));
}

#[test]
fn bootstrap_from_peer_operations_resumes_without_duplicates_and_materializes() {
    let source_root = tempfile::tempdir().expect("source tempdir");
    let source = LedgerStore::open(source_root.path()).expect("source ledger");
    let dest_root = tempfile::tempdir().expect("dest tempdir");
    let dest = LedgerStore::open(dest_root.path()).expect("dest ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("identity");

    let metadata = source
        .sign_next(
            &identity,
            metadata_operation_input(MetadataSpec {
                operation_id: "hop_bootstrap_meta",
                node_seq: 1,
                scope: "global",
                name: "demo",
                description: "from source",
                requires_approval: false,
                group: None,
                actor: "alice",
            }),
        )
        .expect("sign metadata");
    source.append_signed(&metadata).expect("append metadata");
    let value = source
        .sign_next(
            &identity,
            value_operation_input_with_base("hop_bootstrap_value", 2, "api_key", "ciphertext-a", 0),
        )
        .expect("sign value");
    source.append_signed(&value).expect("append value");
    let envelopes = source
        .list_after(0, 10)
        .expect("list source")
        .iter()
        .map(envelope_from_operation)
        .collect::<Vec<_>>();

    let first = dest
        .bootstrap_from_peer_operations("hmc_test", &envelopes[..1])
        .expect("first bootstrap chunk");
    assert_eq!(first.accepted_operations, 1);
    assert_eq!(first.duplicate_operations, 0);
    assert_eq!(first.latest_position, 1);

    let second = dest
        .bootstrap_from_peer_operations("hmc_test", envelopes.as_slice())
        .expect("resume bootstrap");
    assert_eq!(second.accepted_operations, 1);
    assert_eq!(second.duplicate_operations, 1);
    assert_eq!(second.latest_position, 2);
    assert_eq!(second.materialized_records, 1);

    let metadata = dest
        .get_materialized_secret_metadata("hmc_test", "global", "demo")
        .expect("metadata")
        .expect("metadata exists");
    assert_eq!(metadata.description, "from source");
    let versions = dest
        .list_secret_value_versions("hmc_test", "global", "demo", "api_key")
        .expect("versions");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].operation_id, "hop_bootstrap_value");
}

#[test]
fn bootstrap_from_peer_operations_rejects_tampered_signature_and_wrong_cluster() {
    let source_root = tempfile::tempdir().expect("source tempdir");
    let source = LedgerStore::open(source_root.path()).expect("source ledger");
    let dest_root = tempfile::tempdir().expect("dest tempdir");
    let dest = LedgerStore::open(dest_root.path()).expect("dest ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("identity");

    append_signed_operation(&source, &identity, "hop_bootstrap_a", 1, 1);
    let operation = source
        .list_after(0, 1)
        .expect("list source")
        .pop()
        .expect("operation");
    let mut tampered = envelope_from_operation(&operation);
    tampered.signature_b64 = "not-a-valid-signature".to_string();
    let err = dest
        .bootstrap_from_peer_operations("hmc_test", &[tampered])
        .expect_err("tampered signature must fail");
    assert!(err.to_string().contains("signature") || err.to_string().contains("base64"));

    let wrong_cluster = source
        .sign_next(
            &identity,
            LedgerOperationInput {
                operation_id: "hop_bootstrap_wrong_cluster".to_string(),
                cluster_id: "hmc_wrong".to_string(),
                node_id: "hmn_a".to_string(),
                node_seq: 2,
                op_type: "secret.set".to_string(),
                payload_json: json!({
                    "scope": "global",
                    "name": "demo",
                    "version": 2,
                }),
                created_at: Utc::now(),
            },
        )
        .expect("sign wrong cluster");
    let err = dest
        .bootstrap_from_peer_operations("hmc_test", &[wrong_cluster])
        .expect_err("wrong cluster must fail");
    assert!(err.to_string().contains("cluster_id"), "{err}");
    assert_eq!(dest.latest_position().expect("latest"), 0);
}

#[test]
fn append_signed_rejects_stale_previous_hash() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "local").expect("identity");

    let first = store
        .sign_next(&identity, operation_input("hop_a", 1, 1))
        .expect("sign first");
    let stale_second = store
        .sign_next(&identity, operation_input("hop_b", 2, 2))
        .expect("sign stale second");
    assert_eq!(stale_second.body.prev_hash_b64, "");

    store.append_signed(&first).expect("append first");
    let err = store
        .append_signed(&stale_second)
        .expect_err("stale previous hash must fail");

    assert!(err.to_string().contains("previous hash mismatch"));
    assert_eq!(store.latest_position().expect("latest"), 1);
}

#[test]
fn checkpoints_commit_to_ledger_prefix_and_accept_cosignatures() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let node_a = NodeIdentity::generate("hmn_a", "a").expect("node a");
    let node_b = NodeIdentity::generate("hmn_b", "b").expect("node b");
    append_signed_operation(&store, &node_a, "hop_a", 1, 1);
    append_signed_operation(&store, &node_a, "hop_b", 2, 2);

    let checkpoint = store
        .create_checkpoint(&node_a, "hmc_test", 2)
        .expect("checkpoint");
    checkpoint.verify().expect("verify checkpoint");
    assert_eq!(checkpoint.body.to_position, 2);
    assert_eq!(checkpoint.body.operation_count, 2);
    assert_ne!(checkpoint.body.merkle_root_b64, "");

    let cosignature = store
        .cosign_checkpoint(&node_b, checkpoint.body.checkpoint_id.as_str())
        .expect("cosign");
    cosignature.verify(&checkpoint).expect("verify cosignature");
    assert_eq!(cosignature.body.signer_node_id, "hmn_b");
    let repeated = store
        .cosign_checkpoint(&node_b, checkpoint.body.checkpoint_id.as_str())
        .expect("repeat cosign");
    assert_eq!(repeated, cosignature);

    let listed = store
        .list_checkpoint_cosignatures(checkpoint.body.checkpoint_id.as_str())
        .expect("list cosignatures");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].body.checkpoint_body_hash_b64,
        checkpoint.body_hash_b64
    );
    store
        .ingest_checkpoint(&checkpoint)
        .expect("checkpoint ingest is idempotent");
    store
        .ingest_checkpoint_cosignature(&cosignature)
        .expect("cosignature ingest is idempotent");
}

#[test]
fn checkpoint_ingest_rejects_divergent_prefix_and_verify_reports_merkle_mismatch() {
    let node_a_root = tempfile::tempdir().expect("tempdir a");
    let node_b_root = tempfile::tempdir().expect("tempdir b");
    let node_a_store = LedgerStore::open(node_a_root.path()).expect("open ledger a");
    let node_b_store = LedgerStore::open(node_b_root.path()).expect("open ledger b");
    let node_a = NodeIdentity::generate("hmn_a", "a").expect("node a");
    append_signed_operation(&node_a_store, &node_a, "hop_a", 1, 1);
    append_signed_operation(&node_b_store, &node_a, "hop_b", 1, 2);

    let checkpoint = node_a_store
        .create_checkpoint(&node_a, "hmc_test", 1)
        .expect("checkpoint");
    let err = node_b_store
        .ingest_checkpoint(&checkpoint)
        .expect_err("divergent prefix must not ingest");
    assert!(
        err.to_string().contains("checkpoint merkle root mismatch"),
        "{err}"
    );

    let conn = Connection::open(node_a_store.path()).expect("open sqlite");
    conn.execute(
        "UPDATE ledger_checkpoints SET merkle_root_b64 = ?1 WHERE checkpoint_id = ?2",
        (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            checkpoint.body.checkpoint_id.as_str(),
        ),
    )
    .expect("corrupt checkpoint merkle root");
    let report = node_a_store.verify_integrity().expect("verify");
    assert!(!report.ok, "{report:?}");
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "checkpoint_merkle"));
}

#[test]
fn verify_integrity_checks_hashes_signatures_blobs_and_checkpoints() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let node_a = NodeIdentity::generate("hmn_a", "a").expect("node a");
    let node_b = NodeIdentity::generate("hmn_b", "b").expect("node b");
    let value = store
        .sign_next(
            &node_a,
            value_operation_input_with_base("hop_verify_a", 1, "api_key", "ciphertext-a", 0),
        )
        .expect("sign value");
    store.append_signed(&value).expect("append value");
    append_signed_operation(&store, &node_a, "hop_verify_b", 2, 2);
    let checkpoint = store
        .create_checkpoint(&node_a, "hmc_test", 2)
        .expect("checkpoint");
    store
        .cosign_checkpoint(&node_b, checkpoint.body.checkpoint_id.as_str())
        .expect("cosign");
    store
        .record_peer_cursor(
            "hmn_b",
            2,
            store.latest_body_hash().expect("hash").unwrap().as_str(),
        )
        .expect("cursor");

    let report = store.verify_integrity().expect("verify");

    assert!(report.ok, "{report:?}");
    assert_eq!(report.operations_checked, 2);
    assert_eq!(report.value_blobs_checked, 1);
    assert_eq!(report.checkpoints_checked, 1);
    assert_eq!(report.checkpoint_cosignatures_checked, 1);
    assert_eq!(report.peer_cursors_checked, 1);
    assert!(report.issues.is_empty());
}

#[test]
fn verify_integrity_checks_peer_quorum_read_evidence_shape() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");
    let evidence = json!({
        "kind": "peer_quorum_v1",
        "required_peer_acks": 1,
        "accepted": [{
            "peer_node_id": "hmn_b",
            "statement_hash_b64": "statement-hash",
            "signing_public_key_b64": "peer-public-key",
            "signature_b64": "peer-signature",
            "statement": {
                "version": "hem-peer-read-quorum-v1",
                "cluster_id": "hmc_test",
                "requester_node_id": "hmn_a",
                "approver_node_id": "hmn_b"
            }
        }]
    });
    let good = store
        .sign_next(
            &identity,
            LedgerOperationInput {
                operation_id: "hop_quorum_good".to_string(),
                cluster_id: "hmc_test".to_string(),
                node_id: "hmn_a".to_string(),
                node_seq: 1,
                op_type: "read.fulfilled".to_string(),
                payload_json: json!({
                    "policy_decision": "peer_quorum",
                    "approval_reference": serde_json::to_string(&evidence).expect("evidence json"),
                }),
                created_at: Utc::now(),
            },
        )
        .expect("sign good read");
    store.append_signed(&good).expect("append good read");

    let good_report = store.verify_integrity().expect("verify good");
    assert!(good_report.ok, "{good_report:?}");

    let bad = store
        .sign_next(
            &identity,
            LedgerOperationInput {
                operation_id: "hop_quorum_bad".to_string(),
                cluster_id: "hmc_test".to_string(),
                node_id: "hmn_a".to_string(),
                node_seq: 2,
                op_type: "read.fulfilled".to_string(),
                payload_json: json!({
                    "policy_decision": "peer_quorum",
                    "approval_reference": serde_json::to_string(&json!({
                        "kind": "peer_quorum_v1",
                        "required_peer_acks": 1,
                        "accepted": [],
                    }))
                    .expect("bad evidence json"),
                }),
                created_at: Utc::now(),
            },
        )
        .expect("sign bad read");
    store.append_signed(&bad).expect("append bad read");

    let bad_report = store.verify_integrity().expect("verify bad");
    assert!(!bad_report.ok, "{bad_report:?}");
    assert!(bad_report.issues.iter().any(|issue| {
        issue.category == "payload"
            && issue
                .message
                .contains("accepted array is below required_peer_acks")
    }));
}

#[test]
fn verify_integrity_reports_peer_cursor_divergence() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");
    append_signed_operation(&store, &identity, "hop_verify_a", 1, 1);

    let conn = Connection::open(store.path()).expect("open sqlite");
    conn.execute(
        "INSERT INTO ledger_peer_cursors (
            peer_node_id,
            last_position,
            last_body_hash_b64,
            updated_at
         ) VALUES (?1, ?2, ?3, ?4)",
        ("hmn_peer", 9_i64, "bad-peer-head", Utc::now().to_rfc3339()),
    )
    .expect("insert divergent cursor");

    let report = store.verify_integrity().expect("verify");

    assert!(report.ok, "{report:?}");
    assert_eq!(report.peer_cursors_checked, 1);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.category == "divergence" && issue.severity == "warning"));
}

#[test]
fn declare_hard_fork_records_parent_checkpoint_and_operation() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");
    append_signed_operation(&store, &identity, "hop_fork_a", 1, 1);
    let checkpoint = store
        .create_checkpoint(&identity, "hmc_test", 1)
        .expect("checkpoint");

    let fork = store
        .declare_hard_fork(
            &identity,
            "hmc_test",
            Some(checkpoint.body.checkpoint_id.as_str()),
            "operator",
            "rewind bad peer history",
        )
        .expect("declare fork");

    assert_eq!(fork.epoch, 1);
    assert_eq!(fork.parent_checkpoint_id, checkpoint.body.checkpoint_id);
    assert_eq!(
        fork.parent_checkpoint_body_hash_b64,
        checkpoint.body_hash_b64
    );
    assert_eq!(fork.parent_position, 1);
    let operation = store
        .get_by_operation_id(fork.operation_id.as_str())
        .expect("get operation")
        .expect("operation");
    assert_eq!(operation.op_type, "ledger.hard_fork");
    assert_eq!(operation.payload_json["fork_id"], fork.fork_id);

    let forks = store.list_forks().expect("list forks");
    assert_eq!(forks, vec![fork]);
    let report = store.verify_integrity().expect("verify");
    assert!(report.ok, "{report:?}");
    assert_eq!(report.forks_declared, 1);
}

#[test]
fn hard_fork_replay_rebuilds_materializers_from_checkpoint_and_after_fork() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("identity");

    let before = store
        .sign_next(
            &identity,
            metadata_operation_input(MetadataSpec {
                operation_id: "hop_meta_before",
                node_seq: 1,
                scope: "global",
                name: "demo",
                description: "before fork",
                requires_approval: false,
                group: None,
                actor: "alice",
            }),
        )
        .expect("sign before");
    store.append_signed(&before).expect("append before");
    let checkpoint = store
        .create_checkpoint(&identity, "hmc_test", 1)
        .expect("checkpoint");

    let bad = store
        .sign_next(
            &identity,
            metadata_operation_input(MetadataSpec {
                operation_id: "hop_meta_bad",
                node_seq: 2,
                scope: "global",
                name: "demo",
                description: "bad state",
                requires_approval: true,
                group: Some("bad"),
                actor: "mallory",
            }),
        )
        .expect("sign bad");
    store.append_signed(&bad).expect("append bad");
    store
        .materialize_secret_metadata()
        .expect("materialize bad");
    assert_eq!(
        store
            .get_materialized_secret_metadata("hmc_test", "global", "demo")
            .expect("metadata")
            .expect("metadata exists")
            .description,
        "bad state"
    );

    let fork = store
        .declare_hard_fork(
            &identity,
            "hmc_test",
            Some(checkpoint.body.checkpoint_id.as_str()),
            "operator",
            "rewind bad state",
        )
        .expect("declare fork");
    let after = store
        .sign_next(
            &identity,
            metadata_operation_input(MetadataSpec {
                operation_id: "hop_meta_after_fork",
                node_seq: 4,
                scope: "global",
                name: "demo",
                description: "after fork",
                requires_approval: false,
                group: Some("good"),
                actor: "alice",
            }),
        )
        .expect("sign after fork");
    store.append_signed(&after).expect("append after fork");

    let report = store
        .execute_hard_fork_replay(
            &identity,
            LedgerForkReplayInput {
                fork_id: fork.fork_id.as_str(),
                actor: "operator",
                backup_reference: "backup://unit-test",
            },
        )
        .expect("execute replay");

    assert_eq!(report.fork_id, fork.fork_id);
    assert_eq!(report.parent_position, 1);
    assert_eq!(report.fork_position, 3);
    assert_eq!(report.operations_skipped, 2);
    assert_eq!(report.materializer_records_rebuilt, 2);
    assert!(report.replay_operation_id.starts_with("hop_"));

    let metadata = store
        .get_materialized_secret_metadata("hmc_test", "global", "demo")
        .expect("metadata")
        .expect("metadata exists");
    assert_eq!(metadata.description, "after fork");
    assert_eq!(metadata.group.as_deref(), Some("good"));
    assert_eq!(metadata.last_operation_id, "hop_meta_after_fork");

    let replay_records = store.list_fork_replays().expect("list replays");
    assert_eq!(replay_records.len(), 1);
    assert_eq!(replay_records[0].fork_id, fork.fork_id);
    assert_eq!(replay_records[0].backup_reference, "backup://unit-test");
    assert_eq!(
        replay_records[0].replay_policy,
        "checkpoint_then_after_fork"
    );

    let operations = store.list_after(0, 20).expect("operations");
    assert!(operations
        .iter()
        .any(|op| op.operation_id == "hop_meta_bad"));
    assert!(operations.iter().any(|op| op.op_type == "ledger.replay"));

    let integrity = store.verify_integrity().expect("verify");
    assert!(integrity.ok, "{integrity:?}");
    assert_eq!(integrity.forks_declared, 1);
    assert_eq!(integrity.fork_replays_declared, 1);
}

#[test]
fn materializes_secret_metadata_from_signed_ledger_operations() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");

    let first = store
        .sign_next(
            &identity,
            metadata_operation_input(MetadataSpec {
                operation_id: "hop_meta_a",
                node_seq: 1,
                scope: "global",
                name: "demo",
                description: "first description",
                requires_approval: false,
                group: Some("ai"),
                actor: "alice",
            }),
        )
        .expect("sign first");
    store.append_signed(&first).expect("append first");
    assert_eq!(store.materialize_secret_metadata().expect("materialize"), 1);

    let first_metadata = store
        .get_materialized_secret_metadata("hmc_test", "global", "demo")
        .expect("get metadata")
        .expect("metadata exists");
    assert_eq!(first_metadata.description, "first description");
    assert_eq!(first_metadata.group.as_deref(), Some("ai"));
    assert!(!first_metadata.requires_approval);
    assert_eq!(first_metadata.updated_by, "alice");

    let second = store
        .sign_next(
            &identity,
            metadata_operation_input(MetadataSpec {
                operation_id: "hop_meta_b",
                node_seq: 2,
                scope: "global",
                name: "demo",
                description: "second description",
                requires_approval: true,
                group: None,
                actor: "bob",
            }),
        )
        .expect("sign second");
    store.append_signed(&second).expect("append second");
    assert_eq!(store.materialize_secret_metadata().expect("materialize"), 1);
    assert_eq!(store.materialize_secret_metadata().expect("no-op"), 0);

    let second_metadata = store
        .get_materialized_secret_metadata("hmc_test", "global", "demo")
        .expect("get metadata")
        .expect("metadata exists");
    assert_eq!(second_metadata.description, "second description");
    assert_eq!(second_metadata.group, None);
    assert!(second_metadata.requires_approval);
    assert_eq!(second_metadata.updated_by, "bob");
    assert_eq!(second_metadata.last_position, 2);
    assert_eq!(second_metadata.last_operation_id, "hop_meta_b");
}

#[test]
fn peer_cursors_validate_hash_and_resume_after_acknowledged_position() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");
    let first = append_signed_operation(&store, &identity, "hop_a", 1, 1);
    let second = append_signed_operation(&store, &identity, "hop_b", 2, 2);

    let err = store
        .record_peer_cursor("hmn_peer", first.position, second.body_hash_b64.as_str())
        .expect_err("wrong hash must fail");
    assert!(err.to_string().contains("body hash mismatch"));

    let cursor = store
        .record_peer_cursor("hmn_peer", first.position, first.body_hash_b64.as_str())
        .expect("record cursor");
    assert_eq!(cursor.last_position, 1);

    let stored = store
        .get_peer_cursor("hmn_peer")
        .expect("get cursor")
        .expect("cursor exists");
    assert_eq!(stored.last_body_hash_b64, first.body_hash_b64);

    let catch_up = store
        .list_after(stored.last_position, 10)
        .expect("list catch up");
    assert_eq!(catch_up.len(), 1);
    assert_eq!(catch_up[0].body_hash_b64, second.body_hash_b64);
}

#[test]
fn materializes_secret_values_as_immutable_versions() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");

    let first = store
        .sign_next(
            &identity,
            value_operation_input_with_base("hop_val_a", 1, "api_key", "ciphertext-a", 0),
        )
        .expect("sign first");
    store.append_signed(&first).expect("append first");
    assert_eq!(store.materialize_secret_value_versions().expect("mat"), 1);

    let second = store
        .sign_next(
            &identity,
            value_operation_input_with_base("hop_val_b", 2, "api_key", "ciphertext-b", 1),
        )
        .expect("sign second");
    store.append_signed(&second).expect("append second");
    assert_eq!(store.materialize_secret_value_versions().expect("mat"), 1);
    assert_eq!(store.materialize_secret_value_versions().expect("no-op"), 0);

    let versions = store
        .list_secret_value_versions("hmc_test", "global", "demo", "api_key")
        .expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version_seq, 1);
    assert_eq!(
        versions[0].encrypted_value_json["ciphertext_b64"],
        "ciphertext-a"
    );
    assert_eq!(versions[1].version_seq, 2);
    assert_eq!(
        versions[1].encrypted_value_json["ciphertext_b64"],
        "ciphertext-b"
    );
    assert_eq!(versions[1].base_version_seq, 1);
    assert_eq!(versions[1].operation_id, "hop_val_b");
}

#[test]
fn detects_and_resolves_stale_value_write_collisions() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");
    let peer_identity = NodeIdentity::generate("hmn_b", "b").expect("node b");
    let first = store
        .sign_next(
            &identity,
            value_operation_input_with_base("hop_collision_a", 1, "api_key", "ciphertext-a", 0),
        )
        .expect("sign first");
    store.append_signed(&first).expect("append first");
    let stale = store
        .sign_next(
            &peer_identity,
            value_operation_input_for_node_with_base(
                "hop_collision_b",
                "hmn_b",
                1,
                "api_key",
                "ciphertext-b",
                0,
            ),
        )
        .expect("sign stale");
    store.append_signed(&stale).expect("append stale");

    assert_eq!(store.materialize_secret_value_versions().expect("mat"), 2);
    let versions = store
        .list_secret_value_versions("hmc_test", "global", "demo", "api_key")
        .expect("versions");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].operation_id, "hop_collision_a");

    let collisions = store
        .list_open_collisions("hmc_test")
        .expect("list collisions");
    assert_eq!(collisions.len(), 1);
    assert_eq!(collisions[0].incoming_operation_id, "hop_collision_b");
    assert_eq!(collisions[0].current_operation_id, "hop_collision_a");

    let incoming = store
        .get_by_operation_id("hop_collision_b")
        .expect("get incoming")
        .expect("incoming operation preserved");
    assert_eq!(
        incoming.payload_json["values"]["api_key"]["ciphertext_b64"],
        "ciphertext-b"
    );

    let resolution_operation = store
        .append_collision_resolution(
            &identity,
            collisions[0].collision_id.as_str(),
            "operator",
            "keep-current",
        )
        .expect("append resolution");
    assert_eq!(resolution_operation.op_type, "collision.resolved");
    assert_eq!(store.materialize_secret_value_versions().expect("mat"), 1);
    let resolved = store
        .get_collision(collisions[0].collision_id.as_str())
        .expect("get collision")
        .expect("collision");
    assert_eq!(resolved.state, "resolved");
    assert_eq!(
        resolved.resolution_operation_id.as_deref(),
        Some(resolution_operation.operation_id.as_str())
    );
    assert_eq!(
        store.list_open_collisions("hmc_test").expect("open").len(),
        0
    );
}

#[test]
fn quorum_collision_resolution_can_materialize_incoming_winner() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = LedgerStore::open(root.path()).expect("open ledger");
    let identity = NodeIdentity::generate("hmn_a", "a").expect("node a");
    let peer_identity = NodeIdentity::generate("hmn_b", "b").expect("node b");
    let first = store
        .sign_next(
            &identity,
            value_operation_input_with_base(
                "hop_quorum_collision_a",
                1,
                "api_key",
                "ciphertext-a",
                0,
            ),
        )
        .expect("sign first");
    store.append_signed(&first).expect("append first");
    let stale = store
        .sign_next(
            &peer_identity,
            value_operation_input_for_node_with_base(
                "hop_quorum_collision_b",
                "hmn_b",
                1,
                "api_key",
                "ciphertext-b",
                0,
            ),
        )
        .expect("sign stale");
    store.append_signed(&stale).expect("append stale");
    store
        .materialize_secret_value_versions()
        .expect("materialize collision");
    let collision = store
        .list_open_collisions("hmc_test")
        .expect("list collisions")
        .pop()
        .expect("collision");
    let agreement = json!({
        "kind": "collision_quorum_v1",
        "required_peer_acks": 1,
        "accepted": [{
            "peer_node_id": "hmn_b",
            "statement_hash_b64": "statement-hash",
            "signing_public_key_b64": "peer-public-key",
            "signature_b64": "peer-signature",
            "statement": {
                "version": "hem-collision-agreement-v1",
                "cluster_id": "hmc_test",
                "requester_node_id": "hmn_a",
                "approver_node_id": "hmn_b",
                "collision_id": collision.collision_id.as_str(),
                "incoming_operation_id": "hop_quorum_collision_b",
                "resolution": "accept-incoming"
            }
        }]
    });

    let resolution_operation = store
        .append_collision_resolution_with_agreement(
            &identity,
            collision.collision_id.as_str(),
            "operator",
            "accept-incoming",
            Some(agreement),
        )
        .expect("append quorum resolution");
    assert_eq!(resolution_operation.op_type, "collision.resolved");
    assert_eq!(
        resolution_operation.payload_json["agreement"]["kind"],
        "collision_quorum_v1"
    );
    store
        .materialize_secret_value_versions()
        .expect("materialize resolution");

    let versions = store
        .list_secret_value_versions("hmc_test", "global", "demo", "api_key")
        .expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].operation_id, "hop_quorum_collision_a");
    assert_eq!(versions[1].operation_id, "hop_quorum_collision_b");
    assert_eq!(
        versions[1].encrypted_value_json["ciphertext_b64"],
        "ciphertext-b"
    );
    assert_eq!(versions[1].base_version_seq, 1);
    let report = store.verify_integrity().expect("verify");
    assert!(report.ok, "{report:?}");
}

fn seeded_store(root: &std::path::Path) -> HemStore {
    HemStore::init(root, false).expect("init hem store");
    let store = HemStore::open(root).expect("open hem store");
    store
        .group_store()
        .expect("group store")
        .set_group("prod", "production secrets")
        .expect("set group");
    store
        .set_secret(SetSecretInput {
            scope: SecretScope::Global,
            name: "openai-prod".to_string(),
            values: HashMap::from([
                ("api-key".to_string(), "sk-live".to_string()),
                ("model".to_string(), "gpt-5".to_string()),
            ]),
            description: "prod model key".to_string(),
            requires_approval: true,
            group: Some("prod".to_string()),
            actor: "operator".to_string(),
        })
        .expect("set global secret");
    store
        .set_secret(SetSecretInput {
            scope: SecretScope::Project {
                project: "valhall".to_string(),
            },
            name: "github-token".to_string(),
            values: HashMap::from([("token".to_string(), "ghp-test".to_string())]),
            description: "project token".to_string(),
            requires_approval: false,
            group: None,
            actor: "operator".to_string(),
        })
        .expect("set project secret");
    store
        .grant_access(
            &SecretScope::Global,
            "openai-prod",
            &SecretScope::Project {
                project: "valhall".to_string(),
            },
            "smi",
            "operator",
        )
        .expect("grant");
    store
}

fn operation_input(operation_id: &str, node_seq: i64, version: i64) -> LedgerOperationInput {
    LedgerOperationInput {
        operation_id: operation_id.to_string(),
        cluster_id: "hmc_test".to_string(),
        node_id: "hmn_a".to_string(),
        node_seq,
        op_type: "secret.set".to_string(),
        payload_json: json!({
            "scope": "global",
            "name": "demo",
            "secret": "global/demo",
            "version": version,
        }),
        created_at: Utc::now(),
    }
}

fn value_operation_input(
    operation_id: &str,
    node_seq: i64,
    key: &str,
    ciphertext_b64: &str,
) -> LedgerOperationInput {
    LedgerOperationInput {
        operation_id: operation_id.to_string(),
        cluster_id: "hmc_test".to_string(),
        node_id: "hmn_a".to_string(),
        node_seq,
        op_type: "secret.value.set".to_string(),
        payload_json: json!({
            "scope": "global",
            "name": "demo",
            "values": {
                key: {
                    "alg": "xchacha20poly1305",
                    "key_id": "mk-test",
                    "nonce_b64": "nonce",
                    "ciphertext_b64": ciphertext_b64,
                }
            },
            "actor": "test",
        }),
        created_at: Utc::now(),
    }
}

fn value_operation_input_with_base(
    operation_id: &str,
    node_seq: i64,
    key: &str,
    ciphertext_b64: &str,
    base_version_seq: i64,
) -> LedgerOperationInput {
    value_operation_input_for_node_with_base(
        operation_id,
        "hmn_a",
        node_seq,
        key,
        ciphertext_b64,
        base_version_seq,
    )
}

fn value_operation_input_for_node_with_base(
    operation_id: &str,
    node_id: &str,
    node_seq: i64,
    key: &str,
    ciphertext_b64: &str,
    base_version_seq: i64,
) -> LedgerOperationInput {
    let mut input = value_operation_input(operation_id, node_seq, key, ciphertext_b64);
    input.node_id = node_id.to_string();
    input.payload_json["base_version_seq"] = json!(base_version_seq);
    input
}

struct MetadataSpec<'a> {
    operation_id: &'a str,
    node_seq: i64,
    scope: &'a str,
    name: &'a str,
    description: &'a str,
    requires_approval: bool,
    group: Option<&'a str>,
    actor: &'a str,
}

fn metadata_operation_input(spec: MetadataSpec<'_>) -> LedgerOperationInput {
    LedgerOperationInput {
        operation_id: spec.operation_id.to_string(),
        cluster_id: "hmc_test".to_string(),
        node_id: "hmn_a".to_string(),
        node_seq: spec.node_seq,
        op_type: "secret.metadata.set".to_string(),
        payload_json: json!({
            "scope": spec.scope,
            "name": spec.name,
            "description": spec.description,
            "requires_approval": spec.requires_approval,
            "group": spec.group,
            "actor": spec.actor,
        }),
        created_at: Utc::now(),
    }
}

fn append_signed_operation(
    store: &LedgerStore,
    identity: &NodeIdentity,
    operation_id: &str,
    node_seq: i64,
    version: i64,
) -> hem_core::LedgerOperation {
    let envelope = store
        .sign_next(identity, operation_input(operation_id, node_seq, version))
        .expect("sign");
    store.append_signed(&envelope).expect("append signed")
}

fn envelope_from_operation(operation: &LedgerOperation) -> LedgerOperationEnvelope {
    LedgerOperationEnvelope {
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
    }
}
