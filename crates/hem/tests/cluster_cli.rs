use std::{collections::HashMap, fs, process::Command};

use chrono::Utc;
use hem_core::{
    AuditStore, ClusterConfig, HemStore, LedgerOperationInput, LedgerStore, NodeIdentity,
    PeerConfig, SecretScope, SetSecretInput,
};
use serde_json::json;

#[test]
fn cluster_init_and_status_use_temp_hem_data_dir() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .arg("--label")
        .arg("local")
        .output()
        .expect("run cluster init");

    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let init_stdout = String::from_utf8_lossy(&init.stdout);
    assert!(
        init_stdout.contains("cluster_initialized=true"),
        "{init_stdout}"
    );
    assert!(data_dir.path().join("cluster.toml").exists());
    assert!(data_dir.path().join("node-identity.json").exists());

    let status = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("status")
        .output()
        .expect("run cluster status");

    assert!(
        status.status.success(),
        "cluster status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("cluster_enabled=true"),
        "{status_stdout}"
    );
    assert!(
        status_stdout.contains("node_id=hmn_local"),
        "{status_stdout}"
    );
    assert!(status_stdout.contains("peers=0"), "{status_stdout}");
}

#[test]
fn cluster_install_copies_artifacts_and_writes_launchd_supervisor() {
    let artifact_dir = tempfile::tempdir().expect("artifact tempdir");
    let prefix = tempfile::tempdir().expect("prefix tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");
    write_artifact_binaries(artifact_dir.path(), "v1");

    let install = Command::new(env!("CARGO_BIN_EXE_hem"))
        .arg("cluster")
        .arg("install")
        .arg("--artifact-dir")
        .arg(artifact_dir.path())
        .arg("--prefix")
        .arg(prefix.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--bind")
        .arg("127.0.0.1:50191")
        .arg("--supervisor")
        .arg("launchd")
        .arg("--force")
        .output()
        .expect("run cluster install");

    assert!(
        install.status.success(),
        "cluster install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );
    let stdout = String::from_utf8_lossy(&install.stdout);
    assert!(stdout.contains("cluster_installed=true"), "{stdout}");
    assert!(stdout.contains("install_mode=install"), "{stdout}");
    assert!(stdout.contains("supervisor_kind=launchd"), "{stdout}");
    assert!(stdout.contains("verify_health_command="), "{stdout}");
    assert!(
        stdout.contains("verify_cluster_status_command="),
        "{stdout}"
    );
    assert!(stdout.contains("verify_ledger_command="), "{stdout}");

    let hem_bin = prefix.path().join("bin/hem");
    let hemd_bin = prefix.path().join("bin/hemd");
    let env_file = prefix.path().join("etc/hem/hemd.env");
    let supervisor_file = prefix.path().join("supervisor/io.valhall.hemd.plist");
    let manifest = prefix.path().join("etc/hem/install-manifest.json");
    assert_eq!(fs::read_to_string(hem_bin).expect("hem bin"), "hem-v1");
    assert_eq!(fs::read_to_string(hemd_bin).expect("hemd bin"), "hemd-v1");
    let env_body = fs::read_to_string(env_file).expect("env file");
    assert!(env_body.contains("HEM_DATA_DIR="), "{env_body}");
    assert!(
        env_body.contains("VALHALL_HEMD_ENDPOINT=http://127.0.0.1:50191"),
        "{env_body}"
    );
    let supervisor_body = fs::read_to_string(supervisor_file).expect("supervisor file");
    assert!(supervisor_body.contains("--data-dir"), "{supervisor_body}");
    assert!(
        supervisor_body.contains(data_dir.path().to_string_lossy().as_ref()),
        "{supervisor_body}"
    );
    assert!(supervisor_body.contains("--bind"), "{supervisor_body}");
    let manifest_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest).expect("manifest")).expect("json");
    assert_eq!(manifest_json["mode"], "install");
    assert_eq!(manifest_json["supervisor_kind"], "launchd");
}

#[test]
fn cluster_rebuild_overwrites_install_and_backs_up_previous_binaries() {
    let artifact_v1 = tempfile::tempdir().expect("artifact v1");
    let artifact_v2 = tempfile::tempdir().expect("artifact v2");
    let prefix = tempfile::tempdir().expect("prefix tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");
    let backup_dir = tempfile::tempdir().expect("backup tempdir");
    write_artifact_binaries(artifact_v1.path(), "v1");
    write_artifact_binaries(artifact_v2.path(), "v2");

    let install = Command::new(env!("CARGO_BIN_EXE_hem"))
        .arg("cluster")
        .arg("install")
        .arg("--artifact-dir")
        .arg(artifact_v1.path())
        .arg("--prefix")
        .arg(prefix.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--force")
        .output()
        .expect("run cluster install");
    assert!(
        install.status.success(),
        "cluster install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );

    let rebuild = Command::new(env!("CARGO_BIN_EXE_hem"))
        .arg("cluster")
        .arg("rebuild")
        .arg("--artifact-dir")
        .arg(artifact_v2.path())
        .arg("--prefix")
        .arg(prefix.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--backup-dir")
        .arg(backup_dir.path())
        .output()
        .expect("run cluster rebuild");

    assert!(
        rebuild.status.success(),
        "cluster rebuild failed: {}",
        String::from_utf8_lossy(&rebuild.stderr)
    );
    let stdout = String::from_utf8_lossy(&rebuild.stdout);
    assert!(stdout.contains("cluster_installed=true"), "{stdout}");
    assert!(stdout.contains("install_mode=rebuild"), "{stdout}");
    assert!(stdout.contains("backup_dir="), "{stdout}");
    assert_eq!(
        fs::read_to_string(prefix.path().join("bin/hem")).expect("hem bin"),
        "hem-v2"
    );
    assert_eq!(
        fs::read_to_string(prefix.path().join("bin/hemd")).expect("hemd bin"),
        "hemd-v2"
    );
    assert_eq!(
        fs::read_to_string(backup_dir.path().join("hem")).expect("hem backup"),
        "hem-v1"
    );
    assert_eq!(
        fs::read_to_string(backup_dir.path().join("hemd")).expect("hemd backup"),
        "hemd-v1"
    );
}

#[test]
fn cluster_peers_do_not_require_daemon() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let peers = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("peers")
        .output()
        .expect("run cluster peers");

    assert!(
        peers.status.success(),
        "cluster peers failed: {}",
        String::from_utf8_lossy(&peers.stderr)
    );
    let peers_stdout = String::from_utf8_lossy(&peers.stdout);
    assert!(peers_stdout.contains("peers=0"), "{peers_stdout}");
}

#[test]
fn policy_and_lease_commands_manage_local_store() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let set_scope = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("policy")
        .arg("set")
        .arg("peer_quorum")
        .arg("--scope")
        .arg("global")
        .output()
        .expect("policy set");
    assert!(
        set_scope.status.success(),
        "policy set failed: {}",
        String::from_utf8_lossy(&set_scope.stderr)
    );
    let set_stdout = String::from_utf8_lossy(&set_scope.stdout);
    assert!(set_stdout.contains("policy_set=true"), "{set_stdout}");
    assert!(set_stdout.contains("tier=peer_quorum"), "{set_stdout}");

    let downgrade = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("policy")
        .arg("set")
        .arg("local_logged")
        .arg("--scope")
        .arg("global")
        .output()
        .expect("policy downgrade");
    assert!(!downgrade.status.success(), "downgrade must fail");
    assert!(
        String::from_utf8_lossy(&downgrade.stderr).contains("--allow-downgrade"),
        "{}",
        String::from_utf8_lossy(&downgrade.stderr)
    );

    let get_secret = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("policy")
        .arg("get")
        .arg("--secret")
        .arg("global/demo")
        .output()
        .expect("policy get");
    assert!(
        get_secret.status.success(),
        "policy get failed: {}",
        String::from_utf8_lossy(&get_secret.stderr)
    );
    let get_stdout = String::from_utf8_lossy(&get_secret.stdout);
    assert!(get_stdout.contains("target=global/demo"), "{get_stdout}");
    assert!(
        get_stdout.contains("effective_tier=peer_quorum"),
        "{get_stdout}"
    );

    let issue = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("lease")
        .arg("issue")
        .arg("global/demo")
        .arg("--requester")
        .arg("token:abc")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--uses")
        .arg("2")
        .arg("--ttl-seconds")
        .arg("600")
        .output()
        .expect("lease issue");
    assert!(
        issue.status.success(),
        "lease issue failed: {}",
        String::from_utf8_lossy(&issue.stderr)
    );
    let issue_stdout = String::from_utf8_lossy(&issue.stdout);
    assert!(issue_stdout.contains("lease_issued=true"), "{issue_stdout}");
    assert!(issue_stdout.contains("remaining_uses=2"), "{issue_stdout}");
    let lease_id = value_for_key(&issue_stdout, "lease_id").expect("lease id");

    let consume = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("lease")
        .arg("consume")
        .arg("global/demo")
        .arg("--requester")
        .arg("token:abc")
        .arg("--node-id")
        .arg("hmn_local")
        .output()
        .expect("lease consume");
    assert!(
        consume.status.success(),
        "lease consume failed: {}",
        String::from_utf8_lossy(&consume.stderr)
    );
    let consume_stdout = String::from_utf8_lossy(&consume.stdout);
    assert!(
        consume_stdout.contains("lease_consumed=true"),
        "{consume_stdout}"
    );
    assert!(
        consume_stdout.contains("remaining_uses=1"),
        "{consume_stdout}"
    );

    let revoke = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("lease")
        .arg("revoke")
        .arg(lease_id)
        .arg("--actor")
        .arg("hem-cli")
        .output()
        .expect("lease revoke");
    assert!(
        revoke.status.success(),
        "lease revoke failed: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    let revoke_stdout = String::from_utf8_lossy(&revoke.stdout);
    assert!(
        revoke_stdout.contains("lease_revoked=true"),
        "{revoke_stdout}"
    );
    assert!(
        revoke_stdout.contains("revoked_by=hem-cli"),
        "{revoke_stdout}"
    );

    let list = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("lease")
        .arg("list")
        .output()
        .expect("lease list");
    assert!(
        list.status.success(),
        "lease list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("leases=1"), "{list_stdout}");
    assert!(list_stdout.contains("revoked_by=hem-cli"), "{list_stdout}");
}

#[test]
fn cluster_invite_and_join_create_signed_peer_config() {
    let inviter_dir = tempfile::tempdir().expect("inviter tempdir");
    let joiner_dir = tempfile::tempdir().expect("joiner tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", inviter_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_inviter")
        .arg("--listen")
        .arg("http://127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .arg("--label")
        .arg("inviter")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let invite = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", inviter_dir.path())
        .arg("cluster")
        .arg("invite")
        .arg("--ttl-seconds")
        .arg("300")
        .output()
        .expect("run cluster invite");
    assert!(
        invite.status.success(),
        "cluster invite failed: {}",
        String::from_utf8_lossy(&invite.stderr)
    );
    let invite_stdout = String::from_utf8_lossy(&invite.stdout);
    let invite_token = value_for_key(&invite_stdout, "invite").expect("invite token");
    assert!(invite_token.starts_with("hem-invite-v1."));

    let join = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", joiner_dir.path())
        .arg("cluster")
        .arg("join")
        .arg(invite_token)
        .arg("--node-id")
        .arg("hmn_joiner")
        .arg("--listen")
        .arg("http://127.0.0.1:50192")
        .arg("--label")
        .arg("joiner")
        .output()
        .expect("run cluster join");
    assert!(
        join.status.success(),
        "cluster join failed: {}",
        String::from_utf8_lossy(&join.stderr)
    );
    let join_stdout = String::from_utf8_lossy(&join.stdout);
    assert!(join_stdout.contains("cluster_joined=true"), "{join_stdout}");
    assert!(
        join_stdout.contains("peer_node_id=hmn_inviter"),
        "{join_stdout}"
    );

    let inviter_config =
        ClusterConfig::load(&inviter_dir.path().join("cluster.toml")).expect("inviter config");
    let joiner_config =
        ClusterConfig::load(&joiner_dir.path().join("cluster.toml")).expect("joiner config");
    assert_eq!(joiner_config.cluster_id, inviter_config.cluster_id);
    assert_eq!(joiner_config.node_id, "hmn_joiner");
    assert_eq!(joiner_config.listen, "http://127.0.0.1:50192");
    assert_eq!(joiner_config.peers.len(), 1);
    assert_eq!(joiner_config.peers[0].node_id, "hmn_inviter");
    assert_eq!(joiner_config.peers[0].endpoint, "http://127.0.0.1:50191");
    assert_eq!(
        joiner_config.peers[0].public_key,
        NodeIdentity::load(&inviter_dir.path().join("node-identity.json"))
            .expect("inviter identity")
            .signing_public_key_b64
    );
}

#[test]
fn cluster_join_rejects_tampered_invite() {
    let inviter_dir = tempfile::tempdir().expect("inviter tempdir");
    let joiner_dir = tempfile::tempdir().expect("joiner tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", inviter_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_inviter")
        .arg("--listen")
        .arg("http://127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let invite = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", inviter_dir.path())
        .arg("cluster")
        .arg("invite")
        .output()
        .expect("run cluster invite");
    assert!(
        invite.status.success(),
        "cluster invite failed: {}",
        String::from_utf8_lossy(&invite.stderr)
    );
    let invite_stdout = String::from_utf8_lossy(&invite.stdout);
    let mut invite_token = value_for_key(&invite_stdout, "invite")
        .expect("invite token")
        .to_string();
    let last = invite_token.pop().expect("invite char");
    invite_token.push(if last == 'A' { 'B' } else { 'A' });

    let join = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", joiner_dir.path())
        .arg("cluster")
        .arg("join")
        .arg(invite_token)
        .arg("--node-id")
        .arg("hmn_joiner")
        .arg("--listen")
        .arg("http://127.0.0.1:50192")
        .output()
        .expect("run cluster join");
    assert!(!join.status.success(), "tampered invite should fail");
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(
        stderr.contains("invite") || stderr.contains("signature"),
        "{stderr}"
    );
}

#[test]
fn cluster_peer_add_update_remove_manage_static_config() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("http://127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let peer = NodeIdentity::generate("hmn_peer", "peer").expect("peer identity");
    let add = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("peer")
        .arg("add")
        .arg("--node-id")
        .arg("hmn_peer")
        .arg("--endpoint")
        .arg("http://127.0.0.1:50192")
        .arg("--public-key")
        .arg(peer.signing_public_key_b64.as_str())
        .output()
        .expect("run peer add");
    assert!(
        add.status.success(),
        "peer add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    let add_stdout = String::from_utf8_lossy(&add.stdout);
    assert!(add_stdout.contains("peer_added=true"), "{add_stdout}");

    let update = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("peer")
        .arg("update")
        .arg("hmn_peer")
        .arg("--endpoint")
        .arg("http://127.0.0.1:50193")
        .output()
        .expect("run peer update");
    assert!(
        update.status.success(),
        "peer update failed: {}",
        String::from_utf8_lossy(&update.stderr)
    );
    let update_stdout = String::from_utf8_lossy(&update.stdout);
    assert!(
        update_stdout.contains("peer_updated=true"),
        "{update_stdout}"
    );

    let config = ClusterConfig::load(&data_dir.path().join("cluster.toml")).expect("config");
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].endpoint, "http://127.0.0.1:50193");
    assert_eq!(config.peers[0].public_key, peer.signing_public_key_b64);

    let remove = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("peer")
        .arg("remove")
        .arg("hmn_peer")
        .output()
        .expect("run peer remove");
    assert!(
        remove.status.success(),
        "peer remove failed: {}",
        String::from_utf8_lossy(&remove.stderr)
    );
    let remove_stdout = String::from_utf8_lossy(&remove.stdout);
    assert!(
        remove_stdout.contains("peer_removed=true"),
        "{remove_stdout}"
    );

    let config = ClusterConfig::load(&data_dir.path().join("cluster.toml")).expect("config");
    assert!(config.peers.is_empty());
}

#[test]
fn cluster_sync_once_dry_run_reports_no_peers_without_daemon() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("http://127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let sync = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("sync")
        .arg("--once")
        .arg("--dry-run")
        .output()
        .expect("run sync");
    assert!(
        sync.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let stdout = String::from_utf8_lossy(&sync.stdout);
    assert!(stdout.contains("sync_dry_run=true"), "{stdout}");
    assert!(stdout.contains("sync_peers=0"), "{stdout}");
}

#[test]
fn cluster_health_reports_healthy_local_node() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (_identity, _peer) = init_cluster_for_health(data_dir.path(), false);

    let health = cluster_health(data_dir.path());
    assert!(
        health.status.success(),
        "health failed: {}",
        String::from_utf8_lossy(&health.stderr)
    );
    let stdout = String::from_utf8_lossy(&health.stdout);
    assert!(stdout.contains("cluster_health_status=healthy"), "{stdout}");
    assert!(stdout.contains("health_exit_code=0"), "{stdout}");
    assert!(stdout.contains("configured_peers=0"), "{stdout}");
}

#[test]
fn cluster_health_reports_lagging_peer_cursor() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (identity, peer) = init_cluster_for_health(data_dir.path(), true);
    let ledger = LedgerStore::open(data_dir.path()).expect("ledger");
    append_test_metadata_operation(
        &ledger,
        &identity,
        "hmc_health",
        "hop_health_lag",
        1,
        "lag",
        "test",
    );
    ledger
        .record_peer_cursor(peer.node_id.as_str(), 0, "")
        .expect("record lagging cursor");

    let health = cluster_health(data_dir.path());
    assert_eq!(
        health.status.code(),
        Some(1),
        "health status stderr={} stdout={}",
        String::from_utf8_lossy(&health.stderr),
        String::from_utf8_lossy(&health.stdout)
    );
    let stdout = String::from_utf8_lossy(&health.stdout);
    assert!(stdout.contains("cluster_health_status=warning"), "{stdout}");
    assert!(stdout.contains("lagging_peers=1"), "{stdout}");
    assert!(
        stdout.contains("peer_health node_id=hmn_peer status=lagging"),
        "{stdout}"
    );
}

#[test]
fn cluster_health_reports_offline_peer_without_cursor() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (identity, _peer) = init_cluster_for_health(data_dir.path(), true);
    let ledger = LedgerStore::open(data_dir.path()).expect("ledger");
    append_test_metadata_operation(
        &ledger,
        &identity,
        "hmc_health",
        "hop_health_offline",
        1,
        "offline",
        "test",
    );

    let health = cluster_health(data_dir.path());
    assert_eq!(health.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&health.stdout);
    assert!(stdout.contains("offline_peers=1"), "{stdout}");
    assert!(
        stdout.contains("peer_health node_id=hmn_peer status=offline"),
        "{stdout}"
    );
}

#[test]
fn cluster_health_reports_divergent_peer_cursor() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (identity, peer) = init_cluster_for_health(data_dir.path(), true);
    let ledger = LedgerStore::open(data_dir.path()).expect("ledger");
    append_test_metadata_operation(
        &ledger,
        &identity,
        "hmc_health",
        "hop_health_divergent",
        1,
        "divergent",
        "test",
    );
    let latest_hash = ledger
        .latest_body_hash()
        .expect("latest hash")
        .expect("hash");
    ledger
        .record_peer_cursor(peer.node_id.as_str(), 1, latest_hash.as_str())
        .expect("record cursor");
    let conn = rusqlite::Connection::open(ledger.path()).expect("open sqlite");
    conn.execute(
        "UPDATE ledger_peer_cursors SET last_body_hash_b64 = 'AAAA' WHERE peer_node_id = 'hmn_peer'",
        [],
    )
    .expect("corrupt cursor");

    let health = cluster_health(data_dir.path());
    assert_eq!(health.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&health.stdout);
    assert!(
        stdout.contains("cluster_health_status=critical"),
        "{stdout}"
    );
    assert!(stdout.contains("divergent_peers=1"), "{stdout}");
    assert!(
        stdout.contains("peer_health node_id=hmn_peer status=divergent"),
        "{stdout}"
    );
}

#[test]
fn cluster_health_reports_open_collisions() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (_identity, _peer) = init_cluster_for_health(data_dir.path(), false);
    create_test_collision(data_dir.path());

    let health = cluster_health(data_dir.path());
    assert_eq!(health.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&health.stdout);
    assert!(stdout.contains("cluster_health_status=warning"), "{stdout}");
    assert!(stdout.contains("collisions=1"), "{stdout}");
}

#[test]
fn cluster_bootstrap_ledger_fails_when_peer_filter_matches_no_configured_peer() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let bootstrap = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("bootstrap-ledger")
        .arg("--peer")
        .arg("hmn_missing")
        .output()
        .expect("run bootstrap-ledger");
    assert!(!bootstrap.status.success(), "bootstrap must fail");
    assert!(
        String::from_utf8_lossy(&bootstrap.stderr)
            .contains("peer filter matched no configured peers"),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
}

#[test]
fn cluster_migrate_dry_run_reports_local_store_counts() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    HemStore::init(data_dir.path(), false).expect("init hem store");
    let store = HemStore::open(data_dir.path()).expect("open hem store");
    store
        .set_secret(SetSecretInput {
            scope: SecretScope::Global,
            name: "migrated-secret".to_string(),
            values: HashMap::from([("token".to_string(), "secret-value".to_string())]),
            description: "migrated by cli".to_string(),
            requires_approval: false,
            group: None,
            actor: "test".to_string(),
        })
        .expect("set secret");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let migrate = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("migrate")
        .arg("--dry-run")
        .output()
        .expect("run cluster migrate dry-run");
    assert!(
        migrate.status.success(),
        "cluster migrate dry-run failed: {}",
        String::from_utf8_lossy(&migrate.stderr)
    );
    let stdout = String::from_utf8_lossy(&migrate.stdout);
    assert!(stdout.contains("migration_dry_run=true"), "{stdout}");
    assert!(stdout.contains("secrets_scanned=1"), "{stdout}");
    assert!(stdout.contains("value_keys_scanned=1"), "{stdout}");
    assert!(stdout.contains("operations_planned=2"), "{stdout}");
    assert!(stdout.contains("operations_appended=0"), "{stdout}");
}

#[test]
fn cluster_rewrap_values_dry_run_reports_legacy_values() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    HemStore::init(data_dir.path(), false).expect("init hem store");
    let store = HemStore::open(data_dir.path()).expect("open hem store");
    store
        .set_secret(SetSecretInput {
            scope: SecretScope::Global,
            name: "legacy-secret".to_string(),
            values: HashMap::from([("token".to_string(), "secret-value".to_string())]),
            description: "legacy by cli".to_string(),
            requires_approval: false,
            group: None,
            actor: "test".to_string(),
        })
        .expect("set secret");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let migrate = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("migrate")
        .output()
        .expect("run cluster migrate");
    assert!(
        migrate.status.success(),
        "cluster migrate failed: {}",
        String::from_utf8_lossy(&migrate.stderr)
    );

    let rewrap = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("rewrap-values")
        .arg("--dry-run")
        .output()
        .expect("run cluster rewrap-values dry-run");
    assert!(
        rewrap.status.success(),
        "cluster rewrap-values dry-run failed: {}",
        String::from_utf8_lossy(&rewrap.stderr)
    );
    let stdout = String::from_utf8_lossy(&rewrap.stdout);
    assert!(stdout.contains("rewrap_dry_run=true"), "{stdout}");
    assert!(stdout.contains("recipients=1"), "{stdout}");
    assert!(stdout.contains("values_scanned=1"), "{stdout}");
    assert!(stdout.contains("values_rewrapped=1"), "{stdout}");
    assert!(stdout.contains("operations_planned=1"), "{stdout}");
    assert!(stdout.contains("operations_appended=0"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn cluster_verify_reports_unsafe_permissions_and_writes_audit_entry() {
    use std::os::unix::fs::PermissionsExt;

    let data_dir = tempfile::tempdir().expect("tempdir");
    HemStore::init(data_dir.path(), false).expect("init hem store");
    let unsafe_file = data_dir
        .path()
        .join("secrets")
        .join("global")
        .join("leaky.json");
    std::fs::write(unsafe_file.as_path(), "{}").expect("write unsafe file");
    std::fs::set_permissions(
        unsafe_file.as_path(),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod unsafe file");

    let verify = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("verify")
        .output()
        .expect("run cluster verify");

    assert_eq!(verify.status.code(), Some(2), "verify should fail closed");
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("ledger_ok=true"), "{stdout}");
    assert!(stdout.contains("data_dir_security_ok=false"), "{stdout}");
    assert!(stdout.contains("security_issue"), "{stdout}");
    assert!(stdout.contains("leaky.json"), "{stdout}");

    let entries = AuditStore::open(data_dir.path())
        .expect("audit store")
        .list(None, None, None, 10)
        .expect("list audit");
    assert!(
        entries.iter().any(|entry| {
            entry.action == "cluster.verify.security"
                && entry.result == "unsafe_permissions"
                && entry.details.contains("issues=")
        }),
        "{entries:?}"
    );
}

#[test]
fn cluster_fork_replay_cli_fails_closed_without_checkpoint_and_confirmation() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let missing_checkpoint = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("fork")
        .arg("--parent-checkpoint")
        .arg("hcp_missing")
        .arg("--reason")
        .arg("missing checkpoint")
        .output()
        .expect("run fork");
    assert!(
        !missing_checkpoint.status.success(),
        "fork with missing checkpoint must fail"
    );
    assert!(
        String::from_utf8_lossy(&missing_checkpoint.stderr).contains("checkpoint not found"),
        "{}",
        String::from_utf8_lossy(&missing_checkpoint.stderr)
    );

    let unsafe_replay = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("replay-fork")
        .arg("hfork_missing")
        .output()
        .expect("run replay fork");
    assert!(
        !unsafe_replay.status.success(),
        "replay without confirmation must fail"
    );
    assert!(
        String::from_utf8_lossy(&unsafe_replay.stderr).contains("--confirm-rewind"),
        "{}",
        String::from_utf8_lossy(&unsafe_replay.stderr)
    );
}

#[test]
fn cluster_replay_fork_rebuilds_materializers_and_verify_reports_replay() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let identity =
        NodeIdentity::load(&data_dir.path().join("node-identity.json")).expect("identity");
    let config = ClusterConfig::load(&data_dir.path().join("cluster.toml")).expect("config");
    let ledger = LedgerStore::open(data_dir.path()).expect("ledger");
    append_test_metadata_operation(
        &ledger,
        &identity,
        config.cluster_id.as_str(),
        "hop_cli_replay_before",
        1,
        "before fork",
        "alice",
    );
    let checkpoint = ledger
        .create_checkpoint(&identity, config.cluster_id.as_str(), 1)
        .expect("checkpoint");
    append_test_metadata_operation(
        &ledger,
        &identity,
        config.cluster_id.as_str(),
        "hop_cli_replay_bad",
        2,
        "bad state",
        "mallory",
    );
    ledger
        .materialize_secret_metadata()
        .expect("materialize bad");

    let fork = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("fork")
        .arg("--parent-checkpoint")
        .arg(checkpoint.body.checkpoint_id.as_str())
        .arg("--reason")
        .arg("rewind bad state")
        .output()
        .expect("run cluster fork");
    assert!(
        fork.status.success(),
        "fork failed: {}",
        String::from_utf8_lossy(&fork.stderr)
    );
    let fork_stdout = String::from_utf8_lossy(&fork.stdout);
    let fork_id = value_for_key(&fork_stdout, "fork_id").expect("fork id");

    append_test_metadata_operation(
        &ledger,
        &identity,
        config.cluster_id.as_str(),
        "hop_cli_replay_after",
        4,
        "after fork",
        "alice",
    );

    let replay = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("replay-fork")
        .arg(fork_id)
        .arg("--confirm-rewind")
        .arg(fork_id)
        .arg("--backup-confirmed")
        .arg("backup://cluster-cli-test")
        .output()
        .expect("run replay fork");
    assert!(
        replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay_stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay_stdout.contains("fork_replay_executed=true"),
        "{replay_stdout}"
    );
    assert!(
        replay_stdout.contains("operations_skipped=2"),
        "{replay_stdout}"
    );

    let metadata = ledger
        .get_materialized_secret_metadata(config.cluster_id.as_str(), "global", "demo")
        .expect("metadata")
        .expect("metadata exists");
    assert_eq!(metadata.description, "after fork");
    assert_eq!(metadata.last_operation_id, "hop_cli_replay_after");

    let verify = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("verify")
        .output()
        .expect("run verify");
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(verify_stdout.contains("ledger_ok=true"), "{verify_stdout}");
    assert!(
        verify_stdout.contains("fork_replays_declared=1"),
        "{verify_stdout}"
    );
}

fn value_for_key<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
}

fn write_artifact_binaries(artifact_dir: &std::path::Path, version: &str) {
    fs::write(artifact_dir.join("hem"), format!("hem-{version}")).expect("write hem artifact");
    fs::write(artifact_dir.join("hemd"), format!("hemd-{version}")).expect("write hemd artifact");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(artifact_dir.join("hem"), fs::Permissions::from_mode(0o755))
            .expect("chmod hem artifact");
        fs::set_permissions(artifact_dir.join("hemd"), fs::Permissions::from_mode(0o755))
            .expect("chmod hemd artifact");
    }
}

fn init_cluster_for_health(
    data_dir: &std::path::Path,
    with_peer: bool,
) -> (NodeIdentity, NodeIdentity) {
    HemStore::init(data_dir, false).expect("init store");
    let identity = NodeIdentity::generate("hmn_local", "local").expect("identity");
    let peer = NodeIdentity::generate("hmn_peer", "peer").expect("peer identity");
    let peers = if with_peer {
        vec![PeerConfig {
            node_id: peer.node_id.clone(),
            endpoint: "http://127.0.0.1:59999".to_string(),
            public_key: peer.signing_public_key_b64.clone(),
            wrap_public_key: peer.wrap_public_key_b64.clone(),
        }]
    } else {
        Vec::new()
    };
    ClusterConfig {
        enabled: true,
        cluster_id: "hmc_health".to_string(),
        node_id: identity.node_id.clone(),
        listen: "127.0.0.1:50191".to_string(),
        quorum: if with_peer { 2 } else { 1 },
        master_node_id: Some(identity.node_id.clone()),
        peers,
    }
    .save(&data_dir.join("cluster.toml"))
    .expect("save config");
    identity
        .save(&data_dir.join("node-identity.json"))
        .expect("save identity");
    (identity, peer)
}

fn cluster_health(data_dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir)
        .arg("cluster")
        .arg("health")
        .output()
        .expect("run cluster health")
}

fn append_test_metadata_operation(
    ledger: &LedgerStore,
    identity: &NodeIdentity,
    cluster_id: &str,
    operation_id: &str,
    node_seq: i64,
    description: &str,
    actor: &str,
) {
    let envelope = ledger
        .sign_next(
            identity,
            LedgerOperationInput {
                operation_id: operation_id.to_string(),
                cluster_id: cluster_id.to_string(),
                node_id: identity.node_id.clone(),
                node_seq,
                op_type: "secret.metadata.set".to_string(),
                payload_json: json!({
                    "scope": "global",
                    "name": "demo",
                    "description": description,
                    "requires_approval": false,
                    "group": null,
                    "actor": actor,
                }),
                created_at: Utc::now(),
            },
        )
        .expect("sign metadata operation");
    ledger
        .append_signed(&envelope)
        .expect("append metadata operation");
}

#[test]
fn cluster_lists_and_resolves_collisions_without_daemon() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("1")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    create_test_collision(data_dir.path());

    let list = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("collisions")
        .output()
        .expect("run cluster collisions");
    assert!(
        list.status.success(),
        "cluster collisions failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("collisions=1"), "{list_stdout}");
    assert!(
        list_stdout.contains("incoming_operation=hop_cli_collision_b"),
        "{list_stdout}"
    );

    let collision_id = list_stdout
        .lines()
        .find_map(|line| line.strip_prefix("collision id="))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("collision id")
        .to_string();
    let resolve = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("resolve-collision")
        .arg(collision_id.as_str())
        .arg("--resolution")
        .arg("keep-current")
        .arg("--actor")
        .arg("test-operator")
        .output()
        .expect("run cluster resolve-collision");
    assert!(
        resolve.status.success(),
        "cluster resolve-collision failed: {}",
        String::from_utf8_lossy(&resolve.stderr)
    );
    let resolve_stdout = String::from_utf8_lossy(&resolve.stdout);
    assert!(
        resolve_stdout.contains("collision_resolved=true"),
        "{resolve_stdout}"
    );
    assert!(
        resolve_stdout.contains("operation_type=collision.resolved"),
        "{resolve_stdout}"
    );

    let relist = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("collisions")
        .output()
        .expect("rerun cluster collisions");
    assert!(
        relist.status.success(),
        "cluster collisions failed after resolve: {}",
        String::from_utf8_lossy(&relist.stderr)
    );
    let relist_stdout = String::from_utf8_lossy(&relist.stdout);
    assert!(relist_stdout.contains("collisions=0"), "{relist_stdout}");
}

#[test]
fn cluster_resolve_collision_requires_quorum_unless_allowed_local() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let init = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("init")
        .arg("--node-id")
        .arg("hmn_local")
        .arg("--listen")
        .arg("127.0.0.1:50191")
        .arg("--quorum")
        .arg("2")
        .output()
        .expect("run cluster init");
    assert!(
        init.status.success(),
        "cluster init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    create_test_collision(data_dir.path());
    let list = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("collisions")
        .output()
        .expect("run cluster collisions");
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    let collision_id = list_stdout
        .lines()
        .find_map(|line| line.strip_prefix("collision id="))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("collision id")
        .to_string();

    let rejected = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("resolve-collision")
        .arg(collision_id.as_str())
        .arg("--resolution")
        .arg("keep-current")
        .output()
        .expect("run rejected resolve-collision");
    assert!(
        !rejected.status.success(),
        "quorum resolution should fail without peers"
    );
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        rejected_stderr.contains("requires 1 reachable peer approval"),
        "{rejected_stderr}"
    );

    let allowed = Command::new(env!("CARGO_BIN_EXE_hem"))
        .env("HEM_DATA_DIR", data_dir.path())
        .arg("cluster")
        .arg("resolve-collision")
        .arg(collision_id.as_str())
        .arg("--resolution")
        .arg("keep-current")
        .arg("--allow-local")
        .output()
        .expect("run local resolve-collision");
    assert!(
        allowed.status.success(),
        "allow-local resolve failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

fn create_test_collision(data_dir: &std::path::Path) {
    let config = ClusterConfig::load(&data_dir.join("cluster.toml")).expect("load config");
    let identity = NodeIdentity::load(&data_dir.join("node-identity.json")).expect("load identity");
    let peer_identity = NodeIdentity::generate("hmn_peer", "peer").expect("peer identity");
    let ledger = LedgerStore::open(data_dir).expect("open ledger");
    let first = ledger
        .sign_next(
            &identity,
            value_operation_input(
                "hop_cli_collision_a",
                config.cluster_id.as_str(),
                identity.node_id.as_str(),
                1,
                "ciphertext-a",
                0,
            ),
        )
        .expect("sign first");
    ledger.append_signed(&first).expect("append first");
    let stale = ledger
        .sign_next(
            &peer_identity,
            value_operation_input(
                "hop_cli_collision_b",
                config.cluster_id.as_str(),
                peer_identity.node_id.as_str(),
                1,
                "ciphertext-b",
                0,
            ),
        )
        .expect("sign stale");
    ledger.append_signed(&stale).expect("append stale");
}

fn value_operation_input(
    operation_id: &str,
    cluster_id: &str,
    node_id: &str,
    node_seq: i64,
    ciphertext_b64: &str,
    base_version_seq: i64,
) -> LedgerOperationInput {
    LedgerOperationInput {
        operation_id: operation_id.to_string(),
        cluster_id: cluster_id.to_string(),
        node_id: node_id.to_string(),
        node_seq,
        op_type: "secret.value.set".to_string(),
        payload_json: json!({
            "scope": "global",
            "name": "demo",
            "values": {
                "api_key": {
                    "alg": "test",
                    "ciphertext_b64": ciphertext_b64,
                    "nonce_b64": "nonce",
                    "key_id": "test",
                }
            },
            "base_version_seq": base_version_seq,
            "actor": "cluster-cli-test",
        }),
        created_at: Utc::now(),
    }
}
