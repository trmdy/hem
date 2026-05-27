use std::process::Command;

use hem_core::{ClusterConfig, HemStore, NodeIdentity, PeerConfig};

#[test]
fn once_reports_cluster_identity_when_cluster_config_is_enabled() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    HemStore::init(data_dir.path(), false).expect("init store");

    let config = ClusterConfig {
        enabled: true,
        cluster_id: "hmc_test".to_string(),
        node_id: "hmn_local".to_string(),
        listen: "127.0.0.1:0".to_string(),
        quorum: 1,
        master_node_id: Some("hmn_local".to_string()),
        peers: vec![PeerConfig {
            node_id: "hmn_peer".to_string(),
            endpoint: "https://peer.example:50191".to_string(),
            public_key: "peer-public-key".to_string(),
            wrap_public_key: None,
        }],
    };
    config
        .save(&data_dir.path().join("cluster.toml"))
        .expect("save cluster config");
    NodeIdentity::generate("hmn_local", "local")
        .expect("generate identity")
        .save(&data_dir.path().join("node-identity.json"))
        .expect("save identity");

    let output = Command::new(env!("CARGO_BIN_EXE_hemd"))
        .arg("--once")
        .arg("--data-dir")
        .arg(data_dir.path())
        .output()
        .expect("run hemd");

    assert!(
        output.status.success(),
        "hemd failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cluster_enabled=true"), "{stdout}");
    assert!(stdout.contains("cluster_node_id=hmn_local"), "{stdout}");
    assert!(stdout.contains("cluster_peers=1"), "{stdout}");
}
