use hem_net::{Mesh, MeshConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MeshConfig::from_env().unwrap_or_default();
    if let Ok(url) = std::env::var("VALHALL_NET_TEST_NATS_URL") {
        config.nats_url = url;
    }

    let mesh = Mesh::connect("example-daemon", config).await?;

    let subject = "valhall.example.mesh_quickstart";
    mesh.emit(subject, br#"{"event":"hello"}"#).await?;
    let _ = mesh.request(subject, b"ping").await.ok();

    mesh.shutdown().await?;
    Ok(())
}
