use std::time::Duration;

use tokio::sync::mpsc;
use tonic_health::pb::{HealthCheckRequest, HealthCheckResponse};
use valhall_net::{Mesh, MeshConfig};

const REQUEST_SUBJECT: &str = "valhall.test.barebones.echo";
const EVENT_SUBJECT: &str = "valhall.test.barebones.received";
const HEALTH_SERVICE_NAME: &str = "valhall.barebones.v1.Mesh";
const HEALTH_METHOD_PATH: &str = "/grpc.health.v1.Health/Check";

fn nats_url() -> String {
    std::env::var("VALHALL_NET_TEST_NATS_URL")
        .or_else(|_| std::env::var("VALHALL_NET_NATS_URL"))
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

fn grpc_endpoint() -> String {
    let addr = std::env::var("VALHALL_BAREBONES_GRPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50071".to_string());
    format!("http://{addr}")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MeshConfig {
        nats_url: nats_url(),
        ..MeshConfig::default()
    };
    config
        .service_endpoints
        .insert("barebones".to_string(), grpc_endpoint());

    let mesh = Mesh::connect("barebones-client", config).await?;

    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let subscription = mesh
        .on(EVENT_SUBJECT, move |event| {
            let _ = events_tx.send(event);
        })
        .await?;

    let payload = b"hello-from-client";
    let response = mesh.request(REQUEST_SUBJECT, payload).await?;
    println!(
        "request_reply_response={}",
        String::from_utf8_lossy(&response)
    );

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await?
        .ok_or("event channel closed before receiving message")?;
    println!("event_subject={}", event.subject);
    println!("event_payload={}", String::from_utf8_lossy(&event.payload));

    let health_req = HealthCheckRequest {
        service: HEALTH_SERVICE_NAME.to_string(),
    };
    let health_resp: HealthCheckResponse = mesh
        .call("barebones", HEALTH_METHOD_PATH, health_req)
        .await?;
    println!("grpc_health_status={}", health_resp.status);

    subscription.unsubscribe().await?;
    mesh.shutdown().await?;
    Ok(())
}
