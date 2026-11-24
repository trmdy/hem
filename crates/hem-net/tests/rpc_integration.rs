use std::{net::SocketAddr, time::Duration};

use tokio::sync::oneshot;
use tonic::transport::Server;
use tonic_health::{
    pb::{health_check_response::ServingStatus, HealthCheckRequest, HealthCheckResponse},
    server::health_reporter,
    ServingStatus as ServiceServingStatus,
};
use hem_net::{Mesh, MeshConfig, MeshError};

const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";
const REGISTERED_SERVICE: &str = "valhall.smi.v1.Mesh";

fn test_nats_url() -> String {
    std::env::var("VALHALL_NET_TEST_NATS_URL")
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

async fn nats_reachable(nats_url: &str) -> bool {
    tokio::time::timeout(
        Duration::from_secs(1),
        async_nats::connect(nats_url.to_string()),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn spawn_health_server() -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind health server port");
    let addr = listener.local_addr().expect("resolve server addr");
    drop(listener);

    let (mut reporter, health_service) = health_reporter();
    reporter
        .set_service_status(REGISTERED_SERVICE, ServiceServingStatus::Serving)
        .await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(health_service)
            .serve_with_shutdown(addr, async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve health server");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx, handle)
}

#[tokio::test]
async fn mesh_call_roundtrip_returns_decoded_response() {
    let (addr, shutdown_tx, handle) = spawn_health_server().await;
    let nats_url = test_nats_url();
    if !nats_reachable(&nats_url).await {
        eprintln!(
            "skipping mesh_call_roundtrip_returns_decoded_response: NATS not reachable at {}",
            nats_url
        );
        let _ = shutdown_tx.send(());
        handle.await.expect("health server join");
        return;
    }

    let mut config = MeshConfig {
        nats_url,
        ..MeshConfig::default()
    };
    config
        .service_endpoints
        .insert("smi".to_string(), format!("http://{addr}"));

    let mesh = Mesh::connect("rpc-test", config)
        .await
        .expect("mesh connect");
    let request = HealthCheckRequest {
        service: REGISTERED_SERVICE.to_string(),
    };

    let response: HealthCheckResponse = mesh
        .call("smi", HEALTH_CHECK_PATH, request)
        .await
        .expect("rpc call should succeed");

    assert_eq!(response.status, ServingStatus::Serving as i32);

    mesh.shutdown().await.expect("mesh shutdown");
    let _ = shutdown_tx.send(());
    handle.await.expect("health server join");
}

#[tokio::test]
async fn mesh_call_maps_grpc_status_errors() {
    let (addr, shutdown_tx, handle) = spawn_health_server().await;
    let nats_url = test_nats_url();
    if !nats_reachable(&nats_url).await {
        eprintln!(
            "skipping mesh_call_maps_grpc_status_errors: NATS not reachable at {}",
            nats_url
        );
        let _ = shutdown_tx.send(());
        handle.await.expect("health server join");
        return;
    }

    let mut config = MeshConfig {
        nats_url,
        ..MeshConfig::default()
    };
    config
        .service_endpoints
        .insert("smi".to_string(), format!("http://{addr}"));

    let mesh = Mesh::connect("rpc-test", config)
        .await
        .expect("mesh connect");
    let request = HealthCheckRequest {
        service: "unregistered.service".to_string(),
    };

    let result = mesh
        .call::<HealthCheckRequest, HealthCheckResponse>("smi", HEALTH_CHECK_PATH, request)
        .await;

    match result {
        Err(MeshError::RpcStatus { code, message }) => {
            assert_eq!(code, tonic::Code::NotFound);
            assert!(!message.is_empty());
        }
        other => panic!("expected MeshError::RpcStatus, got {other:?}"),
    }

    mesh.shutdown().await.expect("mesh shutdown");
    let _ = shutdown_tx.send(());
    handle.await.expect("health server join");
}
