use std::{net::SocketAddr, time::Duration};

use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic_health::{server::health_reporter, ServingStatus};

const REQUEST_SUBJECT: &str = "valhall.test.barebones.echo";
const EVENT_SUBJECT: &str = "valhall.test.barebones.received";
const HEALTH_SERVICE_NAME: &str = "valhall.barebones.v1.Mesh";

fn nats_url() -> String {
    std::env::var("VALHALL_NET_TEST_NATS_URL")
        .or_else(|_| std::env::var("VALHALL_NET_NATS_URL"))
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

fn grpc_addr() -> SocketAddr {
    std::env::var("VALHALL_BAREBONES_GRPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50071".to_string())
        .parse()
        .expect("VALHALL_BAREBONES_GRPC_ADDR must be valid socket addr")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_url = nats_url();
    let grpc_addr = grpc_addr();

    println!("barebones-service starting");
    println!("nats={nats_url}");
    println!("grpc={grpc_addr}");
    println!("request_subject={REQUEST_SUBJECT}");
    println!("event_subject={EVENT_SUBJECT}");

    let nats = async_nats::connect(nats_url.clone()).await?;
    let mut subscriber = nats.subscribe(REQUEST_SUBJECT.to_string()).await?;

    let nats_loop_client = nats.clone();
    let nats_loop = tokio::spawn(async move {
        while let Some(message) = subscriber.next().await {
            if let Some(reply_subject) = message.reply.clone() {
                let reply_payload = format!("echo:{}", String::from_utf8_lossy(&message.payload));
                if let Err(err) = nats_loop_client
                    .publish(reply_subject, reply_payload.into())
                    .await
                {
                    eprintln!("reply publish failed: {err}");
                }
            }

            if let Err(err) = nats_loop_client
                .publish(EVENT_SUBJECT.to_string(), message.payload.clone())
                .await
            {
                eprintln!("event publish failed: {err}");
            }
        }
    });

    let (mut reporter, health_service) = health_reporter();
    reporter
        .set_service_status(HEALTH_SERVICE_NAME, ServingStatus::Serving)
        .await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let grpc_loop = tokio::spawn(async move {
        Server::builder()
            .add_service(health_service)
            .serve_with_shutdown(grpc_addr, async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    tokio::signal::ctrl_c().await?;
    println!("barebones-service stopping");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), grpc_loop).await;
    nats_loop.abort();

    Ok(())
}
