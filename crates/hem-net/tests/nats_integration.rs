#![cfg(feature = "integration-nats")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hem_net::{Mesh, MeshConfig};
use std::{net::TcpListener, process::Stdio};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

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

fn unique_subject(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("valhall.test.{prefix}.{nanos}")
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve tcp port");
    let port = listener.local_addr().expect("resolve reserved port").port();
    drop(listener);
    port
}

async fn start_nats_server(port: u16) -> std::io::Result<Child> {
    Command::new("nats-server")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

async fn stop_nats_server(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn wait_for_nats(nats_url: &str, timeout: Duration) -> bool {
    let start = tokio::time::Instant::now();
    while start.elapsed() < timeout {
        if nats_reachable(nats_url).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn emit_and_on_roundtrip() {
    let mut config = MeshConfig::default();
    config.nats_url = test_nats_url();
    if !nats_reachable(&config.nats_url).await {
        eprintln!(
            "skipping emit_and_on_roundtrip: NATS not reachable at {}",
            config.nats_url
        );
        return;
    }

    let mesh = Mesh::connect("valhall-net-test", config)
        .await
        .expect("mesh connect");

    let subject = unique_subject("emit_on");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let subscription = mesh
        .on(&subject, move |event| {
            let _ = tx.send(event);
        })
        .await
        .expect("subscribe");

    mesh.emit(&subject, b"hello")
        .await
        .expect("emit should succeed");

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for event")
        .expect("channel closed unexpectedly");
    assert_eq!(event.subject, subject);
    assert_eq!(event.payload, b"hello".to_vec());

    subscription
        .unsubscribe()
        .await
        .expect("unsubscribe should succeed");
    mesh.shutdown().await.expect("mesh shutdown");
}

#[tokio::test]
async fn request_reply_roundtrip() {
    let mut config = MeshConfig::default();
    config.nats_url = test_nats_url();
    if !nats_reachable(&config.nats_url).await {
        eprintln!(
            "skipping request_reply_roundtrip: NATS not reachable at {}",
            config.nats_url
        );
        return;
    }

    let mesh = Mesh::connect("valhall-net-test", config)
        .await
        .expect("mesh connect");
    let subject = unique_subject("request_reply");

    let replier = async_nats::connect(mesh.config().nats_url.clone())
        .await
        .expect("replier connect");
    let mut subscriber = replier
        .subscribe(subject.clone())
        .await
        .expect("replier subscribe");

    let replier_task = tokio::spawn(async move {
        use tokio_stream::StreamExt;

        if let Some(message) = subscriber.next().await {
            if let Some(reply_subject) = message.reply {
                replier
                    .publish(reply_subject, b"pong".to_vec().into())
                    .await
                    .expect("publish reply");
            }
        }
    });

    let response = mesh
        .request(&subject, b"ping")
        .await
        .expect("request should succeed");
    assert_eq!(response, b"pong".to_vec());

    replier_task.await.expect("replier task");
    mesh.shutdown().await.expect("mesh shutdown");
}

#[tokio::test]
async fn reconnect_after_broker_bounce() {
    let port = reserve_port();
    let nats_url = format!("nats://127.0.0.1:{port}");

    let mut server = match start_nats_server(port).await {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping reconnect_after_broker_bounce: nats-server not installed");
            return;
        }
        Err(err) => panic!("failed to start nats-server: {err}"),
    };

    if !wait_for_nats(&nats_url, Duration::from_secs(5)).await {
        stop_nats_server(&mut server).await;
        panic!("nats-server did not become ready");
    }

    let mut config = MeshConfig::default();
    config.nats_url = nats_url.clone();
    config.connect_initial_backoff_ms = 50;
    config.connect_max_backoff_ms = 250;
    config.connect_max_retries = 50;

    let mesh = Mesh::connect("valhall-net-test", config)
        .await
        .expect("mesh connect");

    let subject = unique_subject("reconnect");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let subscription = mesh
        .on(&subject, move |event| {
            let _ = tx.send(event);
        })
        .await
        .expect("subscribe");

    mesh.emit(&subject, b"before-bounce")
        .await
        .expect("initial emit should succeed");
    let before = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout waiting for first event")
        .expect("channel closed unexpectedly");
    assert_eq!(before.payload, b"before-bounce".to_vec());

    stop_nats_server(&mut server).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    server = start_nats_server(port)
        .await
        .expect("restart nats-server should succeed");
    assert!(wait_for_nats(&nats_url, Duration::from_secs(5)).await);

    let mut emitted = false;
    for _ in 0..30 {
        if mesh.emit(&subject, b"after-bounce").await.is_ok() {
            emitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(emitted, "mesh should recover and emit after bounce");

    let after = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for post-bounce event")
        .expect("channel closed unexpectedly");
    assert_eq!(after.payload, b"after-bounce".to_vec());

    subscription
        .unsubscribe()
        .await
        .expect("unsubscribe should succeed");
    mesh.shutdown().await.expect("mesh shutdown");
    stop_nats_server(&mut server).await;
}
