use std::time::Duration;

use tracing::{info, warn};

use crate::{
    config::MeshConfig,
    error::{MeshError, Result},
};

pub async fn connect_with_retry(
    service_name: &str,
    config: &MeshConfig,
) -> Result<async_nats::Client> {
    let max_attempts = config.connect_max_retries.saturating_add(1);
    let mut backoff_ms = config.connect_initial_backoff_ms.max(1);
    let max_backoff_ms = config.connect_max_backoff_ms.max(1);

    for attempt in 1..=max_attempts {
        let options = connect_options(service_name, config);
        match options.connect(config.nats_url.clone()).await {
            Ok(client) => {
                info!(
                    service = service_name,
                    nats_url = %config.nats_url,
                    attempt,
                    "connected to nats"
                );
                return Ok(client);
            }
            Err(err) => {
                if attempt == max_attempts {
                    return Err(MeshError::Nats(format!(
                        "failed to connect to nats after {attempt} attempts: {err}"
                    )));
                }

                let sleep_ms = jittered_backoff_ms(backoff_ms, max_backoff_ms, attempt);
                warn!(
                    service = service_name,
                    nats_url = %config.nats_url,
                    attempt,
                    sleep_ms,
                    error = %err,
                    "nats connection failed, retrying"
                );
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff_ms = (backoff_ms.saturating_mul(2)).min(max_backoff_ms);
            }
        }
    }

    Err(MeshError::Nats(
        "nats connection retry loop ended unexpectedly".to_string(),
    ))
}

fn connect_options(service_name: &str, config: &MeshConfig) -> async_nats::ConnectOptions {
    let service_name = service_name.to_string();
    let node_id = config.node_id.clone();
    let reconnect_initial = config.connect_initial_backoff_ms.max(1);
    let reconnect_max = config.connect_max_backoff_ms.max(1);
    let reconnect_budget = usize::try_from(config.connect_max_retries).unwrap_or(usize::MAX);
    let client_name = format!("valhall-net:{service_name}:{node_id}");

    async_nats::ConnectOptions::new()
        .name(client_name)
        .max_reconnects(Some(reconnect_budget))
        .reconnect_delay_callback(move |attempt| {
            Duration::from_millis(jittered_backoff_ms(
                reconnect_initial,
                reconnect_max,
                u32::try_from(attempt).unwrap_or(u32::MAX),
            ))
        })
        .event_callback(move |event| {
            let service_name = service_name.clone();
            let node_id = node_id.clone();
            async move {
                match event {
                    async_nats::Event::Connected => {
                        info!(service = %service_name, node_id = %node_id, "nats connected")
                    }
                    async_nats::Event::Disconnected => {
                        warn!(service = %service_name, node_id = %node_id, "nats disconnected")
                    }
                    async_nats::Event::LameDuckMode => warn!(
                        service = %service_name,
                        node_id = %node_id,
                        "nats entered lame duck mode"
                    ),
                    async_nats::Event::Draining => {
                        info!(service = %service_name, node_id = %node_id, "nats draining")
                    }
                    async_nats::Event::Closed => {
                        info!(service = %service_name, node_id = %node_id, "nats connection closed")
                    }
                    async_nats::Event::SlowConsumer(sid) => warn!(
                        service = %service_name,
                        node_id = %node_id,
                        sid,
                        "nats reported slow consumer"
                    ),
                    async_nats::Event::ServerError(err) => warn!(
                        service = %service_name,
                        node_id = %node_id,
                        error = %err,
                        "nats server error"
                    ),
                    async_nats::Event::ClientError(err) => warn!(
                        service = %service_name,
                        node_id = %node_id,
                        error = %err,
                        "nats client error"
                    ),
                }
            }
        })
}

fn jittered_backoff_ms(base_ms: u64, max_ms: u64, attempt: u32) -> u64 {
    let jitter_ms = (u64::from(attempt) * 31) % 97;
    (base_ms.saturating_add(jitter_ms)).min(max_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jittered_backoff_respects_cap() {
        let delay = jittered_backoff_ms(500, 600, 2);
        assert!(delay <= 600);
    }

    #[test]
    fn jittered_backoff_adds_variance() {
        let first = jittered_backoff_ms(100, 2000, 1);
        let second = jittered_backoff_ms(100, 2000, 3);
        assert_ne!(first, second);
    }
}
