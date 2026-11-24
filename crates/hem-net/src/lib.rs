//! `hem-net` is the Sprint-1 mesh communication crate for Valhall daemons.
//!
//! It wraps:
//! - gRPC request/response via [`Mesh::call`]
//! - NATS events and request/reply via [`Mesh::emit`], [`Mesh::on`], [`Mesh::request`]
//!
//! Quickstart:
//! ```no_run
//! use hem_net::{Mesh, MeshConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = MeshConfig::from_env()?;
//!     let mesh = Mesh::connect("smid", config).await?;
//!     mesh.emit("smi.loop.started", b"{}").await?;
//!     mesh.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! Environment config keys:
//! - `VALHALL_NET_NATS_URL`
//! - `VALHALL_NET_NODE_ID`
//! - `VALHALL_NET_RPC_TIMEOUT_MS`
//! - `VALHALL_NET_REQUEST_TIMEOUT_MS`
//! - `VALHALL_NET_CONNECT_MAX_RETRIES`
//! - `VALHALL_NET_CONNECT_INITIAL_BACKOFF_MS`
//! - `VALHALL_NET_CONNECT_MAX_BACKOFF_MS`
//! - `VALHALL_NET_SERVICE_ENDPOINTS_JSON`
//! - `VALHALL_NET_SERVICE_ENDPOINT__<SERVICE>`
//!
//! Migration note (Sprint-1):
//! downstream crates should use `hem_net::Mesh` instead of importing `tonic`/`async-nats`
//! directly for normal daemon communication paths.
//!
mod config;
mod error;
mod event;
mod nats;
mod rpc;
mod subscription;

use std::{sync::Arc, time::Duration};

use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};
use hem_events::SystemEvent;

pub use config::MeshConfig;
pub use error::{MeshError, Result};
pub use event::Event;
pub use subscription::Subscription;

use rpc::RpcClientPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryKind {
    RequestResponse,
    Publish,
}

pub fn delivery_for(event: &SystemEvent) -> DeliveryKind {
    match event {
        SystemEvent::AgentRunRequested | SystemEvent::ContainerSpawnRequested => {
            DeliveryKind::RequestResponse
        }
        SystemEvent::MemorySyncRequested
        | SystemEvent::FileRootMounted
        | SystemEvent::MessageSent
        | SystemEvent::DirectMessageSent
        | SystemEvent::ChannelCreated => DeliveryKind::Publish,
    }
}

/// Core mesh handle, one per daemon process.
pub struct Mesh {
    service_name: String,
    config: MeshConfig,
    nats: async_nats::Client,
    rpc_pool: RpcClientPool,
}

impl Mesh {
    /// Initialize a new mesh instance for a daemon.
    pub async fn connect(service_name: &str, config: MeshConfig) -> Result<Self> {
        if service_name.trim().is_empty() {
            return Err(MeshError::InvalidArgument(
                "service_name must not be empty".to_string(),
            ));
        }

        config.validate()?;

        info!(
            service = service_name,
            node_id = %config.node_id,
            nats_url = %config.nats_url,
            "connecting mesh"
        );

        let nats = nats::connect_with_retry(service_name, &config).await?;
        let rpc_pool = RpcClientPool::new(config.service_endpoints.clone(), config.rpc_timeout());

        info!(service = service_name, "mesh connected");

        Ok(Self {
            service_name: service_name.to_string(),
            config,
            nats,
            rpc_pool,
        })
    }

    /// Request-response call over gRPC.
    pub async fn call<Req, Res>(&self, service: &str, method: &str, request: Req) -> Result<Res>
    where
        Req: prost::Message + 'static,
        Res: prost::Message + Default + 'static,
    {
        self.rpc_pool.call(service, method, request).await
    }

    /// Emit a fire-and-forget event over NATS.
    pub async fn emit(&self, subject: &str, payload: &[u8]) -> Result<()> {
        if subject.trim().is_empty() {
            return Err(MeshError::InvalidArgument(
                "subject must not be empty".to_string(),
            ));
        }

        self.nats
            .publish(subject.to_string(), payload.to_vec().into())
            .await
            .map_err(MeshError::nats)?;

        debug!(
            service = %self.service_name,
            subject,
            payload_bytes = payload.len(),
            "mesh event published"
        );

        Ok(())
    }

    /// Subscribe to events on a subject or wildcard subject pattern.
    pub async fn on(
        &self,
        subject: &str,
        handler: impl Fn(Event) + Send + Sync + 'static,
    ) -> Result<Subscription> {
        if subject.trim().is_empty() {
            return Err(MeshError::InvalidArgument(
                "subject must not be empty".to_string(),
            ));
        }

        let (stop_tx, mut stop_rx) = oneshot::channel();

        let service_name = self.service_name.clone();
        let subject_owned = subject.to_string();
        let handler = Arc::new(handler);
        let nats = self.nats.clone();

        let join_handle = tokio::spawn(async move {
            debug!(
                service = %service_name,
                subject = %subject_owned,
                "mesh subscription started"
            );

            loop {
                let mut subscriber = match nats.subscribe(subject_owned.clone()).await {
                    Ok(subscriber) => subscriber,
                    Err(error) => {
                        warn!(
                            service = %service_name,
                            subject = %subject_owned,
                            error = %error,
                            "mesh subscription start failed; retrying"
                        );
                        tokio::select! {
                            _ = &mut stop_rx => {
                                debug!(
                                    service = %service_name,
                                    subject = %subject_owned,
                                    "mesh subscription stop requested"
                                );
                                break;
                            }
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                                continue;
                            }
                        }
                    }
                };

                loop {
                    tokio::select! {
                        _ = &mut stop_rx => {
                            debug!(
                                service = %service_name,
                                subject = %subject_owned,
                                "mesh subscription stop requested"
                            );
                            return;
                        }
                        maybe_message = subscriber.next() => {
                            match maybe_message {
                                Some(message) => {
                                    let event = Event::from_nats_message(message);
                                    debug!(
                                        service = %service_name,
                                        subject = %event.subject,
                                        payload_bytes = event.payload.len(),
                                        "mesh event received"
                                    );
                                    handler(event);
                                }
                                None => {
                                    warn!(
                                        service = %service_name,
                                        subject = %subject_owned,
                                        "mesh subscription stream ended; re-subscribing"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Subscription::new(stop_tx, join_handle))
    }

    /// Request-reply helper over NATS.
    pub async fn request(&self, subject: &str, payload: &[u8]) -> Result<Vec<u8>> {
        if subject.trim().is_empty() {
            return Err(MeshError::InvalidArgument(
                "subject must not be empty".to_string(),
            ));
        }

        let timeout = self.config.request_timeout();
        let response = tokio::time::timeout(
            timeout,
            self.nats
                .request(subject.to_string(), payload.to_vec().into()),
        )
        .await
        .map_err(|_| MeshError::Timeout(timeout))?
        .map_err(MeshError::nats)?;

        debug!(
            service = %self.service_name,
            subject,
            payload_bytes = payload.len(),
            response_bytes = response.payload.len(),
            "mesh request completed"
        );

        Ok(response.payload.to_vec())
    }

    /// Graceful shutdown for mesh resources.
    pub async fn shutdown(self) -> Result<()> {
        self.nats.flush().await.map_err(MeshError::nats)?;
        info!(service = %self.service_name, "mesh shutdown complete");
        Ok(())
    }

    pub fn config(&self) -> &MeshConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_kind_matches_event_shape() {
        assert_eq!(
            delivery_for(&SystemEvent::AgentRunRequested),
            DeliveryKind::RequestResponse
        );
        assert_eq!(
            delivery_for(&SystemEvent::FileRootMounted),
            DeliveryKind::Publish
        );
        assert_eq!(
            delivery_for(&SystemEvent::MessageSent),
            DeliveryKind::Publish
        );
        assert_eq!(
            delivery_for(&SystemEvent::DirectMessageSent),
            DeliveryKind::Publish
        );
        assert_eq!(
            delivery_for(&SystemEvent::ChannelCreated),
            DeliveryKind::Publish
        );
    }
}
