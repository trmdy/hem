use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::Mutex;
use tonic::{
    client::Grpc,
    codec::ProstCodec,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};
use tracing::debug;

use crate::error::{MeshError, Result};

#[derive(Clone)]
pub struct RpcClientPool {
    endpoints: Arc<HashMap<String, String>>,
    channels: Arc<Mutex<HashMap<String, Channel>>>,
    timeout: Duration,
}

impl RpcClientPool {
    pub fn new(endpoints: HashMap<String, String>, timeout: Duration) -> Self {
        Self {
            endpoints: Arc::new(endpoints),
            channels: Arc::new(Mutex::new(HashMap::new())),
            timeout,
        }
    }

    pub async fn call<Req, Res>(&self, service: &str, method: &str, request: Req) -> Result<Res>
    where
        Req: prost::Message + 'static,
        Res: prost::Message + Default + 'static,
    {
        let channel = self.channel_for(service).await?;
        let path = canonical_method_path(service, method)?;
        let path_and_query = path.parse::<PathAndQuery>().map_err(|err| {
            MeshError::InvalidArgument(format!(
                "invalid gRPC method path for service '{service}': {err}"
            ))
        })?;
        let codec = ProstCodec::default();
        let mut grpc = Grpc::new(channel);

        debug!(service, method, "performing gRPC mesh call");
        grpc.ready().await.map_err(MeshError::rpc_transport)?;
        let response = tokio::time::timeout(
            self.timeout,
            grpc.unary(tonic::Request::new(request), path_and_query, codec),
        )
        .await
        .map_err(|_| MeshError::Timeout(self.timeout))?
        .map_err(MeshError::rpc_status)?;

        Ok(response.into_inner())
    }

    async fn channel_for(&self, service: &str) -> Result<Channel> {
        if service.trim().is_empty() {
            return Err(MeshError::InvalidArgument(
                "service must not be empty".to_string(),
            ));
        }

        let endpoint = self.endpoints.get(service).ok_or_else(|| {
            MeshError::Config(format!(
                "no gRPC endpoint configured for service '{service}'"
            ))
        })?;

        if let Some(channel) = self.channels.lock().await.get(service).cloned() {
            return Ok(channel);
        }

        let endpoint = Endpoint::from_shared(endpoint.clone()).map_err(|err| {
            MeshError::Config(format!(
                "invalid gRPC endpoint configured for service '{service}': {err}"
            ))
        })?;
        let channel = endpoint.connect().await.map_err(MeshError::rpc_transport)?;

        self.channels
            .lock()
            .await
            .insert(service.to_string(), channel.clone());

        Ok(channel)
    }
}

/// Method-path convention for generic calls:
/// - if `method` starts with `/`, use as-is (full canonical path)
/// - otherwise map to `/valhall.<service>.v1.Mesh/<method>`
pub fn canonical_method_path(service: &str, method: &str) -> Result<String> {
    if method.trim().is_empty() {
        return Err(MeshError::InvalidArgument(
            "method must not be empty".to_string(),
        ));
    }
    if method.starts_with('/') {
        return Ok(method.to_string());
    }

    let service = service.trim();
    if service.is_empty() {
        return Err(MeshError::InvalidArgument(
            "service must not be empty".to_string(),
        ));
    }

    Ok(format!("/valhall.{service}.v1.Mesh/{method}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_accepts_full_path() {
        let path = canonical_method_path("smi", "/custom.Service/Call").expect("path");
        assert_eq!(path, "/custom.Service/Call");
    }

    #[test]
    fn canonical_path_builds_default_shape() {
        let path = canonical_method_path("smi", "RunLoop").expect("path");
        assert_eq!(path, "/valhall.smi.v1.Mesh/RunLoop");
    }
}
