use std::time::Duration;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MeshError>;

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("nats error: {0}")]
    Nats(String),
    #[error("rpc transport error: {0}")]
    RpcTransport(String),
    #[error("rpc status error [{code:?}]: {message}")]
    RpcStatus { code: tonic::Code, message: String },
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),
    #[error("shutdown error: {0}")]
    Shutdown(String),
}

impl MeshError {
    pub fn nats(err: impl std::fmt::Display) -> Self {
        Self::Nats(err.to_string())
    }

    pub fn rpc_transport(err: impl std::fmt::Display) -> Self {
        Self::RpcTransport(err.to_string())
    }

    pub fn rpc_status(status: tonic::Status) -> Self {
        Self::RpcStatus {
            code: status.code(),
            message: status.message().to_string(),
        }
    }
}
