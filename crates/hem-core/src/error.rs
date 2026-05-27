use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HemError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("missing master key at {0}")]
    MissingMasterKey(PathBuf),
    #[error("master key file has insecure permissions (expected 0600): {0}")]
    InsecureMasterKeyPermissions(PathBuf),
    #[error("master key parse failed: {0}")]
    MasterKeyParse(String),
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("group not found: {0}")]
    GroupNotFound(String),
    #[error("approval request not found: {0}")]
    ApprovalRequestNotFound(String),
    #[error("approval request already resolved: {0}")]
    ApprovalAlreadyResolved(String),
    #[error("approval receipt is required")]
    ApprovalReceiptRequired,
    #[error("approval receipt invalid")]
    ApprovalReceiptInvalid,
    #[error("approval receipt expired")]
    ApprovalReceiptExpired,
    #[error("approval receipt already consumed")]
    ApprovalReceiptConsumed,
    #[error("token malformed")]
    TokenMalformed,
    #[error("token signature invalid")]
    TokenSignatureInvalid,
    #[error("token expired")]
    TokenExpired,
    #[error("token revoked: {0}")]
    TokenRevoked(String),
    #[error("token ttl exceeds allowed maximum")]
    TokenTtlExceeded,
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, HemError>;
