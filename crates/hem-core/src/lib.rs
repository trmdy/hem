pub mod approval;
pub mod audit;
pub mod crypto;
pub mod error;
pub mod group;
pub mod model;
pub mod store;
pub mod token;

pub use approval::{DeleteApprovalRecord, DeleteApprovalStore};
pub use audit::AuditStore;
pub use error::{HemError, Result};
pub use group::GroupStore;
pub use model::{
    AuditEntry, GrantInfo, GroupInfo, ScopeResolutionContext, SecretInfo, SecretScope,
    SecretWithValues, SetSecretInput, TokenClaims, TokenType,
};
pub use store::HemStore;
pub use token::{authorize_admin, authorize_read, IssuedToken, TokenManager, TokenManagerConfig};

pub const SERVICE_BANNER: &str = "hem-core::bootstrap";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_mentions_service() {
        assert!(SERVICE_BANNER.contains("hem-core"));
    }
}
