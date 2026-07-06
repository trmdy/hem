pub mod approval;
pub mod approval_adapter;
pub mod audit;
pub mod cluster;
pub mod crypto;
pub mod error;
pub(crate) mod fs_security;
pub mod group;
pub mod ledger;
pub mod model;
pub mod policy;
pub mod store;
pub mod token;

pub use approval::{DeleteApprovalRecord, DeleteApprovalStore};
pub use approval_adapter::{
    ApprovalAdapterDecision, ApprovalCapability, ApprovalChallenge, ApprovalCredential,
    ApprovalMethod, LocalApprovalAdapter, MasterPasswordApprovalAdapter, MasterPasswordKdfConfig,
    MasterPasswordVerifier, PlatformBiometricApprovalAdapter,
};
pub use audit::AuditStore;
pub use cluster::{
    node_statement_hash_b64, peer_transport_auth_statement_bytes, verify_node_statement_signature,
    ClusterConfig, ClusterInvite, ClusterInviteBody, CollisionAgreementStatement, NodeIdentity,
    PeerConfig, PeerTransportAuthStatement, PEER_TRANSPORT_AUTH_VERSION,
};
pub use crypto::{
    envelope_decrypt_for_node, envelope_encrypt_for_nodes, generate_node_wrap_keypair,
    EnvelopeEncryptedValue, NodeKeyRecipient, NodeWrapKeyPair, WrappedDataKey,
};
pub use error::{HemError, Result};
pub use group::GroupStore;
pub use ledger::{
    LedgerBootstrapReport, LedgerCheckpoint, LedgerCheckpointBody, LedgerCheckpointCosignature,
    LedgerCheckpointCosignatureBody, LedgerCollision, LedgerForkRecord, LedgerForkReplayInput,
    LedgerForkReplayRecord, LedgerForkReplayReport, LedgerIntegrityIssue, LedgerIntegrityReport,
    LedgerOperation, LedgerOperationBody, LedgerOperationEnvelope, LedgerOperationInput,
    LedgerPeerCursor, LedgerSecretMetadata, LedgerSecretValueVersion, LedgerStore,
};
pub use model::{
    AuditClientInfo, AuditEntry, AuditTokenInfo, AuditTransportInfo, GrantInfo, GroupInfo,
    ScopeResolutionContext, SecretInfo, SecretScope, SecretWithValues, SetSecretInput, TokenClaims,
    TokenType, AUDIT_SCHEMA_VERSION,
};
pub use policy::{
    IssueOfflineLeaseInput, OfflineLease, PolicyBinding, PolicySnapshot, PolicyStore,
    SecretPolicyTier,
};
pub use store::{
    inspect_data_dir_security, HemDataDirSecurityIssue, HemDataDirSecurityReport, HemStore,
    ImportSecretsReport, LedgerValueRewrapInput, LedgerValueRewrapReport,
    LocalStoreLedgerMigrationInput, LocalStoreLedgerMigrationReport,
};
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
