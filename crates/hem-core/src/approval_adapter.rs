use std::fmt;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{DeleteApprovalRecord, HemError, Result, SecretScope};

type HmacSha256 = Hmac<Sha256>;

const MASTER_PASSWORD_ALG: &str = "pbkdf2-hmac-sha256";
const DEFAULT_MASTER_PASSWORD_ITERATIONS: u32 = 210_000;
const DEFAULT_MASTER_PASSWORD_SALT_LEN: usize = 32;
const MASTER_PASSWORD_VERIFIER_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCapability {
    pub adapter: String,
    pub master_password_available: bool,
    pub biometric_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biometric_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub request_id: String,
    pub action: String,
    pub secret_scope: SecretScope,
    pub secret_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<String>,
    pub requested_by: String,
}

impl ApprovalChallenge {
    #[must_use]
    pub fn from_delete_record(record: &DeleteApprovalRecord) -> Self {
        Self {
            request_id: record.request_id.clone(),
            action: record.action.clone(),
            secret_scope: record.secret_scope.clone(),
            secret_name: record.secret_name.clone(),
            secret_version: record.secret_version.clone(),
            requested_by: record.requested_by.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_non_empty("request_id", self.request_id.as_str())?;
        validate_non_empty("action", self.action.as_str())?;
        self.secret_scope.validate()?;
        crate::model::validate_secret_name(self.secret_name.as_str())?;
        if let Some(version) = self.secret_version.as_ref() {
            validate_non_empty("secret_version", version.as_str())?;
        }
        validate_non_empty("requested_by", self.requested_by.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMethod {
    MasterPassword,
    Biometric { kind: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum ApprovalAdapterDecision {
    Approved { method: ApprovalMethod },
    Denied { reason: String },
    Aborted { reason: String },
}

impl ApprovalAdapterDecision {
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }
}

pub enum ApprovalCredential<'a> {
    MasterPassword(&'a str),
    BiometricAssertion { kind: &'a str, assertion: &'a [u8] },
}

impl fmt::Debug for ApprovalCredential<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MasterPassword(_) => formatter
                .debug_tuple("MasterPassword")
                .field(&"<redacted>")
                .finish(),
            Self::BiometricAssertion { kind, assertion } => formatter
                .debug_struct("BiometricAssertion")
                .field("kind", kind)
                .field("assertion_len", &assertion.len())
                .finish(),
        }
    }
}

pub trait LocalApprovalAdapter: Send + Sync + fmt::Debug {
    fn capability(&self) -> ApprovalCapability;

    fn approve(
        &self,
        challenge: &ApprovalChallenge,
        credential: ApprovalCredential<'_>,
    ) -> Result<ApprovalAdapterDecision>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasterPasswordKdfConfig {
    pub iterations: u32,
    pub salt_len: usize,
}

impl Default for MasterPasswordKdfConfig {
    fn default() -> Self {
        Self {
            iterations: DEFAULT_MASTER_PASSWORD_ITERATIONS,
            salt_len: DEFAULT_MASTER_PASSWORD_SALT_LEN,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterPasswordVerifier {
    pub alg: String,
    pub iterations: u32,
    pub salt_b64: String,
    pub verifier_b64: String,
}

#[derive(Clone)]
pub struct MasterPasswordApprovalAdapter {
    verifier: MasterPasswordVerifier,
}

impl fmt::Debug for MasterPasswordApprovalAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MasterPasswordApprovalAdapter")
            .field("alg", &self.verifier.alg)
            .field("iterations", &self.verifier.iterations)
            .finish_non_exhaustive()
    }
}

impl MasterPasswordApprovalAdapter {
    pub fn from_password(password: &str) -> Result<Self> {
        Self::from_password_with_config(password, MasterPasswordKdfConfig::default())
    }

    pub fn from_password_with_config(
        password: &str,
        config: MasterPasswordKdfConfig,
    ) -> Result<Self> {
        if password.is_empty() {
            return Err(HemError::InvalidArgument(
                "master password must not be empty".to_string(),
            ));
        }
        if config.iterations == 0 {
            return Err(HemError::InvalidArgument(
                "master password kdf iterations must be greater than zero".to_string(),
            ));
        }
        if config.salt_len < 16 {
            return Err(HemError::InvalidArgument(
                "master password kdf salt must be at least 16 bytes".to_string(),
            ));
        }

        let mut salt = vec![0_u8; config.salt_len];
        OsRng.fill_bytes(salt.as_mut_slice());
        let verifier = derive_master_password_verifier(
            password.as_bytes(),
            salt.as_slice(),
            config.iterations,
        )?;

        Ok(Self {
            verifier: MasterPasswordVerifier {
                alg: MASTER_PASSWORD_ALG.to_string(),
                iterations: config.iterations,
                salt_b64: STANDARD_NO_PAD.encode(salt),
                verifier_b64: STANDARD_NO_PAD.encode(verifier),
            },
        })
    }

    pub fn from_verifier(verifier: MasterPasswordVerifier) -> Result<Self> {
        validate_verifier(&verifier)?;
        Ok(Self { verifier })
    }

    #[must_use]
    pub fn verifier(&self) -> &MasterPasswordVerifier {
        &self.verifier
    }

    pub fn approve_with_password(
        &self,
        challenge: &ApprovalChallenge,
        password: &str,
    ) -> Result<ApprovalAdapterDecision> {
        self.approve(challenge, ApprovalCredential::MasterPassword(password))
    }
}

impl LocalApprovalAdapter for MasterPasswordApprovalAdapter {
    fn capability(&self) -> ApprovalCapability {
        ApprovalCapability {
            adapter: "master_password".to_string(),
            master_password_available: true,
            biometric_available: false,
            biometric_kind: None,
        }
    }

    fn approve(
        &self,
        challenge: &ApprovalChallenge,
        credential: ApprovalCredential<'_>,
    ) -> Result<ApprovalAdapterDecision> {
        challenge.validate()?;
        let ApprovalCredential::MasterPassword(password) = credential else {
            return Ok(ApprovalAdapterDecision::Aborted {
                reason: "master password credential required".to_string(),
            });
        };
        if password.is_empty() {
            return Ok(ApprovalAdapterDecision::Aborted {
                reason: "master password entry aborted".to_string(),
            });
        }
        if verify_master_password(password.as_bytes(), &self.verifier)? {
            Ok(ApprovalAdapterDecision::Approved {
                method: ApprovalMethod::MasterPassword,
            })
        } else {
            Ok(ApprovalAdapterDecision::Denied {
                reason: "master password verification failed".to_string(),
            })
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PlatformBiometricApprovalAdapter {
    biometric_kind: Option<String>,
}

impl PlatformBiometricApprovalAdapter {
    #[must_use]
    pub fn detect() -> Self {
        Self {
            biometric_kind: detected_biometric_kind(),
        }
    }
}

impl LocalApprovalAdapter for PlatformBiometricApprovalAdapter {
    fn capability(&self) -> ApprovalCapability {
        ApprovalCapability {
            adapter: "platform_biometric".to_string(),
            master_password_available: false,
            biometric_available: self.biometric_kind.is_some(),
            biometric_kind: self.biometric_kind.clone(),
        }
    }

    fn approve(
        &self,
        challenge: &ApprovalChallenge,
        credential: ApprovalCredential<'_>,
    ) -> Result<ApprovalAdapterDecision> {
        challenge.validate()?;
        let Some(expected_kind) = self.biometric_kind.as_deref() else {
            return Ok(ApprovalAdapterDecision::Aborted {
                reason: "platform biometric approval unavailable on this node".to_string(),
            });
        };
        let ApprovalCredential::BiometricAssertion { kind, .. } = credential else {
            return Ok(ApprovalAdapterDecision::Aborted {
                reason: "platform biometric credential required".to_string(),
            });
        };
        if kind != expected_kind {
            return Ok(ApprovalAdapterDecision::Aborted {
                reason: format!(
                    "platform biometric kind mismatch: expected {expected_kind}, got {kind}"
                ),
            });
        }

        let prompt_reason = biometric_prompt_reason(challenge)?;
        match platform_biometrics::approve(prompt_reason.as_str())? {
            PlatformBiometricOutcome::Approved => Ok(ApprovalAdapterDecision::Approved {
                method: ApprovalMethod::Biometric {
                    kind: expected_kind.to_string(),
                },
            }),
            PlatformBiometricOutcome::Denied { reason } => {
                Ok(ApprovalAdapterDecision::Denied { reason })
            }
            PlatformBiometricOutcome::Aborted { reason } => {
                Ok(ApprovalAdapterDecision::Aborted { reason })
            }
        }
    }
}

fn detected_biometric_kind() -> Option<String> {
    platform_biometrics::detected_kind()
}

fn biometric_prompt_reason(challenge: &ApprovalChallenge) -> Result<String> {
    challenge.validate()?;
    let secret = match &challenge.secret_scope {
        SecretScope::Global => format!("global/{}", challenge.secret_name),
        SecretScope::Project { project } => format!("project/{project}/{}", challenge.secret_name),
        SecretScope::Identity { identity_id } => {
            format!("identity/{identity_id}/{}", challenge.secret_name)
        }
    };
    let version = challenge.secret_version.as_deref().unwrap_or("current");
    Ok(format!(
        "approve {} requested by {} for secret {} at version {}",
        challenge.action, challenge.requested_by, secret, version
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlatformBiometricOutcome {
    Approved,
    Denied { reason: String },
    Aborted { reason: String },
}

#[cfg(target_os = "macos")]
mod platform_biometrics {
    use std::sync::mpsc;

    use block2::{DynBlock, RcBlock};
    use objc2::{rc::Retained, runtime::Bool};
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};

    use super::{HemError, PlatformBiometricOutcome, Result};

    pub fn detected_kind() -> Option<String> {
        let context = unsafe { LAContext::new() };
        if unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        }
        .is_err()
        {
            return None;
        }

        let kind = unsafe { context.biometryType() };
        biometric_kind_label(kind).map(str::to_string)
    }

    pub fn approve(prompt_reason: &str) -> Result<PlatformBiometricOutcome> {
        let context = unsafe { LAContext::new() };
        if let Err(error) = unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        } {
            return Ok(PlatformBiometricOutcome::Aborted {
                reason: format!("platform biometric approval unavailable: {error}"),
            });
        }

        let (sender, receiver) = mpsc::channel();
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let outcome = if success.as_bool() {
                PlatformBiometricOutcome::Approved
            } else {
                classify_authentication_error(error)
            };
            let _ = sender.send(outcome);
        });
        let reply: &DynBlock<dyn Fn(Bool, *mut NSError)> = &reply;
        let localized_reason = NSString::from_str(prompt_reason);

        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                localized_reason.as_ref(),
                reply,
            );
        }

        receiver.recv().map_err(|err| {
            HemError::AuthorizationDenied(format!("platform biometric callback failed: {err}"))
        })
    }

    fn biometric_kind_label(kind: LABiometryType) -> Option<&'static str> {
        match kind {
            LABiometryType::TouchID => Some("touch_id"),
            LABiometryType::FaceID => Some("face_id"),
            LABiometryType::OpticID => Some("optic_id"),
            _ => None,
        }
    }

    fn classify_authentication_error(error: *mut NSError) -> PlatformBiometricOutcome {
        let Some(error) = (unsafe { Retained::retain(error) }) else {
            return PlatformBiometricOutcome::Aborted {
                reason: "platform biometric approval failed without error detail".to_string(),
            };
        };
        let code = error.code();
        let message = error.to_string();

        if code == LAError::AuthenticationFailed.0 {
            return PlatformBiometricOutcome::Denied {
                reason: "platform biometric verification failed".to_string(),
            };
        }
        if matches!(
            code,
            value if value == LAError::UserCancel.0
                || value == LAError::UserFallback.0
                || value == LAError::SystemCancel.0
                || value == LAError::AppCancel.0
                || value == LAError::NotInteractive.0
        ) {
            return PlatformBiometricOutcome::Aborted {
                reason: format!("platform biometric approval canceled: {message}"),
            };
        }
        if matches!(
            code,
            value if value == LAError::PasscodeNotSet.0
                || value == LAError::BiometryNotAvailable.0
                || value == LAError::BiometryNotEnrolled.0
                || value == LAError::BiometryLockout.0
                || value == LAError::BiometryNotPaired.0
                || value == LAError::BiometryDisconnected.0
        ) {
            return PlatformBiometricOutcome::Aborted {
                reason: format!("platform biometric approval unavailable: {message}"),
            };
        }

        PlatformBiometricOutcome::Aborted {
            reason: format!("platform biometric approval failed: {message}"),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform_biometrics {
    use super::{PlatformBiometricOutcome, Result};

    pub fn detected_kind() -> Option<String> {
        None
    }

    pub fn approve(_prompt_reason: &str) -> Result<PlatformBiometricOutcome> {
        Ok(PlatformBiometricOutcome::Aborted {
            reason: "platform biometric approval unavailable on this operating system".to_string(),
        })
    }
}

fn validate_verifier(verifier: &MasterPasswordVerifier) -> Result<()> {
    if verifier.alg != MASTER_PASSWORD_ALG {
        return Err(HemError::InvalidArgument(format!(
            "unsupported master password verifier algorithm: {}",
            verifier.alg
        )));
    }
    if verifier.iterations == 0 {
        return Err(HemError::InvalidArgument(
            "master password verifier iterations must be greater than zero".to_string(),
        ));
    }
    let salt = decode_b64("master password salt", verifier.salt_b64.as_str())?;
    if salt.len() < 16 {
        return Err(HemError::InvalidArgument(
            "master password verifier salt must be at least 16 bytes".to_string(),
        ));
    }
    let derived = decode_b64("master password verifier", verifier.verifier_b64.as_str())?;
    if derived.len() != MASTER_PASSWORD_VERIFIER_LEN {
        return Err(HemError::InvalidArgument(
            "master password verifier must be 32 bytes".to_string(),
        ));
    }
    Ok(())
}

fn verify_master_password(password: &[u8], verifier: &MasterPasswordVerifier) -> Result<bool> {
    validate_verifier(verifier)?;
    let salt = decode_b64("master password salt", verifier.salt_b64.as_str())?;
    let expected = decode_b64("master password verifier", verifier.verifier_b64.as_str())?;
    let actual = derive_master_password_verifier(password, salt.as_slice(), verifier.iterations)?;
    Ok(actual.ct_eq(expected.as_slice()).into())
}

fn derive_master_password_verifier(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; MASTER_PASSWORD_VERIFIER_LEN]> {
    if iterations == 0 {
        return Err(HemError::InvalidArgument(
            "master password kdf iterations must be greater than zero".to_string(),
        ));
    }

    let mut mac = HmacSha256::new_from_slice(password)
        .map_err(|err| HemError::Crypto(format!("master password kdf init failed: {err}")))?;
    mac.update(salt);
    mac.update(&1_u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut out = [0_u8; MASTER_PASSWORD_VERIFIER_LEN];
    out.copy_from_slice(u.as_slice());

    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password)
            .map_err(|err| HemError::Crypto(format!("master password kdf init failed: {err}")))?;
        mac.update(u.as_slice());
        u = mac.finalize().into_bytes();
        for (left, right) in out.iter_mut().zip(u.iter()) {
            *left ^= *right;
        }
    }

    Ok(out)
}

fn decode_b64(label: &str, value: &str) -> Result<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| HemError::InvalidArgument(format!("{label} is not valid base64: {err}")))
}

fn validate_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(HemError::InvalidArgument(format!(
            "{label} must not be empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MasterPasswordKdfConfig {
        MasterPasswordKdfConfig {
            iterations: 2,
            salt_len: 16,
        }
    }

    fn challenge() -> ApprovalChallenge {
        ApprovalChallenge {
            request_id: "apr-test".to_string(),
            action: "read_secret".to_string(),
            secret_scope: SecretScope::Global,
            secret_name: "demo-secret".to_string(),
            secret_version: Some("version-1".to_string()),
            requested_by: "agent-a".to_string(),
        }
    }

    #[test]
    fn master_password_fallback_approves_correct_password() {
        let adapter = MasterPasswordApprovalAdapter::from_password_with_config(
            "correct horse battery staple",
            test_config(),
        )
        .expect("adapter");

        let decision = adapter
            .approve_with_password(&challenge(), "correct horse battery staple")
            .expect("decision");

        assert_eq!(
            decision,
            ApprovalAdapterDecision::Approved {
                method: ApprovalMethod::MasterPassword
            }
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn master_password_fallback_denies_wrong_password() {
        let adapter = MasterPasswordApprovalAdapter::from_password_with_config(
            "correct horse battery staple",
            test_config(),
        )
        .expect("adapter");

        let decision = adapter
            .approve_with_password(&challenge(), "wrong password")
            .expect("decision");

        assert_eq!(
            decision,
            ApprovalAdapterDecision::Denied {
                reason: "master password verification failed".to_string()
            }
        );
        assert!(!decision.is_approved());
    }

    #[test]
    fn master_password_fallback_aborts_empty_password() {
        let adapter = MasterPasswordApprovalAdapter::from_password_with_config(
            "correct horse battery staple",
            test_config(),
        )
        .expect("adapter");

        let decision = adapter
            .approve_with_password(&challenge(), "")
            .expect("decision");

        assert_eq!(
            decision,
            ApprovalAdapterDecision::Aborted {
                reason: "master password entry aborted".to_string()
            }
        );
        assert!(!decision.is_approved());
    }

    #[test]
    fn password_adapter_reports_fallback_capability_without_biometrics() {
        let adapter = MasterPasswordApprovalAdapter::from_password_with_config(
            "correct horse battery staple",
            test_config(),
        )
        .expect("adapter");

        let capability = adapter.capability();

        assert_eq!(capability.adapter, "master_password");
        assert!(capability.master_password_available);
        assert!(!capability.biometric_available);
        assert!(capability.biometric_kind.is_none());
    }

    #[test]
    fn biometric_adapter_is_capability_detected_without_hardware_dependency() {
        let adapter = PlatformBiometricApprovalAdapter::detect();
        let capability = adapter.capability();

        assert_eq!(capability.adapter, "platform_biometric");
        assert!(!capability.master_password_available);
        assert_eq!(
            capability.biometric_available,
            capability.biometric_kind.is_some()
        );
    }

    #[test]
    fn biometric_prompt_reason_includes_context_without_values() {
        let reason = biometric_prompt_reason(&challenge()).expect("reason");

        assert!(reason.contains("read_secret"));
        assert!(reason.contains("agent-a"));
        assert!(reason.contains("global/demo-secret"));
        assert!(reason.contains("version-1"));
        assert!(!reason.contains("api_key"));
        assert!(!reason.contains("secret value"));
    }

    #[test]
    fn biometric_adapter_fails_closed_when_unavailable() {
        let adapter = PlatformBiometricApprovalAdapter::default();

        let decision = adapter
            .approve(
                &challenge(),
                ApprovalCredential::BiometricAssertion {
                    kind: "touch_id",
                    assertion: b"not-a-real-assertion",
                },
            )
            .expect("decision");
        assert_eq!(
            decision,
            ApprovalAdapterDecision::Aborted {
                reason: "platform biometric approval unavailable on this node".to_string()
            }
        );
    }

    #[test]
    fn biometric_adapter_fails_closed_on_wrong_credential_kind() {
        let adapter = PlatformBiometricApprovalAdapter {
            biometric_kind: Some("touch_id".to_string()),
        };

        let decision = adapter
            .approve(&challenge(), ApprovalCredential::MasterPassword("not-used"))
            .expect("decision");
        assert_eq!(
            decision,
            ApprovalAdapterDecision::Aborted {
                reason: "platform biometric credential required".to_string()
            }
        );
    }

    #[test]
    fn biometric_adapter_fails_closed_on_mismatched_biometric_kind() {
        let adapter = PlatformBiometricApprovalAdapter {
            biometric_kind: Some("touch_id".to_string()),
        };

        let decision = adapter
            .approve(
                &challenge(),
                ApprovalCredential::BiometricAssertion {
                    kind: "face_id",
                    assertion: b"intent-to-prompt",
                },
            )
            .expect("decision");
        assert_eq!(
            decision,
            ApprovalAdapterDecision::Aborted {
                reason: "platform biometric kind mismatch: expected touch_id, got face_id"
                    .to_string()
            }
        );
    }

    #[test]
    fn verifier_round_trips_without_plaintext_password() {
        let adapter = MasterPasswordApprovalAdapter::from_password_with_config(
            "correct horse battery staple",
            test_config(),
        )
        .expect("adapter");
        let restored = MasterPasswordApprovalAdapter::from_verifier(adapter.verifier().clone())
            .expect("restored");

        let decision = restored
            .approve_with_password(&challenge(), "correct horse battery staple")
            .expect("decision");

        assert!(decision.is_approved());
    }
}
