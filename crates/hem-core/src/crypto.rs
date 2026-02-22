use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{HemError, Result};

#[derive(Debug, Clone)]
pub struct MasterKey {
    pub key_id: String,
    pub key_bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedValue {
    pub alg: String,
    pub key_id: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn generate_master_key() -> MasterKey {
    let mut key_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    MasterKey {
        key_id: format!(
            "mk-{}",
            valhall_config::ids::generate_entropy_prefixed_ulid()
        ),
        key_bytes,
    }
}

pub fn encrypt_value(master_key: &MasterKey, value: &str, aad: &[u8]) -> Result<EncryptedValue> {
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key.key_bytes));
    let payload = Payload {
        msg: value.as_bytes(),
        aad,
    };
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| HemError::Crypto("encrypt failed".to_string()))?;

    Ok(EncryptedValue {
        alg: "xchacha20poly1305".to_string(),
        key_id: master_key.key_id.clone(),
        nonce_b64: STANDARD_NO_PAD.encode(nonce),
        ciphertext_b64: STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_value(master_key: &MasterKey, value: &EncryptedValue, aad: &[u8]) -> Result<String> {
    if value.alg != "xchacha20poly1305" {
        return Err(HemError::Crypto(format!(
            "unsupported algorithm {}",
            value.alg
        )));
    }
    if value.key_id != master_key.key_id {
        return Err(HemError::Crypto(format!(
            "key_id mismatch encrypted={} active={}",
            value.key_id, master_key.key_id
        )));
    }

    let nonce = STANDARD_NO_PAD
        .decode(value.nonce_b64.as_bytes())
        .map_err(|err| HemError::Crypto(format!("invalid nonce encoding: {err}")))?;
    if nonce.len() != 24 {
        return Err(HemError::Crypto("invalid nonce length".to_string()));
    }

    let ciphertext = STANDARD_NO_PAD
        .decode(value.ciphertext_b64.as_bytes())
        .map_err(|err| HemError::Crypto(format!("invalid ciphertext encoding: {err}")))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key.key_bytes));
    let payload = Payload {
        msg: ciphertext.as_slice(),
        aad,
    };
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce.as_slice()), payload)
        .map_err(|_| HemError::Crypto("decrypt failed".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|err| HemError::Crypto(format!("decrypted value not utf8: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_roundtrip() {
        let key = generate_master_key();
        let encrypted = encrypt_value(&key, "hello", b"aad").expect("encrypt");
        let plain = decrypt_value(&key, &encrypted, b"aad").expect("decrypt");
        assert_eq!(plain, "hello");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = generate_master_key();
        let encrypted = encrypt_value(&key, "hello", b"aad").expect("encrypt");
        let err = decrypt_value(&key, &encrypted, b"bad").expect_err("must fail");
        assert!(err.to_string().contains("decrypt failed"));
    }
}
