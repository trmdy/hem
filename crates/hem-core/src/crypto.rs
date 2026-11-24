use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeWrapKeyPair {
    pub public_key_b64: String,
    pub private_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeyRecipient {
    pub node_id: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDataKey {
    pub node_id: String,
    pub recipient_public_key_b64: String,
    pub ephemeral_public_key_b64: String,
    pub nonce_b64: String,
    pub encrypted_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeEncryptedValue {
    pub alg: String,
    pub data_key_id: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub wraps: Vec<WrappedDataKey>,
}

pub fn generate_master_key() -> MasterKey {
    let mut key_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    MasterKey {
        key_id: format!("mk-{}", hem_config::ids::generate_entropy_prefixed_ulid()),
        key_bytes,
    }
}

pub fn generate_node_wrap_keypair() -> NodeWrapKeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    NodeWrapKeyPair {
        public_key_b64: STANDARD_NO_PAD.encode(public.as_bytes()),
        private_key_b64: STANDARD_NO_PAD.encode(secret.to_bytes()),
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

pub fn envelope_encrypt_for_nodes(
    value: &str,
    aad: &[u8],
    recipients: &[NodeKeyRecipient],
) -> Result<EnvelopeEncryptedValue> {
    if recipients.is_empty() {
        return Err(HemError::InvalidArgument(
            "at least one node key recipient is required".to_string(),
        ));
    }
    let mut data_key = [0_u8; 32];
    OsRng.fill_bytes(&mut data_key);
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&data_key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: value.as_bytes(),
                aad,
            },
        )
        .map_err(|_| HemError::Crypto("envelope encrypt failed".to_string()))?;

    let mut wraps = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let recipient_public = decode_x25519_public_key(recipient.public_key_b64.as_str())?;
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(&recipient_public);
        let wrap_key = derive_wrap_key(
            shared.as_bytes(),
            recipient.node_id.as_str(),
            recipient.public_key_b64.as_str(),
            STANDARD_NO_PAD.encode(ephemeral_public.as_bytes()).as_str(),
        );
        let mut wrap_nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut wrap_nonce);
        let wrap_cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
        let encrypted_key = wrap_cipher
            .encrypt(
                XNonce::from_slice(&wrap_nonce),
                Payload {
                    msg: data_key.as_slice(),
                    aad: envelope_wrap_aad(aad, recipient.node_id.as_str()).as_slice(),
                },
            )
            .map_err(|_| HemError::Crypto("data key wrap failed".to_string()))?;
        wraps.push(WrappedDataKey {
            node_id: recipient.node_id.clone(),
            recipient_public_key_b64: recipient.public_key_b64.clone(),
            ephemeral_public_key_b64: STANDARD_NO_PAD.encode(ephemeral_public.as_bytes()),
            nonce_b64: STANDARD_NO_PAD.encode(wrap_nonce),
            encrypted_key_b64: STANDARD_NO_PAD.encode(encrypted_key),
        });
    }

    Ok(EnvelopeEncryptedValue {
        alg: "hem-node-envelope-v1".to_string(),
        data_key_id: format!("hdek_{}", hem_config::ids::generate_entropy_prefixed_ulid()),
        nonce_b64: STANDARD_NO_PAD.encode(nonce),
        ciphertext_b64: STANDARD_NO_PAD.encode(ciphertext),
        wraps,
    })
}

pub fn envelope_decrypt_for_node(
    value: &EnvelopeEncryptedValue,
    aad: &[u8],
    node_id: &str,
    private_key_b64: &str,
) -> Result<String> {
    if value.alg != "hem-node-envelope-v1" {
        return Err(HemError::Crypto(format!(
            "unsupported envelope algorithm {}",
            value.alg
        )));
    }
    let wrap = value
        .wraps
        .iter()
        .find(|wrap| wrap.node_id == node_id)
        .ok_or_else(|| HemError::AuthorizationDenied(format!("node {node_id} is not wrapped")))?;
    let private_key = decode_x25519_private_key(private_key_b64)?;
    let ephemeral_public = decode_x25519_public_key(wrap.ephemeral_public_key_b64.as_str())?;
    let shared = private_key.diffie_hellman(&ephemeral_public);
    let wrap_key = derive_wrap_key(
        shared.as_bytes(),
        wrap.node_id.as_str(),
        wrap.recipient_public_key_b64.as_str(),
        wrap.ephemeral_public_key_b64.as_str(),
    );
    let wrap_nonce = decode_base64_exact::<24>("wrap nonce", wrap.nonce_b64.as_str())?;
    let encrypted_key = STANDARD_NO_PAD
        .decode(wrap.encrypted_key_b64.as_bytes())
        .map_err(|err| HemError::Crypto(format!("invalid wrapped key encoding: {err}")))?;
    let wrap_cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let data_key = wrap_cipher
        .decrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload {
                msg: encrypted_key.as_slice(),
                aad: envelope_wrap_aad(aad, node_id).as_slice(),
            },
        )
        .map_err(|_| HemError::Crypto("data key unwrap failed".to_string()))?;
    if data_key.len() != 32 {
        return Err(HemError::Crypto(
            "unwrapped data key length invalid".to_string(),
        ));
    }
    let nonce = decode_base64_exact::<24>("envelope nonce", value.nonce_b64.as_str())?;
    let ciphertext = STANDARD_NO_PAD
        .decode(value.ciphertext_b64.as_bytes())
        .map_err(|err| HemError::Crypto(format!("invalid envelope ciphertext: {err}")))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(data_key.as_slice()));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| HemError::Crypto("envelope decrypt failed".to_string()))?;
    String::from_utf8(plaintext)
        .map_err(|err| HemError::Crypto(format!("decrypted value not utf8: {err}")))
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

fn decode_x25519_public_key(value: &str) -> Result<X25519PublicKey> {
    Ok(X25519PublicKey::from(decode_base64_exact::<32>(
        "wrap public key",
        value,
    )?))
}

fn decode_x25519_private_key(value: &str) -> Result<StaticSecret> {
    Ok(StaticSecret::from(decode_base64_exact::<32>(
        "wrap private key",
        value,
    )?))
}

fn decode_base64_exact<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let bytes = STANDARD_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| HemError::Crypto(format!("{label} must be base64-no-pad: {err}")))?;
    bytes
        .try_into()
        .map_err(|_| HemError::Crypto(format!("{label} decoded length must be {N} bytes")))
}

fn derive_wrap_key(
    shared_secret: &[u8; 32],
    node_id: &str,
    recipient_public_key_b64: &str,
    ephemeral_public_key_b64: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hem-node-wrap-v1");
    hasher.update(shared_secret);
    hasher.update(node_id.as_bytes());
    hasher.update(recipient_public_key_b64.as_bytes());
    hasher.update(ephemeral_public_key_b64.as_bytes());
    hasher.finalize().into()
}

fn envelope_wrap_aad(value_aad: &[u8], node_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value_aad.len() + node_id.len() + 18);
    out.extend_from_slice(b"hem-wrap-aad-v1:");
    out.extend_from_slice(node_id.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(value_aad);
    out
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

    #[test]
    fn envelope_wrap_roundtrip_for_authorized_node() {
        let node = generate_node_wrap_keypair();
        let encrypted = envelope_encrypt_for_nodes(
            "hello",
            b"scope/name/key",
            &[NodeKeyRecipient {
                node_id: "hmn_a".to_string(),
                public_key_b64: node.public_key_b64.clone(),
            }],
        )
        .expect("encrypt");
        let plain = envelope_decrypt_for_node(
            &encrypted,
            b"scope/name/key",
            "hmn_a",
            node.private_key_b64.as_str(),
        )
        .expect("decrypt");
        assert_eq!(plain, "hello");
    }

    #[test]
    fn envelope_wrap_denies_unauthorized_node() {
        let node_a = generate_node_wrap_keypair();
        let node_b = generate_node_wrap_keypair();
        let encrypted = envelope_encrypt_for_nodes(
            "hello",
            b"scope/name/key",
            &[NodeKeyRecipient {
                node_id: "hmn_a".to_string(),
                public_key_b64: node_a.public_key_b64,
            }],
        )
        .expect("encrypt");
        let err = envelope_decrypt_for_node(
            &encrypted,
            b"scope/name/key",
            "hmn_b",
            node_b.private_key_b64.as_str(),
        )
        .expect_err("unauthorized");
        assert!(matches!(err, HemError::AuthorizationDenied(_)));
    }

    #[test]
    fn envelope_wrap_rejects_wrong_aad_and_survives_key_rotation() {
        let old_node = generate_node_wrap_keypair();
        let new_node = generate_node_wrap_keypair();
        let old_encrypted = envelope_encrypt_for_nodes(
            "old",
            b"scope/name/key",
            &[NodeKeyRecipient {
                node_id: "hmn_a".to_string(),
                public_key_b64: old_node.public_key_b64.clone(),
            }],
        )
        .expect("encrypt old");
        let new_encrypted = envelope_encrypt_for_nodes(
            "new",
            b"scope/name/key",
            &[NodeKeyRecipient {
                node_id: "hmn_a".to_string(),
                public_key_b64: new_node.public_key_b64.clone(),
            }],
        )
        .expect("encrypt new");
        assert!(envelope_decrypt_for_node(
            &old_encrypted,
            b"wrong",
            "hmn_a",
            old_node.private_key_b64.as_str(),
        )
        .is_err());
        assert_eq!(
            envelope_decrypt_for_node(
                &old_encrypted,
                b"scope/name/key",
                "hmn_a",
                old_node.private_key_b64.as_str(),
            )
            .expect("old decrypt"),
            "old"
        );
        assert_eq!(
            envelope_decrypt_for_node(
                &new_encrypted,
                b"scope/name/key",
                "hmn_a",
                new_node.private_key_b64.as_str(),
            )
            .expect("new decrypt"),
            "new"
        );
    }
}
