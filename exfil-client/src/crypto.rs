use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

const PBKDF2_ITERS: u32 = 100_000;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
}

pub fn derive_key(passphrase: &str) -> [u8; KEY_SIZE] {
    let mut salt = Vec::from(passphrase.as_bytes());
    while salt.len() < KEY_SIZE {
        salt.extend_from_slice(passphrase.as_bytes());
    }
    salt.truncate(KEY_SIZE);

    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut key);
    key
}

pub fn encrypt(data: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    // Prepend nonce for transport just like the Go client
    let mut output = nonce_bytes.to_vec();
    output.append(&mut ciphertext);
    Ok(output)
}

pub fn decrypt(data: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE {
        return Err(CryptoError::Decrypt("ciphertext too short".into()));
    }

    let (nonce_bytes, payload) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("test-key");
        let plaintext = b"top secret payload";
        let ciphertext = encrypt(plaintext, &key).expect("encrypt");
        let recovered = decrypt(&ciphertext, &key).expect("decrypt");
        assert_eq!(plaintext.to_vec(), recovered);
    }
}
