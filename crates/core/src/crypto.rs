use crate::error::SilicateError;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};

/// Encrypts the given plaintext using AES-256-GCM. Returns the ciphertext and the nonce used for encryption.
pub(crate) fn encrypt_passwd(
    key_bytes: &[u8; 32],
    plaintext: String,
) -> Result<(Vec<u8>, [u8; 12]), SilicateError> {
    // Changed [u8; 12] to Vec<u8>
    let cipher = Aes256Gcm::new_from_slice(key_bytes)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypts the given ciphertext using AES-256-GCM. Requires the same key and nonce used for encryption.
pub(crate) fn decrypt_passwd(
    key_bytes: &[u8; 32],
    ciphertext: Vec<u8>,
    nonce_bytes: [u8; 12],
) -> Result<String, SilicateError> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext_bytes = cipher.decrypt(nonce, ciphertext.as_ref())?;
    let plaintext = String::from_utf8(plaintext_bytes)?;
    Ok(plaintext)
}
