use crate::SilicateError;
use aes_gcm::{Aes256Gcm, KeyInit, aead::OsRng};
use argon2::password_hash::{PasswordHasher, rand_core::OsRng as ArOsRng};
use argon2::{Argon2, password_hash::SaltString};

/// Generates a random 256-bit key for AES encryption.
pub fn generate_key() -> [u8; 32] {
    let key = Aes256Gcm::generate_key(OsRng);
    key.into()
}

/// Generates a fallback key using a password-based key derivation.
/// This is used when the user doesn't have a secure key management solution in place.
/// Returns the derived key and the salt used for hashing.
pub fn generate_fallback_key(password: &str) -> Result<([u8; 32], [u8; 16]), SilicateError> {
    let salt = SaltString::generate(&mut ArOsRng);
    let argon2 = Argon2::default(); // 32-byte output by default
    let hashed = argon2.hash_password(password.as_bytes(), &salt)?;
    let key_bytes: [u8; 32] = hashed
        .hash
        .ok_or_else(|| {
            SilicateError::Argon2PasswordHashError(argon2::password_hash::Error::Password)
        })?
        .as_bytes()
        .try_into()?;
    let mut salt_bytes = [0u8; 16];
    salt.decode_b64(&mut salt_bytes)?;
    Ok((key_bytes, salt_bytes))
}

/// This function will take a salt and a password and derive the same key as the generate_fallback_key function.
/// This is used for retrieving the key when the user doesn't have a secure key management solution in place.
pub fn derive_key_from_password(
    password: &str,
    salt: &[u8; 16],
) -> Result<[u8; 32], SilicateError> {
    let salt_string = SaltString::encode_b64(salt)?;
    let argon2 = Argon2::default(); // 32-byte output by default
    let hashed = argon2.hash_password(password.as_bytes(), &salt_string)?;
    let key_bytes: [u8; 32] = hashed
        .hash
        .ok_or_else(|| {
            SilicateError::Argon2PasswordHashError(argon2::password_hash::Error::Password)
        })?
        .as_bytes()
        .try_into()?;
    Ok(key_bytes)
}

/// This function will export the key from the keyring to a file in the config directory.
/// This is for users who need to backup their key or export a key that was generated on a different machine.
pub fn export_key(file_path: &Option<String>) -> Result<(), SilicateError> {
    let key = crate::keyring::retrieve_key_from_keyring()?;
    let path = file_path.as_ref().map_or_else(
        || {
            format!(
                "./key-{}.bin",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S")
            )
        },
        |p| p.clone(),
    );
    std::fs::write(&path, key).unwrap();
    println!("Key exported to {}", path);
    Ok(())
}

/// This function imports the key from a file and stores it in the keyring.
/// This is for users who need to restore a key from a backup or import a key that was generated on a different machine.
pub fn import_key(file_path: &str) -> Result<(), SilicateError> {
    let key_bytes = std::fs::read(file_path).unwrap();
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "Invalid key file: expected 32 bytes")
        .unwrap();
    crate::keyring::store_key_in_keyring(&key)?;
    println!("Key imported and stored in keyring.");
    Ok(())
}
