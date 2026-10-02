use crate::error::SilicateError;

pub mod crypto;
pub mod error;
pub mod keyring;
pub mod keys;
pub mod passwords;
pub mod stats;
pub mod tags;

pub struct Silicate {
    config_dir: String,
}

impl Silicate {
    pub fn new(config_dir: String) -> Self {
        Self { config_dir }
    }

    pub fn config_dir(&self) -> &str {
        &self.config_dir
    }

    pub fn check_fzf_installed(&self) -> bool {
        check_fzf_installed()
    }

    pub fn encrypt_passwd(
        &self,
        key_bytes: &[u8; 32],
        plaintext: String,
    ) -> Result<(Vec<u8>, [u8; 12]), SilicateError> {
        crypto::encrypt_passwd(key_bytes, plaintext)
    }

    pub fn decrypt_passwd(
        &self,
        key_bytes: &[u8; 32],
        ciphertext: Vec<u8>,
        nonce_bytes: [u8; 12],
    ) -> Result<String, SilicateError> {
        crypto::decrypt_passwd(key_bytes, ciphertext, nonce_bytes)
    }

    pub fn store_key_in_keyring(&self, key: &[u8; 32]) -> Result<(), SilicateError> {
        keyring::store_key_in_keyring(key)
    }

    pub fn retrieve_key_from_keyring(&self) -> Result<[u8; 32], SilicateError> {
        keyring::retrieve_key_from_keyring()
    }

    pub fn is_keyring_available(&self) -> bool {
        keyring::is_keyring_available()
    }

    pub fn update_entry(
        &self,
        website: &str,
        tag: Option<&str>,
        new_data: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        keyring::update_entry(&self.config_dir, website, tag, new_data)
    }

    pub fn generate_key(&self) -> [u8; 32] {
        keys::generate_key()
    }

    pub fn generate_fallback_key(
        &self,
        password: &str,
    ) -> Result<([u8; 32], [u8; 16]), SilicateError> {
        keys::generate_fallback_key(password)
    }

    pub fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8; 16],
    ) -> Result<[u8; 32], SilicateError> {
        keys::derive_key_from_password(password, salt)
    }

    pub fn export_key(&self, file_path: &Option<String>) -> Result<(), SilicateError> {
        keys::export_key(file_path)
    }

    pub fn import_key(&self, file_path: &str) -> Result<(), SilicateError> {
        keys::import_key(file_path)
    }

    pub fn list_passwords(&self) -> Result<Vec<String>, SilicateError> {
        passwords::list_passwords(&self.config_dir)
    }

    pub fn search_password(&self, tag: &Option<String>) -> Result<Option<String>, SilicateError> {
        passwords::search_password(&self.config_dir, tag)
    }

    pub fn generate_password(&self, length: usize, use_symbols: bool) -> String {
        passwords::generate_password(length, use_symbols)
    }

    pub fn update_password(
        &self,
        key: &[u8; 32],
        website: &str,
        tag: Option<&str>,
        new_plaintext: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        passwords::update_password(&self.config_dir, key, website, tag, new_plaintext)
    }

    pub fn list_tags(&self) -> Result<Vec<String>, SilicateError> {
        tags::list_tags(&self.config_dir)
    }

    pub fn get_stats(&self) -> Result<stats::Stats, SilicateError> {
        stats::get_stats(&self.config_dir)
    }

    pub fn find_password_file(
        &self,
        target_website: &str,
    ) -> Result<Option<String>, SilicateError> {
        find_password_file(&self.config_dir, target_website)
    }

    pub fn rename_password_file(
        &self,
        old_website: &str,
        new_website: &str,
        tag: &Option<String>,
    ) -> Result<(), SilicateError> {
        rename_password_file(&self.config_dir, old_website, new_website, tag)
    }
}

/// This function checks if fzf is installed on the system by trying to find its path.
fn check_fzf_installed() -> bool {
    which::which("fzf").is_ok()
}

fn find_password_file(
    config_dir: &str,
    target_website: &str,
) -> Result<Option<String>, SilicateError> {
    let passwords = passwords::list_passwords(config_dir)?;

    Ok(passwords.into_iter().find(|filename| {
        // If it's an exact match (no tag)
        if filename == target_website {
            return true;
        }

        // If it has a tag, check if the part before the first '-' matches
        if let Some((base_website, _tag)) = filename.split_once('-') {
            if base_website == target_website {
                return true;
            }
        }

        false
    }))
}

/// This function will rename a password file in the config directory.
fn rename_password_file(
    config_dir: &str,
    old_website: &str,
    new_website: &str,
    tag: &Option<String>,
) -> Result<(), SilicateError> {
    let old_file_path = find_password_file(config_dir, old_website)?.ok_or_else(|| {
        SilicateError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Password file for '{}' not found", old_website),
        ))
    })? + ".bin";

    let tag = if let Some(t) = tag {
        Some(t.clone())
    } else {
        // Try to extract the tag from the old filename if it exists
        if let Some((_, existing_tag)) = old_file_path.split_once('-') {
            Some(existing_tag.to_string())
        } else {
            None
        }
    };

    let old_file_path = std::path::Path::new(config_dir).join(&old_file_path);

    let new_file_name = if let Some(t) = tag {
        format!("{}-{}.bin", new_website, t)
    } else {
        format!("{}.bin", new_website)
    };

    let new_file_path = std::path::Path::new(config_dir).join(new_file_name);

    std::fs::rename(old_file_path, new_file_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = keys::generate_key();
        let plaintext = "This is a test password.".to_string();
        let (ciphertext, nonce) = crypto::encrypt_passwd(&key, plaintext.clone()).unwrap();
        let decrypted = crypto::decrypt_passwd(&key, ciphertext.to_vec(), nonce).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_fallback_key_derivation() {
        let password = "test_password";
        let (derived_key, salt) = keys::generate_fallback_key(password).unwrap();
        let derived_key_again = keys::derive_key_from_password(password, &salt).unwrap();
        assert_eq!(derived_key, derived_key_again);
    }

    #[test]
    fn test_password_generation() {
        let password = passwords::generate_password(16, true);
        assert_eq!(password.len(), 16);
        assert!(
            password
                .chars()
                .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        );
    }

    #[test]
    fn password_generation_no_symbols() {
        let password = passwords::generate_password(16, false);
        assert_eq!(password.len(), 16);
        assert!(
            !password
                .chars()
                .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        );
    }
}
