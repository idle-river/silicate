use error::SilicateError;

pub mod crypto;
pub mod error;
pub mod keyring;
pub mod keys;
pub mod passwords;
pub mod stats;
pub mod tags;

/// This function checks if fzf is installed on the system by trying to find its path.
pub fn check_fzf_installed() -> bool {
    which::which("fzf").is_ok()
}

pub fn find_password_file(
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
pub fn rename_password_file(
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
