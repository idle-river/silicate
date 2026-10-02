use crate::error::SilicateError;
use aes_gcm::aead::rand_core::{OsRng, RngCore};
use colored::*;
use std::io::Write;
use std::process::{Command, Stdio};

/// This function lists all the password files in the config directory, excluding the salt file.
/// It returns a vector of website names (without the .bin extension).
pub(crate) fn list_passwords(config_dir: &str) -> Result<Vec<String>, SilicateError> {
    let mut websites = Vec::new();
    if let Ok(entries) = std::fs::read_dir(config_dir) {
        for entry in entries.flatten() {
            if let Some(filename) = entry.file_name().to_str() {
                if filename.ends_with(".bin") && filename != "salt.bin" {
                    websites.push(filename.trim_end_matches(".bin").to_string());
                }
            }
        }
    }
    Ok(websites)
}

/// This function takes the config directory and an optional tag, lists the passwords, filters them by tag if provided,
pub(crate) fn search_password(
    config_dir: &str,
    tag: &Option<String>,
) -> Result<Option<String>, SilicateError> {
    let websites = list_passwords(config_dir)?;
    if websites.is_empty() {
        println!("No passwords found in the config directory.");
        return Ok(None);
    }

    let websites = if let Some(t) = tag {
        websites
            .into_iter()
            .filter(|w| {
                if let Some((_, w_tag)) = w.split_once('-') {
                    w_tag == t
                } else {
                    false
                }
            })
            .map(|w| {
                if let Some((site, _)) = w.split_once('-') {
                    site.to_string()
                } else {
                    w.clone()
                }
            })
            .collect::<Vec<String>>()
    } else {
        websites
            .into_iter()
            .map(|w| {
                if let Some((site, tag)) = w.split_once('-') {
                    format!("({}) {}", tag, site)
                } else {
                    w.clone()
                }
            })
            .collect::<Vec<String>>()
    };

    if websites.is_empty() {
        println!("{}", "No passwords found for the specified tag.".red());
        return Ok(None);
    }

    let fzf_input = websites.join("\n");

    // 3. Spawn the fzf process
    // We inherit stderr so fzf can draw its interactive UI on the terminal screen,
    // while we pipe stdin (to send data) and stdout (to catch the choice).
    let mut child = Command::new("fzf")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    // 4. Write our database records to fzf's stdin asynchronously
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(fzf_input.as_bytes())?;
    }

    // 5. Wait for the user to make a selection and exit
    let output = child.wait_with_output()?;

    // 6. Handle the result based on the exit code
    if output.status.success() {
        let selection = String::from_utf8(output.stdout)?;
        let trimmed_selection = selection.trim();

        if trimmed_selection.is_empty() {
            println!("{}", "No selection made.".red());
            Ok(None)
        } else {
            Ok(Some(trimmed_selection.to_string()))
        }
    } else {
        // Exit code 130 typically means the user pressed Esc/Ctrl-C
        println!("{}", "Selection canceled or fzf failed.".red());
        Ok(None)
    }
}

/// This function generates a random password of the specified length. If use_symbols is true, it includes symbols in the password.
pub(crate) fn generate_password(length: usize, use_symbols: bool) -> String {
    if length == 0 {
        return String::new();
    }

    let letters_and_digits = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let symbols = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    if use_symbols {
        let mut combined = Vec::with_capacity(letters_and_digits.len() + symbols.len());
        combined.extend_from_slice(letters_and_digits);
        combined.extend_from_slice(symbols);
        return sample_from_pool(&combined, length);
    }

    sample_from_pool(letters_and_digits, length)
}

fn sample_from_pool(pool: &[u8], length: usize) -> String {
    let mut rng = OsRng;
    let mut result = String::with_capacity(length);

    let pool_len = pool.len() as u32;
    // To prevent modulo bias, calculate the maximum allowable value
    // that fits perfectly into multiples of our pool length.
    let zone = u32::MAX - (u32::MAX % pool_len);

    while result.len() < length {
        // Use RngCore's next_u32 directly (always available on OsRng)
        let random_val = rng.next_u32();

        // Rejection sampling: if it falls in the biased remainder zone, skip it
        if random_val < zone {
            let idx = (random_val % pool_len) as usize;
            result.push(pool[idx] as char);
        }
    }

    result
}

pub(crate) fn update_password(
    config_dir: &str,
    key: &[u8; 32],
    website: &str,
    tag: Option<&str>,
    new_plaintext: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (new_ciphertext, new_nonce) = crate::crypto::encrypt_passwd(key, new_plaintext)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&new_nonce);
    combined_data.extend_from_slice(&new_ciphertext);
    crate::keyring::update_entry(config_dir, website, tag, &hex::encode(combined_data))?;
    Ok(())
}
