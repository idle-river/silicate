use crate::error::SilicateError;
use keyring::Entry;

const SERVICE_NAME: &str = "silicate";
const USERNAME: &str = "default";

/// This puts a randomly generated key into the system's keyring.
pub(crate) fn store_key_in_keyring(key: &[u8; 32]) -> Result<(), SilicateError> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    entry.set_password(&hex::encode(key))?;
    Ok(())
}

/// This retrieves the key from the system's keyring.
pub(crate) fn retrieve_key_from_keyring() -> Result<[u8; 32], SilicateError> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    let key_hex = entry.get_password()?;
    let key_bytes: [u8; 32] = hex::decode(key_hex)?.try_into()?;
    Ok(key_bytes)
}

/// This function checks if a keyring is available and can be accessed.
/// This will be for checking if the user has a secure key management solution in place.
pub(crate) fn is_keyring_available() -> bool {
    let entry = Entry::new(SERVICE_NAME, USERNAME);
    entry.is_ok()
}

pub(crate) fn update_entry(
    config_dir: &str,
    website: &str,
    tag: Option<&str>,
    new_data: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = if let Some(t) = tag {
        format!("{}-{}.bin", website, t)
    } else {
        format!("{}.bin", website)
    };
    let filepath = std::path::Path::new(config_dir).join(filename);
    std::fs::write(filepath, new_data)?;
    Ok(())
}
