use crate::error::SilicateError;

/// This function will get all unique tags from the password files in the config directory.
pub(crate) fn list_tags(config_dir: &str) -> Result<Vec<String>, SilicateError> {
    let mut tags = Vec::new();
    let passwords = crate::passwords::list_passwords(config_dir)?;
    for password in passwords {
        if let Some((_, tag)) = password.split_once('-') {
            if !tags.contains(&tag.to_string()) {
                tags.push(tag.to_string());
            }
        }
    }
    Ok(tags)
}
