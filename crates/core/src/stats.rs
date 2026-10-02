use crate::error::SilicateError;
use std::fs;

pub struct Stats {
    pub total_passwords: usize,
    pub unique_tags: usize,
    pub init_timestamp: chrono::DateTime<chrono::Utc>,
}

/// This function will get stats for the password manager, such as the total number of passwords and the number of unique tags.
pub(crate) fn get_stats(config_dir: &str) -> Result<Stats, SilicateError> {
    let passwords = crate::passwords::list_passwords(config_dir)?;
    let total_passwords = passwords.len();
    let unique_tags = crate::tags::list_tags(config_dir)?.len();
    let init_timestamp = match fs::read_to_string(config_dir.to_string() + "init_timestamp.txt") {
        Ok(timestamp) => chrono::DateTime::parse_from_rfc3339(&timestamp.trim())
            .map_err(|e| {
                SilicateError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to parse init timestamp: {}", e),
                ))
            })?
            .with_timezone(&chrono::Utc),
        Err(_) => chrono::Utc::now(),
    };
    Ok(Stats {
        total_passwords,
        unique_tags,
        init_timestamp,
    })
}
