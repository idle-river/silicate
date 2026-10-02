#[derive(Debug)]
pub enum SilicateError {
    Plain(&'static str),
    KeyringError(keyring::Error),
    IoError(std::io::Error),
    HexError(hex::FromHexError),
    SerdeJsonError(serde_json::Error),
    Argon2Error(argon2::password_hash::Error),
    AesGcmError(aes_gcm::Error),
    AesInvalidKeyLengthError(aes_gcm::aes::cipher::InvalidLength),
    StdioError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
    Argon2PasswordHashError(argon2::password_hash::Error),
    TryFromSliceError(std::array::TryFromSliceError),
}

impl From<&'static str> for SilicateError {
    fn from(err: &'static str) -> SilicateError {
        SilicateError::Plain(err)
    }
}

impl From<keyring::Error> for SilicateError {
    fn from(err: keyring::Error) -> SilicateError {
        SilicateError::KeyringError(err)
    }
}

impl From<std::io::Error> for SilicateError {
    fn from(err: std::io::Error) -> SilicateError {
        SilicateError::IoError(err)
    }
}

impl From<hex::FromHexError> for SilicateError {
    fn from(err: hex::FromHexError) -> SilicateError {
        SilicateError::HexError(err)
    }
}

impl From<serde_json::Error> for SilicateError {
    fn from(err: serde_json::Error) -> SilicateError {
        SilicateError::SerdeJsonError(err)
    }
}

impl From<argon2::password_hash::Error> for SilicateError {
    fn from(err: argon2::password_hash::Error) -> SilicateError {
        SilicateError::Argon2Error(err)
    }
}

impl From<aes_gcm::Error> for SilicateError {
    fn from(err: aes_gcm::Error) -> SilicateError {
        SilicateError::AesGcmError(err)
    }
}

impl From<std::string::FromUtf8Error> for SilicateError {
    fn from(err: std::string::FromUtf8Error) -> SilicateError {
        SilicateError::Utf8Error(err)
    }
}

impl From<aes_gcm::aes::cipher::InvalidLength> for SilicateError {
    fn from(err: aes_gcm::aes::cipher::InvalidLength) -> SilicateError {
        SilicateError::AesInvalidKeyLengthError(err)
    }
}

impl From<std::array::TryFromSliceError> for SilicateError {
    fn from(err: std::array::TryFromSliceError) -> SilicateError {
        SilicateError::TryFromSliceError(err)
    }
}

impl From<Vec<u8>> for SilicateError {
    fn from(err: Vec<u8>) -> SilicateError {
        SilicateError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Vec<u8> error: {:?}", err),
        ))
    }
}

impl std::fmt::Display for SilicateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SilicateError::KeyringError(e) => write!(f, "Keyring error: {}", e),
            SilicateError::IoError(e) => write!(f, "I/O error: {}", e),
            SilicateError::HexError(e) => write!(f, "Hex decoding error: {}", e),
            SilicateError::SerdeJsonError(e) => {
                write!(f, "JSON serialization/deserialization error: {}", e)
            }
            SilicateError::Argon2Error(e) => write!(f, "Argon2 error: {}", e),
            SilicateError::AesGcmError(e) => {
                write!(f, "AES-GCM encryption/decryption error: {}", e)
            }
            SilicateError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            SilicateError::AesInvalidKeyLengthError(e) => {
                write!(f, "AES invalid key length error: {}", e)
            }
            SilicateError::TryFromSliceError(e) => write!(f, "TryFromSlice error: {}", e),
            SilicateError::Argon2PasswordHashError(e) => {
                write!(f, "Argon2 password hash error: {}", e)
            }
            SilicateError::StdioError(e) => write!(f, "Stdio error: {}", e),
            SilicateError::Plain(e) => {
                let msg = e.to_string();
                write!(f, "Program Error: {msg}")
            }
        }
    }
}
