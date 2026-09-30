//! The backend seam. Today only SOPS; an `InfisicalBackend` could
//! implement the same trait later without touching broker logic.

use std::path::PathBuf;

/// Where an encrypted secret lives.
#[derive(Debug, Clone)]
pub struct StoreLocation {
    /// Absolute path of the encrypted file.
    pub path: PathBuf,
    /// dotenv key within the file, or `None` for whole-file binary.
    pub dotenv_key: Option<String>,
}

/// Backend errors. `detail` messages are safe to log: they carry
/// subprocess exit status and sanitized output only.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Subprocess failed.
    #[error("sops failed: {0}")]
    Subprocess(String),
    /// Decrypted content did not match expectations.
    #[error("store verification failed: {0}")]
    Verification(String),
    /// The encrypted file appears to be plaintext (interrupted previous
    /// rotation?). The broker refuses to touch it and alarms.
    #[error("store file appears to be UNENCRYPTED at {0}; refusing (restore from backup manually)")]
    Unencrypted(String),
    /// I/O failure.
    #[error("io error: {0}")]
    Io(String),
}

/// Read/write access to an encrypted secret store. Implementations must
/// never place secret bytes in child-process arguments or log output.
pub trait SecretStore {
    /// Decrypt and return the current value for a location. Broker-side
    /// memory only.
    fn read_value(&self, location: &StoreLocation) -> Result<Vec<u8>, StoreError>;

    /// Atomically replace the stored value: back up the encrypted file,
    /// stage plaintext, re-encrypt in place, verify the new value is
    /// retrievable, restore original permissions. On failure the original
    /// encrypted file is restored byte-for-byte.
    fn write_value_atomic(
        &self,
        location: &StoreLocation,
        new_value: &[u8],
    ) -> Result<(), StoreError>;
}
