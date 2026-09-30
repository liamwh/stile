//! Injectable tool paths so integration tests can substitute fakes.
//! Production callers never set the overrides and get the system paths.

use std::path::PathBuf;

/// Path of the curl binary.
pub fn curl() -> PathBuf {
    std::env::var_os("STILE_TEST_CURL")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/curl"))
}

/// Path of the docker binary.
pub fn docker() -> PathBuf {
    std::env::var_os("STILE_TEST_DOCKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/docker"))
}

/// Path of the runuser binary.
pub fn runuser() -> PathBuf {
    std::env::var_os("STILE_TEST_RUNUSER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/runuser"))
}
