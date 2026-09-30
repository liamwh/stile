//! Broker daemon configuration (`/etc/stile/brokerd.toml`,
//! root-owned).

use std::path::PathBuf;

/// Daemon configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Unix socket path.
    pub socket_path: PathBuf,
    /// Registry TOML path (root-owned install of the infra declaration).
    pub registry_path: PathBuf,
    /// Audit log path.
    pub audit_path: PathBuf,
    /// Broker-private work dir for temp files.
    pub work_dir: PathBuf,
    /// SOPS binary.
    pub sops_bin: PathBuf,
    /// Broker age identity (root-owned).
    pub age_key_file: PathBuf,
    /// Encrypted backup dir.
    pub backup_dir: PathBuf,
    /// Unix group name permitted to connect (members may call lifecycle
    /// operations; the socket is 0660 root:<group>).
    pub access_group: String,
    /// UIDs additionally permitted (root always allowed).
    #[serde(default)]
    pub allowed_uids: Vec<u32>,
}

/// Runtime config with resolved group gid.
pub struct Config {
    /// Parsed file.
    pub file: ConfigFile,
    gid: Option<u32>,
}

impl Config {
    /// Load and sanity-check.
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let file: ConfigFile = toml::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
        let gid = group_gid(&file.access_group);
        if gid.is_none() {
            return Err(format!("access group {} does not exist", file.access_group));
        }
        Ok(Self { file, gid })
    }

    /// Resolved gid of the access group.
    pub fn access_group(&self) -> Option<u32> {
        self.gid
    }

    /// Peer authorization: root, allowlisted uid, or a user whose group
    /// membership (including supplementary groups, resolved via
    /// getgrouplist since SO_PEERCRED only reports the primary gid)
    /// contains the access group.
    pub fn peer_allowed(&self, uid: u32, _primary_gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if self.file.allowed_uids.contains(&uid) {
            return true;
        }
        let Some(group_gid) = self.gid else {
            return false;
        };
        user_in_group(uid, group_gid)
    }
}

fn group_gid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam(3) with a NUL-terminated name; the returned
    // pointer is read immediately before any other libc group call.
    unsafe {
        let gr = libc::getgrnam(cname.as_ptr());
        if gr.is_null() {
            return None;
        }
        Some((*gr).gr_gid)
    }
}

fn user_in_group(uid: u32, group_gid: u32) -> bool {
    // Resolve uid -> username.
    // SAFETY: getpwuid(3) returns a passwd pointer valid until the next
    // passwd function call; we copy the strings out immediately.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return false;
    }
    // SAFETY: pw_name is a valid NUL-terminated pointer owned by
    // getpwuid(3)'s static storage, read before any other passwd call.
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
        .to_string_lossy()
        .into_owned();
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut groups = [0u32; 64];
    let mut ngroups = groups.len() as i32;
    // SAFETY: getgrouplist(3) fills the caller-provided gid buffer.
    let rc = unsafe {
        libc::getgrouplist(
            cname.as_ptr(),
            (*pw).pw_gid,
            groups.as_mut_ptr(),
            &mut ngroups,
        )
    };
    if rc < 0 {
        return false;
    }
    groups[..(rc as usize)].contains(&group_gid)
}
