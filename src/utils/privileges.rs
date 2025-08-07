use nix::unistd::{getuid, geteuid};
use crate::utils::errors::Result;

pub fn check_privileges() -> Result<PrivilegeStatus> {
    let uid = getuid();
    let euid = geteuid();
    
    // Check if we're actually running as root
    if uid.is_root() || euid.is_root() {
        return Ok(PrivilegeStatus::Root);
    }
    
    // Check if we're running under sudo (SUDO_UID environment variable is set when using sudo)
    if std::env::var("SUDO_UID").is_ok() {
        return Ok(PrivilegeStatus::Sudo);
    }
    
    // If not root and not running under sudo, then it's a regular user
    // (regardless of whether they COULD use sudo)
    Ok(PrivilegeStatus::User)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrivilegeStatus {
    Root,
    Sudo,
    User,
}

// Unused privilege utility methods removed