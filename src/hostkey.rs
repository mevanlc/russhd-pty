//! Persistent SSH host key: load it from `~/.config/russhd-pty/` if present,
//! otherwise generate a fresh ed25519 key and save it for next startup.
//!
//! Persisting the host key means clients no longer see a host-key-changed
//! warning across daemon restarts (cf. the ephemeral-key behavior in PLAN §2).

use std::path::PathBuf;

use anyhow::{Context, Result};
use russh::keys::Algorithm;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use tracing::info;

/// Directory (under the user's config home) where the host key is stored.
const CONFIG_SUBDIR: &str = "russhd-pty";
/// File name of the persisted OpenSSH-format ed25519 private key.
const KEY_FILE: &str = "host_ed25519_key";

/// Resolve the host-key path: `$XDG_CONFIG_HOME/russhd-pty/host_ed25519_key`,
/// falling back to `~/.config/russhd-pty/host_ed25519_key`.
fn key_path() -> Result<PathBuf> {
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = std::env::var_os("HOME")
                .context("neither XDG_CONFIG_HOME nor HOME is set; cannot locate config dir")?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(config_home.join(CONFIG_SUBDIR).join(KEY_FILE))
}

/// Load the persisted host key, or generate and save a new one if none exists.
///
/// The containing directory is created on first run. A freshly generated key is
/// written in OpenSSH format with `0600` permissions (handled by `ssh-key`).
pub fn load_or_generate() -> Result<PrivateKey> {
    let path = key_path()?;

    if path.exists() {
        let key = PrivateKey::read_openssh_file(&path)
            .with_context(|| format!("failed to load host key from {}", path.display()))?;
        info!(path = %path.display(), "loaded persisted host key");
        return Ok(key);
    }

    // Same generation as the previous ephemeral key (PLAN §2), now persisted.
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("failed to generate ed25519 host key")?;

    let dir = path
        .parent()
        .context("host key path has no parent directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create config directory {}", dir.display()))?;
    key.write_openssh_file(&path, LineEnding::default())
        .with_context(|| format!("failed to save host key to {}", path.display()))?;
    info!(path = %path.display(), "generated and saved new host key");

    Ok(key)
}
