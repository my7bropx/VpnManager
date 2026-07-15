//! wireguard.rs – WireGuard session wrapper using wg-quick
//!
//! wg-quick is synchronous: `wg-quick up` blocks until the interface is
//! configured, so there is no log-tailer thread. The interface name is
//! derived from the temp config filename (max 15 chars for Linux).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::state::{log_push, LogBuf};

pub const TMP_CONF: &str = "/tmp/wgvpnm.conf";
const WG_IFACE: &str = "wgvpnm";

pub struct WireGuardSession {
    tmp_conf: PathBuf,
    pub iface: String,
    stopped:  bool,
}

impl WireGuardSession {
    pub fn start(config: &Path, verbose: bool, log: &LogBuf) -> Result<Self> {
        // Copy to a fixed short name so the derived interface name stays ≤15 chars.
        // Normalise on the way: strip a UTF-8 BOM and Windows line endings —
        // wg rejects a key with a trailing \r as "Key is not the correct
        // length or format".
        let raw = std::fs::read_to_string(config)
            .with_context(|| format!("read WireGuard config {}", config.display()))?;
        let cleaned = raw.trim_start_matches('\u{feff}').replace('\r', "");
        std::fs::write(TMP_CONF, cleaned)
            .context("write WireGuard config to /tmp/wgvpnm.conf")?;

        // 600 — the config holds the private key, and wg-quick warns
        // "world accessible" otherwise
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(TMP_CONF, std::fs::Permissions::from_mode(0o600));
        }

        if verbose {
            println!("[vpn-manager] wg-quick up {TMP_CONF}");
        }

        let out = Command::new("wg-quick")
            .args(["up", TMP_CONF])
            .output()
            .context(
                "failed to run wg-quick — is wireguard-tools installed?\n\
                 Try: apt install wireguard-tools",
            )?;

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        for line in stdout.lines().chain(stderr.lines()) {
            let entry = format!("wg-quick  {line}");
            log_push(log, &entry);
            if verbose { println!("{entry}"); }
        }

        if !out.status.success() {
            anyhow::bail!(
                "wg-quick up failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                stderr.trim()
            );
        }

        Ok(Self {
            tmp_conf: PathBuf::from(TMP_CONF),
            iface:    WG_IFACE.to_string(),
            stopped:  false,
        })
    }

    pub fn stop(&mut self) {
        let _ = Command::new("wg-quick")
            .args(["down", self.tmp_conf.to_str().unwrap_or(TMP_CONF)])
            .status();
        let _ = std::fs::remove_file(&self.tmp_conf);
        self.stopped = true;
    }

}

impl Drop for WireGuardSession {
    fn drop(&mut self) {
        // Best-effort teardown; errors ignored since we're in a destructor.
        // Skipped after stop() — running wg-quick down twice just prints
        // "`/tmp/wgvpnm.conf' does not exist" noise.
        if self.stopped { return; }
        let _ = Command::new("wg-quick")
            .args(["down", self.tmp_conf.to_str().unwrap_or(TMP_CONF)])
            .status();
        let _ = std::fs::remove_file(&self.tmp_conf);
    }
}

// ─── Config inspection ────────────────────────────────────────────────────────

/// A WireGuard key is 32 bytes base64-encoded: exactly 44 chars ending in '='.
fn is_valid_wg_key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Sanity-check a WireGuard config without touching the network.
/// Catches the classic failure modes before we tear down a working tunnel:
/// placeholder keys (a config copy-pasted from a provider page shows the
/// private key masked as "*****"), truncated keys, and missing sections.
pub fn validate_config(path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let mut private_key: Option<String> = None;
    let mut has_endpoint = false;

    for line in text.lines() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("privatekey") {
            if let Some((_, v)) = t.split_once('=') {
                private_key = Some(v.trim().to_string());
            }
        } else if lower.starts_with("endpoint") && t.contains('=') {
            has_endpoint = true;
        }
    }

    match private_key {
        None => return Err("no PrivateKey in the [Interface] section".into()),
        Some(k) if k.contains('*') => {
            return Err("PrivateKey is a masked placeholder (\"*****\") — \
                        re-download the config from your VPN provider".into());
        }
        Some(k) if !is_valid_wg_key(&k) => {
            return Err(format!(
                "PrivateKey is not a valid WireGuard key ({} chars, expected 44 base64 chars)",
                k.len()
            ));
        }
        Some(_) => {}
    }

    if !has_endpoint {
        return Err("no Endpoint in any [Peer] section".into());
    }
    Ok(())
}

pub fn is_wireguard_config(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|s| s.lines().any(|l| matches!(l.trim(), "[Interface]" | "[Peer]")))
        .unwrap_or(false)
}

/// Parse `DNS = ...` from the [Interface] section.
pub fn parse_dns(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    for line in text.lines() {
        let t = line.trim();
        if t.to_ascii_lowercase().starts_with("dns") && t.contains('=') {
            let rhs = t.split_once('=').map(|x| x.1).unwrap_or("").trim();
            return rhs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    vec![]
}

/// Parse `Endpoint = host:port` lines from all [Peer] sections.
/// Returns (host, port, "udp") tuples (WireGuard is always UDP).
pub fn parse_endpoints(path: &Path) -> Vec<(String, u16, String)> {
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.to_ascii_lowercase().starts_with("endpoint") && t.contains('=') {
            let rhs = t.split_once('=').map(|x| x.1).unwrap_or("").trim();
            let (host, port) = if rhs.starts_with('[') {
                // IPv6: [addr]:port
                let close = rhs.find(']').unwrap_or(rhs.len());
                let h = rhs[1..close].to_string();
                let p = rhs.get(close + 2..).and_then(|s| s.parse().ok()).unwrap_or(51820);
                (h, p)
            } else {
                // IPv4: host:port
                let mut parts = rhs.rsplitn(2, ':');
                let p = parts.next().and_then(|s| s.parse().ok()).unwrap_or(51820);
                let h = parts.next().unwrap_or(rhs).to_string();
                (h, p)
            };
            out.push((host, port, "udp".to_string()));
        }
    }
    out
}
