//! configs.rs – VPN config discovery
//!
//! Shared by the `list` subcommand and the TUI "Configs" tab. Detects the
//! protocol by content (a WireGuard .conf has [Interface]/[Peer] sections),
//! not just by extension, and skips .conf files that are neither.

use std::path::{Path, PathBuf};

use crate::wireguard;

pub struct ConfigEntry {
    pub path:   PathBuf,
    pub name:   String,
    pub kind:   &'static str, // "OpenVPN" | "WireGuard"
    pub server: String,
}

/// Scan a directory (non-recursive) for .ovpn / WireGuard .conf files.
pub fn scan(dir: &Path) -> Vec<ConfigEntry> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };

    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("ovpn") | Some("conf")
        ))
        .collect();
    files.sort();

    let mut out = Vec::new();
    for p in files {
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();

        if wireguard::is_wireguard_config(&p) {
            let server = wireguard::parse_endpoints(&p).into_iter().next()
                .map(|(h, port, _)| format!("{h}:{port}"))
                .unwrap_or_else(|| "—".into());
            out.push(ConfigEntry { path: p, name, kind: "WireGuard", server });
        } else {
            let remotes = extract_remotes_from_config(&p);
            let looks_ovpn = p.extension().and_then(|e| e.to_str()) == Some("ovpn")
                || !remotes.is_empty();
            if !looks_ovpn { continue; } // .conf that is neither WG nor OpenVPN

            let server = remotes.first()
                .map(|(h, port, proto)| format!("{h}:{port}/{proto}"))
                .unwrap_or_else(|| "—".into());
            out.push(ConfigEntry { path: p, name, kind: "OpenVPN", server });
        }
    }
    out
}

/// Sanity-check a config before connecting (or switching) to it.
/// Returns a human-readable reason when the file can't work.
pub fn validate(path: &Path) -> Result<(), String> {
    if wireguard::is_wireguard_config(path) {
        wireguard::validate_config(path)
    } else if extract_remotes_from_config(path).is_empty() {
        Err("no `remote` directive found — not a usable OpenVPN profile".into())
    } else {
        Ok(())
    }
}

/// First `remote <host>` from an .ovpn file.
pub fn extract_remote_from_config(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("remote ") {
            return t.split_whitespace().nth(1).map(String::from);
        }
    }
    None
}

/// Parse all `remote <host> <port> [proto]` lines from an .ovpn file.
pub fn extract_remotes_from_config(path: &Path) -> Vec<(String, u16, String)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    // Also check for a top-level `proto` directive as default
    let default_proto = text.lines()
        .find(|l| l.trim().starts_with("proto "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("udp")
        .to_string();

    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("remote ") {
            let parts: Vec<&str> = t.split_whitespace().collect();
            let host  = match parts.get(1) { Some(h) => h.to_string(), None => continue };
            let port  = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(1194);
            let proto = parts.get(3).map(|s| s.to_string()).unwrap_or_else(|| default_proto.clone());
            out.push((host, port, proto));
        }
    }
    out
}
