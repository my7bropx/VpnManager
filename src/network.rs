#![allow(dead_code)]
//! network.rs – system-level networking operations
//!
//! All functions here operate directly on kernel networking state via `ip`,
//! iptables helpers, and /proc. Kept as pure functions (no global state) so
//! they can be called from any context, including emergency paths.

use anyhow::{Context, Result};
use std::process::Command;

// ─── VPN interface teardown ───────────────────────────────────────────────────

/// Enumerate all tun/wg interfaces, flush their routes, bring them down,
/// and delete them.  This is the root fix for the "network gone after failure"
/// bug: without this, kernel routes pointing at a dead tun persist after
/// openvpn dies, dropping all traffic before iptables even runs.
pub fn teardown_vpn_interfaces() -> Result<()> {
    let out = Command::new("ip")
        .args(["link", "show"])
        .output()
        .context("ip link show failed")?;

    let text = String::from_utf8_lossy(&out.stdout);
    let ifaces: Vec<String> = text
        .lines()
        .filter(|l| {
            // Match lines like "3: tun0: <POINTOPOINT,..." or "5: wg0: <..."
            let has_idx = l.trim_start().chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false);
            has_idx && (l.contains(": tun") || l.contains(": wg"))
        })
        .filter_map(|l| {
            // "3: tun0: <..." → "tun0"
            l.split(':').nth(1).map(|s| s.trim().split('@').next().unwrap_or("").trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();

    for iface in &ifaces {
        eprintln!("[network] tearing down {iface}");
        let _ = Command::new("ip").args(["route", "flush", "dev", iface]).status();
        let _ = Command::new("ip").args(["link",  "set",   iface, "down"]).status();
        let _ = Command::new("ip").args(["link",  "delete", iface]).status();
    }

    Ok(())
}

// ─── Routing inspection ───────────────────────────────────────────────────────

/// Returns the default gateway IP (e.g. "192.168.1.1"), if any.
pub fn default_gateway() -> Option<String> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;

    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|&w| w != "via")
        .nth(1)
        .map(String::from)
}

/// Returns the name of the first active tun*/wg* interface found.
pub fn active_vpn_interface() -> Option<String> {
    let out = Command::new("ip").args(["link", "show", "up"]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.contains(": tun") || l.contains(": wg"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().split('@').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True if all traffic is being routed through `iface`.
///
/// Primary check: `ip route get <external ip>` — asks the kernel where a real
/// packet would actually go. This honours policy routing, which wg-quick uses
/// (fwmark rules + table 51820); the main table never shows a default route
/// through a wg interface, so inspecting `ip route show` alone gives false
/// "not through VPN" warnings for WireGuard.
///
/// Fallback: main-table inspection for the two OpenVPN patterns:
///   1. Literal default route:  "default via X dev tun0"
///   2. Split-route:            0.0.0.0/1 + 128.0.0.0/1 both via `iface`
pub fn default_route_is_vpn(iface: &str) -> bool {
    if let Ok(out) = Command::new("ip").args(["-4", "route", "get", "1.1.1.1"]).output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(dev) = text.split_whitespace()
                .skip_while(|w| *w != "dev")
                .nth(1)
            {
                return dev == iface;
            }
        }
    }

    let out = match Command::new("ip").args(["-4", "route", "show"]).output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);

    // Pattern 1: literal default
    if text.lines().any(|l| l.starts_with("default") && l.contains(iface) ) {
        return true;
    }

    // Pattern 2: split-route (0.0.0.0/1 AND 128.0.0.0/1 through iface)
    let has_lower = text.lines().any(|l| l.contains("0.0.0.0/1") && l.contains(iface));
    let has_upper = text.lines().any(|l| l.contains("128.0.0.0/1") && l.contains(iface));
    has_lower && has_upper
}

/// Detect local (LAN) network CIDRs for kill-switch LAN bypass.
pub fn local_networks() -> Vec<String> {
    let out = match Command::new("ip").args(["route", "show"]).output() {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("scope link") || (l.contains("link") && l.contains('/')))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| s.contains('/'))
        .map(String::from)
        .collect()
}

// ─── Traffic counters ─────────────────────────────────────────────────────────

/// Read (rx_bytes, tx_bytes) for an interface from /proc/net/dev.
pub fn iface_bytes(iface: &str) -> Option<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/net/dev").ok()?;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(iface) && trimmed.as_bytes().get(iface.len()) == Some(&b':') {
            let parts: Vec<&str> = trimmed.split_once(':')?.1.split_whitespace().collect();
            let rx = parts.first()?.parse::<u64>().ok()?;
            let tx = parts.get(8)?.parse::<u64>().ok()?;
            return Some((rx, tx));
        }
    }
    None
}

// ─── Public IP ────────────────────────────────────────────────────────────────

pub fn public_ip() -> Option<String> {
    for url in &[
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    ] {
        if let Ok(out) = Command::new("curl")
            .args(["-sf", "--max-time", "5", url])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if is_valid_ip(&s) { return Some(s); }
        }
    }
    None
}

fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

// ─── DNS management ───────────────────────────────────────────────────────────

const DNS_BACKUP: &str = "/tmp/vpn-manager-resolv.bak";

/// Lock DNS to the given servers. Backs up the current /etc/resolv.conf first.
pub fn lock_dns(servers: &[String], iface: &str) -> Result<()> {
    // Back up current resolv.conf
    if std::path::Path::new("/etc/resolv.conf").exists() {
        std::fs::copy("/etc/resolv.conf", DNS_BACKUP)
            .context("backup /etc/resolv.conf")?;
    }

    // Prefer resolvectl (systemd-resolved)
    if resolvectl_available() {
        for dns in servers {
            let _ = Command::new("resolvectl").args(["dns",    iface, dns]).status();
        }
        let _ = Command::new("resolvectl").args(["domain", iface, "~."]).status();
        return Ok(());
    }

    // Fall back to writing resolv.conf directly
    let _ = Command::new("chattr").args(["-i", "/etc/resolv.conf"]).status();
    let mut content = String::from("# managed by vpn-manager\n");
    for dns in servers {
        content.push_str(&format!("nameserver {dns}\n"));
    }
    std::fs::write("/etc/resolv.conf", content).context("write /etc/resolv.conf")?;
    Ok(())
}

/// Restore DNS from backup. Best-effort.
pub fn unlock_dns() {
    let backup = std::path::Path::new(DNS_BACKUP);
    if backup.exists() {
        let _ = Command::new("chattr").args(["-i", "/etc/resolv.conf"]).status();
        let _ = std::fs::copy(backup, "/etc/resolv.conf");
        let _ = std::fs::remove_file(backup);
    }
}

/// Read active nameservers from /etc/resolv.conf.
pub fn current_dns() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.trim_start().starts_with("nameserver"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(String::from)
        .collect()
}

fn resolvectl_available() -> bool {
    Command::new("resolvectl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── openvpn process hunting ──────────────────────────────────────────────────

/// Return PIDs of any running openvpn processes.
pub fn openvpn_pids() -> Vec<u32> {
    let out = Command::new("pgrep").args(["-x", "openvpn"]).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .collect(),
        Err(_) => vec![],
    }
}

/// Kill all running openvpn processes (SIGKILL).
pub fn kill_all_openvpn() {
    for pid in openvpn_pids() {
        eprintln!("[network] killing openvpn pid {pid}");
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

// ─── Geo lookup ───────────────────────────────────────────────────────────────

/// Try to resolve country/city for an IP using ip-api.com (best-effort).
pub fn geo_info(ip: &str) -> (String, String) {
    let url = format!("http://ip-api.com/json/{ip}?fields=country,city");
    if let Ok(out) = Command::new("curl").args(["-sf", "--max-time", "3", &url]).output() {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
            let country = v["country"].as_str().unwrap_or("Unknown").to_string();
            let city    = v["city"].as_str().unwrap_or("Unknown").to_string();
            return (country, city);
        }
    }
    ("Unknown".into(), "Unknown".into())
}
