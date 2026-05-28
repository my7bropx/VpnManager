#![allow(dead_code)]
/// killswitch.rs – iptables-based kill switch
///
/// Fixes over the Python original:
///  1. restore_rules() tracks per-table success independently – no short-circuit
///     on the first success of any table (the "restored" flag bug).
///  2. emergency_recovery() tears down VPN interfaces in addition to
///     resetting iptables.
///  3. KillSwitch implements Drop, so iptables are always restored even on panic.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::network;

// ─── Backup format ────────────────────────────────────────────────────────────

#[derive(Default, Serialize, Deserialize)]
struct TableSet {
    filter: String,
    nat:    String,
    mangle: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Backup {
    ipt:              TableSet,
    ip6t:             TableSet,
    ipv6_all:         Option<String>,
    ipv6_default:     Option<String>,
}

const BACKUP_PATH: &str = "/tmp/vpn-manager-ks-backup.json";

// ─── KillSwitch ───────────────────────────────────────────────────────────────

pub struct KillSwitch {
    active:  bool,
    backup:  Backup,
    servers: Vec<(String, String, u16)>, // (ip, proto, port)
    dns:     HashSet<String>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            active:  false,
            backup:  Backup::default(),
            servers: Vec::new(),
            dns:     ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
                         .iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn add_server(&mut self, ip: &str, proto: &str, port: u16) {
        self.servers.push((ip.to_owned(), proto.to_owned(), port));
    }

    pub fn add_dns(&mut self, dns: &str) {
        self.dns.insert(dns.to_owned());
    }

    pub fn is_active(&self) -> bool { self.active }

    // ── Enable ───────────────────────────────────────────────────────────────

    pub fn enable(&mut self) -> Result<()> {
        if self.active { return Ok(()); }

        self.save_backup()?;

        let gw     = network::default_gateway();
        let locals = network::local_networks();

        self.flush();
        self.apply_ipv4(&gw, &locals)?;
        self.apply_ipv6();
        self.verify()?;
        self.active = true;
        Ok(())
    }

    // ── Disable ──────────────────────────────────────────────────────────────

    pub fn disable(&mut self) {
        self.restore_rules();
        self.restore_ipv6();
        self.active = false;
        let _ = std::fs::remove_file(BACKUP_PATH);
    }

    // ── Emergency recovery ───────────────────────────────────────────────────
    //
    // Called when restore_rules() fails for any table. Does NOT require a
    // valid backup – it resets everything to ACCEPT and tears down VPN ifaces.

    pub fn emergency_recovery(&self) {
        eprintln!("[kill-switch] emergency recovery");

        let cmds: &[&[&str]] = &[
            &["iptables",  "-P", "INPUT",   "ACCEPT"],
            &["iptables",  "-P", "FORWARD", "ACCEPT"],
            &["iptables",  "-P", "OUTPUT",  "ACCEPT"],
            &["iptables",  "-F"],
            &["iptables",  "-X"],
            &["iptables",  "-t", "nat",    "-F"],
            &["iptables",  "-t", "nat",    "-X"],
            &["iptables",  "-t", "mangle", "-F"],
            &["iptables",  "-t", "mangle", "-X"],
            &["ip6tables", "-P", "INPUT",   "ACCEPT"],
            &["ip6tables", "-P", "FORWARD", "ACCEPT"],
            &["ip6tables", "-P", "OUTPUT",  "ACCEPT"],
            &["ip6tables", "-F"],
            &["ip6tables", "-X"],
        ];

        for c in cmds {
            let _ = Command::new(c[0]).args(&c[1..]).status();
        }

        self.restore_ipv6();

        // KEY FIX: tear down lingering tun/wg interfaces so routing is clean
        let _ = network::teardown_vpn_interfaces();
    }

    // ─────────────────────────────────────────────────────────────────────────

    fn save_backup(&mut self) -> Result<()> {
        for (tbl, dst4, dst6) in &mut [
            ("filter", &mut self.backup.ipt.filter, &mut self.backup.ip6t.filter),
            ("nat",    &mut self.backup.ipt.nat,    &mut self.backup.ip6t.nat),
            ("mangle", &mut self.backup.ipt.mangle, &mut self.backup.ip6t.mangle),
        ] {
            if let Ok(o) = Command::new("iptables-save").args(["-t", tbl]).output() {
                **dst4 = String::from_utf8_lossy(&o.stdout).into_owned();
            }
            if let Ok(o) = Command::new("ip6tables-save").args(["-t", tbl]).output() {
                **dst6 = String::from_utf8_lossy(&o.stdout).into_owned();
            }
        }

        // Save IPv6 sysctl values so we can restore them
        self.backup.ipv6_all = read_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6");
        self.backup.ipv6_default = read_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6");

        // Persist to disk in case we restart/recover from a different process
        let json = serde_json::to_string(&self.backup).context("serialize backup")?;
        std::fs::write(BACKUP_PATH, json).context("write backup")?;
        Ok(())
    }

    fn restore_rules(&self) {
        // BUG FIX: track per-table independently. The original Python code set
        // `restored = True` on the first table that succeeded, then skipped
        // emergency_recovery() even if other tables (especially "filter") failed.
        let mut all_ok = true;

        let pairs: &[(&str, &str, &str)] = &[
            ("iptables-restore",  "filter", &self.backup.ipt.filter),
            ("iptables-restore",  "nat",    &self.backup.ipt.nat),
            ("iptables-restore",  "mangle", &self.backup.ipt.mangle),
            ("ip6tables-restore", "filter", &self.backup.ip6t.filter),
            ("ip6tables-restore", "nat",    &self.backup.ip6t.nat),
            ("ip6tables-restore", "mangle", &self.backup.ip6t.mangle),
        ];

        for (cmd, table, rules) in pairs {
            if rules.is_empty() { continue; }

            let ok = restore_table(cmd, table, rules);
            if !ok {
                eprintln!("[kill-switch] failed to restore {cmd} table={table}");
                all_ok = false;
            }
        }

        // Attempt from on-disk backup if in-memory restore failed for any table
        if !all_ok {
            if let Some(disk) = load_backup_from_disk() {
                let disk_pairs: &[(&str, &str, &str)] = &[
                    ("iptables-restore",  "filter", &disk.ipt.filter),
                    ("iptables-restore",  "nat",    &disk.ipt.nat),
                    ("iptables-restore",  "mangle", &disk.ipt.mangle),
                    ("ip6tables-restore", "filter", &disk.ip6t.filter),
                    ("ip6tables-restore", "nat",    &disk.ip6t.nat),
                    ("ip6tables-restore", "mangle", &disk.ip6t.mangle),
                ];
                all_ok = true;
                for (cmd, table, rules) in disk_pairs {
                    if rules.is_empty() { continue; }
                    if !restore_table(cmd, table, rules) {
                        all_ok = false;
                    }
                }
            }
        }

        if !all_ok {
            eprintln!("[kill-switch] in-memory and disk restore both failed → emergency");
            self.emergency_recovery();
        }
    }

    fn flush(&self) {
        let cmds: &[&[&str]] = &[
            &["iptables",  "-P", "INPUT",   "ACCEPT"],
            &["iptables",  "-P", "FORWARD", "ACCEPT"],
            &["iptables",  "-P", "OUTPUT",  "ACCEPT"],
            &["iptables",  "-F"],
            &["iptables",  "-t", "nat",    "-F"],
            &["iptables",  "-t", "mangle", "-F"],
            &["iptables",  "-X"],
            &["iptables",  "-t", "nat",    "-X"],
            &["iptables",  "-t", "mangle", "-X"],
            &["ip6tables", "-P", "INPUT",   "ACCEPT"],
            &["ip6tables", "-P", "FORWARD", "ACCEPT"],
            &["ip6tables", "-P", "OUTPUT",  "ACCEPT"],
            &["ip6tables", "-F"],
            &["ip6tables", "-t", "nat",    "-F"],
            &["ip6tables", "-t", "mangle", "-F"],
            &["ip6tables", "-X"],
        ];
        for c in cmds { let _ = Command::new(c[0]).args(&c[1..]).status(); }
    }

    fn apply_ipv4(&self, _gw: &Option<String>, locals: &[String]) -> Result<()> {
        let mut ipt = Ipt::new();

        // Loopback
        ipt.add(&["-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"]);
        ipt.add(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]);

        // Established / related
        ipt.add(&["-A", "INPUT",  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);
        ipt.add(&["-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);

        // VPN tunnel interfaces (tun+ covers tun0/tun1/…)
        for pat in &["tun+", "wg+"] {
            ipt.add(&["-A", "INPUT",  "-i", pat, "-j", "ACCEPT"]);
            ipt.add(&["-A", "OUTPUT", "-o", pat, "-j", "ACCEPT"]);
        }

        // LAN bypass
        for net in locals {
            ipt.add(&["-A", "INPUT",  "-s", net, "-j", "ACCEPT"]);
            ipt.add(&["-A", "OUTPUT", "-d", net, "-j", "ACCEPT"]);
        }

        // Pre-tunnel DNS: always allow DNS to the configured servers so openvpn
        // can resolve hostnames before the tunnel is up.
        // (If self.servers is empty we don't know the endpoint IPs yet, so we
        // must allow DNS regardless; if all entries are IPs, DNS is still needed
        // for other reasons like geo lookup after connect.)
        let needs_dns = self.servers.is_empty()
            || self.servers.iter().any(|(ip, _, _)| ip.parse::<std::net::IpAddr>().is_err());

        if needs_dns {
            for dns in &self.dns {
                if dns.parse::<std::net::IpAddr>().is_ok() {
                    for proto in &["udp", "tcp"] {
                        ipt.add(&["-A", "OUTPUT", "-d", dns, "-p", proto, "--dport", "53", "-j", "ACCEPT"]);
                    }
                }
            }
            // Also allow any DNS (port 53) to any dest so hostname resolution
            // works regardless of which resolver openvpn ends up using.
            for proto in &["udp", "tcp"] {
                ipt.add(&["-A", "OUTPUT", "-p", proto, "--dport", "53", "-j", "ACCEPT"]);
            }
        }

        // VPN server endpoints
        if self.servers.is_empty() {
            // No server IPs known (connecting via --config with a hostname).
            // Allow outbound on common VPN ports until the tunnel is up.
            for (proto, port) in &[("udp","1194"),("tcp","443"),("udp","443"),("tcp","1194")] {
                ipt.add(&["-A", "OUTPUT", "-p", proto, "--dport", port, "-j", "ACCEPT"]);
                ipt.add(&["-A", "INPUT",  "-p", proto, "--sport", port, "-j", "ACCEPT"]);
            }
        } else {
            for (ip, proto, port) in &self.servers {
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    let ps = port.to_string();
                    ipt.add(&["-A", "OUTPUT", "-d", ip, "-p", proto, "--dport", &ps, "-j", "ACCEPT"]);
                    ipt.add(&["-A", "INPUT",  "-s", ip, "-p", proto, "--sport", &ps, "-j", "ACCEPT"]);
                } else {
                    // hostname: allow the port on any dest (will be tightened once tunnel is up)
                    let ps = port.to_string();
                    ipt.add(&["-A", "OUTPUT", "-p", proto, "--dport", &ps, "-j", "ACCEPT"]);
                    ipt.add(&["-A", "INPUT",  "-p", proto, "--sport", &ps, "-j", "ACCEPT"]);
                }
            }
        }

        // DHCP
        ipt.add(&["-A", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"]);
        ipt.add(&["-A", "INPUT",  "-p", "udp", "--sport", "67:68", "-j", "ACCEPT"]);

        // ICMP (rate-limited to avoid being used as a covert channel)
        ipt.add(&["-A", "OUTPUT", "-p", "icmp", "--icmp-type", "echo-request",
                  "-m", "limit", "--limit", "5/sec", "-j", "ACCEPT"]);
        ipt.add(&["-A", "INPUT",  "-p", "icmp", "--icmp-type", "echo-reply", "-j", "ACCEPT"]);

        // Kernel logging for dropped packets (rate-limited)
        ipt.add(&["-A", "OUTPUT", "-m", "limit", "--limit", "2/min",
                  "-j", "LOG", "--log-prefix", "KS-DROP-OUT: ", "--log-level", "4"]);
        ipt.add(&["-A", "INPUT", "-m", "limit", "--limit", "2/min",
                  "-j", "LOG", "--log-prefix", "KS-DROP-IN: ",  "--log-level", "4"]);

        // Default-drop policies
        ipt.policy("INPUT",   "DROP")?;
        ipt.policy("FORWARD", "DROP")?;
        ipt.policy("OUTPUT",  "DROP")?;

        ipt.check()
    }

    fn apply_ipv6(&self) {
        // Disable IPv6 at sysctl level
        for p in &[
            "/proc/sys/net/ipv6/conf/all/disable_ipv6",
            "/proc/sys/net/ipv6/conf/default/disable_ipv6",
        ] {
            let _ = std::fs::write(p, "1");
        }

        // Also block at ip6tables level
        let cmds: &[&[&str]] = &[
            &["ip6tables", "-P", "INPUT",   "DROP"],
            &["ip6tables", "-P", "FORWARD", "DROP"],
            &["ip6tables", "-P", "OUTPUT",  "DROP"],
            &["ip6tables", "-F"],
            &["ip6tables", "-X"],
        ];
        for c in cmds { let _ = Command::new(c[0]).args(&c[1..]).status(); }
    }

    fn restore_ipv6(&self) {
        if let Some(v) = &self.backup.ipv6_all {
            let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", v);
        }
        if let Some(v) = &self.backup.ipv6_default {
            let _ = std::fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", v);
        }
    }

    fn verify(&self) -> Result<()> {
        let out = Command::new("iptables").args(["-L", "-n"]).output()
            .context("iptables -L -n")?;
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        if !text.contains("policy drop") {
            anyhow::bail!("kill switch verification: DROP policy not found");
        }
        Ok(())
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.active {
            // RAII safety net: always restore rules, even on panic unwind
            self.restore_rules();
            self.restore_ipv6();
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Thin wrapper that accumulates errors from iptables calls.
struct Ipt { errors: Vec<String> }

impl Ipt {
    fn new() -> Self { Self { errors: Vec::new() } }

    fn add(&mut self, args: &[&str]) {
        let ok = Command::new("iptables")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            self.errors.push(format!("iptables {}", args.join(" ")));
        }
    }

    fn policy(&mut self, chain: &str, target: &str) -> Result<()> {
        let ok = Command::new("iptables")
            .args(["-P", chain, target])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok { Ok(()) }
        else { anyhow::bail!("iptables -P {chain} {target} failed") }
    }

    fn check(self) -> Result<()> {
        if self.errors.is_empty() { Ok(()) }
        else { anyhow::bail!("iptables errors:\n  {}", self.errors.join("\n  ")) }
    }
}

fn restore_table(cmd: &str, table: &str, rules: &str) -> bool {
    let mut child = match Command::new(cmd)
        .args(["-T", table])
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(rules.as_bytes());
    }

    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn load_backup_from_disk() -> Option<Backup> {
    let raw = std::fs::read_to_string(BACKUP_PATH).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

// ─── Standalone recovery (called from `recover` subcommand) ──────────────────

/// Full recovery without needing an active KillSwitch instance.
/// Used when the manager crashes and leaves the network broken.
pub fn standalone_recovery() {
    eprintln!("[recover] restoring network state...");

    // 1. Kill any lingering openvpn
    network::kill_all_openvpn();

    // 2. Tear down VPN interfaces first (routing fix)
    let _ = network::teardown_vpn_interfaces();

    // 3. Restore iptables from backup if it exists, else reset to ACCEPT
    let restored = if let Some(backup) = load_backup_from_disk() {
        let pairs: &[(&str, &str, &str)] = &[
            ("iptables-restore",  "filter", &backup.ipt.filter),
            ("iptables-restore",  "nat",    &backup.ipt.nat),
            ("iptables-restore",  "mangle", &backup.ipt.mangle),
            ("ip6tables-restore", "filter", &backup.ip6t.filter),
            ("ip6tables-restore", "nat",    &backup.ip6t.nat),
            ("ip6tables-restore", "mangle", &backup.ip6t.mangle),
        ];
        pairs.iter().filter(|(_, _, r)| !r.is_empty())
             .all(|(cmd, tbl, rules)| restore_table(cmd, tbl, rules))
    } else {
        false
    };

    if !restored {
        eprintln!("[recover] no backup found or restore failed – resetting to ACCEPT");
        let ks = KillSwitch::new();
        ks.emergency_recovery();
    }

    // 4. Restore DNS and IPv6
    network::unlock_dns();
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6",     "0");
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0");

    // 5. Clean up state files
    let _ = std::fs::remove_file(BACKUP_PATH);
    crate::state::SessionFile::remove();

    eprintln!("[recover] done");
}
