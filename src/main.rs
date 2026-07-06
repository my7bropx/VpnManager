//! main.rs – vpn-manager entry point
//!
//! Subcommands:
//!   connect    –  start openvpn, enable kill switch, launch TUI
//!   disconnect –  graceful teardown
//!   recover    –  emergency: kill openvpn, tear down interfaces, restore iptables/DNS
//!   status     –  print current session info

mod killswitch;
mod network;
mod openvpn;
mod state;
mod tui;
mod wireguard;

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use killswitch::KillSwitch;
use openvpn::OpenVpnProcess;
use state::{
    log_push, new_log, new_state, ConnInfo, SessionFile, SharedState, VpnState,
};
use wireguard::WireGuardSession;

// ─── Protocol-agnostic VPN handle ────────────────────────────────────────────

enum ActiveVpn {
    OpenVpn(Arc<Mutex<OpenVpnProcess>>),
    WireGuard(WireGuardSession),
}

impl ActiveVpn {
    fn disconnect(&mut self) {
        match self {
            Self::OpenVpn(ovpn) => ovpn.lock().unwrap().disconnect(),
            Self::WireGuard(wg)  => wg.stop(),
        }
    }
    fn as_openvpn_arc(&self) -> Option<Arc<Mutex<OpenVpnProcess>>> {
        match self {
            Self::OpenVpn(o) => Some(Arc::clone(o)),
            _                => None,
        }
    }
}

// ─── libc for geteuid ────────────────────────────────────────────────────────
extern "C" { fn geteuid() -> u32; }

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "vpn-manager",
    version = "0.2.0",
    about   = "VPN manager with iptables kill switch and live TUI",
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect to a VPN server using an .ovpn profile or host/port
    Connect {
        /// OpenVPN .ovpn profile
        #[arg(long, conflicts_with_all = ["host"])]
        config: Option<PathBuf>,

        /// Server hostname or IP (alternative to --config)
        #[arg(long)]
        host: Option<String>,

        /// Server port
        #[arg(long, default_value = "1194")]
        port: u16,

        /// Protocol: udp or tcp
        #[arg(long, default_value = "udp")]
        proto: String,

        /// DNS servers to enforce
        #[arg(long, num_args = 1.., default_values = ["1.1.1.1", "8.8.8.8"])]
        dns: Vec<String>,

        /// Two-line credential file (username on line 1, password on line 2)
        #[arg(long)]
        auth_file: Option<PathBuf>,

        /// Disable kill switch (not recommended)
        #[arg(long)]
        no_kill_switch: bool,

        /// Skip the TUI, just print status
        #[arg(long)]
        no_tui: bool,

        /// Print openvpn output live to stdout (useful for diagnosing failures)
        #[arg(long)]
        verbose: bool,

        /// Write all log output to this file (appended, created if absent)
        #[arg(long, value_name = "PATH")]
        log_file: Option<PathBuf>,
    },

    /// Gracefully disconnect and restore network access
    Disconnect {
        /// Keep kill switch active after disconnect
        #[arg(long)]
        keep_kill_switch: bool,
    },

    /// Emergency recovery: kill openvpn, remove tun interfaces, restore iptables/DNS
    Recover,

    /// Show current session status
    Status,
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Connect {
            config, host, port, proto, dns,
            auth_file, no_kill_switch, no_tui, verbose, log_file,
        } => cmd_connect(config, host, port, proto, dns, auth_file, no_kill_switch, no_tui, verbose, log_file),

        Cmd::Disconnect { keep_kill_switch } => cmd_disconnect(keep_kill_switch),

        Cmd::Recover => {
            // WireGuard: attempt wg-quick down so DNS is restored properly
            let _ = std::process::Command::new("wg-quick")
                .args(["down", wireguard::TMP_CONF])
                .status();
            network::kill_all_openvpn();
            let _ = network::teardown_vpn_interfaces();
            killswitch::standalone_recovery();
            network::unlock_dns();
            SessionFile::remove();
            println!("recovery complete");
            Ok(())
        }

        Cmd::Status => cmd_status(),
    }
}

// ─── connect ──────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_connect(
    config:         Option<PathBuf>,
    host:           Option<String>,
    port:           u16,
    proto:          String,
    dns:            Vec<String>,
    auth_file:      Option<PathBuf>,
    no_kill_switch: bool,
    no_tui:         bool,
    verbose:        bool,
    log_file:       Option<PathBuf>,
) -> Result<()> {
    if unsafe { geteuid() } != 0 {
        bail!("vpn-manager connect must be run as root (sudo)");
    }
    if config.is_none() && host.is_none() {
        bail!("either --config <file.ovpn> or --host <hostname> is required");
    }

    let server_host = if let Some(ref cfg) = config {
        extract_remote_from_config(cfg).unwrap_or_else(|| cfg.to_string_lossy().into_owned())
    } else {
        host.clone().unwrap_or_default()
    };

    // ── Shared state + log ────────────────────────────────────────────────────
    let shared = new_state();
    let log    = new_log();

    set_vpn_state(&shared, VpnState::Connecting, |i| {
        i.server_host = server_host.clone();
        i.dns_servers = dns.clone();
    });
    log_push_file(&log, "connecting...", log_file.as_ref());

    // Kill switch is enabled AFTER the tunnel is up (see below).
    // Enabling it before openvpn connects blocks the connection itself.
    let mut ks: Option<KillSwitch> = None;

    // Optional log file header
    if let Some(ref lp) = log_file {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(lp) {
            let _ = writeln!(f, "\n=== vpn-manager session {} ===", {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
            });
        }
        println!("logging to: {}", lp.display());
    }
    if verbose {
        println!("[vpn-manager] verbose mode enabled");
        println!("[vpn-manager] kill switch: {}", if no_kill_switch { "disabled" } else { "enabled" });
    }

    // ── Detect config type and start tunnel ───────────────────────────────────
    let is_wg = config.as_deref()
        .map(wireguard::is_wireguard_config)
        .unwrap_or(false);

    let (iface, mut active_vpn) = if is_wg {
        // ── WireGuard path ────────────────────────────────────────────────────
        let cfg = config.as_deref().unwrap(); // guarded: is_wg implies config is Some
        println!("[vpn-manager] detected WireGuard config — using wg-quick");

        let wg = WireGuardSession::start(cfg, verbose, &log)
            .with_context(|| "wg-quick failed to bring up tunnel")?;

        let iface = wg.iface.clone();
        log_push_file(&log, &format!("WireGuard tunnel up: {iface}"), log_file.as_ref());
        (iface, ActiveVpn::WireGuard(wg))

    } else {
        // ── OpenVPN path ──────────────────────────────────────────────────────
        let mut ovpn = OpenVpnProcess::new(Arc::clone(&log));
        ovpn.verbose  = verbose;
        ovpn.log_file = log_file.clone();

        let start_result = if let Some(ref cfg) = config {
            ovpn.start_with_config(cfg, auth_file.as_deref())
        } else {
            ovpn.start_generic(
                host.as_deref().unwrap_or(""),
                port, &proto, &dns,
                auth_file.as_deref(),
            )
        };

        if let Err(e) = start_result {
            cleanup_on_failure(&mut ks);
            return Err(e.context("start openvpn"));
        }

        log_push_file(&log, "openvpn process started, waiting for tunnel...", log_file.as_ref());

        if let Err(e) = ovpn.wait_connected(Duration::from_secs(60)) {
            ovpn.force_disconnect();
            cleanup_on_failure(&mut ks);
            {
                let buf = log.lock().unwrap();
                let tail: Vec<_> = buf.iter().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect();
                if !tail.is_empty() && !verbose {
                    eprintln!("\n--- openvpn log (last {} lines) ---", tail.len());
                    for line in tail { eprintln!("{line}"); }
                    eprintln!("--- end of log ---\n");
                }
            }
            return Err(e.context("openvpn did not connect"));
        }

        let iface = match wait_for_vpn_iface(15) {
            Some(i) => i,
            None => {
                ovpn.force_disconnect();
                cleanup_on_failure(&mut ks);
                bail!("VPN tunnel interface never appeared after connect");
            }
        };

        log_push_file(&log, &format!("tunnel interface: {iface}"), log_file.as_ref());
        (iface, ActiveVpn::OpenVpn(Arc::new(Mutex::new(ovpn))))
    };

    log_push(&log, format!("tunnel interface: {iface}"));

    // ── Kill switch – enabled NOW, after tunnel is up ─────────────────────────
    if !no_kill_switch {
        log_push_file(&log, "enabling kill switch (tunnel is up)", log_file.as_ref());
        let mut k = KillSwitch::new();

        if is_wg {
            // Parse endpoints and DNS from the WireGuard config
            let cfg = config.as_deref().unwrap();
            for (h, p, pr) in wireguard::parse_endpoints(cfg) {
                k.add_server(&h, &pr, p);
            }
            let wg_dns = wireguard::parse_dns(cfg);
            for d in &wg_dns { k.add_dns(d); }
        } else if let Some(ref h) = host {
            k.add_server(h, &proto, port);
        } else if let Some(ref cfg) = config {
            for (h, p, pr) in extract_remotes_from_config(cfg) {
                k.add_server(&h, &pr, p);
            }
            for d in &dns { k.add_dns(d); }
        }

        match k.enable() {
            Ok(()) => {
                set_vpn_state(&shared, VpnState::Connected, |i| i.ks_active = true);
                log_push_file(&log, "kill switch active", log_file.as_ref());
                ks = Some(k);
            }
            Err(e) => {
                log_push(&log, format!("WARN: kill switch failed to enable: {e}"));
            }
        }
    }

    // ── Lock DNS (OpenVPN only – wg-quick manages DNS for WireGuard) ──────────
    if !is_wg {
        if let Err(e) = network::lock_dns(&dns, &iface) {
            log_push(&log, format!("WARN: DNS lock failed: {e}"));
        }
    }

    // ── Public IP + geo ────────────────────────────────────────────────────────
    let public_ip = network::public_ip();
    let (country, city) = if let Some(ref ip) = public_ip {
        network::geo_info(ip)
    } else {
        ("Unknown".into(), "Unknown".into())
    };

    let connected_at = Instant::now();

    set_vpn_state(&shared, VpnState::Connected, |i| {
        i.vpn_iface      = Some(iface.clone());
        i.public_ip      = public_ip.clone();
        i.server_country = country.clone();
        i.server_city    = city.clone();
        i.connected_at   = Some(connected_at);
        i.protocol       = if is_wg { "WireGuard".into() } else { "OpenVPN".into() };
    });

    log_push(&log, format!(
        "connected  ip={}  location={city}, {country}  iface={iface}",
        public_ip.as_deref().unwrap_or("?")
    ));
    println!(
        "✓ connected  ip={}  {city}, {country}",
        public_ip.as_deref().unwrap_or("?")
    );

    // ── Session file ──────────────────────────────────────────────────────────
    SessionFile {
        pid:       std::process::id(),
        iface:     Some(iface.clone()),
        host:      server_host.clone(),
        country:   country.clone(),
        ks_active: !no_kill_switch,
        dns:       dns.clone(),
        ts:        SystemTime::now().duration_since(UNIX_EPOCH)
                       .unwrap_or_default().as_secs(),
    }.write();

    // ── Monitor thread ────────────────────────────────────────────────────────
    let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
    let mon_ovpn = active_vpn.as_openvpn_arc(); // None for WireGuard

    {
        let mon_shared = Arc::clone(&shared);
        let mon_log    = Arc::clone(&log);
        let mon_iface  = iface.clone();

        thread::Builder::new()
            .name("vpn-monitor".into())
            .spawn(move || monitor_loop(mon_shared, mon_log, mon_iface, mon_ovpn, stop_rx))
            .context("spawn monitor thread")?;
    }

    // ── TUI ────────────────────────────────────────────────────────────────────
    let stop_for_tui = stop_tx.clone();
    if !no_tui {
        tui::run(Arc::clone(&shared), Arc::clone(&log), stop_for_tui)?;
    } else {
        println!("running in background  (Ctrl-C to disconnect)");
        let _ = stop_tx.send(());
    }

    // ── Teardown ──────────────────────────────────────────────────────────────
    println!("disconnecting...");
    set_vpn_state(&shared, VpnState::Disconnecting, |_| {});

    active_vpn.disconnect();

    if let Some(ref mut k) = ks { k.disable(); }
    // wg-quick restores DNS on `down`; only call unlock_dns for OpenVPN
    if !is_wg { network::unlock_dns(); }

    set_vpn_state(&shared, VpnState::Disconnected, |i| {
        i.ks_active    = false;
        i.vpn_iface    = None;
        i.public_ip    = None;
        i.connected_at = None;
    });

    SessionFile::remove();
    println!("✓ disconnected – network restored");
    Ok(())
}

// ─── disconnect ───────────────────────────────────────────────────────────────

fn cmd_disconnect(keep_kill_switch: bool) -> Result<()> {
    if unsafe { geteuid() } != 0 {
        bail!("vpn-manager disconnect requires root");
    }

    if let Some(sf) = SessionFile::read() {
        println!("sending SIGTERM to manager (pid {})...", sf.pid);
        let _ = signal::kill(Pid::from_raw(sf.pid as i32), Signal::SIGTERM);

        for _ in 0..50 {
            if SessionFile::read().is_none() { break; }
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Safety net: clean up even if the manager already died
    if SessionFile::read().is_some() || network::active_vpn_interface().is_some() {
        println!("forcing cleanup...");
        // Try wg-quick down first so DNS is properly restored for WireGuard
        let _ = std::process::Command::new("wg-quick")
            .args(["down", wireguard::TMP_CONF])
            .status();
        network::kill_all_openvpn();
        let _ = network::teardown_vpn_interfaces();
        if !keep_kill_switch {
            killswitch::standalone_recovery();
        }
        network::unlock_dns();
        SessionFile::remove();
    }

    println!("✓ disconnected");
    Ok(())
}

// ─── status ───────────────────────────────────────────────────────────────────

fn cmd_status() -> Result<()> {
    match SessionFile::read() {
        None => {
            println!("state        DISCONNECTED");
            println!("interface    {}", network::active_vpn_interface().as_deref().unwrap_or("none"));
        }
        Some(sf) => {
            println!("state        CONNECTED (pid {})", sf.pid);
            println!("server       {}", sf.host);
            println!("location     {}", sf.country);
            println!("interface    {}", sf.iface.as_deref().unwrap_or("?"));
            println!("kill switch  {}", if sf.ks_active { "active" } else { "inactive" });
            println!("dns          {}", sf.dns.join(", "));
            if let Some(ip) = network::public_ip() {
                println!("public ip    {ip}");
            }
        }
    }

    if let Ok(out) = std::process::Command::new("iptables")
        .args(["-L", "-n"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        let policies: Vec<&str> = text.lines()
            .filter(|l| l.starts_with("Chain "))
            .collect();
        if !policies.is_empty() {
            println!("\niptables policies:");
            for p in policies { println!("  {p}"); }
        }
    }

    Ok(())
}

// ─── Monitor loop ─────────────────────────────────────────────────────────────

fn monitor_loop(
    shared:  SharedState,
    log:     state::LogBuf,
    iface:   String,
    ovpn:    Option<Arc<Mutex<OpenVpnProcess>>>,
    stop_rx: mpsc::Receiver<()>,
) {
    let mut last_traffic      = Instant::now();
    let mut last_ip_check     = Instant::now();
    let mut last_route_check  = Instant::now();
    let mut route_miss_count  = 0u32;

    loop {
        if stop_rx.try_recv().is_ok() { break; }

        // OpenVPN process health (skipped for WireGuard — route check covers it)
        if let Some(ref ovpn) = ovpn {
            let mut g = ovpn.lock().unwrap();
            if !g.is_alive() {
                log_push(&log, "ERROR: openvpn process died unexpectedly");
                set_vpn_state(&shared, VpnState::Error("openvpn process died".into()), |_| {});
                break;
            }
        }

        // Traffic counters every 1 s
        if last_traffic.elapsed() >= Duration::from_secs(1) {
            if let Some((rx, tx)) = network::iface_bytes(&iface) {
                let mut g = shared.lock().unwrap();
                g.1.traffic.update(tx, rx);
            }
            last_traffic = Instant::now();
        }

        // Public IP refresh every 5 min
        if last_ip_check.elapsed() >= Duration::from_secs(300) {
            if let Some(ip) = network::public_ip() {
                let mut g = shared.lock().unwrap();
                g.1.public_ip = Some(ip);
            }
            last_ip_check = Instant::now();
        }

        // Tunnel route sanity check every 10 s (not every 500 ms)
        if last_route_check.elapsed() >= Duration::from_secs(10) {
            if !network::default_route_is_vpn(&iface) {
                route_miss_count += 1;
                // Log on first miss, then only every 5th to avoid spam
                if route_miss_count == 1 || route_miss_count.is_multiple_of(5) {
                    log_push(&log, format!(
                        "WARN: default route not through VPN tunnel (miss #{})", route_miss_count
                    ));
                }
            } else {
                if route_miss_count > 0 {
                    log_push(&log, "INFO: default route is back through VPN tunnel");
                }
                route_miss_count = 0;
            }
            last_route_check = Instant::now();
        }

        thread::sleep(Duration::from_millis(500));
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Push a log entry to the ring buffer AND optionally to a file.
fn log_push_file(buf: &state::LogBuf, msg: &str, path: Option<&PathBuf>) {
    log_push(buf, msg);
    if let Some(p) = path {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{msg}");
        }
    }
}

fn set_vpn_state(s: &SharedState, vs: VpnState, f: impl FnOnce(&mut ConnInfo)) {
    let mut g = s.lock().unwrap();
    g.0 = vs;
    f(&mut g.1);
}

fn wait_for_vpn_iface(secs: u64) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(i) = network::active_vpn_interface() { return Some(i); }
        if Instant::now() >= deadline { return None; }
        thread::sleep(Duration::from_millis(300));
    }
}

fn extract_remote_from_config(path: &PathBuf) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("remote ") {
            return t.split_whitespace().nth(1).map(String::from);
        }
    }
    None
}

fn cleanup_on_failure(ks: &mut Option<KillSwitch>) {
    if let Some(k) = ks { k.disable(); }
    network::unlock_dns();
}

/// Parse all `remote <host> <port> [proto]` lines from an .ovpn file.
fn extract_remotes_from_config(path: &PathBuf) -> Vec<(String, u16, String)> {
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
