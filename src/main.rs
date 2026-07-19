//! main.rs – vpn-manager entry point
//!
//! Subcommands:
//!   connect    –  start openvpn/wireguard, enable kill switch, launch TUI
//!   disconnect –  graceful teardown
//!   recover    –  emergency: kill openvpn, tear down interfaces, restore iptables/DNS
//!   status     –  print current session info
//!   list       –  show VPN config files in a directory

mod configs;
mod killswitch;
mod network;
mod openvpn;
mod state;
mod tui;
mod wireguard;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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
    log_push, new_log, new_state, ConnInfo, SessionFile, SharedState, Traffic, VpnState,
};
use tui::{ConfigPicker, TuiAction};
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

    /// List available VPN config files (.ovpn / WireGuard .conf) in a directory
    List {
        /// Directory to scan (defaults to the current directory)
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
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

        Cmd::List { dir } => cmd_list(&dir),
    }
}

// ─── connect ──────────────────────────────────────────────────────────────────

/// Everything a live tunnel session owns; consumed by `end_session`.
struct Session {
    active_vpn: ActiveVpn,
    ks:         Option<KillSwitch>,
    is_wg:      bool,
    stop_tx:    mpsc::SyncSender<()>,
    geo_stop:   Arc<AtomicBool>,
}

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
    // Passing a directory to --config lists what's inside instead of failing
    if let Some(ref cfg) = config {
        if cfg.is_dir() {
            println!("--config points to a directory — available configs:\n");
            cmd_list(cfg)?;
            bail!("pass one specific file, e.g. --config {}/<FILE>", cfg.display());
        }
    }

    // Catch obviously broken configs (placeholder keys, no remote) up front —
    // before the root check, so it doesn't even need sudo to tell you
    if let Some(ref cfg) = config {
        if let Err(msg) = configs::validate(cfg) {
            bail!("invalid config {}: {msg}", cfg.display());
        }
    }

    if unsafe { geteuid() } != 0 {
        bail!("vpn-manager connect must be run as root (sudo)");
    }
    if config.is_none() && host.is_none() {
        bail!("either --config <file.ovpn> or --host <hostname> is required");
    }

    // ── Shared state + log (persist across config switches) ───────────────────
    let shared = new_state();
    let log    = new_log();

    // Optional log file header
    if let Some(ref lp) = log_file {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(lp) {
            let _ = writeln!(f, "\n=== vpn-manager session {} ===",
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
        }
        println!("logging to: {}", lp.display());
    }
    if verbose {
        println!("[vpn-manager] verbose mode enabled");
        println!("[vpn-manager] kill switch: {}", if no_kill_switch { "disabled" } else { "enabled" });
    }

    // ── Session loop: TUI can exit with "switch to another config" ────────────
    let mut current_config = config;
    let mut prev_config: Option<PathBuf> = None;

    loop {
        let start = |cfg: Option<&Path>| start_session(
            cfg,
            host.as_deref(),
            port, &proto, &dns,
            auth_file.as_deref(),
            no_kill_switch, no_tui, verbose,
            log_file.as_ref(),
            &shared, &log,
        );

        let mut session = match start(current_config.as_deref()) {
            Ok(s) => s,
            // A switch target that validated can still fail to connect
            // (auth, unreachable endpoint…) — fall back to the config that
            // was working a moment ago instead of exiting disconnected.
            Err(e) => match prev_config.take() {
                Some(prev) => {
                    eprintln!("✗ connect failed: {e:#}");
                    log_push_file(&log, &format!(
                        "ERROR: connect failed ({e:#}); reconnecting to previous config {}",
                        prev.display()
                    ), log_file.as_ref());
                    println!("reconnecting to previous config {}...", prev.display());
                    current_config = Some(prev);
                    start(current_config.as_deref())?
                }
                None => return Err(e),
            },
        };

        let action = if !no_tui {
            let picker = ConfigPicker {
                dir: current_config.as_ref().and_then(|c| {
                    c.parent().map(|p| {
                        if p.as_os_str().is_empty() { PathBuf::from(".") } else { p.to_path_buf() }
                    })
                }),
                current: current_config.clone(),
            };
            tui::run(Arc::clone(&shared), Arc::clone(&log), session.stop_tx.clone(), picker)?
        } else {
            println!("running headless  (Ctrl-C or `sudo vpn-manager disconnect` to stop)");
            wait_for_shutdown_signal();
            TuiAction::Quit
        };

        end_session(&mut session, &shared);

        match action {
            TuiAction::Quit => break,
            TuiAction::Switch(p) => {
                log_push_file(&log, &format!("switching to {}", p.display()), log_file.as_ref());
                println!("switching to {}...", p.display());
                prev_config    = current_config.take();
                current_config = Some(p);
            }
        }
    }

    SessionFile::remove();
    println!("✓ disconnected – network restored");
    Ok(())
}

/// Bring up the tunnel, kill switch, DNS lock, session file, and the
/// monitor / ip-geo threads. Returns the handles `end_session` needs.
#[allow(clippy::too_many_arguments)]
fn start_session(
    config:         Option<&Path>,
    host:           Option<&str>,
    port:           u16,
    proto:          &str,
    dns:            &[String],
    auth_file:      Option<&Path>,
    no_kill_switch: bool,
    no_tui:         bool,
    verbose:        bool,
    log_file:       Option<&PathBuf>,
    shared:         &SharedState,
    log:            &state::LogBuf,
) -> Result<Session> {
    let server_host = if let Some(cfg) = config {
        configs::extract_remote_from_config(cfg)
            .unwrap_or_else(|| cfg.to_string_lossy().into_owned())
    } else {
        host.unwrap_or_default().to_string()
    };

    set_vpn_state(shared, VpnState::Connecting, |i| {
        i.server_host    = server_host.clone();
        i.dns_servers    = dns.to_vec();
        i.public_ip      = None;
        i.server_country = String::new();
        i.server_city    = String::new();
        i.vpn_iface      = None;
        i.connected_at   = None;
        i.ks_active      = false;
        i.traffic        = Traffic::default();
        i.protocol       = String::new();
    });
    log_push_file(log, &format!("connecting to {server_host}..."), log_file);

    // Kill switch is enabled AFTER the tunnel is up (see below).
    // Enabling it before openvpn connects blocks the connection itself.
    let mut ks: Option<KillSwitch> = None;

    // ── Detect config type and start tunnel ───────────────────────────────────
    let is_wg = config.map(wireguard::is_wireguard_config).unwrap_or(false);

    let (iface, active_vpn) = if is_wg {
        // ── WireGuard path ────────────────────────────────────────────────────
        let cfg = config.unwrap(); // guarded: is_wg implies config is Some
        println!("[vpn-manager] detected WireGuard config — using wg-quick");

        let wg = WireGuardSession::start(cfg, verbose, log)
            .with_context(|| "wg-quick failed to bring up tunnel")?;

        let iface = wg.iface.clone();
        log_push_file(log, &format!("WireGuard tunnel up: {iface}"), log_file);
        (iface, ActiveVpn::WireGuard(wg))

    } else {
        // ── OpenVPN path ──────────────────────────────────────────────────────
        let mut ovpn = OpenVpnProcess::new(Arc::clone(log));
        ovpn.verbose  = verbose;
        ovpn.log_file = log_file.cloned();

        let start_result = if let Some(cfg) = config {
            ovpn.start_with_config(cfg, auth_file)
        } else {
            ovpn.start_generic(host.unwrap_or(""), port, proto, dns, auth_file)
        };

        if let Err(e) = start_result {
            cleanup_on_failure(&mut ks);
            return Err(e.context("start openvpn"));
        }

        log_push_file(log, "openvpn process started, waiting for tunnel...", log_file);

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

        log_push_file(log, &format!("tunnel interface: {iface}"), log_file);
        (iface, ActiveVpn::OpenVpn(Arc::new(Mutex::new(ovpn))))
    };

    // ── Kill switch – enabled NOW, after tunnel is up ─────────────────────────
    if !no_kill_switch {
        log_push_file(log, "enabling kill switch (tunnel is up)", log_file);
        let mut k = KillSwitch::new();

        if is_wg {
            // Parse endpoints and DNS from the WireGuard config
            let cfg = config.unwrap();
            for (h, p, pr) in wireguard::parse_endpoints(cfg) {
                k.add_server(&h, &pr, p);
            }
            for d in &wireguard::parse_dns(cfg) { k.add_dns(d); }
        } else if let Some(h) = host {
            k.add_server(h, proto, port);
        } else if let Some(cfg) = config {
            for (h, p, pr) in configs::extract_remotes_from_config(cfg) {
                k.add_server(&h, &pr, p);
            }
            for d in dns { k.add_dns(d); }
        }

        match k.enable() {
            Ok(()) => {
                set_vpn_state(shared, VpnState::Connected, |i| i.ks_active = true);
                log_push_file(log, "kill switch active", log_file);
                ks = Some(k);
            }
            Err(e) => {
                log_push(log, format!("WARN: kill switch failed to enable: {e}"));
            }
        }
    }

    // ── Lock DNS (OpenVPN only – wg-quick manages DNS for WireGuard) ──────────
    if !is_wg {
        if let Err(e) = network::lock_dns(dns, &iface) {
            log_push(log, format!("WARN: DNS lock failed: {e}"));
        }
    }

    // ── Mark connected immediately ────────────────────────────────────────────
    // Public IP + geo lookups are curl calls that can take ~18 s of timeouts;
    // they run in a background thread so the TUI starts instantly and the
    // uptime clock starts when the tunnel actually came up.
    let connected_at = Instant::now();

    // For WireGuard the effective DNS comes from the config, not our --dns flag
    let effective_dns = if is_wg {
        let d = wireguard::parse_dns(config.unwrap());
        if d.is_empty() { dns.to_vec() } else { d }
    } else {
        dns.to_vec()
    };

    set_vpn_state(shared, VpnState::Connected, |i| {
        i.vpn_iface    = Some(iface.clone());
        i.dns_servers  = effective_dns.clone();
        i.connected_at = Some(connected_at);
        i.protocol     = if is_wg { "WireGuard".into() } else { "OpenVPN".into() };
    });

    println!("✓ tunnel up  iface={iface}");

    // ── Session file ──────────────────────────────────────────────────────────
    SessionFile {
        pid:       std::process::id(),
        iface:     Some(iface.clone()),
        host:      server_host.clone(),
        country:   "resolving...".into(),
        ks_active: ks.is_some(),
        dns:       effective_dns.clone(),
        ts:        SystemTime::now().duration_since(UNIX_EPOCH)
                       .unwrap_or_default().as_secs(),
    }.write();

    // ── Background public-IP / geo thread (initial fetch + 5-min refresh) ─────
    let geo_stop = Arc::new(AtomicBool::new(false));
    {
        let stop         = Arc::clone(&geo_stop);
        let bg_shared    = Arc::clone(shared);
        let bg_log       = Arc::clone(log);
        let bg_log_file  = log_file.cloned();
        let print_result = no_tui;

        thread::Builder::new()
            .name("ip-geo".into())
            .spawn(move || {
                let mut first = true;
                while !stop.load(Ordering::SeqCst) {
                    let public_ip = network::public_ip();
                    if stop.load(Ordering::SeqCst) { break; }
                    let (country, city) = match public_ip {
                        Some(ref ip) => network::geo_info(ip),
                        None         => ("Unknown".into(), "Unknown".into()),
                    };

                    {
                        let mut g = bg_shared.lock().unwrap();
                        g.1.public_ip      = public_ip.clone();
                        g.1.server_country = country.clone();
                        g.1.server_city    = city.clone();
                    }

                    if first {
                        first = false;
                        log_push_file(&bg_log, &format!(
                            "connected  ip={}  location={city}, {country}",
                            public_ip.as_deref().unwrap_or("?")
                        ), bg_log_file.as_ref());
                        if print_result {
                            println!("✓ connected  ip={}  {city}, {country}",
                                     public_ip.as_deref().unwrap_or("?"));
                        }
                        if let Some(mut sf) = SessionFile::read() {
                            sf.country = country.clone();
                            sf.write();
                        }
                    }

                    // Sleep 5 min in 1 s slices so a config switch stops us fast
                    for _ in 0..300 {
                        if stop.load(Ordering::SeqCst) { return; }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .context("spawn ip-geo thread")?;
    }

    // ── Monitor thread ────────────────────────────────────────────────────────
    let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
    let mon_ovpn = active_vpn.as_openvpn_arc(); // None for WireGuard

    {
        let mon_shared = Arc::clone(shared);
        let mon_log    = Arc::clone(log);
        let mon_iface  = iface.clone();

        thread::Builder::new()
            .name("vpn-monitor".into())
            .spawn(move || monitor_loop(mon_shared, mon_log, mon_iface, mon_ovpn, stop_rx))
            .context("spawn monitor thread")?;
    }

    Ok(Session { active_vpn, ks, is_wg, stop_tx, geo_stop })
}

/// Tear down one session: tunnel, kill switch, DNS, threads, state.
fn end_session(s: &mut Session, shared: &SharedState) {
    println!("disconnecting...");
    set_vpn_state(shared, VpnState::Disconnecting, |_| {});

    let _ = s.stop_tx.try_send(());
    s.geo_stop.store(true, Ordering::SeqCst);

    s.active_vpn.disconnect();

    if let Some(ref mut k) = s.ks { k.disable(); }
    // wg-quick restores DNS on `down`; only call unlock_dns for OpenVPN
    if !s.is_wg { network::unlock_dns(); }

    set_vpn_state(shared, VpnState::Disconnected, |i| {
        i.ks_active    = false;
        i.vpn_iface    = None;
        i.public_ip    = None;
        i.connected_at = None;
    });
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

// ─── list ─────────────────────────────────────────────────────────────────────

/// Scan a directory for VPN configs (.ovpn and WireGuard .conf) and print them.
fn cmd_list(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }

    let entries = configs::scan(dir);
    if entries.is_empty() {
        println!("no .ovpn or WireGuard .conf config files found in {}", dir.display());
        return Ok(());
    }

    println!("{:<40} {:<10} SERVER", "FILE", "TYPE");
    println!("{}", "─".repeat(72));
    for e in &entries {
        println!("{:<40} {:<10} {}", e.name, e.kind, e.server);
    }

    println!("\n{} config(s)  —  connect with:", entries.len());
    println!("  sudo vpn-manager connect --config {}/<FILE>", dir.display());
    Ok(())
}

// ─── Shutdown signal (headless mode) ─────────────────────────────────────────

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_shutdown_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Block until SIGINT (Ctrl-C) or SIGTERM (`vpn-manager disconnect`).
fn wait_for_shutdown_signal() {
    use nix::sys::signal::{signal as set_handler, SigHandler};
    unsafe {
        let _ = set_handler(Signal::SIGINT,  SigHandler::Handler(on_shutdown_signal));
        let _ = set_handler(Signal::SIGTERM, SigHandler::Handler(on_shutdown_signal));
    }
    while !SHUTDOWN.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }
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

        // (public IP refresh lives in the dedicated ip-geo thread — curl can
        //  block for seconds and must never stall the 1 s traffic sampling)

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

fn cleanup_on_failure(ks: &mut Option<KillSwitch>) {
    if let Some(k) = ks { k.disable(); }
    network::unlock_dns();
}
