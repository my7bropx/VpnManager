#![allow(dead_code)]
//! openvpn.rs – OpenVPN process wrapper
//!
//! Robustness decisions:
//!  - Preprocesses the .ovpn config to strip `daemon`, `log`, `log-append`,
//!    `persist-tun` — directives that silently break our process management
//!  - Uses `--log <tmpfile>` (not stderr pipe) as the output channel — immune
//!    to per-distro openvpn stderr buffering and config-level log overrides
//!  - Resolves the openvpn binary through common sbin paths because sudo
//!    typically strips /usr/sbin from PATH
//!  - disconnect(): SIGTERM → 10 s grace → SIGKILL, then teardown_vpn_interfaces()
//!  - force_disconnect(): SIGKILL immediately + teardown
//!  - Drop guarantees force_disconnect() even on panic

use anyhow::{Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{network, state::LogBuf};

// ─── OpenVpnProcess ───────────────────────────────────────────────────────────

pub struct OpenVpnProcess {
    child:        Option<Child>,
    /// Temp file for the sanitised config we generate
    tmp_config:   Option<PathBuf>,
    /// Temp file openvpn writes its log into (kept alive for session duration)
    tmp_log:      Option<PathBuf>,
    pub connected:    Arc<Mutex<bool>>,
    pub fail_reason:  Arc<Mutex<Option<String>>>,
    log:          LogBuf,
    /// User-supplied extra log file (appended, always created)
    pub log_file: Option<PathBuf>,
    /// Stream openvpn lines to stdout in real time
    pub verbose:  bool,
    /// Path of the active openvpn log (useful for post-mortem)
    pub ovpn_log_path: Option<PathBuf>,
}

impl OpenVpnProcess {
    pub fn new(log: LogBuf) -> Self {
        Self {
            child:         None,
            tmp_config:    None,
            tmp_log:       None,
            connected:     Arc::new(Mutex::new(false)),
            fail_reason:   Arc::new(Mutex::new(None)),
            log,
            log_file:      None,
            verbose:       false,
            ovpn_log_path: None,
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    pub fn start_with_config(&mut self, config: &Path, auth_file: Option<&Path>) -> Result<()> {
        let clean = self.sanitise_config(config)?;
        self.spawn_process(&clean, auth_file)
    }

    pub fn start_generic(
        &mut self,
        host:      &str,
        port:      u16,
        proto:     &str,
        dns:       &[String],
        auth_file: Option<&Path>,
    ) -> Result<()> {
        let cfg = write_minimal_config(host, port, proto, dns)
            .context("generate openvpn config")?;
        self.tmp_config = Some(cfg.clone());
        self.spawn_process(&cfg, auth_file)
    }

    /// Block until "Initialization Sequence Completed" or a known failure, with timeout.
    pub fn wait_connected(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if *self.connected.lock().unwrap() { return Ok(()); }
            if let Some(r) = self.fail_reason.lock().unwrap().clone() {
                anyhow::bail!("{}", r);
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out after {}s", timeout.as_secs());
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn is_alive(&mut self) -> bool {
        match &mut self.child {
            Some(c) => c.try_wait().ok().flatten().is_none(),
            None    => false,
        }
    }

    pub fn disconnect(&mut self) {
        if let Some(child) = &self.child {
            let pid = Pid::from_raw(child.id() as i32);
            let _ = kill(pid, Signal::SIGTERM);
            let dl = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(c) = &mut self.child {
                    if c.try_wait().ok().flatten().is_some() { break; }
                }
                if Instant::now() >= dl { break; }
                thread::sleep(Duration::from_millis(200));
            }
        }
        if let Some(c) = &mut self.child { let _ = c.kill(); let _ = c.wait(); }
        self.child = None;
        *self.connected.lock().unwrap() = false;
        let _ = network::teardown_vpn_interfaces();
        self.cleanup();
    }

    pub fn force_disconnect(&mut self) {
        if let Some(c) = &mut self.child { let _ = c.kill(); let _ = c.wait(); }
        self.child = None;
        *self.connected.lock().unwrap() = false;
        let _ = network::teardown_vpn_interfaces();
        self.cleanup();
    }

    // ── Config sanitiser ─────────────────────────────────────────────────────
    //
    // Many provider configs include directives that silently break our process
    // management. We strip them from a temp copy before passing to openvpn.

    fn sanitise_config(&mut self, original: &Path) -> Result<PathBuf> {
        let raw = std::fs::read_to_string(original)
            .with_context(|| format!("read config {}", original.display()))?;

        // Reject WireGuard configs early with a useful message
        let is_wireguard = raw.lines().any(|l| {
            matches!(l.trim(), "[Interface]" | "[Peer]")
        });
        if is_wireguard {
            anyhow::bail!(
                "{} is a WireGuard config, not an OpenVPN config.\n\
                 Use `wg-quick up {}` or a WireGuard client instead.",
                original.display(),
                original.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("wg0")
            );
        }

        // Directives to strip (matched as line prefix, case-insensitive)
        const STRIP: &[&str] = &[
            "daemon",        // forks openvpn — we lose process control entirely
            "log ",          // redirects output away from our log file
            "log-append ",   // same
            "persist-tun",   // keeps tun alive after process death → orphaned routes
            "writepid",      // we track the pid ourselves
        ];

        let cleaned: String = raw
            .lines()
            .filter(|line| {
                let t = line.trim().to_lowercase();
                // Keep the line unless it starts with one of our strip prefixes
                // or equals a bare keyword (e.g. bare "daemon" with no arg)
                !STRIP.iter().any(|s| {
                    let s = s.trim();
                    t == s || t.starts_with(&format!("{s} ")) || t.starts_with(&format!("{s}\t"))
                })
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Write to temp file
        let tmp = std::env::temp_dir().join(format!(
            "vpnmgr-config-{}.ovpn",
            std::process::id()
        ));
        std::fs::write(&tmp, cleaned).context("write sanitised config")?;
        self.tmp_config = Some(tmp.clone());

        if self.verbose {
            println!("[vpn-manager] config (sanitised) : {}", tmp.display());
        }

        Ok(tmp)
    }

    // ── Process spawning ──────────────────────────────────────────────────────

    fn spawn_process(&mut self, config: &Path, auth_file: Option<&Path>) -> Result<()> {
        // ── Resolve binary ────────────────────────────────────────────────────
        // sudo commonly strips /usr/sbin from PATH; try explicit locations first.
        let bin = resolve_openvpn_bin();

        // ── Dedicated log file ────────────────────────────────────────────────
        // We tell openvpn to write to a temp file via --log so we own the output
        // channel regardless of what the .ovpn config says.
        let log_path = std::env::temp_dir()
            .join(format!("vpnmgr-ovpn-{}.log", std::process::id()));
        // Pre-create the file so openvpn doesn't complain about permissions
        std::fs::write(&log_path, "").context("create openvpn log file")?;
        self.tmp_log       = Some(log_path.clone());
        self.ovpn_log_path = Some(log_path.clone());

        // ── Build argv ────────────────────────────────────────────────────────
        let verb = if self.verbose { "5" } else { "3" };
        let log_path_str = log_path.to_str().unwrap();

        let mut cmd = Command::new(&bin);
        cmd.args([
            "--config",               config.to_str().unwrap(),
            "--verb",                 verb,
            "--log",                  log_path_str,  // our output channel
            "--auth-nocache",
            "--connect-retry",        "5",
            "--connect-retry-max",    "3",
            "--explicit-exit-notify", "2",
            // NO --persist-tun
        ]);

        if let Some(auth) = auth_file {
            cmd.args(["--auth-user-pass", auth.to_str().unwrap()]);
        }

        // stdin inherited → credential prompts reach the terminal
        // stdout → null (everything goes to --log file)
        // stderr → appended to log file so early crash messages are captured
        let stderr_sink = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .context("open log file for stderr")?;
        cmd.stdin(Stdio::inherit())
           .stdout(Stdio::null())
           .stderr(stderr_sink);

        if self.verbose {
            println!("[vpn-manager] openvpn binary : {bin}");
            println!("[vpn-manager] openvpn log   : {log_path_str}");
        }

        let child = cmd.spawn()
            .with_context(|| format!(
                "failed to exec openvpn ({bin}) — is it installed?\n\
                 Try: apt install openvpn  or  which openvpn"
            ))?;

        self.child = Some(child);

        // ── Log-tail thread ───────────────────────────────────────────────────
        let connected   = Arc::clone(&self.connected);
        let fail_reason = Arc::clone(&self.fail_reason);
        let ring        = Arc::clone(&self.log);
        let user_log    = self.log_file.clone();
        let verbose     = self.verbose;
        let lp          = log_path.clone();

        thread::Builder::new()
            .name("ovpn-tailer".into())
            .spawn(move || tail_log(lp, connected, fail_reason, ring, user_log, verbose))
            .context("spawn log-tailer thread")?;

        Ok(())
    }

    fn cleanup(&mut self) {
        if let Some(p) = self.tmp_config.take() { let _ = std::fs::remove_file(p); }
        // Keep tmp_log alive for post-mortem; remove only if no user log requested
        if self.log_file.is_none() {
            if let Some(p) = self.tmp_log.take() { let _ = std::fs::remove_file(p); }
        }
    }
}

impl Drop for OpenVpnProcess {
    fn drop(&mut self) {
        if self.child.is_some() { self.force_disconnect(); }
    }
}

// ─── Log tailer (standalone fn so the thread closure is small) ───────────────

fn tail_log(
    log_path:   PathBuf,
    connected:  Arc<Mutex<bool>>,
    fail_reason: Arc<Mutex<Option<String>>>,
    ring:       LogBuf,
    user_log:   Option<PathBuf>,
    verbose:    bool,
) {
    // Wait for openvpn to create / populate the log file (up to 5 s)
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if log_path.metadata().map(|m| m.len() > 0).unwrap_or(false) { break; }
        if Instant::now() >= deadline {
            let msg = "ERROR: openvpn log file empty after 5 s — binary may not exist or crashed \
                 immediately. Check: which openvpn  or  ls /usr/sbin/openvpn".to_string();
            push_log(&ring, &msg);
            if verbose { eprintln!("{msg}"); }
            *fail_reason.lock().unwrap() = Some("openvpn did not start".into());
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Open user passthrough sink
    let mut user_sink: Option<std::fs::File> = user_log.as_ref().and_then(|p| {
        std::fs::OpenOptions::new().create(true).append(true).open(p).ok()
    });

    let file = match std::fs::File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            push_log(&ring, &format!("ERROR: open openvpn log: {e}"));
            return;
        }
    };
    let mut reader = BufReader::new(file);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data yet — sleep and retry
                thread::sleep(Duration::from_millis(80));
                continue;
            }
            Err(_) => break,
            Ok(_)  => {}
        }

        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        let entry = format!("openvpn  {line}");
        push_log(&ring, &entry);
        if verbose { println!("{entry}"); }

        if let Some(ref mut f) = user_sink {
            use std::io::Write;
            let _ = writeln!(f, "{entry}");
        }

        // ── State transitions ────────────────────────────────────────────────
        if line.contains("Initialization Sequence Completed") {
            *connected.lock().unwrap() = true;

        } else if line.contains("AUTH_FAILED") || line.contains("auth-failure") {
            *fail_reason.lock().unwrap() = Some(format!("authentication failed: {line}"));

        } else if line.contains("TLS Error") || line.contains("TLS_ERROR") {
            *fail_reason.lock().unwrap() = Some(format!("TLS error: {line}"));

        } else if line.contains("Cannot resolve host address") || line.contains("getaddrinfo") {
            *fail_reason.lock().unwrap() = Some(format!("DNS resolution failed: {line}"));

        } else if line.contains("Connection refused") || line.contains("ECONNREFUSED") {
            *fail_reason.lock().unwrap() = Some(format!("connection refused: {line}"));

        } else if line.contains("process exiting") || line.contains("SIGTERM received") {
            *connected.lock().unwrap() = false;
        }
    }

    *connected.lock().unwrap() = false;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Find the openvpn binary, checking sbin paths that sudo strips from PATH.
fn resolve_openvpn_bin() -> String {
    let candidates = [
        "/usr/sbin/openvpn",
        "/usr/local/sbin/openvpn",
        "/sbin/openvpn",
        "openvpn",
    ];
    for c in candidates {
        if c.starts_with('/') {
            if std::path::Path::new(c).exists() { return c.to_string(); }
        } else {
            // Search $PATH
            if std::env::var("PATH").unwrap_or_default()
                .split(':')
                .any(|d| std::path::Path::new(d).join(c).exists())
            {
                return c.to_string();
            }
        }
    }
    // Last resort — just try "openvpn" and let the OS error if absent
    "openvpn".to_string()
}

/// Write a minimal in-house .ovpn config for --host mode (no `daemon`, no `persist-tun`).
fn write_minimal_config(host: &str, port: u16, proto: &str, dns: &[String]) -> Result<PathBuf> {
    use std::io::Write;
    let p1 = dns.first().map(|s| s.as_str()).unwrap_or("1.1.1.1");
    let p2 = dns.get(1).map(|s| s.as_str()).unwrap_or(p1);
    let content = format!(
        "client\ndev tun\nproto {proto}\nremote {host} {port}\n\
         resolv-retry infinite\nnobind\npersist-key\n\
         remote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n\
         verb 3\nmute 20\nauth-user-pass\nredirect-gateway def1\n\
         block-outside-dns\ndhcp-option DNS {p1}\ndhcp-option DNS {p2}\n\
         sndbuf 393216\nrcvbuf 393216\nfast-io\nkeepalive 10 30\n"
    );
    let path = std::env::temp_dir().join(format!("vpnmgr-gen-{}.ovpn", std::process::id()));
    let mut f = std::fs::File::create(&path).context("create generated config")?;
    f.write_all(content.as_bytes())?;
    Ok(path)
}

fn push_log(log: &LogBuf, msg: &str) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let ts = format!("{:02}:{:02}:{:02}", (s % 86400) / 3600, (s % 3600) / 60, s % 60);
    let mut b = log.lock().unwrap();
    if b.len() >= 4096 { b.pop_front(); }
    b.push_back(format!("[{ts}] {msg}"));
}
