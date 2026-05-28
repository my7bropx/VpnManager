/// openvpn.rs – OpenVPN process wrapper
///
/// Key fixes over the Python version:
///  - No `persist-tun` in generated configs
///  - disconnect(): SIGTERM → 10 s wait → SIGKILL, then teardown_vpn_interfaces()
///  - force_disconnect(): SIGKILL immediately, then teardown_vpn_interfaces()
///  - Drop impl guarantees force_disconnect() is called even on panic

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
    tmp_config:   Option<PathBuf>,
    pub connected:    Arc<Mutex<bool>>,
    pub fail_reason:  Arc<Mutex<Option<String>>>,
    log:          LogBuf,
    /// If set, every log line is also written here (appended, created if absent)
    pub log_file: Option<std::path::PathBuf>,
    /// If true, every openvpn line is also printed to stdout while connecting
    pub verbose:  bool,
}

impl OpenVpnProcess {
    pub fn new(log: LogBuf) -> Self {
        Self {
            child:       None,
            tmp_config:  None,
            connected:   Arc::new(Mutex::new(false)),
            fail_reason: Arc::new(Mutex::new(None)),
            log,
            log_file:    None,
            verbose:     false,
        }
    }

    // ── Start with a provided .ovpn file ─────────────────────────────────────

    pub fn start_with_config(
        &mut self,
        config: &Path,
        auth_file: Option<&Path>,
    ) -> Result<()> {
        self.spawn_process(config, auth_file)
    }

    // ── Generate a minimal config and start ──────────────────────────────────

    pub fn start_generic(
        &mut self,
        host:       &str,
        port:       u16,
        proto:      &str,
        dns:        &[String],
        auth_file:  Option<&Path>,
    ) -> Result<()> {
        let cfg = write_temp_config(host, port, proto, dns)
            .context("generate openvpn config")?;
        self.tmp_config = Some(cfg.clone());
        self.spawn_process(&cfg, auth_file)
    }

    // ── Wait until "Initialization Sequence Completed" or failure ────────────

    pub fn wait_connected(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if *self.connected.lock().unwrap() { return Ok(()); }

            if let Some(reason) = self.fail_reason.lock().unwrap().clone() {
                anyhow::bail!("{}", reason);
            }

            if Instant::now() >= deadline {
                anyhow::bail!("connection timed out after {}s", timeout.as_secs());
            }

            thread::sleep(Duration::from_millis(400));
        }
    }

    pub fn is_alive(&mut self) -> bool {
        match &mut self.child {
            Some(c) => c.try_wait().ok().flatten().is_none(),
            None    => false,
        }
    }

    // ── Graceful disconnect ───────────────────────────────────────────────────

    pub fn disconnect(&mut self) {
        if let Some(child) = &self.child {
            // SIGTERM → graceful OpenVPN shutdown (runs down scripts)
            let pid = Pid::from_raw(child.id() as i32);
            let _ = kill(pid, Signal::SIGTERM);

            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let Some(c) = &mut self.child {
                    if c.try_wait().ok().flatten().is_some() { break; }
                }
                thread::sleep(Duration::from_millis(200));
            }

            // Force-kill if still running
            if let Some(c) = &mut self.child {
                if c.try_wait().ok().flatten().is_none() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
        }

        self.child = None;
        *self.connected.lock().unwrap() = false;

        // CRITICAL FIX: explicitly tear down the interface.
        // OpenVPN's graceful shutdown removes routes via its down script, but
        // SIGKILL bypasses that, and even SIGTERM can race. We always do it
        // ourselves so the routing table is clean regardless.
        let _ = network::teardown_vpn_interfaces();

        self.remove_tmp_config();
    }

    // ── Force kill (emergency) ────────────────────────────────────────────────

    pub fn force_disconnect(&mut self) {
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.child = None;
        *self.connected.lock().unwrap() = false;

        // Same fix as above – explicit interface teardown
        let _ = network::teardown_vpn_interfaces();

        self.remove_tmp_config();
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn spawn_process(&mut self, config: &Path, auth_file: Option<&Path>) -> Result<()> {
        let mut cmd = Command::new("openvpn");
        cmd.args([
            "--config",              config.to_str().unwrap(),
            "--auth-nocache",
            "--connect-retry",       "5",
            "--connect-retry-max",   "3",
            "--explicit-exit-notify","2",
            // NO --persist-tun (root cause of the original network-lock bug)
        ]);
        if self.verbose {
            cmd.args(["--verb", "5"]);
        }

        if let Some(auth) = auth_file {
            cmd.args(["--auth-user-pass", auth.to_str().unwrap()]);
        }
        // If no auth_file: openvpn reads credentials from its own stdin prompt
        // (inherited below). Do NOT add a bare --auth-user-pass here; the .ovpn
        // config already contains it and adding it twice causes a double-prompt.

        // KEY FIX: OpenVPN writes ALL log output to stderr, not stdout.
        // The original code piped stdout and nulled stderr, so the reader thread
        // saw nothing and the 45 s connect timeout always fired.
        //
        // stdin  -> inherited  (lets openvpn prompt for credentials interactively)
        // stdout -> null       (openvpn doesn't use stdout meaningfully)
        // stderr -> piped      (all log lines incl. "Initialization Sequence Completed")
        cmd.stdin(Stdio::inherit())
           .stdout(Stdio::null())
           .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("spawn openvpn")?;
        let stderr = child.stderr.take().expect("stderr pipe");

        self.child = Some(child);

        // Spawn a monitor thread that reads openvpn stderr
        let connected   = Arc::clone(&self.connected);
        let fail_reason = Arc::clone(&self.fail_reason);
        let log         = Arc::clone(&self.log);

        thread::Builder::new()
            .name("openvpn-reader".into())
            .spawn(move || {
                let reader = BufReader::new(stderr);
                for raw in reader.lines() {
                    let Ok(line) = raw else { break };
                    let line = line.trim().to_string();
                    if line.is_empty() { continue; }

                    push_log(&log, &format!("openvpn  {line}"));

                    if line.contains("Initialization Sequence Completed") {
                        *connected.lock().unwrap() = true;

                    } else if line.contains("AUTH_FAILED") || line.contains("auth-failure") {
                        *fail_reason.lock().unwrap() =
                            Some(format!("authentication failed: {line}"));

                    } else if line.contains("TLS Error") || line.contains("TLS_ERROR") {
                        *fail_reason.lock().unwrap() =
                            Some(format!("TLS error: {line}"));

                    } else if line.contains("process exiting") || line.contains("SIGTERM") {
                        *connected.lock().unwrap() = false;
                    }
                }
                // EOF → process died
                *connected.lock().unwrap() = false;
            })
            .context("spawn reader thread")?;

        Ok(())
    }

    fn remove_tmp_config(&mut self) {
        if let Some(p) = self.tmp_config.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for OpenVpnProcess {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.force_disconnect();
        }
    }
}

// ─── Config generation ────────────────────────────────────────────────────────

/// Write a minimal, correct OpenVPN config to a temp file.
/// Notably absent: `persist-tun` – that directive keeps the kernel interface
/// alive after the process dies, orphaning routes that block all traffic.
fn write_temp_config(
    host:  &str,
    port:  u16,
    proto: &str,
    dns:   &[String],
) -> Result<PathBuf> {
    use std::io::Write;

    let primary   = dns.first().map(|s| s.as_str()).unwrap_or("1.1.1.1");
    let secondary = dns.get(1).map(|s| s.as_str()).unwrap_or(primary);

    let content = format!(
        "client\n\
         dev tun\n\
         proto {proto}\n\
         remote {host} {port}\n\
         resolv-retry infinite\n\
         nobind\n\
         persist-key\n\
         remote-cert-tls server\n\
         cipher AES-256-GCM\n\
         auth SHA256\n\
         verb 3\n\
         mute 20\n\
         auth-user-pass\n\
         redirect-gateway def1\n\
         block-outside-dns\n\
         dhcp-option DNS {primary}\n\
         dhcp-option DNS {secondary}\n\
         sndbuf 393216\n\
         rcvbuf 393216\n\
         fast-io\n\
         keepalive 10 30\n"
    );

    let mut f = tempfile::Builder::new()
        .suffix(".ovpn")
        .tempfile()
        .context("create temp config")?;
    f.write_all(content.as_bytes())?;
    let (_, path) = f.keep().context("keep temp config")?;
    Ok(path)
}

// ─── Helper ───────────────────────────────────────────────────────────────────

fn push_log(log: &LogBuf, msg: &str) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s =  secs % 60;
    let ts = format!("{h:02}:{m:02}:{s:02}");

    let mut buf = log.lock().unwrap();
    if buf.len() >= 4096 { buf.pop_front(); }
    buf.push_back(format!("[{ts}] {msg}"));
}
