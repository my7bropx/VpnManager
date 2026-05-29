#![allow(dead_code)]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum VpnState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error(String),
}

impl VpnState {
    pub fn label(&self) -> &str {
        match self {
            Self::Disconnected  => "DISCONNECTED",
            Self::Connecting    => "CONNECTING",
            Self::Connected     => "CONNECTED",
            Self::Disconnecting => "DISCONNECTING",
            Self::Error(_)      => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Traffic {
    pub bytes_sent:    u64,
    pub bytes_recv:    u64,
    pub upload_bps:    f64,
    pub download_bps:  f64,
    pub last_sample:   Option<(Instant, u64, u64)>, // (time, sent, recv)
}

impl Traffic {
    /// Update bytes from /proc/net/dev counters and compute rates.
    pub fn update(&mut self, new_sent: u64, new_recv: u64) {
        let now = Instant::now();
        if let Some((t, ps, pr)) = self.last_sample {
            let elapsed = t.elapsed().as_secs_f64().max(0.001);
            self.upload_bps   = (new_sent.saturating_sub(ps)) as f64 / elapsed;
            self.download_bps = (new_recv.saturating_sub(pr)) as f64 / elapsed;
        }
        self.bytes_sent  = new_sent;
        self.bytes_recv  = new_recv;
        self.last_sample = Some((now, new_sent, new_recv));
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConnInfo {
    pub server_host:    String,
    pub server_country: String,
    pub server_city:    String,
    pub public_ip:      Option<String>,
    pub vpn_iface:      Option<String>,
    pub dns_servers:    Vec<String>,
    pub connected_at:   Option<Instant>,
    pub ks_active:      bool,
    pub traffic:        Traffic,
}

// ─── Shared handles ────────────────────────────────────────────────────────────

pub type SharedState = Arc<Mutex<(VpnState, ConnInfo)>>;
pub type LogBuf      = Arc<Mutex<VecDeque<String>>>;

pub fn new_state() -> SharedState {
    Arc::new(Mutex::new((VpnState::Disconnected, ConnInfo::default())))
}

pub fn new_log() -> LogBuf {
    Arc::new(Mutex::new(VecDeque::with_capacity(4096)))
}

// ─── State file for cross-process disconnect/recover ─────────────────────────

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionFile {
    pub pid:       u32,
    pub iface:     Option<String>,
    pub host:      String,
    pub country:   String,
    pub ks_active: bool,
    pub dns:       Vec<String>,
    pub ts:        u64,
}

pub const SESSION_PATH: &str = "/tmp/vpn-manager.session";

impl SessionFile {
    pub fn write(&self) {
        if let Ok(j) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(SESSION_PATH, j);
        }
    }

    pub fn read() -> Option<Self> {
        let raw = std::fs::read_to_string(SESSION_PATH).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn remove() {
        let _ = std::fs::remove_file(SESSION_PATH);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

pub fn log_push(buf: &LogBuf, msg: impl Into<String>) {
    let mut b = buf.lock().unwrap();
    if b.len() >= 4096 { b.pop_front(); }
    b.push_back(msg.into());
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{} B", n) } else { format!("{:.1} {}", v, UNITS[i]) }
}

pub fn human_rate(bps: f64) -> String {
    human_bytes(bps as u64) + "/s"
}

pub fn hms(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}
