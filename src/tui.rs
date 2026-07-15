#![allow(deprecated)]
//! tui.rs – three-tab TUI (ratatui 0.21 API)
//!
//! Tab 0 – Status:  connection state, server, IP, uptime, traffic, kill-switch
//! Tab 1 – Log:     live verbose log scrollable with arrow keys / PgUp / PgDn
//! Tab 2 – Configs: config files next to the active one; Enter switches VPN

use std::io;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};

use crate::configs::{self, ConfigEntry};
use crate::state::{human_bytes, human_rate, hms, LogBuf, SharedState, VpnState};

// ─── Public types ─────────────────────────────────────────────────────────────

/// What the user chose when the TUI exited.
pub enum TuiAction {
    /// Disconnect and quit
    Quit,
    /// Disconnect, then reconnect using this config file
    Switch(PathBuf),
}

/// Where to look for sibling configs and which one is active.
pub struct ConfigPicker {
    pub dir:     Option<PathBuf>,
    pub current: Option<PathBuf>,
}

impl ConfigPicker {
    fn scan(&self) -> Vec<ConfigEntry> {
        self.dir.as_deref().map(configs::scan).unwrap_or_default()
    }

    fn is_current(&self, path: &std::path::Path) -> bool {
        match &self.current {
            None => false,
            Some(cur) => {
                let a = std::fs::canonicalize(cur).unwrap_or_else(|_| cur.clone());
                let b = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
                a == b
            }
        }
    }
}

// ─── Gruvbox palette ─────────────────────────────────────────────────────────
#[allow(dead_code)]
const BG:     Color = Color::Rgb(40,  40,  40);
const FG:     Color = Color::Rgb(235, 219, 178);
const YELLOW: Color = Color::Rgb(215, 153, 33);
const GREEN:  Color = Color::Rgb(152, 151, 26);
const RED:    Color = Color::Rgb(204, 36,  29);
const BLUE:   Color = Color::Rgb(69,  133, 136);
const AQUA:   Color = Color::Rgb(104, 157, 106);
const ORANGE: Color = Color::Rgb(214, 93,  14);
const GRAY:   Color = Color::Rgb(146, 131, 116);

const TAB_COUNT: usize = 3;

// ─── Public entry ─────────────────────────────────────────────────────────────

pub fn run(
    state:   SharedState,
    log_buf: LogBuf,
    stop_tx: SyncSender<()>,
    picker:  ConfigPicker,
) -> anyhow::Result<TuiAction> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut tab     = 0usize;
    let mut log_off = 0usize;
    let mut action  = TuiAction::Quit;

    // Config list state (rescanned every time the tab is entered)
    let mut cfg_entries: Vec<ConfigEntry> = Vec::new();
    let mut cfg_sel = 0usize;

    let enter_configs_tab = |entries: &mut Vec<ConfigEntry>, sel: &mut usize| {
        *entries = picker.scan();
        if *sel >= entries.len() { *sel = entries.len().saturating_sub(1); }
    };

    // First frame right away — don't sit on a blank alternate screen
    term.draw(|f| render(f, &state, &log_buf, tab, log_off, &cfg_entries, cfg_sel, &picker))?;
    let mut last = Instant::now();

    loop {
        if last.elapsed() >= Duration::from_millis(100) {
            term.draw(|f| render(f, &state, &log_buf, tab, log_off, &cfg_entries, cfg_sel, &picker))?;
            last = Instant::now();
        }

        if !event::poll(Duration::from_millis(50))? { continue; }

        if let Event::Key(k) = event::read()? {
            match (k.code, k.modifiers) {
                (KeyCode::Char('q'), _)
                | (KeyCode::Esc, _)
                | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                    let _ = stop_tx.try_send(());
                    break;
                }
                (KeyCode::Tab, _) => {
                    tab = (tab + 1) % TAB_COUNT;
                    log_off = 0;
                    if tab == 2 { enter_configs_tab(&mut cfg_entries, &mut cfg_sel); }
                }
                (KeyCode::Char('1'), _)  => { tab = 0; }
                (KeyCode::Char('2'), _)  => { tab = 1; }
                (KeyCode::Char('3'), _)  => {
                    tab = 2;
                    enter_configs_tab(&mut cfg_entries, &mut cfg_sel);
                }

                // Log tab scrolling
                (KeyCode::Up,     _) if tab == 1 => { log_off = log_off.saturating_add(1); }
                (KeyCode::Down,   _) if tab == 1 => { log_off = log_off.saturating_sub(1); }
                (KeyCode::PageUp, _) if tab == 1 => { log_off = log_off.saturating_add(20); }
                (KeyCode::PageDown,_) if tab == 1 => { log_off = log_off.saturating_sub(20); }
                (KeyCode::End,    _) if tab == 1 => { log_off = 0; }

                // Configs tab selection
                (KeyCode::Up,   _) if tab == 2 => { cfg_sel = cfg_sel.saturating_sub(1); }
                (KeyCode::Down, _) if tab == 2 => {
                    if cfg_sel + 1 < cfg_entries.len() { cfg_sel += 1; }
                }
                (KeyCode::Enter, _) if tab == 2 => {
                    if let Some(e) = cfg_entries.get(cfg_sel) {
                        if !picker.is_current(&e.path) {
                            let _ = stop_tx.try_send(());
                            action = TuiAction::Switch(e.path.clone());
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    Ok(action)
}

// ─── Root render ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render(
    f:           &mut Frame<CrosstermBackend<io::Stdout>>,
    state:       &SharedState,
    log_buf:     &LogBuf,
    tab:         usize,
    log_off:     usize,
    cfg_entries: &[ConfigEntry],
    cfg_sel:     usize,
    picker:      &ConfigPicker,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.size());

    render_tab_bar(f, rows[0], tab);

    match tab {
        0 => render_status(f, rows[1], state),
        1 => render_log(f,    rows[1], log_buf, log_off),
        2 => render_configs(f, rows[1], cfg_entries, cfg_sel, picker),
        _ => {}
    }

    render_help(f, rows[2], tab);
}

// ─── Tab bar ─────────────────────────────────────────────────────────────────

fn render_tab_bar(
    f:    &mut Frame<CrosstermBackend<io::Stdout>>,
    area: Rect,
    sel:  usize,
) {
    let titles = vec![
        Spans::from(vec![
            Span::raw("  "),
            Span::styled("1", Style::default().fg(YELLOW)),
            Span::raw(" Status  "),
        ]),
        Spans::from(vec![
            Span::raw("  "),
            Span::styled("2", Style::default().fg(YELLOW)),
            Span::raw(" Log  "),
        ]),
        Spans::from(vec![
            Span::raw("  "),
            Span::styled("3", Style::default().fg(YELLOW)),
            Span::raw(" Configs  "),
        ]),
    ];

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " vpn-manager ",
                    Style::default().fg(AQUA).add_modifier(Modifier::BOLD),
                ))
                .border_style(Style::default().fg(GRAY)),
        )
        .select(sel)
        .style(Style::default().fg(FG))
        .highlight_style(
            Style::default()
                .fg(GREEN)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        );

    f.render_widget(tabs, area);
}

// ─── Status tab ───────────────────────────────────────────────────────────────

fn render_status(
    f:     &mut Frame<CrosstermBackend<io::Stdout>>,
    area:  Rect,
    state: &SharedState,
) {
    let (vpn_state, info) = {
        let g = state.lock().unwrap();
        (g.0.clone(), g.1.clone())
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // ── Left: connection info ────────────────────────────────────────────────
    let uptime = info.connected_at
        .map(|t| hms(t.elapsed().as_secs()))
        .unwrap_or_else(|| "—".into());

    let (sc, icon) = match &vpn_state {
        VpnState::Connected    => (GREEN,  "● CONNECTED"),
        VpnState::Connecting   => (YELLOW, "◌ CONNECTING"),
        VpnState::Disconnected => (GRAY,   "○ DISCONNECTED"),
        VpnState::Error(_)     => (RED,    "✗ ERROR"),
        _                      => (ORANGE, "◎ BUSY"),
    };

    let ks_label = if info.ks_active { "● ACTIVE" } else { "○ inactive" };
    let ks_color = if info.ks_active { GREEN } else { GRAY };

    let proto_color = if info.protocol == "WireGuard" { AQUA } else { BLUE };

    // City, Country — matches the log format; placeholder until the
    // background geo lookup finishes
    let location = if info.server_city.is_empty() && info.server_country.is_empty() {
        "resolving...".to_string()
    } else {
        format!("{}, {}", info.server_city, info.server_country)
    };
    let public_ip = info.public_ip.as_deref().unwrap_or(
        if vpn_state == VpnState::Connected { "resolving..." } else { "—" }
    );

    let rows = vec![
        kv("State",      icon, sc),
        kv("Protocol",   if info.protocol.is_empty() { "—" } else { &info.protocol }, proto_color),
        kv("Server",     &info.server_host, FG),
        kv("Location",   &location, BLUE),
        kv("Public IP",  public_ip, AQUA),
        kv("Interface",  info.vpn_iface.as_deref().unwrap_or("—"), FG),
        kv("Uptime",     &uptime, YELLOW),
        blank(),
        kv("Kill Switch", ks_label, ks_color),
        kv("DNS",        &info.dns_servers.join("  "), FG),
    ];

    let conn = Paragraph::new(rows)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" Connection ", Style::default().fg(BLUE)))
            .border_style(Style::default().fg(GRAY)))
        .wrap(Wrap { trim: true });
    f.render_widget(conn, cols[0]);

    // ── Right: traffic ────────────────────────────────────────────────────────
    let t = &info.traffic;
    let traffic_rows = vec![
        blank(),
        kv("↑ Sent",      &human_bytes(t.bytes_sent),   FG),
        kv("↑ Rate",      &human_rate(t.upload_bps),    ORANGE),
        blank(),
        kv("↓ Received",  &human_bytes(t.bytes_recv),   FG),
        kv("↓ Rate",      &human_rate(t.download_bps),  AQUA),
    ];

    let traf = Paragraph::new(traffic_rows)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" Traffic ", Style::default().fg(BLUE)))
            .border_style(Style::default().fg(GRAY)));
    f.render_widget(traf, cols[1]);
}

// ─── Log tab ─────────────────────────────────────────────────────────────────

fn render_log(
    f:       &mut Frame<CrosstermBackend<io::Stdout>>,
    area:    Rect,
    log_buf: &LogBuf,
    offset:  usize,
) {
    let buf      = log_buf.lock().unwrap();
    let inner_h  = area.height.saturating_sub(2) as usize;
    let total    = buf.len();
    let skip     = offset.min(total.saturating_sub(inner_h));
    let start    = total.saturating_sub(inner_h + skip);
    let end      = (start + inner_h).min(total);

    let items: Vec<ListItem> = buf
        .range(start..end)
        .map(|line| {
            let color = if line.contains("ERROR") || line.contains("failed") {
                RED
            } else if line.contains("WARN") {
                ORANGE
            } else if line.contains("kill") || line.contains("kill-switch") {
                YELLOW
            } else if line.contains("connected") || line.contains("Initialization") {
                GREEN
            } else if line.contains("wg-quick") || line.contains("WireGuard") {
                AQUA
            } else if line.contains("openvpn") {
                BLUE
            } else {
                FG
            };
            ListItem::new(Spans::from(Span::styled(line.clone(), Style::default().fg(color))))
        })
        .collect();

    let title = if offset > 0 {
        format!(" Log (↑{offset} lines) ")
    } else {
        " Log (live) ".into()
    };

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(title, Style::default().fg(BLUE)))
            .border_style(Style::default().fg(GRAY)));

    f.render_widget(list, area);
}

// ─── Configs tab ─────────────────────────────────────────────────────────────

fn render_configs(
    f:       &mut Frame<CrosstermBackend<io::Stdout>>,
    area:    Rect,
    entries: &[ConfigEntry],
    sel:     usize,
    picker:  &ConfigPicker,
) {
    let title = match &picker.dir {
        Some(d) => format!(" Configs ({}) ", d.display()),
        None    => " Configs ".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(title, Style::default().fg(BLUE)))
        .border_style(Style::default().fg(GRAY));

    if entries.is_empty() {
        let msg = match &picker.dir {
            Some(d) => format!("no .ovpn / WireGuard .conf files found in {}", d.display()),
            None    => "connected via --host — no config directory to scan".to_string(),
        };
        let p = Paragraph::new(msg)
            .style(Style::default().fg(GRAY))
            .block(block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, area);
        return;
    }

    // Keep the selection visible in the window
    let inner_h = area.height.saturating_sub(2) as usize;
    let start = if inner_h == 0 || sel < inner_h { 0 } else { sel + 1 - inner_h };

    let items: Vec<ListItem> = entries
        .iter()
        .enumerate()
        .skip(start)
        .take(inner_h.max(1))
        .map(|(i, e)| {
            let is_cur = picker.is_current(&e.path);
            let marker = if is_cur { "● " } else { "  " };
            let kind_color = if e.kind == "WireGuard" { AQUA } else { BLUE };

            let mut name_style = Style::default().fg(if is_cur { GREEN } else { FG });
            let mut row_prefix = Style::default().fg(GREEN);
            if i == sel {
                name_style = name_style.add_modifier(Modifier::REVERSED);
                row_prefix = row_prefix.add_modifier(Modifier::REVERSED);
            }

            ListItem::new(Spans::from(vec![
                Span::styled(marker.to_string(), row_prefix),
                Span::styled(format!("{:<36}", e.name), name_style),
                Span::styled(format!(" {:<10}", e.kind), Style::default().fg(kind_color)),
                Span::styled(format!(" {}", e.server), Style::default().fg(GRAY)),
            ]))
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

// ─── Help bar ─────────────────────────────────────────────────────────────────

fn render_help(
    f:    &mut Frame<CrosstermBackend<io::Stdout>>,
    area: Rect,
    tab:  usize,
) {
    let mut spans = vec![
        Span::styled("[Tab/1/2/3]", Style::default().fg(YELLOW)),
        Span::raw(" switch   "),
        Span::styled("[q / Esc]", Style::default().fg(RED)),
        Span::raw(" disconnect & quit   "),
    ];
    match tab {
        1 => spans.extend([
            Span::styled("[↑↓ PgUp PgDn]", Style::default().fg(YELLOW)),
            Span::raw(" scroll   "),
            Span::styled("[End]", Style::default().fg(YELLOW)),
            Span::raw(" jump to bottom"),
        ]),
        2 => spans.extend([
            Span::styled("[↑↓]", Style::default().fg(YELLOW)),
            Span::raw(" select   "),
            Span::styled("[Enter]", Style::default().fg(GREEN)),
            Span::raw(" reconnect with selected config"),
        ]),
        _ => {}
    }
    let p = Paragraph::new(Spans::from(spans))
        .alignment(Alignment::Left)
        .style(Style::default().fg(GRAY));
    f.render_widget(p, area);
}

// ─── Row helpers ─────────────────────────────────────────────────────────────

fn kv(label: &str, value: &str, vc: Color) -> Spans<'static> {
    let w = 14usize;
    Spans::from(vec![
        Span::styled(format!("{:<w$}", label), Style::default().fg(GRAY)),
        Span::styled(value.to_string(), Style::default().fg(vc)),
    ])
}

fn blank() -> Spans<'static> { Spans::from("") }
