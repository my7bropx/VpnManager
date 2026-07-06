#![allow(deprecated)]
//! tui.rs – two-tab TUI (ratatui 0.21 API)
//!
//! Tab 0 – Status: connection state, server, IP, uptime, traffic, kill-switch
//! Tab 1 – Log:    live verbose log scrollable with arrow keys / PgUp / PgDn

use std::io;
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

use crate::state::{human_bytes, human_rate, hms, LogBuf, SharedState, VpnState};

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

// ─── Public entry ─────────────────────────────────────────────────────────────

pub fn run(
    state:   SharedState,
    log_buf: LogBuf,
    stop_tx: SyncSender<()>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut tab     = 0usize;
    let mut log_off = 0usize;
    let mut last    = Instant::now();

    loop {
        if last.elapsed() >= Duration::from_millis(100) {
            term.draw(|f| render(f, &state, &log_buf, tab, log_off))?;
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
                (KeyCode::Tab, _)        => { tab = (tab + 1) % 2; log_off = 0; }
                (KeyCode::Char('1'), _)  => { tab = 0; }
                (KeyCode::Char('2'), _)  => { tab = 1; }
                (KeyCode::Up,     _) if tab == 1 => { log_off = log_off.saturating_add(1); }
                (KeyCode::Down,   _) if tab == 1 => { log_off = log_off.saturating_sub(1); }
                (KeyCode::PageUp, _) if tab == 1 => { log_off = log_off.saturating_add(20); }
                (KeyCode::PageDown,_) if tab == 1 => { log_off = log_off.saturating_sub(20); }
                (KeyCode::End,    _) if tab == 1 => { log_off = 0; }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

// ─── Root render ─────────────────────────────────────────────────────────────

fn render(
    f:       &mut Frame<CrosstermBackend<io::Stdout>>,
    state:   &SharedState,
    log_buf: &LogBuf,
    tab:     usize,
    log_off: usize,
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
            Span::raw(" Log     "),
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
    let rows = vec![
        kv("State",      icon, sc),
        kv("Protocol",   if info.protocol.is_empty() { "—" } else { &info.protocol }, proto_color),
        kv("Server",     &info.server_host, FG),
        kv("Location",   &format!("{}, {}", info.server_country, info.server_city), BLUE),
        kv("Public IP",  info.public_ip.as_deref().unwrap_or("—"), AQUA),
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

// ─── Help bar ─────────────────────────────────────────────────────────────────

fn render_help(
    f:    &mut Frame<CrosstermBackend<io::Stdout>>,
    area: Rect,
    tab:  usize,
) {
    let mut spans = vec![
        Span::styled("[Tab/1/2]", Style::default().fg(YELLOW)),
        Span::raw(" switch   "),
        Span::styled("[q / Esc]", Style::default().fg(RED)),
        Span::raw(" disconnect & quit   "),
    ];
    if tab == 1 {
        spans.extend([
            Span::styled("[↑↓ PgUp PgDn]", Style::default().fg(YELLOW)),
            Span::raw(" scroll   "),
            Span::styled("[End]", Style::default().fg(YELLOW)),
            Span::raw(" jump to bottom"),
        ]);
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
