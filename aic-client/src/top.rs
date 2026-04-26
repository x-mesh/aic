//! `aic top` 라이브 TUI — ratatui 기반 데몬 metric 모니터.
//!
//! - 1초 polling으로 `MetricsSnapshot` 갱신
//! - q 종료 / r 강제 refresh / Esc 종료
//! - 비-TTY 환경에서는 caller가 텍스트 모드로 fallback해야 함

use crate::uds_client::UdsClient;
use aic_common::MetricsSnapshot;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};
use ratatui::Terminal;
use std::time::{Duration, Instant};

pub async fn run_top(client: UdsClient, interval_secs: u64) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let interval = Duration::from_secs(interval_secs.max(1));
    let mut snap: Option<MetricsSnapshot> = client.get_metrics().await.ok();
    let mut last_refresh = Instant::now();

    let result: anyhow::Result<()> = loop {
        if let Err(e) = terminal.draw(|f| draw(f, snap.as_ref())) {
            break Err(e.into());
        }

        let poll_remaining = interval.saturating_sub(last_refresh.elapsed());
        let poll_dur = if poll_remaining.is_zero() {
            Duration::from_millis(50)
        } else {
            poll_remaining.min(Duration::from_millis(200))
        };

        let event_pending = match event::poll(poll_dur) {
            Ok(b) => b,
            Err(e) => break Err(e.into()),
        };
        if event_pending {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                        KeyCode::Char('r') => {
                            snap = client.get_metrics().await.ok();
                            last_refresh = Instant::now();
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_refresh.elapsed() >= interval {
            snap = client.get_metrics().await.ok();
            last_refresh = Instant::now();
        }
    };

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    result
}

fn draw(frame: &mut ratatui::Frame, snap: Option<&MetricsSnapshot>) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    // header
    let alive = snap.is_some();
    let header = Paragraph::new(Line::from(vec![
        Span::raw("aic-session — "),
        Span::styled(
            if alive {
                "✔ alive"
            } else {
                "✗ no response"
            },
            Style::default()
                .fg(if alive { Color::Green } else { Color::Red })
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(header, chunks[0]);

    // metrics body
    let body_lines: Vec<Line> = match snap {
        Some(m) => {
            let h = m.uptime_secs / 3600;
            let mn = (m.uptime_secs / 60) % 60;
            let s = m.uptime_secs % 60;
            let last = m
                .last_command_secs_ago
                .map(|n| format!("{n}s ago"))
                .unwrap_or_else(|| "-".into());
            vec![
                line_kv("uptime", format!("{h}h {mn}m {s}s")),
                line_kv("pid", m.pid.to_string()),
                line_kv("ipc reqs (cumulative)", m.ipc_request_count.to_string()),
                line_kv("rb usage", format!("{}/{} lines", m.rb_used, m.rb_capacity)),
                line_kv("last cmd", last),
            ]
        }
        None => vec![Line::from(Span::styled(
            "(데몬 응답 없음)",
            Style::default().fg(Color::DarkGray),
        ))],
    };
    let body =
        Paragraph::new(body_lines).block(Block::default().borders(Borders::ALL).title("Metrics"));
    frame.render_widget(body, chunks[1]);

    // gauge for rb usage
    let pct = match snap {
        Some(m) if m.rb_capacity > 0 => {
            ((m.rb_used as f64 / m.rb_capacity as f64) * 100.0).clamp(0.0, 100.0) as u16
        }
        _ => 0,
    };
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Ring Buffer 사용률"),
        )
        .gauge_style(Style::default().fg(if pct >= 80 {
            Color::Red
        } else if pct >= 50 {
            Color::Yellow
        } else {
            Color::Green
        }))
        .percent(pct);
    frame.render_widget(gauge, chunks[2]);

    // footer help
    let footer = Paragraph::new("q / Esc = quit · r = refresh now")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[3]);
}

fn line_kv(key: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{key:<24}"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(value),
    ])
}
