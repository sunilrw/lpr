use crate::sym::*;
use crate::engine::{
    extract_source_from_sql, format_helpful_error, generate_intent_suggestions, IntentSuggestion,
    LogEngine,
};
use crate::parsers::{clean_windows_path, is_supported_log_or_data_file, InputFormat};
use crate::server::discover_initial_source;
use anyhow::Result;
use arrow::util::display::array_value_to_string;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap},
    Terminal,
};
use std::io;
use std::path::{Path, PathBuf};

#[derive(PartialEq, Eq)]
enum TuiModal {
    None,
    Help,
    Intents,
    FileBrowser,
}

struct BrowserItem {
    name: String,
    path: String,
    is_dir: bool,
}

const STATIC_COMPLETIONS: &[&str] = &[
    "SELECT",
    "FROM",
    "logs",
    "WHERE",
    "GROUP BY",
    "ORDER BY",
    "LIMIT",
    "COUNT(*)",
    "detect_threat(",
    "ip_in_cidr(",
    "shannon_entropy(",
    "mask_pii(",
    "cluster_template(",
    "url_decode(",
    "parse_ua(",
    "extract_token(",
    "extract_extension(",
    "to_timestamp(",
    "index_of(",
];

pub async fn run_tui(initial_source: &str, format: InputFormat) -> Result<()> {
    let mut engine = LogEngine::new();
    let cleaned_init = clean_windows_path(initial_source);
    let mut active_source = if cleaned_init == "." || Path::new(&cleaned_init).is_dir() {
        discover_initial_source(None).unwrap_or(cleaned_init)
    } else {
        cleaned_init
    };
    let mut active_format = format;
    let mut detected_fmt = InputFormat::Auto;
    let mut columns: Vec<String> = Vec::new();
    let mut suggestions: Vec<IntentSuggestion> = Vec::new();
    let mut last_error: Option<String> = None;

    if Path::new(&active_source).is_file() || active_source.contains('*') {
        match engine
            .register_source("logs", &active_source, active_format, None)
            .await
        {
            Ok(fmt) => {
                detected_fmt = fmt;
                columns = engine.table_columns("logs").await;
                suggestions = generate_intent_suggestions(detected_fmt, &columns);
            }
            Err(e) => {
                last_error = Some(format_helpful_error(&e.to_string(), Some(&active_source), &[]));
            }
        }
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut sql_input = if !suggestions.is_empty() {
        suggestions[0].sql.clone()
    } else {
        String::from("SELECT * FROM logs LIMIT 50")
    };
    let mut status_msg = format!(
        "Source: `{}` ({:?}) | Enter=Run | Tab=AutoComplete | F1=Help | F2=Intents | F3=Browse Files | Esc=Quit",
        active_source, detected_fmt
    );
    let mut headers: Vec<String> = Vec::new();
    let mut table_rows: Vec<Vec<String>> = Vec::new();

    if !columns.is_empty() {
        match engine.query(&sql_input).await {
            Ok(batches) => {
                extract_grid(&batches, &mut headers, &mut table_rows);
                last_error = None;
            }
            Err(e) => {
                last_error = Some(format_helpful_error(
                    &e.to_string(),
                    Some(&active_source),
                    &columns,
                ));
            }
        }
    } else if last_error.is_none() {
        last_error = Some(format_helpful_error(
            "table 'datafusion.public.logs' not found",
            Some(&active_source),
            &[],
        ));
    }

    let mut modal = if Path::new(&active_source).is_dir() || columns.is_empty() {
        TuiModal::FileBrowser
    } else {
        TuiModal::None
    };

    let mut intent_idx: usize = 0;
    let mut help_scroll: u16 = 0;
    let mut current_dir: PathBuf = if Path::new(&active_source).is_dir() {
        PathBuf::from(&active_source)
    } else {
        Path::new(&active_source)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    };
    let mut browser_items = scan_directory(&current_dir);
    let mut browser_idx: usize = 0;
    let mut tab_cycle_idx: usize = 0;
    let mut last_tab_prefix = String::new();

    loop {
        let hint_token = compute_inline_completion(&sql_input, &columns);

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(4),
                    Constraint::Min(8),
                    Constraint::Length(3),
                ])
                .split(f.area());

            let top_bar = Paragraph::new(Line::from(vec![
                Span::styled(
                    format!(" {SYM_SHIELD} lpr Studio TUI v{} ", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{SYM_FOLDER} {} ({:?}) ", active_source, detected_fmt),
                    Style::default().fg(Color::LightCyan),
                ),
                Span::styled(
                    format!("| {SYM_LIST} Columns: {} ", columns.join(", ")),
                    Style::default().fg(Color::Gray),
                ),
            ]));
            f.render_widget(top_bar, chunks[0]);

            let mut query_spans = vec![Span::styled(
                sql_input.as_str(),
                Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
            )];
            if let Some(ref suggestion) = hint_token {
                query_spans.push(Span::styled(
                    format!("  [Tab -> {}]", suggestion),
                    Style::default().fg(Color::DarkGray),
                ));
            }

            let query_box = Paragraph::new(Line::from(query_spans))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" SQL Editor (Enter=Run | Tab=AutoComplete | F1=Help | F2=Smart Intents | F3=Browse Files | Esc=Quit) "),
                );
            f.render_widget(query_box, chunks[1]);

            if let Some(ref err_detail) = last_error {
                let mut err_lines = vec![
                    Line::from(Span::styled(
                        format!("{SYM_WARN}  DIAGNOSTIC & TROUBLESHOOTING GUIDE"),
                        Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                ];
                for line in err_detail.lines() {
                    let st = if line.starts_with("WHAT IS WRONG:")
                        || line.starts_with("HOW TO SOLVE IT:")
                        || line.starts_with("AVAILABLE COLUMNS")
                    {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else if line.trim_start().starts_with('•') {
                        Style::default().fg(Color::LightCyan)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    err_lines.push(Line::from(Span::styled(format!("  {}", line), st)));
                }
                let err_box = Paragraph::new(err_lines)
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .style(Style::default().fg(Color::LightRed))
                            .title(" Diagnostic Details & Solution Steps (Press F3 to Browse Files or F1 for Help) "),
                    );
                f.render_widget(err_box, chunks[2]);
            } else {
                let header_cells = headers.iter().map(|h| {
                    Cell::from(h.as_str())
                        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                });
                let header = Row::new(header_cells).height(1).bottom_margin(1);
                let rows = table_rows.iter().map(|r| {
                    Row::new(r.iter().map(|c| {
                        let style = if c.starts_with("CRITICAL:") || c.starts_with("HIGH:") {
                            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
                        } else if c.starts_with("MEDIUM:") {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::White)
                        };
                        Cell::from(c.as_str()).style(style)
                    }))
                    .height(1)
                });
                let col_count = headers.len().max(1);
                let widths: Vec<Constraint> = (0..col_count)
                    .map(|_| Constraint::Percentage((100 / col_count).max(5) as u16))
                    .collect();

                let table = Table::new(rows, widths).header(header).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" Query Results ({} rows) ", table_rows.len())),
                );
                f.render_widget(table, chunks[2]);
            }

            let status_bar = Paragraph::new(status_msg.lines().next().unwrap_or(&status_msg))
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Status & Shortcuts "));
            f.render_widget(status_bar, chunks[3]);

            match modal {
                TuiModal::None => {}
                TuiModal::Help => {
                    let area = centered_rect(88, 86, f.area());
                    f.render_widget(Clear, area);
                    let help_text = vec![
                        Line::from(Span::styled(
                            format!("{SYM_BOOKS} LPR v{} COMPLETE TUI, CLI, FLEET & SQL REFERENCE MANUAL (Use Up/Down/PgUp/PgDn to scroll)", env!("CARGO_PKG_VERSION")),
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        )),
                        Line::from(""),
                        Line::from(Span::styled("1. TUI KEYBOARD SHORTCUTS:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from("  • Enter         Execute current SQL query"),
                        Line::from("  • Tab           Context-aware auto-completion (schema columns, SQL keywords, UDFs)"),
                        Line::from("  • F1            Toggle this Full Help & Parameter Reference Manual"),
                        Line::from("  • F2            Open Context-Aware Intent Query Picker (tailored to active file)"),
                        Line::from("  • F3            Open Interactive File & Directory Browser (select file, *.log, or *.csv)"),
                        Line::from("  • Ctrl+U        Clear SQL query input"),
                        Line::from("  • Esc           Close active modal or exit TUI"),
                        Line::from(""),
                        Line::from(Span::styled("2. MULTI-SERVER FLEET SCANNER & TIME WINDOWS (`lpr fleet`):", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from("  • Save server profile once:  lpr fleet --save-profile ProdWeb --servers servers.csv --site AcmeStore --log-path \"D:\\Logs\\AcmeStore\" -j 8"),
                        Line::from("  • Scan last 12 hours:        lpr fleet --hours 12 --status 302 -g \"/partner-api/\""),
                        Line::from("  • Scan today (1 day):        lpr fleet -d 1 --status 500"),
                        Line::from("  • Scan newest active file:   lpr fleet --latest --status 5"),
                        Line::from("  • Custom SQL across servers: lpr fleet -d 1 --sql \"SELECT date, time, cs_uri_stem, sc_status FROM logs WHERE cs_uri_stem LIKE '%/partner-api/%'\""),
                        Line::from(""),
                        Line::from(Span::styled("3. SESSION INTELLIGENCE & CROSS-SERVER USER JOURNEY RECONSTRUCTION (NO AI):", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from("  • Step 1 — Learn session cookies/query params/X-Forwarded-For from logs & save to lpr.config.json:"),
                        Line::from("      lpr fleet --learn --latest"),
                        Line::from("  • Step 2A — Trace full journey of a specific Customer ID, Session ID, Order ID, or Cookie:"),
                        Line::from("      lpr fleet -d 1 --customer \"CUST-99481\""),
                        Line::from("  • Step 2B — Trace full journey by Clear Client IP or X-Forwarded-For IP:"),
                        Line::from("      lpr fleet -d 1 --trace-ip \"203.0.113.45\""),
                        Line::from("  • Step 2C — Trace journeys of ALL customers who failed payment or hit 500/302 (`--trace`):"),
                        Line::from("      lpr fleet --hours 12 --status 500 -g \"/checkout/payment\" --trace"),
                        Line::from(""),
                        Line::from(Span::styled("4. COMMAND HISTORY, PROFILES & LINUX CLI FLAGS:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from("  • Command History:           lpr history  |  lpr history -i (DOS Up/Down arrows)  |  lpr --rerun 5  |  lpr !5"),
                        Line::from("  • Saved Profiles:            lpr config   |  lpr config --set-default ProdWeb"),
                        Line::from("  • Linux grep + awk + stats:  lpr -f app.log -g \"500\" -F date,time,c_ip,cs_uri_stem,sc_status  |  lpr -f app.log --stats"),
                        Line::from(""),
                        Line::from(Span::styled("5. CYBERSECURITY & MICROSOFT LOG PARSER 2.2 SQL UDFs (23 FUNCTIONS):", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from("  • detect_threat(col)             Detects SQLi, XSS, LFI, RCE/Log4Shell, SSRF"),
                        Line::from("  • ip_in_cidr(ip, '10.0.0.0/8')   IPv4/IPv6 CIDR subnet containment"),
                        Line::from("  • shannon_entropy(col)           0.0-8.0 entropy score for base64/DGA anomalies"),
                        Line::from("  • mask_pii(col)                  Redacts emails to [REDACTED_EMAIL]"),
                        Line::from("  • cluster_template(col)          Drain clustering: replaces IPs/IDs/nums with <*>"),
                        Line::from("  • url_decode(col) / parse_ua(c)  URL percent-decode & User-Agent classification"),
                        Line::from("  • extract_token(s, idx, delim)   [LogParser 2.2] 0-based token split"),
                        Line::from("  • extract_extension(path)        [LogParser 2.2] Lowercase file extension (.aspx)"),
                        Line::from("  • win32_error_description(code)  [LogParser 2.2] Translate sc_win32_status code"),
                        Line::from("  • to_timestamp(date, time)       [LogParser 2.2] Combine W3C date & time"),
                        Line::from("  • index_of(str, substr)          [LogParser 2.2] 0-based substring index"),
                        Line::from(""),
                        Line::from(Span::styled("6. MICROSOFT LOG PARSER 2.2 SQL EXAMPLES:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                        Line::from("  • Direct file in FROM:  SELECT * FROM 'D:\\Logs\\u_ex261016.log' WHERE sc-status LIKE '5%'"),
                        Line::from("  • Export via INTO:      SELECT TOP 20 cs-uri-stem, COUNT(*) AS hits INTO top.csv FROM *.log GROUP BY 1 ORDER BY hits DESC"),
                    ];
                    let p = Paragraph::new(help_text)
                        .scroll((help_scroll, 0))
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .style(Style::default().bg(Color::Black))
                                .title(" Full Help Manual (Up/Down/PgUp/PgDn to Scroll | Esc or F1 to Close) "),
                        );
                    f.render_widget(p, area);
                }
                TuiModal::Intents => {
                    let area = centered_rect(80, 70, f.area());
                    f.render_widget(Clear, area);
                    let items: Vec<ListItem> = suggestions
                        .iter()
                        .enumerate()
                        .map(|(i, s)| {
                            let prefix = if i == intent_idx { SYM_SEL.s() } else { "  " };
                            let style = if i == intent_idx {
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::LightCyan)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            };
                            ListItem::new(vec![
                                Line::from(Span::styled(
                                    format!("{}[{}] {} — {}", prefix, s.category, s.title, s.description),
                                    style,
                                )),
                                Line::from(Span::styled(
                                    format!("     SQL: {}", s.sql),
                                    Style::default().fg(Color::LightGreen),
                                )),
                            ])
                        })
                        .collect();
                    let list = List::new(items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .style(Style::default().bg(Color::Black))
                            .title(format!(" {SYM_BRAIN} Context-Aware Intent Queries ({SYM_UP}/{SYM_DOWN} to select, Enter to run, Esc to close) ")),
                    );
                    f.render_widget(list, area);
                }
                TuiModal::FileBrowser => {
                    let area = centered_rect(78, 78, f.area());
                    f.render_widget(Clear, area);
                    let items: Vec<ListItem> = browser_items
                        .iter()
                        .enumerate()
                        .map(|(i, item)| {
                            let icon = if item.is_dir { format!("{SYM_FOLDER}") } else { format!("{SYM_FILE}") };
                            let prefix = if i == browser_idx { SYM_SEL.s() } else { "  " };
                            let style = if i == browser_idx {
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else if item.is_dir {
                                Style::default().fg(Color::LightCyan)
                            } else {
                                Style::default().fg(Color::White)
                            };
                            ListItem::new(Line::from(Span::styled(
                                format!("{}{} {}", prefix, icon, item.name),
                                style,
                            )))
                        })
                        .collect();
                    let mut list_state = ListState::default();
                    list_state.select(Some(browser_idx));
                    let list = List::new(items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .style(Style::default().bg(Color::Black))
                            .title(format!(
                                " {SYM_DIR} File & Folder Browser: {} ({SYM_UP}/{SYM_DOWN}, Enter=Select, Esc=Close) ",
                                clean_windows_path(&current_dir.to_string_lossy())
                            )),
                    );
                    f.render_stateful_widget(list, area, &mut list_state);
                }
            }
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match modal {
                    TuiModal::Help => match key.code {
                        KeyCode::Esc | KeyCode::F(1) | KeyCode::Enter => modal = TuiModal::None,
                        KeyCode::Down => help_scroll = help_scroll.saturating_add(1),
                        KeyCode::Up => help_scroll = help_scroll.saturating_sub(1),
                        KeyCode::PageDown => help_scroll = help_scroll.saturating_add(10),
                        KeyCode::PageUp => help_scroll = help_scroll.saturating_sub(10),
                        _ => {}
                    },
                    TuiModal::Intents => match key.code {
                        KeyCode::Esc | KeyCode::F(2) => modal = TuiModal::None,
                        KeyCode::Down => {
                            if !suggestions.is_empty() {
                                intent_idx = (intent_idx + 1) % suggestions.len();
                            }
                        }
                        KeyCode::Up => {
                            if !suggestions.is_empty() {
                                intent_idx = (intent_idx + suggestions.len() - 1) % suggestions.len();
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(chosen) = suggestions.get(intent_idx) {
                                sql_input = chosen.sql.clone();
                                modal = TuiModal::None;
                                match engine.query(&sql_input).await {
                                    Ok(batches) => {
                                        extract_grid(&batches, &mut headers, &mut table_rows);
                                        last_error = None;
                                        status_msg = format!(
                                            "Executed Intent `{}` -> {} rows",
                                            chosen.title,
                                            table_rows.len()
                                        );
                                    }
                                    Err(e) => {
                                        let helpful = format_helpful_error(
                                            &e.to_string(),
                                            Some(&active_source),
                                            &columns,
                                        );
                                        status_msg = format!("SQL Error: {}", helpful.lines().next().unwrap_or(""));
                                        last_error = Some(helpful);
                                    }
                                }
                            }
                        }
                        _ => {}
                    },
                    TuiModal::FileBrowser => match key.code {
                        KeyCode::Esc | KeyCode::F(3) => modal = TuiModal::None,
                        KeyCode::Down => {
                            if !browser_items.is_empty() {
                                browser_idx = (browser_idx + 1) % browser_items.len();
                            }
                        }
                        KeyCode::Up => {
                            if !browser_items.is_empty() {
                                browser_idx =
                                    (browser_idx + browser_items.len() - 1) % browser_items.len();
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(chosen) = browser_items.get(browser_idx) {
                                if chosen.is_dir && !chosen.path.contains('*') {
                                    current_dir = PathBuf::from(clean_windows_path(&chosen.path));
                                    browser_items = scan_directory(&current_dir);
                                    browser_idx = 0;
                                } else {
                                    let new_source = clean_windows_path(&chosen.path);
                                    let new_engine = LogEngine::new();
                                    match new_engine
                                        .register_source("logs", &new_source, InputFormat::Auto, None)
                                        .await
                                    {
                                        Ok(fmt) => {
                                            engine = new_engine;
                                            active_source = new_source;
                                            active_format = InputFormat::Auto;
                                            detected_fmt = fmt;
                                            columns = engine.table_columns("logs").await;
                                            suggestions =
                                                generate_intent_suggestions(detected_fmt, &columns);
                                            intent_idx = 0;
                                            if !suggestions.is_empty() {
                                                sql_input = suggestions[0].sql.clone();
                                            } else {
                                                sql_input = "SELECT * FROM logs LIMIT 50".to_string();
                                            }
                                            match engine.query(&sql_input).await {
                                                Ok(batches) => {
                                                    extract_grid(&batches, &mut headers, &mut table_rows);
                                                    last_error = None;
                                                }
                                                Err(e) => {
                                                    last_error = Some(format_helpful_error(
                                                        &e.to_string(),
                                                        Some(&active_source),
                                                        &columns,
                                                    ));
                                                }
                                            }
                                            status_msg = format!(
                                                "Loaded `{}` ({:?}) | {} rows",
                                                active_source,
                                                detected_fmt,
                                                table_rows.len()
                                            );
                                            modal = TuiModal::None;
                                        }
                                        Err(e) => {
                                            let helpful = format_helpful_error(
                                                &e.to_string(),
                                                Some(&new_source),
                                                &[],
                                            );
                                            status_msg = format!(
                                                "Failed to load file: {}",
                                                helpful.lines().next().unwrap_or("")
                                            );
                                            last_error = Some(helpful);
                                            modal = TuiModal::None;
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    },
                    TuiModal::None => match key.code {
                        KeyCode::Esc => break,
                        KeyCode::F(1) => {
                            help_scroll = 0;
                            modal = TuiModal::Help;
                        }
                        KeyCode::F(2) => modal = TuiModal::Intents,
                        KeyCode::F(3) => {
                            browser_items = scan_directory(&current_dir);
                            browser_idx = 0;
                            modal = TuiModal::FileBrowser;
                        }
                        KeyCode::Char('o')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            browser_items = scan_directory(&current_dir);
                            browser_idx = 0;
                            modal = TuiModal::FileBrowser;
                        }
                        KeyCode::Tab => {
                            apply_tab_autocomplete(
                                &mut sql_input,
                                &columns,
                                &mut last_tab_prefix,
                                &mut tab_cycle_idx,
                            );
                        }
                        KeyCode::Enter => {
                            let (rewritten_sql, extracted_path) = extract_source_from_sql(&sql_input);
                            if let Some(raw_new_path) = extracted_path {
                                let new_path = clean_windows_path(&raw_new_path);
                                if new_path != active_source {
                                    let new_engine = LogEngine::new();
                                    match new_engine
                                        .register_source("logs", &new_path, active_format, None)
                                        .await
                                    {
                                        Ok(fmt) => {
                                            engine = new_engine;
                                            active_source = new_path;
                                            detected_fmt = fmt;
                                            columns = engine.table_columns("logs").await;
                                            suggestions =
                                                generate_intent_suggestions(detected_fmt, &columns);
                                        }
                                        Err(e) => {
                                            let helpful = format_helpful_error(
                                                &e.to_string(),
                                                Some(&new_path),
                                                &columns,
                                            );
                                            status_msg = format!(
                                                "Source Error: {}",
                                                helpful.lines().next().unwrap_or("")
                                            );
                                            last_error = Some(helpful);
                                            continue;
                                        }
                                    }
                                }
                            }
                            match engine.query(&rewritten_sql).await {
                                Ok(batches) => {
                                    extract_grid(&batches, &mut headers, &mut table_rows);
                                    last_error = None;
                                    status_msg = format!(
                                        "Returned {} rows | F1=Help | F2=Intents | F3=Browse Files",
                                        table_rows.len()
                                    );
                                }
                                Err(e) => {
                                    let helpful = format_helpful_error(
                                        &e.to_string(),
                                        Some(&active_source),
                                        &columns,
                                    );
                                    status_msg = format!(
                                        "SQL Error: {}",
                                        helpful.lines().next().unwrap_or("")
                                    );
                                    last_error = Some(helpful);
                                }
                            }
                        }
                        KeyCode::Backspace => {
                            sql_input.pop();
                            last_tab_prefix.clear();
                        }
                        KeyCode::Char('u')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            sql_input.clear();
                            last_tab_prefix.clear();
                        }
                        KeyCode::Char(c) => {
                            sql_input.push(c);
                            last_tab_prefix.clear();
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn compute_inline_completion(sql: &str, columns: &[String]) -> Option<String> {
    let word = sql
        .rsplit(|c: char| c.is_whitespace() || c == '(' || c == ',')
        .next()
        .unwrap_or("");
    if word.is_empty() {
        return None;
    }
    let lower = word.to_lowercase();
    for col in columns {
        if col.to_lowercase().starts_with(&lower) && col.len() > word.len() {
            return Some(col.clone());
        }
    }
    for &kw in STATIC_COMPLETIONS {
        if kw.to_lowercase().starts_with(&lower) && kw.len() > word.len() {
            return Some(kw.to_string());
        }
    }
    None
}

fn apply_tab_autocomplete(
    sql_input: &mut String,
    columns: &[String],
    last_prefix: &mut String,
    cycle_idx: &mut usize,
) {
    let split_pos = sql_input
        .rfind(|c: char| c.is_whitespace() || c == '(' || c == ',')
        .map(|i| i + 1)
        .unwrap_or(0);
    let current_token = &sql_input[split_pos..];

    let prefix = if !last_prefix.is_empty() {
        last_prefix.clone()
    } else {
        let p = current_token.to_string();
        *last_prefix = p.clone();
        *cycle_idx = 0;
        p
    };

    let lower = prefix.to_lowercase();
    let mut matches: Vec<String> = Vec::new();
    for col in columns {
        if lower.is_empty() || col.to_lowercase().starts_with(&lower) {
            matches.push(col.clone());
        }
    }
    for &kw in STATIC_COMPLETIONS {
        if lower.is_empty() || kw.to_lowercase().starts_with(&lower) {
            matches.push(kw.to_string());
        }
    }

    if matches.is_empty() {
        return;
    }
    let chosen = &matches[*cycle_idx % matches.len()];
    *cycle_idx += 1;
    sql_input.truncate(split_pos);
    sql_input.push_str(chosen);
}

fn scan_directory(dir: &Path) -> Vec<BrowserItem> {
    let mut items = Vec::new();
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let clean_dir = clean_windows_path(&canonical.to_string_lossy());
    if let Some(parent) = canonical.parent() {
        items.push(BrowserItem {
            name: ".. (Parent Directory)".to_string(),
            path: clean_windows_path(&parent.to_string_lossy()),
            is_dir: true,
        });
    }
    let sep = std::path::MAIN_SEPARATOR;
    let glob_log_str = format!("{}{}*.log", clean_dir.trim_end_matches(sep), sep);
    items.push(BrowserItem {
        name: format!("{SYM_SPARK} Query all *.log files in this folder ({})", glob_log_str),
        path: glob_log_str,
        is_dir: false,
    });
    let glob_csv_str = format!("{}{}*.csv", clean_dir.trim_end_matches(sep), sep);
    items.push(BrowserItem {
        name: format!("{SYM_CHART} Query all *.csv files in this folder ({})", glob_csv_str),
        path: glob_csv_str,
        is_dir: false,
    });

    if let Ok(entries) = std::fs::read_dir(&canonical) {
        let mut sub_items = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let is_dir = path.is_dir();
            if is_dir || is_supported_log_or_data_file(&path) {
                sub_items.push(BrowserItem {
                    name,
                    path: clean_windows_path(&path.to_string_lossy()),
                    is_dir,
                });
            }
        }
        sub_items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        });
        items.extend(sub_items);
    }
    items
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn extract_grid(
    batches: &[arrow::record_batch::RecordBatch],
    headers: &mut Vec<String>,
    rows: &mut Vec<Vec<String>>,
) {
    headers.clear();
    rows.clear();
    if let Some(first) = batches.first() {
        *headers = first
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        for batch in batches {
            for r in 0..batch.num_rows() {
                let mut row_vec = Vec::new();
                for c in 0..batch.num_columns() {
                    let val = array_value_to_string(batch.column(c), r).unwrap_or_default();
                    row_vec.push(val);
                }
                rows.push(row_vec);
            }
        }
    }
}
