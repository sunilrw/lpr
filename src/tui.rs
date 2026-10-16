use crate::engine::{extract_source_from_sql, generate_intent_suggestions, IntentSuggestion, LogEngine};
use crate::parsers::InputFormat;
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
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap},
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
    let mut active_source = initial_source.to_string();
    let mut active_format = format;
    let mut detected_fmt = InputFormat::Auto;
    let mut columns: Vec<String> = Vec::new();
    let mut suggestions: Vec<IntentSuggestion> = Vec::new();

    if Path::new(&active_source).is_file() || active_source.contains('*') {
        if let Ok(fmt) = engine.register_source("logs", &active_source, active_format, None).await {
            detected_fmt = fmt;
            columns = engine.table_columns("logs").await;
            suggestions = generate_intent_suggestions(detected_fmt, &columns);
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

    if let Ok(batches) = engine.query(&sql_input).await {
        extract_grid(&batches, &mut headers, &mut table_rows);
    }

    let mut modal = if Path::new(&active_source).is_dir() {
        TuiModal::FileBrowser
    } else {
        TuiModal::None
    };

    let mut intent_idx: usize = 0;
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
                    " 🛡️ lpr Studio TUI v1.1.0 ",
                    Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("📁 {} ({:?}) ", active_source, detected_fmt),
                    Style::default().fg(Color::LightCyan),
                ),
                Span::styled(
                    format!("| 📋 Columns: {} ", columns.join(", ")),
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

            let status_bar = Paragraph::new(status_msg.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Status & Shortcuts "));
            f.render_widget(status_bar, chunks[3]);

            match modal {
                TuiModal::None => {}
                TuiModal::Help => {
                    let area = centered_rect(82, 82, f.area());
                    f.render_widget(Clear, area);
                    let help_text = vec![
                        Line::from(Span::styled(
                            "📚 LPR TUI & SQL COMPLETE REFERENCE MANUAL",
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        )),
                        Line::from(""),
                        Line::from("⌨️  KEYBOARD SHORTCUTS:"),
                        Line::from("  • Enter       Execute current SQL query"),
                        Line::from("  • Tab         Context-aware auto-completion (schema columns, SQL keywords, UDFs)"),
                        Line::from("  • F1          Toggle this Full Help & UDF Reference Manual"),
                        Line::from("  • F2          Open Context-Aware Intent Query Picker (tailored to active file)"),
                        Line::from("  • F3          Open Interactive File & Directory Browser (select file or *.log)"),
                        Line::from("  • Ctrl+U      Clear SQL query input"),
                        Line::from("  • Esc         Close active modal or exit TUI"),
                        Line::from(""),
                        Line::from("🛡️  CYBERSECURITY & LOG PARSER 2.2 SQL UDFs:"),
                        Line::from("  • detect_threat(col)             Detects SQLi, XSS, LFI, RCE/Log4Shell, SSRF"),
                        Line::from("  • ip_in_cidr(ip, '10.0.0.0/8')   IPv4/IPv6 CIDR subnet containment"),
                        Line::from("  • shannon_entropy(col)           0.0-8.0 entropy score for base64/DGA anomalies"),
                        Line::from("  • mask_pii(col)                  Redacts emails to [REDACTED_EMAIL]"),
                        Line::from("  • cluster_template(col)          Drain clustering: replaces IPs/IDs/nums with <*>"),
                        Line::from("  • url_decode(col) / parse_ua(c)  URL percent-decode & User-Agent classification"),
                        Line::from("  • extract_token(s, idx, delim)   [LogParser 2.2] 0-based token split"),
                        Line::from("  • extract_extension(path)        [LogParser 2.2] Lowercase file extension (.aspx)"),
                        Line::from("  • to_timestamp(date, time)       [LogParser 2.2] Combine W3C date & time"),
                        Line::from("  • index_of(str, substr)          [LogParser 2.2] 0-based substring index"),
                        Line::from(""),
                        Line::from("💡 MICROSOFT LOG PARSER 2.2 COMPATIBILITY:"),
                        Line::from("  • Query files directly in SQL:   SELECT * FROM 'samples/iis/u_extend01.log' WHERE sc-status LIKE '5%'"),
                        Line::from("  • Hyphenated & TOP N syntax:     SELECT TOP 10 cs-uri-stem, [time-taken] FROM logs"),
                    ];
                    let p = Paragraph::new(help_text)
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .style(Style::default().bg(Color::Black))
                                .title(" Full Help Manual (Press Esc or F1 to close) "),
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
                            let prefix = if i == intent_idx { "▶ " } else { "  " };
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
                            .title(" 🧠 Context-Aware Intent Queries (↑/↓ to select, Enter to run, Esc to close) "),
                    );
                    f.render_widget(list, area);
                }
                TuiModal::FileBrowser => {
                    let area = centered_rect(75, 75, f.area());
                    f.render_widget(Clear, area);
                    let items: Vec<ListItem> = browser_items
                        .iter()
                        .enumerate()
                        .map(|(i, item)| {
                            let icon = if item.is_dir { "📁" } else { "📄" };
                            let prefix = if i == browser_idx { "▶ " } else { "  " };
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
                    let list = List::new(items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .style(Style::default().bg(Color::Black))
                            .title(format!(
                                " 📂 File & Folder Browser: {} (↑/↓, Enter=Select, Esc=Close) ",
                                current_dir.to_string_lossy()
                            )),
                    );
                    f.render_widget(list, area);
                }
            }
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match modal {
                    TuiModal::Help => match key.code {
                        KeyCode::Esc | KeyCode::F(1) | KeyCode::Enter => modal = TuiModal::None,
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
                                        status_msg = format!(
                                            "Executed Intent `{}` -> {} rows",
                                            chosen.title,
                                            table_rows.len()
                                        );
                                    }
                                    Err(e) => status_msg = format!("SQL Error: {}", e),
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
                                if chosen.is_dir && !chosen.path.ends_with("*.log") {
                                    current_dir = PathBuf::from(&chosen.path);
                                    browser_items = scan_directory(&current_dir);
                                    browser_idx = 0;
                                } else {
                                    let new_source = chosen.path.clone();
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
                                            if let Ok(batches) = engine.query(&sql_input).await {
                                                extract_grid(&batches, &mut headers, &mut table_rows);
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
                                            status_msg = format!("Failed to load file: {}", e);
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
                        KeyCode::F(1) => modal = TuiModal::Help,
                        KeyCode::F(2) => modal = TuiModal::Intents,
                        KeyCode::F(3) => {
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
                            if let Some(new_path) = extracted_path {
                                if new_path != active_source {
                                    let new_engine = LogEngine::new();
                                    if let Ok(fmt) = new_engine
                                        .register_source("logs", &new_path, active_format, None)
                                        .await
                                    {
                                        engine = new_engine;
                                        active_source = new_path;
                                        detected_fmt = fmt;
                                        columns = engine.table_columns("logs").await;
                                        suggestions =
                                            generate_intent_suggestions(detected_fmt, &columns);
                                    }
                                }
                            }
                            match engine.query(&rewritten_sql).await {
                                Ok(batches) => {
                                    extract_grid(&batches, &mut headers, &mut table_rows);
                                    status_msg = format!(
                                        "Returned {} rows | F1=Help | F2=Intents | F3=Browse Files",
                                        table_rows.len()
                                    );
                                }
                                Err(e) => {
                                    status_msg = format!("SQL Error: {}", e);
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
    if let Some(parent) = canonical.parent() {
        items.push(BrowserItem {
            name: ".. (Parent Directory)".to_string(),
            path: parent.to_string_lossy().to_string(),
            is_dir: true,
        });
    }
    let sep = std::path::MAIN_SEPARATOR;
    let glob_str = format!(
        "{}{}*.log",
        canonical.to_string_lossy().trim_end_matches(sep),
        sep
    );
    items.push(BrowserItem {
        name: format!("✨ Query all *.log files in this folder ({})", glob_str),
        path: glob_str,
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
            sub_items.push(BrowserItem {
                name,
                path: path.to_string_lossy().to_string(),
                is_dir,
            });
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
