use crate::sym::*;
use crate::engine::LogEngine;
use crate::parsers::{
    extract_sql_pre_filter, filter_items_by_datetime, filter_items_by_min_date,
    keep_latest_log_item, resolve_source_items_with_cutoff, InputFormat, ScanPreFilter,
};
use crate::sinks::batches_to_json_value;
use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Persistent configuration store (`lpr.config.json`) supporting named profiles and command history.
/// Zero hardcoded client names, paths, or servers — users save their own profiles once via `--save-profile <name>`
/// and reuse them anytime via `--profile <name>`. Also stores up to 100 recently executed CLI commands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LprConfigFile {
    #[serde(default = "default_profile_name")]
    pub default_profile: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, SavedProfile>,
    #[serde(default)]
    pub command_history: Vec<CommandHistoryEntry>,
}

pub const MAX_COMMAND_HISTORY: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandHistoryEntry {
    pub timestamp: String,
    pub cwd: String,
    pub args: Vec<String>,
    pub command_line: String,
}

fn default_profile_name() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedProfile {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub threads: Option<usize>,
    #[serde(default)]
    pub days: Option<i64>,
    #[serde(default)]
    pub site_name: Option<String>,
    /// Optional report filename prefix (e.g. "IIS-500Errors" or any custom label)
    #[serde(default)]
    pub report_prefix: Option<String>,
    #[serde(default)]
    pub status_prefix: Option<String>,
    #[serde(default)]
    pub output_dir: Option<String>,
    /// Path to a CSV/JSON server inventory file (e.g. "servers.csv")
    #[serde(default)]
    pub servers_file: Option<String>,
    /// Hostname pattern for numbered servers when no CSV is used (e.g. "web-prod-{02}" or "app-{n}")
    #[serde(default)]
    pub host_pattern: Option<String>,
    /// Remote or local log path templates (supports `{server}`, `{ip}`, `{site}` or automatic `D:\...` -> `\\{server}\d$\...` conversion)
    #[serde(default)]
    pub path_templates: Vec<String>,
    /// Auto-discover the IIS site's log directory from `applicationHost.config` or Linux Nginx/Apache/Caddy/HAProxy/Tomcat configs
    #[serde(default)]
    pub iis_auto_discover: Option<bool>,
    /// Server / web stack type (`auto`, `iis`, `nginx`, `apache`, `caddy`, `haproxy`, `tomcat`, `alb`)
    #[serde(default)]
    pub server_type: Option<String>,
    /// Use SSH to stream and scan logs from remote Linux/Unix web servers
    #[serde(default)]
    pub ssh_enabled: Option<bool>,
    #[serde(default)]
    pub ssh_user: Option<String>,
    #[serde(default)]
    pub ssh_key: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub server_filter: Option<String>,
    #[serde(default)]
    pub server_numbers: Option<String>,
    #[serde(default)]
    pub local_path: Option<String>,
    /// Rolling hour window for fleet scans (overrides `days` when set)
    #[serde(default)]
    pub hours: Option<i64>,
    /// Scan only the newest (currently active) log file per server
    #[serde(default)]
    pub latest_only: Option<bool>,
    /// Default SQL query or input/output format for general `lpr` CLI runs using this profile
    #[serde(default)]
    pub default_sql: Option<String>,
    #[serde(default)]
    pub input_format: Option<String>,
    #[serde(default)]
    pub output_format: Option<String>,
    #[serde(default)]
    pub verbose: Option<bool>,
    /// Alternate credential username for remote SMB shares (combined with auth_domain)
    #[serde(default)]
    pub auth_user: Option<String>,
    #[serde(default)]
    pub auth_domain: Option<String>,
    /// Secret reference — `env:VAR_NAME`, `file:PATH`, or `prompt` (asks at scan time, never stored)
    #[serde(default)]
    pub auth_password_ref: Option<String>,
    /// DPAPI-encrypted password blob (hex). Only decryptable by the same Windows user account on this machine.
    #[serde(default)]
    pub auth_password_enc: Option<String>,
    /// Inline server list saved directly inside the profile
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
    /// Deterministically learned session/cookie/query/IP intelligence for cross-server journey reconstruction
    #[serde(default)]
    pub session_intelligence: Option<SessionIntelligence>,
}

/// Deterministic, non-AI correlation intelligence learned from scanning a server's W3C/web logs
/// and stored in `lpr.config.json` for fast cross-server user journey reconstruction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionIntelligence {
    pub learned_at_utc: String,
    pub sample_rows_analyzed: usize,
    pub detected_columns: Vec<String>,
    /// High-cardinality cookie names that identify a user, session, customer, visitor, or cart across requests
    pub identity_cookies: Vec<String>,
    /// Query-string parameter names (`cs-uri-query`) that carry customer, order, payment, cart, or session IDs
    pub query_correlators: Vec<String>,
    /// Client IP columns in priority order (e.g. `x_forwarded_for`, `cf_connecting_ip`, `true_client_ip`, `c_ip`)
    pub client_ip_columns: Vec<String>,
    /// Response redirect header column if logged by IIS (`sclocation` / `sc_location` / `location`)
    pub redirect_location_column: Option<String>,
}

impl Default for SavedProfile {
    fn default() -> Self {
        Self {
            description: None,
            threads: None,
            days: Some(7),
            site_name: None,
            report_prefix: Some("IIS-Errors".to_string()),
            status_prefix: Some("5".to_string()),
            output_dir: Some("output".to_string()),
            servers_file: None,
            host_pattern: None,
            path_templates: Vec::new(),
            iis_auto_discover: Some(true),
            server_type: Some("auto".to_string()),
            ssh_enabled: None,
            ssh_user: None,
            ssh_key: None,
            ssh_port: None,
            server_filter: None,
            server_numbers: None,
            local_path: None,
            hours: None,
            latest_only: None,
            default_sql: None,
            input_format: None,
            output_format: None,
            verbose: None,
            auth_user: None,
            auth_domain: None,
            auth_password_ref: None,
            auth_password_enc: None,
            servers: Vec::new(),
            session_intelligence: None,
        }
    }
}

impl LprConfigFile {
    pub fn resolve_config_path(explicit: Option<&str>) -> PathBuf {
        if let Some(p) = explicit.filter(|s| !s.trim().is_empty()) {
            return PathBuf::from(p);
        }
        let local = PathBuf::from("lpr.config.json");
        if local.exists() {
            return local;
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let beside_exe = dir.join("lpr.config.json");
                if beside_exe.exists() {
                    return beside_exe;
                }
            }
        }
        local
    }

    pub fn load(explicit: Option<&str>) -> Self {
        let path = Self::resolve_config_path(explicit);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<Self>(&content) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self, explicit: Option<&str>) -> Result<PathBuf> {
        let path = Self::resolve_config_path(explicit);
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(path)
    }

    pub fn format_command_line(args: &[String]) -> String {
        let mut parts = Vec::with_capacity(args.len() + 1);
        parts.push("lpr".to_string());
        for a in args {
            if a.contains(' ') || a.contains('\t') || a.contains('"') || a.contains('\'') || a.contains('*') {
                let escaped = a.replace('"', "\\\"");
                parts.push(format!("\"{}\"", escaped));
            } else {
                parts.push(a.clone());
            }
        }
        parts.join(" ")
    }

    pub fn record_command_execution(explicit: Option<&str>, args_without_bin: &[String]) {
        if args_without_bin.is_empty() {
            return;
        }
        let mut store = Self::load(explicit);
        let cmd_line = Self::format_command_line(args_without_bin);
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| ".".to_string());
        let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        // Keep only unique commands: remove any existing entry with the exact same args/command_line
        // so the newly executed one replaces it at the latest position.
        store
            .command_history
            .retain(|entry| entry.args != args_without_bin && entry.command_line != cmd_line);

        store.command_history.push(CommandHistoryEntry {
            timestamp: ts,
            cwd,
            args: args_without_bin.to_vec(),
            command_line: cmd_line,
        });

        // Cap at MAX_COMMAND_HISTORY (100): evict the oldest command(s) when over 100
        if store.command_history.len() > MAX_COMMAND_HISTORY {
            let excess = store.command_history.len() - MAX_COMMAND_HISTORY;
            store.command_history.drain(0..excess);
        }

        let _ = store.save(explicit);
    }
}

#[derive(Debug, Clone)]
pub struct FleetScanConfig {
    pub cfg_file_path: Option<String>,
    pub profile_name: Option<String>,
    pub save_profile_name: Option<String>,
    pub list_profiles: bool,
    pub days: Option<i64>,
    pub site_name: Option<String>,
    pub report_prefix: Option<String>,
    pub servers_csv: Option<String>,
    pub config_json: Option<String>,
    pub host_pattern: Option<String>,
    pub path_template: Option<String>,
    pub log_path: Option<String>,
    pub archive_path: Option<String>,
    pub iis_auto: bool,
    pub server_type: Option<String>,
    pub ssh_enabled: bool,
    pub ssh_user: Option<String>,
    pub ssh_key: Option<String>,
    pub ssh_port: Option<u16>,
    pub auth_user: Option<String>,
    pub auth_domain: Option<String>,
    pub password_ref: Option<String>,
    pub save_password: bool,
    pub output_dir: Option<String>,
    pub server_filter: Option<String>,
    pub server_numbers: Option<String>,
    pub local_path: Option<String>,
    pub status_prefix: Option<String>,
    pub contains_pattern: Option<String>,
    pub custom_sql: Option<String>,
    pub hours: Option<i64>,
    pub latest_only: bool,
    pub learn_intelligence: bool,
    pub trace_journeys: bool,
    pub trace_id: Option<String>,
    pub trace_window_mins: i64,
    pub max_journeys: usize,
    pub threads: Option<usize>,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub ip: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FleetErrorRow {
    #[serde(rename = "ServerName")]
    pub server_name: String,
    #[serde(rename = "ServerIP")]
    pub server_ip: String,
    #[serde(rename = "Date")]
    pub date: String,
    #[serde(rename = "Time")]
    pub time: String,
    #[serde(rename = "ClientIP")]
    pub client_ip: String,
    #[serde(rename = "Method")]
    pub method: String,
    #[serde(rename = "UriStem")]
    pub uri_stem: String,
    #[serde(rename = "UriQuery")]
    pub uri_query: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "SubStatus")]
    pub sub_status: String,
    #[serde(rename = "Win32Status")]
    pub win32_status: String,
    #[serde(rename = "TimeTakenMs")]
    pub time_taken_ms: String,
    #[serde(rename = "UserAgent")]
    pub user_agent: String,
    #[serde(rename = "Referer")]
    pub referer: String,
    #[serde(rename = "LogFile")]
    pub log_file: String,
    #[serde(rename = "LogRow")]
    pub log_row: String,
    #[serde(skip_serializing)]
    pub forwarded_ip: String,
    #[serde(skip_serializing)]
    pub cookie: String,
    #[serde(skip_serializing)]
    pub redirect_location: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FleetServerSummary {
    #[serde(rename = "ServerName")]
    pub server_name: String,
    #[serde(rename = "ServerIP")]
    pub server_ip: String,
    #[serde(rename = "Success")]
    pub success: bool,
    #[serde(rename = "TotalErrors")]
    pub total_errors: usize,
    #[serde(rename = "LogFilesScanned")]
    pub log_files_scanned: usize,
    #[serde(rename = "LogFilesTotal")]
    pub log_files_total: usize,
    #[serde(rename = "LinesScanned")]
    pub lines_scanned: usize,
    #[serde(rename = "BytesScanned")]
    pub bytes_scanned: u64,
    #[serde(rename = "ElapsedSeconds")]
    pub elapsed_seconds: String,
    #[serde(rename = "Engine")]
    pub engine: String,
    #[serde(rename = "FirstError")]
    pub first_error: String,
    #[serde(rename = "LastError")]
    pub last_error: String,
    #[serde(rename = "ScannedPaths")]
    pub scanned_paths: String,
    #[serde(rename = "ErrorMessage")]
    pub error_message: String,
}

pub fn print_saved_profiles(cfg_file_path: Option<&str>) {
    let path = LprConfigFile::resolve_config_path(cfg_file_path);
    let store = LprConfigFile::load(cfg_file_path);
    println!("================================================================================");
    println!(" {SYM_GEAR}  LPR SAVED CONFIGURATION PROFILES ({})", path.to_string_lossy());
    println!("================================================================================");
    if store.profiles.is_empty() {
        println!("  No profiles saved yet.");
        println!("  {SYM_TIP} Save a profile once with:");
        println!("     lpr fleet --save-profile prod-web --servers servers.csv --site MySite --threads 8 --days 7");
        println!("  {SYM_TIP} Then run anytime with:");
        println!("     lpr fleet --profile prod-web");
        println!("     lpr fleet --profile prod-web --server-numbers \"1-12\"");
        return;
    }
    for (name, p) in &store.profiles {
        let is_def = if name == &store.default_profile {
            " (DEFAULT)"
        } else {
            ""
        };
        println!("\n  {SYM_BULLET} Profile: `{}`{}", name, is_def);
        if let Some(ref d) = p.description {
            println!("     Description    : {}", d);
        }
        println!(
            "     Threads        : {:?} | Days: {:?} | Status Prefix: {:?}",
            p.threads, p.days, p.status_prefix
        );
        println!(
            "     Site Name      : {:?} | Report Prefix: {:?} | Output Dir: {:?}",
            p.site_name, p.report_prefix, p.output_dir
        );
        println!(
            "     Servers Source : CSV={:?} | HostPattern={:?} | InlineServers={}",
            p.servers_file,
            p.host_pattern,
            p.servers.len()
        );
        if !p.path_templates.is_empty() {
            println!("     Path Templates : {}", p.path_templates.join(" ; "));
        }
        if p.local_path.is_some() {
            println!("     Local Path     : {:?}", p.local_path);
        }
        if let Some(ref u) = p.auth_user {
            let secret_mode = if p.auth_password_enc.is_some() {
                "DPAPI-encrypted blob"
            } else if let Some(ref r) = p.auth_password_ref {
                r.as_str()
            } else {
                "none"
            };
            println!(
                "     SMB Auth       : user={:?} domain={:?} secret=[{}]",
                u, p.auth_domain, secret_mode
            );
        }
        if let Some(ref intel) = p.session_intelligence {
            println!(
                "     Session Intel  : Learned={} ({} rows) | Cookies={:?} | QueryKeys={:?} | IPCols={:?} | RedirectCol={:?}",
                intel.learned_at_utc,
                intel.sample_rows_analyzed,
                intel.identity_cookies,
                intel.query_correlators,
                intel.client_ip_columns,
                intel.redirect_location_column
            );
        }
    }
    if !store.command_history.is_empty() {
        println!("\n  {SYM_TIP} Saved Command History: {} unique command(s) in `{}`", store.command_history.len(), path.to_string_lossy());
        println!("     • List all:      lpr history");
        println!("     • Rerun #N:      lpr --rerun 1   (or `lpr history 33`)");
        println!("     • Arrow Browse:  lpr history -i  (Up/Down arrows + Enter to run)");
    }
    println!();
}

pub fn print_command_history(cfg_file_path: Option<&str>, filter: Option<&str>) {
    let path = LprConfigFile::resolve_config_path(cfg_file_path);
    let store = LprConfigFile::load(cfg_file_path);
    println!("================================================================================");
    println!(
        " {SYM_LIST} LPR SAVED COMMAND HISTORY ({} / max {} unique commands in `{}`)",
        store.command_history.len(),
        MAX_COMMAND_HISTORY,
        path.to_string_lossy()
    );
    println!("================================================================================");
    if store.command_history.is_empty() {
        println!("  No commands saved in history yet.");
        println!("  Every command you run is automatically saved here (up to 100 unique commands).");
        return;
    }

    let needle = filter.map(|s| s.to_lowercase());
    for (idx, entry) in store.command_history.iter().enumerate() {
        let num = idx + 1;
        if let Some(ref pat) = needle {
            if !entry.command_line.to_lowercase().contains(pat)
                && !entry.cwd.to_lowercase().contains(pat)
            {
                continue;
            }
        }
        println!(
            "  [{:>3}] {}  ({} | dir: {})",
            num, entry.command_line, entry.timestamp, entry.cwd
        );
    }
    println!("--------------------------------------------------------------------------------");
    println!(" {SYM_TIP} Rerun by number : `lpr --rerun 33`  or  `lpr history 33`  or  `lpr !33`");
    println!(" {SYM_TIP} Rerun last      : `lpr --rerun last` or  `lpr !!`");
    println!(" {SYM_TIP} DOS Up/Down UI  : `lpr history -i`  (browse with ↑/↓ arrows, Enter to execute)");
    println!("================================================================================");
}

/// Interactive DOS-style Up/Down arrow command browser in the terminal.
/// Returns `Ok(Some(args))` if the user pressed Enter on a command to execute it.
pub fn browse_command_history_interactive(cfg_file_path: Option<&str>) -> Result<Option<Vec<String>>> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
        Terminal,
    };
    use std::io;

    let path = LprConfigFile::resolve_config_path(cfg_file_path);
    let mut store = LprConfigFile::load(cfg_file_path);
    if store.command_history.is_empty() {
        println!("No saved commands in `{}` yet.", path.to_string_lossy());
        return Ok(None);
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Start at the most recent command (bottom of list), just like DOSKEY / Up-Arrow!
    let mut selected: usize = store.command_history.len().saturating_sub(1);
    let mut filter_text = String::new();
    let mut chosen_args: Option<Vec<String>> = None;

    loop {
        let filtered_indices: Vec<usize> = store
            .command_history
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                filter_text.is_empty()
                    || e.command_line
                        .to_lowercase()
                        .contains(&filter_text.to_lowercase())
            })
            .map(|(i, _)| i)
            .collect();

        if !filtered_indices.is_empty() && selected >= filtered_indices.len() {
            selected = filtered_indices.len() - 1;
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(8),
                    Constraint::Length(5),
                ])
                .split(f.area());

            let header = Paragraph::new(Line::from(vec![
                Span::styled(
                    " LPR COMMAND HISTORY BROWSER ",
                    Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "  [↑/↓ or PgUp/PgDn] Browse  [Enter] Run Command  [Del] Remove  [Type] Filter: `{}`  [Esc] Cancel",
                    filter_text
                )),
            ]))
            .block(Block::default().borders(Borders::ALL).title(format!(
                " Config: {} ({}/{} unique commands) ",
                path.to_string_lossy(),
                store.command_history.len(),
                MAX_COMMAND_HISTORY
            )));
            f.render_widget(header, chunks[0]);

            let items: Vec<ListItem> = filtered_indices
                .iter()
                .map(|&orig_idx| {
                    let entry = &store.command_history[orig_idx];
                    let num = orig_idx + 1;
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!(" [{:>3}] ", num),
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(&entry.command_line, Style::default().fg(Color::White)),
                        Span::styled(
                            format!("   ({} | {})", entry.timestamp, entry.cwd),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                })
                .collect();

            let mut list_state = ListState::default();
            if !filtered_indices.is_empty() {
                list_state.select(Some(selected));
            }

            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Saved Commands (Oldest -> Newest; starts at Latest like DOS Up-Arrow) "),
                )
                .highlight_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▶ ");
            f.render_stateful_widget(list, chunks[1], &mut list_state);

            let detail_text = if let Some(&orig_idx) = filtered_indices.get(selected) {
                let entry = &store.command_history[orig_idx];
                vec![
                    Line::from(vec![
                        Span::styled(" Selected Command (#", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{}", orig_idx + 1),
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("): ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            &entry.command_line,
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(format!(
                        " Last Ran: {}   |   Folder: {}   |   Direct CLI Rerun: `lpr --rerun {}`",
                        entry.timestamp,
                        entry.cwd,
                        orig_idx + 1
                    )),
                ]
            } else {
                vec![Line::from(" No matching commands.")]
            };

            let footer = Paragraph::new(detail_text)
                .block(Block::default().borders(Borders::ALL).title(" Command Details (Press Enter to Execute Now) "));
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Up => {
                        if selected > 0 {
                            selected -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if selected + 1 < filtered_indices.len() {
                            selected += 1;
                        }
                    }
                    KeyCode::PageUp => {
                        selected = selected.saturating_sub(10);
                    }
                    KeyCode::PageDown => {
                        if !filtered_indices.is_empty() {
                            selected = (selected + 10).min(filtered_indices.len() - 1);
                        }
                    }
                    KeyCode::Home => {
                        selected = 0;
                    }
                    KeyCode::End => {
                        if !filtered_indices.is_empty() {
                            selected = filtered_indices.len() - 1;
                        }
                    }
                    KeyCode::Delete => {
                        if let Some(&orig_idx) = filtered_indices.get(selected) {
                            store.command_history.remove(orig_idx);
                            let _ = store.save(cfg_file_path);
                            if store.command_history.is_empty() {
                                break;
                            }
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(&orig_idx) = filtered_indices.get(selected) {
                            chosen_args = Some(store.command_history[orig_idx].args.clone());
                            break;
                        }
                    }
                    KeyCode::Backspace => {
                        filter_text.pop();
                    }
                    KeyCode::Char(c) => {
                        if c == 'q' && filter_text.is_empty() {
                            break;
                        }
                        filter_text.push(c);
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(chosen_args)
}

pub async fn run_fleet_scan(req: FleetScanConfig) -> Result<()> {
    if req.list_profiles {
        print_saved_profiles(req.cfg_file_path.as_deref());
        return Ok(());
    }

    let mut cfg_store = LprConfigFile::load(req.cfg_file_path.as_deref());
    let active_profile_name = req
        .profile_name
        .clone()
        .or_else(|| req.save_profile_name.clone())
        .unwrap_or_else(|| cfg_store.default_profile.clone());

    let mut profile = cfg_store
        .profiles
        .get(&active_profile_name)
        .cloned()
        .unwrap_or_default();

    // Merge any CLI arguments on top of the loaded profile
    if let Some(t) = req.threads {
        profile.threads = Some(t);
    }
    if let Some(d) = req.days {
        profile.days = Some(d);
    }
    if let Some(ref s) = req.site_name {
        profile.site_name = Some(s.clone());
    }
    if let Some(ref rp) = req.report_prefix {
        profile.report_prefix = Some(rp.clone());
    }
    if let Some(ref st) = req.status_prefix {
        profile.status_prefix = Some(st.clone());
    }
    if let Some(ref q) = req.custom_sql {
        profile.default_sql = Some(q.clone());
    }
    if let Some(h) = req.hours {
        profile.hours = Some(h);
    }
    if req.latest_only {
        profile.latest_only = Some(true);
    }
    if let Some(ref o) = req.output_dir {
        profile.output_dir = Some(o.clone());
    }
    if let Some(ref sc) = req.servers_csv {
        profile.servers_file = Some(sc.clone());
    }
    if let Some(ref cj) = req.config_json {
        profile.servers_file = Some(cj.clone());
    }
    if let Some(ref hp) = req.host_pattern {
        profile.host_pattern = Some(hp.clone());
    }
    if req.iis_auto {
        profile.iis_auto_discover = Some(true);
    }
    if let Some(ref st_type) = req.server_type {
        profile.server_type = Some(st_type.clone());
    }
    if req.ssh_enabled || req.ssh_user.is_some() || req.ssh_key.is_some() {
        profile.ssh_enabled = Some(true);
    }
    if let Some(ref su) = req.ssh_user {
        profile.ssh_user = Some(su.clone());
    }
    if let Some(ref sk) = req.ssh_key {
        profile.ssh_key = Some(sk.clone());
    }
    if let Some(sp) = req.ssh_port {
        profile.ssh_port = Some(sp);
    }
    let mut merged_templates = Vec::new();
    if let Some(ref lp) = req.log_path {
        for part in lp.split(';') {
            let t = part.trim();
            if !t.is_empty() {
                merged_templates.push(t.to_string());
            }
        }
    }
    if let Some(ref ap) = req.archive_path {
        for part in ap.split(';') {
            let t = part.trim();
            if !t.is_empty() {
                merged_templates.push(t.to_string());
            }
        }
    }
    if let Some(ref pt) = req.path_template {
        for part in pt.split(';') {
            let t = part.trim();
            if !t.is_empty() {
                merged_templates.push(t.to_string());
            }
        }
    }
    if !merged_templates.is_empty() {
        profile.path_templates = merged_templates;
    }
    if let Some(ref sf) = req.server_filter {
        profile.server_filter = Some(sf.clone());
    }
    if let Some(ref sn) = req.server_numbers {
        profile.server_numbers = Some(sn.clone());
    }
    if let Some(ref lp) = req.local_path {
        profile.local_path = Some(lp.clone());
    }
    if req.verbose {
        profile.verbose = Some(true);
    }
    if let Some(ref au) = req.auth_user {
        profile.auth_user = Some(au.clone());
    }
    if let Some(ref ad) = req.auth_domain {
        profile.auth_domain = Some(ad.clone());
    }
    if let Some(ref pr) = req.password_ref {
        let trimmed = pr.trim();
        let lower = trimmed.to_lowercase();
        if !(lower == "prompt" || lower.starts_with("env:") || lower.starts_with("file:")) {
            anyhow::bail!(
                "Invalid --password-ref `{}`: must be `env:VAR_NAME`, `file:PATH`, or `prompt` (plaintext passwords are never accepted on CLI or stored in config; use `--save-password` for DPAPI encryption)",
                trimmed
            );
        }
        profile.auth_password_ref = Some(trimmed.to_string());
    }
    if req.save_password {
        match prompt_and_encrypt_password() {
            Ok(hex_blob) => {
                profile.auth_password_enc = Some(hex_blob);
                eprintln!("{SYM_LOCK} Password stored DPAPI-encrypted (bound to this Windows user account only).");
            }
            Err(e) => {
                eprintln!(
                    "{SYM_WARN}  --save-password could not store a secret here ({e}). Use --password-ref env:LPR_SMB_PASS, --password-ref file:<path>, or --password-ref prompt instead."
                );
            }
        }
    }

    // If `--save-profile <name>` was passed, persist the merged profile (including imported servers list if a CSV/JSON was given)
    if let Some(ref save_name) = req.save_profile_name {
        if let Ok(loaded_srvs) = discover_raw_server_inventory(
            profile.servers_file.as_deref(),
            profile.host_pattern.as_deref(),
            &profile.servers,
        ) {
            if !loaded_srvs.is_empty() {
                profile.servers = loaded_srvs;
            }
        }
        cfg_store
            .profiles
            .insert(save_name.clone(), profile.clone());
        if cfg_store.profiles.len() == 1 {
            cfg_store.default_profile = save_name.clone();
        }
        let saved_path = cfg_store.save(req.cfg_file_path.as_deref())?;
        println!(
            "{SYM_SAVE} Saved profile `{}` to `{}` ({} servers stored in profile)",
            save_name,
            saved_path.to_string_lossy(),
            profile.servers.len()
        );
    }

    let days = profile.days.unwrap_or(7);
    let site_name = profile.site_name.clone().unwrap_or_default();
    let report_prefix = profile
        .report_prefix
        .clone()
        .unwrap_or_else(|| {
            if !site_name.is_empty() {
                format!("{}-{}00Errors", site_name, profile.status_prefix.as_deref().unwrap_or("5"))
            } else {
                format!("IIS-{}00Errors", profile.status_prefix.as_deref().unwrap_or("5"))
            }
        });
    let status_prefix = if req.trace_id.is_some() && req.status_prefix.is_none() {
        "*".to_string()
    } else {
        profile
            .status_prefix
            .clone()
            .unwrap_or_else(|| "5".to_string())
    };
    let custom_sql = profile.default_sql.clone();
    let output_dir = profile
        .output_dir
        .clone()
        .unwrap_or_else(|| "output".to_string());
    let server_filter = profile
        .server_filter
        .clone()
        .unwrap_or_else(|| "*".to_string());
    let server_numbers = profile.server_numbers.clone().unwrap_or_default();
    let threads = profile.threads;
    let verbose = profile.verbose.unwrap_or(req.verbose);

    let hours = profile.hours;
    let latest_only = profile.latest_only.unwrap_or(false);
    let (cutoff_date, cutoff_time): (String, Option<String>) = if let Some(h) = hours {
        let dt = Utc::now() - Duration::hours(h.max(0));
        (
            dt.format("%Y-%m-%d").to_string(),
            Some(dt.format("%H:%M:%S").to_string()),
        )
    } else {
        (
            (Utc::now() - Duration::days((days - 1).max(0)))
                .format("%Y-%m-%d")
                .to_string(),
            None,
        )
    };
    let run_stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();

    fs::create_dir_all(&output_dir)?;

    println!("================================================================================");
    println!(" {SYM_GLOBE} LPR MULTI-SERVER FLEET SCANNER (Profile: `{}`)", active_profile_name);
    println!(
        " {SYM_CAL} {} | {} | Threads: {}{}",
        if let Some(h) = hours {
            format!(
                "Hours: {} (Cutoff >= {} {})",
                h,
                cutoff_date,
                cutoff_time.as_deref().unwrap_or("")
            )
        } else {
            format!("Days: {} (Cutoff >= {})", days, cutoff_date)
        },
        if custom_sql.is_some() {
            "Mode: Custom SQL".to_string()
        } else {
            format!("Status: {}xx", status_prefix)
        },
        threads
            .map(|t| t.to_string())
            .unwrap_or_else(|| "Auto (All Cores)".to_string()),
        if latest_only { " | Latest file only" } else { "" }
    );
    println!(" {SYM_FOLDER} Output Folder: {} | Report Prefix: {}", output_dir, report_prefix);
    println!("================================================================================");

    let fleet_start = std::time::Instant::now();
    let trace_id_clean = req
        .trace_id
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let trace_active = req.trace_journeys || trace_id_clean.is_some();

    let mut base_pre_filter = if let Some(ref sql_q) = custom_sql {
        extract_sql_pre_filter(sql_q)
    } else {
        ScanPreFilter::default()
    };
    base_pre_filter.min_date = Some(cutoff_date.clone());
    base_pre_filter.min_time = cutoff_time.clone();
    // When tracing a specific Customer ID / Session / IP without --status, scan all statuses (200, 302, 500, etc.)
    if trace_id_clean.is_some() && req.status_prefix.is_none() && custom_sql.is_none() {
        base_pre_filter.status_prefix = None;
    } else if custom_sql.is_none() || req.status_prefix.is_some() {
        base_pre_filter.status_prefix = Some(status_prefix.clone());
    }
    if let Some(ref pat) = req.contains_pattern {
        let lower = pat.trim().to_ascii_lowercase();
        if !lower.is_empty() && !base_pre_filter.required_substrings.contains(&lower) {
            base_pre_filter.required_substrings.push(lower);
        }
    }
    if let Some(ref tid) = trace_id_clean {
        let lower = tid.to_ascii_lowercase();
        if !lower.is_empty() && !base_pre_filter.required_substrings.contains(&lower) {
            base_pre_filter.required_substrings.push(lower);
        }
    }

    if !base_pre_filter.required_substrings.is_empty()
        || !base_pre_filter.any_substrings.is_empty()
        || base_pre_filter.status_prefix.is_some()
    {
        println!(
            " {SYM_ZAP} Raw-Byte Pushdown : StatusPrefix={:?} | RequiredSubstrings={:?} | AnySubstrings={:?}",
            base_pre_filter.status_prefix,
            base_pre_filter.required_substrings,
            base_pre_filter.any_substrings
        );
    }

    if let Some(ref local_target) = profile.local_path.clone() {
        if req.learn_intelligence || (trace_active && profile.session_intelligence.is_none()) {
            let cutoff_naive = chrono::NaiveDate::parse_from_str(&cutoff_date, "%Y-%m-%d")
                .unwrap_or_else(|_| chrono::Utc::now().date_naive());
            if let Ok(sample_items) =
                resolve_source_items_with_cutoff(local_target, Some(cutoff_naive))
            {
                let sample_subset: Vec<_> = sample_items.into_iter().take(2).collect();
                if let Ok(intel) =
                    learn_session_intelligence_from_items(&sample_subset, threads).await
                {
                    print_session_intelligence_summary(&active_profile_name, &intel);
                    profile.session_intelligence = Some(intel);
                    cfg_store
                        .profiles
                        .insert(active_profile_name.clone(), profile.clone());
                    let _ = cfg_store.save(req.cfg_file_path.as_deref());
                }
            }
            if req.learn_intelligence && !trace_active {
                return Ok(());
            }
        }
        return run_local_or_archive_fleet_scan(
            local_target,
            &cutoff_date,
            cutoff_time.as_deref(),
            &run_stamp,
            &output_dir,
            &report_prefix,
            &status_prefix,
            days,
            threads,
            verbose,
            custom_sql.as_deref(),
            latest_only,
            &base_pre_filter,
            fleet_start,
            trace_active,
            trace_id_clean.as_deref(),
            req.trace_window_mins,
            req.max_journeys,
            profile.session_intelligence.as_ref(),
        )
        .await;
    }

    let servers = resolve_filtered_servers(
        profile.servers_file.as_deref(),
        profile.host_pattern.as_deref(),
        &profile.servers,
        &server_filter,
        &server_numbers,
    )?;

    if servers.is_empty() {
        anyhow::bail!(
            "No servers found or matched filter! Provide `--servers <servers.csv>`, `--host-pattern \"web-prod-{{02}}\" --server-numbers \"1-12\"`, `--local-path <dir_or_zip>`, or `--profile <saved_profile>`."
        );
    }

    let server_type = profile
        .server_type
        .clone()
        .unwrap_or_else(|| "auto".to_string())
        .to_lowercase();
    let ssh_enabled = profile.ssh_enabled.unwrap_or(false);
    let path_templates = if !profile.path_templates.is_empty() {
        profile.path_templates.clone()
    } else {
        default_path_templates_for_stack(&server_type, &site_name, ssh_enabled)
    };

    println!(
        " {SYM_SERVER}  Target Servers ({}) : {} | Stack: {} | Transport: {}",
        servers.len(),
        servers
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        server_type.to_uppercase(),
        if ssh_enabled { "SSH" } else { "SMB / Local" }
    );
    println!("--------------------------------------------------------------------------------");

    let mut all_errors: Vec<FleetErrorRow> = Vec::new();
    let mut summaries: Vec<FleetServerSummary> = Vec::new();
    let mut failed_servers: Vec<String> = Vec::new();
    let mut custom_cols: Vec<String> = Vec::new();
    let mut custom_rows: Vec<Vec<String>> = Vec::new();
    let mut resolved_server_sources: Vec<(
        ServerEntry,
        Vec<crate::parsers::LogSourceItem>,
        String,
        InputFormat,
    )> = Vec::new();
    let mut learned_during_scan = false;

    #[cfg(windows)]
    let resolved_smb_secret = if profile.auth_user.is_some() {
        resolve_secret(&profile)
    } else {
        None
    };

    for srv in &servers {
        let srv_start = std::time::Instant::now();
        // SSH Transport Mode for Linux / Unix Web Servers (Nginx, Apache, Caddy, HAProxy, Tomcat)
        if ssh_enabled {
            match scan_linux_server_via_ssh(
                srv,
                &profile,
                &path_templates,
                &site_name,
                &status_prefix,
                &cutoff_date,
                days,
                threads,
                verbose,
                custom_sql.as_deref(),
                hours,
                latest_only,
            )
            .await
            {
                Ok((rows, generic, files_count, scanned_info)) => {
                    let srv_secs = srv_start.elapsed().as_secs_f64();
                    let first_err = rows
                        .first()
                        .map(|r| format!("{} {}", r.date, r.time))
                        .unwrap_or_default();
                    let last_err = rows
                        .last()
                        .map(|r| format!("{} {}", r.date, r.time))
                        .unwrap_or_default();
                    let row_count = generic.as_ref().map(|g| g.1.len()).unwrap_or(rows.len());
                    println!(
                        "  {SYM_OK}  [SSH] {:14} ({:12}) -> {:>5} match(es) across {:>4} remote file(s) in {:.2}s",
                        srv.name,
                        srv.ip,
                        row_count,
                        files_count,
                        srv_secs
                    );
                    summaries.push(FleetServerSummary {
                        server_name: srv.name.clone(),
                        server_ip: srv.ip.clone(),
                        success: true,
                        total_errors: row_count,
                        log_files_scanned: files_count,
                        log_files_total: files_count,
                        lines_scanned: row_count,
                        bytes_scanned: 0,
                        elapsed_seconds: format!("{:.2}", srv_secs),
                        engine: "lpr-ssh-linux".to_string(),
                        first_error: first_err,
                        last_error: last_err,
                        scanned_paths: scanned_info,
                        error_message: String::new(),
                    });
                    if let Some((cols, grows)) = generic {
                        if custom_cols.is_empty() {
                            custom_cols = cols;
                        }
                        custom_rows.extend(grows);
                    }
                    all_errors.extend(rows);
                }
                Err(e) => {
                    let srv_secs = srv_start.elapsed().as_secs_f64();
                    println!(
                        "  {SYM_WARN}  [SSH] {:14} ({:12}) -> Failed in {:.2}s: {}",
                        srv.name, srv.ip, srv_secs, e
                    );
                    failed_servers.push(srv.name.clone());
                    summaries.push(FleetServerSummary {
                        server_name: srv.name.clone(),
                        server_ip: srv.ip.clone(),
                        success: false,
                        total_errors: 0,
                        log_files_scanned: 0,
                        log_files_total: 0,
                        lines_scanned: 0,
                        bytes_scanned: 0,
                        elapsed_seconds: format!("{:.2}", srv_secs),
                        engine: "lpr-ssh-linux".to_string(),
                        first_error: String::new(),
                        last_error: String::new(),
                        scanned_paths: String::new(),
                        error_message: e.to_string(),
                    });
                }
            }
            continue;
        }

        let mut existing_paths: Vec<String> = Vec::new();
        let mut tried_paths: Vec<String> = Vec::new();

        // If alternate SMB credentials are configured, establish a `net use` IPC$ session first (Windows only).
        #[cfg(windows)]
        let _smb_guard = establish_smb_session(srv, &profile, resolved_smb_secret.as_deref());

        // 1. Expand user-configured log_path / archive_path / path_templates (converting local D:\... to \\server\d$\... automatically!).
        // Avoid adding BOTH \\ServerName\... and \\ServerIP\... for the same template so we never scan the same server share twice!
        for tpl in &path_templates {
            let expanded = expand_remote_path_template(tpl, &srv.name, &srv.ip, &site_name);
            tried_paths.push(expanded.clone());
            if Path::new(&expanded).exists() {
                if !existing_paths.contains(&expanded) {
                    existing_paths.push(expanded);
                }
            } else if !srv.ip.is_empty() && srv.ip != srv.name {
                let expanded_ip = expand_remote_path_template(tpl, &srv.ip, &srv.ip, &site_name);
                tried_paths.push(expanded_ip.clone());
                if Path::new(&expanded_ip).exists() && !existing_paths.contains(&expanded_ip) {
                    existing_paths.push(expanded_ip);
                }
            }
        }

        // 2. Only probe IIS applicationHost.config / Linux vhost auto-discovery if no explicit path_templates matched (or --iis-auto was passed)
        if existing_paths.is_empty() && profile.iis_auto_discover.unwrap_or(true) {
            if !site_name.is_empty() {
                for host_target in [&srv.name, &srv.ip] {
                    if !host_target.is_empty() {
                        for discovered in
                            discover_iis_site_log_paths_on_server(host_target, &site_name)
                        {
                            tried_paths.push(discovered.clone());
                            if Path::new(&discovered).exists()
                                && !existing_paths.contains(&discovered)
                            {
                                existing_paths.push(discovered);
                            }
                        }
                        if !existing_paths.is_empty() {
                            break;
                        }
                    }
                }
            }
            if existing_paths.is_empty() {
                for discovered_linux in discover_local_linux_webserver_logs(&site_name) {
                    if Path::new(&discovered_linux).exists()
                        && !existing_paths.contains(&discovered_linux)
                    {
                        existing_paths.push(discovered_linux);
                    }
                }
            }
        }

        if existing_paths.is_empty() {
            let srv_secs = srv_start.elapsed().as_secs_f64();
            println!(
                "  {SYM_WARN}  {:18} ({:12}) -> Path not accessible in {:.2}s ({})",
                srv.name,
                srv.ip,
                srv_secs,
                tried_paths.first().cloned().unwrap_or_default()
            );
            failed_servers.push(srv.name.clone());
            summaries.push(FleetServerSummary {
                server_name: srv.name.clone(),
                server_ip: srv.ip.clone(),
                success: false,
                total_errors: 0,
                log_files_scanned: 0,
                log_files_total: 0,
                lines_scanned: 0,
                bytes_scanned: 0,
                elapsed_seconds: format!("{:.2}", srv_secs),
                engine: "lpr-native".to_string(),
                first_error: String::new(),
                last_error: String::new(),
                scanned_paths: String::new(),
                error_message: format!("Paths not accessible: {}", tried_paths.join("; ")),
            });
            continue;
        }

        let cutoff_naive = chrono::NaiveDate::parse_from_str(&cutoff_date, "%Y-%m-%d")
            .unwrap_or_else(|_| chrono::Utc::now().date_naive());
        let cutoff_dt = cutoff_time.as_ref().and_then(|t| {
            chrono::NaiveDateTime::parse_from_str(
                &format!("{} {}", cutoff_date, t),
                "%Y-%m-%d %H:%M:%S",
            )
            .ok()
        });

        // For short windows (--latest, --hours <= 24, or --days 1), resolve primary live log paths first
        // so we don't enumerate thousands of historical files in Archive/Old folders unless needed!
        let is_short_window = latest_only || hours.map(|h| h <= 24).unwrap_or(days <= 1);
        let live_only_paths: Vec<String> = existing_paths
            .iter()
            .filter(|p| {
                let pl = p.to_ascii_lowercase();
                !pl.contains("old") && !pl.contains("archive") && !pl.contains("backup")
            })
            .cloned()
            .collect();

        let (active_scan_paths, all_items) = if is_short_window
            && !live_only_paths.is_empty()
            && live_only_paths.len() < existing_paths.len()
        {
            let live_joined = live_only_paths.join(";");
            let live_items =
                resolve_source_items_with_cutoff(&live_joined, Some(cutoff_naive))
                    .unwrap_or_default();
            if !live_items.is_empty() {
                (live_only_paths, live_items)
            } else {
                let full_joined = existing_paths.join(";");
                let full_items =
                    resolve_source_items_with_cutoff(&full_joined, Some(cutoff_naive))
                        .unwrap_or_default();
                (existing_paths.clone(), full_items)
            }
        } else {
            let full_joined = existing_paths.join(";");
            let full_items =
                resolve_source_items_with_cutoff(&full_joined, Some(cutoff_naive))
                    .unwrap_or_default();
            (existing_paths.clone(), full_items)
        };

        let joined_pattern = active_scan_paths.join(";");
        let total_files = all_items.len();
        let items = match cutoff_dt {
            Some(cdt) => filter_items_by_datetime(all_items, cdt),
            None => filter_items_by_min_date(all_items, cutoff_naive),
        };
        let items = if latest_only {
            keep_latest_log_item(items)
        } else {
            items
        };
        let files_count = items.len();
        if items.is_empty() {
            let srv_secs = srv_start.elapsed().as_secs_f64();
            println!(
                "  {SYM_OK}  {:18} ({:12}) [Skip] ->     0 match(es) |    0/{:>4} files |           0 lines | {:>5.2}s",
                srv.name, srv.ip, total_files, srv_secs
            );
            summaries.push(FleetServerSummary {
                server_name: srv.name.clone(),
                server_ip: srv.ip.clone(),
                success: true,
                total_errors: 0,
                log_files_scanned: 0,
                log_files_total: total_files,
                lines_scanned: 0,
                bytes_scanned: 0,
                elapsed_seconds: format!("{:.2}", srv_secs),
                engine: "lpr-window-skip".to_string(),
                first_error: String::new(),
                last_error: String::new(),
                scanned_paths: active_scan_paths.join("; "),
                error_message: String::new(),
            });
            continue;
        }
        if !learned_during_scan
            && (req.learn_intelligence || (trace_active && profile.session_intelligence.is_none()))
        {
            let sample_subset: Vec<_> = keep_latest_log_item(items.clone())
                .into_iter()
                .take(2)
                .collect();
            if let Ok(intel) = learn_session_intelligence_from_items(&sample_subset, threads).await
            {
                print_session_intelligence_summary(&active_profile_name, &intel);
                profile.session_intelligence = Some(intel);
                cfg_store
                    .profiles
                    .insert(active_profile_name.clone(), profile.clone());
                let _ = cfg_store.save(req.cfg_file_path.as_deref());
                learned_during_scan = true;
            }
            if req.learn_intelligence && !trace_active {
                return Ok(());
            }
        }
        let pre_filter = base_pre_filter.clone();
        let engine = LogEngine::with_options(threads, verbose);
        let input_fmt = parse_stack_input_format(&server_type);
        if trace_active {
            resolved_server_sources.push((
                srv.clone(),
                items.clone(),
                joined_pattern.clone(),
                input_fmt,
            ));
        }
        match engine
            .register_source_items_filtered(
                "logs",
                items,
                input_fmt,
                None,
                None,
                Some(&joined_pattern),
                Some(&pre_filter),
            )
            .await
        {
            Ok(detected_fmt) => {
                let p_stats = engine.get_last_stats();
                let cols = engine.table_columns("logs").await;
                let sql = custom_sql.clone().unwrap_or_else(|| {
                    build_multi_format_error_sql(
                        &cols,
                        &status_prefix,
                        &cutoff_date,
                        cutoff_time.as_deref(),
                    )
                });
                match engine.query(&sql).await {
                    Ok(batches) => {
                        let srv_secs = srv_start.elapsed().as_secs_f64();
                        let (rows, row_count) = if custom_sql.is_some() {
                            let grows =
                                extract_generic_rows(&batches, &mut custom_cols, &srv.name, &srv.ip);
                            let n = grows.len();
                            custom_rows.extend(grows);
                            let trace_rows = if trace_active {
                                extract_fleet_rows(&batches, &srv.name, &srv.ip)
                            } else {
                                Vec::new()
                            };
                            (trace_rows, n)
                        } else {
                            let rows = extract_fleet_rows(&batches, &srv.name, &srv.ip);
                            let n = rows.len();
                            (rows, n)
                        };
                        let first_err = rows
                            .first()
                            .map(|r| format!("{} {}", r.date, r.time))
                            .unwrap_or_default();
                        let last_err = rows
                            .last()
                            .map(|r| format!("{} {}", r.date, r.time))
                            .unwrap_or_default();
                        println!(
                            "  {SYM_OK}  {:18} ({:12}) [{:?}] -> {:>5} match(es) | {:>4}/{:>4} files | {:>11} lines | {:>5.2}s",
                            srv.name,
                            srv.ip,
                            detected_fmt,
                            row_count,
                            files_count,
                            total_files,
                            format_int_commas(p_stats.total_lines),
                            srv_secs
                        );
                        summaries.push(FleetServerSummary {
                            server_name: srv.name.clone(),
                            server_ip: srv.ip.clone(),
                            success: true,
                            total_errors: row_count,
                            log_files_scanned: files_count,
                            log_files_total: total_files,
                            lines_scanned: p_stats.total_lines,
                            bytes_scanned: p_stats.total_bytes,
                            elapsed_seconds: format!("{:.2}", srv_secs),
                            engine: format!("lpr-{:?}", detected_fmt),
                            first_error: first_err,
                            last_error: last_err,
                            scanned_paths: active_scan_paths.join("; "),
                            error_message: String::new(),
                        });
                        all_errors.extend(rows);
                    }
                    Err(e) => {
                        let srv_secs = srv_start.elapsed().as_secs_f64();
                        println!(
                            "  {SYM_WARN}  {:18} ({:12}) -> SQL Error in {:.2}s: {}",
                            srv.name, srv.ip, srv_secs, e
                        );
                        failed_servers.push(srv.name.clone());
                        summaries.push(FleetServerSummary {
                            server_name: srv.name.clone(),
                            server_ip: srv.ip.clone(),
                            success: false,
                            total_errors: 0,
                            log_files_scanned: files_count,
                            log_files_total: total_files,
                            lines_scanned: p_stats.total_lines,
                            bytes_scanned: p_stats.total_bytes,
                            elapsed_seconds: format!("{:.2}", srv_secs),
                            engine: "lpr-native-parallel".to_string(),
                            first_error: String::new(),
                            last_error: String::new(),
                            scanned_paths: active_scan_paths.join("; "),
                            error_message: e.to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                let srv_secs = srv_start.elapsed().as_secs_f64();
                println!(
                    "  {SYM_WARN}  {:18} ({:12}) -> Parse Error in {:.2}s: {}",
                    srv.name, srv.ip, srv_secs, e
                );
                failed_servers.push(srv.name.clone());
                summaries.push(FleetServerSummary {
                    server_name: srv.name.clone(),
                    server_ip: srv.ip.clone(),
                    success: false,
                    total_errors: 0,
                    log_files_scanned: 0,
                    log_files_total: total_files,
                    lines_scanned: 0,
                    bytes_scanned: 0,
                    elapsed_seconds: format!("{:.2}", srv_secs),
                    engine: "lpr-native-parallel".to_string(),
                    first_error: String::new(),
                    last_error: String::new(),
                    scanned_paths: active_scan_paths.join("; "),
                    error_message: e.to_string(),
                });
            }
        }
    }

    let total_fleet_secs = fleet_start.elapsed().as_secs_f64();
    write_fleet_reports(
        &output_dir,
        &report_prefix,
        &status_prefix,
        days,
        &cutoff_date,
        &run_stamp,
        servers.len(),
        &all_errors,
        &summaries,
        &failed_servers,
        if custom_sql.is_some() {
            Some((&custom_cols, &custom_rows))
        } else {
            None
        },
        total_fleet_secs,
    )?;

    if trace_active && !all_errors.is_empty() && !resolved_server_sources.is_empty() {
        run_cross_server_journey_tracer(
            &resolved_server_sources,
            &all_errors,
            trace_id_clean.as_deref(),
            req.trace_window_mins.max(1),
            req.max_journeys.max(1),
            profile.session_intelligence.as_ref(),
            &cutoff_date,
            cutoff_time.as_deref(),
            &output_dir,
            &report_prefix,
            &run_stamp,
            threads,
            verbose,
        )
        .await?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_local_or_archive_fleet_scan(
    target_path: &str,
    cutoff_date: &str,
    cutoff_time: Option<&str>,
    run_stamp: &str,
    output_dir: &str,
    report_prefix: &str,
    status_prefix: &str,
    days: i64,
    threads: Option<usize>,
    verbose: bool,
    custom_sql: Option<&str>,
    latest_only: bool,
    base_pre_filter: &ScanPreFilter,
    fleet_start: std::time::Instant,
    trace_active: bool,
    trace_id: Option<&str>,
    trace_window_mins: i64,
    max_journeys: usize,
    session_intel: Option<&SessionIntelligence>,
) -> Result<()> {
    let srv_start = std::time::Instant::now();
    let cutoff_naive = chrono::NaiveDate::parse_from_str(cutoff_date, "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    let cutoff_dt = cutoff_time.and_then(|t| {
        chrono::NaiveDateTime::parse_from_str(
            &format!("{} {}", cutoff_date, t),
            "%Y-%m-%d %H:%M:%S",
        )
        .ok()
    });
    let all_items = resolve_source_items_with_cutoff(target_path, Some(cutoff_naive))?;
    let total_files = all_items.len();
    let items = match cutoff_dt {
        Some(cdt) => filter_items_by_datetime(all_items, cdt),
        None => filter_items_by_min_date(all_items, cutoff_naive),
    };
    let items = if latest_only {
        keep_latest_log_item(items)
    } else {
        items
    };
    if items.is_empty() {
        anyhow::bail!("No log files on/after {} in {}", cutoff_date, target_path);
    }
    let files_scanned = items.len();
    let items_for_trace = items.clone();
    let pre_filter = base_pre_filter.clone();
    let engine = LogEngine::with_options(threads, verbose);
    let detected_fmt = engine
        .register_source_items_filtered(
            "logs",
            items,
            InputFormat::Auto,
            None,
            None,
            Some(target_path),
            Some(&pre_filter),
        )
        .await?;
    let p_stats = engine.get_last_stats();
    let cols = engine.table_columns("logs").await;
    let sql = custom_sql.map(|s| s.to_string()).unwrap_or_else(|| {
        build_multi_format_error_sql(&cols, status_prefix, cutoff_date, cutoff_time)
    });
    let batches = engine.query(&sql).await?;

    let mut custom_cols: Vec<String> = Vec::new();
    let mut custom_rows: Vec<Vec<String>> = Vec::new();
    let mut all_errors: Vec<FleetErrorRow> = Vec::new();
    let row_count;
    if custom_sql.is_some() {
        custom_rows = extract_generic_rows(&batches, &mut custom_cols, "LOCAL-SERVER", "127.0.0.1");
        row_count = custom_rows.len();
        if trace_active {
            all_errors = extract_fleet_rows(&batches, "LOCAL-SERVER", "127.0.0.1");
        }
    } else {
        all_errors = extract_fleet_rows(&batches, "LOCAL-SERVER", "127.0.0.1");
        row_count = all_errors.len();
    }

    let first_err = all_errors
        .first()
        .map(|r| format!("{} {}", r.date, r.time))
        .unwrap_or_default();
    let last_err = all_errors
        .last()
        .map(|r| format!("{} {}", r.date, r.time))
        .unwrap_or_default();
    let srv_name = all_errors
        .first()
        .map(|r| r.server_name.clone())
        .unwrap_or_else(|| "LOCAL-ARCHIVE".to_string());
    let srv_ip = all_errors
        .first()
        .map(|r| r.server_ip.clone())
        .unwrap_or_default();
    let srv_secs = srv_start.elapsed().as_secs_f64();

    println!(
        "  {SYM_OK}  {:18} ({:12}) [{:?}] -> {:>5} match(es) | {:>4}/{:>4} files | {:>11} lines | {:>5.2}s",
        srv_name,
        srv_ip,
        detected_fmt,
        row_count,
        files_scanned,
        total_files,
        format_int_commas(p_stats.total_lines),
        srv_secs
    );

    let summaries = vec![FleetServerSummary {
        server_name: srv_name,
        server_ip: srv_ip,
        success: true,
        total_errors: row_count,
        log_files_scanned: files_scanned,
        log_files_total: total_files,
        lines_scanned: p_stats.total_lines,
        bytes_scanned: p_stats.total_bytes,
        elapsed_seconds: format!("{:.2}", srv_secs),
        engine: format!("lpr-{:?}", detected_fmt),
        first_error: first_err,
        last_error: last_err,
        scanned_paths: target_path.to_string(),
        error_message: String::new(),
    }];

    write_fleet_reports(
        output_dir,
        report_prefix,
        status_prefix,
        days,
        cutoff_date,
        run_stamp,
        1,
        &all_errors,
        &summaries,
        &[],
        if custom_sql.is_some() {
            Some((&custom_cols, &custom_rows))
        } else {
            None
        },
        fleet_start.elapsed().as_secs_f64(),
    )?;

    if trace_active && !all_errors.is_empty() {
        let local_srv = ServerEntry {
            name: "LOCAL-SERVER".to_string(),
            ip: "127.0.0.1".to_string(),
            enabled: true,
        };
        let sources = vec![(
            local_srv,
            items_for_trace,
            target_path.to_string(),
            detected_fmt,
        )];
        run_cross_server_journey_tracer(
            &sources,
            &all_errors,
            trace_id,
            trace_window_mins.max(1),
            max_journeys.max(1),
            session_intel,
            cutoff_date,
            cutoff_time,
            output_dir,
            report_prefix,
            run_stamp,
            threads,
            verbose,
        )
        .await?;
    }

    Ok(())
}

fn extract_generic_rows(
    batches: &[arrow::record_batch::RecordBatch],
    col_names: &mut Vec<String>,
    srv_name: &str,
    srv_ip: &str,
) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if col_names.is_empty() {
        if let Some(b) = batches.first() {
            *col_names = b
                .schema()
                .fields()
                .iter()
                .map(|f| f.name().clone())
                .collect();
        }
    }
    if let Ok(val) = batches_to_json_value(batches) {
        if let Some(arr) = val.as_array() {
            for obj in arr {
                let mut rec = Vec::with_capacity(col_names.len() + 2);
                rec.push(srv_name.to_string());
                rec.push(srv_ip.to_string());
                for c in col_names.iter() {
                    rec.push(match obj.get(c.as_str()) {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        Some(serde_json::Value::Null) | None => String::new(),
                        Some(v) => v.to_string(),
                    });
                }
                out.push(rec);
            }
        }
    }
    out
}

fn extract_fleet_rows(
    batches: &[arrow::record_batch::RecordBatch],
    srv_name: &str,
    srv_ip: &str,
) -> Vec<FleetErrorRow> {
    let mut rows = Vec::new();
    if let Ok(val) = batches_to_json_value(batches) {
        if let Some(arr) = val.as_array() {
            for obj in arr {
                let effective_srv = obj["s_computername"]
                    .as_str()
                    .or_else(|| obj["s_sitename"].as_str())
                    .or_else(|| obj["host"].as_str())
                    .or_else(|| obj["elb"].as_str())
                    .filter(|s| !s.is_empty() && srv_name == "LOCAL-SERVER")
                    .unwrap_or(srv_name);
                let effective_ip = obj["s_ip"]
                    .as_str()
                    .or_else(|| obj["target_ip"].as_str())
                    .filter(|s| !s.is_empty() && srv_ip == "127.0.0.1")
                    .unwrap_or(srv_ip);

                let (date_val, time_val) = if let Some(d) = obj["date"].as_str() {
                    (
                        d.to_string(),
                        obj["time"].as_str().unwrap_or("").to_string(),
                    )
                } else if let Some(tl) = obj["time_local"]
                    .as_str()
                    .or_else(|| obj["timestamp"].as_str())
                    .or_else(|| obj["time"].as_str())
                {
                    split_timestamp_into_date_time(tl)
                } else {
                    (String::new(), String::new())
                };

                let client_ip = obj["c_ip"]
                    .as_str()
                    .or_else(|| obj["remote_addr"].as_str())
                    .or_else(|| obj["client_ip"].as_str())
                    .or_else(|| obj["remote_ip"].as_str())
                    .or_else(|| obj["srcip"].as_str())
                    .unwrap_or("")
                    .to_string();

                let method = obj["cs_method"]
                    .as_str()
                    .or_else(|| obj["method"].as_str())
                    .or_else(|| obj["operation"].as_str())
                    .unwrap_or("")
                    .to_string();

                let (uri_stem, uri_query) = if let Some(stem) = obj["cs_uri_stem"].as_str() {
                    (
                        stem.to_string(),
                        obj["cs_uri_query"].as_str().unwrap_or("").to_string(),
                    )
                } else if let Some(full_uri) = obj["request_uri"]
                    .as_str()
                    .or_else(|| obj["request"].as_str())
                    .or_else(|| obj["uri"].as_str())
                {
                    match full_uri.split_once('?') {
                        Some((s, q)) => (s.to_string(), q.to_string()),
                        None => (full_uri.to_string(), String::new()),
                    }
                } else {
                    (String::new(), String::new())
                };

                let status = obj["sc_status"]
                    .as_str()
                    .or_else(|| obj["status"].as_str())
                    .or_else(|| obj["elb_status_code"].as_str())
                    .or_else(|| obj["http_status"].as_str())
                    .or_else(|| obj["http_status_code"].as_str())
                    .unwrap_or("")
                    .to_string();

                let time_taken_ms = obj["time_taken"]
                    .as_str()
                    .or_else(|| obj["request_processing_time"].as_str())
                    .or_else(|| obj["total_time"].as_str())
                    .or_else(|| obj["duration"].as_str())
                    .unwrap_or("")
                    .to_string();

                let user_agent = obj["csuser_agent"]
                    .as_str()
                    .or_else(|| obj["http_user_agent"].as_str())
                    .or_else(|| obj["user_agent"].as_str())
                    .unwrap_or("")
                    .to_string();

                let referer = obj["csreferer"]
                    .as_str()
                    .or_else(|| obj["http_referer"].as_str())
                    .or_else(|| obj["referrer"].as_str())
                    .unwrap_or("")
                    .to_string();

                let log_file = obj["log_filename"]
                    .as_str()
                    .or_else(|| obj["file"].as_str())
                    .unwrap_or("")
                    .to_string();

                let log_row = obj["log_row"]
                    .as_str()
                    .or_else(|| obj["line_number"].as_str())
                    .unwrap_or("")
                    .to_string();

                let raw_xff = obj["x_forwarded_for"]
                    .as_str()
                    .or_else(|| obj["csx_forwarded_for"].as_str())
                    .or_else(|| obj["cf_connecting_ip"].as_str())
                    .or_else(|| obj["true_client_ip"].as_str())
                    .or_else(|| obj["x_real_ip"].as_str())
                    .or_else(|| obj["forwarded_for"].as_str())
                    .unwrap_or("");
                let forwarded_ip = raw_xff
                    .split([',', ';', '+'])
                    .next()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && *s != "-")
                    .unwrap_or("")
                    .to_string();

                let cookie = obj["cscookie"]
                    .as_str()
                    .or_else(|| obj["cs_cookie"].as_str())
                    .or_else(|| obj["cookie"].as_str())
                    .filter(|s| *s != "-")
                    .unwrap_or("")
                    .to_string();

                let redirect_location = obj["sclocation"]
                    .as_str()
                    .or_else(|| obj["sc_location"].as_str())
                    .or_else(|| obj["location"].as_str())
                    .or_else(|| obj["redirect_url"].as_str())
                    .filter(|s| *s != "-")
                    .unwrap_or("")
                    .to_string();

                rows.push(FleetErrorRow {
                    server_name: effective_srv.to_string(),
                    server_ip: effective_ip.to_string(),
                    date: date_val,
                    time: time_val,
                    client_ip,
                    method,
                    uri_stem,
                    uri_query,
                    status,
                    sub_status: obj["sc_substatus"].as_str().unwrap_or("").to_string(),
                    win32_status: obj["sc_win32_status"].as_str().unwrap_or("").to_string(),
                    time_taken_ms,
                    user_agent,
                    referer,
                    log_file,
                    log_row,
                    forwarded_ip,
                    cookie,
                    redirect_location,
                });
            }
        }
    }
    rows
}

fn format_int_commas(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (idx, &b) in bytes.iter().enumerate() {
        if idx > 0 && (bytes.len() - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn format_bytes_human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

#[allow(clippy::too_many_arguments)]
fn write_fleet_reports(
    output_dir: &str,
    report_prefix: &str,
    status_prefix: &str,
    days: i64,
    cutoff_date: &str,
    run_stamp: &str,
    servers_requested: usize,
    all_errors: &[FleetErrorRow],
    summaries: &[FleetServerSummary],
    failed_servers: &[String],
    custom_detail: Option<(&[String], &[Vec<String>])>,
    total_fleet_secs: f64,
) -> Result<()> {
    let safe_prefix: String = report_prefix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_' | '.'))
        .collect();
    let safe_prefix = if safe_prefix.is_empty() || safe_prefix.contains("..") {
        "IIS-Errors"
    } else {
        &safe_prefix
    };
    let out_dir = PathBuf::from(output_dir);
    let detail_csv = out_dir.join(format!("{}-{}.csv", safe_prefix, run_stamp));
    let summary_csv = out_dir.join(format!("{}-Summary-{}.csv", safe_prefix, run_stamp));
    let manifest_txt = out_dir.join(format!("{}-Manifest-{}.txt", safe_prefix, run_stamp));

    {
        let mut wtr = csv::Writer::from_path(&detail_csv)?;
        match custom_detail {
            Some((cols, rows)) => {
                let mut header = vec!["ServerName".to_string(), "ServerIP".to_string()];
                header.extend(cols.iter().cloned());
                wtr.write_record(&header)?;
                for r in rows {
                    wtr.write_record(r)?;
                }
            }
            None => {
                for row in all_errors {
                    wtr.serialize(row)?;
                }
            }
        }
        wtr.flush()?;
    }

    {
        let mut wtr = csv::Writer::from_path(&summary_csv)?;
        for s in summaries {
            wtr.serialize(s)?;
        }
        wtr.flush()?;
    }

    let succeeded = summaries.iter().filter(|s| s.success).count();
    let servers_skipped = summaries
        .iter()
        .filter(|s| s.success && s.log_files_scanned == 0)
        .count();
    let servers_scanned_active = succeeded.saturating_sub(servers_skipped);
    let servers_with_matches = summaries.iter().filter(|s| s.total_errors > 0).count();

    let files_total: usize = summaries.iter().map(|s| s.log_files_total).sum();
    let files_scanned: usize = summaries.iter().map(|s| s.log_files_scanned).sum();
    let files_skipped = files_total.saturating_sub(files_scanned);

    let lines_total: usize = summaries.iter().map(|s| s.lines_scanned).sum();
    let bytes_total: u64 = summaries.iter().map(|s| s.bytes_scanned).sum();
    let total_matches = custom_detail
        .map(|(_, rows)| rows.len())
        .unwrap_or(all_errors.len());
    let lines_filtered_out = lines_total.saturating_sub(total_matches);

    let safe_secs = total_fleet_secs.max(0.001);
    let avg_srv_secs = if !summaries.is_empty() {
        total_fleet_secs / (summaries.len() as f64)
    } else {
        0.0
    };
    let lines_per_sec = ((lines_total as f64) / safe_secs).round() as usize;
    let mb_per_sec = (bytes_total as f64 / (1024.0 * 1024.0)) / safe_secs;

    let manifest_content = format!(
        "GeneratedUtc={}\nEngine=lpr-v{}\nDays={}\nCutoffDate={}\nServersRequested={}\nServersSucceeded={}\nServersSkipped={}\nServersFailed={}\nServersWithMatches={}\nFilesTotal={}\nFilesScanned={}\nFilesSkipped={}\nLinesScanned={}\nBytesScanned={}\nTotalMatches={}\nTotalElapsedSeconds={:.2}\nDetailCsv={}\nSummaryCsv={}\nFailedServers={}\n",
        Utc::now().to_rfc3339(),
        env!("CARGO_PKG_VERSION"),
        days,
        cutoff_date,
        servers_requested,
        succeeded,
        servers_skipped,
        failed_servers.len(),
        servers_with_matches,
        files_total,
        files_scanned,
        files_skipped,
        lines_total,
        bytes_total,
        total_matches,
        total_fleet_secs,
        detail_csv.to_string_lossy(),
        summary_csv.to_string_lossy(),
        failed_servers.join(",")
    );
    fs::write(&manifest_txt, manifest_content)?;

    println!("--------------------------------------------------------------------------------");
    println!(
        "               {:>12} {:>14} {:>12} {:>10} {:>13}",
        "Total", "Scanned / OK", "Skipped", "Failed", "Matched"
    );
    println!(
        "  Servers :    {:>12} {:>14} {:>12} {:>10} {:>13}",
        format_int_commas(servers_requested),
        format_int_commas(servers_scanned_active),
        format_int_commas(servers_skipped),
        format_int_commas(failed_servers.len()),
        format!("{} srv(s)", servers_with_matches)
    );
    println!(
        "  Files   :    {:>12} {:>14} {:>12} {:>10} {:>13}",
        format_int_commas(files_total),
        format_int_commas(files_scanned),
        format_int_commas(files_skipped),
        "0",
        "--"
    );
    println!(
        "  Lines   :    {:>12} {:>14} {:>12} {:>10} {:>13}",
        format_int_commas(lines_total),
        format_int_commas(lines_total),
        format_int_commas(lines_filtered_out),
        "0",
        format_int_commas(total_matches)
    );
    println!(
        "  Volume  :    {:>12} {:>14} {:>12} {:>10} {:>13}",
        format_bytes_human(bytes_total),
        format_bytes_human(bytes_total),
        "--",
        "0 B",
        format!("{} rows", format_int_commas(total_matches))
    );
    println!("--------------------------------------------------------------------------------");
    println!(
        "  Speed   :    {:.2} MB/sec | {} lines/sec | Threads: Parallel Rayon + Arrow",
        mb_per_sec,
        format_int_commas(lines_per_sec)
    );
    println!(
        "  Times   :    Total: {:.2}s | Avg/Server: {:.2}s | Ended: {}",
        total_fleet_secs,
        avg_srv_secs,
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("--------------------------------------------------------------------------------");
    if custom_detail.is_some() {
        println!(
            " {SYM_DONE} Fleet Scan Complete — {} matching row(s) found across {}/{} server(s) in {:.2}s",
            format_int_commas(total_matches),
            servers_with_matches,
            servers_requested,
            total_fleet_secs
        );
    } else {
        println!(
            " {SYM_DONE} Fleet Scan Complete — {} ({}xx) match(es) found across {}/{} server(s) in {:.2}s",
            format_int_commas(total_matches),
            status_prefix,
            servers_with_matches,
            servers_requested,
            total_fleet_secs
        );
    }
    println!(" {SYM_FILE} Detail CSV        : {}", detail_csv.to_string_lossy());
    println!(" {SYM_LIST} Summary CSV       : {}", summary_csv.to_string_lossy());
    println!(" {SYM_NOTE} Manifest File     : {}", manifest_txt.to_string_lossy());
    println!("================================================================================");

    Ok(())
}

fn discover_raw_server_inventory(
    servers_file: Option<&str>,
    host_pattern: Option<&str>,
    saved_servers: &[ServerEntry],
) -> Result<Vec<ServerEntry>> {
    if let Some(f) = servers_file.filter(|s| !s.is_empty() && Path::new(s).exists()) {
        return load_servers_from_file(f);
    }
    if !saved_servers.is_empty() {
        return Ok(saved_servers.to_vec());
    }
    if Path::new("servers.csv").exists() {
        return load_servers_from_file("servers.csv");
    }
    if Path::new("IISLogRotation.config.json").exists() {
        return load_servers_from_file("IISLogRotation.config.json");
    }
    if let Some(pat) = host_pattern {
        let mut generated = Vec::new();
        for n in 1..=24 {
            let name = expand_host_pattern(pat, n);
            generated.push(ServerEntry {
                name: name.clone(),
                ip: name,
                enabled: true,
            });
        }
        return Ok(generated);
    }
    Ok(Vec::new())
}

fn load_servers_from_file(path: &str) -> Result<Vec<ServerEntry>> {
    let mut list = Vec::new();
    if path.to_lowercase().ends_with(".json") {
        let content = fs::read_to_string(path)?;
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(arr) = val["Servers"].as_array() {
                for s in arr {
                    let enabled = s["Enabled"].as_bool().unwrap_or(true);
                    let name = s["Name"].as_str().unwrap_or("").to_string();
                    let ip = s["IP"].as_str().unwrap_or(&name).to_string();
                    if enabled && !name.is_empty() {
                        list.push(ServerEntry { name, ip, enabled });
                    }
                }
            }
        }
    } else {
        let mut rdr = csv::Reader::from_path(path)?;
        for result in rdr.records() {
            if let Ok(rec) = result {
                let name = rec.get(0).unwrap_or("").trim().to_string();
                let ip = rec.get(1).unwrap_or(&name).trim().to_string();
                let en_str = rec.get(2).unwrap_or("true").trim().to_lowercase();
                let enabled = en_str == "true" || en_str == "1" || en_str == "yes";
                if enabled && !name.is_empty() {
                    list.push(ServerEntry { name, ip, enabled });
                }
            }
        }
    }
    Ok(list)
}

fn expand_host_pattern(pattern: &str, n: usize) -> String {
    if pattern.contains("{02}") || pattern.contains("{n:02}") {
        pattern
            .replace("{02}", &format!("{:02}", n))
            .replace("{n:02}", &format!("{:02}", n))
    } else if pattern.contains("{03}") || pattern.contains("{n:03}") {
        pattern
            .replace("{03}", &format!("{:03}", n))
            .replace("{n:03}", &format!("{:03}", n))
    } else if pattern.contains("{n}") || pattern.contains("{}") {
        pattern
            .replace("{n}", &n.to_string())
            .replace("{}", &n.to_string())
    } else {
        format!("{}{:02}", pattern, n)
    }
}

fn resolve_filtered_servers(
    servers_file: Option<&str>,
    host_pattern: Option<&str>,
    saved_servers: &[ServerEntry],
    filter: &str,
    numbers_spec: &str,
) -> Result<Vec<ServerEntry>> {
    let allowed_nums = parse_server_numbers(numbers_spec);

    // If the user gave `--host-pattern` AND `--server-numbers` without a CSV file, synthesize exact server names!
    if servers_file.is_none()
        && saved_servers.is_empty()
        && !Path::new("servers.csv").exists()
        && host_pattern.is_some()
        && !allowed_nums.is_empty()
    {
        let pat = host_pattern.unwrap();
        let mut nums: Vec<usize> = allowed_nums.into_iter().collect();
        nums.sort();
        return Ok(nums
            .into_iter()
            .map(|n| {
                let name = expand_host_pattern(pat, n);
                ServerEntry {
                    name: name.clone(),
                    ip: name,
                    enabled: true,
                }
            })
            .collect());
    }

    let list = discover_raw_server_inventory(servers_file, host_pattern, saved_servers)?;
    let filter_lower = filter.to_lowercase();

    let filtered: Vec<ServerEntry> = list
        .into_iter()
        .filter(|s| {
            let matches_wildcard = if filter_lower == "*" || filter_lower.is_empty() {
                true
            } else if let Some(prefix) = filter_lower.strip_suffix('*') {
                s.name.to_lowercase().starts_with(prefix)
            } else {
                s.name.to_lowercase().contains(&filter_lower)
            };

            let matches_num = if allowed_nums.is_empty() {
                true
            } else if let Some(num) = extract_trailing_number(&s.name) {
                allowed_nums.contains(&num)
            } else {
                false
            };

            matches_wildcard && matches_num
        })
        .collect();

    Ok(filtered)
}

fn parse_server_numbers(spec: &str) -> HashSet<usize> {
    let mut set = HashSet::new();
    for part in spec.split(',') {
        let tok = part.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(start), Ok(end)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                let capped_end = end.min(start.saturating_add(10_000));
                for n in start..=capped_end {
                    set.insert(n);
                }
            }
        } else if let Ok(n) = tok.parse::<usize>() {
            set.insert(n);
        }
    }
    set
}

fn extract_trailing_number(name: &str) -> Option<usize> {
    let digits: String = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    digits.parse::<usize>().ok()
}

/// Converts a user path like `D:\Logs\MySite\W3SVC3` or `D:\Logs\{site}`
/// into a remote UNC path `\\<server>\d$\Logs\MySite\W3SVC3` automatically!
fn expand_remote_path_template(tpl: &str, srv_name: &str, srv_ip: &str, site_name: &str) -> String {
    let replaced = tpl
        .replace("{server}", srv_name)
        .replace("{ip}", srv_ip)
        .replace("{site}", site_name);
    let bytes = replaced.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = &replaced[3..];
        return format!(r"\\{}\{}$\{}", srv_name, drive, rest);
    }
    replaced
}

/// Reads IIS `applicationHost.config` on a remote Windows server (`\\<server>\c$\Windows\System32\inetsrv\config\applicationHost.config`)
/// or local machine (`C:\Windows\System32\inetsrv\config\applicationHost.config`), finds the matching `<site name="..." id="...">`,
/// and returns its exact UNC log directory (`\\<server>\d$\...\W3SVC<id>`).
fn discover_iis_site_log_paths_on_server(host: &str, site_query: &str) -> Vec<String> {
    let mut results = Vec::new();
    let candidates = vec![
        format!(
            r"\\{}\c$\Windows\System32\inetsrv\config\applicationHost.config",
            host
        ),
        r"C:\Windows\System32\inetsrv\config\applicationHost.config".to_string(),
    ];

    let q_lower = site_query.trim().to_lowercase();
    let numeric_id_query = q_lower.strip_prefix("w3svc").unwrap_or(&q_lower);

    for cfg_path in candidates {
        let Ok(xml) = fs::read_to_string(&cfg_path) else {
            continue;
        };

        // Find server-level default logFile directory if defined: <siteDefaults><logFile directory="..." />
        let mut default_log_dir = r"%SystemDrive%\inetpub\logs\LogFiles".to_string();
        if let Some(sd_idx) = xml.find("<siteDefaults") {
            if let Some(sd_end) = xml[sd_idx..].find("</siteDefaults>") {
                let sd_block = &xml[sd_idx..sd_idx + sd_end];
                if let Some(dir) = extract_xml_attr(sd_block, "directory") {
                    default_log_dir = dir;
                }
            }
        }

        // Scan each <site name="..." id="...">...</site> block
        let mut search_from = 0;
        while let Some(pos) = xml[search_from..].find("<site ") {
            let start = search_from + pos;
            let Some(end_rel) = xml[start..].find("</site>") else {
                break;
            };
            let site_block = &xml[start..start + end_rel];
            search_from = start + end_rel + 7;

            let open_tag_end = site_block.find('>').unwrap_or(site_block.len());
            let open_tag = &site_block[..open_tag_end];
            let s_name = extract_xml_attr(open_tag, "name").unwrap_or_default();
            let s_id = extract_xml_attr(open_tag, "id").unwrap_or_default();

            let matches = s_name.eq_ignore_ascii_case(site_query)
                || s_id == numeric_id_query
                || format!("w3svc{}", s_id).eq_ignore_ascii_case(site_query);

            if matches && !s_id.is_empty() {
                let site_log_dir = extract_xml_attr(site_block, "directory")
                    .unwrap_or_else(|| default_log_dir.clone())
                    .replace("%SystemDrive%", "C:");
                let full_local = format!(
                    r"{}\W3SVC{}",
                    site_log_dir.trim_end_matches(['\\', '/']),
                    s_id
                );
                let unc = expand_remote_path_template(&full_local, host, host, &s_name);
                if !results.contains(&unc) {
                    results.push(unc);
                }
                let parent_unc = expand_remote_path_template(&site_log_dir, host, host, &s_name);
                if !results.contains(&parent_unc) {
                    results.push(parent_unc);
                }
            }
        }
        if !results.is_empty() {
            break;
        }
    }
    results
}

fn extract_xml_attr(fragment: &str, attr_name: &str) -> Option<String> {
    let needle = format!("{}=\"", attr_name);
    let start = fragment.find(&needle)? + needle.len();
    let end = fragment[start..].find('"')?;
    Some(fragment[start..start + end].to_string())
}

// ---------------------------------------------------------------------------
// Credential handling — secret refs + Windows DPAPI-encrypted storage
// ---------------------------------------------------------------------------

/// Minimal raw FFI wrapper around CryptProtectData / CryptUnprotectData (DPAPI,
/// CurrentUser scope) — no extra crate needed.
#[cfg(windows)]
mod dpapi {
    use anyhow::Result;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *const core::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *const core::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    pub fn encrypt_data(data: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut input = DataBlob {
                cb_data: data.len() as u32,
                pb_data: data.as_ptr() as *mut u8,
            };
            let mut output = DataBlob {
                cb_data: 0,
                pb_data: std::ptr::null_mut(),
            };
            if CryptProtectData(
                &mut input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                &mut output,
            ) == 0
            {
                anyhow::bail!("CryptProtectData failed (win32 error)");
            }
            let slice = std::slice::from_raw_parts(output.pb_data, output.cb_data as usize);
            let out = slice.to_vec();
            LocalFree(output.pb_data as *mut core::ffi::c_void);
            Ok(out)
        }
    }

    pub fn decrypt_data(data: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut input = DataBlob {
                cb_data: data.len() as u32,
                pb_data: data.as_ptr() as *mut u8,
            };
            let mut output = DataBlob {
                cb_data: 0,
                pb_data: std::ptr::null_mut(),
            };
            if CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                &mut output,
            ) == 0
            {
                anyhow::bail!("CryptUnprotectData failed (wrong user/machine or corrupt blob)");
            }
            let slice = std::slice::from_raw_parts(output.pb_data, output.cb_data as usize);
            let out = slice.to_vec();
            LocalFree(output.pb_data as *mut core::ffi::c_void);
            Ok(out)
        }
    }
}

#[allow(dead_code)] // used by Windows SMB session establishment; also resolves refs for `prompt` mode
fn resolve_secret(profile: &SavedProfile) -> Option<String> {
    #[cfg(windows)]
    if let Some(ref hex_blob) = profile.auth_password_enc {
        if let Ok(raw) = hex_decode(hex_blob) {
            if let Ok(bytes) = dpapi::decrypt_data(&raw) {
                let s = String::from_utf8_lossy(&bytes).to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    match profile.auth_password_ref.as_deref().map(|s| s.trim()) {
        Some(r) if r.to_lowercase().starts_with("env:") => {
            std::env::var(&r[4..]).ok().filter(|v| !v.is_empty())
        }
        Some(r) if r.to_lowercase().starts_with("file:") => fs::read_to_string(&r[5..])
            .ok()
            .and_then(|c| c.lines().next().map(|l| l.trim().to_string()))
            .filter(|v| !v.is_empty()),
        Some(r) if r.eq_ignore_ascii_case("prompt") => {
            rpassword::prompt_password(format!(
                "Enter password for {}: ",
                profile.auth_user.as_deref().unwrap_or("remote share")
            ))
            .ok()
            .filter(|v| !v.is_empty())
        }
        _ => None,
    }
}

/// Prompt for a password (hidden input) and DPAPI-encrypt it for profile storage. Windows only.
#[cfg(windows)]
fn prompt_and_encrypt_password() -> Result<String> {
    eprintln!("{SYM_WARN}  The password will be DPAPI-encrypted and bound to THIS Windows user account on THIS machine only.");
    eprintln!("{SYM_WARN}  Other users / machines cannot decrypt it. If the account changes, re-save with --save-password.");
    let pass = rpassword::prompt_password("Enter SMB password to encrypt: ")?;
    if pass.is_empty() {
        anyhow::bail!("empty password");
    }
    let blob = dpapi::encrypt_data(pass.as_bytes())?;
    Ok(hex_encode(&blob))
}

#[cfg(not(windows))]
fn prompt_and_encrypt_password() -> Result<String> {
    anyhow::bail!("DPAPI encryption is Windows-only")
}

#[cfg(windows)]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(windows)]
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        anyhow::bail!("invalid hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

/// RAII guard: opens `net use \\server\IPC$` with alternate credentials on creation,
/// tears it down (`net use /delete`) when dropped. Windows only; no-op elsewhere.
#[cfg(windows)]
struct SmbSessionGuard {
    targets: Vec<String>,
}

#[cfg(windows)]
impl SmbSessionGuard {
    fn new(targets: Vec<String>) -> Self {
        Self { targets }
    }
}

#[cfg(windows)]
impl Drop for SmbSessionGuard {
    fn drop(&mut self) {
        for t in &self.targets {
            let _ = std::process::Command::new("net")
                .args(["use", t, "/delete", "/y"])
                .output();
        }
    }
}

#[cfg(windows)]
fn is_safe_smb_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.starts_with('/')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

#[cfg(windows)]
fn establish_smb_session(
    srv: &ServerEntry,
    profile: &SavedProfile,
    resolved_pass: Option<&str>,
) -> SmbSessionGuard {
    let Some(ref user) = profile.auth_user else {
        return SmbSessionGuard::new(Vec::new());
    };
    let user_trimmed = user.trim();
    if !is_safe_smb_ident(user_trimmed) {
        eprintln!("  {SYM_WARN}  Invalid SMB username `{}` — skipping net use", user_trimmed);
        return SmbSessionGuard::new(Vec::new());
    }
    let full_user = match profile.auth_domain.as_deref().map(|d| d.trim()).filter(|d| !d.is_empty()) {
        Some(dom) if is_safe_smb_ident(dom) => format!("{}\\{}", dom, user_trimmed),
        Some(dom) => {
            eprintln!("  {SYM_WARN}  Invalid SMB domain `{}` — skipping net use", dom);
            return SmbSessionGuard::new(Vec::new());
        }
        None => user_trimmed.to_string(),
    };
    let pass = resolved_pass.unwrap_or("");
    let mut active_targets = Vec::new();
    for candidate in [srv.name.trim(), srv.ip.trim()] {
        if !is_safe_smb_ident(candidate) {
            continue;
        }
        let target = format!(r"\\{}\IPC$", candidate);
        if active_targets.contains(&target) {
            continue;
        }
        let out = std::process::Command::new("net")
            .args([
                "use",
                &target,
                &format!("/user:{}", full_user),
                pass,
                "/persistent:no",
            ])
            .output();
        if out.map(|o| o.status.success()).unwrap_or(false) {
            active_targets.push(target);
        }
    }
    if active_targets.is_empty() {
        eprintln!(
            "  {SYM_WARN}  net use \\\\{}\\IPC$ as {} failed — falling back to current session credentials",
            srv.name, full_user
        );
    }
    SmbSessionGuard::new(active_targets)
}

fn default_path_templates_for_stack(
    server_type: &str,
    site_name: &str,
    ssh_enabled: bool,
) -> Vec<String> {
    if ssh_enabled
        || matches!(
            server_type,
            "nginx" | "apache" | "httpd" | "caddy" | "haproxy" | "tomcat" | "linux"
        )
    {
        match server_type {
            "nginx" => vec!["/var/log/nginx".to_string()],
            "apache" | "httpd" => {
                vec!["/var/log/apache2".to_string(), "/var/log/httpd".to_string()]
            }
            "caddy" => vec!["/var/log/caddy".to_string()],
            "haproxy" => vec!["/var/log/haproxy.log".to_string(), "/var/log/haproxy".to_string()],
            "tomcat" => vec![
                "/var/log/tomcat".to_string(),
                "/opt/tomcat/logs".to_string(),
            ],
            _ => vec![
                "/var/log/nginx".to_string(),
                "/var/log/apache2".to_string(),
                "/var/log/httpd".to_string(),
                "/var/log/caddy".to_string(),
                "/var/log/tomcat".to_string(),
            ],
        }
    } else if !site_name.is_empty() {
        vec![
            r"\\{server}\c$\inetpub\logs\LogFiles\{site}".to_string(),
            r"\\{server}\d$\Logs\{site}".to_string(),
            r"\\{server}\d$\IISLogs\{site}".to_string(),
            format!("/var/log/nginx/{}", site_name),
            format!("/var/log/apache2/{}", site_name),
        ]
    } else {
        vec![
            r"\\{server}\c$\inetpub\logs\LogFiles".to_string(),
            r"\\{server}\d$\Logs".to_string(),
            "/var/log/nginx".to_string(),
            "/var/log/apache2".to_string(),
            "/var/log/httpd".to_string(),
        ]
    }
}

fn parse_stack_input_format(server_type: &str) -> InputFormat {
    match server_type {
        "iis" | "w3c" | "smtp" => InputFormat::W3c,
        "nginx" | "apache" | "httpd" | "tomcat" => InputFormat::Nginx,
        "caddy" | "json" => InputFormat::Json,
        "haproxy" | "syslog" => InputFormat::Syslog,
        "alb" => InputFormat::AwsAlb,
        _ => InputFormat::Auto,
    }
}

/// Builds a universal SQL query for `lpr fleet` that adapts automatically to IIS W3C (`sc_status`),
/// Nginx/Apache/Tomcat (`status`), AWS ALB (`elb_status_code`), S3 (`http_status`), or Syslog/HAProxy (`message`).
fn build_multi_format_error_sql(
    cols: &[String],
    status_prefix: &str,
    cutoff_date: &str,
    cutoff_time: Option<&str>,
) -> String {
    let trimmed_sp = status_prefix.trim();
    let match_all_status = trimmed_sp == "*"
        || trimmed_sp.eq_ignore_ascii_case("all")
        || trimmed_sp.eq_ignore_ascii_case("any");
    let safe_status: String = trimmed_sp
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let sp = if safe_status.is_empty() { "5" } else { &safe_status };
    let safe_cutoff: String = cutoff_date
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let has = |c: &str| cols.iter().any(|x| x.eq_ignore_ascii_case(c));
    let date_clause = match (cutoff_time, has("time")) {
        (Some(t), true) => {
            let safe_t: String = t
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == ':')
                .collect();
            format!(
                "(date > '{d}' OR (date = '{d}' AND time >= '{t}'))",
                d = safe_cutoff,
                t = safe_t
            )
        }
        _ => format!("date >= '{}'", safe_cutoff),
    };
    if match_all_status {
        if has("date") && has("time") {
            return format!(
                "SELECT * FROM logs WHERE {} ORDER BY date, time",
                date_clause
            );
        } else {
            return "SELECT * FROM logs".to_string();
        }
    }
    if has("sc_status") && has("date") {
        format!(
            "SELECT * FROM logs WHERE sc_status LIKE '{}%' AND {} ORDER BY date, time",
            sp, date_clause
        )
    } else if has("status") {
        format!("SELECT * FROM logs WHERE CAST(status AS VARCHAR) LIKE '{}%'", sp)
    } else if has("elb_status_code") {
        format!(
            "SELECT * FROM logs WHERE elb_status_code LIKE '{}%' OR target_status_code LIKE '{}%'",
            sp, sp
        )
    } else if has("http_status") {
        format!("SELECT * FROM logs WHERE http_status LIKE '{}%'", sp)
    } else if has("http_status_code") {
        format!("SELECT * FROM logs WHERE http_status_code LIKE '{}%'", sp)
    } else {
        "SELECT * FROM logs LIMIT 500".to_string()
    }
}

fn split_timestamp_into_date_time(ts: &str) -> (String, String) {
    // Handle Nginx/Apache CLF: "15/Oct/2026:10:03:15 +0000"
    if ts.len() >= 20 && ts.as_bytes().get(2) == Some(&b'/') && ts.as_bytes().get(6) == Some(&b'/')
    {
        let day = &ts[0..2];
        let mon_str = &ts[3..6];
        let year = &ts[7..11];
        let time_part = ts[12..].split_whitespace().next().unwrap_or("");
        let mon_num = match mon_str.to_lowercase().as_str() {
            "jan" => "01",
            "feb" => "02",
            "mar" => "03",
            "apr" => "04",
            "may" => "05",
            "jun" => "06",
            "jul" => "07",
            "aug" => "08",
            "sep" => "09",
            "oct" => "10",
            "nov" => "11",
            "dec" => "12",
            _ => "01",
        };
        return (format!("{}-{}-{}", year, mon_num, day), time_part.to_string());
    }
    // Handle ISO-8601: "2026-10-15T10:20:00Z" or "2026-10-15 10:20:00"
    if let Some((d, t)) = ts.split_once(['T', ' ']) {
        return (d.to_string(), t.trim_end_matches('Z').to_string());
    }
    (ts.to_string(), String::new())
}

/// Auto-discovers local Linux Nginx, Apache, Caddy, Tomcat, and HAProxy log files
/// by scanning `/etc/nginx`, `/etc/apache2`, `/etc/httpd`, `/etc/caddy`, and `/var/log`.
fn discover_local_linux_webserver_logs(site_query: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let config_dirs = [
        "/etc/nginx/sites-enabled",
        "/etc/nginx/conf.d",
        "/etc/apache2/sites-enabled",
        "/etc/httpd/conf.d",
        "/etc/caddy",
    ];

    for dir in config_dirs {
        let p = Path::new(dir);
        if !p.is_dir() {
            continue;
        }
        if let Ok(rd) = fs::read_dir(p) {
            for entry in rd.flatten() {
                if !site_query.is_empty()
                    && !entry
                        .file_name()
                        .to_string_lossy()
                        .to_lowercase()
                        .contains(&site_query.to_lowercase())
                {
                    continue;
                }
                if let Ok(text) = fs::read_to_string(entry.path()) {
                    for line in text.lines() {
                        let t = line.trim();
                        if let Some(rest) =
                            t.strip_prefix("access_log").or_else(|| t.strip_prefix("CustomLog"))
                        {
                            if let Some(log_p) = rest.split_whitespace().next() {
                                let clean =
                                    log_p.trim_matches([';', '"', '\'']).to_string();
                                if clean.starts_with('/') && Path::new(&clean).exists() {
                                    paths.push(clean);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    paths
}

fn posix_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn is_safe_host_or_user(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// Connects to a remote Linux/Unix web server over SSH, discovers & streams matching log lines
/// (including `.gz` archives via `zcat -f`) from Nginx, Apache, Caddy, HAProxy, or Tomcat, and parses them with `lpr`.
#[allow(clippy::too_many_arguments)]
async fn scan_linux_server_via_ssh(
    srv: &ServerEntry,
    profile: &SavedProfile,
    path_templates: &[String],
    site_name: &str,
    status_prefix: &str,
    cutoff_date: &str,
    days: i64,
    threads: Option<usize>,
    verbose: bool,
    custom_sql: Option<&str>,
    hours: Option<i64>,
    latest_only: bool,
) -> Result<(
    Vec<FleetErrorRow>,
    Option<(Vec<String>, Vec<Vec<String>>)>,
    usize,
    String,
)> {
    let target_host = if !srv.ip.is_empty() {
        srv.ip.trim()
    } else {
        srv.name.trim()
    };
    if !is_safe_host_or_user(target_host) {
        anyhow::bail!("Unsafe SSH host identifier: {}", target_host);
    }
    let ssh_target = match &profile.ssh_user {
        Some(u) if !u.trim().is_empty() => {
            let ut = u.trim();
            if !is_safe_host_or_user(ut) {
                anyhow::bail!("Unsafe SSH username: {}", ut);
            }
            format!("{}@{}", ut, target_host)
        }
        _ => target_host.to_string(),
    };

    let search_dirs: Vec<String> = path_templates
        .iter()
        .map(|t| {
            t.replace("{server}", &srv.name)
                .replace("{ip}", &srv.ip)
                .replace("{site}", site_name)
        })
        .filter(|d| !d.trim().is_empty())
        .collect();
    let quoted_dirs: Vec<String> = search_dirs.iter().map(|d| posix_single_quote(d)).collect();
    let dirs_arg = search_dirs.join(" ");

    // Build a POSIX-quoted remote shell command that prevents command injection.
    // --hours uses -mmin (minute granularity); --latest sorts by mtime and keeps only the newest file.
    let find_time = match hours {
        Some(h) => format!("-mmin -{}", (h.max(1) * 60).min(5_256_000)),
        None => format!("-mtime -{}", days.clamp(1, 3650)),
    };
    let remote_cmd = if latest_only {
        format!(
            "find {} -maxdepth 2 -type f \\( -name '*.log' -o -name '*.log.1' -o -name '*access*.gz' \\) {} -printf '%T@ %p\\n' 2>/dev/null | sort -rn | head -n 1 | cut -d' ' -f2- | xargs -r zcat -f 2>/dev/null",
            quoted_dirs.join(" "),
            find_time
        )
    } else {
        format!(
            "find {} -maxdepth 2 -type f \\( -name '*.log' -o -name '*.log.1' -o -name '*access*.gz' \\) {} 2>/dev/null | head -n 50 | xargs -r zcat -f 2>/dev/null",
            quoted_dirs.join(" "),
            find_time
        )
    };

    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=10");
    if let Some(port) = profile.ssh_port {
        cmd.arg("-p").arg(port.to_string());
    }
    if let Some(ref key_path) = profile.ssh_key {
        let kp = key_path.trim();
        if !kp.is_empty() && !kp.starts_with('-') {
            cmd.arg("-i").arg(kp);
        }
    }
    cmd.arg("--").arg(&ssh_target).arg(&remote_cmd);

    let out = cmd.output()?;
    if !out.status.success() && out.stdout.is_empty() {
        let err_str = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("SSH error: {}", err_str);
    }

    if out.stdout.is_empty() {
        return Ok((
            Vec::new(),
            None,
            0,
            format!("ssh://{}:{}", ssh_target, dirs_arg),
        ));
    }

    let safe_srv_tag: String = srv
        .name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let tmp_path = std::env::temp_dir().join(format!(
        "lpr_ssh_{}_{}.log",
        safe_srv_tag,
        std::process::id()
    ));
    fs::write(&tmp_path, &out.stdout)?;

    let engine = LogEngine::with_options(threads, verbose);
    let server_type = profile.server_type.as_deref().unwrap_or("auto");
    let fmt = parse_stack_input_format(server_type);
    let tmp_str = tmp_path.to_string_lossy().to_string();

    let res = engine.register_source("logs", &tmp_str, fmt, None).await;
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    let cols = engine.table_columns("logs").await;
    let sql = custom_sql
        .map(|s| s.to_string())
        .unwrap_or_else(|| build_multi_format_error_sql(&cols, status_prefix, cutoff_date, None));
    let batches = engine.query(&sql).await?;
    if custom_sql.is_some() {
        let mut gcols = Vec::new();
        let grows = extract_generic_rows(&batches, &mut gcols, &srv.name, &srv.ip);
        let _ = fs::remove_file(&tmp_path);
        return Ok((
            Vec::new(),
            Some((gcols, grows)),
            1,
            format!("ssh://{}:{}", ssh_target, dirs_arg),
        ));
    }
    let mut rows = extract_fleet_rows(&batches, &srv.name, &srv.ip);
    for r in &mut rows {
        if r.log_file.starts_with("lpr_ssh_") {
            r.log_file = format!("ssh://{}:{}", srv.name, dirs_arg);
        }
    }
    let _ = fs::remove_file(&tmp_path);

    Ok((
        rows,
        None,
        1,
        format!("ssh://{}:{}", ssh_target, dirs_arg),
    ))
}

// ================================================================================================
// DETERMINISTIC SESSION INTELLIGENCE LEARNER & CROSS-SERVER USER JOURNEY ENGINE (ZERO AI)
// ================================================================================================

#[derive(Debug, Clone, Serialize)]
pub struct FleetJourneyCsvRow {
    #[serde(rename = "JourneyID")]
    pub journey_id: usize,
    #[serde(rename = "ActorIdentity")]
    pub actor_identity: String,
    #[serde(rename = "MatchedBy")]
    pub matched_by: String,
    #[serde(rename = "StepNumber")]
    pub step_number: usize,
    #[serde(rename = "StepRole")]
    pub step_role: String,
    #[serde(rename = "DeltaSeconds")]
    pub delta_seconds: String,
    #[serde(rename = "ServerHop")]
    pub server_hop: String,
    #[serde(rename = "ServerName")]
    pub server_name: String,
    #[serde(rename = "ServerIP")]
    pub server_ip: String,
    #[serde(rename = "Date")]
    pub date: String,
    #[serde(rename = "Time")]
    pub time: String,
    #[serde(rename = "ClientIP")]
    pub client_ip: String,
    #[serde(rename = "ForwardedIP")]
    pub forwarded_ip: String,
    #[serde(rename = "Method")]
    pub method: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "SubStatus")]
    pub sub_status: String,
    #[serde(rename = "TimeTakenMs")]
    pub time_taken_ms: String,
    #[serde(rename = "UriStem")]
    pub uri_stem: String,
    #[serde(rename = "UriQuery")]
    pub uri_query: String,
    #[serde(rename = "RedirectTarget")]
    pub redirect_target: String,
    #[serde(rename = "Referer")]
    pub referer: String,
    #[serde(rename = "UserAgent")]
    pub user_agent: String,
    #[serde(rename = "LogFile")]
    pub log_file: String,
    #[serde(rename = "LogRow")]
    pub log_row: String,
}

fn is_identity_key_name(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "session",
        "sess",
        "sid",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspsessionid",
        "customer",
        "cust",
        "userid",
        "user_id",
        "visitor",
        "visit",
        "cart",
        "basket",
        "order",
        "payment",
        "checkout",
        "token",
        "auth",
        "shop_session",
        "cf_clearance",
        "_ga",
        "guid",
        "uuid",
        "correlation",
        "trace",
        "transaction",
    ];
    PATTERNS.iter().any(|p| k.contains(p))
}

fn is_ignored_static_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "lang"
            | "language"
            | "locale"
            | "country"
            | "currency"
            | "page"
            | "sort"
            | "limit"
            | "offset"
            | "size"
            | "color"
            | "category"
            | "v"
            | "ver"
            | "version"
            | "format"
    )
}

/// Parses `cs(Cookie)` strings (`name=val; name2=val2` or IIS `+`-separated `name=val;+name2=val2`) into `(name, value)` pairs.
fn parse_cookie_pairs(raw_cookie: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let trimmed = raw_cookie.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return out;
    }
    for part in trimmed.split(';') {
        let clean = part.trim().trim_start_matches('+').trim();
        if let Some((k, v)) = clean.split_once('=') {
            let k_clean = k.trim();
            let v_clean = v.trim().trim_matches('"');
            if !k_clean.is_empty() && v_clean.len() >= 3 && v_clean != "-" {
                out.push((k_clean.to_string(), v_clean.to_string()));
            }
        }
    }
    out
}

/// Parses `cs-uri-query` strings (`k=v&k2=v2`) into `(name, value)` pairs.
fn parse_query_pairs(raw_query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let trimmed = raw_query.trim().trim_start_matches('?');
    if trimmed.is_empty() || trimmed == "-" {
        return out;
    }
    for part in trimmed.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let k_clean = k.trim();
            let v_clean = v.trim();
            if !k_clean.is_empty() && v_clean.len() >= 2 && v_clean != "-" {
                out.push((k_clean.to_string(), v_clean.to_string()));
            }
        }
    }
    out
}

/// Deterministically analyzes a sample of log files to discover:
/// - Available W3C/log columns
/// - Client IP & Forwarded IP columns (`x_forwarded_for`, `cf_connecting_ip`, `c_ip`, etc.)
/// - High-cardinality identity/session cookies (`cs(Cookie)`) using cardinality & repeat-hit statistics
/// - Query-string correlation parameters (`cs-uri-query`)
/// - Redirect target column (`sc(Location)`)
pub async fn learn_session_intelligence_from_items(
    items: &[crate::parsers::LogSourceItem],
    threads: Option<usize>,
) -> Result<SessionIntelligence> {
    if items.is_empty() {
        anyhow::bail!("No log files available to learn session intelligence");
    }
    let engine = LogEngine::with_options(threads, false);
    engine
        .register_source_items_filtered(
            "logs",
            items.to_vec(),
            InputFormat::Auto,
            None,
            None,
            None,
            None,
        )
        .await?;
    let cols = engine.table_columns("logs").await;
    let batches = engine.query("SELECT * FROM logs LIMIT 10000").await?;
    let rows = extract_fleet_rows(&batches, "SAMPLE", "127.0.0.1");

    // 1. Discover IP columns in priority order (Forwarded-For first, then c_ip)
    let mut ip_cols = Vec::new();
    for candidate in [
        "x_forwarded_for",
        "csx_forwarded_for",
        "cf_connecting_ip",
        "true_client_ip",
        "x_real_ip",
        "forwarded_for",
        "client_ip",
        "c_ip",
        "remote_addr",
    ] {
        if cols.iter().any(|c| c.eq_ignore_ascii_case(candidate)) {
            ip_cols.push(candidate.to_string());
        }
    }

    // 2. Discover redirect location column if logged
    let redirect_col = ["sclocation", "sc_location", "location", "redirect_url"]
        .into_iter()
        .find(|cand| cols.iter().any(|c| c.eq_ignore_ascii_case(cand)))
        .map(|s| s.to_string());

    // 3. Score cookie keys by cardinality & repeat-visit continuity (Zero AI)
    // Map: cookie_name -> HashMap<cookie_value, hit_count>
    let mut cookie_stats: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut query_stats: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();

    for r in &rows {
        for (k, v) in parse_cookie_pairs(&r.cookie) {
            if !is_ignored_static_key(&k) {
                *cookie_stats.entry(k).or_default().entry(v).or_insert(0) += 1;
            }
        }
        for (k, v) in parse_query_pairs(&r.uri_query) {
            if !is_ignored_static_key(&k) {
                *query_stats.entry(k).or_default().entry(v).or_insert(0) += 1;
            }
        }
    }

    let mut scored_cookies: Vec<(String, usize)> = cookie_stats
        .into_iter()
        .filter_map(|(k, val_map)| {
            let unique_vals = val_map.len();
            let multi_hit_vals = val_map.values().filter(|&&c| c >= 2).count();
            let avg_val_len =
                val_map.keys().map(|v| v.len()).sum::<usize>() / unique_vals.max(1);
            let name_match = is_identity_key_name(&k);
            // Keep if it matches known session/customer/cart naming OR has >= 2 distinct values with session-like length
            if name_match || (unique_vals >= 2 && avg_val_len >= 6) {
                let score = (if name_match { 1000 } else { 0 })
                    + unique_vals * 10
                    + multi_hit_vals * 25
                    + avg_val_len.min(64);
                Some((k, score))
            } else {
                None
            }
        })
        .collect();
    scored_cookies.sort_by(|a, b| b.1.cmp(&a.1));

    let mut identity_cookies: Vec<String> =
        scored_cookies.into_iter().take(10).map(|(k, _)| k).collect();
    if identity_cookies.is_empty() {
        // Default enterprise IIS/web session cookie priority list when sample had no cookies yet
        identity_cookies = vec![
            "ASP.NET_SessionId".to_string(),
            "SessionId".to_string(),
            "shop_session".to_string(),
            "customerId".to_string(),
            "visitorId".to_string(),
            "cartId".to_string(),
            "PHPSESSID".to_string(),
            "JSESSIONID".to_string(),
        ];
    }

    let mut scored_queries: Vec<(String, usize)> = query_stats
        .into_iter()
        .filter_map(|(k, val_map)| {
            let unique_vals = val_map.len();
            let multi_hit_vals = val_map.values().filter(|&&c| c >= 2).count();
            let name_match = is_identity_key_name(&k);
            if name_match || (unique_vals >= 2 && multi_hit_vals >= 1) {
                let score =
                    (if name_match { 1000 } else { 0 }) + unique_vals * 10 + multi_hit_vals * 25;
                Some((k, score))
            } else {
                None
            }
        })
        .collect();
    scored_queries.sort_by(|a, b| b.1.cmp(&a.1));

    let mut query_correlators: Vec<String> =
        scored_queries.into_iter().take(10).map(|(k, _)| k).collect();
    if query_correlators.is_empty() {
        query_correlators = vec![
            "customerId".to_string(),
            "customer_id".to_string(),
            "orderId".to_string(),
            "order_id".to_string(),
            "paymentId".to_string(),
            "cartId".to_string(),
            "sessionId".to_string(),
            "token".to_string(),
        ];
    }

    Ok(SessionIntelligence {
        learned_at_utc: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        sample_rows_analyzed: rows.len(),
        detected_columns: cols,
        identity_cookies,
        query_correlators,
        client_ip_columns: ip_cols,
        redirect_location_column: redirect_col,
    })
}

pub fn print_session_intelligence_summary(profile_name: &str, intel: &SessionIntelligence) {
    println!("--------------------------------------------------------------------------------");
    println!(
        " {SYM_BRAIN} DETERMINISTIC SESSION INTELLIGENCE LEARNED & SAVED (Profile: `{}`)",
        profile_name
    );
    println!(
        "    Sample Analyzed   : {} log rows | Columns Detected: {}",
        format_int_commas(intel.sample_rows_analyzed),
        intel.detected_columns.len()
    );
    println!(
        "    Client IP Columns : {:?}",
        intel.client_ip_columns
    );
    println!(
        "    Identity Cookies  : {:?}",
        intel.identity_cookies
    );
    println!(
        "    Query Correlators : {:?}",
        intel.query_correlators
    );
    println!(
        "    Redirect Column   : {:?}",
        intel
            .redirect_location_column
            .as_deref()
            .unwrap_or("Not logged (will infer 302 target from next chronological hit)")
    );
    println!("--------------------------------------------------------------------------------");
}

#[derive(Debug, Clone)]
struct JourneyActor {
    /// Human-readable label for the customer/session (e.g. `Cookie:ASP.NET_SessionId=8f92a...` or `IP:198.51.100.42`)
    actor_label: String,
    /// How this actor was correlated (`Cookie`, `QueryParam`, `ForwardedIP+UA`, `ClientIP+UA`, `DirectTraceID`)
    matched_by: String,
    /// Raw ASCII substrings (`session_val`, `customer_id`, `forwarded_ip`, `client_ip`) used for raw-byte pushdown across all 24 servers
    raw_needles: Vec<String>,
    /// Exact cookie values `(key, val)` belonging to this actor
    cookie_tokens: Vec<(String, String)>,
    /// Exact query parameter values `(key, val)` belonging to this actor
    query_tokens: Vec<(String, String)>,
    /// Forwarded IP (`X-Forwarded-For`) if present
    forwarded_ip: String,
    /// Clear Client IP (`c-ip`)
    client_ip: String,
    /// User-Agent string (used when falling back to IP+UA correlation)
    user_agent: String,
}

impl JourneyActor {
    fn matches_row(&self, row: &FleetErrorRow, explicit_trace_id: Option<&str>) -> Option<String> {
        if let Some(tid) = explicit_trace_id {
            let tl = tid.to_ascii_lowercase();
            if row.cookie.to_ascii_lowercase().contains(&tl)
                || row.uri_query.to_ascii_lowercase().contains(&tl)
                || row.uri_stem.to_ascii_lowercase().contains(&tl)
                || row.forwarded_ip.eq_ignore_ascii_case(tid)
                || row.client_ip.eq_ignore_ascii_case(tid)
            {
                return Some(format!("TraceID({})", tid));
            }
        }
        // Tier 1: Identity Cookie match (works across non-sticky servers even if IP changes!)
        if !self.cookie_tokens.is_empty() && !row.cookie.is_empty() {
            let row_cookies = parse_cookie_pairs(&row.cookie);
            for (tk, tv) in &self.cookie_tokens {
                if row_cookies
                    .iter()
                    .any(|(rk, rv)| rk.eq_ignore_ascii_case(tk) && rv == tv)
                {
                    return Some(format!("Cookie({}={})", tk, tv));
                }
            }
        }
        // Tier 2: Query-String Correlator match (e.g. orderId, customerId, cartId, paymentId)
        if !self.query_tokens.is_empty() && !row.uri_query.is_empty() {
            let row_q = parse_query_pairs(&row.uri_query);
            for (qk, qv) in &self.query_tokens {
                if row_q
                    .iter()
                    .any(|(rk, rv)| rk.eq_ignore_ascii_case(qk) && rv == qv)
                {
                    return Some(format!("Query({}={})", qk, qv));
                }
            }
        }
        // Tier 3: X-Forwarded-For IP
        if !self.forwarded_ip.is_empty()
            && row.forwarded_ip.eq_ignore_ascii_case(&self.forwarded_ip)
        {
            return Some(
                if !self.user_agent.is_empty() && row.user_agent == self.user_agent {
                    format!("ForwardedIP+UA({})", self.forwarded_ip)
                } else {
                    format!("ForwardedIP({})", self.forwarded_ip)
                },
            );
        }
        // Tier 4: Clear Client IP (`c-ip`)
        if !self.client_ip.is_empty() && row.client_ip.eq_ignore_ascii_case(&self.client_ip) {
            return Some(
                if !self.user_agent.is_empty() && row.user_agent == self.user_agent {
                    format!("ClientIP+UA({})", self.client_ip)
                } else {
                    format!("ClientIP({})", self.client_ip)
                },
            );
        }
        None
    }
}

fn build_actors_from_trigger_rows(
    trigger_rows: &[FleetErrorRow],
    explicit_trace_id: Option<&str>,
    intel: Option<&SessionIntelligence>,
    max_journeys: usize,
) -> Vec<JourneyActor> {
    let mut actors: Vec<JourneyActor> = Vec::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    let id_cookies: Vec<String> = intel
        .map(|i| i.identity_cookies.clone())
        .unwrap_or_else(|| {
            vec![
                "ASP.NET_SessionId".to_string(),
                "SessionId".to_string(),
                "shop_session".to_string(),
                "customerId".to_string(),
                "visitorId".to_string(),
                "cartId".to_string(),
            ]
        });
    let q_keys: Vec<String> = intel
        .map(|i| i.query_correlators.clone())
        .unwrap_or_else(|| {
            vec![
                "customerId".to_string(),
                "orderId".to_string(),
                "paymentId".to_string(),
                "cartId".to_string(),
                "sessionId".to_string(),
                "token".to_string(),
            ]
        });

    for r in trigger_rows {
        if actors.len() >= max_journeys {
            break;
        }
        let mut cookie_tokens = Vec::new();
        for (ck, cv) in parse_cookie_pairs(&r.cookie) {
            if id_cookies.iter().any(|ic| ic.eq_ignore_ascii_case(&ck)) || is_identity_key_name(&ck)
            {
                cookie_tokens.push((ck, cv));
            }
        }
        let mut query_tokens = Vec::new();
        for (qk, qv) in parse_query_pairs(&r.uri_query) {
            if q_keys.iter().any(|iq| iq.eq_ignore_ascii_case(&qk)) || is_identity_key_name(&qk) {
                query_tokens.push((qk, qv));
            }
        }

        // Determine primary actor identity key so multiple trigger hits from the same customer group into 1 journey
        let (dedup_key, actor_label, matched_by) = if let Some(tid) = explicit_trace_id {
            (
                format!("TID:{}", tid.to_ascii_lowercase()),
                format!("TraceID={}", tid),
                "DirectTraceID".to_string(),
            )
        } else if let Some((ck, cv)) = cookie_tokens.first() {
            (
                format!("COOKIE:{}={}", ck.to_ascii_lowercase(), cv),
                format!("{}={}", ck, cv),
                format!("Cookie({})", ck),
            )
        } else if let Some((qk, qv)) = query_tokens.first() {
            (
                format!("QUERY:{}={}", qk.to_ascii_lowercase(), qv),
                format!("{}={}", qk, qv),
                format!("QueryParam({})", qk),
            )
        } else if !r.forwarded_ip.is_empty() {
            (
                format!("XFF:{}|{}", r.forwarded_ip, r.user_agent),
                format!("ForwardedIP={}", r.forwarded_ip),
                "ForwardedIP+UA".to_string(),
            )
        } else if !r.client_ip.is_empty() {
            (
                format!("CIP:{}|{}", r.client_ip, r.user_agent),
                format!("ClientIP={}", r.client_ip),
                "ClientIP+UA".to_string(),
            )
        } else {
            continue;
        };

        if let Some(existing) = actors.iter_mut().find(|a| a.actor_label == actor_label) {
            // Enrich existing actor with any newly seen cookie/query/IP on subsequent trigger rows
            for ct in cookie_tokens {
                if !existing.cookie_tokens.contains(&ct) {
                    if ct.1.len() >= 4 {
                        existing.raw_needles.push(ct.1.to_ascii_lowercase());
                    }
                    existing.cookie_tokens.push(ct);
                }
            }
            for qt in query_tokens {
                if !existing.query_tokens.contains(&qt) {
                    if qt.1.len() >= 3 {
                        existing.raw_needles.push(qt.1.to_ascii_lowercase());
                    }
                    existing.query_tokens.push(qt);
                }
            }
            if existing.forwarded_ip.is_empty() && !r.forwarded_ip.is_empty() {
                existing.forwarded_ip = r.forwarded_ip.clone();
                existing
                    .raw_needles
                    .push(r.forwarded_ip.to_ascii_lowercase());
            }
            if existing.client_ip.is_empty() && !r.client_ip.is_empty() {
                existing.client_ip = r.client_ip.clone();
                existing.raw_needles.push(r.client_ip.to_ascii_lowercase());
            }
            continue;
        }

        if !seen_keys.insert(dedup_key) {
            continue;
        }

        let mut raw_needles = Vec::new();
        if let Some(tid) = explicit_trace_id {
            raw_needles.push(tid.to_ascii_lowercase());
        }
        for (_, cv) in &cookie_tokens {
            if cv.len() >= 4 {
                raw_needles.push(cv.to_ascii_lowercase());
            }
        }
        for (_, qv) in &query_tokens {
            if qv.len() >= 3 {
                raw_needles.push(qv.to_ascii_lowercase());
            }
        }
        if !r.forwarded_ip.is_empty() {
            raw_needles.push(r.forwarded_ip.to_ascii_lowercase());
        }
        if !r.client_ip.is_empty() {
            raw_needles.push(r.client_ip.to_ascii_lowercase());
        }
        raw_needles.sort();
        raw_needles.dedup();

        actors.push(JourneyActor {
            actor_label,
            matched_by,
            raw_needles,
            cookie_tokens,
            query_tokens,
            forwarded_ip: r.forwarded_ip.clone(),
            client_ip: r.client_ip.clone(),
            user_agent: r.user_agent.clone(),
        });
    }

    actors
}

fn parse_row_epoch_secs(date: &str, time: &str) -> Option<i64> {
    let dt_str = format!("{} {}", date.trim(), time.trim());
    chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| ndt.and_utc().timestamp())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_cross_server_journey_tracer(
    server_sources: &[(
        ServerEntry,
        Vec<crate::parsers::LogSourceItem>,
        String,
        InputFormat,
    )],
    trigger_rows: &[FleetErrorRow],
    explicit_trace_id: Option<&str>,
    trace_window_mins: i64,
    max_journeys: usize,
    intel: Option<&SessionIntelligence>,
    cutoff_date: &str,
    cutoff_time: Option<&str>,
    output_dir: &str,
    report_prefix: &str,
    run_stamp: &str,
    threads: Option<usize>,
    verbose: bool,
) -> Result<()> {
    let trace_start = std::time::Instant::now();
    let actors =
        build_actors_from_trigger_rows(trigger_rows, explicit_trace_id, intel, max_journeys);
    if actors.is_empty() {
        return Ok(());
    }

    // Collect union of all raw-byte search needles across all actors (Session IDs, Customer IDs, Forwarded IPs, Clear IPs)
    let mut union_needles: Vec<String> = Vec::new();
    for a in &actors {
        for n in &a.raw_needles {
            if !n.is_empty() && !union_needles.contains(n) {
                union_needles.push(n.clone());
            }
        }
    }

    println!("================================================================================");
    println!(
        " {SYM_SEARCH} CROSS-SERVER USER JOURNEY RECONSTRUCTION (Tracing {} Customer/Session Actor(s) across {} Server(s))",
        actors.len(),
        server_sources.len()
    );
    println!(
        " {SYM_ZAP} Journey Needles   : {:?} (Window: +/- {} mins around trigger events)",
        union_needles, trace_window_mins
    );
    println!("--------------------------------------------------------------------------------");

    let journey_pre_filter = ScanPreFilter {
        min_date: Some(cutoff_date.to_string()),
        min_time: cutoff_time.map(|t| t.to_string()),
        status_prefix: None, // Capture ALL status codes (200, 301, 302, 400, 500) in the customer's journey!
        required_substrings: Vec::new(),
        any_substrings: union_needles,
    };

    let mut candidate_rows: Vec<FleetErrorRow> = Vec::new();
    for (srv, items, joined_pattern, input_fmt) in server_sources {
        let engine = LogEngine::with_options(threads, verbose);
        if engine
            .register_source_items_filtered(
                "logs",
                items.clone(),
                *input_fmt,
                None,
                None,
                Some(joined_pattern),
                Some(&journey_pre_filter),
            )
            .await
            .is_ok()
        {
            let cols = engine.table_columns("logs").await;
            let sql = build_multi_format_error_sql(&cols, "*", cutoff_date, cutoff_time);
            if let Ok(batches) = engine.query(&sql).await {
                let rows = extract_fleet_rows(&batches, &srv.name, &srv.ip);
                candidate_rows.extend(rows);
            }
        }
    }

    // Build a fast lookup set of trigger row signatures (`server|date|time|uri_stem|status|log_row`)
    let trigger_sigs: HashSet<String> = trigger_rows
        .iter()
        .map(|r| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                r.server_name, r.date, r.time, r.uri_stem, r.status, r.log_row
            )
        })
        .collect();

    let window_secs = trace_window_mins.max(1) * 60;
    let mut all_journey_csv_rows: Vec<FleetJourneyCsvRow> = Vec::new();

    for (j_idx, actor) in actors.iter().enumerate() {
        let journey_id = j_idx + 1;
        // Find all candidate rows belonging to this actor
        let mut matched_steps: Vec<(FleetErrorRow, String, Option<i64>, bool)> = Vec::new();
        let mut trigger_timestamps: Vec<i64> = Vec::new();

        for r in &candidate_rows {
            if let Some(reason) = actor.matches_row(r, explicit_trace_id) {
                let sig = format!(
                    "{}|{}|{}|{}|{}|{}",
                    r.server_name, r.date, r.time, r.uri_stem, r.status, r.log_row
                );
                let is_trig = trigger_sigs.contains(&sig);
                let ts = parse_row_epoch_secs(&r.date, &r.time);
                if is_trig {
                    if let Some(t) = ts {
                        trigger_timestamps.push(t);
                    }
                }
                matched_steps.push((r.clone(), reason, ts, is_trig));
            }
        }

        // Filter steps to within +/- trace_window_mins of at least one trigger timestamp (unless explicit_trace_id is used)
        if explicit_trace_id.is_none() && !trigger_timestamps.is_empty() {
            matched_steps.retain(|(_, _, ts_opt, is_trig)| {
                if *is_trig {
                    return true;
                }
                match ts_opt {
                    Some(t) => trigger_timestamps
                        .iter()
                        .any(|trig_t| (*t - *trig_t).abs() <= window_secs),
                    None => true,
                }
            });
        }

        // Sort chronologically across all servers by (date, time, log_row)
        matched_steps.sort_by(|a, b| {
            a.0.date
                .cmp(&b.0.date)
                .then_with(|| a.0.time.cmp(&b.0.time))
                .then_with(|| {
                    a.0.log_row
                        .parse::<usize>()
                        .unwrap_or(0)
                        .cmp(&b.0.log_row.parse::<usize>().unwrap_or(0))
                })
        });

        // Deduplicate identical log rows if any
        matched_steps.dedup_by(|a, b| {
            a.0.server_name == b.0.server_name
                && a.0.date == b.0.date
                && a.0.time == b.0.time
                && a.0.log_file == b.0.log_file
                && a.0.log_row == b.0.log_row
        });

        if matched_steps.is_empty() {
            continue;
        }

        let unique_servers: HashSet<&str> = matched_steps
            .iter()
            .map(|s| s.0.server_name.as_str())
            .collect();
        let first_ts = matched_steps.first().and_then(|s| s.2);

        println!(
            "\n  {SYM_BULLET} JOURNEY #{} | Actor: {} ({}) | Steps: {} across {} server(s)",
            journey_id,
            actor.actor_label,
            actor.matched_by,
            matched_steps.len(),
            unique_servers.len()
        );
        println!(
            "    {:>4}  {:19}  {:>7}  {:14}  {:6}  {:6}  {:42}  {}",
            "Step", "Date & Time (UTC)", "Delta", "Server", "Method", "Status", "URI + Query", "Evidence / Role"
        );
        println!(
            "    ----  -------------------  -------  --------------  ------  ------  ------------------------------------------  ------------------------------"
        );

        let mut prev_server = String::new();
        let mut prev_was_redirect = false;

        for (s_idx, (row, match_reason, ts_opt, is_trig)) in matched_steps.iter().enumerate() {
            let step_num = s_idx + 1;
            let delta_str = match (first_ts, ts_opt) {
                (Some(t0), Some(t)) => format!("+{:.0}s", (*t - t0).max(0) as f64),
                _ => "+0s".to_string(),
            };
            let server_hop = if !prev_server.is_empty() && prev_server != row.server_name {
                format!("{}->{}", prev_server, row.server_name)
            } else {
                String::new()
            };
            prev_server = row.server_name.clone();

            let is_30x = matches!(row.status.as_str(), "301" | "302" | "303" | "307" | "308");
            // Infer redirect target either from `sc(Location)` or from the immediate next step in the user's journey!
            let inferred_redirect_target = if !row.redirect_location.is_empty() {
                row.redirect_location.clone()
            } else if is_30x {
                matched_steps
                    .get(s_idx + 1)
                    .map(|next| {
                        if next.0.uri_query.is_empty() {
                            format!("{} (on {})", next.0.uri_stem, next.0.server_name)
                        } else {
                            format!(
                                "{}?{} (on {})",
                                next.0.uri_stem, next.0.uri_query, next.0.server_name
                            )
                        }
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let step_role = if *is_trig && is_30x {
                "TRIGGER_302_REDIRECT"
            } else if *is_trig {
                "TRIGGER_EVENT"
            } else if prev_was_redirect {
                "REDIRECT_LANDING"
            } else if step_num == 1 {
                "ENTRY"
            } else {
                "STEP"
            };
            prev_was_redirect = is_30x;

            let full_uri = if row.uri_query.is_empty() || row.uri_query == "-" {
                row.uri_stem.clone()
            } else {
                format!("{}?{}", row.uri_stem, row.uri_query)
            };
            let uri_disp = if full_uri.len() > 42 {
                format!("{}...", &full_uri[..39])
            } else {
                full_uri.clone()
            };

            let mut note_parts = vec![step_role.to_string()];
            if !inferred_redirect_target.is_empty() {
                note_parts.push(format!("-> To: {}", inferred_redirect_target));
            }
            if !server_hop.is_empty() {
                note_parts.push(format!("[Hop: {}]", server_hop));
            }
            if step_num == 1 && !row.referer.is_empty() && row.referer != "-" {
                note_parts.push(format!("Ref: {}", row.referer));
            }

            println!(
                "    {:>4}  {:10} {:8}  {:>7}  {:14}  {:6}  {:6}  {:42}  {}",
                step_num,
                row.date,
                row.time,
                delta_str,
                row.server_name,
                row.method,
                row.status,
                uri_disp,
                note_parts.join(" | ")
            );

            all_journey_csv_rows.push(FleetJourneyCsvRow {
                journey_id,
                actor_identity: actor.actor_label.clone(),
                matched_by: match_reason.clone(),
                step_number: step_num,
                step_role: step_role.to_string(),
                delta_seconds: delta_str,
                server_hop,
                server_name: row.server_name.clone(),
                server_ip: row.server_ip.clone(),
                date: row.date.clone(),
                time: row.time.clone(),
                client_ip: row.client_ip.clone(),
                forwarded_ip: row.forwarded_ip.clone(),
                method: row.method.clone(),
                status: row.status.clone(),
                sub_status: row.sub_status.clone(),
                time_taken_ms: row.time_taken_ms.clone(),
                uri_stem: row.uri_stem.clone(),
                uri_query: row.uri_query.clone(),
                redirect_target: inferred_redirect_target,
                referer: row.referer.clone(),
                user_agent: row.user_agent.clone(),
                log_file: row.log_file.clone(),
                log_row: row.log_row.clone(),
            });
        }
    }

    let safe_prefix: String = report_prefix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_' | '.'))
        .collect();
    let safe_prefix = if safe_prefix.is_empty() || safe_prefix.contains("..") {
        "IIS-Errors"
    } else {
        &safe_prefix
    };
    let journey_csv = PathBuf::from(output_dir).join(format!(
        "{}-Journeys-{}.csv",
        safe_prefix, run_stamp
    ));
    {
        let mut wtr = csv::Writer::from_path(&journey_csv)?;
        for jrow in &all_journey_csv_rows {
            wtr.serialize(jrow)?;
        }
        wtr.flush()?;
    }

    println!("\n--------------------------------------------------------------------------------");
    println!(
        " {SYM_DONE} Journey Reconstruction Complete: {} total step(s) across {} customer journey(s) in {:.2}s",
        format_int_commas(all_journey_csv_rows.len()),
        actors.len(),
        trace_start.elapsed().as_secs_f64()
    );
    println!(
        " {SYM_FILE} Journeys CSV      : {}",
        journey_csv.to_string_lossy()
    );
    println!("================================================================================");

    Ok(())
}
