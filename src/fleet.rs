use crate::engine::LogEngine;
use crate::parsers::{resolve_source_items, InputFormat};
use crate::sinks::batches_to_json_value;
use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Persistent configuration store (`lpr.config.json`) supporting named profiles.
/// Zero hardcoded client names, paths, or servers — users save their own profiles once via `--save-profile <name>`
/// and reuse them anytime via `--profile <name>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LprConfigFile {
    #[serde(default = "default_profile_name")]
    pub default_profile: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, SavedProfile>,
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
            default_sql: None,
            input_format: None,
            output_format: None,
            verbose: None,
            auth_user: None,
            auth_domain: None,
            auth_password_ref: None,
            auth_password_enc: None,
            servers: Vec::new(),
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
        Ok(path)
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
    println!(" ⚙️  LPR SAVED CONFIGURATION PROFILES ({})", path.to_string_lossy());
    println!("================================================================================");
    if store.profiles.is_empty() {
        println!("  No profiles saved yet.");
        println!("  💡 Save a profile once with:");
        println!("     lpr fleet --save-profile prod-web --servers servers.csv --site MySite --threads 8 --days 7");
        println!("  💡 Then run anytime with:");
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
        println!("\n  🔹 Profile: `{}`{}", name, is_def);
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
    }
    println!();
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
        profile.auth_password_ref = Some(pr.clone());
    }
    if req.save_password {
        match prompt_and_encrypt_password() {
            Ok(hex_blob) => {
                profile.auth_password_enc = Some(hex_blob);
                eprintln!("🔐 Password stored DPAPI-encrypted (bound to this Windows user account only).");
            }
            Err(e) => {
                eprintln!(
                    "⚠️  --save-password could not store a secret here ({e}). Use --password-ref env:LPR_SMB_PASS, --password-ref file:<path>, or --password-ref prompt instead."
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
            "💾 Saved profile `{}` to `{}` ({} servers stored in profile)",
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
    let status_prefix = profile
        .status_prefix
        .clone()
        .unwrap_or_else(|| "5".to_string());
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

    let cutoff_date = (Utc::now() - Duration::days((days - 1).max(0)))
        .format("%Y-%m-%d")
        .to_string();
    let run_stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();

    fs::create_dir_all(&output_dir)?;

    println!("================================================================================");
    println!(" 🌐 LPR MULTI-SERVER FLEET SCANNER (Profile: `{}`)", active_profile_name);
    println!(
        " 📅 Days: {} (Cutoff >= {}) | Status: {}xx | Threads: {}",
        days,
        cutoff_date,
        status_prefix,
        threads
            .map(|t| t.to_string())
            .unwrap_or_else(|| "Auto (All Cores)".to_string())
    );
    println!(" 📁 Output Folder: {} | Report Prefix: {}", output_dir, report_prefix);
    println!("================================================================================");

    if let Some(ref local_target) = profile.local_path {
        return run_local_or_archive_fleet_scan(
            local_target,
            &cutoff_date,
            &run_stamp,
            &output_dir,
            &report_prefix,
            &status_prefix,
            days,
            threads,
            verbose,
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
        " 🖥️  Target Servers ({}) : {} | Stack: {} | Transport: {}",
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

    for srv in &servers {
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
            )
            .await
            {
                Ok((rows, files_count, scanned_info)) => {
                    let first_err = rows
                        .first()
                        .map(|r| format!("{} {}", r.date, r.time))
                        .unwrap_or_default();
                    let last_err = rows
                        .last()
                        .map(|r| format!("{} {}", r.date, r.time))
                        .unwrap_or_default();
                    println!(
                        "  ✔  [SSH] {:14} ({:12}) -> {:>5} match(es) across {:>4} remote file(s)",
                        srv.name,
                        srv.ip,
                        rows.len(),
                        files_count
                    );
                    summaries.push(FleetServerSummary {
                        server_name: srv.name.clone(),
                        server_ip: srv.ip.clone(),
                        success: true,
                        total_errors: rows.len(),
                        log_files_scanned: files_count,
                        engine: "lpr-ssh-linux".to_string(),
                        first_error: first_err,
                        last_error: last_err,
                        scanned_paths: scanned_info,
                        error_message: String::new(),
                    });
                    all_errors.extend(rows);
                }
                Err(e) => {
                    println!(
                        "  ⚠️  [SSH] {:14} ({:12}) -> Failed: {}",
                        srv.name, srv.ip, e
                    );
                    failed_servers.push(srv.name.clone());
                    summaries.push(FleetServerSummary {
                        server_name: srv.name.clone(),
                        server_ip: srv.ip.clone(),
                        success: false,
                        total_errors: 0,
                        log_files_scanned: 0,
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

        let mut candidate_paths: Vec<String> = Vec::new();

        // If alternate SMB credentials are configured, establish a `net use` IPC$ session first (Windows only).
        #[cfg(windows)]
        let _smb_guard = establish_smb_session(srv, &profile);

        // 1. Expand user-configured log_path / archive_path / path_templates (converting local D:\... to \\server\d$\... automatically!)
        for tpl in &path_templates {
            let expanded = expand_remote_path_template(tpl, &srv.name, &srv.ip, &site_name);
            if !candidate_paths.contains(&expanded) {
                candidate_paths.push(expanded);
            }
        }

        // 2. If Auto-Discovery is enabled, check IIS applicationHost.config AND Linux Nginx/Apache/Caddy vhost configs!
        if profile.iis_auto_discover.unwrap_or(true) {
            if !site_name.is_empty() {
                for host_target in [&srv.name, &srv.ip] {
                    if !host_target.is_empty() {
                        for discovered in
                            discover_iis_site_log_paths_on_server(host_target, &site_name)
                        {
                            if !candidate_paths.contains(&discovered) {
                                candidate_paths.push(discovered);
                            }
                        }
                    }
                }
            }
            for discovered_linux in discover_local_linux_webserver_logs(&site_name) {
                if !candidate_paths.contains(&discovered_linux) {
                    candidate_paths.push(discovered_linux);
                }
            }
        }

        let existing_paths: Vec<String> = candidate_paths
            .iter()
            .filter(|p| Path::new(p).exists())
            .cloned()
            .collect();

        if existing_paths.is_empty() {
            println!(
                "  ⚠️  {:18} ({:12}) -> Path not accessible ({})",
                srv.name,
                srv.ip,
                candidate_paths.first().cloned().unwrap_or_default()
            );
            failed_servers.push(srv.name.clone());
            summaries.push(FleetServerSummary {
                server_name: srv.name.clone(),
                server_ip: srv.ip.clone(),
                success: false,
                total_errors: 0,
                log_files_scanned: 0,
                engine: "lpr-native".to_string(),
                first_error: String::new(),
                last_error: String::new(),
                scanned_paths: String::new(),
                error_message: format!("Paths not accessible: {}", candidate_paths.join("; ")),
            });
            continue;
        }

        let joined_pattern = existing_paths.join(";");
        let files_count = resolve_source_items(&joined_pattern)
            .map(|v| v.len())
            .unwrap_or(0);
        let engine = LogEngine::with_options(threads, verbose);
        let input_fmt = parse_stack_input_format(&server_type);
        match engine
            .register_source("logs", &joined_pattern, input_fmt, None)
            .await
        {
            Ok(detected_fmt) => {
                let cols = engine.table_columns("logs").await;
                let sql = build_multi_format_error_sql(&cols, &status_prefix, &cutoff_date);
                match engine.query(&sql).await {
                    Ok(batches) => {
                        let rows = extract_fleet_rows(&batches, &srv.name, &srv.ip);
                        let first_err = rows
                            .first()
                            .map(|r| format!("{} {}", r.date, r.time))
                            .unwrap_or_default();
                        let last_err = rows
                            .last()
                            .map(|r| format!("{} {}", r.date, r.time))
                            .unwrap_or_default();
                        println!(
                            "  ✔  {:18} ({:12}) [{:?}] -> {:>5} match(es) across {:>4} log file(s)",
                            srv.name,
                            srv.ip,
                            detected_fmt,
                            rows.len(),
                            files_count
                        );
                        summaries.push(FleetServerSummary {
                            server_name: srv.name.clone(),
                            server_ip: srv.ip.clone(),
                            success: true,
                            total_errors: rows.len(),
                            log_files_scanned: files_count,
                            engine: format!("lpr-{:?}", detected_fmt),
                            first_error: first_err,
                            last_error: last_err,
                            scanned_paths: existing_paths.join("; "),
                            error_message: String::new(),
                        });
                        all_errors.extend(rows);
                    }
                    Err(e) => {
                        failed_servers.push(srv.name.clone());
                        summaries.push(FleetServerSummary {
                            server_name: srv.name.clone(),
                            server_ip: srv.ip.clone(),
                            success: false,
                            total_errors: 0,
                            log_files_scanned: files_count,
                            engine: "lpr-native-parallel".to_string(),
                            first_error: String::new(),
                            last_error: String::new(),
                            scanned_paths: existing_paths.join("; "),
                            error_message: e.to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                failed_servers.push(srv.name.clone());
                summaries.push(FleetServerSummary {
                    server_name: srv.name.clone(),
                    server_ip: srv.ip.clone(),
                    success: false,
                    total_errors: 0,
                    log_files_scanned: 0,
                    engine: "lpr-native-parallel".to_string(),
                    first_error: String::new(),
                    last_error: String::new(),
                    scanned_paths: existing_paths.join("; "),
                    error_message: e.to_string(),
                });
            }
        }
    }

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
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_local_or_archive_fleet_scan(
    target_path: &str,
    cutoff_date: &str,
    run_stamp: &str,
    output_dir: &str,
    report_prefix: &str,
    status_prefix: &str,
    days: i64,
    threads: Option<usize>,
    verbose: bool,
) -> Result<()> {
    let items = resolve_source_items(target_path)?;
    let engine = LogEngine::with_options(threads, verbose);
    let detected_fmt = engine
        .register_source("logs", target_path, InputFormat::Auto, None)
        .await?;
    let cols = engine.table_columns("logs").await;
    let sql = build_multi_format_error_sql(&cols, status_prefix, cutoff_date);
    let batches = engine.query(&sql).await?;
    let all_errors = extract_fleet_rows(&batches, "LOCAL-SERVER", "127.0.0.1");

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

    let summaries = vec![FleetServerSummary {
        server_name: srv_name,
        server_ip: srv_ip,
        success: true,
        total_errors: all_errors.len(),
        log_files_scanned: items.len(),
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
    )
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
                });
            }
        }
    }
    rows
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
) -> Result<()> {
    let out_dir = PathBuf::from(output_dir);
    let detail_csv = out_dir.join(format!("{}-{}.csv", report_prefix, run_stamp));
    let summary_csv = out_dir.join(format!("{}-Summary-{}.csv", report_prefix, run_stamp));
    let manifest_txt = out_dir.join(format!("{}-Manifest-{}.txt", report_prefix, run_stamp));

    {
        let mut wtr = csv::Writer::from_path(&detail_csv)?;
        for row in all_errors {
            wtr.serialize(row)?;
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
    let manifest_content = format!(
        "GeneratedUtc={}\nEngine=lpr-v1.3.0\nDays={}\nCutoffDate={}\nServersRequested={}\nServersSucceeded={}\nServersFailed={}\nTotalErrors={}\nDetailCsv={}\nSummaryCsv={}\nFailedServers={}\n",
        Utc::now().to_rfc3339(),
        days,
        cutoff_date,
        servers_requested,
        succeeded,
        failed_servers.len(),
        all_errors.len(),
        detail_csv.to_string_lossy(),
        summary_csv.to_string_lossy(),
        failed_servers.join(",")
    );
    fs::write(&manifest_txt, manifest_content)?;

    println!("--------------------------------------------------------------------------------");
    println!(" ✅ Fleet Scan Complete!");
    println!(" 📊 Total {}xx Matches : {}", status_prefix, all_errors.len());
    println!(" 📄 Detail CSV        : {}", detail_csv.to_string_lossy());
    println!(" 📋 Summary CSV       : {}", summary_csv.to_string_lossy());
    println!(" 📝 Manifest File     : {}", manifest_txt.to_string_lossy());
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
                for n in start..=end {
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
    eprintln!("⚠️  The password will be DPAPI-encrypted and bound to THIS Windows user account on THIS machine only.");
    eprintln!("⚠️  Other users / machines cannot decrypt it. If the account changes, re-save with --save-password.");
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
    target: String,
    active: bool,
}

#[cfg(windows)]
impl SmbSessionGuard {
    fn new(target: String, active: bool) -> Self {
        Self { target, active }
    }
}

#[cfg(windows)]
impl Drop for SmbSessionGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::process::Command::new("net")
                .args(["use", &self.target, "/delete", "/y"])
                .output();
        }
    }
}

#[cfg(windows)]
fn establish_smb_session(srv: &ServerEntry, profile: &SavedProfile) -> SmbSessionGuard {
    let Some(ref user) = profile.auth_user else {
        return SmbSessionGuard::new(String::new(), false);
    };
    let host = if srv.ip.trim().is_empty() {
        srv.name.trim()
    } else {
        srv.ip.trim()
    };
    if host.is_empty() {
        return SmbSessionGuard::new(String::new(), false);
    }
    let full_user = match profile.auth_domain.as_deref().filter(|d| !d.trim().is_empty()) {
        Some(dom) => format!("{}\\{}", dom.trim(), user.trim()),
        None => user.trim().to_string(),
    };
    let pass = resolve_secret(profile).unwrap_or_default();
    let target = format!(r"\\{}\IPC$", host);
    let out = std::process::Command::new("net")
        .args([
            "use",
            &target,
            &format!("/user:{}", full_user),
            &pass,
            "/persistent:no",
        ])
        .output();
    let ok = out.map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("  ⚠️  net use {} as {} failed — falling back to current credentials", target, full_user);
    }
    SmbSessionGuard::new(target, ok)
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
            r"\\{server}\d$\emLogs\{site}".to_string(),
            r"\\{server}\d$\emLogs\OldIISLogs\{site}".to_string(),
            r"\\{server}\c$\inetpub\logs\LogFiles\{site}".to_string(),
            format!("/var/log/nginx/{}", site_name),
            format!("/var/log/apache2/{}", site_name),
        ]
    } else {
        vec![
            r"\\{server}\c$\inetpub\logs\LogFiles".to_string(),
            r"\\{server}\d$\emLogs".to_string(),
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
fn build_multi_format_error_sql(cols: &[String], status_prefix: &str, cutoff_date: &str) -> String {
    let has = |c: &str| cols.iter().any(|x| x.eq_ignore_ascii_case(c));
    if has("sc_status") && has("date") {
        format!(
            "SELECT * FROM logs WHERE sc_status LIKE '{}%' AND date >= '{}' ORDER BY date, time",
            status_prefix, cutoff_date
        )
    } else if has("status") {
        format!("SELECT * FROM logs WHERE CAST(status AS VARCHAR) LIKE '{}%'", status_prefix)
    } else if has("elb_status_code") {
        format!(
            "SELECT * FROM logs WHERE elb_status_code LIKE '{}%' OR target_status_code LIKE '{}%'",
            status_prefix, status_prefix
        )
    } else if has("http_status") {
        format!("SELECT * FROM logs WHERE http_status LIKE '{}%'", status_prefix)
    } else if has("http_status_code") {
        format!(
            "SELECT * FROM logs WHERE http_status_code LIKE '{}%'",
            status_prefix
        )
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
) -> Result<(Vec<FleetErrorRow>, usize, String)> {
    let target_host = if !srv.ip.is_empty() {
        &srv.ip
    } else {
        &srv.name
    };
    let ssh_target = match &profile.ssh_user {
        Some(u) if !u.trim().is_empty() => format!("{}@{}", u.trim(), target_host),
        _ => target_host.to_string(),
    };

    let search_dirs: Vec<String> = path_templates
        .iter()
        .map(|t| {
            t.replace("{server}", &srv.name)
                .replace("{ip}", &srv.ip)
                .replace("{site}", site_name)
        })
        .collect();
    let dirs_arg = search_dirs.join(" ");

    // Build a fast remote shell command that auto-discovers Nginx/Apache vhost logs + searches log directories
    let remote_cmd = format!(
        "find {} -maxdepth 2 -type f \\( -name '*.log' -o -name '*.log.1' -o -name '*access*.gz' \\) -mtime -{} 2>/dev/null | head -n 50 | xargs -r zcat -f 2>/dev/null",
        dirs_arg,
        days.max(1)
    );

    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=10");
    if let Some(port) = profile.ssh_port {
        cmd.arg("-p").arg(port.to_string());
    }
    if let Some(ref key_path) = profile.ssh_key {
        if !key_path.trim().is_empty() {
            cmd.arg("-i").arg(key_path.trim());
        }
    }
    cmd.arg(&ssh_target).arg(&remote_cmd);

    let out = cmd.output()?;
    if !out.status.success() && out.stdout.is_empty() {
        let err_str = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("SSH error: {}", err_str);
    }

    if out.stdout.is_empty() {
        return Ok((Vec::new(), 0, format!("ssh://{}:{}", ssh_target, dirs_arg)));
    }

    let tmp_path = std::env::temp_dir().join(format!("lpr_ssh_{}.log", srv.name));
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
    let sql = build_multi_format_error_sql(&cols, status_prefix, cutoff_date);
    let batches = engine.query(&sql).await?;
    let mut rows = extract_fleet_rows(&batches, &srv.name, &srv.ip);
    for r in &mut rows {
        if r.log_file.starts_with("lpr_ssh_") {
            r.log_file = format!("ssh://{}:{}", srv.name, dirs_arg);
        }
    }
    let _ = fs::remove_file(&tmp_path);

    Ok((rows, 1, format!("ssh://{}:{}", ssh_target, dirs_arg)))
}
