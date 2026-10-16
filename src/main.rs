mod audit;
mod checkpoint;
mod engine;
mod fleet;
mod gui;
mod hooks;
mod mcp;
mod parsers;
mod server;
mod sinks;
mod sym;
mod tui;
mod udfs;

use crate::sym::*;
use anyhow::Result;
use checkpoint::CheckpointStore;
use clap::{CommandFactory, Parser, Subcommand};
use engine::{
    build_universal_search_predicate, extract_into_from_sql, extract_source_from_sql, LogEngine,
};
use hooks::{evaluate_and_fire_hooks, HookConfig};
use parsers::{resolve_source_items, InputFormat};
use sinks::{infer_output_format_from_path, write_batches, write_batches_with_options, OutputFormat};
use std::io::{IsTerminal, Write};

pub const LPR_VERSION: &str = "1.4.0";

pub fn get_ascii_banner() -> &'static str {
    r#"   ___             ___                         
  / / |___  _ __  / _ \___ _ _ _ ___ ___ _ _   
 / /| '_ \ '_ \/ /_\/ _ \ '_| '_/ -_) _ \ '_|  
/_/ |_.__/ .__/\__/\___/_| |_|  \___|___/_|    
         |_|   v1.4.0 — Multi-Threaded Rust SQL Log Engine & Security Auditor
               Powered by Apache Arrow 53, DataFusion 42 & Rayon Parallel Engine
               Made using vibe coding by Sunil Warrier
================================================================================"#
}

#[derive(Parser)]
#[command(
    name = "lpr",
    version = LPR_VERSION,
    about = "Modern Multi-Threaded Rust SQL Log Parser & Security Auditor (Log Parser 2.2 + Linux + .NET/PS + REST API + MCP)",
    long_about = "High-performance vectorized & multi-threaded log engine powered by Apache Arrow, DataFusion & Rayon.\nReads uncompressed logs, .zip archives, .gz, and .zst streams directly across CPU cores.\nSupports ANSI SQL, Microsoft Log Parser 2.2 syntax (`-i:IISW3C`, `SELECT TOP 10 ... INTO out.csv FROM *.log`), Linux CLI filters (`-g`, `-v`, `-F`, `--stats`, `stdin` pipes), .NET/PowerShell integration (`lpr sdk`), HTTP REST API (`lpr serve`), and AI MCP (`lpr mcp`)."
)]
struct Cli {
    /// ANSI SQL, Microsoft Log Parser 2.2 query, or lnav filter (`:filter-in <pat>`)
    #[arg(value_name = "SQL_QUERY")]
    query: Option<String>,

    /// Path, glob pattern, or .zip/.gz/.zst archive of log files to query (optional if in SQL FROM)
    #[arg(short = 'f', long = "file", value_name = "PATH_GLOB_OR_ZIP")]
    file: Option<String>,

    /// Log format parser (supports `-i w3c` and Log Parser `-i:IISW3C`, `-i:W3C`, `-i:TEXTLINE` syntax)
    #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
    input_format: InputFormat,

    /// Output sink format (`table`, `vertical`, `csv`, `tsv`, `json`, `ndjson`, `xml`, `chart`, `markdown`, `sql`, `parquet`)
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Table)]
    output_format: OutputFormat,

    /// Write query output directly to a file instead of stdout (or use SQL `INTO 'filename.csv'`)
    #[arg(long = "out-file", value_name = "PATH")]
    out_file: Option<String>,

    /// Number of parallel worker threads for multi-file / multi-archive parsing & SQL execution (default: all CPU cores)
    #[arg(short = 'j', long = "threads", global = true, value_name = "NUM_THREADS")]
    threads: Option<usize>,

    /// Path to persistent configuration file (default: lpr.config.json)
    #[arg(long = "cfg", global = true, value_name = "CFG_FILE")]
    cfg_file: Option<String>,

    /// Load a named profile from lpr.config.json (restores saved threads, paths, servers, and options)
    #[arg(short = 'P', long = "profile", global = true, value_name = "PROFILE_NAME")]
    profile: Option<String>,

    /// Save current CLI options (threads, file/paths, format, etc.) into lpr.config.json under this profile name
    #[arg(long = "save-profile", global = true, value_name = "PROFILE_NAME")]
    save_profile: Option<String>,

    /// List all saved profiles in lpr.config.json
    #[arg(long = "list-profiles", global = true)]
    list_profiles: bool,

    /// Enable detailed per-file verbose progress logging (shows each file, lines, rows, and parse time)
    #[arg(short = 'V', long = "verbose", global = true)]
    verbose: bool,

    /// Force plain ASCII output (no emoji) for older consoles — auto-detected, or use LPR_ASCII=1
    #[arg(long = "ascii", global = true)]
    ascii: bool,

    /// Explicitly disable verbose per-file progress output
    #[arg(long = "no-verbose")]
    no_verbose: bool,

    /// Write execution progress & statistics log to a file (default when --log is passed: lpr_execution.log)
    #[arg(long = "log-file", alias = "log", value_name = "LOG_PATH")]
    log_file: Option<String>,

    /// Disable execution header, status logging, and summary footer (same as `-q` / `-q:ON` / `-stats:OFF`)
    #[arg(long = "no-log", alias = "silent")]
    no_log: bool,

    /// Suppress startup banner and execution statistics (`-q` or Log Parser `-q:ON`)
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Format output rows vertically as key-value cards (`\G` style, ideal for wide IIS/Cookie logs)
    #[arg(short = 'G', long = "vertical")]
    vertical: bool,

    /// Maximum column width in characters when displaying ASCII tables (0 = unlimited/no truncation; default = 80)
    #[arg(long = "max-width", default_value_t = 80)]
    max_width: usize,

    /// [Linux grep / ripgrep] Filter rows matching pattern across all columns (`-g` / `-E` / `--grep`)
    #[arg(short = 'g', short_alias = 'E', long = "grep", value_name = "PATTERN")]
    grep: Option<String>,

    /// [Linux grep -v] Invert match when used with `-g` / `--grep` (exclude matching rows)
    #[arg(short = 'v', long = "invert-match")]
    invert_match: bool,

    /// [Linux grep -c / wc -l] Print only the count of matching rows
    #[arg(short = 'c', long = "count")]
    count_only: bool,

    /// [Linux awk / cut] Comma-separated list of fields/columns to project (e.g. `-F c_ip,sc_status,time_taken`)
    #[arg(short = 'F', long = "fields", value_name = "COL1,COL2")]
    fields: Option<String>,

    /// [Linux GoAccess / LogParser -stats] Show executive traffic, status, IP, threat & latency summary
    #[arg(long = "stats")]
    stats: bool,

    /// State file to persist read byte offsets for continuous/incremental log tailing
    #[arg(long = "checkpoint", value_name = "STATE_FILE_JSON")]
    checkpoint: Option<String>,

    /// Live-tail log file(s) continuously (`tail -f` mode), executing the SQL query on new lines
    #[arg(short = 't', long = "tail")]
    tail: bool,

    /// Polling interval in milliseconds when running in `--tail` mode
    #[arg(long = "tail-interval-ms", default_value_t = 1500)]
    tail_interval_ms: u64,

    /// Custom named-capture regex pattern to parse arbitrary log formats into SQL columns
    #[arg(long = "regex-pattern", value_name = "REGEX")]
    regex_pattern: Option<String>,

    /// Additional tables to register for relational SQL JOINs (e.g. --join geoip=data/geo.csv)
    #[arg(long = "join", value_name = "NAME=PATH")]
    joins: Vec<String>,

    /// HTTP POST webhook URL to notify when query matches rows
    #[arg(long = "hook-url", value_name = "URL")]
    hook_url: Option<String>,

    /// Shell command or script to execute when query matches rows
    #[arg(long = "hook-exec", value_name = "COMMAND")]
    hook_exec: Option<String>,

    /// Minimum matching row threshold required before firing webhook/exec hooks
    #[arg(long = "hook-min-rows", default_value_t = 1)]
    hook_min_rows: usize,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Target log file, glob, or .zip archive to audit (also accepts positional path: `lpr audit samples/iis/W3SVC3.zip`)
    Audit {
        /// Target log file or configuration to audit (via -f <PATH>)
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<String>,

        /// Positional target log file, folder, or .zip archive (so `lpr audit <path>` works without `-f`)
        #[arg(value_name = "TARGET_PATH")]
        target: Option<String>,

        /// Format of the target file (auto-detects if omitted)
        #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
        input_format: InputFormat,

        /// Output audit findings as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect a log file's schema and generate context-aware, intent-based SQL query suggestions
    Suggest {
        /// Target log file, glob pattern, or .zip archive to inspect (via -f <PATH>)
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<String>,

        /// Positional target log file, folder, or .zip archive (so `lpr suggest <path>` works without `-f`)
        #[arg(value_name = "TARGET_PATH")]
        target: Option<String>,

        /// Format of the target file (auto-detects if omitted)
        #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
        input_format: InputFormat,

        /// Output schema and intent suggestions as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate ready-to-use PowerShell, .NET C#, Python, and cURL API / CLI integration wrappers
    Sdk {
        /// Target language (`powershell`, `csharp`, `dotnet`, `curl`, or `all`)
        #[arg(default_value = "all", value_name = "TARGET")]
        target: String,
    },

    /// Display the complete interactive reference manual (Log Parser 2.2, Linux tools, UDFs, .NET/PS, API/MCP)
    #[command(name = "help-full", alias = "manual", alias = "cheatsheet")]
    HelpFull,

    /// Launch the native desktop window application (lpr Studio)
    Gui {
        /// Preload a specific log file or glob pattern
        #[arg(long, value_name = "PATH")]
        source: Option<String>,
    },

    /// Launch interactive terminal dashboard (TUI) with file browser, Tab autocomplete & help menus
    Tui {
        /// Log file to inspect in the terminal UI (defaults to samples/nginx_access.log or current folder)
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<String>,

        /// Format of the log file
        #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
        input_format: InputFormat,
    },

    /// Start Model Context Protocol (MCP) JSON-RPC stdio server for AI agents
    Mcp,

    /// Start the HTTP REST API server and web-based lpr Studio console
    Serve {
        /// Address and port to bind HTTP server to
        #[arg(long, default_value = "127.0.0.1:8080", value_name = "IP:PORT")]
        bind: String,

        /// Preload a default log file path
        #[arg(long, value_name = "PATH")]
        source: Option<String>,
    },

    /// Zero-script multi-server IIS fleet error scanner (supports saved profiles in lpr.config.json, servers.csv, or host patterns)
    #[command(alias = "scan-500")]
    Fleet {
        /// Number of days to look back (inclusive, default: 7)
        #[arg(short = 'd', long = "days")]
        days: Option<i64>,

        /// IIS Site folder name under log roots (e.g. --site W3SVC1 or --site MySite)
        #[arg(long = "site")]
        site: Option<String>,

        /// Custom prefix for generated CSV/Manifest report filenames (default: "IIS-500Errors" or "<site>-500Errors")
        #[arg(long = "report-prefix")]
        report_prefix: Option<String>,

        /// Path to servers.csv (Name, IP, Enabled)
        #[arg(long = "servers", value_name = "CSV_PATH")]
        servers: Option<String>,

        /// Path to JSON server config fallback
        #[arg(long = "config", value_name = "JSON_PATH")]
        config: Option<String>,

        /// Hostname template when scanning numbered servers without a CSV (e.g. "vm-web-prod-{02}" or "web-{n}")
        #[arg(long = "host-pattern", value_name = "PATTERN")]
        host_pattern: Option<String>,

        /// Live log path on each server (e.g. "D:\Logs\W3SVC1" or "/var/log/nginx" — auto-converted for SMB or SSH)
        #[arg(long = "log-path", alias = "remote-path", value_name = "SERVER_LOG_PATH")]
        log_path: Option<String>,

        /// Archived log path on each server (e.g. "D:\OldLogs\W3SVC1" or "/var/log/nginx")
        #[arg(long = "archive-path", value_name = "SERVER_ARCHIVE_PATH")]
        archive_path: Option<String>,

        /// Auto-discover web server log paths from IIS applicationHost.config or Linux /etc/nginx, /etc/apache2, /etc/httpd, /etc/caddy
        #[arg(long = "iis-auto", alias = "auto-discover")]
        iis_auto: bool,

        /// Web server stack type (`auto`, `iis`, `nginx`, `apache`, `caddy`, `haproxy`, `tomcat`, `alb`)
        #[arg(long = "server-type", value_name = "STACK")]
        server_type: Option<String>,

        /// Connect to Linux / Unix web servers over SSH to stream and scan logs remotely
        #[arg(long = "ssh")]
        ssh: bool,

        /// SSH username for remote Linux web server scanning (e.g. "ubuntu" or "root")
        #[arg(long = "ssh-user", value_name = "USER")]
        ssh_user: Option<String>,

        /// SSH private key path for remote Linux web server scanning (e.g. "~/.ssh/id_ed25519")
        #[arg(long = "ssh-key", value_name = "KEY_PATH")]
        ssh_key: Option<String>,

        /// SSH port for remote Linux web server scanning (default: 22)
        #[arg(long = "ssh-port", value_name = "PORT")]
        ssh_port: Option<u16>,

        /// Alternate SMB username for remote Windows shares (e.g. "svc-logreader")
        #[arg(long = "user", value_name = "USER")]
        auth_user: Option<String>,

        /// SMB domain/workgroup for the alternate user (e.g. "CORP" or "SERVER01")
        #[arg(long = "domain", value_name = "DOMAIN")]
        auth_domain: Option<String>,

        /// Password source — env:VAR_NAME | file:PATH | prompt (never stores plaintext)
        #[arg(long = "password-ref", value_name = "env:VAR|file:PATH|prompt")]
        password_ref: Option<String>,

        /// Prompt for a password and store it DPAPI-encrypted in the profile (Windows only, bound to this user account)
        #[arg(long = "save-password")]
        save_password: bool,

        /// Semicolon-separated log path templates supporting {server}, {ip}, {site} (e.g. "\\\\{server}\\d$\\Logs\\{site}")
        #[arg(long = "path-template", value_name = "TEMPLATE")]
        path_template: Option<String>,

        /// Output directory for generated Detail, Summary, and Manifest CSVs
        #[arg(short = 'o', long = "output")]
        output: Option<String>,

        /// Server wildcard filter (e.g. "vm-web-prod-0*")
        #[arg(long = "server-filter")]
        server_filter: Option<String>,

        /// Server number range filter (e.g. "1-12" or "1,3,5")
        #[arg(long = "server-numbers")]
        server_numbers: Option<String>,

        /// Scan a local directory, glob, or .zip archive directly instead of remote SMB server shares
        #[arg(short = 'f', long = "local-path", value_name = "PATH_OR_ZIP")]
        local_path: Option<String>,

        /// HTTP status prefix to scan for (default "5" for 500-599 errors; use "4" for 4xx)
        #[arg(long = "status-prefix")]
        status_prefix: Option<String>,
    },

    /// Manage saved configuration profiles in lpr.config.json (list, show, save, set-default)
    Config {
        /// List all saved profiles in lpr.config.json
        #[arg(short = 'l', long = "list")]
        list: bool,

        /// Set the default profile name in lpr.config.json
        #[arg(long = "set-default", value_name = "PROFILE_NAME")]
        set_default: Option<String>,
    },
}

fn preprocess_cli_args<I: IntoIterator<Item = String>>(raw_args: I) -> Vec<String> {
    let mut out = Vec::new();
    for arg in raw_args {
        let lower = arg.to_lowercase();
        if let Some(val) = lower.strip_prefix("-i:").or_else(|| lower.strip_prefix("/i:")) {
            out.push("-i".to_string());
            out.push(val.to_string());
        } else if let Some(val) = lower.strip_prefix("-o:").or_else(|| lower.strip_prefix("/o:")) {
            out.push("-o".to_string());
            out.push(val.to_string());
        } else if let Some(val) = lower
            .strip_prefix("-threads:")
            .or_else(|| lower.strip_prefix("/threads:"))
            .or_else(|| lower.strip_prefix("-j:"))
        {
            out.push("-j".to_string());
            out.push(val.to_string());
        } else if lower == "-q:on" || lower == "/q:on" || lower == "-q" {
            out.push("-q".to_string());
        } else if lower == "-q:off" || lower == "/q:off" {
            out.push("-V".to_string());
        } else if lower == "-stats:on" || lower == "/stats:on" || lower == "-stats" {
            out.push("--stats".to_string());
        } else if lower == "-stats:off" || lower == "/stats:off" {
            out.push("--no-log".to_string());
        } else if lower == "--log" {
            out.push("--log-file".to_string());
            out.push("lpr_execution.log".to_string());
        } else if lower.starts_with("-e:")
            || lower.starts_with("/e:")
            || lower.starts_with("-iw:")
            || lower.starts_with("/iw:")
            || lower.starts_with("-rtp:")
            || lower.starts_with("/rtp:")
            || lower.starts_with("-recurse:")
        {
            // Accepted for 100% Log Parser 2.2 script drop-in compatibility
        } else if let Some(sql_file) = arg
            .strip_prefix("file:")
            .or_else(|| arg.strip_prefix("FILE:"))
        {
            if let Ok(contents) = std::fs::read_to_string(sql_file.trim()) {
                out.push(contents);
            } else {
                out.push(arg);
            }
        } else {
            out.push(arg);
        }
    }
    out
}

fn log_message(log_writer: &mut Option<std::fs::File>, show_stderr: bool, msg: &str) {
    if show_stderr {
        eprintln!("{}", msg);
    }
    if let Some(ref mut f) = log_writer {
        let _ = writeln!(f, "{}", msg);
    }
}

pub fn print_sdk_templates(target: &str) {
    let t = target.to_lowercase();
    let mut out = std::io::stdout();

    if t == "all" || t == "powershell" || t == "ps" || t == "pwsh" {
        let _ = writeln!(
            out,
            r#"# ==============================================================================
# {SYM_BSQ} 1. POWERSHELL MODULE & NATIVE PIPELINE INTEGRATION
# ==============================================================================
# Run `lpr.exe` directly in PowerShell and convert output into native PSObjects:

function Invoke-LprQuery {{
    param(
        [Parameter(Mandatory=$true)][string]$Sql,
        [string]$File = "",
        [string]$InputFormat = "auto",
        [int]$Threads = 0
    )
    $argsList = @("-q", "-o", "json", "-i", $InputFormat)
    if ($Threads -gt 0) {{ $argsList += @("-j", "$Threads") }}
    if ($File -ne "") {{ $argsList += @("-f", $File) }}
    $argsList += $Sql
    $rawJson = & lpr @argsList
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rawJson)) {{ return @() }}
    return ($rawJson | ConvertFrom-Json)
}}

# Example 1: Query IIS W3C 5xx errors inside a .zip archive or folder as native PowerShell objects:
# $errors = Invoke-LprQuery "SELECT * FROM 'samples/iis/u_extend01.log' WHERE sc-status LIKE '5%'"
# $errors | Where-Object {{ [int]$_.time_taken -gt 1000 }} | Format-Table c_ip, cs_uri_stem, sc_status, time_taken
"#
        );
    }

    if t == "all" || t == "csharp" || t == "dotnet" || t == "cs" || t == ".net" {
        let _ = writeln!(
            out,
            r#"// ==============================================================================
// {SYM_PSQ} 2. .NET / C# SDK INTEGRATION (CLI Process & HTTP REST Client)
// ==============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

public sealed class LprClient
{{
    private readonly string _executablePath;
    private readonly HttpClient _http;
    private readonly string _apiBaseUrl;

    public LprClient(string executablePath = "lpr.exe", string apiBaseUrl = "http://127.0.0.1:8080")
    {{
        _executablePath = executablePath;
        _apiBaseUrl = apiBaseUrl.TrimEnd('/');
        _http = new HttpClient();
    }}

    public async Task<List<Dictionary<string, object>>> QueryCliAsync(string sql, string? file = null, int threads = 0)
    {{
        var psi = new ProcessStartInfo(_executablePath)
        {{
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        }};
        psi.ArgumentList.Add("-q");
        psi.ArgumentList.Add("-o");
        psi.ArgumentList.Add("json");
        if (threads > 0) {{ psi.ArgumentList.Add("-j"); psi.ArgumentList.Add(threads.ToString()); }}
        if (!string.IsNullOrEmpty(file)) {{ psi.ArgumentList.Add("-f"); psi.ArgumentList.Add(file); }}
        psi.ArgumentList.Add(sql);

        using var proc = Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        if (proc.ExitCode != 0) throw new InvalidOperationException($"lpr failed: {{stderr}}");
        return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(stdout) ?? new();
    }}

    public async Task<JsonElement> QueryRestApiAsync(string sql, string? source = null, string? format = null)
    {{
        var response = await _http.PostAsJsonAsync($"{{_apiBaseUrl}}/v1/query", new {{ sql, source, format }});
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }}
}}
"#
        );
    }

    if t == "all" || t == "curl" || t == "api" || t == "mcp" {
        let _ = writeln!(
            out,
            r#"# ==============================================================================
# {SYM_GLOBE} 3. HTTP REST API & AI MCP (MODEL CONTEXT PROTOCOL) INTEGRATION
# ==============================================================================
# Start REST API Server:
#   lpr serve --bind 127.0.0.1:8080
# Query via GET or POST:
#   curl -s "http://127.0.0.1:8080/v1/query?source=samples/iis/u_extend01.log&sql=SELECT+sc-status,COUNT(*)+FROM+logs+GROUP+BY+1"
"#
        );
    }
}

pub fn print_full_manual() {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{}", get_ascii_banner());
    let _ = writeln!(
        out,
        r#"
{SYM_BOOKS} LPR v1.3.0 COMPLETE REFERENCE MANUAL (MULTI-THREADED + ZIP/GZ/ZST + LOG PARSER 2.2 + LINUX)
================================================================================

1. DIRECT .ZIP, .GZ, AND .ZST ARCHIVE & MULTI-THREADED QUERYING
--------------------------------------------------------------------------------
  • Query a .zip archive containing multiple IIS or Linux log files in parallel across all CPU threads:
    lpr -f logs_archive.zip "SELECT sc-status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC"
  • Control thread count (`-j` / `--threads`) and show per-file verbose progress (`-V` / `--verbose`):
    lpr -j 8 -V -f "logs_archive.zip" "SELECT * FROM logs WHERE sc-status LIKE '5%' INTO 500_errors.csv"

2. MULTI-SERVER FLEET SCANNER & SAVED PROFILES (WINDOWS IIS + LINUX NGINX/APACHE/CADDY/HAPROXY/TOMCAT)
--------------------------------------------------------------------------------
  • Save a Windows IIS server farm profile once (auto-discovers W3SVC paths from applicationHost.config or uses --log-path):
    lpr fleet --save-profile prod-iis --servers servers.csv --site W3SVC1 --threads 8 --days 7
  • Save a Linux Nginx/Apache/Caddy server farm profile over SSH (streams & decompresses .log / .gz remotely):
    lpr fleet --save-profile prod-linux --servers linux_servers.csv --server-type nginx --ssh --ssh-user ubuntu --log-path /var/log/nginx
  • Run saved profile anytime (or filter server numbers 1-12):
    lpr fleet --profile prod-iis --server-numbers "1-12" --days 3
  • View or manage saved profiles in `lpr.config.json`:
    lpr config

3. LOGGING, VERBOSITY & TABLE FORMATTING OPTIONS
--------------------------------------------------------------------------------
  • Default Mode:     Shows startup banner, execution plan, and final Log Parser statistics summary
  • `-V` / `--verbose`: Prints per-file progress (file name, line count, parsed rows, elapsed ms)
  • `--no-verbose`:   Disables per-file progress lines while keeping the startup header and final summary
  • `--log-file <f>`: Writes execution plan, per-file progress, and summary stats to a log file
  • `-q` / `--no-log`: Quiet mode — suppresses all banners, progress, and statistics (pure data output)
  • `--max-width 80`: Truncates wide table cells (like huge cookies) so ASCII tables fit cleanly on screen (`--max-width 0` for full width)
  • `-G` / `--vertical`: Displays each record vertically (`key : value` cards) for wide logs

4. MICROSOFT LOG PARSER 2.2 DROP-IN SYNTAX
--------------------------------------------------------------------------------
  • Query files/globs/zips in SQL FROM & write to file via SQL INTO:
    lpr -i:IISW3C "SELECT TOP 10 cs-uri-stem, [sc-status], [time-taken] INTO out.csv FROM 'samples/iis/u_extend01.log' WHERE sc-status LIKE '5%'"
  • Colon Flags & Virtual Columns (LogFilename, LogRow):
    lpr -i:W3C -o:DATAGRID "SELECT LogFilename, LogRow, c-ip, sc-status, win32_error_description(sc-win32-status) FROM samples/*.log"

5. LINUX POWER-TOOL SYNTAX (GREP / AWK / GOACCESS / LNAV / STDIN PIPES)
--------------------------------------------------------------------------------
  • Grep & Invert-Grep with Structured Table Output (`-g`, `-v`, `-c`, `-F`):
    lpr -f samples/iis/u_extend01.log -g "500" -F date,time,c_ip,cs_uri_stem,sc_status,time_taken
  • GoAccess-style Instant Traffic, SMTP & Threat Summary (`--stats` or `-stats:ON`):
    lpr -f samples/iis/u_extend01.log --stats
    lpr -f samples/iis_smtp/u_ex260101.log --stats
  • Terminal Horizontal Bar Charts (`-o chart` / `-o:CHART`):
    lpr -f samples/iis/u_extend01.log -o:CHART "SELECT sc-status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC"

6. BUILT-IN CYBERSECURITY & LOG PARSER 2.2 SQL UDFs (23 FUNCTIONS)
--------------------------------------------------------------------------------
  • Cyber & Email UDFs: detect_threat(col), ip_in_cidr(ip, cidr), shannon_entropy(col), mask_pii(col),
                        cluster_template(col), url_decode(col), parse_ua(col), extract_email(col), extract_domain(col)
  • LogParser 2.2 UDFs: extract_token(s, idx, sep), extract_prefix(s, idx, sep), extract_suffix(s, idx, sep),
                        extract_filename(p), extract_path(p), extract_extension(p),
                        win32_error_description(code), reversedns(ip), to_timestamp(d, t),
                        index_of(s, sub), strlen(s), to_uppercase(s), to_lowercase(s), to_int(s), to_real(s)
"#
    );
}

async fn run_suggest_command(
    file: &str,
    input_format: InputFormat,
    json_out: bool,
    threads: Option<usize>,
) -> Result<()> {
    let engine = LogEngine::with_options(threads, false);
    let discovery = engine.inspect_schema_and_intents(file, input_format).await?;

    if json_out {
        println!("{}", serde_json::to_string_pretty(&discovery)?);
        return Ok(());
    }

    println!("================================================================================");
    println!(" {SYM_BRAIN} LPR CONTEXT-AWARE SCHEMA & INTENT ASSISTANT");
    println!(
        " {SYM_FOLDER} Source: {} | Format: {} | Rows: {}",
        file, discovery.detected_format, discovery.row_count_estimate
    );
    println!("================================================================================");
    println!(
        "\n{SYM_LIST} DISCOVERED COLUMNS ({}):\n   {}\n",
        discovery.columns.len(),
        discovery.columns.join(", ")
    );
    println!("{SYM_ZAP} RECOMMENDED INTENT-BASED SQL QUERIES:");
    for (idx, item) in discovery.suggestions.iter().enumerate() {
        println!(
            "\n  [{}] [{}] {} — {}",
            idx + 1,
            item.category,
            item.title,
            item.description
        );
        println!("      lpr -f \"{}\" \"{}\"", file, item.sql);
    }
    println!();
    Ok(())
}

async fn run_goaccess_stats(engine: &LogEngine, file_pattern: &str, fmt: InputFormat) -> Result<()> {
    let cols = engine.table_columns("logs").await;
    let has = |c: &str| cols.iter().any(|x| x.eq_ignore_ascii_case(c));

    println!("================================================================================");
    println!(" {SYM_CHART} LPR EXECUTIVE LOG ANALYTICS & THREAT SUMMARY (GoAccess / LogParser Mode)");
    println!(" {SYM_FOLDER} Source: {} | Format: {:?}", file_pattern, fmt);
    println!("================================================================================");

    if let Ok(b) = engine.query("SELECT COUNT(*) AS total_rows FROM logs").await {
        write_batches(&b, OutputFormat::Table, None)?;
    }

    if has("sc_status") {
        println!("{SYM_BULLET} HTTP Status Distribution:");
        if let Ok(b) = engine
            .query("SELECT sc_status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC")
            .await
        {
            write_batches(&b, OutputFormat::Chart, None)?;
        }
    } else if has("status") {
        println!("{SYM_BULLET} Status Distribution:");
        if let Ok(b) = engine
            .query("SELECT status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC")
            .await
        {
            write_batches(&b, OutputFormat::Chart, None)?;
        }
    }

    if has("c_ip") {
        println!("\n{SYM_BULLET} Top Client IPs:");
        if let Ok(b) = engine
            .query("SELECT c_ip, COUNT(*) AS requests FROM logs GROUP BY 1 ORDER BY requests DESC LIMIT 10")
            .await
        {
            write_batches(&b, OutputFormat::Chart, None)?;
        }
    } else if has("remote_addr") {
        println!("\n{SYM_BULLET} Top Remote IPs:");
        if let Ok(b) = engine
            .query("SELECT remote_addr, COUNT(*) AS requests FROM logs GROUP BY 1 ORDER BY requests DESC LIMIT 10")
            .await
        {
            write_batches(&b, OutputFormat::Chart, None)?;
        }
    } else if has("srcip") {
        println!("\n{SYM_BULLET} Top Firewall Source IPs:");
        if let Ok(b) = engine
            .query("SELECT srcip, COUNT(*) AS events FROM logs GROUP BY 1 ORDER BY events DESC LIMIT 10")
            .await
        {
            write_batches(&b, OutputFormat::Chart, None)?;
        }
    }

    // If this W3C log contains IIS SMTP commands (MAIL / RCPT / EHLO), automatically display SMTP Senders, Clients & Top Recipients!
    if has("cs_method") {
        if let Ok(smtp_check) = engine
            .query("SELECT COUNT(*) FROM logs WHERE UPPER(cs_method) IN ('MAIL', 'RCPT', 'EHLO', 'HELO')")
            .await
        {
            let smtp_cnt: usize = smtp_check
                .first()
                .and_then(|b| arrow::util::display::array_value_to_string(b.column(0), 0).ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if smtp_cnt > 0 {
                println!("\n{SYM_MAIL} IIS SMTP — Unique Senders (FROM) & Sending Client IPs:");
                if let Ok(b) = engine
                    .query("SELECT extract_email(COALESCE(cs_uri_query, cs_uri_stem)) AS from_address, extract_domain(COALESCE(cs_uri_query, cs_uri_stem)) AS sender_domain, c_ip AS sending_client_ip, COUNT(*) AS messages_sent FROM logs WHERE UPPER(cs_method) = 'MAIL' GROUP BY 1, 2, 3 ORDER BY messages_sent DESC")
                    .await
                {
                    write_batches(&b, OutputFormat::Table, None)?;
                }

                println!("{SYM_MAILBOX} IIS SMTP — Top Recipients (TO) & Delivery Status:");
                if let Ok(b) = engine
                    .query("SELECT extract_email(COALESCE(cs_uri_query, cs_uri_stem)) AS to_address, extract_domain(COALESCE(cs_uri_query, cs_uri_stem)) AS recipient_domain, sc_status AS smtp_status, COUNT(*) AS recipient_hits FROM logs WHERE UPPER(cs_method) = 'RCPT' GROUP BY 1, 2, 3 ORDER BY recipient_hits DESC LIMIT 25")
                    .await
                {
                    write_batches(&b, OutputFormat::Table, None)?;
                }

                println!("{SYM_SERVER}  IIS SMTP — Connecting Client IPs & Announced EHLO/HELO Hostnames:");
                if let Ok(b) = engine
                    .query("SELECT c_ip AS client_ip, TRIM(LEADING '+' FROM COALESCE(cs_uri_query, cs_uri_stem)) AS ehlo_hostname, cs_username, COUNT(*) AS sessions FROM logs WHERE UPPER(cs_method) IN ('EHLO', 'HELO') GROUP BY 1, 2, 3 ORDER BY sessions DESC LIMIT 20")
                    .await
                {
                    write_batches(&b, OutputFormat::Table, None)?;
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();

    // If invoked with zero arguments, show banner + quick-start + help
    if raw_args.len() <= 1 {
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{}", get_ascii_banner());
        let _ = writeln!(out, "\n{SYM_TIP} QUICK START:");
        let _ = writeln!(out, "  • Query .log or .zip:   lpr \"SELECT * FROM 'samples/iis/u_extend01.log' WHERE sc-status LIKE '5%' INTO 500.csv\"");
        let _ = writeln!(out, "  • Verbose Multi-Thread: lpr -V -j 8 -f samples/iis/u_extend01.log \"SELECT sc-status, COUNT(*) FROM logs GROUP BY 1\"");
        let _ = writeln!(out, "  • Linux grep / awk:     lpr -f samples/iis/u_extend01.log -g 500 -F date,time,c_ip,cs_uri_stem,sc_status");
        let _ = writeln!(out, "  • GoAccess Summary:     lpr -f samples/iis/u_extend01.log --stats");
        let _ = writeln!(out, "  • Fleet Server Scanner: lpr fleet --save-profile prod-web --servers servers.csv --site W3SVC1 --threads 8");
        let _ = writeln!(out, "  • Smart SQL Intents:    lpr suggest samples/iis/u_extend01.log");
        let _ = writeln!(out, "  • PowerShell / .NET C#: lpr sdk");
        let _ = writeln!(out, "  • Launch Web Studio:    lpr serve");
        let _ = writeln!(out, "  • Full Manual & UDFs:   lpr help-full\n");
        let help_str = Cli::command().render_help().to_string();
        let _ = writeln!(out, "{}", help_str);
        return Ok(());
    }

    let processed_args = preprocess_cli_args(raw_args);
    let cli = Cli::parse_from(processed_args);
    if cli.ascii {
        sym::force_ascii();
    }

    match cli.command {
        Some(Commands::Audit {
            file,
            target,
            input_format,
            json,
        }) => {
            let path = file.or(target).ok_or_else(|| {
                anyhow::anyhow!("Provide a target path: `lpr audit <path>` or `lpr audit -f <path>`")
            })?;
            return audit::run_automated_security_audit(&path, input_format, json).await;
        }
        Some(Commands::Suggest {
            file,
            target,
            input_format,
            json,
        }) => {
            let path = file.or(target).ok_or_else(|| {
                anyhow::anyhow!(
                    "Provide a target path: `lpr suggest <path>` or `lpr suggest -f <path>`"
                )
            })?;
            return run_suggest_command(&path, input_format, json, cli.threads).await;
        }
        Some(Commands::Sdk { target }) => {
            print_sdk_templates(&target);
            return Ok(());
        }
        Some(Commands::HelpFull) => {
            print_full_manual();
            return Ok(());
        }
        Some(Commands::Gui { source }) => return gui::launch_native_desktop_gui(source),
        Some(Commands::Tui { file, input_format }) => {
            let default_path = file.unwrap_or_else(|| {
                if std::path::Path::new("samples/nginx_access.log").exists() {
                    "samples/nginx_access.log".to_string()
                } else {
                    ".".to_string()
                }
            });
            return tui::run_tui(&default_path, input_format).await;
        }
        Some(Commands::Mcp) => return mcp::run_mcp_stdio_server().await,
        Some(Commands::Serve { bind, source }) => return server::run_http_server(&bind, source).await,
        Some(Commands::Config { list: _, set_default }) => {
            if let Some(def_name) = set_default {
                let mut store = fleet::LprConfigFile::load(cli.cfg_file.as_deref());
                store.default_profile = def_name.clone();
                let p = store.save(cli.cfg_file.as_deref())?;
                println!("{SYM_DONE} Set default profile to `{}` in `{}`", def_name, p.to_string_lossy());
            }
            fleet::print_saved_profiles(cli.cfg_file.as_deref());
            return Ok(());
        }
        Some(Commands::Fleet {
            days,
            site,
            report_prefix,
            servers,
            config,
            host_pattern,
            log_path,
            archive_path,
            iis_auto,
            server_type,
            ssh,
            ssh_user,
            ssh_key,
            ssh_port,
            auth_user,
            auth_domain,
            password_ref,
            save_password,
            path_template,
            output,
            server_filter,
            server_numbers,
            local_path,
            status_prefix,
        }) => {
            let cfg = fleet::FleetScanConfig {
                cfg_file_path: cli.cfg_file.clone(),
                profile_name: cli.profile.clone(),
                save_profile_name: cli.save_profile.clone(),
                list_profiles: cli.list_profiles,
                days,
                site_name: site,
                report_prefix,
                servers_csv: servers,
                config_json: config,
                host_pattern,
                path_template,
                log_path,
                archive_path,
                iis_auto,
                server_type,
                ssh_enabled: ssh,
                ssh_user,
                ssh_key,
                ssh_port,
                auth_user,
                auth_domain,
                password_ref,
                save_password,
                output_dir: output,
                server_filter,
                server_numbers,
                local_path,
                status_prefix,
                threads: cli.threads,
                verbose: cli.verbose,
            };
            return fleet::run_fleet_scan(cfg).await;
        }
        None => {}
    }

    if cli.list_profiles {
        fleet::print_saved_profiles(cli.cfg_file.as_deref());
        return Ok(());
    }

    // Load or save general CLI profile settings from lpr.config.json if --profile or --save-profile is used
    let mut cfg_store = fleet::LprConfigFile::load(cli.cfg_file.as_deref());
    let active_prof_opt = cli
        .profile
        .as_ref()
        .and_then(|name| cfg_store.profiles.get(name))
        .or_else(|| cfg_store.profiles.get(&cfg_store.default_profile))
        .cloned();

    if let Some(ref save_name) = cli.save_profile {
        let mut prof = cfg_store
            .profiles
            .get(save_name)
            .cloned()
            .unwrap_or_default();
        if let Some(t) = cli.threads {
            prof.threads = Some(t);
        }
        if let Some(ref f) = cli.file {
            prof.local_path = Some(f.clone());
        }
        if let Some(ref q) = cli.query {
            prof.default_sql = Some(q.clone());
        }
        if cli.verbose {
            prof.verbose = Some(true);
        }
        cfg_store.profiles.insert(save_name.clone(), prof);
        if cfg_store.profiles.len() == 1 {
            cfg_store.default_profile = save_name.clone();
        }
        let saved_path = cfg_store.save(cli.cfg_file.as_deref())?;
        eprintln!(
            "{SYM_SAVE} Saved CLI profile `{}` to `{}`",
            save_name,
            saved_path.to_string_lossy()
        );
    }

    let profile_sql = active_prof_opt
        .as_ref()
        .and_then(|p| p.default_sql.as_deref());
    let profile_file = active_prof_opt
        .as_ref()
        .and_then(|p| p.local_path.as_deref());
    let effective_threads = cli
        .threads
        .or_else(|| active_prof_opt.as_ref().and_then(|p| p.threads));

    let raw_sql = cli
        .query
        .as_deref()
        .or(profile_sql)
        .unwrap_or("SELECT * FROM logs LIMIT 50");
    let (_, into_file) = extract_into_from_sql(raw_sql);
    let (rewritten_sql, extracted_file) = extract_source_from_sql(raw_sql);

    let default_stdin = if !std::io::stdin().is_terminal() {
        Some("-")
    } else {
        None
    };

    let file_pattern = cli
        .file
        .as_deref()
        .or(extracted_file.as_deref())
        .or(profile_file)
        .or(default_stdin)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Provide a file path via `-f <path>`, pipe via `stdin`, or specify in SQL (`SELECT * FROM '<path>'`). Run `lpr help-full` for examples."
            )
        })?;

    let effective_out_file = cli.out_file.as_deref().or(into_file.as_deref());
    let mut effective_output_format = if cli.vertical {
        OutputFormat::Vertical
    } else {
        cli.output_format
    };
    if let Some(out_p) = effective_out_file {
        effective_output_format = infer_output_format_from_path(out_p, effective_output_format);
    }

    // Determine logging / verbosity mode:
    // By default, show startup graphic banner + execution plan + final summary on stderr unless -q / --no-log / machine JSON stdout pipe
    let is_machine_stdout = effective_out_file.is_none()
        && matches!(
            effective_output_format,
            OutputFormat::Json | OutputFormat::Ndjson | OutputFormat::Csv | OutputFormat::Tsv | OutputFormat::Xml
        );
    let show_status = !cli.quiet && !cli.no_log && !cli.count_only && !is_machine_stdout;
    let is_verbose = (cli.verbose && !cli.no_verbose) || (cli.log_file.is_some() && !cli.no_verbose);

    let mut log_file_writer: Option<std::fs::File> = match &cli.log_file {
        Some(p) => std::fs::File::create(p).ok(),
        None => None,
    };

    let engine = LogEngine::with_options(effective_threads, is_verbose && show_status);
    let source_items_preview = resolve_source_items(file_pattern).unwrap_or_default();
    let total_source_bytes: u64 = source_items_preview.iter().map(|i| i.size_bytes()).sum();

    // 1. Clear Startup Banner & Execution Plan Header (Log Parser + Modern Rust style)
    if show_status || log_file_writer.is_some() {
        log_message(
            &mut log_file_writer,
            show_status,
            "================================================================================",
        );
        log_message(
            &mut log_file_writer,
            show_status,
            &format!(
                " {SYM_SHIELD}  LPR v{} — Multi-Threaded Rust SQL Log Engine (DataFusion 42 / Arrow 53)",
                LPR_VERSION
            ),
        );
        log_message(
            &mut log_file_writer,
            show_status,
            "================================================================================",
        );
        log_message(
            &mut log_file_writer,
            show_status,
            &format!(
                " {SYM_DIR} Input Source   : {} ({} file/archive stream(s), {:.2} MB uncompressed)",
                file_pattern,
                source_items_preview.len(),
                total_source_bytes as f64 / (1024.0 * 1024.0)
            ),
        );
        log_message(
            &mut log_file_writer,
            show_status,
            &format!(
                " {SYM_GEAR}  Worker Threads : {} parallel thread(s) | Output Sink: {:?}{}",
                engine.threads,
                effective_output_format,
                effective_out_file
                    .map(|p| format!(" -> `{}`", p))
                    .unwrap_or_default()
            ),
        );
        log_message(
            &mut log_file_writer,
            show_status,
            &format!(" {SYM_SEARCH} SQL Query      : {}", raw_sql),
        );
        log_message(
            &mut log_file_writer,
            show_status,
            "--------------------------------------------------------------------------------",
        );
        log_message(
            &mut log_file_writer,
            show_status,
            " ⏳ Reading & parsing log streams in parallel...",
        );
    }

    if cli.tail {
        let mut ckpt_store = CheckpointStore::load(cli.checkpoint.as_deref());
        eprintln!(
            "{SYM_RADIO} Live-tailing `{}` (interval={}ms, Ctrl+C to stop)...",
            file_pattern, cli.tail_interval_ms
        );
        loop {
            let tail_engine = LogEngine::with_options(cli.threads, false);
            if tail_engine
                .register_source_with_checkpoint(
                    "logs",
                    file_pattern,
                    cli.input_format,
                    cli.regex_pattern.as_deref(),
                    Some(&mut ckpt_store),
                )
                .await
                .is_ok()
            {
                if let Ok(batches) = tail_engine.query(&rewritten_sql).await {
                    let count: usize = batches.iter().map(|b| b.num_rows()).sum();
                    if count > 0 {
                        write_batches_with_options(
                            &batches,
                            effective_output_format,
                            effective_out_file,
                            Some(cli.max_width),
                        )?;
                        if cli.hook_url.is_some() || cli.hook_exec.is_some() {
                            let hook_cfg = HookConfig {
                                webhook_url: cli.hook_url.clone(),
                                exec_command: cli.hook_exec.clone(),
                                min_rows: cli.hook_min_rows,
                            };
                            evaluate_and_fire_hooks(&batches, &hook_cfg).await?;
                        }
                    }
                }
            }
            if cli.checkpoint.is_some() {
                ckpt_store.save(cli.checkpoint.as_deref())?;
            }
            tokio::time::sleep(std::time::Duration::from_millis(cli.tail_interval_ms)).await;
        }
    }

    let overall_start = std::time::Instant::now();
    let parse_start = std::time::Instant::now();

    let mut ckpt_store = CheckpointStore::load(cli.checkpoint.as_deref());
    let ckpt_opt = if cli.checkpoint.is_some() {
        Some(&mut ckpt_store)
    } else {
        None
    };

    let detected_fmt = engine
        .register_source_with_checkpoint(
            "logs",
            file_pattern,
            cli.input_format,
            cli.regex_pattern.as_deref(),
            ckpt_opt,
        )
        .await?;
    let parse_elapsed = parse_start.elapsed();
    let parse_stats = engine.get_last_stats();

    if log_file_writer.is_some() && is_verbose {
        for fsum in &parse_stats.file_summaries {
            log_message(
                &mut log_file_writer,
                false,
                &format!(
                    "  {SYM_OK} Parsed {:28} | {:>8} lines | {:>8} rows | {:>5} ms",
                    fsum.name, fsum.lines, fsum.rows, fsum.elapsed_ms
                ),
            );
        }
    }

    for join_spec in &cli.joins {
        if let Some((tbl, path)) = join_spec.split_once('=') {
            engine
                .register_source(tbl, path, InputFormat::Auto, None)
                .await?;
        }
    }

    if cli.stats && cli.query.is_none() {
        return run_goaccess_stats(&engine, file_pattern, detected_fmt).await;
    }

    let known_cols = engine.table_columns("logs").await;
    let final_sql = if cli.query.is_none()
        && (cli.grep.is_some() || cli.fields.is_some() || cli.count_only)
    {
        let select_projection = if cli.count_only {
            "COUNT(*) AS match_count".to_string()
        } else if let Some(ref f_list) = cli.fields {
            f_list
                .split(',')
                .map(|s| s.trim().replace('-', "_"))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            "*".to_string()
        };

        let where_clause = if let Some(ref pat) = cli.grep {
            format!(
                " WHERE {}",
                build_universal_search_predicate(&known_cols, pat, cli.invert_match)
            )
        } else {
            String::new()
        };

        format!("SELECT {} FROM logs{}", select_projection, where_clause)
    } else if cli.count_only {
        format!("SELECT COUNT(*) AS match_count FROM ({})", rewritten_sql)
    } else {
        rewritten_sql
    };

    let sql_start = std::time::Instant::now();
    let batches = engine.query(&final_sql).await?;
    let sql_elapsed = sql_start.elapsed();
    let matched_rows: usize = batches.iter().map(|b| b.num_rows()).sum();

    if cli.count_only {
        let count_val = batches
            .first()
            .and_then(|b| arrow::util::display::array_value_to_string(b.column(0), 0).ok())
            .unwrap_or_else(|| "0".to_string());
        println!("{}", count_val);
    } else {
        write_batches_with_options(
            &batches,
            effective_output_format,
            effective_out_file,
            Some(cli.max_width),
        )?;
    }

    let total_elapsed = overall_start.elapsed();
    let secs = total_elapsed.as_secs_f64().max(0.0001);
    let mb_processed = (parse_stats.total_bytes as f64) / (1024.0 * 1024.0);
    let throughput_mb_s = mb_processed / secs;
    let lines_per_sec = (parse_stats.total_lines as f64) / secs;

    // 2. Final Log Parser 2.2 + Modern Summary Footer
    if show_status || cli.stats || log_file_writer.is_some() {
        let show_on_stderr = show_status || cli.stats;
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            "--------------------------------------------------------------------------------",
        );
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            &format!(
                " {SYM_DONE} Task Complete   : Detected Format: {:?} | Threads Used: {}",
                detected_fmt, engine.threads
            ),
        );
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            &format!(
                " {SYM_CHART} Statistics      : Files Processed : {:>10}  | Total Data   : {:>8.2} MB",
                parse_stats.files_processed, mb_processed
            ),
        );
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            &format!(
                "                    : Lines Processed : {:>10}  | Rows Parsed  : {:>10}",
                parse_stats.total_lines, parse_stats.total_rows
            ),
        );
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            &format!(
                "                    : Elements Output : {:>10}  | Throughput   : {:>8.2} MB/s ({:.0} lines/s)",
                matched_rows, throughput_mb_s, lines_per_sec
            ),
        );
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            &format!(
                " ⏱️  Execution Time  : {:.3} sec total (Parse: {:.3}s | SQL Engine: {:.3}s){}",
                secs,
                parse_elapsed.as_secs_f64(),
                sql_elapsed.as_secs_f64(),
                effective_out_file
                    .map(|p| format!(" | Saved to `{}`", p))
                    .unwrap_or_default()
            ),
        );
        log_message(
            &mut log_file_writer,
            show_on_stderr,
            "================================================================================",
        );
    }

    if cli.checkpoint.is_some() {
        ckpt_store.save(cli.checkpoint.as_deref())?;
    }

    if cli.hook_url.is_some() || cli.hook_exec.is_some() {
        let hook_cfg = HookConfig {
            webhook_url: cli.hook_url,
            exec_command: cli.hook_exec,
            min_rows: cli.hook_min_rows,
        };
        evaluate_and_fire_hooks(&batches, &hook_cfg).await?;
    }

    Ok(())
}
