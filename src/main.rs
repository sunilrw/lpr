mod audit;
mod checkpoint;
mod engine;
mod gui;
mod hooks;
mod mcp;
mod parsers;
mod server;
mod sinks;
mod tui;
mod udfs;

use anyhow::Result;
use checkpoint::CheckpointStore;
use clap::{Parser, Subcommand};
use engine::LogEngine;
use hooks::{evaluate_and_fire_hooks, HookConfig};
use parsers::InputFormat;
use sinks::{write_batches, OutputFormat};

#[derive(Parser)]
#[command(
    name = "lpr",
    version = "1.0.0",
    about = "Modern Rust SQL Log Parser & Security Auditor",
    long_about = "High-performance log engine powered by Apache Arrow & DataFusion.\nQuery, analyze, and security-audit any log format using ANSI SQL and built-in cyber UDFs."
)]
struct Cli {
    /// ANSI SQL query to execute against the 'logs' table (e.g. 'SELECT * FROM logs LIMIT 50')
    #[arg(value_name = "SQL_QUERY")]
    query: Option<String>,

    /// Path or glob pattern of log files to query (e.g. -f access.log, -f '/var/log/**/*.log.gz')
    #[arg(short = 'f', long = "file", value_name = "PATH_OR_GLOB")]
    file: Option<String>,

    /// Log format parser (auto-detects from content and extension if omitted)
    #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
    input_format: InputFormat,

    /// Output sink format
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Table)]
    output_format: OutputFormat,

    /// Write query output directly to a file instead of stdout
    #[arg(long = "out-file", value_name = "PATH")]
    out_file: Option<String>,

    /// State file to persist read byte offsets for continuous/incremental log tailing
    #[arg(long = "checkpoint", value_name = "STATE_FILE_JSON")]
    checkpoint: Option<String>,

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
    /// Run automated security, OWASP, and CIS compliance audits against logs or network configs
    Audit {
        /// Target log file or configuration to audit
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: String,

        /// Format of the target file (auto-detects if omitted)
        #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
        input_format: InputFormat,

        /// Output audit findings as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Launch the native desktop window application (lpr Studio)
    Gui {
        /// Preload a specific log file or glob pattern
        #[arg(long, value_name = "PATH")]
        source: Option<String>,
    },

    /// Launch interactive terminal dashboard (TUI) with live query editor
    Tui {
        /// Log file to inspect in the terminal UI
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: String,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Audit { file, input_format, json }) => return audit::run_automated_security_audit(&file, input_format, json).await,
        Some(Commands::Gui { source }) => return gui::launch_native_desktop_gui(source),
        Some(Commands::Tui { file, input_format }) => return tui::run_tui(&file, input_format).await,
        Some(Commands::Mcp) => return mcp::run_mcp_stdio_server().await,
        Some(Commands::Serve { bind, source }) => return server::run_http_server(&bind, source).await,
        None => {}
    }

    let sql = cli.query.as_deref().unwrap_or("SELECT * FROM logs LIMIT 50");
    let file_pattern = cli.file.as_deref().ok_or_else(|| anyhow::anyhow!("Provide a file path via `-f <path>` or use subcommands"))?;

    let mut ckpt_store = CheckpointStore::load(cli.checkpoint.as_deref());
    let ckpt_opt = if cli.checkpoint.is_some() { Some(&mut ckpt_store) } else { None };

    let engine = LogEngine::new();
    engine.register_source_with_checkpoint("logs", file_pattern, cli.input_format, cli.regex_pattern.as_deref(), ckpt_opt).await?;

    for join_spec in &cli.joins {
        if let Some((tbl, path)) = join_spec.split_once('=') {
            engine.register_source(tbl, path, InputFormat::Auto, None).await?;
        }
    }

    let batches = engine.query(sql).await?;
    write_batches(&batches, cli.output_format, cli.out_file.as_deref())?;

    if cli.checkpoint.is_some() { ckpt_store.save(cli.checkpoint.as_deref())?; }

    if cli.hook_url.is_some() || cli.hook_exec.is_some() {
        let hook_cfg = HookConfig { webhook_url: cli.hook_url, exec_command: cli.hook_exec, min_rows: cli.hook_min_rows };
        evaluate_and_fire_hooks(&batches, &hook_cfg).await?;
    }

    Ok(())
}
