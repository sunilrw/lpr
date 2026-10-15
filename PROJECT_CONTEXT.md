# LPR Technical Context & Developer Specification

This document provides deep technical context for developers and AI models working on the `lpr` codebase.

---

## 1. System & Toolchain Specification

- **Host Machine:** macOS (Apple Silicon `aarch64-apple-darwin`)
- **Primary Toolchain:** Rust `1.98.1` (`stable-aarch64-apple-darwin`)
- **Cross-Compilation Toolchain:** 
  - Rust Target: `x86_64-pc-windows-gnu`
  - Cross Linker: `/opt/homebrew/bin/x86_64-w64-mingw32-gcc`
  - Cross Archiver: `/opt/homebrew/bin/x86_64-w64-mingw32-ar`
  - Config: [`.cargo/config.toml`](file:///Users/sunil/Development/Personal/lpr/.cargo/config.toml)
- **CI/CD Platform:** GitHub Actions ([`.github/workflows/build.yml`](file:///Users/sunil/Development/Personal/lpr/.github/workflows/build.yml)) with `windows-latest`, `ubuntu-latest`, `macos-latest`.

---

## 2. Source Code Architecture & File Map

```
/Users/sunil/Development/Personal/lpr/
├── Cargo.toml            # Manifest, dependencies, feature gates, release profiles
├── .cargo/
│   └── config.toml       # MinGW linker configuration for Windows cross-compilation
├── .github/
│   └── workflows/
│       └── build.yml     # Multi-platform CI/CD build & release pipeline
├── samples/              # Ready-to-query sample files (Nginx, IIS, Firewall, Cisco, JSON)
├── src/
│   ├── main.rs           # CLI definition (Clap 4.5), subcommand dispatch, banner logic
│   ├── engine.rs         # DataFusion 42 SessionContext wrapper, schema registration
│   ├── parsers.rs        # Auto-detection, file decoders (.gz, .zst), 20+ format parsers
│   ├── udfs.rs           # Custom DataFusion SQL scalar functions (cyber & security)
│   ├── audit.rs          # Security & compliance audit rule evaluations
│   ├── server.rs         # Axum 0.7 REST API & embedded HTTP UI server
│   ├── ui.html           # Dark-mode SOC Studio UI (Tailwind CSS, zero build step)
│   ├── gui.rs            # Desktop windowing (Tao 0.30 + Wry 0.44, gated by feature="gui")
│   ├── tui.rs            # Terminal dashboard (Ratatui 0.28 + Crossterm 0.28)
│   ├── mcp.rs            # Model Context Protocol (MCP) JSON-RPC stdio server
│   ├── hooks.rs          # Webhook HTTP POST and subprocess exec triggers
│   ├── checkpoint.rs     # Byte-offset state store for incremental consumption
│   └── sinks.rs          # Output formatters (Table, CSV, JSON, NDJSON, Markdown, SQL, Parquet)
├── tests/
│   └── smoke_test.sh     # Comprehensive smoke test suite
├── HANDOVER.md           # High-level project handover & feature roadmap
└── PROJECT_CONTEXT.md    # This technical context specification
```

---

## 3. Detailed Component Deep-Dive

### A. The Parsing Pipeline (`src/parsers.rs`)
- **Entry points:** `register_source` and `register_source_with_checkpoint`.
- **Path Resolution:** Supports single files and glob patterns (`/logs/**/*.log*`) via `glob::glob`.
- **Compression:** Auto-detects `.gz` (via `flate2::read::GzDecoder`) and `.zst` (via `zstd::stream::read::Decoder`).
- **Batch Construction:** Builds Apache Arrow `RecordBatch` structures using `StringBuilder` and `StringArray` for zero-copy memory layouts.

### B. The SQL Engine (`src/engine.rs`)
- Uses `datafusion::prelude::SessionContext`.
- Registers parsed `RecordBatch` instances as in-memory DataFusion `MemTable` tables under table name `logs` (and custom table names for joins).
- Registers custom cyber UDFs defined in `src/udfs.rs`.
- Query execution produces `Vec<RecordBatch>`, which is passed to output sinks.

### C. Web & REST Server (`src/server.rs`)
- Uses `axum::Router` on Tokio runtime.
- Routes:
  - `GET /`: Serves embedded `ui.html` via `include_str!("ui.html")`.
  - `GET /v1/info`: Returns server metadata, default source, and sample paths.
  - `POST /v1/query`: Accepts `{ sql: String, source?: String, format?: String }`, returns `{ row_count: usize, execution_time_ms: u128, data: Value }`.
  - `POST /v1/audit`: Accepts `{ source?: String, format?: String }`, returns security findings.
  - `GET /metrics`: Prometheus metric scraper.

### D. Desktop GUI Gating (`src/gui.rs` & `Cargo.toml`)
- The `gui` feature gates `wry` and `tao`.
- By default, `default = []` in `Cargo.toml` so server builds (`lpr.exe`) compile without `WebView2Loader.dll` or native GUI dependencies.
- Desktop GUI can be compiled by passing `--features gui`.

---

## 4. Technical Analysis of Upcoming Tasks

### Task 1: Fix UTF-8 / Windows-1252 / UTF-16 Log Reading
**Problem:** `open_log_reader` returns `BufReader` where `reader.lines()` fails with `Error: stream did not contain valid UTF-8` on IIS logs.  
**Implementation Pattern:**
Instead of `reader.lines()`, use a custom line iterator that reads raw bytes with `read_until(b'\n', &mut buf)`:
```rust
// Check BOM on first read:
// If starts with [0xFF, 0xFE], decode as UTF-16LE via encoding_rs::UTF_16LE.decode
// Otherwise, convert line via String::from_utf8_lossy(&buf).to_string()
```
This guarantees zero crashes across all legacy Windows, IIS, Exchange, and firewall logs.

### Task 2: Microsoft Log Parser Syntax Alignment
**Problem:** Users want to run `lpr "SELECT * FROM 'C:\inetpub\logs\*.log' WHERE sc_status LIKE '5%'"` without needing `-f`.  
**Implementation Pattern:**
In `src/main.rs`:
If `cli.file` is `None`, use a regex to scan the `query` string for `FROM\s+['"]?([^'"\s;]+)['"]?`. If the captured token contains a dot, slash, backslash, or asterisk, treat it as the file path/glob, replace it with `FROM logs` in the SQL, and register it!

### Task 3: Startup Banner & No-Parameter Help
**Problem:** Running `lpr.exe` without parameters prints an unhelpful error.  
**Implementation Pattern:**
In `src/main.rs`, check if `std::env::args().len() <= 1`:
```rust
if std::env::args().len() <= 1 {
    println!("{}", get_ascii_banner());
    Cli::command().print_help()?;
    return Ok(());
}
```

### Task 4: Web UI Server-Side File Browser
**Problem:** Users must manually type server paths.  
**Implementation Pattern:**
1. In `src/server.rs`: Add `POST /v1/browse` endpoint accepting `{ path: String }`. Use `std::fs::read_dir` to return directories and `.log`, `.txt`, `.cfg`, `.json`, `.csv`, `.gz` files.
2. In `src/ui.html`: Add a folder browse button with an interactive file-selection modal.
