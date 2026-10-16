# 🛡️ LPR (Log Parser Rust) v1.4.0

**Modern Multi-Threaded Rust SQL Log Engine, Fleet Error Scanner & Automated Security Auditor**  
*Powered by Apache Arrow 53, DataFusion 42 & Rayon Parallel Engine*  
✨ **Made using vibe coding by Sunil Warrier**

[![License: MIT OR Unlicense](https://img.shields.io/badge/License-MIT%20%2F%20Unlicense-brightgreen.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](Cargo.toml)
[![Engine: DataFusion 42](https://img.shields.io/badge/Engine-DataFusion%2042%20%2F%20Arrow%2053-blue.svg)](Cargo.toml)

---

## 🚀 Overview

`lpr` is a zero-dependency, single-binary SQL log parser, multi-server fleet scanner, and cybersecurity auditor written in Rust. It is designed as a ultra-fast, cross-platform replacement and superset of **Microsoft Log Parser 2.2**, **GoAccess**, **lnav**, and custom PowerShell/Bash log-scraping scripts.

It can decompress and query **1+ GB of logs (2.5+ million lines across multiple files inside a `.zip` archive) in ~0.60 seconds (~1,700+ MB/s)** using parallel Rayon worker threads and vectorized Apache Arrow execution.

---

## ✨ Key Features

### 1. ⚡ Multi-Threaded Archive & Stream Engine (`.zip`, `.gz`, `.zst`, `.log`)
- **Direct Archive Querying**: Query `.zip` archives containing dozens of log files, `.gz`, and `.zst` streams directly in memory without extracting them to disk first.
- **Parallel Multi-Core Execution**: Every file or `.zip` entry is parsed in parallel across CPU cores (`-j <threads>` / `--threads <N>`) and registered as parallel DataFusion partitions.
- **Universal Encoding Resilience**: Automatically detects and decodes **UTF-16LE BOM**, **UTF-16BE BOM**, **UTF-8 BOM**, and **Windows-1252 / Latin-1** logs without ever failing with `stream did not contain valid UTF-8`.

### 2. 🪟 100% Microsoft Log Parser 2.2 Compatibility
- **Direct `FROM` & `INTO` in SQL**:
  ```cmd
  lpr -i:IISW3C "SELECT TOP 10 LogFilename, LogRow, cs-uri-stem, [sc-status], [time-taken] INTO 500_errors.csv FROM 'samples/iis_u_ex.log' WHERE sc-status LIKE '5%'"
  ```
- **Colon Flags**: Supports `-i:IISW3C`, `-i:W3C`, `-i:SMTP`, `-i:TEXTLINE`, `-i:CSV`, `-o:DATAGRID`, `-o:CSV`, `-o:XML`, `-o:CHART`, `-o:JSON`, `-q:ON`, `-stats:ON`, and `file:query.sql`.
- **Hyphenated & Bracketed Columns**: Supports `sc-status`, `[time-taken]`, `cs(User-Agent)`, `cs(Cookie)`, `cs(Referer)`, and `SELECT TOP N`.
- **16 Classic Log Parser Functions**: `extract_token`, `extract_prefix`, `extract_suffix`, `extract_filename`, `extract_path`, `extract_extension`, `win32_error_description`, `reversedns`, `to_timestamp`, `index_of`, `strlen`, `to_uppercase`, `to_lowercase`, `to_int`, `to_real`, `extract_email`, `extract_domain`.

### 3. 🐧 Famous Linux Power-Tool Syntax (`grep`, `awk`, `GoAccess`, `lnav`, `stdin`)
- **Structured Grep & Field Cut (`-g` / `-E`, `-v`, `-c`, `-F`)**:
  ```bash
  lpr -f samples/iis_u_ex.log -g "500" -F date,time,c_ip,cs_uri_stem,sc_status,time_taken
  lpr -f samples/nginx_access.log -g "sqlmap" -v -c
  ```
- **GoAccess Instant Summary & Bar Charts (`--stats` and `-o:CHART`)**:
  ```bash
  lpr -f samples/iis_u_ex.log --stats
  lpr -f samples/iis_smtp_u_ex.log --stats
  lpr -f samples/iis_u_ex.log -o:CHART "SELECT sc-status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC"
  ```
- **`lnav` Filter Syntax**: `lpr -f samples/nginx_access.log ":filter-in UNION"`
- **Unix & PowerShell `stdin` Piping**: `cat samples/nginx_access.log | lpr -i nginx "SELECT remote_addr, status, detect_threat(request_uri) FROM stdin"`

### 4. 🌐 Multi-Server Fleet Scanner & Saved Profiles (`lpr fleet` & `lpr config`)
Scan dozens of **Windows IIS** (via SMB `\\server\d$...` + automatic `applicationHost.config` site discovery) or **Linux Nginx / Apache / Caddy / HAProxy / Tomcat** servers (via SSH `--ssh` + automatic `/etc/nginx`, `/etc/apache2`, `/etc/httpd`, `/etc/caddy` vhost discovery):
```bash
# Save a Windows IIS farm profile once into lpr.config.json:
lpr fleet --save-profile prod-iis --servers servers.csv --site W3SVC1 --threads 8 --days 7

# Save a Linux Nginx farm profile over SSH once into lpr.config.json:
lpr fleet --save-profile prod-nginx --servers linux_servers.csv --server-type nginx --ssh --ssh-user ubuntu --log-path /var/log/nginx

# Run anytime using the saved profile (or filter server numbers 1-12):
lpr fleet --profile prod-iis --server-numbers "1-12" --days 3

# View or manage saved profiles:
lpr config
```

### 5. 🛡️ Automated Security Auditor (`lpr audit`) & Cyber SQL UDFs
- **One-Liner Security Audit**:
  ```bash
  lpr audit samples/nginx_access.log
  lpr audit samples/iis_u_ex.log
  lpr audit samples/iis_smtp_u_ex.log
  lpr audit samples/cisco_switch.cfg
  ```
- **Cybersecurity SQL UDFs**:
  - `detect_threat(col)` — Detects SQL Injection, XSS, Path Traversal (LFI), RCE / Log4Shell, SSRF, and Vulnerability Scanners.
  - `ip_in_cidr(ip, '10.0.0.0/8')` — IPv4/IPv6 CIDR subnet matching.
  - `shannon_entropy(col)` — Entropy anomaly scoring for obfuscated/base64 payloads and DGA domains.
  - `mask_pii(col)` — GDPR/HIPAA email redaction (`[REDACTED_EMAIL]`).
  - `cluster_template(col)` — Drain log clustering into structural templates (`<*>`).
  - `url_decode(col)` & `parse_ua(col)` — Percent decoding and User-Agent Bot/OS classification.

### 6. 🖥️ Multi-Interface Experience (CLI, Web Studio, TUI, .NET/PowerShell, REST API, MCP)
- **Web Studio (`lpr serve`)**: Dark-mode SOC web console at `http://127.0.0.1:8080` with visual server-side File/Folder Browser, Context-Aware Intent Chips, Live SQL `Tab` Auto-Completion, and Full Help Manual.
- **Terminal UI (`lpr tui`)**: Interactive terminal dashboard with `Tab` auto-complete, `F1` Full Help, `F2` Smart Intents, and `F3` File Browser.
- **Context-Aware Intent Assistant (`lpr suggest <file>`)**: Inspects any log file's schema and outputs ready-to-run SQL queries.
- **PowerShell & .NET C# SDK Generator (`lpr sdk`)**: Generates native PowerShell cmdlets (`Invoke-LprQuery`) and a `.NET C#` `LprClient` class.
- **AI Agent MCP Server (`lpr mcp`)**: Model Context Protocol stdio server exposing `query_logs`, `audit_logs`, and `suggest_queries`.

---

## 🛠️ Building from Source

```bash
# Fast incremental build (low CPU):
cargo build --release

# Final optimized LTO distribution build:
cargo build --profile dist

# Cross-compile standalone Windows 64-bit lpr.exe from macOS/Linux:
cargo build --release --target x86_64-pc-windows-gnu
```

---

## 📜 License

Released under the **MIT License** and **The Unlicense** (dual-licensed).  
**Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software for any purpose, commercial or non-commercial.**

**Made using vibe coding by Sunil Warrier**
