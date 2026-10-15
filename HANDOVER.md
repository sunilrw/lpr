# LPR (Log Parser Rust) — Project Handover & Roadmap Document

**Date:** 2026-10-15  
**Version:** 1.0.0  
**Project:** Modern Rust SQL Log Parser & Security Auditor  
**Location:** `/Users/sunil/Development/Personal/lpr`

---

## 1. Executive Summary & Current State

`lpr` is a high-performance, single-binary log engine and security auditor written in Rust, powered by **Apache Arrow (53.0)** and **DataFusion (42.0)**. It is designed as a modern, cross-platform replacement for legacy tools like Microsoft Log Parser 2.2, GoAccess, and log-tailing scripts.

### What is Currently Implemented & Tested
1. **Vectorized ANSI SQL Engine**: Executes complex SQL queries, aggregations (`GROUP BY`), joins, and filters over local and globbed log files in parallel.
2. **20+ Log Formats**: Auto-detects and parses W3C/IIS, Nginx, Syslog/Auth.log, FortiGate Firewall KV, Cisco Config (.cfg), Cisco ASA, AWS S3/VPC/ALB, Azure Blob, GCP Logging, CEF, JSON/NDJSON, CSV, TSV, Excel (.xlsx), Parquet, and EVTX.
3. **Cyber & Security UDFs**:
   - `detect_threat(col)`: Real-time detection of SQL Injection, XSS, Log4Shell, RCE, Path Traversal (LFI), and SSRF.
   - `ip_in_cidr(ip, 'net/mask')`: IPv4/IPv6 subnet inclusion.
   - `shannon_entropy(col)`: Entropy anomaly detection for base64 payloads and DGA domains.
   - `mask_pii(col)`: GDPR/HIPAA email redaction.
   - `cluster_template(col)`: Drain log clustering (normalizes variables to `<*>`).
   - `url_decode(col)` & `parse_ua(col)`: URI percent decoding and User-Agent classifier.
4. **Automated Security Auditor (`lpr audit`)**: Rules for CIS Cisco ACL checks, Type 7 weak passwords, OWASP web attacks, and S3 modifications.
5. **Multi-Interface Support**:
   - **CLI**: Standard headless querying, stdout pipes, and export sinks (`table`, `json`, `ndjson`, `csv`, `markdown`, `sql`, `parquet`).
   - **Web Studio (`lpr serve`)**: Embedded Axum/Tokio web server running at `http://127.0.0.1:8080` with dark-mode SOC analytics dashboard, query presets, live table filtering, and security audit tabs.
   - **TUI Dashboard (`lpr tui`)**: Ratatui/crossterm terminal UI.
   - **AI Agent API (`lpr mcp`)**: Model Context Protocol stdio server for LLM integration.
6. **Cross-Compiled Binaries**:
   - macOS (native): `target/release/lpr`
   - Windows 64-bit (native standalone, zero WebView2 dependencies): `dist/lpr.exe` (and `target/x86_64-pc-windows-gnu/release/lpr.exe`).

---

## 2. Windows IIS Error Analysis: "stream did not contain valid UTF-8"

### Symptom
When running against Windows IIS logs:
```cmd
D:\emLogs\HOB2014\W3SVC4>d:\emScripts\lpr.exe -f "*.log" "select * FROM logs WHERE sc_status LIKE '5%'"
Error: stream did not contain valid UTF-8
```

### Root Cause
1. On Windows Server (especially older or localized IIS installations like IIS 7.5, 8.5, 10.0), IIS W3C log files are often generated in:
   - **UTF-16LE with BOM** (`0xFF 0xFE`), OR
   - **Windows-1252 / ANSI / ISO-8859-1** (Latin-1).
2. In Rust, standard `BufRead::lines()` strictly requires valid UTF-8 byte sequences. When encountering non-UTF-8 bytes (such as high-order bytes `>= 0x80` in Windows-1252 or 2-byte UTF-16 code units), Rust returns an `io::Error: stream did not contain valid UTF-8`.

### Planned Solution (To Be Implemented)
`encoding_rs` is already a dependency in `Cargo.toml`. The reader in `src/parsers.rs` must be upgraded to:
1. Detect UTF-16LE / UTF-16BE BOM at the start of the file.
2. If UTF-16 is detected, decode using `encoding_rs::UTF_16LE.decode(&bytes)`.
3. If not UTF-16, read lines with `read_until(b'\n')` and apply lossy UTF-8 conversion: `String::from_utf8_lossy(&buf)` or `encoding_rs::WINDOWS_1252.decode(&bytes)`.
4. This guarantees that **no file ever fails with a UTF-8 error**, regardless of Windows locale, BOM, or encoding.

---

## 3. Microsoft Log Parser 2.2 Compatibility Roadmap

The user requested: *"can we have same syntax also working same as log parser"*.

### Feature Parity Plan:
| Microsoft Log Parser Syntax | Current `lpr` Status | Planned `lpr` Enhancement |
| :--- | :--- | :--- |
| `logparser "SELECT * FROM C:\logs\*.log WHERE sc-status >= 500"` | `-f` flag required: `lpr -f "*.log" "SELECT ..."` | **Auto-extract file/glob from SQL `FROM` clause**: If `FROM 'C:\logs\*.log'` or `FROM *.log` is provided without `-f`, automatically register that path as the `logs` table! |
| `-i:IISW3C` or `-i:W3C` | `-i w3c` | Allow `-i:w3c`, `-i:iis`, `-i:iisw3c`, `-i:csv` (accept colon delimiter). |
| Hyphenated column names: `[sc-status]`, `sc-status` | Normalized to `sc_status` | Auto-alias columns so both `sc_status` and `sc-status` (or `[sc-status]`) work cleanly in queries. |
| `-o:CSV`, `-o:DATAGRID` | `-o csv`, `lpr gui` / `lpr serve` | Accept `-o:csv`, `-o:json`, `-o:table`. |

---

## 4. Startup Banner & Help Experience

The user requested:
- *"how can we show a name of the software version in start"*
- *"Can it show a help if no parameter"*

### Planned Implementation:
1. **Zero-Parameter Execution**:
   - If `lpr` is run without any arguments (`args.len() == 1`), instead of printing an error, print a colorful ASCII / ANSI banner and quick-start examples, followed by `--help`.
2. **Startup Banner**:
   ```text
      ___             ___                         
     / / |___  _ __  / _ \___ _ _ _ ___ ___ _ _   
    / /| '_ \ '_ \/ /_\/ _ \ '_| '_/ -_) _ \ '_|  
   /_/ |_.__/ .__/\__/\___/_| |_|  \___|___/_|    
            |_|       v1.0.0 (DataFusion 42 / Arrow 53)
   ==============================================================
   ```
   - Automatically suppressed when output is piped (`!io::stdout().is_terminal()`), or when running in machine-mode (`-o json`, `-o ndjson`, `-o csv`), ensuring Unix pipeline compatibility.

---

## 5. Web & TUI File Explorer & Context-Aware Intent Assistant

The user requested:
- *"in tui web can we select the folder / file using file selector and option for full help and context aware / intent aware auto fill and help in cmd / cli also similar help"*

### Architecture Design:
1. **Web Studio Server-Side File Browser (`/v1/browse`)**:
   - Add an endpoint `POST /v1/browse` taking `{ "path": "D:\\emLogs" }`.
   - Returns child directories and matching log files (`.log`, `.txt`, `.cfg`, `.json`, `.csv`, `.gz`).
   - Web UI (`src/ui.html`) gets an interactive file/folder picker modal so the user doesn't have to manually type long server paths.
2. **Context-Aware Intent Auto-Fill**:
   - When a file is selected (e.g. `u_ex*.log`), `lpr` sniffs the header `#Fields:`.
   - The Web and TUI UI automatically presents relevant query chips:
     - 🚨 *Find 500-level Server Errors (`sc_status LIKE '5%'`)*
     - ⏱️ *Top 10 Slowest Requests (`ORDER BY time_taken DESC`)*
     - 📉 *HTTP Substatus Breakdown (`sc_status, sc_substatus`)*
     - 🌐 *Top 10 Client IPs (`GROUP BY c_ip`)*
   - In CLI: Add `lpr suggest -f <file>` which inspects the schema and suggests 5 tailored SQL queries.

---

## 6. What Else is Missing? (Gap Analysis)

1. **Encoding Resilience (CRITICAL)**: Support Windows-1252, UTF-16LE, and mixed byte encodings seamlessly via `encoding_rs` and lossy fallback.
2. **SQL `FROM '<path>'` Parser**: Detect file paths or globs directly inside SQL queries so `-f` is optional.
3. **Directory Browsing in Web UI**: Add a visual file picker to `src/ui.html`.
4. **Log Parser Function Compatibility**:
   - `EXTRACT_TOKEN(str, index, delimiter)`
   - `TO_TIMESTAMP(date, time)`
   - `SUBSTR()`, `INDEX_OF()` aliases.
5. **Streaming / Live Tail Mode (`-t` / `--tail`)**:
   - Follow active log files in real-time (`tail -f`) and run SQL continuous queries / alerts.
6. **Multi-File Memory Bounds**:
   - For 100+ GB log directories, add chunked batch execution to keep peak RAM under a configurable threshold (e.g. `--max-memory 2GB`).

---

## 7. Build & Cross-Compilation Cheat Sheet (For Reference Only)

*Note: As instructed, do not execute builds right now.*

- **Mac Native Build**:
  ```bash
  export PATH="$HOME/.cargo/bin:$PATH"
  cargo build --release
  # Output: target/release/lpr
  ```

- **Windows 64-bit Standalone Cross-Compilation (from Mac)**:
  ```bash
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
  cargo build --release --target x86_64-pc-windows-gnu
  # Output: dist/lpr.exe (and target/x86_64-pc-windows-gnu/release/lpr.exe)
  ```
