# LPR (Log Parser Rust) — Project Handover & Complete Architecture Guide

**Date:** 2026-10-16
**Version:** 1.4.0
**Project:** Modern Multi-Threaded Rust SQL Log Engine, Fleet Error Scanner & Security Auditor
**Author / Attribution:** Made using vibe coding by Sunil Warrier
**License:** MIT OR The Unlicense (Open-Source — anyone can modify and use for any purpose)

---

## 1. Executive Summary

`lpr` is a high-performance, single-binary SQL log parser, multi-server fleet scanner, and cybersecurity auditor written in Rust, powered by **Apache Arrow (53.0)**, **DataFusion (42.0)**, and **Rayon (1.10)**. It is a complete, cross-platform replacement and superset of **Microsoft Log Parser 2.2**, **GoAccess**, **lnav**, and custom PowerShell/Bash log-scraping scripts.

Benchmark: parses and queries **1.05 GB of IIS logs (2.55M lines across 11 files inside a `.zip`) in ~0.6 s (~1,700+ MB/s)** on a 14-core Apple Silicon host.

---

## 2. Repository Layout (all paths relative to repo root)

```
├── Cargo.toml              # v1.4.0, authors=["Sunil Warrier"], license = "MIT OR Unlicense"
├── LICENSE                 # Dual MIT / Unlicense — "Made using vibe coding by Sunil Warrier"
├── README.md               # GitHub landing page
├── HANDOVER.md             # This file
├── PROJECT_CONTEXT.md      # Developer spec & next-agent transfer notes
├── AGENTS.md               # Build rules (incremental vs dist)
├── .gitignore              # Excludes /target, Cargo.lock, *.zip (except samples/**), lpr.config.json, samples_client_local/
├── docs/
│   ├── SAMPLE_QUERIES.md   # 200+ ready-to-run SQL recipes across all log types (22 sections)
│   └── EXPECTED_OUTPUTS.md # Sample output shapes for every sink/format/mode
├── samples/                # PUBLIC, synthetic-only logs — 26 files across 18 categories:
│   ├── iis/                #   u_extend01.log, u_extend02.log, multi_site_logs.zip
│   ├── iis_smtp/           #   u_ex260101.log (MAIL/RCPT/EHLO/AUTH/VRFY commands)
│   ├── nginx/              #   access.log (combined format incl. SQLi/LFI/502 rows)
│   ├── apache/             #   access.log
│   ├── caddy/              #   caddy.json (JSON access logs)
│   ├── haproxy/            #   haproxy.log
│   ├── syslog/             #   auth.log (SSH brute force, sudo)
│   ├── firewall/           #   firewall.log (key=value pairs, allowed/denied)
│   ├── cisco_asa/          #   asa.log (%ASA-4/6 events)
│   ├── cisco_config/       #   router.cfg (interfaces, ACLs, SNMP)
│   ├── cef/                #   cef.log
│   ├── aws/                #   alb_access.log, vpc_flow.log, s3_access.log
│   ├── azure/              #   activity.json
│   ├── gcp/                #   audit.json
│   ├── evtx/               #   security_events.json (EventID 4624/4625)
│   ├── json_logs/          #   events.ndjson, app.log (key=value text)
│   ├── csv_logs/           #   events.csv, events.tsv
│   ├── gz_logs/            #   nginx_access.log.gz, u_extend01.log.gz
│   └── zstd_logs/          #   access.log.zst
├── samples_client_local/   # GITIGNORED — local-only client test data, never publish
├── tests/smoke_test.sh     # 10-suite smoke test
├── dist/                   # lpr.exe (Windows x86_64), lpr (macOS arm64), lpr.psm1, LprClient.cs
└── src/
    ├── main.rs             # Clap CLI, LogParser colon-flag preprocessor, Linux flags, banner, sdk, help-full
    ├── engine.rs           # DataFusion SessionContext, MemTable partitioning, SQL normalizer, intents
    ├── parsers.rs          # Rayon-parallel W3C/regex/raw parsers; .zip/.gz/.zst; UTF-16/Win-1252 decoding
    ├── fleet.rs            # Fleet scanner: SMB+IIS applicationHost.config, SSH for Linux; lpr.config.json profiles
    ├── udfs.rs             # 27 scalar UDFs (14 LP2.2 + 9 cyber/email + 4 time-series/utility)
    ├── audit.rs            # Multi-rule audit reports (IIS, SMTP, Nginx, Cisco, Firewall, AWS, cloud)
    ├── server.rs           # Axum REST API (GET/POST /v1/query, /v1/audit, /v1/browse, /v1/schema, /metrics)
    ├── ui.html             # lpr Studio web UI (file browser, Tab autocomplete, intent chips, help)
    ├── tui.rs              # Ratatui TUI (F1 help, F2 intents, F3 browser, Tab complete)
    ├── mcp.rs              # MCP JSON-RPC stdio server (query_logs, audit_logs, suggest_queries)
    ├── gui.rs              # Tao+Wry native window (feature="gui")
    ├── sinks.rs            # Table, CHART bars, vertical cards, CSV/TSV/JSON/NDJSON/XML/Markdown/SQL/Parquet
    ├── hooks.rs            # Webhook + subprocess triggers
    └── checkpoint.rs       # Byte-offset checkpoint store for --tail
```

---

## 3. Feature Matrix (v1.4.0)

### Parsing / Ingestion
- **Formats**: IIS W3C, IIS SMTP (SMTPSVC), Nginx, Apache/httpd, Caddy JSON, HAProxy, Syslog, Firewall key=value, Cisco ASA, Cisco config, CEF, AWS ALB / VPC Flow / S3, Azure activity, GCP audit, generic JSON/NDJSON, CSV/TSV, Excel (.xlsx/.xls via calamine), Parquet, EVTX (.evtx binary or EVTX-as-JSON), raw line, custom regex.
- **Sources**: file path, glob (`*.log`), directory (recursive), semicolon-separated multi-path, `.zip` (parallel per-entry decompression), `.gz`, `.zst`, stdin (`-` / `stdin` / piped).
- **Encodings**: UTF-16LE/BE BOM, UTF-8 BOM, Windows-1252, Latin-1, lossy fallback — never fails on `stream did not contain valid UTF-8`.
- **Virtual columns**: `log_filename`, `log_row` (LogParser `LogFilename`/`LogRow` aliases).
- **W3C mid-file `#Fields:` rotations** handled; scans up to 50 lines for the header; falls back to standard IIS column layout.

### SQL Engine (DataFusion 42)
- Full ANSI SQL: `SELECT`, `WHERE`, `GROUP BY`, `ORDER BY`, `LIMIT`/`TOP N`, `JOIN`, `UNION`, `DISTINCT`, `CASE`, `CAST`, subqueries, CTEs (`WITH`), window functions (`ROW_NUMBER`, `RANK`, `LAG`, `LEAD`, `PERCENT_RANK`, running `COUNT() OVER`).
- **Log Parser 2.2 surface**: `-i:`/`-o:` colon flags, bracketed/hyphenated columns (`[sc-status]`, `cs(User-Agent)`), `FROM 'path-or-glob'`, `INTO 'file'`, `file:query.sql`, `-q`, `-stats`, `-e`, `-iw`, `-rtp`.
- **Time-series (KQL/KSQL-style) UDFs** added in v1.4.0:
  - `time_bucket(date, time, minutes)` → `"YYYY-MM-DD HH:MM"` truncated bucket (tumbling-window equivalent).
  - `date_diff_days(d1, d2)` → integer day delta.
  - `geoip_scope(ip)` → `PRIVATE` / `PUBLIC` / `TEST-NET`.
  - `url_path(url)` → strips query string for page-level grouping.
- **Cyber UDFs**: `detect_threat` (SQLi/XSS/LFI/RCE/SSRF/scanner), `ip_in_cidr`, `shannon_entropy`, `mask_pii`, `cluster_template` (Drain), `url_decode`, `parse_ua`, `extract_email`, `extract_domain`.
- **LP2.2 UDFs**: `extract_token`, `extract_prefix`, `extract_suffix`, `extract_filename`, `extract_path`, `extract_extension`, `win32_error_description`, `reversedns`, `to_timestamp`, `index_of`, `strlen`, `to_uppercase`, `to_lowercase`, `to_int`, `to_real`.

### Fleet Scanner (`lpr fleet`)
- `servers.csv` (Name,IP,Enabled) or `--host-pattern "web-{02}"` + `--server-numbers "1-12"`.
- **Windows/IIS**: expands `D:\path\{site}` → `\\{server}\d$\...`; IIS auto-discovery parses `\\{server}\c$\Windows\System32\inetsrv\config\applicationHost.config` for `<site name|id>` → `<logFile directory>` → `W3SVC{id}`.
- **Linux (--ssh)**: streams `find /var/log/nginx|apache2|httpd|caddy|tomcat ... -mtime -N | xargs zcat -f` over SSH (BatchMode, ConnectTimeout, `-i key`, `-p port`), then parses locally — no agent needed on the host.
- Writes three artifacts per run: `<prefix>-<ts>.csv` (detail), `-Summary-`, `-Manifest-`.
- `lpr.config.json` profiles: `--save-profile NAME` persists servers/paths/threads/days/paths; `--profile NAME` reuses; `lpr config` lists/sets default.

### Interfaces
- CLI (rich banner, `-V` verbose, `--log-file`, `--max-width`, `-G` vertical).
- `lpr serve` → REST + Studio UI (GET/POST `/v1/query`, `/v1/audit`, `/v1/browse`, `/v1/schema`, `/metrics`).
- `lpr tui` → terminal UI; `lpr mcp` → MCP stdio server; `lpr gui` (feature-gated Tao+Wry).
- `lpr sdk` → emits `dist/lpr.psm1` (PowerShell), `dist/LprClient.cs` (.NET), curl snippets.

---

## 4. Build Commands

```bash
# Fast dev build (incremental, jobs=4 cap):
cargo build --release                     # ~10–15 s

# Windows cross-build (also fast — same profile):
cargo build --release --target x86_64-pc-windows-gnu
x86_64-w64-mingw32-strip -s target/x86_64-pc-windows-gnu/release/lpr.exe
cp target/x86_64-pc-windows-gnu/release/lpr.exe dist/lpr.exe

# macOS dist copy:
cp target/release/lpr dist/lpr && cp target/release/lpr dist/lpr-macos-arm64

# Smoke test suite:
bash tests/smoke_test.sh
```

---

## 5. Known Constraints / Next-Agent Notes

1. **`samples_client_local/` is gitignored** — it holds real client logs (Footasylum 1 GB zip). Never publish it. Public `samples/` contains ONLY synthetic RFC-5737 IPs (198.51.100.x, 203.0.113.x, 192.0.2.x).
2. **SSH fleet mode** shells out to system `ssh` (BatchMode — key/agent auth only, no password prompts). Windows fleet mode uses direct `\\server\d$` file access (works when run on Windows with share permissions).
3. **Linux remote scanning is pull-based** (SSH + zcat). A push-based mode (run `lpr` binary on the host) can be added via a `--remote-exec` flag — not yet implemented.
4. `geoip_scope` is a coarse PRIVATE/PUBLIC/TEST-NET classifier — wire in a real MaxMind/GeoLite2 binary lookup (`maxminddb` crate) if full country/ASN data is wanted.
5. `time_bucket` operates on W3C `date`+`time` string columns. For Nginx `time_local` (CLF `15/Oct/2026:10:03:15`), parse via `to_timestamp` or split helpers first.
6. EVTX binary parsing uses the `evtx` crate; the `samples/evtx/security_events.json` file is EVTX-converted-to-JSON for demo only.
7. Blume delivery `3b60b835-732c-40cb-9905-89002f9a1d95` is in Review phase; latest E2E run `7ec57c4b` passed 3/3 steps at revision `be69d68c+wip.fecbe52`.
8. If porting to a new agent: start at `src/main.rs` (CLI surface) → `src/engine.rs` (DataFusion glue) → `src/parsers.rs` (format detection + parallel readers). All UDFs live in `src/udfs.rs`; audit rules in `src/audit.rs`; fleet logic + config profiles in `src/fleet.rs`.
