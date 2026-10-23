# 🛡️ LPR (Log Parser Rust) v1.4.3

**Modern Multi-Threaded Rust SQL Log Engine, Fleet Error Scanner & Automated Security Auditor**  
*Powered by Apache Arrow 53, DataFusion 42 & Rayon Parallel Engine*  
✨ **Made using vibe coding by Sunil Warrier**

[![License: MIT OR Unlicense](https://img.shields.io/badge/License-MIT%20%2F%20Unlicense-brightgreen.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](Cargo.toml)
[![Engine: DataFusion 42](https://img.shields.io/badge/Engine-DataFusion%2042%20%2F%20Arrow%2053-blue.svg)](Cargo.toml)

---

## 🚀 Overview & Binary Locations

`lpr` is a zero-dependency, single-binary SQL log parser, multi-server fleet scanner, and cybersecurity auditor written in Rust. Copy a single file (`lpr.exe` on Windows or `lpr` on Mac/Linux) to any server and query uncompressed logs, `.zip`, `.gz`, or `.zst` archives using standard SQL or Microsoft Log Parser 2.2 syntax.

| Platform | Binary Path | Description |
| :--- | :--- | :--- |
| **Windows Server / PC** | `dist/lpr.exe` | Single standalone 64-bit Windows executable (zero external DLLs required) |
| **macOS** | `target/release/lpr` | Native Apple Silicon executable |
| **Sample Log Files** | `samples/` | Ready-to-run sample logs (`iis/`, `nginx_access.log`, `firewall.log`, `cisco_switch.cfg`, `cloud_events.json`) |
| **200+ Query Cookbook** | [`docs/SAMPLE_QUERIES.md`](docs/SAMPLE_QUERIES.md) | Complete cookbook of 200+ SQL recipes across 22 categories |

---

## 🌐 1. How to See & Use Saved 24-Server Fleet Profiles (When You Forgot the Name)

When you save a fleet configuration (with `--save-profile <name>`), `lpr` stores it in **`lpr.config.json`** (located either in the current folder or in the same folder next to `lpr.exe`).

### A. See All Saved Fleet Profiles & Server Lists
When you are in that folder (or from anywhere if `lpr.config.json` is next to `lpr.exe`), run:

```cmd
lpr.exe config
```
*(Or `lpr.exe --list-profiles` or `lpr.exe fleet --list-profiles`)*

**What `lpr.exe config` shows you:**
- Every saved profile name (e.g. `• Profile: prod-iis (DEFAULT)`)
- Which profile is marked **`(DEFAULT)`**
- Number of inline servers saved (e.g. `InlineServers=24`), CSV path, or host pattern
- Saved `Site Name` (e.g. `W3SVC4`), `Path Templates`, `Threads`, `Days`, and `SMB Auth` settings.

*(If `lpr.config.json` is in another folder, point to it with `lpr.exe --cfg D:\path\to\lpr.config.json config`.)*

---

### B. Run the Saved Fleet Scan (Even Without Typing the Name!)
If your 24-server fleet was saved as the first/default profile, you don't even need to pass `--profile`:

```cmd
:: Runs the (DEFAULT) profile automatically!
lpr.exe fleet
```

Or specify the profile name shown by `lpr.exe config`:
```cmd
:: Run the saved profile by name
lpr.exe fleet --profile <profile-name>

:: Scan only the last 3 hours across all 24 servers
lpr.exe fleet --profile <profile-name> --hours 3

:: Scan only the single newest (currently active) log file on each of the 24 servers
lpr.exe fleet --profile <profile-name> --latest

:: Scan only servers 1 through 12 (or specific servers like "1,3,5")
lpr.exe fleet --profile <profile-name> --server-numbers "1-12"

:: Filter servers by hostname wildcard
lpr.exe fleet --profile <profile-name> --server-filter "*web-0*"

:: Run a custom SQL query across all 24 servers in the fleet
lpr.exe fleet --profile <profile-name> --sql "SELECT cs_uri_stem, sc_status, COUNT(*) AS hits FROM logs WHERE sc_status LIKE '5%' GROUP BY 1, 2 ORDER BY hits DESC"
```

### C. How to Save or Change the Default Fleet Profile
```cmd
:: Save a 24-server IIS profile once into lpr.config.json
lpr.exe fleet --save-profile prod-iis --servers servers.csv --site W3SVC4 --threads 8 --days 7

:: Change which saved profile runs by default when you type `lpr.exe fleet`
lpr.exe config --set-default prod-iis
```

### D. Persistent Command History (Max 100 Unique Commands, Numbered Rerun & DOS Up/Down Browser)
Every command you run is automatically saved into `lpr.config.json` (`command_history`, up to **100 unique commands**).
- If you run the **exact same command** again, `lpr` removes the old duplicate and keeps only the new one at the latest position (only unique commands are stored).
- When the history reaches 100 commands, the oldest command is automatically removed.

```cmd
:: 1. List all saved commands (1..100) with timestamps and folder paths
lpr.exe history
lpr.exe -H

:: 2. Rerun a specific command by its number (e.g. #33) or rerun the last command
lpr.exe --rerun 33
lpr.exe history 33
lpr.exe !33
lpr.exe --rerun last

:: 3. Browse old commands with DOS-style Up/Down arrows and press Enter to execute
lpr.exe history -i
lpr.exe --browse-history

:: 4. Filter saved commands by keyword or clear history
lpr.exe history 500
lpr.exe history --clear
```

### E. Fast Raw-Byte Substring Pushdown & Robocopy/LogParser Summary Table
`lpr fleet` automatically pushes SQL `LIKE` / `ILIKE` substrings and `sc_status` filters down to the raw byte scanner before UTF-8 decoding or Arrow allocation, and prints per-server timing (`files`, `lines`, `elapsed seconds`) plus a **Robocopy / Log Parser 2.2 style summary table** at the end:

```cmd
:: Fast status + URL substring scan across all servers (last 12 hours) without writing SQL:
lpr.exe fleet --profile AcmeStore --hours 12 --status 302 -g "/partner-api/" --report-prefix Acme-Partner-302

:: Or using custom SQL (automatically extracts raw-byte needles & rewrites LOWER(...) LIKE to ILIKE):
lpr.exe fleet --profile AcmeStore --hours 12 --report-prefix Acme-Partner-302 --sql "SELECT * FROM logs WHERE LOWER(cs_uri_stem) LIKE '%/partner-api/%' AND sc_status = '302'"
```

### F. Deterministic Session Intelligence (`--learn`) & Cross-Server User Journey Reconstruction (`--trace`)
When requests are load-balanced across multiple servers **without sticky sessions**, `lpr` can reconstruct the full chronological journey of a customer across all servers using **100% deterministic math (zero AI)**:

1. **Learn & Save Session Intelligence (`--learn`)**:
   Scans sample logs to discover W3C columns, high-cardinality identity/session cookies (`ASP.NET_SessionId`, `shop_session`, `customerId`, `visitorId`, `cartId`), query-string correlators (`orderId`, `paymentId`, `cartId`, `sessionId`), `X-Forwarded-For` / `c-ip` columns, and `sc(Location)` redirect headers, saving them into `lpr.config.json`:
   ```cmd
   lpr.exe fleet --profile AcmeStore --learn
   ```
2. **Trace All Customers Who Hit an Error, Failed Payment, or Got a `302` Redirect (`--trace`)**:
   Finds the trigger events first, extracts each affected customer's Session Cookie, Query ID, `X-Forwarded-For` IP, or Clear `c-ip`, and sweeps all servers (`±15 mins` default) to stitch each user's step-by-step cross-server timeline (including server hops and where `302` redirects landed):
   ```cmd
   :: Trace full cross-server journeys for all customers who failed payment:
   lpr.exe fleet --profile AcmeStore --hours 12 -g "/checkout/pay" --status 5 --trace --report-prefix Acme-FailedPayment

   :: Trace full cross-server journeys for all 302 redirects on /partner-api/ (shows REDIRECT_LANDING target):
   lpr.exe fleet --profile AcmeStore --hours 12 --status 302 -g "/partner-api/" --trace --report-prefix Acme-Partner-302
   ```
3. **Trace a Specific Customer ID, Session ID, Order ID, Cookie, Clear IP, or `X-Forwarded-For` IP (`--customer` / `--trace-ip` / `--trace-id`)**:
   Finds all requests (200, 302, 404, 500) for that identifier across all servers and automatically chains any Session Cookie or IP discovered on those hits to capture pre-login and post-login steps:
   ```cmd
   lpr.exe fleet --profile AcmeStore --hours 12 --customer "CUST-99482" --report-prefix Acme-Customer-99482
   lpr.exe fleet --profile AcmeStore --hours 12 --trace-ip "198.51.100.42" --report-prefix Acme-IP-Journey
   ```

---

## 🪟 2. Running on a Windows IIS Server (Single Folder / Local Logs)

When you are inside an IIS log folder (such as `D:\Logs\AcmeStore\W3SVC4`) or querying `.log` / `.zip` files directly:

### A. Find All 500-Level Errors in the Current Folder
Both `lpr` `-f` syntax and classic **Microsoft Log Parser 2.2** syntax (`FROM *.log`) work identically:

```cmd
:: Using -f flag:
D:\Logs\AcmeStore\W3SVC4>C:\Tools\lpr.exe -f "*.log" "SELECT * FROM logs WHERE sc_status LIKE '5%'"

:: Using Microsoft Log Parser 2.2 syntax (no -f needed, hyphenated column names work!):
D:\Logs\AcmeStore\W3SVC4>C:\Tools\lpr.exe -i:IISW3C "SELECT TOP 20 date, time, c-ip, cs-method, cs-uri-stem, sc-status, sc-substatus, [time-taken] FROM *.log WHERE sc-status LIKE '5%'"
```

**Sample Output (`samples/iis_u_ex.log`):**
```text
+------------+----------+---------------+-----------+---------------+-----------+--------------+------------+
| date       | time     | c_ip          | cs_method | cs_uri_stem   | sc_status | sc_substatus | time_taken |
+------------+----------+---------------+-----------+---------------+-----------+--------------+------------+
| 2026-10-15 | 08:12:10 | 198.51.100.44 | POST      | /api/checkout | 500       | 19           | 1250       |
| 2026-10-15 | 08:12:15 | 203.0.113.12  | GET       | /app/reports  | 500       | 0            | 3400       |
| 2026-10-15 | 08:12:25 | 198.51.100.44 | POST      | /api/payment  | 502       | 3            | 5200       |
| 2026-10-15 | 08:12:35 | 198.51.100.88 | POST      | /api/checkout | 500       | 0            | 1100       |
+------------+----------+---------------+-----------+---------------+-----------+--------------+------------+
```

### B. Group Top Failing Endpoints & Average Response Latency
```cmd
C:\Tools\lpr.exe -f "*.log" "SELECT cs_uri_stem, sc_status, count(*) AS error_count, avg(time_taken::bigint) AS avg_latency_ms FROM logs WHERE sc_status LIKE '5%' GROUP BY cs_uri_stem, sc_status ORDER BY error_count DESC"
```
**Output:**
```text
+---------------+-----------+-------------+----------------+
| cs_uri_stem   | sc_status | error_count | avg_latency_ms |
+---------------+-----------+-------------+----------------+
| /api/checkout | 500       | 2           | 1175.0         |
| /api/payment  | 502       | 1           | 5200.0         |
| /app/reports  | 500       | 1           | 3400.0         |
+---------------+-----------+-------------+----------------+
```

### C. Breakdown by IIS Substatus & Win32 Error Description
```cmd
C:\Tools\lpr.exe -f "*.log" "SELECT sc_status, sc_substatus, sc_win32_status, win32_error_description(sc_win32_status) AS win32_meaning, count(*) AS hits FROM logs WHERE sc_status LIKE '5%' GROUP BY 1, 2, 3, 4"
```

### D. Export 500 Errors Directly to CSV
```cmd
:: Using --out-file:
C:\Tools\lpr.exe -f "*.log" -o csv --out-file C:\temp\iis_500_errors.csv "SELECT * FROM logs WHERE sc_status LIKE '5%'"

:: Or using Log Parser 2.2 INTO syntax:
C:\Tools\lpr.exe -i:IISW3C "SELECT * INTO C:\temp\iis_500_errors.csv FROM *.log WHERE sc-status LIKE '5%'"
```

---

## 🧪 3. All Sample Files & Queries We Tested

All sample files below are included in the [`samples/`](samples/) directory.

### Sample 1: Nginx / Apache Access Logs (`samples/nginx_access.log`)

#### Detect OWASP Attacks (`detect_threat`), Private Subnets (`ip_in_cidr`), and Entropy (`shannon_entropy`)
```bash
./target/release/lpr -f samples/nginx_access.log \
  "SELECT remote_addr, method, request_uri, status, detect_threat(request_uri) AS threat, ip_in_cidr(remote_addr, '192.168.0.0/16') AS is_private, ROUND(shannon_entropy(request_uri)::numeric, 2) AS entropy FROM logs"
```
**Output:**
```text
+---------------+--------+-----------------------------------------------------------+--------+-------------------------+------------+---------+
| remote_addr   | method | request_uri                                               | status | threat                  | is_private | entropy |
+---------------+--------+-----------------------------------------------------------+--------+-------------------------+------------+---------+
| 192.168.1.10  | GET    | /index.html                                               | 200    | CLEAN                   | true       | 3.46    |
| 192.168.1.11  | GET    | /api/v1/users?id=42                                       | 200    | CLEAN                   | true       | 3.79    |
| 203.0.113.55  | GET    | /login?user=admin%27%20OR%201=1--                         | 401    | HIGH:SQL_INJECTION      | false      | 4.39    |
| 203.0.113.55  | GET    | /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E | 200    | MEDIUM:XSS_ATTEMPT      | false      | 4.5     |
| 198.51.100.99 | GET    | /download?file=../../../../etc/passwd                     | 403    | HIGH:PATH_TRAVERSAL_LFI | false      | 3.69    |
| 198.51.100.99 | GET    | /api/headers                                              | 400    | CLEAN                   | false      | 3.08    |
| 10.0.2.14     | POST   | /api/auth/token                                           | 200    | CLEAN                   | false      | 3.32    |
+---------------+--------+-----------------------------------------------------------+--------+-------------------------+------------+---------+
```

#### Automated OWASP Security Audit on Nginx Logs
```bash
./target/release/lpr audit samples/nginx_access.log
```
**Output:**
```text
================================================================================
 🛡️  LPR AUTOMATED MULTI-CLOUD, NETWORK & LOG SECURITY AUDIT REPORT
 📁 Target: samples/nginx_access.log | Detected Profile: Nginx
================================================================================

[1] CRITICAL | WEB_OWASP_PAYLOAD — Exploit Payloads Detected in Request URI (SQLi / XSS / LFI / RCE / Log4Shell) (3 matches)
    💡 Remediation: Block offending source IPs at WAF/Firewall and inspect any HTTP 200 responses.
    +---------------+-------------------------+--------+----------+-----------------------------------------------------------+
    | remote_addr   | threat_type             | status | attempts | sample_uri                                                |
    +---------------+-------------------------+--------+----------+-----------------------------------------------------------+
    | 203.0.113.55  | MEDIUM:XSS_ATTEMPT      | 200    | 1        | /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E |
    | 203.0.113.55  | HIGH:SQL_INJECTION      | 401    | 1        | /login?user=admin%27%20OR%201=1--                         |
    | 198.51.100.99 | HIGH:PATH_TRAVERSAL_LFI | 403    | 1        | /download?file=../../../../etc/passwd                     |
    +---------------+-------------------------+--------+----------+-----------------------------------------------------------+
```

---

### Sample 2: Cisco Switch / Router Configuration (`samples/cisco_switch.cfg`)

#### Automated CIS & Firewall Security Audit
```bash
./target/release/lpr audit samples/cisco_switch.cfg
```
**Output:**
```text
================================================================================
 🛡️  LPR AUTOMATED MULTI-CLOUD, NETWORK & LOG SECURITY AUDIT REPORT
 📁 Target: samples/cisco_switch.cfg | Detected Profile: CiscoConfig
================================================================================

[1] CRITICAL | CISCO_ACL_ANY_ANY — Overly Permissive Firewall Rule ('permit ip/tcp any any') (1 matches)
    💡 Remediation: Restrict ACL rules to explicit source/destination subnets and required ports.
    +--------------------------+-------------+------------------------------------+-------------------+
    | file                     | line_number | section                            | directive         |
    +--------------------------+-------------+------------------------------------+-------------------+
    | samples/cisco_switch.cfg | 25          | ip access-list extended OUTSIDE_IN | permit ip any any |
    +--------------------------+-------------+------------------------------------+-------------------+

[2] CRITICAL | CISCO_WEAK_SECRET — Weak or Reversible Password Hash ('enable password' or Type 0/7) (2 matches)
    💡 Remediation: Replace enable password and Type 7 passwords with enable secret (Type 8/9).
    +--------------------------+-------------+--------------------------------+
    | file                     | line_number | directive                      |
    +--------------------------+-------------+--------------------------------+
    | samples/cisco_switch.cfg | 11          | enable password 7 0822455D0A16 |
    | samples/cisco_switch.cfg | 28          | password 0 cisco123            |
    +--------------------------+-------------+--------------------------------+
```

---

### Sample 3: Firewall Key-Value Logs (`samples/firewall.log`)

#### Aggregate Firewall Traffic by Action & Bytes Sent
```bash
./target/release/lpr -f samples/firewall.log \
  "SELECT action, count(*) AS count, sum(sentbyte::bigint) AS total_sent_bytes FROM logs GROUP BY action"
```
**Output:**
```text
+--------+-------+------------------+
| action | count | total_sent_bytes |
+--------+-------+------------------+
| deny   | 3     | 192              |
| accept | 2     | 1332             |
+--------+-------+------------------+
```

---

### Sample 4: Cloud JSON Events with PII Redaction (`samples/cloud_events.json`)

#### Query JSON Events & Mask Email Addresses (`mask_pii`)
```bash
./target/release/lpr -f samples/cloud_events.json \
  'SELECT timestamp, service, event, mask_pii("user") AS masked_user, ip, status FROM logs'
```
**Output:**
```text
+----------------------+--------------+----------------+------------------+--------------+---------+
| timestamp            | service      | event          | masked_user      | ip           | status  |
+----------------------+--------------+----------------+------------------+--------------+---------+
| 2026-10-15T10:20:00Z | auth-service | user_login     | [REDACTED_EMAIL] | 10.0.1.45    | success |
| 2026-10-15T10:20:05Z | payment-api  | charge_created | [REDACTED_EMAIL] | 192.168.1.12 |         |
| 2026-10-15T10:21:10Z | auth-service | password_reset | [REDACTED_EMAIL] | 203.0.113.99 | failed  |
+----------------------+--------------+----------------+------------------+--------------+---------+
```

---

### Sample 5: Fast Linux Power-Tool Shortcuts (`-g`, `-F`, `--stats`, `-o:CHART`)

```bash
# Grep + field cut (like grep + awk)
./target/release/lpr -f samples/iis_u_ex.log -g "500" -F date,time,c_ip,cs_uri_stem,sc_status,time_taken

# GoAccess-style executive summary
./target/release/lpr -f samples/iis_u_ex.log --stats

# Instant ASCII bar chart in terminal
./target/release/lpr -f samples/iis_u_ex.log -o:CHART "SELECT sc-status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC"

# Auto-suggest context-aware SQL queries for any log file
./target/release/lpr suggest samples/iis_u_ex.log
```

---

## 🖥️ 4. Web Studio, Terminal UI (TUI), and API Modes

### A. Web Studio Interface (`lpr serve`)
```bash
# Mac / Linux
./target/release/lpr serve --bind 127.0.0.1:8080

# Windows Server
C:\Tools\lpr.exe serve --bind 0.0.0.0:8080
```
Open **`http://localhost:8080`** for the dark-mode SOC console with visual File/Folder Browser, Context-Aware Intent Chips, Live SQL `Tab` Auto-Completion, and Security Audit tabs.

### B. Interactive Terminal UI (`lpr tui`)
```bash
./target/release/lpr tui -f samples/iis_u_ex.log
```
*(Supports `Tab` auto-complete, `F1` Full Help, `F2` Smart Intents, `F3` File Browser, and `Esc`/`q` to quit.)*

### C. Complete Built-In Manual
```bash
./target/release/lpr help-full
```

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
**Made using vibe coding by Sunil Warrier**
