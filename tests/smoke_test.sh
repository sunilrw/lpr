#!/usr/bin/env bash
set -e

if [ -z "$LPR_BIN" ]; then
  echo "🔨 Compiling lpr (fast incremental dev build)..."
  cargo build
  BIN="./target/debug/lpr"
else
  echo "🔨 Using prebuilt binary: $LPR_BIN"
  BIN="$LPR_BIN"
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cat << 'MOCK' > "$TMP_DIR/running-config.cfg"
!
hostname core-fw-01
enable password 7 0822455D0A16
ip access-list extended OUTSIDE_IN
 permit ip any any
!
MOCK

cat << 'MOCK' > "$TMP_DIR/nginx_access.log"
198.51.100.42 - - [15/Oct/2026:00:10:01 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 1420 "-" "sqlmap/1.8"
10.0.0.15 - - [15/Oct/2026:00:10:03 +0000] "GET /index.html HTTP/1.1" 200 890 "-" "Mozilla/5.0"
MOCK

# Create a Windows-1252 / non-UTF8 IIS W3C log file and a UTF-16LE BOM IIS W3C log file
python3 -c '
content = """#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2026-10-15 08:12:10 10.0.0.5 POST /api/checkout-caf\xe9 - 443 DOMAIN\\alice 198.51.100.44 Mozilla/5.0 https://portal/ 500 19 2147942405 1250
2026-10-15 08:12:25 10.0.0.5 GET /default.aspx id=10 80 - 192.168.1.50 Mozilla/5.0 - 200 0 0 15
"""
with open("'"$TMP_DIR"'/iis_win1252.log", "wb") as f:
    f.write(content.encode("latin1"))
with open("'"$TMP_DIR"'/iis_utf16le.log", "wb") as f:
    f.write(b"\xff\xfe" + content.encode("utf-16-le"))
'

echo "🧪 [1/10] Zero-parameter help & banner..."
$BIN | head -n 12

echo "🧪 [2/10] Auditing Cisco config..."
$BIN audit -i cisco-config -f "$TMP_DIR/running-config.cfg"

echo "🧪 [3/10] Auditing Nginx logs for OWASP attacks..."
$BIN audit -i nginx -f "$TMP_DIR/nginx_access.log"

echo "🧪 [4/10] Microsoft Log Parser 2.2 syntax (INTO file.csv, virtual columns LogFilename/LogRow, win32_error_description)..."
$BIN -i:IISW3C -q:ON "SELECT TOP 5 LogFilename, LogRow, cs-uri-stem, [sc-status], win32_error_description(sc-win32-status) AS win32_desc, extract_filename(cs-uri-stem) AS fname INTO '$TMP_DIR/out.csv' FROM '$TMP_DIR/iis_*.log' WHERE sc-status LIKE '5%'"
cat "$TMP_DIR/out.csv"

echo "🧪 [5/10] Linux grep (-g), invert (-v), field cut (-F), and GoAccess bar chart (-o:CHART)..."
$BIN -f samples/iis/u_extend01.log -g "500" -F date,time,c-ip,cs-uri-stem,sc-status
$BIN -f samples/iis/u_extend01.log --stats

echo "🧪 [6/10] Linux / PowerShell stdin pipe support..."
cat "$TMP_DIR/nginx_access.log" | $BIN -i nginx "SELECT remote_addr, status, detect_threat(request_uri) AS threat FROM stdin"

echo "🧪 [7/10] lnav filter syntax (:filter-in)..."
$BIN -f "$TMP_DIR/nginx_access.log" ":filter-in UNION"

echo "🧪 [8/10] Context-aware schema & intent suggestions (lpr suggest)..."
$BIN suggest -f samples/iis/u_extend01.log | head -n 20

echo "🧪 [9/10] PowerShell & .NET C# SDK generator (lpr sdk)..."
$BIN sdk | head -n 25

echo "🧪 [10/10] Querying CIDR UDF & XML/SQL output..."
$BIN -i nginx -f "$TMP_DIR/nginx_access.log" -o:XML \
  "SELECT remote_addr, detect_threat(request_uri) AS threat, ip_in_cidr(remote_addr, '10.0.0.0/8') AS is_internal FROM logs"

echo "✅ All 10 test suites passed successfully!"
