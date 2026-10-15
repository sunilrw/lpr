#!/usr/bin/env bash
set -e

echo "🔨 Compiling lpr..."
cargo build --release
BIN="./target/release/lpr"

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

echo "🧪 [1/3] Auditing Cisco config..."
$BIN audit -i cisco-config -f "$TMP_DIR/running-config.cfg"

echo "🧪 [2/3] Auditing Nginx logs for OWASP attacks..."
$BIN audit -i nginx -f "$TMP_DIR/nginx_access.log"

echo "🧪 [3/3] Querying CIDR UDF & SQL output..."
$BIN -i nginx -f "$TMP_DIR/nginx_access.log" -o sql \
  "SELECT remote_addr, detect_threat(request_uri) AS threat, ip_in_cidr(remote_addr, '10.0.0.0/8') AS is_internal FROM logs"

echo "✅ All tests passed successfully!"
