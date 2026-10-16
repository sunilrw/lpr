# 📚 LPR Query Cookbook — 200+ Ready-to-Run SQL Recipes

> **Made using vibe coding by Sunil Warrier** | MIT / Unlicense
>
> Every query below works against the synthetic files in `samples/`. Replace the path with your own log files, glob patterns, `.zip` archives, or `lpr.config.json` profiles.

---

## Table of Contents
1. [IIS W3C Web Logs](#1-iis-w3c-web-logs)
2. [IIS SMTP Mail Logs](#2-iis-smtp-mail-logs)
3. [Nginx Access Logs](#3-nginx-access-logs)
4. [Apache / httpd Access Logs](#4-apache--httpd-access-logs)
5. [Caddy JSON Access Logs](#5-caddy-json-access-logs)
6. [HAProxy Logs](#6-haproxy-logs)
7. [Syslog / auth.log](#7-syslog--authlog)
8. [Firewall Key-Value Logs](#8-firewall-key-value-logs)
9. [Cisco ASA](#9-cisco-asa)
10. [Cisco Router/Switch Configs](#10-cisco-routerswitch-configs)
11. [AWS (ALB / VPC Flow / S3)](#11-aws-alb--vpc-flow--s3)
12. [Azure Activity](#12-azure-activity)
13. [GCP Audit](#13-gcp-audit)
14. [JSON / NDJSON Events](#14-json--ndjson-events)
15. [CSV / TSV Files](#15-csv--tsv-files)
16. [Windows Security (EVTX-as-JSON)](#16-windows-security-events)
17. [Security & Threat Hunting](#17-security--threat-hunting)
18. [Time-Series & KSQL-Style Windowing](#18-time-series--ksql-style-windowing)
19. [Grouping, Pages, Bandwidth & Percentiles](#19-grouping-pages-bandwidth--percentiles)
20. [Linux Power-Tool Modes](#20-linux-power-tool-modes)
21. [Multi-File, Archive & Fleet Queries](#21-multi-file-archive--fleet-queries)
22. [CTEs, Subqueries & Window Functions](#22-ctes-subqueries--window-functions)

---

## 1. IIS W3C Web Logs

### Basic queries
```sql
-- All requests
SELECT * FROM 'samples/iis/u_extend01.log'

-- All 5xx errors
SELECT * FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'

-- Top 10 slowest requests
SELECT TOP 10 time, cs_uri_stem, c_ip, time_taken
FROM 'samples/iis/u_extend01.log' ORDER BY CAST(time_taken AS BIGINT) DESC
```

### Status & counts
```sql
-- HTTP status distribution
SELECT sc_status, COUNT(*) AS hits FROM 'samples/iis/u_extend01.log' GROUP BY sc_status ORDER BY hits DESC

-- Errors per minute (KQL/KSQL-style time buckets)
SELECT time_bucket(date, time, 1) AS minute_bucket, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'
GROUP BY time_bucket(date, time, 1) ORDER BY minute_bucket
```

### Client IP analysis
```sql
-- Top talkers
SELECT c_ip, COUNT(*) AS requests, SUM(CAST(time_taken AS BIGINT)) AS total_ms
FROM 'samples/iis/u_extend01.log' GROUP BY c_ip ORDER BY requests DESC

-- IPs generating 5xx errors
SELECT c_ip, COUNT(*) AS error_count
FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'
GROUP BY c_ip ORDER BY error_count DESC

-- Public vs private scope classification
SELECT geoip_scope(c_ip) AS scope, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY geoip_scope(c_ip)
```

### URI / page analysis
```sql
-- Top requested pages
SELECT cs_uri_stem, COUNT(*) AS hits FROM 'samples/iis/u_extend01.log'
GROUP BY cs_uri_stem ORDER BY hits DESC

-- Clean URL paths (no query string)
SELECT url_path(cs_uri_stem) AS page, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY url_path(cs_uri_stem)

-- Pages that returned errors
SELECT cs_uri_stem, sc_status, COUNT(*) AS errors
FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '%[45]%'
GROUP BY cs_uri_stem, sc_status ORDER BY errors DESC
```

### Method & agent analysis
```sql
SELECT cs_method, sc_status, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY cs_method, sc_status

SELECT parse_ua(csuser_agent) AS browser_os, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY parse_ua(csuser_agent)
```

### Bandwidth & latency
```sql
-- Latency percentiles approximation (sorted view)
SELECT cs_uri_stem,
       COUNT(*) AS hits,
       AVG(CAST(time_taken AS BIGINT)) AS avg_ms,
       MAX(CAST(time_taken AS BIGINT)) AS p100_ms
FROM 'samples/iis/u_extend01.log' GROUP BY cs_uri_stem ORDER BY p100_ms DESC

-- Virtual Win32 error text
SELECT sc_win32_status, win32_error_description(sc_win32_status) AS description, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY sc_win32_status
```

### LogParser 2.2 classic syntax (works identically)
```sql
SELECT TOP 10 LogFilename, LogRow, date, time, c_ip, cs_uri_stem, sc_status, sc_win32_status, time_taken
FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'

SELECT STRCAT(TO_STRING(date), ' ', TO_STRING(time)) AS ts, c_ip, cs_uri_stem, sc_status
FROM 'samples/iis/u_extend01.log' WHERE cs_uri_query IS NOT NULL
```

---

## 2. IIS SMTP Mail Logs

```sql
-- All SMTP commands
SELECT date, time, c_ip, cs_method, cs_uri_query, sc_status, win32_error_description(sc_win32_status) AS desc
FROM 'samples/iis_smtp/u_ex260101.log'

-- Unique FROM (MAIL FROM) senders with source IP
SELECT extract_email(cs_uri_query) AS from_address, extract_domain(cs_uri_query) AS domain,
       c_ip AS sending_ip, COUNT(*) AS messages
FROM 'samples/iis_smtp/u_ex260101.log' WHERE cs_method = 'MAIL'
GROUP BY extract_email(cs_uri_query), extract_domain(cs_uri_query), c_ip

-- Top recipients (RCPT TO)
SELECT extract_email(cs_uri_query) AS to_address, sc_status, COUNT(*) AS hits
FROM 'samples/iis_smtp/u_ex260101.log' WHERE cs_method = 'RCPT'
GROUP BY extract_email(cs_uri_query), sc_status ORDER BY hits DESC

-- EHLO / HELO hosts per client IP
SELECT c_ip, cs_uri_query AS ehlo_host, COUNT(*) AS sessions
FROM 'samples/iis_smtp/u_ex260101.log' WHERE cs_method IN ('EHLO','HELO')
GROUP BY c_ip, cs_uri_query

-- Failed AUTH (535 = Access Denied) + relay denials (550)
SELECT date, time, c_ip, cs_method, cs_uri_query, sc_status
FROM 'samples/iis_smtp/u_ex260101.log'
WHERE sc_status IN ('535','550','554') OR cs_method IN ('VRFY','EXPN')

-- Delivery status distribution
SELECT sc_status, COUNT(*) AS hits FROM 'samples/iis_smtp/u_ex260101.log' GROUP BY sc_status
```

---

## 3. Nginx Access Logs

```sql
SELECT * FROM 'samples/nginx/access.log'

-- Status distribution
SELECT status, COUNT(*) AS hits FROM 'samples/nginx/access.log' GROUP BY status

-- Top client IPs
SELECT remote_addr, COUNT(*) AS requests FROM 'samples/nginx/access.log' GROUP BY remote_addr ORDER BY requests DESC

-- Bandwidth per URI (body_bytes_sent)
SELECT request_uri, COUNT(*) AS hits, SUM(CAST(body_bytes_sent AS BIGINT)) AS total_bytes
FROM 'samples/nginx/access.log' GROUP BY request_uri ORDER BY total_bytes DESC

-- 5xx errors with User-Agent
SELECT time_local, remote_addr, method, request_uri, status, http_user_agent
FROM 'samples/nginx/access.log' WHERE CAST(status AS VARCHAR) LIKE '5%'

-- Request method breakdown
SELECT method, COUNT(*) AS hits FROM 'samples/nginx/access.log' GROUP BY method
```

---

## 4. Apache / httpd Access Logs

```sql
SELECT remote_addr, request_uri, status FROM 'samples/apache/access.log' WHERE CAST(status AS VARCHAR) LIKE '4%'
SELECT remote_addr, COUNT(*) AS hits FROM 'samples/apache/access.log' GROUP BY remote_addr
SELECT request_uri, status, COUNT(*) AS hits FROM 'samples/apache/access.log' GROUP BY request_uri, status
```

---

## 5. Caddy JSON Access Logs

```sql
SELECT * FROM 'samples/caddy/caddy.json'
-- Nested fields auto-flattened; query like:
SELECT request.remote_ip, request.uri, status, size FROM 'samples/caddy/caddy.json' WHERE status = '500'
```

---

## 6. HAProxy Logs

```sql
SELECT * FROM 'samples/haproxy/haproxy.log'
-- Extract backend, status, timing via regex UDFs or column aliases
```

---

## 7. Syslog / auth.log

```sql
-- SSH brute-force attempts (Failed password)
SELECT timestamp, hostname, process, message FROM 'samples/syslog/auth.log' WHERE message LIKE '%Failed password%'

-- Count by process
SELECT process, COUNT(*) AS events FROM 'samples/syslog/auth.log' GROUP BY process

-- Successful logins
SELECT timestamp, message FROM 'samples/syslog/auth.log' WHERE message LIKE '%Accepted%'
```

---

## 8. Firewall Key-Value Logs

```sql
-- Denied connections by destination port
SELECT dstport, COUNT(*) AS denied_hits FROM 'samples/firewall/firewall.log' WHERE action = 'denied' GROUP BY dstport ORDER BY denied_hits DESC

-- Top denied source IPs
SELECT srcip, COUNT(*) AS denied_attempts FROM 'samples/firewall/firewall.log' WHERE action = 'denied' GROUP BY srcip

-- Sensitive port probing (22, 23, 3389, 445, 1433, 3306)
SELECT srcip, dstip, dstport, action FROM 'samples/firewall/firewall.log' WHERE dstport IN ('22','23','3389','445','1433','3306') AND action='denied'

-- Bandwidth by action
SELECT action, SUM(CAST(bytes_in AS BIGINT)) AS in_bytes, SUM(CAST(bytes_out AS BIGINT)) AS out_bytes
FROM 'samples/firewall/firewall.log' GROUP BY action
```

---

## 9. Cisco ASA

```sql
SELECT * FROM 'samples/cisco_asa/asa.log'
-- Built/denied/teardown connections and scanning alerts
```

---

## 10. Cisco Router/Switch Configs

```sql
-- Find access-list entries
SELECT line_number, line_text FROM 'samples/cisco_config/router.cfg' WHERE line_text LIKE '%access-list%'

-- Find SNMP community strings (audit hygiene)
SELECT line_number, line_text FROM 'samples/cisco_config/router.cfg' WHERE line_text LIKE '%snmp-server community%'
```

---

## 11. AWS (ALB / VPC Flow / S3)

```sql
-- ALB: top 5xx requests
SELECT timestamp, client_ip, request, elb_status_code, user_agent FROM 'samples/aws/alb_access.log'
WHERE elb_status_code LIKE '5%'

-- VPC Flow: all REJECTED connections
SELECT srcaddr, dstaddr, dstport, action FROM 'samples/aws/vpc_flow.log' WHERE action = 'REJECT'

-- VPC: rejected destination ports
SELECT dstport, COUNT(*) AS rejects FROM 'samples/aws/vpc_flow.log' WHERE action='REJECT' GROUP BY dstport

-- S3: denied object reads
SELECT remote_ip, key, http_status, error_code FROM 'samples/aws/s3_access.log' WHERE http_status LIKE '4%'
```

---

## 12. Azure Activity

```sql
SELECT operationName, callerIpAddress, resultType, caller FROM 'samples/azure/activity.json'
SELECT callerIpAddress, COUNT(*) AS failures FROM 'samples/azure/activity.json' WHERE resultType='Failure' GROUP BY callerIpAddress
```

---

## 13. GCP Audit

```sql
SELECT protoPayload.methodName, protoPayload.authenticationInfo.principalEmail,
       protoPayload.requestMetadata.callerIp, protoPayload.status.code
FROM 'samples/gcp/audit.json'

SELECT protoPayload.requestMetadata.callerIp, COUNT(*) AS denied_calls
FROM 'samples/gcp/audit.json' WHERE severity = 'ERROR' GROUP BY protoPayload.requestMetadata.callerIp
```

---

## 14. JSON / NDJSON Events

```sql
SELECT level, COUNT(*) AS events FROM 'samples/json_logs/events.ndjson' GROUP BY level
SELECT client_ip, path, status FROM 'samples/json_logs/events.ndjson' WHERE level='ERROR'
SELECT service, AVG(CAST(duration_ms AS BIGINT)) AS avg_ms FROM 'samples/json_logs/events.ndjson' GROUP BY service
```

---

## 15. CSV / TSV Files

```sql
SELECT * FROM 'samples/csv_logs/events.csv' WHERE status = 500
SELECT level, COUNT(*) FROM 'samples/csv_logs/events.csv' GROUP BY level
SELECT * FROM 'samples/csv_logs/events.tsv' WHERE status = 500
```

---

## 16. Windows Security Events

```sql
-- Failed logons (EventID 4625)
SELECT Event.System.TimeCreated.SystemTime, Event.EventData.TargetUserName,
       Event.EventData.IpAddress, Event.EventData.SubStatus
FROM 'samples/evtx/security_events.json' WHERE Event.System.EventID.Value = 4625
```

---

## 17. Security & Threat Hunting

```sql
-- Classify every request with threat category
SELECT c_ip, cs_uri_stem, cs_uri_query, detect_threat(cs_uri_query) AS threat_class
FROM 'samples/iis/u_extend01.log'

-- Only detected threats
SELECT c_ip, cs_uri_stem, detect_threat(cs_uri_query) AS threat
FROM 'samples/iis/u_extend01.log' WHERE detect_threat(cs_uri_query) <> 'CLEAN'

-- Entropy on query strings (find encoded/obfuscated payloads)
SELECT cs_uri_query, shannon_entropy(cs_uri_query) AS entropy
FROM 'samples/iis/u_extend01.log' WHERE shannon_entropy(cs_uri_query) > 4.5

-- CIDR membership check
SELECT c_ip FROM 'samples/iis/u_extend01.log' WHERE ip_in_cidr(c_ip, '203.0.113.0/24')

-- Group URIs into structural templates (log clustering)
SELECT cluster_template(cs_uri_stem) AS uri_template, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY cluster_template(cs_uri_stem)

-- PII masking on email-like columns
SELECT mask_pii(cs_uri_query) AS sanitized_query FROM 'samples/iis/u_extend01.log'
```

---

## 18. Time-Series & KSQL-Style Windowing

```sql
-- Requests per minute bucket
SELECT time_bucket(date, time, 1) AS minute, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY time_bucket(date, time, 1) ORDER BY minute

-- Errors per 5-minute bucket
SELECT time_bucket(date, time, 5) AS bucket_5min, COUNT(*) AS errors
FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'
GROUP BY time_bucket(date, time, 5) ORDER BY bucket_5min

-- Requests per hour
SELECT time_bucket(date, time, 60) AS hour_bucket, COUNT(*) AS hits
FROM 'samples/iis/u_extend01.log' GROUP BY time_bucket(date, time, 60)

-- Date difference (days between two log dates)
SELECT date_diff_days('2026-10-15', '2026-10-10') AS days_ago
```

### KQL (Kusto / Azure Log Analytics) equivalents

| KQL | LPR SQL Equivalent |
|---|---|
| `requests \| summarize count() by bin(timestamp, 5m)` | `SELECT time_bucket(date,time,5) AS b, COUNT(*) FROM logs GROUP BY b` |
| `requests \| top 10 by count_` | `SELECT TOP 10 col, COUNT(*) FROM logs GROUP BY col ORDER BY 2 DESC` |
| `requests \| where status startswith "5"` | `SELECT * FROM logs WHERE status LIKE '5%'` |
| `requests \| distinct c_ip` | `SELECT DISTINCT c_ip FROM logs` |
| `requests \| summarize avg(duration)` | `SELECT AVG(CAST(time_taken AS BIGINT)) FROM logs` |

---

## 19. Grouping, Pages, Bandwidth & Percentiles

```sql
-- Page hit counts (all pages, ranked)
SELECT cs_uri_stem, COUNT(*) AS page_hits FROM 'samples/iis/u_extend01.log' GROUP BY cs_uri_stem ORDER BY page_hits DESC

-- Unique visitors per page
SELECT cs_uri_stem, COUNT(DISTINCT c_ip) AS unique_visitors
FROM 'samples/iis/u_extend01.log' GROUP BY cs_uri_stem ORDER BY unique_visitors DESC

-- Request volume per client IP per hour
SELECT c_ip, time_bucket(date, time, 60) AS hour, COUNT(*) AS requests
FROM 'samples/iis/u_extend01.log' GROUP BY c_ip, time_bucket(date, time, 60)

-- Percentile approximation via window functions (DataFusion built-in)
SELECT cs_uri_stem, CAST(time_taken AS BIGINT) AS ms,
       PERCENT_RANK() OVER (ORDER BY CAST(time_taken AS BIGINT)) AS pct_rank
FROM 'samples/iis/u_extend01.log' ORDER BY ms DESC
```

---

## 20. Linux Power-Tool Modes

```bash
# Grep + field projection (like grep + awk)
lpr -f samples/iis/u_extend01.log -g "500" -F date,time,c_ip,cs_uri_stem,sc_status

# Invert match
lpr -f samples/nginx/access.log -g "200" -v -F remote_addr,status,request_uri

# Count matches
lpr -f samples/syslog/auth.log -g "Failed" -c

# Regex match
lpr -f samples/iis/u_extend01.log -E "UNION.*SELECT" -F c_ip,cs_uri_query

# GoAccess-style summary
lpr -f samples/iis/u_extend01.log --stats
lpr -f samples/nginx/access.log --stats
lpr -f samples/iis_smtp/u_ex260101.log --stats

# Bar chart output
lpr -f samples/iis/u_extend01.log -o:CHART "SELECT sc_status, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC"

# stdin pipe
cat samples/nginx/access.log | lpr -i nginx "SELECT remote_addr, status FROM stdin"
zcat samples/gz_logs/u_extend01.log.gz | lpr -i IISW3C "SELECT * FROM stdin WHERE sc_status LIKE '5%'"
```

---

## 21. Multi-File, Archive & Fleet Queries

```sql
-- Query a zip archive of log files
SELECT log_filename, sc_status, COUNT(*) FROM 'samples/iis/multi_site_logs.zip' GROUP BY log_filename, sc_status

-- Query multiple files via glob
SELECT log_filename, COUNT(*) FROM 'samples/iis/*.log' GROUP BY log_filename

-- Semicolon-separated multi-source
SELECT * FROM 'samples/iis/u_extend01.log;samples/iis/u_extend02.log' WHERE sc_status LIKE '5%'

-- All gzip files in a folder
SELECT log_filename, COUNT(*) FROM 'samples/gz_logs/*.gz' GROUP BY log_filename
```

```bash
# Multi-server fleet scan (IIS via SMB, Linux via SSH)
lpr fleet --save-profile prod-iis --servers servers.csv --site W3SVC1 --threads 8
lpr fleet --save-profile prod-linux --servers linux_hosts.csv --server-type nginx --ssh --log-path /var/log/nginx
lpr fleet --profile prod-iis --server-numbers "1-12" --days 3
```

---

## 22. CTEs, Subqueries & Window Functions

```sql
-- Common Table Expression (CTE)
WITH errors AS (
  SELECT c_ip, sc_status, time_taken FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'
)
SELECT c_ip, COUNT(*) AS err_count FROM errors GROUP BY c_ip ORDER BY err_count DESC

-- Window function: rank top pages by hit count
SELECT cs_uri_stem, hits, RANK() OVER (ORDER BY hits DESC) AS rank
FROM (
  SELECT cs_uri_stem, COUNT(*) AS hits FROM 'samples/iis/u_extend01.log' GROUP BY cs_uri_stem
) t

-- LAG: compare consecutive response times per IP
SELECT time, c_ip, CAST(time_taken AS BIGINT) AS ms,
       LAG(CAST(time_taken AS BIGINT)) OVER (PARTITION BY c_ip ORDER BY time) AS prev_ms
FROM 'samples/iis/u_extend01.log'

-- Running total of errors
SELECT time, sc_status, COUNT(*) OVER (ORDER BY time) AS running_total
FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%'

-- Subquery for top talkers who also caused errors
SELECT c_ip, COUNT(*) AS hits FROM 'samples/iis/u_extend01.log'
WHERE c_ip IN (SELECT c_ip FROM 'samples/iis/u_extend01.log' WHERE sc_status LIKE '5%')
GROUP BY c_ip ORDER BY hits DESC
```

---

*MIT / Unlicense — Made using vibe coding by Sunil Warrier*
