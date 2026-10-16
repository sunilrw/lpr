# 📊 LPR Expected Output Examples

> **Made using vibe coding by Sunil Warrier** | MIT / Unlicense
>
> Real output shapes produced by each output format / mode against `samples/` data.

---

## 1. ASCII Table (`-o:DATAGRID` / default)

```
+------------+----------+------------------+------------+-----------+--------------+-----------+------------+
| date       | time     | c_ip             | cs_method  | cs_uri_stem | sc_status  | sc_win32_status | time_taken |
+------------+----------+------------------+------------+-----------+--------------+-----------+------------+
| 2026-10-14 | 08:00:05 | 198.51.100.42    | POST       | /checkout/pay | 500     | 0          | 9213       |
| 2026-10-14 | 08:00:07 | 192.0.2.15       | GET        | /products.asp | 500     | 0          | 10012      |
| 2026-10-15 | 09:00:06 | 192.0.2.90       | GET        | /product.asp  | 500     | 0          | 230        |
+------------+----------+------------------+------------+-----------+--------------+-----------+------------+
```

## 2. Bar Chart (`-o:CHART`)

```
sc_status  | hits
-----------+------
200        | ████████████████████████████████████████  5
404        | ████████  2
500        | ████████  3
400        | ██  1
```

## 3. CSV (`-o:CSV`)

```csv
date,time,c_ip,cs_uri_stem,sc_status,time_taken
2026-10-14,08:00:05,198.51.100.42,/checkout/pay,500,9213
2026-10-14,08:00:07,192.0.2.15,/products.aspx,500,10012
```

## 4. JSON (`-o:JSON`)

```json
[
  {
    "date": "2026-10-14",
    "time": "08:00:05",
    "c_ip": "198.51.100.42",
    "cs_uri_stem": "/checkout/pay",
    "sc_status": "500",
    "time_taken": "9213"
  }
]
```

## 5. NDJSON (`-o:NDJSON`)

```json
{"date":"2026-10-14","time":"08:00:05","c_ip":"198.51.100.42","cs_uri_stem":"/checkout/pay","sc_status":"500","time_taken":"9213"}
{"date":"2026-10-14","time":"08:00:07","c_ip":"192.0.2.15","cs_uri_stem":"/products.aspx","sc_status":"500","time_taken":"10012"}
```

## 6. Vertical / Card Format (`-G` / `-o:vertical`)

```
** Row 1 **
  date          : 2026-10-14
  time          : 08:00:05
  c_ip          : 198.51.100.42
  cs_uri_stem   : /checkout/pay
  sc_status     : 500
  time_taken    : 9213

** Row 2 **
  date          : 2026-10-14
  time          : 08:00:07
  c_ip          : 192.0.2.15
  cs_uri_stem   : /products.aspx
  sc_status     : 500
  time_taken    : 10012
```

## 7. `--stats` / GoAccess Summary

```
================ [l pr] GoAccess Summary — IIS W3C ================
Files: 1 | Lines: 10 | Rows: 10 | Elapsed: 0.02s

📊 HTTP Status Distribution
  200    ████████████████████████  5 (50.0%)
  500    ██████████████  3 (30.0%)
  404    ██████████  2 (20.0%)
  400    █  1 (10.0%)

🖥️  Top Client IPs
  198.51.100.10  ████████  2
  203.0.113.77   ████████  2
  198.51.100.42  ████  1
```

## 8. Fleet Detail CSV

```csv
ServerName,ServerIP,Date,Time,ClientIP,Method,UriStem,UriQuery,Status,SubStatus,Win32Status,TimeTakenMs,UserAgent,Referer,LogFile,LogRow
LOCAL-SERVER,127.0.0.1,2026-10-14,08:00:05,198.51.100.42,POST,/checkout/pay,,500,,0,9213,Mozilla/5.0,https://example.com/cart,u_extend01.log,6
```

## 9. Audit Output (`lpr audit`)

```
[1] HIGH | IIS_THREAT_SUMMARY
+----------------------------+-----------+------+------------------+
| threat_category            | sc_status | hits | unique_endpoints |
+----------------------------+-----------+------+------------------+
| HIGH:SQL_INJECTION         | 500       | 2    | 2                |
| HIGH:PATH_TRAVERSAL_LFI    | 400       | 1    | 1                |
| MEDIUM:VULN_SCANNER_PROBE  | 404       | 3    | 3                |
+----------------------------+-----------+------+------------------+
```

## 10. XML (`-o:XML`)

```xml
<results>
  <row><date>2026-10-14</date><time>08:00:05</time><c_ip>198.51.100.42</c_ip><sc_status>500</sc_status></row>
</results>
```

## 11. SQL Insert Format (`-o:SQL`)

```sql
INSERT INTO log_results (date, time, c_ip, cs_uri_stem, sc_status, time_taken)
VALUES ('2026-10-14','08:00:05','198.51.100.42','/checkout/pay','500','9213');
```

## 12. Parquet (`-o:PARQUET`)

Binary columnar file `output.parquet` — readable by DuckDB, Polars, Pandas, Spark, Arrow:
```python
import pandas as pd; df = pd.read_parquet("output.parquet"); print(df)
```

## 13. Suggest / Intent Discovery (`lpr suggest`)

```
🔍 Detected Format: IIS W3C  |  Columns: date, time, s_ip, cs_method, cs_uri_stem, ...
💡 Suggested Queries:
   • 5xx Error Summary    → SELECT sc_status, COUNT(*) AS errors FROM logs WHERE sc_status LIKE '5%' GROUP BY sc_status
   • Top Slow Pages       → SELECT TOP 10 cs_uri_stem, MAX(CAST(time_taken AS BIGINT)) AS max_ms FROM logs GROUP BY cs_uri_stem ORDER BY max_ms DESC
   • Threat Detection     → SELECT c_ip, cs_uri_stem, detect_threat(cs_uri_query) AS threat FROM logs WHERE detect_threat(cs_uri_query) <> 'CLEAN'
```

---

*MIT / Unlicense — Made using vibe coding by Sunil Warrier*
