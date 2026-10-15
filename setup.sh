#!/usr/bin/env bash
set -e

mkdir -p src .github/workflows tests

cat << 'EOF' > .gitignore
/target
Cargo.lock
*.parquet
*.zip
*.checkpoint.json
.DS_Store
EOF

cat << 'EOF' > Cargo.toml
[package]
name = "lpr"
version = "1.0.0"
edition = "2021"
description = "Complete Modern Rust SQL Log Parser & Security Auditor"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
datafusion = "42.0"
arrow = { version = "53.0", features = ["prettyprint"] }
parquet = { version = "53.0", features = ["arrow", "async"] }
clap = { version = "4.5", features = ["derive", "env"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
regex = "1.11"
flate2 = "1.0"
zstd = "0.13"
evtx = "0.8"
calamine = "0.26"
glob = "0.3"
urlencoding = "2.1"
ipnet = "2.10"
chrono = { version = "0.4", features = ["serde"] }
axum = "0.7"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
ratatui = "0.28"
crossterm = "0.28"

[target.'cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))'.dependencies]
tao = "0.30"
wry = "0.44"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
EOF

cat << 'EOF' > src/checkpoint.rs
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Default, Serialize, Deserialize)]
pub struct CheckpointStore {
    pub offsets: HashMap<String, u64>,
}

impl CheckpointStore {
    pub fn load(path: Option<&str>) -> Self {
        if let Some(p) = path {
            if let Ok(data) = fs::read_to_string(p) {
                if let Ok(store) = serde_json::from_str(&data) {
                    return store;
                }
            }
        }
        Self::default()
    }

    pub fn get_offset(&self, file_path: &Path) -> u64 {
        let key = file_path.to_string_lossy().to_string();
        self.offsets.get(&key).copied().unwrap_or(0)
    }

    pub fn update_offset(&mut self, file_path: &Path, new_offset: u64) {
        let key = file_path.to_string_lossy().to_string();
        self.offsets.insert(key, new_offset);
    }

    pub fn save(&self, path: Option<&str>) -> Result<()> {
        if let Some(p) = path {
            let json = serde_json::to_string_pretty(self)?;
            fs::write(p, json)?;
        }
        Ok(())
    }
}
EOF

cat << 'EOF' > src/udfs.rs
use arrow::array::{Array, BooleanArray, Float64Array, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::cast::as_string_array;
use datafusion::error::Result;
use datafusion::logical_expr::{ColumnarValue, Volatility};
use datafusion::prelude::*;
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap());

static DRAIN_TOKENS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|0x[0-9a-f]+|\b\d+\b)").unwrap()
});

static SQLI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\bunion\s+(all\s+)?select\b|\bselect\b.{1,40}\bfrom\b|\bor\s+['\x22]?1['\x22]?\s*=\s*['\x22]?1|--\s|/\*.*\*/|\bwaitfor\s+delay\b|\bsleep\(\d+\)|\bbenchmark\()").unwrap()
});
static XSS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|onloadstart\s*=|<iframe\b|<svg\b.*onload|alert\(|document\.cookie)").unwrap()
});
static LFI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|c:\\windows\\win\.ini|boot\.ini|/proc/self/environ)").unwrap()
});
static RCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\$\{jndi:(ldap|rmi|dns|nis|iiop)s?:|;\s*(cat|ls|whoami|id|uname|curl|wget|bash|sh|nc|powershell|cmd\.exe)\b|\|\s*(bash|sh|nc|powershell)\b|`.*`)").unwrap()
});
static SSRF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])").unwrap()
});
static SCANNER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(/\.env\b|/\.git/|/wp-login\.php|/xmlrpc\.php|/phpmyadmin|/actuator/env|/vendor/phpunit|/shell\.php|/\.aws/credentials)").unwrap()
});

pub fn register_all_udfs(ctx: &SessionContext) {
    let entropy_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: Float64Array = str_arr.iter().map(|opt_s| opt_s.map(calculate_entropy)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("shannon_entropy", vec![DataType::Utf8], Arc::new(DataType::Float64), Volatility::Immutable, entropy_fn));

    let url_decode_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|s| urlencoding::decode(s).map(|c| c.into_owned()).unwrap_or_else(|_| s.to_string()))).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("url_decode", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, url_decode_fn));

    let ua_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(classify_user_agent)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("parse_ua", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, ua_fn));

    let pii_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|s| EMAIL_RE.replace_all(s, "[REDACTED_EMAIL]").into_owned())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("mask_pii", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, pii_fn));

    let cluster_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|s| DRAIN_TOKENS_RE.replace_all(s, "<*>").into_owned())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("cluster_template", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, cluster_fn));

    let threat_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(classify_payload_threat)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("detect_threat", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, threat_fn));

    let cidr_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let len = match &args[0] {
            ColumnarValue::Array(a) => a.len(),
            ColumnarValue::Scalar(_) => 1,
        };
        let ip_arr = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };
        let net_arr = match &args[1] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };
        let ips = as_string_array(&ip_arr)?;
        let nets = as_string_array(&net_arr)?;

        let result: BooleanArray = ips.iter().zip(nets.iter()).map(|(opt_ip, opt_net)| match (opt_ip, opt_net) {
            (Some(ip_s), Some(net_s)) => {
                let clean_ip = ip_s.split(':').next().unwrap_or(ip_s);
                match (clean_ip.parse::<IpAddr>(), net_s.parse::<IpNet>()) {
                    (Ok(ip), Ok(net)) => Some(net.contains(&ip)),
                    _ => Some(false),
                }
            }
            _ => Some(false),
        }).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("ip_in_cidr", vec![DataType::Utf8, DataType::Utf8], Arc::new(DataType::Boolean), Volatility::Immutable, cidr_fn));
}

pub fn classify_payload_threat(raw: &str) -> &'static str {
    let decoded = urlencoding::decode(raw).map(|c| c.into_owned()).unwrap_or_else(|_| raw.to_string());
    if RCE_RE.is_match(&decoded) { "CRITICAL:RCE_OR_LOG4SHELL" }
    else if SQLI_RE.is_match(&decoded) { "HIGH:SQL_INJECTION" }
    else if LFI_RE.is_match(&decoded) { "HIGH:PATH_TRAVERSAL_LFI" }
    else if SSRF_RE.is_match(&decoded) { "HIGH:SSRF_CLOUD_METADATA" }
    else if XSS_RE.is_match(&decoded) { "MEDIUM:XSS_ATTEMPT" }
    else if SCANNER_RE.is_match(&decoded) { "MEDIUM:VULN_SCANNER_PROBE" }
    else { "CLEAN" }
}

fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = HashMap::new();
    let len = s.len() as f64;
    for b in s.bytes() { *counts.entry(b).or_insert(0usize) += 1; }
    counts.values().fold(0.0, |acc, &count| {
        let p = (count as f64) / len;
        acc - p * p.log2()
    })
}

fn classify_user_agent(ua: &str) -> String {
    let lower = ua.to_lowercase();
    let is_bot = lower.contains("bot") || lower.contains("crawler") || lower.contains("spider") || lower.contains("curl") || lower.contains("python") || lower.contains("nmap") || lower.contains("sqlmap") || lower.contains("nuclei") || lower.contains(" go-http");
    let os = if lower.contains("windows") { "Windows" }
    else if lower.contains("macintosh") || lower.contains("mac os") { "macOS" }
    else if lower.contains("android") { "Android" }
    else if lower.contains("iphone") || lower.contains("ipad") { "iOS" }
    else if lower.contains("linux") { "Linux" }
    else { "OtherOS" };

    let browser = if is_bot { "Bot/Scanner" }
    else if lower.contains("edg/") { "Edge" }
    else if lower.contains("chrome/") { "Chrome" }
    else if lower.contains("firefox/") { "Firefox" }
    else if lower.contains("safari/") { "Safari" }
    else { "Unknown" };

    format!("{}/{}", browser, os)
}
EOF

cat << 'EOF' > src/parsers.rs
use crate::checkpoint::CheckpointStore;
use anyhow::{Context, Result};
use arrow::array::{ArrayRef, Int64Array, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use calamine::{open_workbook_auto, Data, Reader};
use clap::ValueEnum;
use evtx::EvtxParser;
use flate2::read::GzDecoder;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum InputFormat {
    Auto, W3c, Json, Csv, Tsv, Excel, Parquet, Nginx, Syslog, Evtx,
    FirewallKv, CiscoAsa, CiscoConfig, Cef, Ias, Akamai, AwsS3, AwsVpc,
    AwsAlb, AzureBlob, Gcp, Regex, Line,
}

static NGINX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<method>\S+) (?P<request_uri>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<body_bytes_sent>\d+|-) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)""#).unwrap()
});
static SYSLOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"#).unwrap()
});
static KV_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|(\S+))"#).unwrap()
});
static CISCO_ASA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"%ASA-(?P<severity>\d)-(?P<msg_id>\d{6}):\s*(?P<message>.*)$"#).unwrap()
});
static IP_EXTRACTOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d+))?\b").unwrap()
});
static AWS_S3_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?P<bucket_owner>\S+) (?P<bucket>\S+) \[(?P<time>[^\]]+)\] (?P<remote_ip>\S+) (?P<requester>\S+) (?P<request_id>\S+) (?P<operation>\S+) (?P<key>\S+) "(?P<request_uri>[^"]*)" (?P<http_status>\S+) (?P<error_code>\S+) (?P<bytes_sent>\S+) (?P<object_size>\S+) (?P<total_time>\S+) (?P<turn_around_time>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)""#).unwrap()
});
static AWS_ALB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?P<type>\S+) (?P<time>\S+) (?P<elb>\S+) (?P<client_ip>[^:\s]+)(?::\d+)? (?P<target_ip>\S+) (?P<request_processing_time>\S+) (?P<target_processing_time>\S+) (?P<response_processing_time>\S+) (?P<elb_status_code>\S+) (?P<target_status_code>\S+) (?P<received_bytes>\S+) (?P<sent_bytes>\S+) "(?P<request>[^"]*)" "(?P<user_agent>[^"]*)" (?P<ssl_cipher>\S+) (?P<ssl_protocol>\S+)"#).unwrap()
});

pub fn resolve_paths(pattern: &str) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if pattern.contains('*') || pattern.contains('?') {
        for entry in glob::glob(pattern).context("Invalid glob pattern")? {
            if let Ok(path) = entry { if path.is_file() { paths.push(path); } }
        }
    } else {
        paths.push(PathBuf::from(pattern));
    }
    if paths.is_empty() { anyhow::bail!("No log files matched pattern: {}", pattern); }
    Ok(paths)
}

pub fn open_log_reader_with_checkpoint(path: &Path, ckpt: &mut Option<&mut CheckpointStore>) -> Result<Box<dyn BufRead + Send>> {
    let mut file = File::open(path).with_context(|| format!("Failed to open {:?}", path))?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    match ext {
        "gz" => Ok(Box::new(BufReader::with_capacity(128 * 1024, GzDecoder::new(file)))),
        "zst" => Ok(Box::new(BufReader::with_capacity(128 * 1024, zstd::stream::read::Decoder::new(file)?))),
        _ => {
            if let Some(store) = ckpt.as_deref_mut() {
                let len = file.metadata().map(|m| m.len()).unwrap_or(0);
                let prev = store.get_offset(path);
                if prev > 0 && prev <= len { let _ = file.seek(SeekFrom::Start(prev)); }
                store.update_offset(path, len);
            }
            Ok(Box::new(BufReader::with_capacity(128 * 1024, file)))
        }
    }
}

pub fn open_log_reader(path: &Path) -> Result<Box<dyn BufRead + Send>> {
    let mut none_ckpt = None;
    open_log_reader_with_checkpoint(path, &mut none_ckpt)
}

pub fn detect_format(path: &Path) -> InputFormat {
    let name = path.to_string_lossy().to_lowercase();
    let clean = name.trim_end_matches(".gz").trim_end_matches(".zst");
    if clean.ends_with(".xlsx") || clean.ends_with(".xls") || clean.ends_with(".ods") { return InputFormat::Excel; }
    if clean.ends_with(".evtx") { return InputFormat::Evtx; }
    if clean.ends_with(".parquet") { return InputFormat::Parquet; }
    if clean.ends_with(".csv") { return InputFormat::Csv; }
    if clean.ends_with(".tsv") { return InputFormat::Tsv; }
    if clean.ends_with(".cfg") || clean.contains("running-config") { return InputFormat::CiscoConfig; }
    if clean.ends_with(".json") || clean.ends_with(".ndjson") || clean.ends_with(".jsonl") { return InputFormat::Json; }

    if let Ok(mut reader) = open_log_reader(path) {
        let mut first_line = String::new();
        for _ in 0..10 {
            first_line.clear();
            if reader.read_line(&mut first_line).unwrap_or(0) == 0 { break; }
            let trimmed = first_line.trim();
            if trimmed.is_empty() { continue; }
            if trimmed.starts_with("#Software:") || trimmed.starts_with("#Fields:") || trimmed.starts_with("#Version:") { return InputFormat::W3c; }
            if trimmed.starts_with('{') || trimmed.starts_with('[') { return InputFormat::Json; }
            if trimmed.contains("CEF:") { return InputFormat::Cef; }
            if trimmed.contains("%ASA-") { return InputFormat::CiscoAsa; }
            if trimmed.starts_with("1.0;") || trimmed.starts_with("2.0;") { return InputFormat::AzureBlob; }
            if trimmed.starts_with("version account-id interface-id") { return InputFormat::AwsVpc; }
            if AWS_S3_RE.is_match(trimmed) { return InputFormat::AwsS3; }
            if AWS_ALB_RE.is_match(trimmed) { return InputFormat::AwsAlb; }
            if NGINX_RE.is_match(trimmed) { return InputFormat::Nginx; }
            if KV_PAIR_RE.find_iter(trimmed).count() >= 4 { return InputFormat::FirewallKv; }
            if SYSLOG_RE.is_match(trimmed) { return InputFormat::Syslog; }
        }
    }
    InputFormat::Line
}

pub fn parse_excel_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let mut headers: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for path in paths {
        let mut workbook = open_workbook_auto(path)?;
        if let Some(sheet_name) = workbook.sheet_names().first().cloned() {
            if let Ok(range) = workbook.worksheet_range(&sheet_name) {
                for (row_idx, row) in range.rows().enumerate() {
                    if row_idx == 0 && headers.is_empty() {
                        headers = row.iter().enumerate().map(|(i, c)| {
                            let s = cell_to_string(c).trim().replace([' ', '-', '.'], "_");
                            if s.is_empty() { format!("col_{}", i + 1) } else { s }
                        }).collect();
                    } else if !headers.is_empty() {
                        let vals: Vec<String> = (0..headers.len()).map(|i| row.get(i).map(cell_to_string).unwrap_or_default()).collect();
                        rows.push(vals);
                    }
                }
            }
        }
    }
    if headers.is_empty() { anyhow::bail!("No worksheet data found in Excel file(s)"); }
    build_string_batch(&headers, &rows)
}

fn cell_to_string(c: &Data) -> String {
    match c {
        Data::String(s) => s.clone(),
        Data::Float(f) => if f.fract() == 0.0 { format!("{:.0}", f) } else { f.to_string() },
        Data::Int(i) => i.to_string(),
        Data::Bool(b) => b.to_string(),
        Data::DateTime(dt) => dt.to_string(),
        Data::DateTimeIso(s) | Data::DurationIso(s) => s.clone(),
        Data::Error(e) => format!("ERR:{:?}", e),
        Data::Empty => String::new(),
    }
}

pub fn parse_json_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let mut keys: Vec<String> = Vec::new();
    let mut flat_objects: Vec<HashMap<String, String>> = Vec::new();

    for path in paths {
        let mut reader = open_log_reader(path)?;
        let mut full_content = String::new();
        reader.read_to_string(&mut full_content)?;
        let trimmed = full_content.trim();
        if trimmed.is_empty() { continue; }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            extract_json_records(val, &mut keys, &mut flat_objects);
            continue;
        }
        for line in trimmed.lines() {
            let l = line.trim();
            if l.is_empty() { continue; }
            if let Ok(val) = serde_json::from_str::<Value>(l) {
                extract_json_records(val, &mut keys, &mut flat_objects);
            }
        }
    }
    if keys.is_empty() { anyhow::bail!("No valid JSON objects found in input"); }
    let rows: Vec<Vec<String>> = flat_objects.into_iter().map(|obj| keys.iter().map(|k| obj.get(k).cloned().unwrap_or_default()).collect()).collect();
    build_string_batch(&keys, &rows)
}

fn extract_json_records(val: Value, keys: &mut Vec<String>, out: &mut Vec<HashMap<String, String>>) {
    match val {
        Value::Array(arr) => for item in arr { extract_json_records(item, keys, out); },
        Value::Object(mut map) => {
            if let Some(Value::Array(records)) = map.remove("Records").or_else(|| map.remove("records")) {
                for r in records { extract_json_records(r, keys, out); }
                return;
            }
            let mut flat = HashMap::new();
            flatten_json_object("", &map, &mut flat, keys);
            if !flat.is_empty() { out.push(flat); }
        }
        _ => {}
    }
}

fn flatten_json_object(prefix: &str, map: &Map<String, Value>, flat: &mut HashMap<String, String>, keys: &mut Vec<String>) {
    for (k, v) in map {
        let col_name = if prefix.is_empty() { k.replace(['-', '.'], "_") } else { format!("{}_{}", prefix, k.replace(['-', '.'], "_")) };
        match v {
            Value::Object(sub) => {
                if prefix.is_empty() { flatten_json_object(&col_name, sub, flat, keys); }
                else {
                    if !keys.contains(&col_name) { keys.push(col_name.clone()); }
                    flat.insert(col_name, Value::Object(sub.clone()).to_string());
                }
            }
            Value::Null => {}
            Value::String(s) => {
                if !keys.contains(&col_name) { keys.push(col_name.clone()); }
                flat.insert(col_name, s.clone());
            }
            other => {
                if !keys.contains(&col_name) { keys.push(col_name.clone()); }
                flat.insert(col_name, other.to_string());
            }
        }
    }
}

pub fn parse_w3c_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let mut field_names: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            if let Some(fields_str) = trimmed.strip_prefix("#Fields:") {
                if field_names.is_empty() {
                    field_names = fields_str.split_whitespace().map(|s| s.replace('-', "_").replace(['(', ')'], "")).collect();
                }
                continue;
            }
            if trimmed.starts_with('#') { continue; }
            let parts: Vec<String> = trimmed.split_whitespace().map(|s| s.to_string()).collect();
            if !field_names.is_empty() && parts.len() == field_names.len() { rows.push(parts); }
        }
    }
    if field_names.is_empty() { anyhow::bail!("No #Fields: header found in W3C log file(s)"); }
    build_string_batch(&field_names, &rows)
}

pub fn parse_aws_vpc_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let default_fields = vec!["version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log_status"];
    let mut field_names: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            if trimmed.starts_with("version ") {
                if field_names.is_empty() { field_names = trimmed.split_whitespace().map(|s| s.replace('-', "_")).collect(); }
                continue;
            }
            if field_names.is_empty() { field_names = default_fields.iter().map(|s| s.to_string()).collect(); }
            let parts: Vec<String> = trimmed.split_whitespace().map(|s| s.to_string()).collect();
            if parts.len() >= field_names.len() { rows.push(parts.into_iter().take(field_names.len()).collect()); }
        }
    }
    build_string_batch(&field_names, &rows)
}

pub fn parse_azure_blob_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec!["version", "request_start_time", "operation_type", "request_status", "http_status_code", "end_to_end_latency_ms", "server_latency_ms", "authentication_type", "requester_account_name", "owner_account_name", "service_type", "request_url", "requested_object_key", "request_id_header", "operation_count", "caller_ip_address"].into_iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut rows = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let parts: Vec<String> = trimmed.split(';').take(fields.len()).map(|s| s.trim_matches('"').to_string()).collect();
            if parts.len() >= 12 {
                let mut padded = parts;
                padded.resize(fields.len(), String::new());
                rows.push(padded);
            }
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_aws_s3_files(paths: &[PathBuf]) -> Result<RecordBatch> { parse_regex_files(paths, &AWS_S3_RE) }
pub fn parse_aws_alb_files(paths: &[PathBuf]) -> Result<RecordBatch> { parse_regex_files(paths, &AWS_ALB_RE) }
pub fn parse_nginx_files(paths: &[PathBuf]) -> Result<RecordBatch> { parse_regex_files(paths, &NGINX_RE) }
pub fn parse_syslog_files(paths: &[PathBuf]) -> Result<RecordBatch> { parse_regex_files(paths, &SYSLOG_RE) }

pub fn parse_regex_files(paths: &[PathBuf], re: &Regex) -> Result<RecordBatch> {
    let group_names: Vec<String> = re.capture_names().flatten().map(|s| s.to_string()).collect();
    if group_names.is_empty() { anyhow::bail!("Regex must contain named capture groups"); }
    let mut rows: Vec<Vec<String>> = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(caps) = re.captures(&line) {
                let row: Vec<String> = group_names.iter().map(|name| caps.name(name).map(|m| m.as_str().to_string()).unwrap_or_default()).collect();
                rows.push(row);
            }
        }
    }
    build_string_batch(&group_names, &rows)
}

pub fn parse_firewall_kv_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let mut keys: Vec<String> = Vec::new();
    let mut objects: Vec<HashMap<String, String>> = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            let mut map = HashMap::new();
            for caps in KV_PAIR_RE.captures_iter(&line) {
                let k = caps[1].replace(['-', '.'], "_");
                let v = caps.get(2).or_else(|| caps.get(3)).map(|m| m.as_str().to_string()).unwrap_or_default();
                if !keys.contains(&k) { keys.push(k.clone()); }
                map.insert(k, v);
            }
            if line.contains("UFW BLOCK") || line.contains("DROP") {
                if !keys.contains(&"fw_action".to_string()) { keys.push("fw_action".to_string()); }
                map.entry("fw_action".to_string()).or_insert_with(|| "BLOCK".to_string());
            }
            if !map.is_empty() { objects.push(map); }
        }
    }
    if keys.is_empty() { anyhow::bail!("No key=value firewall fields found"); }
    let rows: Vec<Vec<String>> = objects.into_iter().map(|obj| keys.iter().map(|k| obj.get(k).cloned().unwrap_or_default()).collect()).collect();
    build_string_batch(&keys, &rows)
}

pub fn parse_cisco_asa_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec!["severity".to_string(), "msg_id".to_string(), "action".to_string(), "src_ip".to_string(), "src_port".to_string(), "dst_ip".to_string(), "dst_port".to_string(), "message".to_string()];
    let mut rows = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(caps) = CISCO_ASA_RE.captures(&line) {
                let sev = caps["severity"].to_string();
                let msg_id = caps["msg_id"].to_string();
                let msg = caps["message"].to_string();
                let lower = msg.to_lowercase();
                let action = if lower.contains("denied") || lower.contains("deny") || lower.contains("failed") { "DENY" }
                else if lower.contains("built") || lower.contains("permitted") || lower.contains("permit") { "PERMIT" }
                else if lower.contains("teardown") { "TEARDOWN" } else { "INFO" };

                let mut ips = IP_EXTRACTOR_RE.captures_iter(&msg);
                let (src_ip, src_port) = ips.next().map(|c| (c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(), c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default())).unwrap_or_default();
                let (dst_ip, dst_port) = ips.next().map(|c| (c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(), c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default())).unwrap_or_default();
                rows.push(vec![sev, msg_id, action.to_string(), src_ip, src_port, dst_ip, dst_port, msg]);
            }
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_cisco_config_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec!["file".to_string(), "line_number".to_string(), "section".to_string(), "directive".to_string(), "is_no_cmd".to_string()];
    let mut rows = Vec::new();
    for path in paths {
        let fname = path.to_string_lossy().to_string();
        let reader = open_log_reader(path)?;
        let mut current_section = String::from("GLOBAL");
        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            let trimmed_right = line.trim_end();
            let trimmed = trimmed_right.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('!') { continue; }
            let is_indented = trimmed_right.starts_with(' ') || trimmed_right.starts_with('\t');
            if !is_indented {
                if trimmed.starts_with("interface ") || trimmed.starts_with("router ") || trimmed.starts_with("line ") || trimmed.starts_with("ip access-list ") || trimmed.starts_with("crypto ") || trimmed.starts_with("object-group ") {
                    current_section = trimmed.to_string();
                } else {
                    current_section = "GLOBAL".to_string();
                }
            }
            let is_no = if trimmed.starts_with("no ") { "true" } else { "false" };
            rows.push(vec![fname.clone(), (idx + 1).to_string(), current_section.clone(), trimmed.to_string(), is_no.to_string()]);
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_cef_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec!["vendor".to_string(), "product".to_string(), "signature_id".to_string(), "name".to_string(), "severity".to_string(), "src".to_string(), "dst".to_string(), "act".to_string(), "request".to_string(), "extensions".to_string()];
    let mut rows = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(cef_idx) = line.find("CEF:") {
                let cef_body = &line[cef_idx..];
                let parts: Vec<&str> = cef_body.splitn(8, '|').collect();
                if parts.len() == 8 {
                    let ext = parts[7];
                    let mut src = String::new();
                    let mut dst = String::new();
                    let mut act = String::new();
                    let mut req = String::new();
                    for caps in KV_PAIR_RE.captures_iter(ext) {
                        let k = &caps[1];
                        let v = caps.get(2).or_else(|| caps.get(3)).map(|m| m.as_str()).unwrap_or("");
                        match k {
                            "src" | "c_ip" => src = v.to_string(),
                            "dst" | "s_ip" => dst = v.to_string(),
                            "act" | "action" => act = v.to_string(),
                            "request" | "cs_uri" => req = v.to_string(),
                            _ => {}
                        }
                    }
                    rows.push(vec![parts[1].to_string(), parts[2].to_string(), parts[4].to_string(), parts[5].to_string(), parts[6].to_string(), src, dst, act, req, ext.to_string()]);
                }
            }
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_ias_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec!["timestamp".to_string(), "computer".to_string(), "user_name".to_string(), "client_ip".to_string(), "nas_ip".to_string(), "packet_type".to_string(), "reason_code".to_string()];
    let xml_tag_re = Regex::new(r"<([A-Za-z0-9_-]+)(?:\s+[^>]*)?>([^<]*)</[A-Za-z0-9_-]+>").unwrap();
    let mut rows = Vec::new();
    for path in paths {
        let reader = open_log_reader(path)?;
        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.starts_with("<Event>") {
                let mut map = HashMap::new();
                for caps in xml_tag_re.captures_iter(trimmed) { map.insert(caps[1].to_string(), caps[2].to_string()); }
                rows.push(vec![
                    map.get("Timestamp").cloned().unwrap_or_default(),
                    map.get("Computer-Name").cloned().unwrap_or_default(),
                    map.get("User-Name").or_else(|| map.get("SAM-Account-Name")).cloned().unwrap_or_default(),
                    map.get("Calling-Station-Id").or_else(|| map.get("Client-IP-Address")).cloned().unwrap_or_default(),
                    map.get("NAS-IP-Address").cloned().unwrap_or_default(),
                    map.get("Packet-Type").cloned().unwrap_or_default(),
                    map.get("Reason-Code").cloned().unwrap_or_default(),
                ]);
            } else if trimmed.contains(',') {
                let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim_matches('"')).collect();
                if parts.len() >= 11 {
                    rows.push(vec![format!("{} {}", parts[2], parts[3]), parts[0].to_string(), parts[5].to_string(), parts.get(6).copied().unwrap_or("").to_string(), parts.get(9).copied().unwrap_or("").to_string(), parts[4].to_string(), parts.get(10).copied().unwrap_or("").to_string()]);
                }
            }
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_evtx_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let mut record_ids = Vec::new();
    let mut timestamps = Vec::new();
    let mut event_ids = Vec::new();
    let mut levels = Vec::new();
    let mut channels = Vec::new();
    let mut computers = Vec::new();
    let mut payloads = Vec::new();

    for path in paths {
        let mut parser = EvtxParser::from_path(path)?;
        for record in parser.records_json_value() {
            if let Ok(rec) = record {
                record_ids.push(rec.event_record_id as i64);
                timestamps.push(rec.timestamp.to_rfc3339());
                let sys = &rec.data["Event"]["System"];
                let eid = sys["EventID"].as_i64().or_else(|| sys["EventID"]["#text"].as_i64()).unwrap_or(0);
                event_ids.push(eid);
                levels.push(sys["Level"].as_i64().unwrap_or(0));
                channels.push(sys["Channel"].as_str().unwrap_or("").to_string());
                computers.push(sys["Computer"].as_str().unwrap_or("").to_string());
                payloads.push(rec.data["Event"]["EventData"].to_string());
            }
        }
    }

    let schema = Arc::new(Schema::new(vec![
        Field::new("record_id", DataType::Int64, false),
        Field::new("timestamp", DataType::Utf8, false),
        Field::new("event_id", DataType::Int64, false),
        Field::new("level", DataType::Int64, false),
        Field::new("channel", DataType::Utf8, false),
        Field::new("computer", DataType::Utf8, false),
        Field::new("event_data", DataType::Utf8, false),
    ]));

    let mut ts_b = StringBuilder::new();
    let mut ch_b = StringBuilder::new();
    let mut comp_b = StringBuilder::new();
    let mut pay_b = StringBuilder::new();
    for i in 0..record_ids.len() {
        ts_b.append_value(&timestamps[i]);
        ch_b.append_value(&channels[i]);
        comp_b.append_value(&computers[i]);
        pay_b.append_value(&payloads[i]);
    }

    Ok(RecordBatch::try_new(schema, vec![
        Arc::new(Int64Array::from(record_ids)),
        Arc::new(ts_b.finish()),
        Arc::new(Int64Array::from(event_ids)),
        Arc::new(Int64Array::from(levels)),
        Arc::new(ch_b.finish()),
        Arc::new(comp_b.finish()),
        Arc::new(pay_b.finish()),
    ])?)
}

pub fn parse_raw_lines_with_checkpoint(paths: &[PathBuf], mut ckpt: Option<&mut CheckpointStore>) -> Result<RecordBatch> {
    let fields = vec!["file".to_string(), "line_number".to_string(), "raw_line".to_string()];
    let mut rows = Vec::new();
    for path in paths {
        let fname = path.to_string_lossy().to_string();
        let reader = open_log_reader_with_checkpoint(path, &mut ckpt)?;
        for (idx, line_res) in reader.lines().enumerate() {
            rows.push(vec![fname.clone(), (idx + 1).to_string(), line_res?]);
        }
    }
    build_string_batch(&fields, &rows)
}

fn build_string_batch(field_names: &[String], rows: &[Vec<String>]) -> Result<RecordBatch> {
    let fields: Vec<Field> = field_names.iter().map(|name| Field::new(name, DataType::Utf8, true)).collect();
    let schema = Arc::new(Schema::new(fields));
    let mut builders: Vec<StringBuilder> = (0..field_names.len()).map(|_| StringBuilder::new()).collect();
    for row in rows {
        for (col_idx, val) in row.iter().enumerate() {
            if val == "-" || val.is_empty() { builders[col_idx].append_null(); }
            else { builders[col_idx].append_value(val); }
        }
    }
    let arrays: Vec<ArrayRef> = builders.into_iter().map(|mut b| Arc::new(b.finish()) as ArrayRef).collect();
    Ok(RecordBatch::try_new(schema, arrays)?)
}
EOF

cat << 'EOF' > src/engine.rs
use crate::checkpoint::CheckpointStore;
use crate::parsers::{
    detect_format, parse_aws_alb_files, parse_aws_s3_files, parse_aws_vpc_files,
    parse_azure_blob_files, parse_cef_files, parse_cisco_asa_files, parse_cisco_config_files,
    parse_evtx_files, parse_excel_files, parse_firewall_kv_files, parse_ias_files,
    parse_json_files, parse_nginx_files, parse_raw_lines_with_checkpoint, parse_regex_files,
    parse_syslog_files, parse_w3c_files, resolve_paths, InputFormat,
};
use crate::udfs::register_all_udfs;
use anyhow::Result;
use arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::*;
use regex::Regex;
use std::sync::Arc;

pub struct LogEngine {
    pub ctx: SessionContext,
}

impl LogEngine {
    pub fn new() -> Self {
        let config = SessionConfig::new().with_target_partitions(num_cpus());
        let ctx = SessionContext::new_with_config(config);
        register_all_udfs(&ctx);
        Self { ctx }
    }

    pub async fn register_source(&self, table_name: &str, path_pattern: &str, format: InputFormat, custom_regex: Option<&str>) -> Result<InputFormat> {
        self.register_source_with_checkpoint(table_name, path_pattern, format, custom_regex, None).await
    }

    pub async fn register_source_with_checkpoint(&self, table_name: &str, path_pattern: &str, format: InputFormat, custom_regex: Option<&str>, ckpt: Option<&mut CheckpointStore>) -> Result<InputFormat> {
        let paths = resolve_paths(path_pattern)?;
        let effective_format = if format == InputFormat::Auto { detect_format(&paths[0]) } else { format };

        match effective_format {
            InputFormat::Csv => { self.ctx.register_csv(table_name, path_pattern, CsvReadOptions::new()).await?; }
            InputFormat::Tsv => { self.ctx.register_csv(table_name, path_pattern, CsvReadOptions::new().delimiter(b'\t')).await?; }
            InputFormat::Excel => { let b = parse_excel_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Parquet => { self.ctx.register_parquet(table_name, path_pattern, ParquetReadOptions::default()).await?; }
            InputFormat::W3c => { let b = parse_w3c_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Json | InputFormat::Akamai | InputFormat::Gcp => { let b = parse_json_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Nginx => { let b = parse_nginx_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Syslog => { let b = parse_syslog_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Evtx => { let b = parse_evtx_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::FirewallKv => { let b = parse_firewall_kv_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::CiscoAsa => { let b = parse_cisco_asa_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::CiscoConfig => { let b = parse_cisco_config_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Cef => { let b = parse_cef_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Ias => { let b = parse_ias_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AwsS3 => { let b = parse_aws_s3_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AwsVpc => { let b = parse_aws_vpc_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AwsAlb => { let b = parse_aws_alb_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::AzureBlob => { let b = parse_azure_blob_files(&paths)?; self.register_batch(table_name, b)?; }
            InputFormat::Regex => {
                let pattern = custom_regex.ok_or_else(|| anyhow::anyhow!("--regex-pattern required for -i regex"))?;
                let re = Regex::new(pattern)?;
                let b = parse_regex_files(&paths, &re)?;
                self.register_batch(table_name, b)?;
            }
            InputFormat::Line | InputFormat::Auto => {
                let b = parse_raw_lines_with_checkpoint(&paths, ckpt)?;
                self.register_batch(table_name, b)?;
            }
        }
        Ok(effective_format)
    }

    fn register_batch(&self, table_name: &str, batch: RecordBatch) -> Result<()> {
        let schema = batch.schema();
        let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
        self.ctx.register_table(table_name, Arc::new(mem_table))?;
        Ok(())
    }

    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>> {
        let df = self.ctx.sql(sql).await?;
        let batches = df.collect().await?;
        Ok(batches)
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}
EOF

cat << 'EOF' > src/audit.rs
use crate::engine::LogEngine;
use crate::parsers::InputFormat;
use crate::sinks::batches_to_json_value;
use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct SecurityFinding {
    pub severity: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub matched_count: usize,
    pub remediation: &'static str,
    pub sample_evidence: String,
    pub rows: serde_json::Value,
}

pub struct AuditRule {
    pub severity: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub sql: &'static str,
    pub remediation: &'static str,
}

pub async fn evaluate_security_findings(path_pattern: &str, explicit_format: InputFormat) -> Result<(InputFormat, Vec<SecurityFinding>)> {
    let engine = LogEngine::new();
    let detected_fmt = engine.register_source("logs", path_pattern, explicit_format, None).await?;
    let rules = get_rules_for_format(detected_fmt);
    let mut findings = Vec::new();

    for rule in rules {
        if let Ok(batches) = engine.query(rule.sql).await {
            let count: usize = batches.iter().map(|b| b.num_rows()).sum();
            if count > 0 {
                let sample = pretty_format_batches(&batches).map(|s| s.to_string()).unwrap_or_default();
                let rows = batches_to_json_value(&batches).unwrap_or_default();
                findings.push(SecurityFinding {
                    severity: rule.severity,
                    category: rule.category,
                    title: rule.title,
                    matched_count: count,
                    remediation: rule.remediation,
                    sample_evidence: sample,
                    rows,
                });
            }
        }
    }
    Ok((detected_fmt, findings))
}

pub async fn run_automated_security_audit(path_pattern: &str, explicit_format: InputFormat, json_output: bool) -> Result<()> {
    let (fmt, findings) = evaluate_security_findings(path_pattern, explicit_format).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }

    println!("================================================================================");
    println!(" 🛡️  LPR AUTOMATED MULTI-CLOUD, NETWORK & LOG SECURITY AUDIT REPORT");
    println!(" 📁 Target: {} | Detected Profile: {:?}", path_pattern, fmt);
    println!("================================================================================\n");

    if findings.is_empty() {
        println!("✅ No security findings or policy violations triggered across audit rules.");
        return Ok(());
    }

    for (idx, f) in findings.iter().enumerate() {
        println!("[{}] {} | {} — {} ({} matches)", idx + 1, f.severity, f.category, f.title, f.matched_count);
        println!("    💡 Remediation: {}", f.remediation);
        for line in f.sample_evidence.lines() { println!("    {}", line); }
        println!();
    }
    Ok(())
}

fn get_rules_for_format(fmt: InputFormat) -> Vec<AuditRule> {
    match fmt {
        InputFormat::CiscoConfig => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "CISCO_ACL_ANY_ANY",
                title: "Overly Permissive Firewall Rule ('permit ip/tcp any any')",
                sql: "SELECT file, line_number, section, directive FROM logs WHERE LOWER(directive) LIKE '%permit ip any any%' OR LOWER(directive) LIKE '%permit tcp any any%'",
                remediation: "Restrict ACL rules to explicit source/destination subnets and required ports.",
            },
            AuditRule {
                severity: "CRITICAL",
                category: "CISCO_WEAK_SECRET",
                title: "Weak or Reversible Password Hash ('enable password' or Type 0/7)",
                sql: "SELECT file, line_number, directive FROM logs WHERE LOWER(directive) LIKE 'enable password%' OR LOWER(directive) LIKE '%password 7 %' OR LOWER(directive) LIKE '%password 0 %'",
                remediation: "Replace enable password and Type 7 passwords with enable secret (Type 8/9).",
            },
        ],
        InputFormat::AwsS3 => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "AWS_S3_EXPLOIT_OR_ACL",
                title: "Suspicious S3 Bucket ACL/Policy Modification or Exploit URI",
                sql: "SELECT remote_ip, requester, operation, key, http_status FROM logs WHERE operation LIKE '%ACL%' OR operation LIKE '%POLICY%' OR detect_threat(request_uri) != 'CLEAN' LIMIT 25",
                remediation: "Enable S3 Block Public Access and review IAM principals modifying bucket policies.",
            },
        ],
        InputFormat::Nginx => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "WEB_OWASP_PAYLOAD",
                title: "Exploit Payloads Detected in Request URI (SQLi / XSS / LFI / RCE / Log4Shell)",
                sql: "SELECT remote_addr, detect_threat(request_uri) AS threat_type, status, COUNT(*) AS attempts, MIN(request_uri) AS sample_uri FROM logs WHERE detect_threat(request_uri) != 'CLEAN' GROUP BY 1, 2, 3 ORDER BY attempts DESC LIMIT 20",
                remediation: "Block offending source IPs at WAF/Firewall and inspect any HTTP 200 responses.",
            },
        ],
        _ => vec![
            AuditRule {
                severity: "HIGH",
                category: "UNIVERSAL_THREAT_SCAN",
                title: "Exploit Signatures Detected in Log Lines",
                sql: "SELECT file, line_number, detect_threat(raw_line) AS threat, raw_line FROM logs WHERE detect_threat(raw_line) != 'CLEAN' LIMIT 25",
                remediation: "Investigate matching log lines for injection or command execution attempts.",
            },
        ],
    }
}
EOF

cat << 'EOF' > src/sinks.rs
use anyhow::Result;
use arrow::csv::WriterBuilder as CsvWriterBuilder;
use arrow::json::{ArrayWriter, LineDelimitedWriter};
use arrow::record_batch::RecordBatch;
use arrow::util::pretty::pretty_format_batches;
use clap::ValueEnum;
use parquet::arrow::ArrowWriter;
use std::fs::File;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Table, Json, Ndjson, Csv, Markdown, Parquet, Sql,
}

pub fn write_batches(batches: &[RecordBatch], format: OutputFormat, output_path: Option<&str>) -> Result<()> {
    if batches.is_empty() { return Ok(()); }
    if format == OutputFormat::Parquet {
        let path = output_path.unwrap_or("output.parquet");
        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, batches[0].schema(), None)?;
        for batch in batches { writer.write(batch)?; }
        writer.close()?;
        return Ok(());
    }

    let mut out: Box<dyn Write> = match output_path {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };

    match format {
        OutputFormat::Table => {
            let formatted = pretty_format_batches(batches)?;
            writeln!(out, "{}", formatted)?;
        }
        OutputFormat::Json => {
            let mut buf = Vec::new();
            {
                let mut writer = ArrayWriter::new(&mut buf);
                let refs: Vec<&RecordBatch> = batches.iter().collect();
                writer.write_batches(&refs)?;
                writer.finish()?;
            }
            out.write_all(&buf)?;
            writeln!(out)?;
        }
        OutputFormat::Ndjson => {
            let mut buf = Vec::new();
            {
                let mut writer = LineDelimitedWriter::new(&mut buf);
                let refs: Vec<&RecordBatch> = batches.iter().collect();
                writer.write_batches(&refs)?;
                writer.finish()?;
            }
            out.write_all(&buf)?;
        }
        OutputFormat::Csv => {
            let mut writer = CsvWriterBuilder::new().with_header(true).build(out);
            for batch in batches { writer.write(batch)?; }
        }
        OutputFormat::Markdown => {
            let schema = batches[0].schema();
            let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            writeln!(out, "| {} |", headers.join(" | "))?;
            let sep: Vec<&str> = headers.iter().map(|_| "---").collect();
            writeln!(out, "| {} |", sep.join(" | "))?;
            for batch in batches {
                for row_idx in 0..batch.num_rows() {
                    let mut cells = Vec::new();
                    for col_idx in 0..batch.num_columns() {
                        let col = batch.column(col_idx);
                        let val = arrow::util::display::array_value_to_string(col, row_idx).unwrap_or_default();
                        cells.push(val);
                    }
                    writeln!(out, "| {} |", cells.join(" | "))?;
                }
            }
        }
        OutputFormat::Sql => {
            let schema = batches[0].schema();
            let cols: Vec<String> = schema.fields().iter().map(|f| format!("\"{}\"", f.name())).collect();
            let col_defs: Vec<String> = schema.fields().iter().map(|f| format!("    \"{}\" TEXT", f.name())).collect();
            writeln!(out, "CREATE TABLE IF NOT EXISTS lpr_export (\n{}\n);", col_defs.join(",\n"))?;
            for batch in batches {
                for row_idx in 0..batch.num_rows() {
                    let mut vals = Vec::new();
                    for col_idx in 0..batch.num_columns() {
                        let col = batch.column(col_idx);
                        if col.is_null(row_idx) { vals.push("NULL".to_string()); }
                        else {
                            let val = arrow::util::display::array_value_to_string(col, row_idx).unwrap_or_default().replace('\'', "''");
                            vals.push(format!("'{}'", val));
                        }
                    }
                    writeln!(out, "INSERT INTO lpr_export ({}) VALUES ({});", cols.join(", "), vals.join(", "))?;
                }
            }
        }
        OutputFormat::Parquet => unreachable!(),
    }
    Ok(())
}

pub fn batches_to_json_value(batches: &[RecordBatch]) -> Result<serde_json::Value> {
    if batches.is_empty() { return Ok(serde_json::json!([])); }
    let mut buf = Vec::new();
    {
        let mut writer = ArrayWriter::new(&mut buf);
        let refs: Vec<&RecordBatch> = batches.iter().collect();
        writer.write_batches(&refs)?;
        writer.finish()?;
    }
    let val: serde_json::Value = serde_json::from_slice(&buf)?;
    Ok(val)
}
EOF

cat << 'EOF' > src/hooks.rs
use crate::sinks::batches_to_json_value;
use anyhow::Result;
use arrow::record_batch::RecordBatch;
use std::io::Write;
use std::process::{Command, Stdio};

pub struct HookConfig {
    pub webhook_url: Option<String>,
    pub exec_command: Option<String>,
    pub min_rows: usize,
}

pub async fn evaluate_and_fire_hooks(batches: &[RecordBatch], config: &HookConfig) -> Result<()> {
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    if total_rows < config.min_rows || total_rows == 0 { return Ok(()); }
    let rows_json = batches_to_json_value(batches)?;
    let payload = serde_json::json!({
        "event": "lpr_query_match",
        "matched_rows": total_rows,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "results": rows_json,
    });

    if let Some(url) = &config.webhook_url {
        let client = reqwest::Client::new();
        let res = client.post(url).json(&payload).send().await?;
        eprintln!("[HOOK] Fired webhook to {} (rows={}, status={})", url, total_rows, res.status());
    }

    if let Some(cmd_str) = &config.exec_command {
        let shell = if cfg!(target_os = "windows") { ("powershell", "-Command") } else { ("sh", "-c") };
        let mut child = Command::new(shell.0).arg(shell.1).arg(cmd_str).env("LPR_MATCH_COUNT", total_rows.to_string()).stdin(Stdio::piped()).spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let bytes = serde_json::to_vec(&payload)?;
            stdin.write_all(&bytes)?;
        }
        let status = child.wait()?;
        eprintln!("[HOOK] Executed command `{}` (exit={})", cmd_str, status);
    }
    Ok(())
}
EOF

cat << 'EOF' > src/ui.html
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <title>lpr Studio</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background: #0b0f19; color: #e2e8f0; font-family: ui-sans-serif, system-ui, sans-serif; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body class="min-h-screen flex flex-col p-6 space-y-4">
  <header class="flex items-center justify-between border-b border-slate-800 pb-3">
    <div class="flex items-center gap-3">
      <span class="px-2.5 py-1 rounded bg-indigo-600 text-xs font-bold uppercase">lpr Studio v1.0</span>
      <h1 class="text-lg font-semibold text-white">Log Parser & Security Auditor</h1>
    </div>
  </header>
  <div class="space-y-3">
    <input id="source" type="text" placeholder="/path/to/log.log" class="w-full px-3 py-2 rounded bg-slate-950 border border-slate-700 text-sm mono" />
    <textarea id="sql" rows="3" class="w-full p-3 rounded bg-slate-950 border border-slate-700 text-sm mono text-emerald-300">SELECT * FROM logs LIMIT 50</textarea>
    <button onclick="runQuery()" class="px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-500 font-semibold text-white text-xs">Run Query</button>
  </div>
  <div class="overflow-auto max-h-[60vh] border border-slate-800 rounded bg-slate-900">
    <table class="w-full text-left text-xs mono" id="result-table"></table>
  </div>
  <script>
    async function runQuery() {
      const sql = document.getElementById('sql').value;
      const source = document.getElementById('source').value;
      const res = await fetch('/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql, source })
      });
      const payload = await res.json();
      const t = document.getElementById('result-table');
      t.innerHTML = '';
      if (!payload.data || !payload.data.length) return;
      const cols = Object.keys(payload.data[0]);
      t.innerHTML = '<thead class="bg-slate-950"><tr>' + cols.map(c => '<th class="p-2 border-b border-slate-800">' + c + '</th>').join('') + '</tr></thead>' +
        '<tbody>' + payload.data.map(r => '<tr class="border-b border-slate-800/40">' + cols.map(c => '<td class="p-2 truncate max-w-xs">' + (r[c] ?? '') + '</td>').join('') + '</tr>').join('') + '</tbody>';
    }
  </script>
</body>
</html>
EOF

cat << 'EOF' > src/server.rs
use crate::audit::evaluate_security_findings;
use crate::engine::LogEngine;
use crate::parsers::InputFormat;
use crate::sinks::batches_to_json_value;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct AppState {
    pub total_queries: AtomicU64,
    pub default_source: Option<String>,
}

#[derive(Deserialize)]
pub struct QueryRequest {
    pub sql: String,
    pub source: Option<String>,
    pub format: Option<String>,
}

#[derive(Deserialize)]
pub struct AuditRequest {
    pub source: Option<String>,
    pub format: Option<String>,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub row_count: usize,
    pub execution_time_ms: u128,
    pub data: serde_json::Value,
}

pub async fn run_http_server(bind_addr: &str, default_source: Option<String>) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        total_queries: AtomicU64::new(0),
        default_source,
    });

    let app = Router::new()
        .route("/", get(serve_web_ui))
        .route("/v1/info", get(handle_info))
        .route("/v1/query", post(handle_query))
        .route("/v1/audit", post(handle_audit))
        .route("/metrics", get(handle_metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    eprintln!("🚀 lpr Studio listening on http://{}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_web_ui() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

pub fn parse_format_str(s: Option<&str>) -> InputFormat {
    match s {
        Some("w3c") => InputFormat::W3c,
        Some("json") => InputFormat::Json,
        Some("csv") => InputFormat::Csv,
        Some("tsv") => InputFormat::Tsv,
        Some("excel") => InputFormat::Excel,
        Some("parquet") => InputFormat::Parquet,
        Some("nginx") => InputFormat::Nginx,
        Some("syslog") => InputFormat::Syslog,
        Some("evtx") => InputFormat::Evtx,
        Some("firewall-kv") => InputFormat::FirewallKv,
        Some("cisco-asa") => InputFormat::CiscoAsa,
        Some("cisco-config") => InputFormat::CiscoConfig,
        Some("cef") => InputFormat::Cef,
        Some("ias") => InputFormat::Ias,
        Some("akamai") => InputFormat::Akamai,
        Some("aws-s3") => InputFormat::AwsS3,
        Some("aws-vpc") => InputFormat::AwsVpc,
        Some("aws-alb") => InputFormat::AwsAlb,
        Some("azure-blob") => InputFormat::AzureBlob,
        Some("gcp") => InputFormat::Gcp,
        Some("line") => InputFormat::Line,
        _ => InputFormat::Auto,
    }
}

async fn handle_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let samples = vec![
        "samples/nginx_access.log",
        "samples/firewall.log",
        "samples/cisco_switch.cfg",
        "samples/cloud_events.json",
    ];
    Json(serde_json::json!({
        "version": "1.0.0",
        "default_source": state.default_source.clone(),
        "samples": samples,
    }))
}

async fn handle_query(State(state): State<Arc<AppState>>, Json(req): Json<QueryRequest>) -> impl IntoResponse {
    state.total_queries.fetch_add(1, Ordering::Relaxed);
    let start = std::time::Instant::now();
    let engine = LogEngine::new();
    let src = req.source.or_else(|| state.default_source.clone());
    if let Some(path) = src {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let fmt = parse_format_str(req.format.as_deref());
            if let Err(e) = engine.register_source("logs", trimmed, fmt, None).await {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }

    match engine.query(&req.sql).await {
        Ok(batches) => {
            let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();
            let data = batches_to_json_value(&batches).unwrap_or_default();
            let execution_time_ms = start.elapsed().as_millis();
            (StatusCode::OK, Json(serde_json::to_value(QueryResponse { row_count, execution_time_ms, data }).unwrap()))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

async fn handle_audit(State(state): State<Arc<AppState>>, Json(req): Json<AuditRequest>) -> impl IntoResponse {
    let src = match req.source.or_else(|| state.default_source.clone()) {
        Some(s) if !s.trim().is_empty() => s,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Provide a file or glob path" }))),
    };
    let fmt = parse_format_str(req.format.as_deref());
    match evaluate_security_findings(src.trim(), fmt).await {
        Ok((detected, findings)) => (StatusCode::OK, Json(serde_json::json!({ "detected_format": format!("{:?}", detected), "findings": findings }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

async fn handle_metrics(State(state): State<Arc<AppState>>) -> String {
    let count = state.total_queries.load(Ordering::Relaxed);
    format!("# HELP lpr_queries_total Total log queries\n# TYPE lpr_queries_total counter\nlpr_queries_total {}\n", count)
}
EOF

cat << 'EOF' > src/gui.rs
use anyhow::Result;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn launch_native_desktop_gui(default_source: Option<String>) -> Result<()> {
    use tao::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    };
    use wry::WebViewBuilder;

    let bind_addr = "127.0.0.1:18765";
    let url = format!("http://{}", bind_addr);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = rt.block_on(crate::server::run_http_server(bind_addr, default_source));
    });

    std::thread::sleep(std::time::Duration::from_millis(200));

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("lpr Studio")
        .with_inner_size(tao::dpi::LogicalSize::new(1360.0, 860.0))
        .build(&event_loop)?;

    let _webview = WebViewBuilder::new(&window).with_url(&url).build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = event {
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn launch_native_desktop_gui(_default_source: Option<String>) -> Result<()> {
    anyhow::bail!("Native desktop GUI is only supported on macOS, Windows, and Linux")
}
EOF

cat << 'EOF' > src/tui.rs
use crate::engine::LogEngine;
use crate::parsers::InputFormat;
use anyhow::Result;
use arrow::util::display::array_value_to_string;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::io;

pub async fn run_tui(source_path: &str, format: InputFormat) -> Result<()> {
    let engine = LogEngine::new();
    engine.register_source("logs", source_path, format, None).await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut sql_input = String::from("SELECT * FROM logs LIMIT 50");
    let mut status_msg = format!("Loaded `{}` | Enter=Run, Esc=Quit", source_path);
    let mut headers: Vec<String> = Vec::new();
    let mut table_rows: Vec<Vec<String>> = Vec::new();

    if let Ok(batches) = engine.query(&sql_input).await {
        extract_grid(&batches, &mut headers, &mut table_rows);
    }

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3)])
                .split(f.area());

            let query_box = Paragraph::new(sql_input.as_str())
                .style(Style::default().fg(Color::LightGreen))
                .block(Block::default().borders(Borders::ALL).title(" SQL Query (Enter=Execute, Esc=Quit) "));
            f.render_widget(query_box, chunks[0]);

            let header_cells = headers.iter().map(|h| Cell::from(h.as_str()).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells).height(1).bottom_margin(1);
            let rows = table_rows.iter().map(|r| Row::new(r.iter().map(|c| Cell::from(c.as_str()))).height(1));
            let widths: Vec<Constraint> = (0..headers.len().max(1)).map(|_| Constraint::Percentage((100 / headers.len().max(1)) as u16)).collect();

            let table = Table::new(rows, widths).header(header).block(Block::default().borders(Borders::ALL).title(" Results "));
            f.render_widget(table, chunks[1]);

            let status_bar = Paragraph::new(status_msg.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Status "));
            f.render_widget(status_bar, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Enter => match engine.query(&sql_input).await {
                        Ok(batches) => {
                            extract_grid(&batches, &mut headers, &mut table_rows);
                            status_msg = format!("Returned {} rows", table_rows.len());
                        }
                        Err(e) => { status_msg = format!("SQL Error: {}", e); }
                    },
                    KeyCode::Backspace => { sql_input.pop(); }
                    KeyCode::Char(c) => { sql_input.push(c); }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn extract_grid(batches: &[arrow::record_batch::RecordBatch], headers: &mut Vec<String>, rows: &mut Vec<Vec<String>>) {
    headers.clear();
    rows.clear();
    if let Some(first) = batches.first() {
        *headers = first.schema().fields().iter().map(|f| f.name().clone()).collect();
        for batch in batches {
            for r in 0..batch.num_rows() {
                let mut row_vec = Vec::new();
                for c in 0..batch.num_columns() {
                    let val = array_value_to_string(batch.column(c), r).unwrap_or_default();
                    row_vec.push(val);
                }
                rows.push(row_vec);
            }
        }
    }
}
EOF

cat << 'EOF' > src/mcp.rs
use crate::audit::evaluate_security_findings;
use crate::engine::LogEngine;
use crate::server::parse_format_str;
use crate::sinks::batches_to_json_value;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

pub async fn run_mcp_stdio_server() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let line = line_res?;
        if line.trim().is_empty() { continue; }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "lpr-mcp", "version": "1.0.0" }
                }
            }),
            "notifications/initialized" => continue,
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "query_logs",
                            "description": "Execute ANSI SQL against logs (W3C/IIS, JSON, AWS S3/VPC, Azure Blob, Cisco Config/ASA, FortiGate, Excel, CSV, Parquet, EVTX). UDFs: detect_threat(col), cluster_template(col), ip_in_cidr(ip, cidr), shannon_entropy(col).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string" },
                                    "sql": { "type": "string" },
                                    "format": { "type": "string" }
                                },
                                "required": ["path", "sql"]
                            }
                        },
                        {
                            "name": "audit_logs",
                            "description": "Run automated security audit against logs or Cisco configs.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string" },
                                    "format": { "type": "string" }
                                },
                                "required": ["path"]
                            }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let params = &req["params"];
                let tool_name = params["name"].as_str().unwrap_or("");
                let args = &params["arguments"];
                let tool_output = handle_mcp_tool(tool_name, args).await;
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": tool_output }] }
                })
            }
            _ => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Method not found" } }),
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }
    Ok(())
}

async fn handle_mcp_tool(name: &str, args: &Value) -> String {
    let path = args["path"].as_str().unwrap_or("");
    let fmt = parse_format_str(args["format"].as_str());

    if name == "audit_logs" {
        return match evaluate_security_findings(path, fmt).await {
            Ok((detected, findings)) => serde_json::to_string_pretty(&json!({ "detected_format": format!("{:?}", detected), "findings": findings })).unwrap_or_default(),
            Err(e) => format!("Audit Error: {}", e),
        };
    }

    let engine = LogEngine::new();
    if let Err(e) = engine.register_source("logs", path, fmt, None).await {
        return format!("Error loading log source `{}`: {}", path, e);
    }

    let sql = args["sql"].as_str().unwrap_or("SELECT * FROM logs LIMIT 25");
    match engine.query(sql).await {
        Ok(batches) => batches_to_json_value(&batches).map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default(),
        Err(e) => format!("SQL Execution Error: {}", e),
    }
}
EOF

cat << 'EOF' > src/main.rs
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
#[command(name = "lpr", version = "1.0.0", about = "Modern Rust SQL Log Parser & Security Auditor")]
struct Cli {
    #[arg(value_name = "SQL_QUERY")]
    query: Option<String>,
    #[arg(short = 'f', long = "file", value_name = "PATH_OR_GLOB")]
    file: Option<String>,
    #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
    input_format: InputFormat,
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Table)]
    output_format: OutputFormat,
    #[arg(long = "out-file")]
    out_file: Option<String>,
    #[arg(long = "checkpoint", value_name = "STATE_FILE_JSON")]
    checkpoint: Option<String>,
    #[arg(long = "regex-pattern")]
    regex_pattern: Option<String>,
    #[arg(long = "join", value_name = "NAME=PATH")]
    joins: Vec<String>,
    #[arg(long = "hook-url")]
    hook_url: Option<String>,
    #[arg(long = "hook-exec")]
    hook_exec: Option<String>,
    #[arg(long = "hook-min-rows", default_value_t = 1)]
    hook_min_rows: usize,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Audit {
        #[arg(short = 'f', long = "file")]
        file: String,
        #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
        input_format: InputFormat,
        #[arg(long)]
        json: bool,
    },
    Gui {
        #[arg(long)]
        source: Option<String>,
    },
    Tui {
        #[arg(short = 'f', long = "file")]
        file: String,
        #[arg(short = 'i', long = "input", value_enum, default_value_t = InputFormat::Auto)]
        input_format: InputFormat,
    },
    Mcp,
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        #[arg(long)]
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
EOF

cat << 'EOF' > tests/smoke_test.sh
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
EOF
chmod +x tests/smoke_test.sh

echo "🎉 All files created successfully in $(pwd)!"
