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
