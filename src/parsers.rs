use crate::sym::*;
use crate::checkpoint::CheckpointStore;
use anyhow::{Context, Result};
use arrow::array::{ArrayRef, Int64Array, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use calamine::{open_workbook_auto, Data, Reader};
use clap::ValueEnum;
use evtx::EvtxParser;
use flate2::read::GzDecoder;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

static STDIN_CACHE: LazyLock<Mutex<Option<Vec<u8>>>> = LazyLock::new(|| Mutex::new(None));

pub fn is_stdin_path(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed == "-" || trimmed.eq_ignore_ascii_case("stdin") || trimmed == "/dev/stdin"
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Serialize)]
pub enum InputFormat {
    Auto,
    #[value(alias = "iis", alias = "iisw3c", alias = "w3c", alias = "smtp", alias = "iissmtp", alias = "smtpsvc")]
    W3c,
    #[value(alias = "ndjson", alias = "jsonl")]
    Json,
    Csv,
    Tsv,
    #[value(alias = "xlsx", alias = "xls")]
    Excel,
    Parquet,
    #[value(alias = "apache", alias = "ncsa")]
    Nginx,
    Syslog,
    #[value(alias = "evt")]
    Evtx,
    #[value(alias = "fortigate", alias = "kv")]
    FirewallKv,
    #[value(alias = "asa")]
    CiscoAsa,
    #[value(alias = "cisco", alias = "cfg")]
    CiscoConfig,
    Cef,
    Ias,
    Akamai,
    #[value(alias = "s3")]
    AwsS3,
    #[value(alias = "vpc")]
    AwsVpc,
    #[value(alias = "alb")]
    AwsAlb,
    #[value(alias = "azure")]
    AzureBlob,
    Gcp,
    Regex,
    #[value(alias = "textline", alias = "raw")]
    Line,
}

#[derive(Debug, Clone)]
pub enum LogSourceItem {
    DiskFile(PathBuf),
    ZipEntry {
        archive_path: PathBuf,
        entry_index: usize,
        entry_name: String,
        uncompressed_size: u64,
    },
    Stdin,
}

impl LogSourceItem {
    pub fn display_name(&self) -> String {
        match self {
            Self::DiskFile(p) => p.to_string_lossy().to_string(),
            Self::ZipEntry {
                archive_path,
                entry_name,
                ..
            } => format!("{}::{}", archive_path.to_string_lossy(), entry_name),
            Self::Stdin => "stdin".to_string(),
        }
    }

    pub fn short_filename(&self) -> String {
        match self {
            Self::DiskFile(p) => p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| p.to_string_lossy().to_string()),
            Self::ZipEntry { entry_name, .. } => Path::new(entry_name)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry_name.clone()),
            Self::Stdin => "stdin".to_string(),
        }
    }

    pub fn size_bytes(&self) -> u64 {
        match self {
            Self::DiskFile(p) => std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
            Self::ZipEntry {
                uncompressed_size, ..
            } => *uncompressed_size,
            Self::Stdin => 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ParseStats {
    pub files_processed: usize,
    pub total_lines: usize,
    pub total_rows: usize,
    pub total_bytes: u64,
    pub file_summaries: Vec<FileParseSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileParseSummary {
    pub name: String,
    pub lines: usize,
    pub rows: usize,
    pub bytes: u64,
    pub elapsed_ms: u128,
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
static W3C_DATA_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+").unwrap()
});

pub fn resolve_paths(pattern: &str) -> Result<Vec<PathBuf>> {
    if is_stdin_path(pattern) {
        return Ok(vec![PathBuf::from("-")]);
    }
    let mut paths = Vec::new();
    // Support comma- or semicolon-separated lists of files/globs/directories (Log Parser 2.2 style: FROM 'file1.log', 'file2.log' or -f "dir1;dir2")
    let sub_patterns: Vec<&str> = if pattern.contains(';') || pattern.contains(',') {
        pattern
            .split([';', ','])
            .map(|s| s.trim().trim_matches(['\'', '"']))
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![pattern.trim().trim_matches(['\'', '"'])]
    };

    for sub in sub_patterns {
        if sub.contains('*') || sub.contains('?') {
            if let Ok(entries) = glob::glob(sub) {
                for entry in entries.flatten() {
                    if entry.is_file() {
                        paths.push(entry);
                    }
                }
            }
        } else {
            let p = PathBuf::from(sub);
            if p.is_dir() {
                collect_files_recursive(&p, &mut paths);
            } else if p.exists() {
                paths.push(p);
            }
        }
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        anyhow::bail!("No log files matched pattern: {}", pattern);
    }
    Ok(paths)
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let ep = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            if ep.is_dir() {
                collect_files_recursive(&ep, out);
            } else if ep.is_file() {
                out.push(ep);
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanPreFilter {
    pub min_date: Option<String>,
    pub min_time: Option<String>,
    pub status_prefix: Option<String>,
    /// Case-insensitive ASCII substrings that MUST ALL appear in the raw log line.
    pub required_substrings: Vec<String>,
    /// Case-insensitive ASCII substrings where AT LEAST ONE must appear in the raw log line (if non-empty).
    pub any_substrings: Vec<String>,
}

static SQL_JOIN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bJOIN\b").unwrap());
static SQL_WHERE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)\bWHERE\b\s+(.*?)(?:\bGROUP\s+BY\b|\bORDER\s+BY\b|\bLIMIT\b|\bHAVING\b|\bUNION\b|\bINTO\b|;|$)").unwrap()
});
static SQL_STATUS_EQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?i)\s*(?:[a-zA-Z0-9_]+\.)?\[?(?:sc_status|sc-status|status)\]?\s*(?:=\s*'(\d{1,3})'|I?LIKE\s*'(\d{1,3})%?')\s*$").unwrap()
});
static SQL_COL_LIKE_EQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?i)\s*(?:(?:LOWER|UPPER|TRIM)\s*\(\s*)?(?:[a-zA-Z0-9_]+\.)?\[?([a-zA-Z0-9_()-]+)\]?\s*\)?\s*(?:I?LIKE|=)\s*'([^']+)'\s*$").unwrap()
});
static SQL_NEGATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bNOT\b|!=|<>|\bIS\s+NULL\b|\bCOALESCE\b").unwrap()
});

/// Extracts safe, zero-false-negative row-level pre-filter hints (`status_prefix`, `required_substrings`, `any_substrings`)
/// from a SQL query's `WHERE` clause so lines that cannot possibly match are skipped at the raw byte level
/// BEFORE UTF-8 decoding, whitespace splitting, or Arrow StringBuilder allocation.
pub fn extract_sql_pre_filter(sql: &str) -> ScanPreFilter {
    let mut filter = ScanPreFilter::default();
    if SQL_JOIN_RE.is_match(sql) {
        return filter;
    }
    let Some(caps) = SQL_WHERE_RE.captures(sql) else {
        return filter;
    };
    let where_body = caps[1].trim();
    if where_body.is_empty() {
        return filter;
    }

    for raw_conj in split_top_level_sql_keyword(where_body, "AND") {
        let conj = strip_outer_sql_parens(raw_conj.trim());
        if conj.is_empty() {
            continue;
        }
        let or_branches = split_top_level_sql_keyword(conj, "OR");
        if or_branches.len() == 1 {
            if SQL_NEGATION_RE.is_match(conj) {
                continue;
            }
            if let Some(sc) = SQL_STATUS_EQ_RE.captures(conj) {
                if let Some(m) = sc.get(1).or_else(|| sc.get(2)) {
                    filter.status_prefix = Some(m.as_str().to_string());
                }
            }
            for seg in extract_positive_like_substrings(conj) {
                let lower = seg.to_ascii_lowercase();
                if !filter.required_substrings.contains(&lower) {
                    filter.required_substrings.push(lower);
                }
            }
        } else {
            // Multiple OR branches: if EVERY branch is a positive LIKE/= predicate on a data column,
            // then at least one branch's required substring must appear in the raw line!
            let mut branch_needles: Vec<String> = Vec::new();
            let mut all_valid = true;
            for br in or_branches {
                let b_clean = strip_outer_sql_parens(br.trim());
                if SQL_NEGATION_RE.is_match(b_clean) {
                    all_valid = false;
                    break;
                }
                let mut segs = extract_positive_like_substrings(b_clean);
                // Pick the longest literal segment for this OR branch
                segs.sort_by(|a, b| b.len().cmp(&a.len()));
                if let Some(best) = segs.into_iter().next() {
                    let lower = best.to_ascii_lowercase();
                    if !branch_needles.contains(&lower) {
                        branch_needles.push(lower);
                    }
                } else {
                    all_valid = false;
                    break;
                }
            }
            if all_valid && !branch_needles.is_empty() {
                if branch_needles.len() == 1 {
                    let only = branch_needles.remove(0);
                    if !filter.required_substrings.contains(&only) {
                        filter.required_substrings.push(only);
                    }
                } else if filter.any_substrings.is_empty() {
                    filter.any_substrings = branch_needles;
                }
            }
        }
    }

    filter
}

fn extract_positive_like_substrings(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(caps) = SQL_COL_LIKE_EQ_RE.captures(expr) {
        let col = caps[1].to_ascii_lowercase();
        if matches!(
            col.as_str(),
            "log_filename" | "logfilename" | "log_row" | "logrow" | "file" | "line_number" | "index"
        ) {
            return out;
        }
        let pat = &caps[2];
        for seg in pat.split(['%', '_']) {
            if seg.len() >= 2 && seg.is_ascii() {
                out.push(seg.to_string());
            }
        }
    }
    out
}

fn strip_outer_sql_parens(mut s: &str) -> &str {
    loop {
        let trimmed = s.trim();
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            let bytes = trimmed.as_bytes();
            let mut depth = 0i32;
            let mut in_single = false;
            let mut wraps_all = true;
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'\'' {
                    in_single = !in_single;
                } else if !in_single {
                    if b == b'(' {
                        depth += 1;
                    } else if b == b')' {
                        depth -= 1;
                        if depth == 0 && i + 1 < bytes.len() {
                            wraps_all = false;
                            break;
                        }
                    }
                }
            }
            if wraps_all && depth == 0 {
                s = &trimmed[1..trimmed.len() - 1];
                continue;
            }
        }
        return trimmed;
    }
}

fn split_top_level_sql_keyword<'a>(s: &'a str, kw: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
    let kw_bytes = kw.as_bytes();
    let kw_len = kw_bytes.len();
    let mut depth = 0i32;
    let mut in_single = false;
    let mut last_start = 0;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth = (depth - 1).max(0);
            } else if depth == 0 && i + kw_len <= bytes.len() {
                let prev_ok = i == 0 || bytes[i - 1].is_ascii_whitespace() || bytes[i - 1] == b')';
                let next_ok = i + kw_len == bytes.len()
                    || bytes[i + kw_len].is_ascii_whitespace()
                    || bytes[i + kw_len] == b'(';
                if prev_ok && next_ok && bytes[i..i + kw_len].eq_ignore_ascii_case(kw_bytes) {
                    parts.push(&s[last_start..i]);
                    i += kw_len;
                    last_start = i;
                    continue;
                }
            }
        }
        i += 1;
    }
    parts.push(&s[last_start..]);
    parts
}

#[inline(always)]
pub fn contains_ascii_ci_prelowered(haystack: &[u8], needle_lower: &[u8]) -> bool {
    let n_len = needle_lower.len();
    if n_len == 0 {
        return true;
    }
    let h_len = haystack.len();
    if h_len < n_len {
        return false;
    }
    let first_lo = needle_lower[0];
    let first_hi = first_lo.to_ascii_uppercase();
    let max_i = h_len - n_len;

    if n_len == 1 {
        return haystack.iter().any(|&b| b == first_lo || b == first_hi);
    }

    let second_lo = needle_lower[1];
    let second_hi = second_lo.to_ascii_uppercase();
    let rest = &needle_lower[2..];

    let mut i = 0;
    if first_lo == first_hi {
        while i <= max_i {
            if let Some(rel) = haystack[i..=max_i].iter().position(|&b| b == first_lo) {
                i += rel;
                let b1 = haystack[i + 1];
                if (b1 == second_lo || b1 == second_hi)
                    && eq_ascii_ci_lowered(&haystack[i + 2..i + n_len], rest)
                {
                    return true;
                }
                i += 1;
            } else {
                return false;
            }
        }
        false
    } else {
        while i <= max_i {
            let b0 = haystack[i];
            if b0 == first_lo || b0 == first_hi {
                let b1 = haystack[i + 1];
                if (b1 == second_lo || b1 == second_hi)
                    && eq_ascii_ci_lowered(&haystack[i + 2..i + n_len], rest)
                {
                    return true;
                }
            }
            i += 1;
        }
        false
    }
}

#[inline(always)]
fn eq_ascii_ci_lowered(slice: &[u8], needle_lower: &[u8]) -> bool {
    for idx in 0..needle_lower.len() {
        if slice[idx].to_ascii_lowercase() != needle_lower[idx] {
            return false;
        }
    }
    true
}

#[inline(always)]
pub fn matches_raw_line_needles(
    slice: &[u8],
    req_needles_lower: &[Vec<u8>],
    any_needles_lower: &[Vec<u8>],
) -> bool {
    for req in req_needles_lower {
        if !contains_ascii_ci_prelowered(slice, req) {
            return false;
        }
    }
    if !any_needles_lower.is_empty()
        && !any_needles_lower
            .iter()
            .any(|n| contains_ascii_ci_prelowered(slice, n))
    {
        return false;
    }
    true
}

static RE_IIS_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)u_(?:ex|in)(\d{2})(\d{2})(\d{2})(\d{2})?").unwrap());
static RE_ISO_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"((?:19|20)\d{2})-(\d{2})-(\d{2})").unwrap());
static RE_COMPACT_YYYYMMDD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9])((?:19|20)\d{2})(\d{2})(\d{2})(?:[^0-9]|$)").unwrap()
});

fn max_zip_entry_bytes() -> u64 {
    std::env::var("LPR_MAX_ENTRY_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(512 * 1024 * 1024)
}

/// Expands any `.zip` archives in `paths` into individual `LogSourceItem::ZipEntry` items
/// so that all entries inside a `.zip` can be decompressed and parsed in parallel across threads!
pub fn resolve_source_items(pattern: &str) -> Result<Vec<LogSourceItem>> {
    resolve_source_items_with_cutoff(pattern, None)
}

pub fn resolve_source_items_with_cutoff(
    pattern: &str,
    cutoff: Option<chrono::NaiveDate>,
) -> Result<Vec<LogSourceItem>> {
    if is_stdin_path(pattern) {
        return Ok(vec![LogSourceItem::Stdin]);
    }
    let paths = resolve_paths(pattern)?;
    let mtime_grace = cutoff.map(|c| c - chrono::Duration::days(1));
    let mut items = Vec::new();
    for path in paths {
        if let Some(c) = cutoff {
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if let Some(d) = filename_embedded_date(fname) {
                if d < c {
                    continue;
                }
            } else if let Some(grace) = mtime_grace {
                let keep = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.date_naive() >= grace
                    })
                    .unwrap_or(true);
                if !keep {
                    continue;
                }
            }
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "zip" {
            let Ok(file) = File::open(&path) else {
                continue;
            };
            let Ok(mut archive) = zip::ZipArchive::new(BufReader::new(file)) else {
                continue;
            };
            for idx in 0..archive.len() {
                if let Ok(entry) = archive.by_index_raw(idx) {
                    if entry.is_file() && !entry.name().starts_with("__MACOSX") {
                        if let Some(c) = cutoff {
                            if let Some(d) = filename_embedded_date(entry.name()) {
                                if d < c {
                                    continue;
                                }
                            } else if let Some(dt) = entry.last_modified() {
                                if let Some(nd) = chrono::NaiveDate::from_ymd_opt(
                                    dt.year() as i32,
                                    dt.month() as u32,
                                    dt.day() as u32,
                                ) {
                                    if nd < c {
                                        continue;
                                    }
                                }
                            }
                        }
                        items.push(LogSourceItem::ZipEntry {
                            archive_path: path.clone(),
                            entry_index: idx,
                            entry_name: entry.name().to_string(),
                            uncompressed_size: entry.size(),
                        });
                    }
                }
            }
        } else {
            items.push(LogSourceItem::DiskFile(path));
        }
    }
    if items.is_empty() {
        anyhow::bail!("No log files or ZIP archive entries matched: {}", pattern);
    }
    Ok(items)
}

/// Extracts a calendar date embedded in a log filename, e.g.
/// `u_ex251014.log` (IIS W3C daily), `u_ex25101400.log` (hourly), `access-2026-10-14.log`,
/// `error.20261014.log`. Does NOT misinterpret IIS size-rollover sequence numbers (`u_extend22.log`,
/// `u_extend100512.log`) as dates.
fn filename_embedded_date(name: &str) -> Option<chrono::NaiveDate> {
    let stem = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // 1. IIS daily/hourly u_exYYMMDD(HH) / u_inYYMMDD
    if let Some(cap) = RE_IIS_DATE.captures_iter(stem).last() {
        let yy: i32 = cap[1].parse().unwrap_or(0);
        let year = if yy < 70 { 2000 + yy } else { 1900 + yy };
        if let (Ok(mo), Ok(d)) = (cap[2].parse::<u32>(), cap[3].parse::<u32>()) {
            if let Some(dt) = chrono::NaiveDate::from_ymd_opt(year, mo, d) {
                return Some(dt);
            }
        }
    }
    // 2. Explicit 4-digit year dates: YYYY-MM-DD or YYYYMMDD
    let mut found = None;
    for re in [&*RE_ISO_DATE, &*RE_COMPACT_YYYYMMDD] {
        for cap in re.captures_iter(stem) {
            let y: i32 = cap[1].parse().unwrap_or(0);
            let mo: u32 = cap[2].parse().unwrap_or(0);
            let d: u32 = cap[3].parse().unwrap_or(0);
            if let Some(dt) = chrono::NaiveDate::from_ymd_opt(y, mo, d) {
                found = Some(dt);
            }
        }
    }
    found
}

/// Drops log files/zip entries that provably contain no rows on/after `cutoff`
/// (IIS-style filename date or filesystem modified time). Items whose date
/// can't be determined are kept. Prevents multi-GB scans of old rotated logs.
pub fn filter_items_by_min_date(
    items: Vec<LogSourceItem>,
    cutoff: chrono::NaiveDate,
) -> Vec<LogSourceItem> {
    let mtime_grace = cutoff - chrono::Duration::days(1);
    items
        .into_iter()
        .filter(|item| {
            let name = item.display_name();
            if let Some(d) = filename_embedded_date(&name) {
                return d >= cutoff;
            }
            match item {
                LogSourceItem::DiskFile(p) => std::fs::metadata(p)
                    .and_then(|m| m.modified())
                    .map(|t| {
                        let t: chrono::DateTime<chrono::Utc> = t.into();
                        t.date_naive() >= mtime_grace
                    })
                    .unwrap_or(true),
                LogSourceItem::ZipEntry { archive_path, .. } => std::fs::metadata(archive_path)
                    .and_then(|m| m.modified())
                    .map(|t| {
                        let t: chrono::DateTime<chrono::Utc> = t.into();
                        t.date_naive() >= mtime_grace
                    })
                    .unwrap_or(true),
                LogSourceItem::Stdin => true,
            }
        })
        .collect()
}

/// Returns (date, optional hour) embedded in a log filename. `u_exYYMMDDHH`
/// hourly IIS files yield an hour; daily names and generic dates yield None.
fn filename_date_hour(name: &str) -> (Option<chrono::NaiveDate>, Option<u32>) {
    let stem = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if let Some(cap) = RE_IIS_DATE.captures_iter(stem).last() {
        let yy: i32 = cap[1].parse().unwrap_or(0);
        let year = if yy < 70 { 2000 + yy } else { 1900 + yy };
        if let (Ok(mo), Ok(d)) = (cap[2].parse::<u32>(), cap[3].parse::<u32>()) {
            if let Some(dt) = chrono::NaiveDate::from_ymd_opt(year, mo, d) {
                let hh = cap
                    .get(4)
                    .and_then(|m| m.as_str().parse::<u32>().ok())
                    .filter(|h| *h < 24);
                return (Some(dt), hh);
            }
        }
    }
    (filename_embedded_date(name), None)
}

/// Drops log files that provably contain no rows on/after `cutoff` DATETIME —
/// hour-precision variant of `filter_items_by_min_date` for `--hours` scans.
/// Hourly-named files compare on full datetime; date-only named files are kept
/// if their day is in window; everything else falls back to file mtime.
pub fn filter_items_by_datetime(
    items: Vec<LogSourceItem>,
    cutoff: chrono::NaiveDateTime,
) -> Vec<LogSourceItem> {
    let cutoff_date = cutoff.date();
    let mtime_recent = |r: std::io::Result<std::time::SystemTime>| {
        r.map(|t| {
            let t: chrono::DateTime<chrono::Utc> = t.into();
            t.naive_utc() >= cutoff
        })
        .unwrap_or(true)
    };
    items
        .into_iter()
        .filter(|item| {
            let name = item.display_name();
            let (fd, fh) = filename_date_hour(&name);
            if let (Some(d), Some(h)) = (fd, fh) {
                return d.and_hms_opt(h, 0, 0).map(|dt| dt >= cutoff).unwrap_or(true);
            }
            if let Some(d) = fd {
                return d >= cutoff_date;
            }
            match item {
                LogSourceItem::DiskFile(p) => mtime_recent(std::fs::metadata(p).and_then(|m| m.modified())),
                LogSourceItem::ZipEntry { archive_path, .. } => {
                    mtime_recent(std::fs::metadata(archive_path).and_then(|m| m.modified()))
                }
                LogSourceItem::Stdin => true,
            }
        })
        .collect()
}

/// Keeps only the newest log item(s) — the "currently active" log file per
/// server (`--latest`). Filename date+hour wins over mtime; all entries from
/// the newest archive are kept together.
pub fn keep_latest_log_item(items: Vec<LogSourceItem>) -> Vec<LogSourceItem> {
    fn recency_key(item: &LogSourceItem) -> chrono::NaiveDateTime {
        let name = item.display_name();
        let (fd, fh) = filename_date_hour(&name);
        if let Some(d) = fd {
            return d
                .and_hms_opt(fh.unwrap_or(23), 59, 59)
                .unwrap_or_else(|| d.and_hms_opt(0, 0, 0).unwrap());
        }
        let mt = match item {
            LogSourceItem::DiskFile(p) => {
                std::fs::metadata(p).and_then(|m| m.modified()).ok()
            }
            LogSourceItem::ZipEntry { archive_path, .. } => {
                std::fs::metadata(archive_path).and_then(|m| m.modified()).ok()
            }
            LogSourceItem::Stdin => None,
        };
        mt.map(|t| {
            let t: chrono::DateTime<chrono::Utc> = t.into();
            t.naive_utc()
        })
        .unwrap_or(chrono::NaiveDateTime::MIN)
    }
    if items.len() <= 1 {
        return items;
    }
    let best = items
        .iter()
        .map(recency_key)
        .max()
        .unwrap_or(chrono::NaiveDateTime::MIN);
    items.into_iter().filter(|i| recency_key(i) == best).collect()
}

pub fn open_source_item_reader(
    item: &LogSourceItem,
    ckpt: &mut Option<&mut CheckpointStore>,
) -> Result<Box<dyn BufRead + Send>> {
    match item {
        LogSourceItem::Stdin => {
            let mut guard = STDIN_CACHE.lock().unwrap();
            if guard.is_none() {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                *guard = Some(buf);
            }
            let data = guard.clone().unwrap_or_default();
            Ok(Box::new(Cursor::new(data)))
        }
        LogSourceItem::DiskFile(path) => open_log_reader_with_checkpoint(path, ckpt),
        LogSourceItem::ZipEntry {
            archive_path,
            entry_index,
            ..
        } => {
            let file = File::open(archive_path)
                .with_context(|| format!("Failed to open ZIP {:?}", archive_path))?;
            let mut archive = zip::ZipArchive::new(BufReader::with_capacity(256 * 1024, file))?;
            let entry = archive.by_index(*entry_index)?;
            let cap = entry.size().min(8 * 1024 * 1024) as usize;
            let mut buf = Vec::with_capacity(cap);
            entry.take(max_zip_entry_bytes()).read_to_end(&mut buf)?;
            Ok(Box::new(Cursor::new(buf)))
        }
    }
}

pub fn open_log_reader_with_checkpoint(
    path: &Path,
    ckpt: &mut Option<&mut CheckpointStore>,
) -> Result<Box<dyn BufRead + Send>> {
    if is_stdin_path(&path.to_string_lossy()) {
        let mut none_ckpt = None;
        return open_source_item_reader(&LogSourceItem::Stdin, &mut none_ckpt);
    }
    let mut file = File::open(path).with_context(|| format!("Failed to open {:?}", path))?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "gz" | "gzip" => Ok(Box::new(BufReader::with_capacity(
            256 * 1024,
            GzDecoder::new(file),
        ))),
        "zst" | "zstd" => Ok(Box::new(BufReader::with_capacity(
            256 * 1024,
            zstd::stream::read::Decoder::new(file)?,
        ))),
        "zip" => {
            let mut archive = zip::ZipArchive::new(BufReader::with_capacity(256 * 1024, file))?;
            for idx in 0..archive.len() {
                let entry = archive.by_index(idx)?;
                if entry.is_file() {
                    let cap = entry.size().min(8 * 1024 * 1024) as usize;
                    let mut buf = Vec::with_capacity(cap);
                    entry.take(max_zip_entry_bytes()).read_to_end(&mut buf)?;
                    return Ok(Box::new(Cursor::new(buf)));
                }
            }
            anyhow::bail!("ZIP archive {:?} contains no files", path);
        }
        _ => {
            if let Some(store) = ckpt.as_deref_mut() {
                let len = file.metadata().map(|m| m.len()).unwrap_or(0);
                let prev = store.get_offset(path);
                if prev > 0 && prev <= len {
                    let _ = file.seek(SeekFrom::Start(prev));
                }
                store.update_offset(path, len);
            }
            Ok(Box::new(BufReader::with_capacity(256 * 1024, file)))
        }
    }
}

pub fn read_decoded_lines_from_item(
    item: &LogSourceItem,
    ckpt: &mut Option<&mut CheckpointStore>,
    max_lines: Option<usize>,
) -> Result<Vec<String>> {
    let mut reader = open_source_item_reader(item, ckpt)?;
    read_decoded_lines_from_bufread(&mut *reader, max_lines)
}

pub fn read_decoded_lines_with_checkpoint(
    path: &Path,
    ckpt: &mut Option<&mut CheckpointStore>,
    max_lines: Option<usize>,
) -> Result<Vec<String>> {
    let mut reader = open_log_reader_with_checkpoint(path, ckpt)?;
    read_decoded_lines_from_bufread(&mut *reader, max_lines)
}

fn read_decoded_lines_from_bufread(
    reader: &mut dyn BufRead,
    max_lines: Option<usize>,
) -> Result<Vec<String>> {
    let mut prefix = [0u8; 4];
    let mut prefix_len = 0;
    while prefix_len < 4 {
        match reader.read(&mut prefix[prefix_len..prefix_len + 1]) {
            Ok(0) => break,
            Ok(n) => prefix_len += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if prefix_len == 0 {
        return Ok(Vec::new());
    }

    let is_utf16_le = (prefix_len >= 2 && prefix[0] == 0xFF && prefix[1] == 0xFE)
        || (prefix_len >= 4
            && prefix[0] != 0
            && prefix[1] == 0
            && prefix[2] != 0
            && prefix[3] == 0);
    let is_utf16_be = (prefix_len >= 2 && prefix[0] == 0xFE && prefix[1] == 0xFF)
        || (prefix_len >= 4
            && prefix[0] == 0
            && prefix[1] != 0
            && prefix[2] == 0
            && prefix[3] != 0);

    if is_utf16_le || is_utf16_be {
        let mut all_bytes = Vec::from(&prefix[..prefix_len]);
        reader.read_to_end(&mut all_bytes)?;
        let start = if (is_utf16_le && all_bytes.starts_with(&[0xFF, 0xFE]))
            || (is_utf16_be && all_bytes.starts_with(&[0xFE, 0xFF]))
        {
            2
        } else {
            0
        };
        let slice = &all_bytes[start..];
        let u16_units: Vec<u16> = slice
            .chunks_exact(2)
            .map(|c| {
                if is_utf16_le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        let text = String::from_utf16_lossy(&u16_units);
        let iter = text.lines().map(|s| s.trim_end_matches('\r').to_string());
        return Ok(match max_lines {
            Some(limit) => iter.take(limit).collect(),
            None => iter.collect(),
        });
    }

    let start_offset =
        if prefix_len >= 3 && prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF {
            3
        } else {
            0
        };

    let mut lines = Vec::new();
    let mut line_buf = Vec::from(&prefix[start_offset..prefix_len]);

    loop {
        if let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let line_bytes = &line_buf[..pos];
            lines.push(decode_bytes_resilient(line_bytes));
            line_buf.drain(..=pos);
            if let Some(limit) = max_lines {
                if lines.len() >= limit {
                    return Ok(lines);
                }
            }
            continue;
        }

        let mut chunk = Vec::new();
        let n = reader.read_until(b'\n', &mut chunk)?;
        if n == 0 {
            if !line_buf.is_empty() {
                lines.push(decode_bytes_resilient(&line_buf));
            }
            break;
        }
        line_buf.extend_from_slice(&chunk);
    }

    Ok(lines)
}

pub fn read_decoded_lines(path: &Path) -> Result<Vec<String>> {
    let mut none_ckpt = None;
    read_decoded_lines_with_checkpoint(path, &mut none_ckpt, None)
}

#[inline]
fn decode_bytes_resilient(bytes: &[u8]) -> String {
    let trimmed = if bytes.ends_with(b"\r") {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    match std::str::from_utf8(trimmed) {
        Ok(s) => s.to_string(),
        Err(_) => trimmed.iter().map(|&b| b as char).collect(),
    }
}

pub fn detect_format_item(item: &LogSourceItem) -> InputFormat {
    let name = item.short_filename().to_lowercase();
    let clean = name
        .trim_end_matches(".gz")
        .trim_end_matches(".gzip")
        .trim_end_matches(".zst")
        .trim_end_matches(".zip");
    if clean.ends_with(".xlsx") || clean.ends_with(".xls") || clean.ends_with(".ods") {
        return InputFormat::Excel;
    }
    if clean.ends_with(".evtx") {
        return InputFormat::Evtx;
    }
    if clean.ends_with(".parquet") {
        return InputFormat::Parquet;
    }
    if clean.ends_with(".csv") {
        return InputFormat::Csv;
    }
    if clean.ends_with(".tsv") {
        return InputFormat::Tsv;
    }
    if clean.ends_with(".cfg") || clean.contains("running-config") {
        return InputFormat::CiscoConfig;
    }
    if clean.ends_with(".json") || clean.ends_with(".ndjson") || clean.ends_with(".jsonl") {
        return InputFormat::Json;
    }

    // IIS W3C / SMTP filename heuristic: u_ex*.log, u_extend*.log, W3SVC*, SMTPSVC*
    let full_disp = item.display_name().to_lowercase();
    let is_iis_filename = clean.starts_with("u_ex")
        || clean.starts_with("u_in")
        || clean.starts_with("ex")
        || clean.starts_with("smtp")
        || full_disp.contains("w3svc")
        || full_disp.contains("smtpsvc");
    if clean.starts_with("u_ex")
        || clean.starts_with("u_in")
        || full_disp.contains("w3svc")
        || full_disp.contains("smtpsvc")
    {
        return InputFormat::W3c;
    }

    let mut none_ckpt = None;
    if let Ok(sample_lines) = read_decoded_lines_from_item(item, &mut none_ckpt, Some(50)) {
        let mut saw_kv_line = false;
        for first_line in &sample_lines {
            let trimmed = first_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("#Software:")
                || trimmed.starts_with("#Fields:")
                || trimmed.starts_with("#Version:")
                || trimmed.starts_with("#Date:")
            {
                return InputFormat::W3c;
            }
            if W3C_DATA_LINE_RE.is_match(trimmed)
                && (is_iis_filename || trimmed.contains("W3SVC") || trimmed.contains("SMTPSVC"))
            {
                return InputFormat::W3c;
            }
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return InputFormat::Json;
            }
            if trimmed.contains("CEF:") {
                return InputFormat::Cef;
            }
            if trimmed.contains("%ASA-") {
                return InputFormat::CiscoAsa;
            }
            if trimmed.starts_with("1.0;") || trimmed.starts_with("2.0;") {
                return InputFormat::AzureBlob;
            }
            if trimmed.starts_with("version account-id interface-id") {
                return InputFormat::AwsVpc;
            }
            if AWS_S3_RE.is_match(trimmed) {
                return InputFormat::AwsS3;
            }
            if AWS_ALB_RE.is_match(trimmed) {
                return InputFormat::AwsAlb;
            }
            if NGINX_RE.is_match(trimmed) {
                return InputFormat::Nginx;
            }
            if W3C_DATA_LINE_RE.is_match(trimmed) {
                // Check if space-separated W3C line (avoid mistaking cookies with `=` for FirewallKv!)
                let parts_count = trimmed.split_whitespace().count();
                if parts_count >= 10 && !trimmed.starts_with("date=") {
                    return InputFormat::W3c;
                }
            }
            if KV_PAIR_RE.find_iter(trimmed).count() >= 4 {
                saw_kv_line = true;
            }
            if SYSLOG_RE.is_match(trimmed) {
                return InputFormat::Syslog;
            }
        }
        if saw_kv_line {
            return InputFormat::FirewallKv;
        }
    }
    if is_iis_filename {
        return InputFormat::W3c;
    }
    InputFormat::Line
}

#[allow(dead_code)]
pub fn detect_format(path: &Path) -> InputFormat {
    if let Ok(items) = resolve_source_items(&path.to_string_lossy()) {
        if let Some(first) = items.first() {
            return detect_format_item(first);
        }
    }
    detect_format_item(&LogSourceItem::DiskFile(path.to_path_buf()))
}

const DEFAULT_IIS_W3C_FIELDS: &[&str] = &[
    "date",
    "time",
    "s_sitename",
    "s_computername",
    "s_ip",
    "cs_method",
    "cs_uri_stem",
    "cs_uri_query",
    "s_port",
    "cs_username",
    "c_ip",
    "cs_version",
    "csuser_agent",
    "cscookie",
    "csreferer",
    "cs_host",
    "sc_status",
    "sc_substatus",
    "sc_win32_status",
    "sc_bytes",
    "cs_bytes",
    "time_taken",
];

/// High-performance multi-threaded W3C / IIS parser.
/// Parses each file or ZIP entry in parallel on a Rayon thread pool, building a `RecordBatch`
/// per file without intermediate `Vec<Vec<String>>` row allocations, and applies optional
/// streaming row-level pushdown filters (`min_date` / `status_prefix`) BEFORE Arrow allocation.
pub fn parse_w3c_items_parallel(
    items: &[LogSourceItem],
    verbose: bool,
) -> Result<(Vec<RecordBatch>, ParseStats)> {
    parse_w3c_items_parallel_filtered(items, verbose, None)
}

pub fn parse_w3c_items_parallel_filtered(
    items: &[LogSourceItem],
    verbose: bool,
    pre_filter: Option<&ScanPreFilter>,
) -> Result<(Vec<RecordBatch>, ParseStats)> {
    // Step 1: Discover canonical W3C field list across the items (scanning headers quickly)
    let mut canonical_fields: Vec<String> = Vec::new();
    for item in items {
        let mut none_ckpt = None;
        if let Ok(sample) = read_decoded_lines_from_item(item, &mut none_ckpt, Some(100)) {
            for line in sample {
                if let Some(f_str) = line.trim().strip_prefix("#Fields:") {
                    canonical_fields = f_str
                        .split_whitespace()
                        .map(|s| s.replace('-', "_").replace(['(', ')'], "").to_lowercase())
                        .collect();
                    break;
                }
            }
        }
        if !canonical_fields.is_empty() {
            break;
        }
    }
    if canonical_fields.is_empty() {
        canonical_fields = DEFAULT_IIS_W3C_FIELDS.iter().map(|s| s.to_string()).collect();
    }

    let mut schema_fields = canonical_fields.clone();
    schema_fields.push("log_filename".to_string());
    schema_fields.push("log_row".to_string());
    let arrow_fields: Vec<Field> = schema_fields
        .iter()
        .map(|name| Field::new(name, DataType::Utf8, true))
        .collect();
    let schema = Arc::new(Schema::new(arrow_fields));

    let num_data_cols = canonical_fields.len();
    let canon_status_idx = canonical_fields.iter().position(|c| c == "sc_status");
    let canon_date_idx = canonical_fields.iter().position(|c| c == "date");
    let canon_time_idx = canonical_fields.iter().position(|c| c == "time");
    let filter_min_date = pre_filter.and_then(|f| f.min_date.as_deref());
    let filter_min_time = pre_filter.and_then(|f| f.min_time.as_deref());
    let filter_status_prefix = pre_filter.and_then(|f| f.status_prefix.as_deref());
    let req_needles_lower: Vec<Vec<u8>> = pre_filter
        .map(|f| {
            f.required_substrings
                .iter()
                .map(|s| s.to_ascii_lowercase().into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let any_needles_lower: Vec<Vec<u8>> = pre_filter
        .map(|f| {
            f.any_substrings
                .iter()
                .map(|s| s.to_ascii_lowercase().into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let has_raw_filter = !req_needles_lower.is_empty() || !any_needles_lower.is_empty();

    // Step 2: Process every file / ZIP entry in parallel via Rayon!
    let per_file_results: Vec<Result<(RecordBatch, FileParseSummary)>> = items
        .par_iter()
        .map(|item| {
            let file_start = std::time::Instant::now();
            let short_name = item.short_filename();
            let disp_name = item.display_name();
            let bytes = item.size_bytes();

            let mut reader = open_source_item_reader(item, &mut None)?;
            // Modest initial capacity (256 rows / 4 KB per col) so 80+ files never pre-allocate GBs of unused RAM
            let mut builders: Vec<StringBuilder> = (0..num_data_cols + 2)
                .map(|_| StringBuilder::with_capacity(256, 4096))
                .collect();

            let mut line_buf: Vec<u8> = Vec::with_capacity(8192);
            let mut line_idx: usize = 0;
            let mut row_count: usize = 0;
            let mut first_chunk = true;
            let mut file_status_idx = canon_status_idx;
            let mut file_date_idx = canon_date_idx;
            let mut file_time_idx = canon_time_idx;
            let mut file_num_cols = num_data_cols;
            // Maps canonical column `c` -> token index in this file (None if canonical matches 1:1)
            let mut custom_col_map: Option<Vec<Option<usize>>> = None;

            loop {
                line_buf.clear();
                let n = reader.read_until(b'\n', &mut line_buf)?;
                if n == 0 {
                    break;
                }
                line_idx += 1;

                let mut slice = &line_buf[..];
                if first_chunk {
                    first_chunk = false;
                    if slice.starts_with(&[0xEF, 0xBB, 0xBF]) {
                        slice = &slice[3..];
                    } else if slice.starts_with(&[0xFF, 0xFE]) || slice.starts_with(&[0xFE, 0xFF]) {
                        // Fall back to full UTF-16 decoder for this item
                        drop(reader);
                        return parse_w3c_single_item_utf16(
                            item,
                            &schema,
                            num_data_cols,
                            file_start,
                            verbose,
                            pre_filter,
                        );
                    }
                }

                while slice.ends_with(b"\n") || slice.ends_with(b"\r") {
                    slice = &slice[..slice.len() - 1];
                }
                while slice.first().map(|b| b.is_ascii_whitespace()).unwrap_or(false) {
                    slice = &slice[1..];
                }
                if slice.is_empty() {
                    continue;
                }
                if slice[0] == b'#' {
                    if slice.starts_with(b"#Fields:") {
                        if let Ok(hdr) = std::str::from_utf8(&slice[8..]) {
                            let file_cols: Vec<String> = hdr
                                .split_whitespace()
                                .map(|s| s.replace('-', "_").replace(['(', ')'], "").to_lowercase())
                                .collect();
                            if !file_cols.is_empty() {
                                file_num_cols = file_cols.len();
                                file_status_idx = file_cols.iter().position(|c| c == "sc_status");
                                file_date_idx = file_cols.iter().position(|c| c == "date");
                                file_time_idx = file_cols.iter().position(|c| c == "time");
                                if file_cols != canonical_fields {
                                    let map: Vec<Option<usize>> = canonical_fields
                                        .iter()
                                        .map(|cf| file_cols.iter().position(|fc| fc == cf))
                                        .collect();
                                    custom_col_map = Some(map);
                                } else {
                                    custom_col_map = None;
                                }
                            }
                        }
                    }
                    continue;
                }

                // Zero-allocation raw-byte substring pushdown BEFORE UTF-8 decoding or whitespace splitting!
                if has_raw_filter
                    && !matches_raw_line_needles(slice, &req_needles_lower, &any_needles_lower)
                {
                    continue;
                }

                // Fast ASCII/UTF-8 whitespace field splitter
                let line_cow = match std::str::from_utf8(slice) {
                    Ok(s) => std::borrow::Cow::Borrowed(s),
                    Err(_) => std::borrow::Cow::Owned(slice.iter().map(|&b| b as char).collect()),
                };

                let mut iter = line_cow.split_whitespace();
                let mut tokens: [&str; 32] = [""; 32];
                let mut t_count = 0;
                while let Some(tok) = iter.next() {
                    if t_count < 32 {
                        tokens[t_count] = tok;
                    }
                    t_count += 1;
                }

                // Standard W3C row or IIS SMTP W3C row (where trailing cs-uri-query/parameters can contain spaces or be omitted)
                if t_count == file_num_cols
                    || (t_count >= file_num_cols.saturating_sub(2) && file_num_cols >= 6)
                {
                    // Zero-allocation pushdown pre-filter: skip non-matching status / old dates BEFORE touching Arrow StringBuilder!
                    if let Some(sp) = filter_status_prefix {
                        if let Some(s_idx) = file_status_idx {
                            if s_idx >= t_count || !tokens[s_idx].starts_with(sp) {
                                continue;
                            }
                        }
                    }
                    if let Some(md) = filter_min_date {
                        if let Some(d_idx) = file_date_idx {
                            if d_idx < t_count && !tokens[d_idx].is_empty() && tokens[d_idx] < md {
                                continue;
                            }
                            if let (Some(mt), Some(t_idx)) = (filter_min_time, file_time_idx) {
                                if t_idx < t_count
                                    && tokens[d_idx] == md
                                    && tokens[t_idx] < mt
                                {
                                    continue;
                                }
                            }
                        }
                    }

                    if let Some(ref cmap) = custom_col_map {
                        for c in 0..num_data_cols {
                            let v = cmap[c]
                                .filter(|&idx| idx < t_count)
                                .map(|idx| tokens[idx])
                                .unwrap_or("");
                            if v == "-" || v.is_empty() {
                                builders[c].append_null();
                            } else {
                                builders[c].append_value(v);
                            }
                        }
                    } else {
                        for c in 0..num_data_cols {
                            let v = if c < t_count { tokens[c] } else { "" };
                            if v == "-" || v.is_empty() {
                                builders[c].append_null();
                            } else {
                                builders[c].append_value(v);
                            }
                        }
                    }
                    builders[num_data_cols].append_value(&short_name);
                    let mut num_buf = itoa_stack(line_idx);
                    builders[num_data_cols + 1].append_value(&mut num_buf);
                    row_count += 1;
                }
            }

            let arrays: Vec<ArrayRef> = builders
                .into_iter()
                .map(|mut b| Arc::new(b.finish()) as ArrayRef)
                .collect();
            let batch = RecordBatch::try_new(schema.clone(), arrays)?;
            let elapsed_ms = file_start.elapsed().as_millis();

            if verbose {
                eprintln!(
                    "  {SYM_OK} Parsed {:28} | {:>8} lines | {:>8} rows | {:>5} ms",
                    disp_name, line_idx, row_count, elapsed_ms
                );
            }

            Ok((
                batch,
                FileParseSummary {
                    name: disp_name,
                    lines: line_idx,
                    rows: row_count,
                    bytes,
                    elapsed_ms,
                },
            ))
        })
        .collect();

    let mut batches = Vec::with_capacity(per_file_results.len());
    let mut stats = ParseStats::default();
    for res in per_file_results {
        let (batch, summary) = res?;
        stats.files_processed += 1;
        stats.total_lines += summary.lines;
        stats.total_rows += summary.rows;
        stats.total_bytes += summary.bytes;
        stats.file_summaries.push(summary);
        if batch.num_rows() > 0 {
            batches.push(batch);
        }
    }

    if batches.is_empty() {
        let empty_arrays: Vec<ArrayRef> = (0..num_data_cols + 2)
            .map(|_| {
                let mut b = StringBuilder::new();
                Arc::new(b.finish()) as ArrayRef
            })
            .collect();
        batches.push(RecordBatch::try_new(schema, empty_arrays)?);
    }

    Ok((batches, stats))
}

fn parse_w3c_single_item_utf16(
    item: &LogSourceItem,
    schema: &Arc<Schema>,
    num_data_cols: usize,
    file_start: std::time::Instant,
    verbose: bool,
    pre_filter: Option<&ScanPreFilter>,
) -> Result<(RecordBatch, FileParseSummary)> {
    let short_name = item.short_filename();
    let disp_name = item.display_name();
    let bytes = item.size_bytes();
    let lines = read_decoded_lines_from_item(item, &mut None, None)?;
    let mut builders: Vec<StringBuilder> = (0..num_data_cols + 2)
        .map(|_| StringBuilder::with_capacity(256, 4096))
        .collect();
    let mut row_count = 0;
    let status_idx = schema.fields().iter().position(|f| f.name() == "sc_status");
    let date_idx = schema.fields().iter().position(|f| f.name() == "date");
    let time_idx = schema.fields().iter().position(|f| f.name() == "time");
    let filter_min_date = pre_filter.and_then(|f| f.min_date.as_deref());
    let filter_min_time = pre_filter.and_then(|f| f.min_time.as_deref());
    let filter_status_prefix = pre_filter.and_then(|f| f.status_prefix.as_deref());
    let req_needles_lower: Vec<Vec<u8>> = pre_filter
        .map(|f| {
            f.required_substrings
                .iter()
                .map(|s| s.to_ascii_lowercase().into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let any_needles_lower: Vec<Vec<u8>> = pre_filter
        .map(|f| {
            f.any_substrings
                .iter()
                .map(|s| s.to_ascii_lowercase().into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let has_raw_filter = !req_needles_lower.is_empty() || !any_needles_lower.is_empty();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if has_raw_filter
            && !matches_raw_line_needles(
                trimmed.as_bytes(),
                &req_needles_lower,
                &any_needles_lower,
            )
        {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() == num_data_cols {
            if let Some(sp) = filter_status_prefix {
                if let Some(s_idx) = status_idx {
                    if s_idx >= parts.len() || !parts[s_idx].starts_with(sp) {
                        continue;
                    }
                }
            }
            if let Some(md) = filter_min_date {
                if let Some(d_idx) = date_idx {
                    if d_idx < parts.len() && !parts[d_idx].is_empty() && parts[d_idx] < md {
                        continue;
                    }
                    if let (Some(mt), Some(t_idx)) = (filter_min_time, time_idx) {
                        if t_idx < parts.len() && parts[d_idx] == md && parts[t_idx] < mt {
                            continue;
                        }
                    }
                }
            }
            for c in 0..num_data_cols {
                let v = parts[c];
                if v == "-" || v.is_empty() {
                    builders[c].append_null();
                } else {
                    builders[c].append_value(v);
                }
            }
            builders[num_data_cols].append_value(&short_name);
            builders[num_data_cols + 1].append_value(itoa_stack(idx + 1));
            row_count += 1;
        }
    }

    let arrays: Vec<ArrayRef> = builders
        .into_iter()
        .map(|mut b| Arc::new(b.finish()) as ArrayRef)
        .collect();
    let batch = RecordBatch::try_new(schema.clone(), arrays)?;
    let elapsed_ms = file_start.elapsed().as_millis();
    if verbose {
        eprintln!(
            "  {SYM_OK} Parsed {:28} | {:>8} lines | {:>8} rows | {:>5} ms",
            disp_name,
            lines.len(),
            row_count,
            elapsed_ms
        );
    }
    Ok((
        batch,
        FileParseSummary {
            name: disp_name,
            lines: lines.len(),
            rows: row_count,
            bytes,
            elapsed_ms,
        },
    ))
}

#[inline]
fn itoa_stack(n: usize) -> String {
    n.to_string()
}

#[allow(dead_code)]
pub fn parse_w3c_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let items: Vec<LogSourceItem> = paths
        .iter()
        .cloned()
        .map(LogSourceItem::DiskFile)
        .collect();
    let (batches, _) = parse_w3c_items_parallel(&items, false)?;
    if batches.len() == 1 {
        Ok(batches.into_iter().next().unwrap())
    } else {
        let schema = batches[0].schema();
        Ok(arrow::compute::concat_batches(&schema, &batches)?)
    }
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
                        headers = row
                            .iter()
                            .enumerate()
                            .map(|(i, c)| {
                                let s = cell_to_string(c).trim().replace([' ', '-', '.'], "_");
                                if s.is_empty() {
                                    format!("col_{}", i + 1)
                                } else {
                                    s
                                }
                            })
                            .collect();
                    } else if !headers.is_empty() {
                        let vals: Vec<String> = (0..headers.len())
                            .map(|i| row.get(i).map(cell_to_string).unwrap_or_default())
                            .collect();
                        rows.push(vals);
                    }
                }
            }
        }
    }
    if headers.is_empty() {
        anyhow::bail!("No worksheet data found in Excel file(s)");
    }
    build_string_batch(&headers, &rows)
}

fn cell_to_string(c: &Data) -> String {
    match c {
        Data::String(s) => s.clone(),
        Data::Float(f) => {
            if f.fract() == 0.0 {
                format!("{:.0}", f)
            } else {
                f.to_string()
            }
        }
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
        let lines = read_decoded_lines(path)?;
        let full_content = lines.join("\n");
        let trimmed = full_content.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            extract_json_records(val, &mut keys, &mut flat_objects);
            continue;
        }
        for line in &lines {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(l) {
                extract_json_records(val, &mut keys, &mut flat_objects);
            }
        }
    }
    if keys.is_empty() {
        anyhow::bail!("No valid JSON objects found in input");
    }
    let rows: Vec<Vec<String>> = flat_objects
        .into_iter()
        .map(|obj| {
            keys.iter()
                .map(|k| obj.get(k).cloned().unwrap_or_default())
                .collect()
        })
        .collect();
    build_string_batch(&keys, &rows)
}

fn extract_json_records(
    val: Value,
    keys: &mut Vec<String>,
    out: &mut Vec<HashMap<String, String>>,
) {
    match val {
        Value::Array(arr) => {
            for item in arr {
                extract_json_records(item, keys, out);
            }
        }
        Value::Object(mut map) => {
            if let Some(Value::Array(records)) =
                map.remove("Records").or_else(|| map.remove("records"))
            {
                for r in records {
                    extract_json_records(r, keys, out);
                }
                return;
            }
            let mut flat = HashMap::new();
            flatten_json_object("", &map, &mut flat, keys);
            if !flat.is_empty() {
                out.push(flat);
            }
        }
        _ => {}
    }
}

fn flatten_json_object(
    prefix: &str,
    map: &Map<String, Value>,
    flat: &mut HashMap<String, String>,
    keys: &mut Vec<String>,
) {
    for (k, v) in map {
        let col_name = if prefix.is_empty() {
            k.replace(['-', '.'], "_")
        } else {
            format!("{}_{}", prefix, k.replace(['-', '.'], "_"))
        };
        match v {
            Value::Object(sub) => {
                if prefix.is_empty() {
                    flatten_json_object(&col_name, sub, flat, keys);
                } else {
                    if !keys.contains(&col_name) {
                        keys.push(col_name.clone());
                    }
                    flat.insert(col_name, Value::Object(sub.clone()).to_string());
                }
            }
            Value::Null => {}
            Value::String(s) => {
                if !keys.contains(&col_name) {
                    keys.push(col_name.clone());
                }
                flat.insert(col_name, s.clone());
            }
            other => {
                if !keys.contains(&col_name) {
                    keys.push(col_name.clone());
                }
                flat.insert(col_name, other.to_string());
            }
        }
    }
}

pub fn parse_aws_vpc_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let default_fields = vec![
        "version",
        "account_id",
        "interface_id",
        "srcaddr",
        "dstaddr",
        "srcport",
        "dstport",
        "protocol",
        "packets",
        "bytes",
        "start",
        "end",
        "action",
        "log_status",
    ];
    let mut field_names: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for path in paths {
        for line in read_decoded_lines(path)? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("version ") {
                if field_names.is_empty() {
                    field_names = trimmed
                        .split_whitespace()
                        .map(|s| s.replace('-', "_"))
                        .collect();
                }
                continue;
            }
            if field_names.is_empty() {
                field_names = default_fields.iter().map(|s| s.to_string()).collect();
            }
            let parts: Vec<String> = trimmed.split_whitespace().map(|s| s.to_string()).collect();
            if parts.len() >= field_names.len() {
                rows.push(parts.into_iter().take(field_names.len()).collect());
            }
        }
    }
    build_string_batch(&field_names, &rows)
}

pub fn parse_azure_blob_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec![
        "version",
        "request_start_time",
        "operation_type",
        "request_status",
        "http_status_code",
        "end_to_end_latency_ms",
        "server_latency_ms",
        "authentication_type",
        "requester_account_name",
        "owner_account_name",
        "service_type",
        "request_url",
        "requested_object_key",
        "request_id_header",
        "operation_count",
        "caller_ip_address",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for path in paths {
        for line in read_decoded_lines(path)? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<String> = trimmed
                .split(';')
                .take(fields.len())
                .map(|s| s.trim_matches('"').to_string())
                .collect();
            if parts.len() >= 12 {
                let mut padded = parts;
                padded.resize(fields.len(), String::new());
                rows.push(padded);
            }
        }
    }
    build_string_batch(&fields, &rows)
}

#[allow(dead_code)]
pub fn parse_aws_s3_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    parse_regex_files(paths, &AWS_S3_RE)
}
#[allow(dead_code)]
pub fn parse_aws_alb_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    parse_regex_files(paths, &AWS_ALB_RE)
}
#[allow(dead_code)]
pub fn parse_nginx_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    parse_regex_files(paths, &NGINX_RE)
}
#[allow(dead_code)]
pub fn parse_syslog_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    parse_regex_files(paths, &SYSLOG_RE)
}

pub fn parse_regex_items_parallel(
    items: &[LogSourceItem],
    re: &Regex,
    verbose: bool,
) -> Result<(Vec<RecordBatch>, ParseStats)> {
    parse_regex_items_parallel_filtered(items, re, verbose, None)
}

pub fn parse_regex_items_parallel_filtered(
    items: &[LogSourceItem],
    re: &Regex,
    verbose: bool,
    pre_filter: Option<&ScanPreFilter>,
) -> Result<(Vec<RecordBatch>, ParseStats)> {
    let mut group_names: Vec<String> = re
        .capture_names()
        .flatten()
        .map(|s| s.to_string())
        .collect();
    if group_names.is_empty() {
        anyhow::bail!("Regex must contain named capture groups");
    }
    let base_len = group_names.len();
    group_names.push("log_filename".to_string());
    group_names.push("log_row".to_string());

    let arrow_fields: Vec<Field> = group_names
        .iter()
        .map(|name| Field::new(name, DataType::Utf8, true))
        .collect();
    let schema = Arc::new(Schema::new(arrow_fields));
    let filter_status_prefix = pre_filter.and_then(|f| f.status_prefix.as_deref());
    let req_needles_lower: Vec<Vec<u8>> = pre_filter
        .map(|f| {
            f.required_substrings
                .iter()
                .map(|s| s.to_ascii_lowercase().into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let any_needles_lower: Vec<Vec<u8>> = pre_filter
        .map(|f| {
            f.any_substrings
                .iter()
                .map(|s| s.to_ascii_lowercase().into_bytes())
                .collect()
        })
        .unwrap_or_default();
    let has_raw_filter = !req_needles_lower.is_empty() || !any_needles_lower.is_empty();
    let status_group_idx = group_names.iter().position(|g| {
        matches!(
            g.as_str(),
            "status" | "elb_status_code" | "http_status" | "sc_status"
        )
    });

    let per_file: Vec<Result<(RecordBatch, FileParseSummary)>> = items
        .par_iter()
        .map(|item| {
            let start = std::time::Instant::now();
            let short_name = item.short_filename();
            let disp_name = item.display_name();
            let bytes = item.size_bytes();
            let lines = read_decoded_lines_from_item(item, &mut None, None)?;
            let mut builders: Vec<StringBuilder> = (0..base_len + 2)
                .map(|_| StringBuilder::with_capacity(256, 4096))
                .collect();
            let mut row_count = 0;

            for (line_idx, line) in lines.iter().enumerate() {
                if has_raw_filter
                    && !matches_raw_line_needles(
                        line.as_bytes(),
                        &req_needles_lower,
                        &any_needles_lower,
                    )
                {
                    continue;
                }
                if let Some(caps) = re.captures(line) {
                    if let (Some(sp), Some(s_idx)) = (filter_status_prefix, status_group_idx) {
                        let st = caps
                            .name(&group_names[s_idx])
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        let target_st = caps
                            .name("target_status_code")
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        if !st.starts_with(sp) && !target_st.starts_with(sp) {
                            continue;
                        }
                    }
                    for c in 0..base_len {
                        let val = caps
                            .name(&group_names[c])
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        if val == "-" || val.is_empty() {
                            builders[c].append_null();
                        } else {
                            builders[c].append_value(val);
                        }
                    }
                    builders[base_len].append_value(&short_name);
                    builders[base_len + 1].append_value(itoa_stack(line_idx + 1));
                    row_count += 1;
                }
            }

            let arrays: Vec<ArrayRef> = builders
                .into_iter()
                .map(|mut b| Arc::new(b.finish()) as ArrayRef)
                .collect();
            let batch = RecordBatch::try_new(schema.clone(), arrays)?;
            let elapsed_ms = start.elapsed().as_millis();
            if verbose {
                eprintln!(
                    "  {SYM_OK} Parsed {:28} | {:>8} lines | {:>8} rows | {:>5} ms",
                    disp_name,
                    lines.len(),
                    row_count,
                    elapsed_ms
                );
            }
            Ok((
                batch,
                FileParseSummary {
                    name: disp_name,
                    lines: lines.len(),
                    rows: row_count,
                    bytes,
                    elapsed_ms,
                },
            ))
        })
        .collect();

    let mut batches = Vec::new();
    let mut stats = ParseStats::default();
    for res in per_file {
        let (b, s) = res?;
        stats.files_processed += 1;
        stats.total_lines += s.lines;
        stats.total_rows += s.rows;
        stats.total_bytes += s.bytes;
        stats.file_summaries.push(s);
        if b.num_rows() > 0 {
            batches.push(b);
        }
    }
    if batches.is_empty() {
        let empty: Vec<ArrayRef> = (0..base_len + 2)
            .map(|_| {
                let mut b = StringBuilder::new();
                Arc::new(b.finish()) as ArrayRef
            })
            .collect();
        batches.push(RecordBatch::try_new(schema, empty)?);
    }
    Ok((batches, stats))
}

#[allow(dead_code)]
pub fn parse_regex_files(paths: &[PathBuf], re: &Regex) -> Result<RecordBatch> {
    let items: Vec<LogSourceItem> = paths
        .iter()
        .cloned()
        .map(LogSourceItem::DiskFile)
        .collect();
    let (batches, _) = parse_regex_items_parallel(&items, re, false)?;
    if batches.len() == 1 {
        Ok(batches.into_iter().next().unwrap())
    } else {
        let schema = batches[0].schema();
        Ok(arrow::compute::concat_batches(&schema, &batches)?)
    }
}

pub fn parse_firewall_kv_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let mut keys: Vec<String> = Vec::new();
    let mut objects: Vec<HashMap<String, String>> = Vec::new();
    for path in paths {
        for line in read_decoded_lines(path)? {
            let mut map = HashMap::new();
            for caps in KV_PAIR_RE.captures_iter(&line) {
                let k = caps[1].replace(['-', '.'], "_");
                let v = caps
                    .get(2)
                    .or_else(|| caps.get(3))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                if !keys.contains(&k) {
                    keys.push(k.clone());
                }
                map.insert(k, v);
            }
            if line.contains("UFW BLOCK") || line.contains("DROP") {
                if !keys.contains(&"fw_action".to_string()) {
                    keys.push("fw_action".to_string());
                }
                map.entry("fw_action".to_string())
                    .or_insert_with(|| "BLOCK".to_string());
            }
            if !map.is_empty() {
                objects.push(map);
            }
        }
    }
    if keys.is_empty() {
        anyhow::bail!("No key=value firewall fields found");
    }
    let rows: Vec<Vec<String>> = objects
        .into_iter()
        .map(|obj| {
            keys.iter()
                .map(|k| obj.get(k).cloned().unwrap_or_default())
                .collect()
        })
        .collect();
    build_string_batch(&keys, &rows)
}

pub fn parse_cisco_asa_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec![
        "severity".to_string(),
        "msg_id".to_string(),
        "action".to_string(),
        "src_ip".to_string(),
        "src_port".to_string(),
        "dst_ip".to_string(),
        "dst_port".to_string(),
        "message".to_string(),
    ];
    let mut rows = Vec::new();
    for path in paths {
        for line in read_decoded_lines(path)? {
            if let Some(caps) = CISCO_ASA_RE.captures(&line) {
                let sev = caps["severity"].to_string();
                let msg_id = caps["msg_id"].to_string();
                let msg = caps["message"].to_string();
                let lower = msg.to_lowercase();
                let action = if lower.contains("denied")
                    || lower.contains("deny")
                    || lower.contains("failed")
                {
                    "DENY"
                } else if lower.contains("built")
                    || lower.contains("permitted")
                    || lower.contains("permit")
                {
                    "PERMIT"
                } else if lower.contains("teardown") {
                    "TEARDOWN"
                } else {
                    "INFO"
                };

                let mut ips = IP_EXTRACTOR_RE.captures_iter(&msg);
                let (src_ip, src_port) = ips
                    .next()
                    .map(|c| {
                        (
                            c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                            c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default(),
                        )
                    })
                    .unwrap_or_default();
                let (dst_ip, dst_port) = ips
                    .next()
                    .map(|c| {
                        (
                            c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                            c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default(),
                        )
                    })
                    .unwrap_or_default();
                rows.push(vec![
                    sev,
                    msg_id,
                    action.to_string(),
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    msg,
                ]);
            }
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_cisco_config_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec![
        "file".to_string(),
        "line_number".to_string(),
        "section".to_string(),
        "directive".to_string(),
        "is_no_cmd".to_string(),
    ];
    let mut rows = Vec::new();
    for path in paths {
        let fname = path.to_string_lossy().to_string();
        let mut current_section = String::from("GLOBAL");
        for (idx, line) in read_decoded_lines(path)?.into_iter().enumerate() {
            let trimmed_right = line.trim_end();
            let trimmed = trimmed_right.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('!') {
                continue;
            }
            let is_indented = trimmed_right.starts_with(' ') || trimmed_right.starts_with('\t');
            if !is_indented {
                if trimmed.starts_with("interface ")
                    || trimmed.starts_with("router ")
                    || trimmed.starts_with("line ")
                    || trimmed.starts_with("ip access-list ")
                    || trimmed.starts_with("crypto ")
                    || trimmed.starts_with("object-group ")
                {
                    current_section = trimmed.to_string();
                } else {
                    current_section = "GLOBAL".to_string();
                }
            }
            let is_no = if trimmed.starts_with("no ") {
                "true"
            } else {
                "false"
            };
            rows.push(vec![
                fname.clone(),
                (idx + 1).to_string(),
                current_section.clone(),
                trimmed.to_string(),
                is_no.to_string(),
            ]);
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_cef_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec![
        "vendor".to_string(),
        "product".to_string(),
        "signature_id".to_string(),
        "name".to_string(),
        "severity".to_string(),
        "src".to_string(),
        "dst".to_string(),
        "act".to_string(),
        "request".to_string(),
        "extensions".to_string(),
    ];
    let mut rows = Vec::new();
    for path in paths {
        for line in read_decoded_lines(path)? {
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
                        let v = caps
                            .get(2)
                            .or_else(|| caps.get(3))
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        match k {
                            "src" | "c_ip" => src = v.to_string(),
                            "dst" | "s_ip" => dst = v.to_string(),
                            "act" | "action" => act = v.to_string(),
                            "request" | "cs_uri" => req = v.to_string(),
                            _ => {}
                        }
                    }
                    rows.push(vec![
                        parts[1].to_string(),
                        parts[2].to_string(),
                        parts[4].to_string(),
                        parts[5].to_string(),
                        parts[6].to_string(),
                        src,
                        dst,
                        act,
                        req,
                        ext.to_string(),
                    ]);
                }
            }
        }
    }
    build_string_batch(&fields, &rows)
}

pub fn parse_ias_files(paths: &[PathBuf]) -> Result<RecordBatch> {
    let fields = vec![
        "timestamp".to_string(),
        "computer".to_string(),
        "user_name".to_string(),
        "client_ip".to_string(),
        "nas_ip".to_string(),
        "packet_type".to_string(),
        "reason_code".to_string(),
    ];
    let xml_tag_re = Regex::new(r"<([A-Za-z0-9_-]+)(?:\s+[^>]*)?>([^<]*)</[A-Za-z0-9_-]+>").unwrap();
    let mut rows = Vec::new();
    for path in paths {
        for line in read_decoded_lines(path)? {
            let trimmed = line.trim();
            if trimmed.starts_with("<Event>") {
                let mut map = HashMap::new();
                for caps in xml_tag_re.captures_iter(trimmed) {
                    map.insert(caps[1].to_string(), caps[2].to_string());
                }
                rows.push(vec![
                    map.get("Timestamp").cloned().unwrap_or_default(),
                    map.get("Computer-Name").cloned().unwrap_or_default(),
                    map.get("User-Name")
                        .or_else(|| map.get("SAM-Account-Name"))
                        .cloned()
                        .unwrap_or_default(),
                    map.get("Calling-Station-Id")
                        .or_else(|| map.get("Client-IP-Address"))
                        .cloned()
                        .unwrap_or_default(),
                    map.get("NAS-IP-Address").cloned().unwrap_or_default(),
                    map.get("Packet-Type").cloned().unwrap_or_default(),
                    map.get("Reason-Code").cloned().unwrap_or_default(),
                ]);
            } else if trimmed.contains(',') {
                let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim_matches('"')).collect();
                if parts.len() >= 11 {
                    rows.push(vec![
                        format!("{} {}", parts[2], parts[3]),
                        parts[0].to_string(),
                        parts[5].to_string(),
                        parts.get(6).copied().unwrap_or("").to_string(),
                        parts.get(9).copied().unwrap_or("").to_string(),
                        parts[4].to_string(),
                        parts.get(10).copied().unwrap_or("").to_string(),
                    ]);
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
                let eid = sys["EventID"]
                    .as_i64()
                    .or_else(|| sys["EventID"]["#text"].as_i64())
                    .unwrap_or(0);
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

    Ok(RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(record_ids)),
            Arc::new(ts_b.finish()),
            Arc::new(Int64Array::from(event_ids)),
            Arc::new(Int64Array::from(levels)),
            Arc::new(ch_b.finish()),
            Arc::new(comp_b.finish()),
            Arc::new(pay_b.finish()),
        ],
    )?)
}

pub fn parse_raw_items_parallel(
    items: &[LogSourceItem],
    mut ckpt: Option<&mut CheckpointStore>,
    verbose: bool,
) -> Result<(Vec<RecordBatch>, ParseStats)> {
    let fields = vec![
        Field::new("file", DataType::Utf8, true),
        Field::new("line_number", DataType::Utf8, true),
        Field::new("raw_line", DataType::Utf8, true),
        Field::new("text", DataType::Utf8, true),
        Field::new("index", DataType::Utf8, true),
    ];
    let schema = Arc::new(Schema::new(fields));

    // If checkpoint is used, process sequentially so offsets update deterministically
    if ckpt.is_some() {
        let mut batches = Vec::new();
        let mut stats = ParseStats::default();
        for item in items {
            let start = std::time::Instant::now();
            let fname = item.display_name();
            let bytes = item.size_bytes();
            let lines = read_decoded_lines_from_item(item, &mut ckpt, None)?;
            let mut b_file = StringBuilder::new();
            let mut b_ln = StringBuilder::new();
            let mut b_raw = StringBuilder::new();
            let mut b_txt = StringBuilder::new();
            let mut b_idx = StringBuilder::new();
            for (i, line) in lines.iter().enumerate() {
                let ln = itoa_stack(i + 1);
                b_file.append_value(&fname);
                b_ln.append_value(&ln);
                b_raw.append_value(line);
                b_txt.append_value(line);
                b_idx.append_value(&ln);
            }
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(b_file.finish()),
                    Arc::new(b_ln.finish()),
                    Arc::new(b_raw.finish()),
                    Arc::new(b_txt.finish()),
                    Arc::new(b_idx.finish()),
                ],
            )?;
            let elapsed_ms = start.elapsed().as_millis();
            stats.files_processed += 1;
            stats.total_lines += lines.len();
            stats.total_rows += lines.len();
            stats.total_bytes += bytes;
            stats.file_summaries.push(FileParseSummary {
                name: fname,
                lines: lines.len(),
                rows: lines.len(),
                bytes,
                elapsed_ms,
            });
            if batch.num_rows() > 0 {
                batches.push(batch);
            }
        }
        if batches.is_empty() {
            let empty: Vec<ArrayRef> = (0..5)
                .map(|_| {
                    let mut b = StringBuilder::new();
                    Arc::new(b.finish()) as ArrayRef
                })
                .collect();
            batches.push(RecordBatch::try_new(schema, empty)?);
        }
        return Ok((batches, stats));
    }

    let per_file: Vec<Result<(RecordBatch, FileParseSummary)>> = items
        .par_iter()
        .map(|item| {
            let start = std::time::Instant::now();
            let fname = item.display_name();
            let bytes = item.size_bytes();
            let lines = read_decoded_lines_from_item(item, &mut None, None)?;
            let mut b_file = StringBuilder::new();
            let mut b_ln = StringBuilder::new();
            let mut b_raw = StringBuilder::new();
            let mut b_txt = StringBuilder::new();
            let mut b_idx = StringBuilder::new();
            for (i, line) in lines.iter().enumerate() {
                let ln = itoa_stack(i + 1);
                b_file.append_value(&fname);
                b_ln.append_value(&ln);
                b_raw.append_value(line);
                b_txt.append_value(line);
                b_idx.append_value(&ln);
            }
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(b_file.finish()),
                    Arc::new(b_ln.finish()),
                    Arc::new(b_raw.finish()),
                    Arc::new(b_txt.finish()),
                    Arc::new(b_idx.finish()),
                ],
            )?;
            let elapsed_ms = start.elapsed().as_millis();
            if verbose {
                eprintln!(
                    "  {SYM_OK} Parsed {:28} | {:>8} lines | {:>8} rows | {:>5} ms",
                    fname,
                    lines.len(),
                    lines.len(),
                    elapsed_ms
                );
            }
            Ok((
                batch,
                FileParseSummary {
                    name: fname,
                    lines: lines.len(),
                    rows: lines.len(),
                    bytes,
                    elapsed_ms,
                },
            ))
        })
        .collect();

    let mut batches = Vec::new();
    let mut stats = ParseStats::default();
    for res in per_file {
        let (b, s) = res?;
        stats.files_processed += 1;
        stats.total_lines += s.lines;
        stats.total_rows += s.rows;
        stats.total_bytes += s.bytes;
        stats.file_summaries.push(s);
        if b.num_rows() > 0 {
            batches.push(b);
        }
    }
    if batches.is_empty() {
        let empty: Vec<ArrayRef> = (0..5)
            .map(|_| {
                let mut b = StringBuilder::new();
                Arc::new(b.finish()) as ArrayRef
            })
            .collect();
        batches.push(RecordBatch::try_new(schema, empty)?);
    }
    Ok((batches, stats))
}

#[allow(dead_code)]
pub fn parse_raw_lines_with_checkpoint(
    paths: &[PathBuf],
    ckpt: Option<&mut CheckpointStore>,
) -> Result<RecordBatch> {
    let items: Vec<LogSourceItem> = paths
        .iter()
        .cloned()
        .map(LogSourceItem::DiskFile)
        .collect();
    let (batches, _) = parse_raw_items_parallel(&items, ckpt, false)?;
    if batches.len() == 1 {
        Ok(batches.into_iter().next().unwrap())
    } else {
        let schema = batches[0].schema();
        Ok(arrow::compute::concat_batches(&schema, &batches)?)
    }
}

fn build_string_batch(field_names: &[String], rows: &[Vec<String>]) -> Result<RecordBatch> {
    let fields: Vec<Field> = field_names
        .iter()
        .map(|name| Field::new(name, DataType::Utf8, true))
        .collect();
    let schema = Arc::new(Schema::new(fields));
    let mut builders: Vec<StringBuilder> =
        (0..field_names.len()).map(|_| StringBuilder::new()).collect();
    for row in rows {
        for (col_idx, val) in row.iter().enumerate() {
            if val == "-" || val.is_empty() {
                builders[col_idx].append_null();
            } else {
                builders[col_idx].append_value(val);
            }
        }
    }
    let arrays: Vec<ArrayRef> = builders
        .into_iter()
        .map(|mut b| Arc::new(b.finish()) as ArrayRef)
        .collect();
    Ok(RecordBatch::try_new(schema, arrays)?)
}

pub fn get_format_regex(fmt: InputFormat) -> Option<&'static Regex> {
    match fmt {
        InputFormat::Nginx => Some(&NGINX_RE),
        InputFormat::Syslog => Some(&SYSLOG_RE),
        InputFormat::AwsS3 => Some(&AWS_S3_RE),
        InputFormat::AwsAlb => Some(&AWS_ALB_RE),
        _ => None,
    }
}
