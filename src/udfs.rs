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
