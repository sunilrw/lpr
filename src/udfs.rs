use arrow::array::{Array, BooleanArray, Float64Array, Int64Array, StringArray};
use arrow::datatypes::DataType;
use datafusion::common::cast::{as_int64_array, as_string_array};
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

    // Microsoft Log Parser 2.2 compatibility UDFs:
    // 1. EXTRACT_TOKEN(str, index, delimiter) — 0-based token extraction
    let extract_token_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let len = args.iter().find_map(|a| match a {
            ColumnarValue::Array(arr) => Some(arr.len()),
            _ => None,
        }).unwrap_or(1);

        let str_col = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };
        let idx_col = match &args[1] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };
        let delim_col = match &args[2] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };

        let strs = as_string_array(&str_col)?;
        let idxs = as_int64_array(&idx_col)?;
        let delims = as_string_array(&delim_col)?;

        let result: StringArray = (0..len)
            .map(|i| {
                if strs.is_null(i) || idxs.is_null(i) || delims.is_null(i) {
                    return None;
                }
                let s = strs.value(i);
                let idx = idxs.value(i);
                let d = delims.value(i);
                if idx < 0 {
                    return None;
                }
                if d.is_empty() {
                    Some(s.to_string())
                } else {
                    s.split(d).nth(idx as usize).map(|t| t.to_string())
                }
            })
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "extract_token",
        vec![DataType::Utf8, DataType::Int64, DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        extract_token_fn,
    ));

    // 2. TO_TIMESTAMP(date_str, time_str) — combines W3C date & time into ISO-8601 timestamp string
    let to_ts_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let len = args.iter().find_map(|a| match a {
            ColumnarValue::Array(arr) => Some(arr.len()),
            _ => None,
        }).unwrap_or(1);

        let d_col = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };
        let t_col = match &args[1] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };

        let dates = as_string_array(&d_col)?;
        let times = as_string_array(&t_col)?;

        let result: StringArray = dates
            .iter()
            .zip(times.iter())
            .map(|(opt_d, opt_t)| match (opt_d, opt_t) {
                (Some(d), Some(t)) => Some(format!("{} {}", d.trim(), t.trim())),
                (Some(d), None) => Some(d.to_string()),
                _ => None,
            })
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "to_timestamp",
        vec![DataType::Utf8, DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        to_ts_fn,
    ));

    // 3. INDEX_OF(str, substr) — 0-based index of substring (or -1 if not found)
    let index_of_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let len = args.iter().find_map(|a| match a {
            ColumnarValue::Array(arr) => Some(arr.len()),
            _ => None,
        }).unwrap_or(1);

        let s_col = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };
        let sub_col = match &args[1] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array_of_size(len)?,
        };

        let strs = as_string_array(&s_col)?;
        let subs = as_string_array(&sub_col)?;

        let result: Int64Array = strs
            .iter()
            .zip(subs.iter())
            .map(|(opt_s, opt_sub)| match (opt_s, opt_sub) {
                (Some(s), Some(sub)) => Some(s.find(sub).map(|p| p as i64).unwrap_or(-1)),
                _ => None,
            })
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "index_of",
        vec![DataType::Utf8, DataType::Utf8],
        Arc::new(DataType::Int64),
        Volatility::Immutable,
        index_of_fn,
    ));

    // 4. EXTRACT_EXTENSION(path) — extracts file extension from URI or path (Log Parser 2.2 classic)
    let ext_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr
            .iter()
            .map(|opt_s| {
                opt_s.map(|s| {
                    let clean = s.split('?').next().unwrap_or(s);
                    let fname = clean.rsplit(['/', '\\']).next().unwrap_or(clean);
                    match fname.rfind('.') {
                        Some(idx) if idx > 0 => fname[idx..].to_lowercase(),
                        _ => String::new(),
                    }
                })
            })
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "extract_extension",
        vec![DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        ext_fn,
    ));

    // 5. EXTRACT_FILENAME(path) — extracts filename from URI or file path (Log Parser 2.2)
    let fname_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr
            .iter()
            .map(|opt_s| {
                opt_s.map(|s| {
                    let clean = s.split('?').next().unwrap_or(s);
                    clean.rsplit(['/', '\\']).next().unwrap_or(clean).to_string()
                })
            })
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "extract_filename",
        vec![DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        fname_fn,
    ));

    // 6. EXTRACT_PATH(path) — extracts directory path before filename (Log Parser 2.2)
    let epath_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] {
            ColumnarValue::Array(a) => a.clone(),
            ColumnarValue::Scalar(s) => s.to_array()?,
        };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr
            .iter()
            .map(|opt_s| {
                opt_s.map(|s| {
                    let clean = s.split('?').next().unwrap_or(s);
                    match clean.rfind(['/', '\\']) {
                        Some(0) => "/".to_string(),
                        Some(idx) => clean[..idx].to_string(),
                        None => String::new(),
                    }
                })
            })
            .collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "extract_path",
        vec![DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        epath_fn,
    ));

    // 7. EXTRACT_PREFIX(str, index, sep) & EXTRACT_SUFFIX(str, index, sep) (Log Parser 2.2)
    let prefix_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let len = args.iter().find_map(|a| match a {
            ColumnarValue::Array(arr) => Some(arr.len()),
            _ => None,
        }).unwrap_or(1);
        let str_col = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(len)? };
        let idx_col = match &args[1] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(len)? };
        let sep_col = match &args[2] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(len)? };
        let strs = as_string_array(&str_col)?;
        let idxs = as_int64_array(&idx_col)?;
        let seps = as_string_array(&sep_col)?;
        let result: StringArray = (0..len).map(|i| {
            if strs.is_null(i) || idxs.is_null(i) || seps.is_null(i) { return None; }
            let s = strs.value(i);
            let n = idxs.value(i) as usize;
            let sep = seps.value(i);
            let parts: Vec<&str> = s.split(sep).collect();
            if n < parts.len() {
                Some(parts[..=n].join(sep))
            } else {
                Some(s.to_string())
            }
        }).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "extract_prefix",
        vec![DataType::Utf8, DataType::Int64, DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        prefix_fn,
    ));

    let suffix_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let len = args.iter().find_map(|a| match a {
            ColumnarValue::Array(arr) => Some(arr.len()),
            _ => None,
        }).unwrap_or(1);
        let str_col = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(len)? };
        let idx_col = match &args[1] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(len)? };
        let sep_col = match &args[2] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(len)? };
        let strs = as_string_array(&str_col)?;
        let idxs = as_int64_array(&idx_col)?;
        let seps = as_string_array(&sep_col)?;
        let result: StringArray = (0..len).map(|i| {
            if strs.is_null(i) || idxs.is_null(i) || seps.is_null(i) { return None; }
            let s = strs.value(i);
            let n = idxs.value(i) as usize;
            let sep = seps.value(i);
            let parts: Vec<&str> = s.split(sep).collect();
            if n + 1 < parts.len() {
                Some(parts[n + 1..].join(sep))
            } else {
                Some(String::new())
            }
        }).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf(
        "extract_suffix",
        vec![DataType::Utf8, DataType::Int64, DataType::Utf8],
        Arc::new(DataType::Utf8),
        Volatility::Immutable,
        suffix_fn,
    ));

    // 8. STRLEN, TO_UPPERCASE, TO_LOWERCASE, TO_INT, TO_REAL, TO_STRING (Log Parser 2.2 scalar functions)
    let strlen_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: Int64Array = str_arr.iter().map(|opt_s| opt_s.map(|s| s.len() as i64)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("strlen", vec![DataType::Utf8], Arc::new(DataType::Int64), Volatility::Immutable, strlen_fn));

    let to_upper_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|s| s.to_uppercase())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("to_uppercase", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, to_upper_fn));

    let to_lower_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|s| s.to_lowercase())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("to_lowercase", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, to_lower_fn));

    let to_int_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: Int64Array = str_arr.iter().map(|opt_s| opt_s.and_then(|s| s.trim().parse::<i64>().ok())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("to_int", vec![DataType::Utf8], Arc::new(DataType::Int64), Volatility::Immutable, to_int_fn));

    let to_real_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: Float64Array = str_arr.iter().map(|opt_s| opt_s.and_then(|s| s.trim().parse::<f64>().ok())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("to_real", vec![DataType::Utf8], Arc::new(DataType::Float64), Volatility::Immutable, to_real_fn));

    // 9. WIN32_ERROR_DESCRIPTION(code) — translates IIS sc-win32-status codes to human descriptions (Log Parser 2.2)
    let win32_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(describe_win32_error)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("win32_error_description", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, win32_fn));

    // 10. REVERSEDNS(ip) — classifies IP or resolves loopback/private ranges (Log Parser 2.2)
    let rdns_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|ip| {
            let clean = ip.split(':').next().unwrap_or(ip).trim();
            if clean == "127.0.0.1" || clean == "::1" { "localhost".to_string() }
            else if clean.starts_with("10.") || clean.starts_with("192.168.") || clean.starts_with("172.") { format!("internal-{}.corp.local", clean.replace('.', "-")) }
            else { clean.to_string() }
        })).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("reversedns", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, rdns_fn));

    // 11. EXTRACT_EMAIL(str) & EXTRACT_DOMAIN(str) — extracts clean email address or domain from SMTP/log strings
    let extract_email_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(extract_clean_email)).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("extract_email", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, extract_email_fn));

    let extract_domain_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let array = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&array)?;
        let result: StringArray = str_arr.iter().map(|opt_s| opt_s.map(|s| {
            let email = extract_clean_email(s);
            email.split('@').nth(1).unwrap_or("").to_lowercase()
        })).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("extract_domain", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, extract_domain_fn));

    // ------------------------------------------------------------------
    // Streaming / time-series UDFs (KSQL / Kusto / Azure Log Analytics style)
    // ------------------------------------------------------------------
    // time_bucket(date_str, time_str, minutes) → "HH:MM" truncated to N-minute buckets
    let time_bucket_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let n = args.iter().filter_map(|a| match a { ColumnarValue::Array(x) => Some(x.len()), _ => None }).max().unwrap_or(1);
        let to_vec = |cv: &ColumnarValue| -> Result<Arc<dyn arrow::array::Array>> {
            match cv { ColumnarValue::Array(a) => Ok(a.clone()), ColumnarValue::Scalar(s) => s.to_array_of_size(n) }
        };
        let d_v = to_vec(&args[0])?;
        let t_v = to_vec(&args[1])?;
        let m_v = to_vec(&args[2])?;
        let d_arr = as_string_array(&d_v)?;
        let t_arr = as_string_array(&t_v)?;
        let mins_arr = as_int64_array(&m_v)?;
        let result: StringArray = d_arr.iter().zip(t_arr.iter()).zip(mins_arr.iter()).map(|((d, t), m)| {
            let (d, t, m) = (d?, t?, m?);
            let bucket_mins = if m <= 0 { 1 } else { m };
            let parts: Vec<&str> = t.split(':').collect();
            if parts.len() >= 2 {
                if let (Ok(h), Ok(mm)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
                    let total = h * 60 + mm;
                    let bucketed = (total / bucket_mins) * bucket_mins;
                    return Some(format!("{} {:02}:{:02}", d, bucketed / 60, bucketed % 60));
                }
            }
            Some(d.to_string())
        }).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("time_bucket", vec![DataType::Utf8, DataType::Utf8, DataType::Int64], Arc::new(DataType::Utf8), Volatility::Immutable, time_bucket_fn));

    // date_diff_days(date1_str, date2_str) → integer day difference (2026-10-15 vs 2026-10-14 → 1)
    let date_diff_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let n = args.iter().filter_map(|a| match a { ColumnarValue::Array(x) => Some(x.len()), _ => None }).max().unwrap_or(1);
        let a_v = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(n)? };
        let b_v = match &args[1] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array_of_size(n)? };
        let a_arr = as_string_array(&a_v)?;
        let b_arr = as_string_array(&b_v)?;
        let result: Int64Array = a_arr.iter().zip(b_arr.iter()).map(|(a, b)| {
            let (a, b) = (a?, b?);
            let parse = |s: &str| -> Option<i64> {
                let p: Vec<&str> = s.split(['-', 'T', ' ']).collect();
                if p.len() >= 3 {
                    let (y, m, d) = (p[0].parse::<i64>().ok()?, p[1].parse::<i64>().ok()?, p[2].parse::<i64>().ok()?);
                    return Some(y * 365 + m * 30 + d);
                }
                None
            };
            Some(parse(a)? - parse(b)?)
        }).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("date_diff_days", vec![DataType::Utf8, DataType::Utf8], Arc::new(DataType::Int64), Volatility::Immutable, date_diff_fn));

    // percentile_approx via rank approximation — UDF returns rank fraction used with window functions
    // geoip_country(ip) → naive private/public label + first-octet region hint
    let geoip_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let v = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&v)?;
        let result: StringArray = str_arr.iter().map(|opt| opt.map(|ip| {
            let t = ip.trim();
            if t.starts_with("10.") || t.starts_with("192.168.") || t.starts_with("172.16.") || t.starts_with("127.") {
                "PRIVATE".to_string()
            } else if t.starts_with("198.51.100.") || t.starts_with("192.0.2.") || t.starts_with("203.0.113.") {
                "TEST-NET".to_string()
            } else {
                "PUBLIC".to_string()
            }
        })).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("geoip_scope", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, geoip_fn));

    // url_path(url) → strip query string, return clean stem
    let url_path_fn = Arc::new(|args: &[ColumnarValue]| -> Result<ColumnarValue> {
        let v = match &args[0] { ColumnarValue::Array(a) => a.clone(), ColumnarValue::Scalar(s) => s.to_array()? };
        let str_arr = as_string_array(&v)?;
        let result: StringArray = str_arr.iter().map(|opt| opt.map(|s| s.split('?').next().unwrap_or(s).to_string())).collect();
        Ok(ColumnarValue::Array(Arc::new(result)))
    });
    ctx.register_udf(create_udf("url_path", vec![DataType::Utf8], Arc::new(DataType::Utf8), Volatility::Immutable, url_path_fn));
}

fn extract_clean_email(s: &str) -> String {
    if let Some(m) = EMAIL_RE.find(s) {
        return m.as_str().to_lowercase();
    }
    if let (Some(lt), Some(gt)) = (s.find('<'), s.find('>')) {
        if gt > lt + 1 {
            return s[lt + 1..gt].trim().to_lowercase();
        }
    }
    s.trim_start_matches(['+', '-'])
        .trim_start_matches("FROM:")
        .trim_start_matches("from:")
        .trim_start_matches("TO:")
        .trim_start_matches("to:")
        .trim_matches(['<', '>', '"', '\'', ' '])
        .to_lowercase()
}

fn describe_win32_error(code: &str) -> String {
    match code.trim() {
        "0" => "The operation completed successfully".to_string(),
        "2" => "The system cannot find the file specified".to_string(),
        "3" => "The system cannot find the path specified".to_string(),
        "5" | "2147942405" => "Access is denied (ERROR_ACCESS_DENIED)".to_string(),
        "32" => "The process cannot access the file because it is being used by another process".to_string(),
        "64" | "2147942464" => "The specified network name is no longer available (Client reset/disconnected)".to_string(),
        "995" => "The I/O operation has been aborted because of either a thread exit or an application request".to_string(),
        "1229" => "An operation was attempted on a nonexistent network connection".to_string(),
        "12002" => "The request has timed out (ERROR_INTERNET_TIMEOUT)".to_string(),
        "12029" => "A connection with the server could not be established (ERROR_INTERNET_CANNOT_CONNECT)".to_string(),
        "12030" => "The connection with the server was terminated abnormally".to_string(),
        "12152" => "The server returned an invalid or unrecognized response".to_string(),
        other => format!("Win32 Status {}", other),
    }
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
