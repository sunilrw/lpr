use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct QueryTranslation {
    pub sql: String,
    pub was_english_translated: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AutoCorrectSuggestion {
    pub corrected_sql: String,
    pub changes: Vec<String>,
}

const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "DISTINCT", "TOP", "FROM", "WHERE", "GROUP", "BY", "ORDER", "ASC", "DESC", "LIMIT",
    "OFFSET", "HAVING", "AS", "AND", "OR", "NOT", "IN", "IS", "NULL", "LIKE", "ILIKE", "BETWEEN",
    "CASE", "WHEN", "THEN", "ELSE", "END", "CAST", "INT", "INTEGER", "BIGINT", "FLOAT", "DOUBLE",
    "VARCHAR", "TEXT", "UNION", "ALL", "JOIN", "INNER", "LEFT", "RIGHT", "ON", "INTO", "TRUE",
    "FALSE", "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "LOWER", "UPPER", "SUBSTR", "TRIM",
    "ROUND",
];

const KNOWN_UDFS: &[&str] = &[
    "detect_threat",
    "ip_in_cidr",
    "shannon_entropy",
    "mask_pii",
    "cluster_template",
    "url_decode",
    "parse_ua",
    "extract_email",
    "extract_domain",
    "extract_token",
    "extract_prefix",
    "extract_suffix",
    "extract_filename",
    "extract_path",
    "extract_extension",
    "win32_error_description",
    "reversedns",
    "to_timestamp",
    "index_of",
    "strlen",
    "to_uppercase",
    "to_lowercase",
    "to_int",
    "to_real",
    "geoip_scope",
    "time_bucket",
];

static RE_LIKE_GLOB_STAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(NOT\s+)?(I?LIKE)\s+'([^'%]*\*[^'%]*)'").unwrap()
});

static RE_HYBRID_STARTS_WITH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-zA-Z0-9_."-]+)\s+(?:starts|start|begins|begin)\s+with\s+(?:'([^']+)'|"([^"]+)"|(\S+))"#).unwrap()
});

static RE_HYBRID_ENDS_WITH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-zA-Z0-9_."-]+)\s+(?:ends|end)\s+with\s+(?:'([^']+)'|"([^"]+)"|(\S+))"#).unwrap()
});

static RE_HYBRID_CONTAINS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-zA-Z0-9_."-]+)\s+(?:contains|contain|containing|has|having|includes)\s+(?:'([^']+)'|"([^"]+)"|(\S+))"#).unwrap()
});

static RE_HYBRID_EQUALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-zA-Z0-9_."-]+)\s+(?:is|equals|equal\s+to)\s+(?:'([^']+)'|"([^"]+)"|([a-zA-Z0-9_./:-]+))"#).unwrap()
});

/// Formats a column identifier for DataFusion SQL: wraps in double quotes if it contains uppercase letters.
pub fn quote_col_if_needed(col: &str) -> String {
    let clean = col.trim_matches('"');
    if clean.chars().any(|c| c.is_ascii_uppercase()) {
        format!("\"{}\"", clean)
    } else {
        clean.to_string()
    }
}

/// Resolves a semantic concept (e.g. "user_agent", "uri_stem", "client_ip", "status", "date", "time_taken")
/// to the actual column name present in `known_columns`, formatted for DataFusion.
pub fn resolve_concept_column(concept: &str, known_columns: &[String]) -> Option<String> {
    let candidates: &[&str] = match concept {
        "user_agent" => &[
            "csuser_agent",
            "UserAgent",
            "user_agent",
            "http_user_agent",
            "cs_user_agent",
            "ua",
        ],
        "client_ip" => &[
            "c_ip",
            "ClientIP",
            "client_ip",
            "remote_addr",
            "srcip",
            "src_ip",
            "remote_ip",
            "ip",
        ],
        "server_ip" => &["s_ip", "ServerIP", "server_ip", "dstip", "dst_ip", "target_ip"],
        "server_name" => &[
            "server_name",
            "ServerName",
            "s_computername",
            "host",
            "devname",
            "s_sitename",
        ],
        "uri_stem" => &[
            "cs_uri_stem",
            "UriStem",
            "url_path",
            "request_uri",
            "uri",
            "url",
            "path",
            "key",
        ],
        "uri_query" => &["cs_uri_query", "UriQuery", "query_string", "query", "sample_query_or_error"],
        "status" => &[
            "sc_status",
            "Status",
            "status_code",
            "status",
            "http_status",
            "elb_status_code",
        ],
        "substatus" => &["sc_substatus", "SubStatus", "substatus"],
        "win32_status" => &["sc_win32_status", "Win32Status", "win32_status"],
        "method" => &["cs_method", "Method", "http_verb", "method", "operation"],
        "time_taken" => &[
            "time_taken",
            "TimeTakenMs",
            "max_time_taken_ms",
            "total_time",
            "target_processing_time",
            "latency_ms",
        ],
        "date" => &["date", "Date", "time_local", "timestamp", "first_seen"],
        "time" => &["time", "Time", "time_local", "timestamp"],
        "cookie" => &["cscookie", "Cookie", "cookie"],
        "referer" => &["csreferer", "Referer", "http_referer", "referrer"],
        "username" => &["cs_username", "Username", "remote_user", "user", "requester"],
        "log_file" => &["log_filename", "LogFile", "file"],
        "log_row" => &["log_row", "LogRow", "line_number"],
        _ => &[],
    };

    for &cand in candidates {
        if let Some(found) = known_columns
            .iter()
            .find(|c| c.eq_ignore_ascii_case(cand))
        {
            return Some(quote_col_if_needed(found));
        }
    }
    None
}

/// Maps natural English column phrases (e.g. "user agent", "client ip", "url", "status code") to a concept key.
pub fn english_phrase_to_concept(phrase: &str) -> Option<&'static str> {
    let p = phrase.trim().to_ascii_lowercase();
    match p.as_str() {
        "user agent" | "user agents" | "useragent" | "user_agent" | "user-agent" | "browser"
        | "browsers" | "ua" | "agent" => Some("user_agent"),
        "client ip" | "client ips" | "clientip" | "ip address" | "ip addresses" | "source ip"
        | "remote ip" | "visitor ip" | "ip" | "ips" => Some("client_ip"),
        "server ip" | "serverip" => Some("server_ip"),
        "server" | "servers" | "server name" | "servername" | "hostname" | "computer name" => {
            Some("server_name")
        }
        "url" | "urls" | "uri" | "uris" | "uri stem" | "uristem" | "path" | "paths" | "page"
        | "pages" | "endpoint" | "endpoints" => Some("uri_stem"),
        "query string" | "querystring" | "uri query" | "uriquery" | "query params" | "params" => {
            Some("uri_query")
        }
        "status" | "status code" | "status codes" | "http status" | "error code"
        | "response code" => Some("status"),
        "substatus" | "sub status" => Some("substatus"),
        "win32 status" | "win32" | "win32 code" => Some("win32_status"),
        "method" | "methods" | "verb" | "http method" => Some("method"),
        "time taken" | "timetaken" | "latency" | "duration" | "response time" => {
            Some("time_taken")
        }
        "date" | "dates" | "day" => Some("date"),
        "time" | "times" => Some("time"),
        "cookie" | "cookies" => Some("cookie"),
        "referer" | "referrer" | "referers" => Some("referer"),
        "username" | "user" | "users" => Some("username"),
        "log file" | "logfile" | "filename" | "file" => Some("log_file"),
        _ => None,
    }
}

/// Damerau-Levenshtein distance (supports adjacent transpositions, insertions, deletions, substitutions).
pub fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let len_a = a_chars.len();
    let len_b = b_chars.len();
    if len_a == 0 {
        return len_b;
    }
    if len_b == 0 {
        return len_a;
    }

    let mut dp = vec![vec![0usize; len_b + 1]; len_a + 1];
    for i in 0..=len_a {
        dp[i][0] = i;
    }
    for j in 0..=len_b {
        dp[0][j] = j;
    }

    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
            if i > 1
                && j > 1
                && a_chars[i - 1] == b_chars[j - 2]
                && a_chars[i - 2] == b_chars[j - 1]
            {
                dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + cost);
            }
        }
    }
    dp[len_a][len_b]
}

/// Normalizes an identifier for fuzzy comparison (lowercase, strips `_`, `-`, `"`, `[`, `]`).
fn norm_ident(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Finds the closest matching column name in `known_columns` for a potentially misspelled token `token`.
pub fn find_closest_column(token: &str, known_columns: &[String]) -> Option<(String, usize)> {
    let t_norm = norm_ident(token);
    if t_norm.len() < 2 {
        return None;
    }

    // Check semantic English alias first (e.g. "useragent", "uristem", "url", "ip", "status")
    if let Some(concept) = english_phrase_to_concept(&t_norm) {
        if let Some(resolved) = resolve_concept_column(concept, known_columns) {
            return Some((resolved, 0));
        }
    }

    // Check exact normalized match (e.g. `uristem` -> `"UriStem"` or `cs_uri_stem`)
    for col in known_columns {
        if norm_ident(col) == t_norm {
            return Some((quote_col_if_needed(col), 0));
        }
    }

    // Cross-schema aliases (e.g. W3C `cs_uri_stem` vs Fleet CSV `UriStem`)
    let cross_concept = match t_norm.as_str() {
        "csuristem" | "uristem" | "urlpath" | "requesturi" => Some("uri_stem"),
        "csuriquery" | "uriquery" | "querystring" => Some("uri_query"),
        "scstatus" | "statuscode" | "httpstatus" => Some("status"),
        "scsubstatus" | "substatus" => Some("substatus"),
        "scwin32status" | "win32status" => Some("win32_status"),
        "csmethod" | "httpverb" => Some("method"),
        "cip" | "clientip" | "remoteaddr" | "srcip" => Some("client_ip"),
        "sip" | "serverip" | "dstip" => Some("server_ip"),
        "scomputername" | "servername" => Some("server_name"),
        "csuseragent" | "useragent" | "httpuseragent" => Some("user_agent"),
        "csreferer" | "referer" | "httpreferer" => Some("referer"),
        "cscookie" | "cookie" => Some("cookie"),
        "timetaken" | "timetakenms" | "maxtimetakenms" => Some("time_taken"),
        "logfilename" | "logfile" => Some("log_file"),
        "logrow" | "linenumber" => Some("log_row"),
        _ => None,
    };
    if let Some(concept) = cross_concept {
        if let Some(resolved) = resolve_concept_column(concept, known_columns) {
            return Some((resolved, 0));
        }
    }

    // Fuzzy Damerau-Levenshtein match against `known_columns`
    let mut best: Option<(String, usize, f64)> = None;
    for col in known_columns {
        let c_norm = norm_ident(col);
        let dist = damerau_levenshtein(&t_norm, &c_norm);
        let max_len = t_norm.len().max(c_norm.len());
        let sim = 1.0 - (dist as f64 / max_len as f64);
        let max_allowed_dist = if max_len <= 4 {
            1
        } else if max_len <= 7 {
            2
        } else {
            3
        };
        if dist <= max_allowed_dist && sim >= 0.65 {
            if best
                .as_ref()
                .map(|(_, bd, bs)| dist < *bd || (dist == *bd && sim > *bs))
                .unwrap_or(true)
            {
                best = Some((quote_col_if_needed(col), dist, sim));
            }
        }
    }

    best.map(|(col, dist, _)| (col, dist))
}

/// Finds the closest SQL keyword for a typo like `SELETC`, `FORM`, `WHER`, `GROPU`, `LIMTI`, `LKIE`.
pub fn find_closest_sql_keyword(token: &str) -> Option<(&'static str, usize)> {
    let upper = token.to_ascii_uppercase();
    if upper.len() < 3 {
        return None;
    }
    for &kw in SQL_KEYWORDS {
        if kw == upper {
            return Some((kw, 0));
        }
    }
    let mut best: Option<(&'static str, usize)> = None;
    for &kw in SQL_KEYWORDS {
        if kw.len() < 4 {
            continue;
        }
        let dist = damerau_levenshtein(&upper, kw);
        let max_dist = if kw.len() <= 5 { 1 } else { 2 };
        if dist <= max_dist && upper.chars().next() == kw.chars().next() {
            if best.map(|(_, bd)| dist < bd).unwrap_or(true) {
                best = Some((kw, dist));
            }
        }
    }
    best
}

/// Translates Plain-English queries or Hybrid SQL+English queries into valid DataFusion SQL without AI.
/// Examples:
///   - `find unique user agent from todays logs`
///   - `top 10 url with 500 errors`
///   - `count by status and server where url contains /cat`
///   - `SELECT * FROM logs where url starts with /cat and status is 302`
pub fn translate_natural_or_hybrid_sql(
    input: &str,
    known_columns: &[String],
) -> QueryTranslation {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return QueryTranslation {
            sql: "SELECT * FROM logs LIMIT 50".to_string(),
            was_english_translated: false,
            note: None,
        };
    }

    // Check if the query starts with SQL (`SELECT`, `WITH`, `EXPLAIN`, `:filter-`) or a minor typo of `SELECT` (`SELETC`, `SELCT`)
    let first_word = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let starts_like_sql = matches!(
        first_word.as_str(),
        "SELECT" | "WITH" | "EXPLAIN" | "SHOW" | "DESCRIBE"
    ) || trimmed.starts_with(":filter-")
        || (first_word.starts_with('S') && damerau_levenshtein(&first_word, "SELECT") <= 2);

    if starts_like_sql {
        // Hybrid SQL + English normalization (e.g. `where url starts with /cat`, `like '/cat*'`, mixed-case columns)
        let (rewritten, hybrid_notes) = rewrite_hybrid_sql_clauses(trimmed, known_columns);
        let note = if hybrid_notes.is_empty() {
            None
        } else {
            Some(hybrid_notes.join("; "))
        };
        return QueryTranslation {
            sql: rewritten,
            was_english_translated: !hybrid_notes.is_empty(),
            note,
        };
    }

    // Pure English Grammar -> SQL Compiler!
    let compiled = compile_english_grammar_to_sql(trimmed, known_columns);
    QueryTranslation {
        note: Some(format!("Translated English query -> `{}`", compiled)),
        sql: compiled,
        was_english_translated: true,
    }
}

/// Rewrites hybrid English phrases inside an otherwise SQL query:
/// - `where url starts with /cat` -> `WHERE "UriStem" ILIKE '/cat%'`
/// - `where uri contains /api` -> `WHERE "UriStem" ILIKE '%/api%'`
/// - `where status is 500` -> `WHERE "Status" = '500'`
/// - `LIKE '/cat*'` -> `ILIKE '/cat%'`
/// - Case-insensitive column resolution (`uristem` -> `"UriStem"`)
fn rewrite_hybrid_sql_clauses(sql: &str, known_columns: &[String]) -> (String, Vec<String>) {
    let mut working = sql.to_string();
    let mut notes = Vec::new();

    // 1. Convert `col starts with val`
    working = RE_HYBRID_STARTS_WITH
        .replace_all(&working, |caps: &regex::Captures| {
            let raw_col = &caps[1];
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str().trim_matches(['\'', '"', '*']))
                .unwrap_or("");
            let col = find_closest_column(raw_col, known_columns)
                .map(|(c, _)| c)
                .unwrap_or_else(|| raw_col.to_string());
            notes.push(format!("`{} starts with {}` -> `{} ILIKE '{}%'`", raw_col, val, col, val));
            format!("{} ILIKE '{}%'", col, val.replace('\'', "''"))
        })
        .into_owned();

    // 2. Convert `col ends with val`
    working = RE_HYBRID_ENDS_WITH
        .replace_all(&working, |caps: &regex::Captures| {
            let raw_col = &caps[1];
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str().trim_matches(['\'', '"', '*']))
                .unwrap_or("");
            let col = find_closest_column(raw_col, known_columns)
                .map(|(c, _)| c)
                .unwrap_or_else(|| raw_col.to_string());
            notes.push(format!("`{} ends with {}` -> `{} ILIKE '%{}'`", raw_col, val, col, val));
            format!("{} ILIKE '%{}'", col, val.replace('\'', "''"))
        })
        .into_owned();

    // 3. Convert `col contains val`
    working = RE_HYBRID_CONTAINS
        .replace_all(&working, |caps: &regex::Captures| {
            let raw_col = &caps[1];
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str().trim_matches(['\'', '"', '*']))
                .unwrap_or("");
            let col = find_closest_column(raw_col, known_columns)
                .map(|(c, _)| c)
                .unwrap_or_else(|| raw_col.to_string());
            notes.push(format!("`{} contains {}` -> `{} ILIKE '%{}%'`", raw_col, val, col, val));
            format!("{} ILIKE '%{}%'", col, val.replace('\'', "''"))
        })
        .into_owned();

    // 4. Convert `col is val` / `col equals val`
    working = RE_HYBRID_EQUALS
        .replace_all(&working, |caps: &regex::Captures| {
            let raw_col = &caps[1];
            if raw_col.eq_ignore_ascii_case("where")
                || raw_col.eq_ignore_ascii_case("and")
                || raw_col.eq_ignore_ascii_case("or")
            {
                return caps[0].to_string();
            }
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str().trim_matches(['\'', '"']))
                .unwrap_or("");
            if val.eq_ignore_ascii_case("null") || val.eq_ignore_ascii_case("not") {
                return caps[0].to_string();
            }
            let col = find_closest_column(raw_col, known_columns)
                .map(|(c, _)| c)
                .unwrap_or_else(|| raw_col.to_string());
            notes.push(format!("`{} is {}` -> `{} = '{}'`", raw_col, val, col, val));
            format!("{} = '{}'", col, val.replace('\'', "''"))
        })
        .into_owned();

    // 5. Convert glob `*` inside `LIKE '/cat*'` -> `ILIKE '/cat%'`
    working = RE_LIKE_GLOB_STAR
        .replace_all(&working, |caps: &regex::Captures| {
            let not_kw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let pat = caps[3].replace('*', "%");
            notes.push(format!("Converted wildcard `'{}'` -> `'{}'`", &caps[3], pat));
            format!("{}ILIKE '{}'", not_kw, pat)
        })
        .into_owned();

    // 6. Resolve exact case-insensitive or cross-schema column names outside single quotes
    working = resolve_exact_columns_outside_quotes(&working, known_columns);

    (working, notes)
}

/// Replaces unquoted column identifiers that match `known_columns` case-insensitively (dist == 0)
/// with their properly quoted form (e.g. `uristem` -> `"UriStem"`).
pub fn resolve_exact_columns_outside_quotes(sql: &str, known_columns: &[String]) -> String {
    if known_columns.is_empty() {
        return sql.to_string();
    }
    static IDENT_TOKEN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""[^"]+"|[a-zA-Z_][a-zA-Z0-9_-]*"#).unwrap());

    let mut out = String::with_capacity(sql.len() + 16);
    let mut in_single = false;
    let mut seg_start = 0;
    let bytes = sql.as_bytes();

    let transform_segment = |seg: &str| -> String {
        IDENT_TOKEN_RE
            .replace_all(seg, |caps: &regex::Captures| {
                let tok = &caps[0];
                if tok.starts_with('"') {
                    // Even if double-quoted, check if case differs from `known_columns`
                    let inner = tok.trim_matches('"');
                    if let Some(found) = known_columns
                        .iter()
                        .find(|c| c.eq_ignore_ascii_case(inner))
                    {
                        return quote_col_if_needed(found);
                    }
                    return tok.to_string();
                }
                let upper = tok.to_ascii_uppercase();
                if SQL_KEYWORDS.contains(&upper.as_str())
                    || tok.eq_ignore_ascii_case("logs")
                    || KNOWN_UDFS.iter().any(|u| u.eq_ignore_ascii_case(tok))
                {
                    return tok.to_string();
                }
                if let Some((resolved, 0)) = find_closest_column(tok, known_columns) {
                    return resolved;
                }
                tok.to_string()
            })
            .into_owned()
    };

    for i in 0..bytes.len() {
        if bytes[i] == b'\'' {
            let seg = &sql[seg_start..i];
            if in_single {
                out.push_str(seg);
            } else {
                out.push_str(&transform_segment(seg));
            }
            out.push('\'');
            in_single = !in_single;
            seg_start = i + 1;
        }
    }
    let tail = &sql[seg_start..];
    if in_single {
        out.push_str(tail);
    } else {
        out.push_str(&transform_segment(tail));
    }
    out
}

/// Inspects a SQL query for near-miss column or keyword typos (e.g. `UriStrem` -> `"UriStem"`, `LIKE '/cat*'`)
/// and returns `Some(AutoCorrectSuggestion)` if a high-confidence correction is found.
pub fn suggest_sql_autocorrect(
    sql: &str,
    known_columns: &[String],
) -> Option<AutoCorrectSuggestion> {
    if known_columns.is_empty() {
        return None;
    }
    static IDENT_TOKEN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""[^"]+"|[a-zA-Z_][a-zA-Z0-9_-]*"#).unwrap());

    let (mut working, mut changes) = rewrite_hybrid_sql_clauses(sql, known_columns);

    let mut out = String::with_capacity(working.len() + 16);
    let mut in_single = false;
    let mut seg_start = 0;
    let bytes = working.as_bytes();

    let mut fix_segment = |seg: &str| -> String {
        IDENT_TOKEN_RE
            .replace_all(seg, |caps: &regex::Captures| {
                let tok = &caps[0];
                let clean = tok.trim_matches('"');
                let upper = clean.to_ascii_uppercase();
                if SQL_KEYWORDS.contains(&upper.as_str())
                    || clean.eq_ignore_ascii_case("logs")
                    || KNOWN_UDFS.iter().any(|u| u.eq_ignore_ascii_case(clean))
                {
                    return tok.to_string();
                }
                // Check if already an exact column
                if let Some(exact) = known_columns
                    .iter()
                    .find(|c| c.eq_ignore_ascii_case(clean))
                {
                    return quote_col_if_needed(exact);
                }
                // 1. Check fuzzy column match first
                if let Some((best_col, dist)) = find_closest_column(clean, known_columns) {
                    if dist > 0 {
                        changes.push(format!("`{}` -> `{}`", tok, best_col));
                    }
                    return best_col;
                }
                // 2. Check fuzzy SQL keyword match (e.g. `SELETC`, `WHER`, `FORM`, `LIMTI`)
                if !tok.starts_with('"') {
                    if let Some((kw, dist)) = find_closest_sql_keyword(clean) {
                        if dist > 0 {
                            changes.push(format!("`{}` -> `{}`", tok, kw));
                            return kw.to_string();
                        }
                    }
                }
                tok.to_string()
            })
            .into_owned()
    };

    for i in 0..bytes.len() {
        if bytes[i] == b'\'' {
            let seg = &working[seg_start..i];
            if in_single {
                out.push_str(seg);
            } else {
                out.push_str(&fix_segment(seg));
            }
            out.push('\'');
            in_single = !in_single;
            seg_start = i + 1;
        }
    }
    let tail = &working[seg_start..];
    if in_single {
        out.push_str(tail);
    } else {
        out.push_str(&fix_segment(tail));
    }
    working = out;

    if changes.is_empty() && working.trim() == sql.trim() {
        None
    } else {
        Some(AutoCorrectSuggestion {
            corrected_sql: working,
            changes,
        })
    }
}

/// Deterministic Rule-Based English Grammar -> SQL Compiler (Zero AI).
fn compile_english_grammar_to_sql(english: &str, known_columns: &[String]) -> String {
    let lower = english.to_ascii_lowercase();

    // 1. Detect Aggregation / Distinct / Top N / Slowest Intent
    let is_unique = lower.contains("unique ")
        || lower.contains("distinct ")
        || lower.starts_with("unique ");
    let is_count_group = lower.contains("count by ")
        || lower.contains("group by ")
        || lower.contains("breakdown by ")
        || lower.contains("summary by ")
        || lower.starts_with("count ")
        || lower.contains("with count");
    let is_how_many = lower.starts_with("how many ") || lower.starts_with("total count");
    let is_slowest = lower.contains("slowest")
        || lower.contains("highest latency")
        || lower.contains("longest time");

    // Extract explicit Top N / Limit N
    static RE_TOP_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:top|limit|first|slowest)\s+(\d+)\b").unwrap()
    });
    let explicit_limit: Option<usize> = RE_TOP_LIMIT
        .captures(&lower)
        .and_then(|c| c[1].parse::<usize>().ok());
    let is_top = lower.starts_with("top ") || lower.contains(" top ") || lower.contains("most frequent") || lower.contains("most common");

    // 2. Discover which columns are mentioned in the English sentence
    let mut mentioned_cols: Vec<String> = Vec::new();
    let mut add_col = |col: String| {
        if !mentioned_cols.contains(&col) {
            mentioned_cols.push(col);
        }
    };

    // Multi-word concepts first
    let multi_word_concepts = [
        ("user agents", "user_agent"),
        ("user agent", "user_agent"),
        ("useragent", "user_agent"),
        ("browsers", "user_agent"),
        ("browser", "user_agent"),
        ("client ips", "client_ip"),
        ("client ip", "client_ip"),
        ("ip addresses", "client_ip"),
        ("ip address", "client_ip"),
        ("source ip", "client_ip"),
        ("visitor ip", "client_ip"),
        ("server ip", "server_ip"),
        ("server name", "server_name"),
        ("servers", "server_name"),
        ("server", "server_name"),
        ("uri stem", "uri_stem"),
        ("uristem", "uri_stem"),
        ("query string", "uri_query"),
        ("uri query", "uri_query"),
        ("uriquery", "uri_query"),
        ("status codes", "status"),
        ("status code", "status"),
        ("http status", "status"),
        ("win32 status", "win32_status"),
        ("substatus", "substatus"),
        ("sub status", "substatus"),
        ("time taken", "time_taken"),
        ("response time", "time_taken"),
        ("latency", "time_taken"),
        ("urls", "uri_stem"),
        ("url", "uri_stem"),
        ("uris", "uri_stem"),
        ("uri", "uri_stem"),
        ("endpoints", "uri_stem"),
        ("endpoint", "uri_stem"),
        ("pages", "uri_stem"),
        ("page", "uri_stem"),
        ("paths", "uri_stem"),
        ("cookies", "cookie"),
        ("cookie", "cookie"),
        ("referer", "referer"),
        ("referrer", "referer"),
        ("methods", "method"),
        ("method", "method"),
        ("ips", "client_ip"),
    ];

    // Split sentence into target part (before `where` / `with` / `having` / `for` / `in` / `from`) vs filter part
    static RE_FILTER_SPLIT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:where|with|having|when|whose)\b").unwrap()
    });
    let target_part = if let Some(m) = RE_FILTER_SPLIT.find(&lower) {
        &lower[..m.start()]
    } else {
        &lower[..]
    };

    for (phrase, concept) in multi_word_concepts {
        if contains_word_phrase(target_part, phrase) {
            if let Some(c) = resolve_concept_column(concept, known_columns) {
                add_col(c);
            }
        }
    }
    // Check standalone "ip" or "status" or "path" in target_part
    for (word, concept) in [
        ("ip", "client_ip"),
        ("status", "status"),
        ("path", "uri_stem"),
    ] {
        if contains_word_phrase(target_part, word) {
            if let Some(c) = resolve_concept_column(concept, known_columns) {
                add_col(c);
            }
        }
    }
    // Also check if any exact column name from `known_columns` is mentioned in `target_part`
    for col in known_columns {
        let c_lower = col.to_ascii_lowercase();
        if c_lower.len() >= 3 && contains_word_phrase(target_part, &c_lower) {
            add_col(quote_col_if_needed(col));
        }
    }

    // 3. Extract WHERE filters from the English sentence
    let mut where_clauses: Vec<String> = Vec::new();

    // 3a. Date filter: "todays logs" / "today's logs" / "today"
    if lower.contains("today") {
        if let Some(date_col) = resolve_concept_column("date", known_columns) {
            where_clauses.push(format!(
                "{} = (SELECT MAX({}) FROM logs)",
                date_col, date_col
            ));
        }
    } else if lower.contains("yesterday") {
        if let Some(date_col) = resolve_concept_column("date", known_columns) {
            let yest = (chrono::Utc::now().date_naive() - chrono::Duration::days(1))
                .format("%Y-%m-%d")
                .to_string();
            where_clauses.push(format!("{} = '{}'", date_col, yest));
        }
    }

    // 3b. Status code filters: "500 errors", "5xx", "status 302", "getting 302", "404"
    static RE_STATUS_CODE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:status(?:\s+code)?(?:\s+is|\s*=)?\s*|getting\s+|http\s+|with\s+)?([2345]\d{2}|[45]xx)\b(?:\s+errors?|\s+redirects?|\s+status)?").unwrap()
    });
    if let Some(status_col) = resolve_concept_column("status", known_columns) {
        let mut added_status = false;
        for caps in RE_STATUS_CODE.captures_iter(&lower) {
            let code = &caps[1];
            // Avoid matching a number that was part of `top 200` or `limit 500`
            let match_start = caps.get(1).unwrap().start();
            let before = lower[..match_start].trim_end();
            if before.ends_with("top")
                || before.ends_with("limit")
                || before.ends_with("first")
                || before.ends_with("slowest")
            {
                continue;
            }
            if code.eq_ignore_ascii_case("5xx") {
                where_clauses.push(format!("{} LIKE '5%'", status_col));
            } else if code.eq_ignore_ascii_case("4xx") {
                where_clauses.push(format!("{} LIKE '4%'", status_col));
            } else {
                where_clauses.push(format!("{} = '{}'", status_col, code));
            }
            added_status = true;
        }
        if !added_status && (lower.contains("server error") || lower.contains("failed")) {
            where_clauses.push(format!("{} LIKE '5%'", status_col));
        } else if !added_status && lower.contains("redirect") {
            where_clauses.push(format!("{} LIKE '3%'", status_col));
        }
    }

    // 3c. Path / URL literal filters (e.g. `/cat*`, `/partner-api/`, `starts with /cat`, `contains /api`)
    static RE_SLASH_PATH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:^|[\s'"])(/[a-zA-Z0-9_./*-]+)"#).unwrap()
    });
    if let Some(uri_col) = resolve_concept_column("uri_stem", known_columns) {
        for caps in RE_SLASH_PATH.captures_iter(english) {
            let raw_path = caps[1].trim_matches(['\'', '"', ',', ';']);
            if raw_path.len() >= 2 {
                let starts_with_intent = lower.contains("starts with")
                    || lower.contains("starting with")
                    || lower.contains("begins with")
                    || raw_path.ends_with('*');
                let clean_path = raw_path.trim_matches('*').replace('\'', "''");
                let cond = if starts_with_intent {
                    format!("{} ILIKE '{}%'", uri_col, clean_path)
                } else {
                    format!("{} ILIKE '%{}%'", uri_col, clean_path)
                };
                if !where_clauses.contains(&cond) {
                    where_clauses.push(cond);
                }
            }
        }
    }

    // 3d. IP address literal filter (e.g. `for ip 203.0.113.5`)
    static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b").unwrap()
    });
    if let Some(ip_col) = resolve_concept_column("client_ip", known_columns) {
        for caps in RE_IPV4.captures_iter(english) {
            let ip = &caps[1];
            where_clauses.push(format!("{} = '{}'", ip_col, ip));
        }
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_clauses.join(" AND "))
    };

    // 4. Construct final SELECT + FROM + WHERE + GROUP BY + ORDER BY + LIMIT
    if is_how_many {
        return format!("SELECT COUNT(*) AS total_matches FROM logs{}", where_sql);
    }

    if is_slowest {
        let limit = explicit_limit.unwrap_or(25);
        if let Some(tt_col) = resolve_concept_column("time_taken", known_columns) {
            return format!(
                "SELECT * FROM logs{} ORDER BY CAST({} AS INT) DESC LIMIT {}",
                where_sql, tt_col, limit
            );
        }
    }

    if is_unique && !is_count_group && !is_top {
        let proj = if mentioned_cols.is_empty() {
            resolve_concept_column("user_agent", known_columns)
                .or_else(|| resolve_concept_column("client_ip", known_columns))
                .or_else(|| resolve_concept_column("uri_stem", known_columns))
                .unwrap_or_else(|| "*".to_string())
        } else {
            mentioned_cols.join(", ")
        };
        let limit = explicit_limit.unwrap_or(100);
        return format!(
            "SELECT DISTINCT {} FROM logs{} LIMIT {}",
            proj, where_sql, limit
        );
    }

    if is_top || is_count_group {
        let group_cols = if mentioned_cols.is_empty() {
            vec![resolve_concept_column("uri_stem", known_columns)
                .or_else(|| resolve_concept_column("client_ip", known_columns))
                .or_else(|| known_columns.first().map(|c| quote_col_if_needed(c)))
                .unwrap_or_else(|| "*".to_string())]
        } else {
            mentioned_cols
        };
        let group_indices: Vec<String> = (1..=group_cols.len()).map(|i| i.to_string()).collect();
        let limit = explicit_limit.unwrap_or(25);
        return format!(
            "SELECT {}, COUNT(*) AS hits FROM logs{} GROUP BY {} ORDER BY hits DESC LIMIT {}",
            group_cols.join(", "),
            where_sql,
            group_indices.join(", "),
            limit
        );
    }

    // Standard SELECT
    let proj = if mentioned_cols.is_empty() {
        "*".to_string()
    } else {
        mentioned_cols.join(", ")
    };
    let limit = explicit_limit.unwrap_or(100);
    format!("SELECT {} FROM logs{} LIMIT {}", proj, where_sql, limit)
}

fn contains_word_phrase(haystack_lower: &str, phrase_lower: &str) -> bool {
    let pattern = format!(r"\b{}\b", regex::escape(phrase_lower));
    Regex::new(&pattern)
        .map(|re| re.is_match(haystack_lower))
        .unwrap_or(false)
}
