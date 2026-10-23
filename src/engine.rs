use crate::checkpoint::CheckpointStore;
use crate::parsers::{
    clean_windows_path, detect_format_item, get_format_regex, parse_aws_vpc_files,
    parse_azure_blob_files, parse_cef_files, parse_cisco_asa_files, parse_cisco_config_files,
    parse_csv_items_parallel, parse_evtx_files, parse_excel_files, parse_firewall_kv_files,
    parse_ias_files, parse_json_files, parse_parquet_items, parse_raw_items_parallel,
    parse_regex_items_parallel_filtered, parse_w3c_items_parallel_filtered, resolve_paths,
    resolve_source_items, InputFormat, LogSourceItem, ParseStats, ScanPreFilter,
};
use crate::udfs::register_all_udfs;
use anyhow::Result;
use arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::sync::{Arc, LazyLock, Mutex};

static FROM_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bFROM\s+(?:'([^']+)'|"([^"]+)"|([a-zA-Z0-9_.*:/\\-]+))"#).unwrap()
});
static INTO_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bINTO\s+(?:'([^']+)'|"([^"]+)"|([a-zA-Z0-9_.*:/\\-]+))"#).unwrap()
});
static BRACKET_IDENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\[([a-zA-Z0-9_().-]+)\]"#).unwrap()
});
static TOP_N_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bSELECT\s+TOP\s+(\d+)\b"#).unwrap()
});
static LOWER_UPPER_LIKE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:LOWER|UPPER)\s*\(\s*([a-zA-Z0-9_.]+)\s*\)\s*(NOT\s+)?LIKE\s*('[^']*')"#).unwrap()
});

#[derive(Debug, Clone, Serialize)]
pub struct IntentSuggestion {
    pub title: String,
    pub category: String,
    pub description: String,
    pub sql: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaDiscovery {
    pub detected_format: String,
    pub columns: Vec<String>,
    pub row_count_estimate: usize,
    pub suggestions: Vec<IntentSuggestion>,
}

/// Inspects a SQL query for a Microsoft Log Parser style `FROM '<path_or_glob>'` or `FROM *.log`.
/// Returns `(rewritten_sql, Some(extracted_path))` if a file/glob was found in the FROM clause.
pub fn extract_source_from_sql(sql: &str) -> (String, Option<String>) {
    let (sql_no_into, _) = extract_into_from_sql(sql);
    if let Some(caps) = FROM_PATH_RE.captures(&sql_no_into) {
        let matched_token = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map(|m| m.as_str())
            .unwrap_or("");
        let looks_like_path = caps.get(1).is_some()
            || matched_token.eq_ignore_ascii_case("stdin")
            || matched_token == "-"
            || matched_token.contains('*')
            || matched_token.contains('?')
            || matched_token.contains('/')
            || matched_token.contains('\\')
            || matched_token.contains('.');
        if looks_like_path && !matched_token.eq_ignore_ascii_case("logs") {
            let full_match = caps.get(0).unwrap();
            let mut rewritten = String::with_capacity(sql_no_into.len());
            rewritten.push_str(&sql_no_into[..full_match.start()]);
            rewritten.push_str("FROM logs");
            rewritten.push_str(&sql_no_into[full_match.end()..]);
            return (rewritten, Some(matched_token.to_string()));
        }
    }
    (sql_no_into, None)
}

/// Inspects a SQL query for a Microsoft Log Parser 2.2 `INTO '<output_path>'` or `INTO out.csv` clause.
/// Returns `(sql_without_into, Some(into_target))` if an INTO clause was present.
pub fn extract_into_from_sql(sql: &str) -> (String, Option<String>) {
    if sql.trim_start().to_uppercase().starts_with("INSERT INTO") {
        return (sql.to_string(), None);
    }
    if let Some(caps) = INTO_PATH_RE.captures(sql) {
        let target = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if !target.is_empty() {
            let full_match = caps.get(0).unwrap();
            let mut rewritten = String::with_capacity(sql.len());
            rewritten.push_str(sql[..full_match.start()].trim_end());
            rewritten.push(' ');
            rewritten.push_str(sql[full_match.end()..].trim_start());
            return (rewritten.trim().to_string(), Some(target));
        }
    }
    (sql.to_string(), None)
}

/// Normalizes Microsoft Log Parser 2.2 & Linux lnav/jq dialects into ANSI DataFusion SQL:
/// - Converts `:filter-in <pattern>` or `:filter-out <pattern>` (lnav syntax) into SQL WHERE filters
/// - Converts `[sc-status]` or `[cs(User-Agent)]` into `sc_status` / `csUser_Agent`
/// - Converts `SELECT TOP N ...` into `SELECT ... LIMIT N`
/// - Replaces unquoted hyphenated W3C field names (e.g., `sc-status`, `time-taken`, `c-ip`, `cs-uri-stem`)
pub fn normalize_logparser_sql(sql: &str, known_columns: &[String]) -> String {
    let trimmed_input = sql.trim();

    // Linux lnav :filter-in <pattern> and :filter-out <pattern> support
    if let Some(pat) = trimmed_input.strip_prefix(":filter-in ") {
        let p = pat.trim().trim_matches(['\'', '"']).replace('\'', "''");
        let cond = build_universal_search_predicate(known_columns, &p, false);
        return format!("SELECT * FROM logs WHERE {}", cond);
    }
    if let Some(pat) = trimmed_input.strip_prefix(":filter-out ") {
        let p = pat.trim().trim_matches(['\'', '"']).replace('\'', "''");
        let cond = build_universal_search_predicate(known_columns, &p, true);
        return format!("SELECT * FROM logs WHERE {}", cond);
    }
    // jq-style "." shorthand
    if trimmed_input == "." || trimmed_input == ".[]" {
        return "SELECT * FROM logs".to_string();
    }

    let (mut working, _) = extract_source_from_sql(sql);

    // 0. Translate Natural English queries or Hybrid SQL+English grammar & glob wildcards (`LIKE '/cat*'`)
    let initial_nl = crate::nl2sql::translate_natural_or_hybrid_sql(&working, known_columns);
    working = initial_nl.sql;

    // 1. Convert [col-name] bracket identifiers
    working = BRACKET_IDENT_RE
        .replace_all(&working, |caps: &regex::Captures| {
            caps[1].replace('-', "_").replace(['(', ')'], "").to_lowercase()
        })
        .into_owned();

    // 2. Convert SELECT TOP N ... -> SELECT ... LIMIT N (if no LIMIT already exists)
    if let Some(caps) = TOP_N_RE.captures(&working.clone()) {
        let n = caps[1].to_string();
        working = TOP_N_RE.replace(&working, "SELECT").into_owned();
        if !working.to_uppercase().contains("LIMIT ") {
            let trimmed = working.trim_end().trim_end_matches(';');
            working = format!("{} LIMIT {}", trimmed, n);
        }
    }

    // 3. Replace common W3C / IIS hyphenated and parenthesized identifiers outside single quotes
    let mut w3c_candidates: Vec<(String, String)> = vec![
        ("cs(User-Agent)".to_string(), "csuser_agent".to_string()),
        ("cs(Referer)".to_string(), "csreferer".to_string()),
        ("cs(Cookie)".to_string(), "cscookie".to_string()),
        ("cs(Host)".to_string(), "cshost".to_string()),
        ("sc-win32-status".to_string(), "sc_win32_status".to_string()),
        ("sc-substatus".to_string(), "sc_substatus".to_string()),
        ("sc-status".to_string(), "sc_status".to_string()),
        ("sc-bytes".to_string(), "sc_bytes".to_string()),
        ("cs-bytes".to_string(), "cs_bytes".to_string()),
        ("cs-uri-stem".to_string(), "cs_uri_stem".to_string()),
        ("cs-uri-query".to_string(), "cs_uri_query".to_string()),
        ("cs-method".to_string(), "cs_method".to_string()),
        ("cs-username".to_string(), "cs_username".to_string()),
        ("cs-version".to_string(), "cs_version".to_string()),
        ("cs-host".to_string(), "cs_host".to_string()),
        ("s-computername".to_string(), "s_computername".to_string()),
        ("s-sitename".to_string(), "s_sitename".to_string()),
        ("s-ip".to_string(), "s_ip".to_string()),
        ("s-port".to_string(), "s_port".to_string()),
        ("c-ip".to_string(), "c_ip".to_string()),
        ("time-taken".to_string(), "time_taken".to_string()),
        ("LogFilename".to_string(), "log_filename".to_string()),
        ("LogRow".to_string(), "log_row".to_string()),
    ];

    for col in known_columns {
        if col.contains('_') {
            let hyphenated = col.replace('_', "-");
            if !w3c_candidates.iter().any(|(h, _)| h.eq_ignore_ascii_case(&hyphenated)) {
                w3c_candidates.push((hyphenated, col.clone()));
            }
        }
    }
    w3c_candidates.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let replaced = replace_outside_single_quotes(&working, &w3c_candidates);
    // 4. Rewrite LOWER(col) LIKE 'pat' / UPPER(col) LIKE 'pat' -> col ILIKE 'pat' to avoid allocating lowercase StringArrays
    let ilike_rewritten = LOWER_UPPER_LIKE_RE
        .replace_all(&replaced, |caps: &regex::Captures| {
            let col = &caps[1];
            let not_kw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let pat = &caps[3];
            format!("{} {}ILIKE {}", col, not_kw, pat)
        })
        .into_owned();

    // 5. Final pass to map any normalized W3C column names to mixed-case CSV columns (e.g. UriStem -> "UriStem")
    crate::nl2sql::translate_natural_or_hybrid_sql(&ilike_rewritten, known_columns).sql
}

pub fn build_universal_search_predicate(
    known_columns: &[String],
    pattern: &str,
    invert: bool,
) -> String {
    let escaped = pattern.replace('\'', "''");
    let cols: Vec<&str> = if known_columns.is_empty() {
        vec!["raw_line"]
    } else {
        known_columns.iter().map(|s| s.as_str()).collect()
    };
    if invert {
        let parts: Vec<String> = cols
            .iter()
            .map(|c| format!("COALESCE(CAST(\"{}\" AS VARCHAR), '') NOT ILIKE '%{}%'", c, escaped))
            .collect();
        parts.join(" AND ")
    } else {
        let parts: Vec<String> = cols
            .iter()
            .map(|c| format!("COALESCE(CAST(\"{}\" AS VARCHAR), '') ILIKE '%{}%'", c, escaped))
            .collect();
        format!("({})", parts.join(" OR "))
    }
}

fn replace_outside_single_quotes(sql: &str, replacements: &[(String, String)]) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut in_single = false;
    let mut segment_start = 0;
    let bytes = sql.as_bytes();

    for i in 0..bytes.len() {
        if bytes[i] == b'\'' {
            let chunk = &sql[segment_start..i];
            if in_single {
                result.push_str(chunk);
                result.push('\'');
            } else {
                result.push_str(&apply_token_replacements(chunk, replacements));
                result.push('\'');
            }
            in_single = !in_single;
            segment_start = i + 1;
        }
    }
    let tail = &sql[segment_start..];
    if in_single {
        result.push_str(tail);
    } else {
        result.push_str(&apply_token_replacements(tail, replacements));
    }
    result
}

fn apply_token_replacements(chunk: &str, replacements: &[(String, String)]) -> String {
    let mut out = chunk.to_string();
    for (from, to) in replacements {
        if out.to_lowercase().contains(&from.to_lowercase()) {
            let pattern = format!(r"(?i)\b{}\b", regex::escape(from));
            if let Ok(re) = Regex::new(&pattern) {
                out = re.replace_all(&out, to.as_str()).into_owned();
            } else {
                out = out.replace(from, to);
            }
        }
    }
    out
}

pub struct LogEngine {
    pub ctx: SessionContext,
    pub threads: usize,
    pub verbose: bool,
    pub last_stats: Mutex<ParseStats>,
}

impl LogEngine {
    pub fn new() -> Self {
        Self::with_options(None, false)
    }

    pub fn with_options(threads: Option<usize>, verbose: bool) -> Self {
        let num_threads = threads.filter(|&t| t > 0).unwrap_or_else(num_cpus);
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global();
        let config = SessionConfig::new().with_target_partitions(num_threads);
        let ctx = SessionContext::new_with_config(config);
        register_all_udfs(&ctx);
        Self {
            ctx,
            threads: num_threads,
            verbose,
            last_stats: Mutex::new(ParseStats::default()),
        }
    }

    pub fn get_last_stats(&self) -> ParseStats {
        self.last_stats.lock().unwrap().clone()
    }

    pub async fn register_source(
        &self,
        table_name: &str,
        path_pattern: &str,
        format: InputFormat,
        custom_regex: Option<&str>,
    ) -> Result<InputFormat> {
        self.register_source_with_checkpoint(table_name, path_pattern, format, custom_regex, None)
            .await
    }

    pub async fn register_source_with_checkpoint(
        &self,
        table_name: &str,
        path_pattern: &str,
        format: InputFormat,
        custom_regex: Option<&str>,
        ckpt: Option<&mut CheckpointStore>,
    ) -> Result<InputFormat> {
        self.register_source_with_checkpoint_filtered(
            table_name,
            path_pattern,
            format,
            custom_regex,
            ckpt,
            None,
        )
        .await
    }

    pub async fn register_source_with_checkpoint_filtered(
        &self,
        table_name: &str,
        path_pattern: &str,
        format: InputFormat,
        custom_regex: Option<&str>,
        ckpt: Option<&mut CheckpointStore>,
        pre_filter: Option<&ScanPreFilter>,
    ) -> Result<InputFormat> {
        let items = resolve_source_items(path_pattern)?;
        self.register_source_items_filtered(
            table_name,
            items,
            format,
            custom_regex,
            ckpt,
            Some(path_pattern),
            pre_filter,
        )
        .await
    }

    /// Register a pre-resolved (and optionally pre-filtered) set of source items.
    /// Used by fleet scans to skip out-of-window files before parsing.
    #[allow(dead_code)]
    pub async fn register_source_items(
        &self,
        table_name: &str,
        items: Vec<LogSourceItem>,
        format: InputFormat,
        custom_regex: Option<&str>,
        ckpt: Option<&mut CheckpointStore>,
        path_pattern: Option<&str>,
    ) -> Result<InputFormat> {
        self.register_source_items_filtered(
            table_name,
            items,
            format,
            custom_regex,
            ckpt,
            path_pattern,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_source_items_filtered(
        &self,
        table_name: &str,
        items: Vec<LogSourceItem>,
        format: InputFormat,
        custom_regex: Option<&str>,
        ckpt: Option<&mut CheckpointStore>,
        path_pattern: Option<&str>,
        pre_filter: Option<&ScanPreFilter>,
    ) -> Result<InputFormat> {
        if items.is_empty() {
            anyhow::bail!("No log files remained after filtering");
        }
        let effective_format = if format == InputFormat::Auto {
            detect_format_item(&items[0])
        } else {
            format
        };

        let mut stats = ParseStats {
            files_processed: items.len(),
            total_bytes: items.iter().map(|i| i.size_bytes()).sum(),
            ..Default::default()
        };

        match effective_format {
            InputFormat::W3c => {
                let (batches, s) =
                    parse_w3c_items_parallel_filtered(&items, self.verbose, pre_filter)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            InputFormat::Nginx | InputFormat::Syslog | InputFormat::AwsS3 | InputFormat::AwsAlb => {
                let re = get_format_regex(effective_format).unwrap();
                let (batches, s) =
                    parse_regex_items_parallel_filtered(&items, re, self.verbose, pre_filter)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            InputFormat::Regex => {
                let pattern = custom_regex
                    .ok_or_else(|| anyhow::anyhow!("--regex-pattern required for -i regex"))?;
                let re = Regex::new(pattern)?;
                let (batches, s) =
                    parse_regex_items_parallel_filtered(&items, &re, self.verbose, pre_filter)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            InputFormat::Line | InputFormat::Auto => {
                let (batches, s) = parse_raw_items_parallel(&items, ckpt, self.verbose)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            InputFormat::Csv => {
                let (batches, s) = parse_csv_items_parallel(&items, b',', self.verbose)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            InputFormat::Tsv => {
                let (batches, s) = parse_csv_items_parallel(&items, b'\t', self.verbose)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            InputFormat::Parquet => {
                let (batches, s) = parse_parquet_items(&items, self.verbose)?;
                stats = s;
                self.register_batches(table_name, batches)?;
            }
            other => {
                let pp = path_pattern
                    .ok_or_else(|| anyhow::anyhow!("path pattern required for this input format"))?;
                let paths = resolve_paths(pp)?;
                let batch = match other {
                    InputFormat::Excel => parse_excel_files(&paths)?,
                    InputFormat::Json | InputFormat::Akamai | InputFormat::Gcp => {
                        parse_json_files(&paths)?
                    }
                    InputFormat::Evtx => parse_evtx_files(&paths)?,
                    InputFormat::FirewallKv => parse_firewall_kv_files(&paths)?,
                    InputFormat::CiscoAsa => parse_cisco_asa_files(&paths)?,
                    InputFormat::CiscoConfig => parse_cisco_config_files(&paths)?,
                    InputFormat::Cef => parse_cef_files(&paths)?,
                    InputFormat::Ias => parse_ias_files(&paths)?,
                    InputFormat::AwsVpc => parse_aws_vpc_files(&paths)?,
                    InputFormat::AzureBlob => parse_azure_blob_files(&paths)?,
                    _ => unreachable!(),
                };
                stats.total_rows = batch.num_rows();
                stats.total_lines = batch.num_rows();
                self.register_batches(table_name, vec![batch])?;
            }
        }

        *self.last_stats.lock().unwrap() = stats;
        Ok(effective_format)
    }

    fn register_batches(&self, table_name: &str, batches: Vec<RecordBatch>) -> Result<()> {
        let _ = self.ctx.deregister_table(table_name);
        let schema = batches[0].schema();
        // Partition batches across DataFusion partitions so multi-core SQL execution runs in parallel across files!
        let partitions: Vec<Vec<RecordBatch>> = batches.into_iter().map(|b| vec![b]).collect();
        let mem_table = MemTable::try_new(schema, partitions)?;
        self.ctx.register_table(table_name, Arc::new(mem_table))?;
        Ok(())
    }

    pub async fn table_columns(&self, table_name: &str) -> Vec<String> {
        if let Ok(table) = self.ctx.table(table_name).await {
            table
                .schema()
                .fields()
                .iter()
                .map(|f| f.name().clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>> {
        let cols = self.table_columns("logs").await;
        let normalized = normalize_logparser_sql(sql, &cols);
        let df = match self.ctx.sql(&normalized).await {
            Ok(df) => df,
            Err(_) => self.ctx.sql(sql).await.map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    format_helpful_error_with_sql(&e.to_string(), None, &cols, Some(sql))
                )
            })?,
        };
        let batches = df.collect().await.map_err(|e| {
            anyhow::anyhow!(
                "{}",
                format_helpful_error_with_sql(&e.to_string(), None, &cols, Some(sql))
            )
        })?;
        Ok(batches)
    }

    pub async fn inspect_schema_and_intents(
        &self,
        path_pattern: &str,
        format: InputFormat,
    ) -> Result<SchemaDiscovery> {
        let detected = self
            .register_source("logs", path_pattern, format, None)
            .await
            .map_err(|e| anyhow::anyhow!("{}", format_helpful_error(&e.to_string(), Some(path_pattern), &[])))?;
        let columns = self.table_columns("logs").await;
        let row_count_estimate = match self.query("SELECT COUNT(*) AS cnt FROM logs").await {
            Ok(batches) => batches
                .first()
                .and_then(|b| {
                    arrow::util::display::array_value_to_string(b.column(0), 0)
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                })
                .unwrap_or(0),
            Err(_) => 0,
        };
        let suggestions = generate_intent_suggestions(detected, &columns);
        Ok(SchemaDiscovery {
            detected_format: format!("{:?}", detected),
            columns,
            row_count_estimate,
            suggestions,
        })
    }
}

/// Formats any raw DataFusion, filesystem, or parser error into a clear, actionable diagnostic
/// message explaining (1) What went wrong, and (2) Exact instructions/commands to solve it.
pub fn format_helpful_error(
    raw_msg: &str,
    source_hint: Option<&str>,
    available_cols: &[String],
) -> String {
    format_helpful_error_with_sql(raw_msg, source_hint, available_cols, None)
}

pub fn format_helpful_error_with_sql(
    raw_msg: &str,
    source_hint: Option<&str>,
    available_cols: &[String],
    original_sql: Option<&str>,
) -> String {
    let cleaned = raw_msg.trim();
    // Avoid double-wrapping if already formatted
    if cleaned.contains("HOW TO SOLVE IT:") {
        return cleaned.to_string();
    }

    let lower = cleaned.to_ascii_lowercase();
    let src_display = source_hint
        .map(clean_windows_path)
        .unwrap_or_else(|| "<your-log-or-csv-path>".to_string());

    let auto_suggest_block = original_sql
        .and_then(|q| crate::nl2sql::suggest_sql_autocorrect(q, available_cols))
        .map(|sug| {
            format!(
                "\n💡 DID YOU MEAN:\n  {}\n  (Auto-corrected: {})\n  --> Press [Y] or [Enter] to run the auto-corrected query!",
                sug.corrected_sql,
                sug.changes.join(", ")
            )
        })
        .unwrap_or_default();

    // 1. Table 'logs' not found (no file loaded yet or wrong table name in FROM)
    if lower.contains("table 'datafusion.public.") && lower.contains("not found") {
        let is_logs_table = lower.contains("table 'datafusion.public.logs' not found");
        if is_logs_table && available_cols.is_empty() {
            return format!(
                "No log or CSV file is currently loaded into the `logs` table.\n\
                 WHAT IS WRONG:\n  \
                   The SQL engine tried to query `FROM logs`, but no valid log/data file has been loaded yet.\n\
                 HOW TO SOLVE IT:\n  \
                   • In TUI (`lpr tui`): Press `o` to open the File Browser, select a `.log`, `.csv`, `.json`, or `.zip` file, and press Enter.\n  \
                   • In Web Studio (`lpr serve`): Click `Browse...` at the top, select a log/CSV file, and click `Run SQL`.\n  \
                   • In CLI: Pass `-f <path>` or put the file path inside SQL `FROM '<path>'`, e.g.:\n    \
                     lpr -f \"D:\\Logs\\W3SVC1\\*.log\" \"SELECT * FROM logs LIMIT 50\""
            );
        } else {
            return format!(
                "{}\n\
                 WHAT IS WRONG:\n  \
                   Your SQL query referenced a table name that is not registered.\n\
                 HOW TO SOLVE IT:\n  \
                   • Always use `FROM logs` as the table name (or `FROM 'D:\\path\\to\\file.log'`).\n  \
                   • Example: SELECT * FROM logs LIMIT 50",
                cleaned
            );
        }
    }

    // 2. Column not found (`No field named ...`)
    if lower.contains("no field named") {
        let cols_preview = if available_cols.is_empty() {
            "(No columns loaded — open a file first or run `lpr suggest <file>` to inspect columns)".to_string()
        } else {
            available_cols.join(", ")
        };
        // Even if original_sql wasn't passed, try extracting the misspelled field from `No field named <col>.`
        let fallback_col_hint = if auto_suggest_block.is_empty() {
            if let Some(idx) = lower.find("no field named ") {
                let after = &cleaned[idx + "no field named ".len()..];
                let bad_tok = after
                    .split(|c: char| c == '.' || c.is_whitespace() || c == '"' || c == '\'')
                    .find(|s| !s.is_empty())
                    .unwrap_or("");
                if let Some((closest, _)) = crate::nl2sql::find_closest_column(bad_tok, available_cols) {
                    format!(
                        "\n💡 DID YOU MEAN COLUMN: `{}` (instead of `{}`)?",
                        closest, bad_tok
                    )
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            auto_suggest_block.clone()
        };
        return format!(
            "{}{}\n\
             WHAT IS WRONG:\n  \
               The SQL query referenced a column name that does not exist in the currently loaded file (`{}`).\n\
             AVAILABLE COLUMNS IN THIS FILE ({}):\n  \
               {}\n\
             HOW TO SOLVE IT:\n  \
               • Replace the missing column in your `SELECT` / `WHERE` clause with one of the available columns listed above.\n  \
               • Or type plain English (e.g. `find unique user agent from todays logs` or `SELECT * FROM logs where url starts with /cat`).",
            cleaned,
            fallback_col_hint,
            src_display,
            available_cols.len(),
            cols_preview
        );
    }

    // 3. File / Path / Object Store error
    if lower.contains("no log")
        || lower.contains("matched")
        || lower.contains("object store")
        || lower.contains("invalid path")
        || lower.contains("failed to open")
        || lower.contains("cannot find the path")
        || lower.contains("os error")
    {
        return format!(
            "{}\n\
             WHAT IS WRONG:\n  \
               Could not open or find any supported log/data files at `{}`.\n\
             HOW TO SOLVE IT:\n  \
               • Check that the file or folder path exists and is readable.\n  \
               • Supported formats: `.log`, `.csv`, `.tsv`, `.json`, `.zip`, `.gz`, `.zst`, `.evtx`, `.xlsx`, `.parquet`, `.cfg`.\n  \
               • On Windows, wrap paths with spaces or wildcards in double quotes: `-f \"D:\\Logs\\W3SVC1\\*.log\"`.\n  \
               • In TUI (`lpr tui`), press `o` to browse and pick a file; in Web Studio (`lpr serve`), click `Browse...`.",
            cleaned, src_display
        );
    }

    // 4. SQL parser syntax error
    if lower.contains("sql parser error") || lower.contains("expected:") {
        return format!(
            "{}{}\n\
             WHAT IS WRONG:\n  \
               The query has a SQL syntax error or an unrecognized keyword.\n\
             HOW TO SOLVE IT:\n  \
               • Enclose string literals and `LIKE` patterns in single quotes (`'...'`), e.g.:\n    \
                 SELECT * FROM logs WHERE sc_status = '500' AND cs_uri_stem LIKE '%/api/%' LIMIT 50\n  \
               • Or type plain English directly — `lpr` translates English grammar to SQL automatically (no AI needed):\n    \
                 find unique user agent from todays logs\n    \
                 SELECT * FROM logs where url starts with /cat and status is 500",
            cleaned, auto_suggest_block
        );
    }

    // 5. Fallback general diagnostic
    let cols_note = if !available_cols.is_empty() {
        format!("\nAVAILABLE COLUMNS ({}):\n  {}", available_cols.len(), available_cols.join(", "))
    } else {
        String::new()
    };
    format!(
        "{}{}{}\n\
         HOW TO SOLVE IT:\n  \
           • Try running `SELECT * FROM logs LIMIT 50` first to verify the loaded columns and data.\n  \
           • Run `lpr suggest \"{}\"` to get ready-to-run SQL queries tailored to this file.\n  \
           • You can also type plain English queries such as `find unique user agent from todays logs`.\n  \
           • Run `lpr help-full` or `lpr --help` for complete parameter & SQL syntax examples.",
        cleaned, auto_suggest_block, cols_note, src_display
    )
}

pub fn generate_intent_suggestions(
    format: InputFormat,
    columns: &[String],
) -> Vec<IntentSuggestion> {
    let has = |col: &str| columns.iter().any(|c| c.eq_ignore_ascii_case(col));
    let mut list = Vec::new();

    match format {
        InputFormat::W3c => {
            list.push(IntentSuggestion {
                title: "Find 500-level Server Errors".to_string(),
                category: "Troubleshooting".to_string(),
                description: "Filter IIS/W3C requests returning HTTP 5xx server error status codes".to_string(),
                sql: "SELECT date, time, c_ip, cs_method, cs_uri_stem, sc_status, sc_substatus, sc_win32_status, time_taken FROM logs WHERE sc_status LIKE '5%' ORDER BY CAST(time_taken AS INT) DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Top 10 Slowest Requests (Latency)".to_string(),
                category: "Performance".to_string(),
                description: "Rank endpoints by highest time_taken (ms) to spot bottlenecks".to_string(),
                sql: "SELECT date, time, cs_method, cs_uri_stem, cs_uri_query, sc_status, CAST(time_taken AS INT) AS latency_ms FROM logs ORDER BY latency_ms DESC LIMIT 10".to_string(),
            });
            list.push(IntentSuggestion {
                title: "HTTP Status & Substatus Breakdown".to_string(),
                category: "Analytics".to_string(),
                description: "Group requests by sc_status, sc_substatus, and sc_win32_status".to_string(),
                sql: "SELECT sc_status, sc_substatus, sc_win32_status, COUNT(*) AS hits FROM logs GROUP BY 1, 2, 3 ORDER BY hits DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Top Client IPs & Subnet Classification".to_string(),
                category: "Network".to_string(),
                description: "Aggregate traffic by c_ip and check private RFC1918 subnet inclusion".to_string(),
                sql: "SELECT c_ip, ip_in_cidr(c_ip, '192.168.0.0/16') AS is_lan, COUNT(*) AS requests FROM logs GROUP BY 1, 2 ORDER BY requests DESC LIMIT 15".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Detect Web Attack Payloads in URI/Query".to_string(),
                category: "SecOps".to_string(),
                description: "Scan cs_uri_stem and cs_uri_query for SQLi, XSS, LFI, and RCE".to_string(),
                sql: "SELECT date, time, c_ip, cs_uri_stem, cs_uri_query, detect_threat( COALESCE(cs_uri_query, cs_uri_stem) ) AS threat FROM logs WHERE detect_threat( COALESCE(cs_uri_query, cs_uri_stem) ) != 'CLEAN'".to_string(),
            });
            list.push(IntentSuggestion {
                title: "File Extension Traffic Summary (Log Parser Classic)".to_string(),
                category: "LogParser 2.2".to_string(),
                description: "Use extract_extension() to group hits by file type (.aspx, .png, etc.)".to_string(),
                sql: "SELECT extract_extension(cs_uri_stem) AS ext, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "IIS SMTP: Unique FROM Addresses & Sending Client IPs".to_string(),
                category: "IIS SMTP".to_string(),
                description: "Extract every unique sender (FROM) address and which client IP / HELO host is sending from this server".to_string(),
                sql: "SELECT extract_email(COALESCE(cs_uri_query, cs_uri_stem)) AS from_address, extract_domain(COALESCE(cs_uri_query, cs_uri_stem)) AS sender_domain, c_ip AS client_ip, COUNT(*) AS emails_sent FROM logs WHERE UPPER(cs_method) = 'MAIL' GROUP BY 1, 2, 3 ORDER BY emails_sent DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "IIS SMTP: Top X Recipient (TO) Addresses & Domains".to_string(),
                category: "IIS SMTP".to_string(),
                description: "Rank top recipient (RCPT TO) addresses, target domains, and delivery status (250 Accepted vs 550 Rejected)".to_string(),
                sql: "SELECT TOP 25 extract_email(COALESCE(cs_uri_query, cs_uri_stem)) AS to_address, extract_domain(COALESCE(cs_uri_query, cs_uri_stem)) AS recipient_domain, sc_status AS smtp_status, COUNT(*) AS total_rcpt FROM logs WHERE UPPER(cs_method) = 'RCPT' GROUP BY 1, 2, 3 ORDER BY total_rcpt DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "IIS SMTP: Client IP + HELO/EHLO Banner Inventory".to_string(),
                category: "IIS SMTP".to_string(),
                description: "List all machines/clients connecting to this SMTP server and the hostname they announce in EHLO/HELO".to_string(),
                sql: "SELECT c_ip AS client_ip, TRIM(LEADING '+' FROM COALESCE(cs_uri_query, cs_uri_stem)) AS ehlo_hostname, cs_username, COUNT(*) AS sessions FROM logs WHERE UPPER(cs_method) IN ('EHLO', 'HELO') GROUP BY 1, 2, 3 ORDER BY sessions DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "IIS SMTP Relay Rejections & Auth Failures (5xx / 4xx)".to_string(),
                category: "IIS SMTP".to_string(),
                description: "Find rejected emails, 550 relay denied, 535 auth failures, and Win32 socket errors".to_string(),
                sql: "SELECT c_ip, cs_method AS smtp_cmd, cs_uri_stem, cs_uri_query, sc_status, sc_win32_status, win32_error_description(sc_win32_status) AS win32_error, COUNT(*) AS failures FROM logs WHERE sc_status LIKE '5%' OR sc_status LIKE '4%' OR sc_win32_status != '0' GROUP BY 1, 2, 3, 4, 5, 6, 7 ORDER BY failures DESC".to_string(),
            });
        }
        InputFormat::Nginx => {
            list.push(IntentSuggestion {
                title: "Detect OWASP Exploits (SQLi / XSS / LFI / Log4Shell)".to_string(),
                category: "SecOps".to_string(),
                description: "Scan request_uri and http_user_agent for malicious exploit signatures".to_string(),
                sql: "SELECT remote_addr, time_local, method, request_uri, status, detect_threat(request_uri) AS uri_threat, detect_threat(http_user_agent) AS ua_threat FROM logs WHERE detect_threat(request_uri) != 'CLEAN' OR detect_threat(http_user_agent) != 'CLEAN'".to_string(),
            });
            list.push(IntentSuggestion {
                title: "HTTP 5xx & 4xx Error Summary by URI".to_string(),
                category: "Troubleshooting".to_string(),
                description: "Find endpoints generating server or client errors".to_string(),
                sql: "SELECT status, request_uri, COUNT(*) AS error_count FROM logs WHERE status LIKE '5%' OR status LIKE '4%' GROUP BY 1, 2 ORDER BY error_count DESC LIMIT 20".to_string(),
            });
            list.push(IntentSuggestion {
                title: "High Shannon Entropy URI Scan (Obfuscation/Base64)".to_string(),
                category: "Anomaly".to_string(),
                description: "Identify obfuscated payloads or anomalous tokens via Shannon entropy".to_string(),
                sql: "SELECT remote_addr, request_uri, ROUND(shannon_entropy(request_uri)::numeric, 2) AS entropy, status FROM logs ORDER BY entropy DESC LIMIT 15".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Bot & Scanner User-Agent Classification".to_string(),
                category: "Threat Intel".to_string(),
                description: "Classify User-Agent strings into Bot/Scanner vs Browser/OS".to_string(),
                sql: "SELECT parse_ua(http_user_agent) AS agent_class, http_user_agent, COUNT(*) AS hits FROM logs GROUP BY 1, 2 ORDER BY hits DESC".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Drain Log Template Clustering".to_string(),
                category: "NLP / Drain".to_string(),
                description: "Normalize dynamic IDs and numbers in URIs into structural templates".to_string(),
                sql: "SELECT cluster_template(request_uri) AS endpoint_pattern, COUNT(*) AS hits FROM logs GROUP BY 1 ORDER BY hits DESC".to_string(),
            });
        }
        InputFormat::CiscoConfig => {
            list.push(IntentSuggestion {
                title: "Overly Permissive ACL Rules ('permit any any')".to_string(),
                category: "CIS Compliance".to_string(),
                description: "Locate dangerous access-list rules permitting unrestricted traffic".to_string(),
                sql: "SELECT file, line_number, section, directive FROM logs WHERE LOWER(directive) LIKE '%permit%any any%'".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Weak Passwords & Reversible Type 7 Secrets".to_string(),
                category: "CIS Compliance".to_string(),
                description: "Detect cleartext Type 0 or weak Cisco Type 7 passwords".to_string(),
                sql: "SELECT file, line_number, section, directive FROM logs WHERE LOWER(directive) LIKE '%password%' OR LOWER(directive) LIKE '%secret%'".to_string(),
            });
            list.push(IntentSuggestion {
                title: "Network Interface IP & ACL Mapping".to_string(),
                category: "Network".to_string(),
                description: "Inspect all interface configuration directives".to_string(),
                sql: "SELECT section AS interface_name, line_number, directive FROM logs WHERE section LIKE 'interface %'".to_string(),
            });
        }
        InputFormat::FirewallKv | InputFormat::CiscoAsa => {
            list.push(IntentSuggestion {
                title: "Blocked / Denied Firewall Traffic by Destination Port".to_string(),
                category: "SecOps".to_string(),
                description: "Summarize denied connections across target ports (SSH, RDP, Telnet)".to_string(),
                sql: if has("srcip") {
                    "SELECT srcip, dstip, dstport, action, COUNT(*) AS attempts FROM logs WHERE LOWER(action) IN ('deny', 'block', 'drop') GROUP BY 1, 2, 3, 4 ORDER BY attempts DESC".to_string()
                } else {
                    "SELECT src_ip, dst_ip, dst_port, action, COUNT(*) AS attempts FROM logs WHERE action = 'DENY' GROUP BY 1, 2, 3, 4 ORDER BY attempts DESC".to_string()
                },
            });
            list.push(IntentSuggestion {
                title: "Top Bandwidth Talkers (Bytes Sent/Received)".to_string(),
                category: "Network".to_string(),
                description: "Rank source IPs by total transmitted bytes".to_string(),
                sql: if has("sentbyte") {
                    "SELECT srcip, dstip, SUM(CAST(sentbyte AS BIGINT)) AS total_sent, SUM(CAST(rcvdbyte AS BIGINT)) AS total_rcvd FROM logs GROUP BY 1, 2 ORDER BY total_sent DESC".to_string()
                } else {
                    "SELECT * FROM logs LIMIT 50".to_string()
                },
            });
        }
        InputFormat::Json | InputFormat::Gcp | InputFormat::Akamai => {
            list.push(IntentSuggestion {
                title: "Failed Events & Security Anomalies".to_string(),
                category: "SecOps".to_string(),
                description: "Filter JSON events with failed status or error indicators".to_string(),
                sql: if has("status") {
                    "SELECT * FROM logs WHERE LOWER(status) LIKE '%fail%' OR LOWER(status) LIKE '%err%' OR LOWER(status) LIKE '%deny%'".to_string()
                } else {
                    "SELECT * FROM logs LIMIT 50".to_string()
                },
            });
            if has("user") {
                list.push(IntentSuggestion {
                    title: "GDPR / HIPAA PII Redaction Preview".to_string(),
                    category: "Privacy".to_string(),
                    description: "Mask email addresses in user fields using mask_pii()".to_string(),
                    sql: "SELECT timestamp, service, event, mask_pii(\"user\") AS redacted_user, ip, status FROM logs".to_string(),
                });
            }
        }
        InputFormat::Csv | InputFormat::Tsv | InputFormat::Excel | InputFormat::Parquet => {
            list.push(IntentSuggestion {
                title: "Preview First 50 Records".to_string(),
                category: "Explore".to_string(),
                description: "Inspect all columns in the selected CSV / tabular file".to_string(),
                sql: "SELECT * FROM logs LIMIT 50".to_string(),
            });
            if has("server_name") && has("cs_uri_stem") && has("sc_status") {
                list.push(IntentSuggestion {
                    title: "Hits by Server & Status Code".to_string(),
                    category: "Fleet CSV".to_string(),
                    description: "Group fleet CSV records by server_name and sc_status".to_string(),
                    sql: "SELECT server_name, sc_status, COUNT(*) AS hits FROM logs GROUP BY 1, 2 ORDER BY hits DESC".to_string(),
                });
                list.push(IntentSuggestion {
                    title: "Top Endpoints in Fleet Report".to_string(),
                    category: "Fleet CSV".to_string(),
                    description: "Group fleet CSV records by cs_uri_stem and sc_status".to_string(),
                    sql: "SELECT cs_uri_stem, sc_status, COUNT(*) AS hits FROM logs GROUP BY 1, 2 ORDER BY hits DESC LIMIT 25".to_string(),
                });
            } else if has("url_path") && has("status_code") {
                list.push(IntentSuggestion {
                    title: "Top Failing Endpoints Across Fleet".to_string(),
                    category: "Fleet Summary".to_string(),
                    description: "Rank summary CSV rows by error_hits descending".to_string(),
                    sql: "SELECT * FROM logs ORDER BY CAST(error_hits AS INT) DESC LIMIT 25".to_string(),
                });
            }
            if has("journey_id") && has("step_num") {
                list.push(IntentSuggestion {
                    title: "View Reconstructed Customer Journeys".to_string(),
                    category: "Journey Trace".to_string(),
                    description: "Order cross-server user journey steps chronologically".to_string(),
                    sql: "SELECT journey_id, step_num, date, time, server_name, cs_method, cs_uri_stem, sc_status, time_taken, matched_identifiers FROM logs ORDER BY CAST(journey_id AS INT), CAST(step_num AS INT)".to_string(),
                });
            }
        }
        _ => {}
    }

    // Universal fallback / general exploration queries based on discovered columns
    if has("raw_line") {
        list.push(IntentSuggestion {
            title: "Universal Threat Signature Scan".to_string(),
            category: "SecOps".to_string(),
            description: "Scan raw log lines for SQLi, XSS, LFI, and RCE patterns".to_string(),
            sql: "SELECT file, line_number, detect_threat(raw_line) AS threat, raw_line FROM logs WHERE detect_threat(raw_line) != 'CLEAN'".to_string(),
        });
        list.push(IntentSuggestion {
            title: "Drain Log Template Clustering".to_string(),
            category: "NLP / Drain".to_string(),
            description: "Group unstructured lines into normalized structural templates".to_string(),
            sql: "SELECT cluster_template(raw_line) AS template, COUNT(*) AS count FROM logs GROUP BY 1 ORDER BY count DESC LIMIT 20".to_string(),
        });
    }

    list.push(IntentSuggestion {
        title: "Preview First 50 Log Records".to_string(),
        category: "Explore".to_string(),
        description: "Inspect all parsed columns in the current log source".to_string(),
        sql: "SELECT * FROM logs LIMIT 50".to_string(),
    });

    list
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}
