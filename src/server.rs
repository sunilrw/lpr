use crate::sym::*;
use crate::audit::evaluate_security_findings;
use crate::engine::{extract_source_from_sql, LogEngine};
use crate::parsers::InputFormat;
use crate::sinks::batches_to_json_value;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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

#[derive(Deserialize)]
pub struct BrowseRequest {
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct BrowseResponse {
    pub current_dir: String,
    pub parent_dir: Option<String>,
    pub glob_all_logs: String,
    pub entries: Vec<FileEntry>,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub row_count: usize,
    pub execution_time_ms: u128,
    pub columns: Vec<String>,
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
        .route("/v1/query", get(handle_query_get).post(handle_query))
        .route("/v1/audit", post(handle_audit))
        .route("/v1/browse", post(handle_browse))
        .route("/v1/schema", post(handle_schema))
        .route("/metrics", get(handle_metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    eprintln!("{SYM_ROCKET} lpr Studio v1.3.0 listening on http://{}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_web_ui() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

pub fn parse_format_str(s: Option<&str>) -> InputFormat {
    match s.map(|v| v.to_lowercase()).as_deref() {
        Some("w3c") | Some("iis") | Some("iisw3c") => InputFormat::W3c,
        Some("json") | Some("ndjson") | Some("jsonl") => InputFormat::Json,
        Some("csv") => InputFormat::Csv,
        Some("tsv") => InputFormat::Tsv,
        Some("excel") | Some("xlsx") | Some("xls") => InputFormat::Excel,
        Some("parquet") => InputFormat::Parquet,
        Some("nginx") | Some("apache") => InputFormat::Nginx,
        Some("syslog") => InputFormat::Syslog,
        Some("evtx") => InputFormat::Evtx,
        Some("firewall-kv") | Some("fortigate") | Some("kv") => InputFormat::FirewallKv,
        Some("cisco-asa") | Some("asa") => InputFormat::CiscoAsa,
        Some("cisco-config") | Some("cisco") | Some("cfg") => InputFormat::CiscoConfig,
        Some("cef") => InputFormat::Cef,
        Some("ias") => InputFormat::Ias,
        Some("akamai") => InputFormat::Akamai,
        Some("aws-s3") | Some("s3") => InputFormat::AwsS3,
        Some("aws-vpc") | Some("vpc") => InputFormat::AwsVpc,
        Some("aws-alb") | Some("alb") => InputFormat::AwsAlb,
        Some("azure-blob") | Some("azure") => InputFormat::AzureBlob,
        Some("gcp") => InputFormat::Gcp,
        Some("line") | Some("raw") | Some("textline") => InputFormat::Line,
        _ => InputFormat::Auto,
    }
}

async fn handle_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let samples = vec![
        "samples/iis/u_extend01.log",
        "samples/nginx_access.log",
        "samples/firewall.log",
        "samples/cisco_switch.cfg",
        "samples/cloud_events.json",
    ];
    Json(serde_json::json!({
        "version": "1.3.0",
        "default_source": state.default_source.clone(),
        "samples": samples,
    }))
}

async fn handle_query_get(
    State(state): State<Arc<AppState>>,
    Query(req): Query<QueryRequest>,
) -> impl IntoResponse {
    handle_query(State(state), Json(req)).await
}

async fn handle_query(State(state): State<Arc<AppState>>, Json(req): Json<QueryRequest>) -> impl IntoResponse {
    state.total_queries.fetch_add(1, Ordering::Relaxed);
    let start = std::time::Instant::now();
    let engine = LogEngine::new();

    let (rewritten_sql, extracted_path) = extract_source_from_sql(&req.sql);
    let src = req
        .source
        .filter(|s| !s.trim().is_empty())
        .or(extracted_path)
        .or_else(|| state.default_source.clone());

    if let Some(path) = src {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let fmt = parse_format_str(req.format.as_deref());
            if let Err(e) = engine.register_source("logs", trimmed, fmt, None).await {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                );
            }
        }
    }

    let columns = engine.table_columns("logs").await;

    match engine.query(&rewritten_sql).await {
        Ok(batches) => {
            let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();
            let data = batches_to_json_value(&batches).unwrap_or_default();
            let execution_time_ms = start.elapsed().as_millis();
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(QueryResponse {
                        row_count,
                        execution_time_ms,
                        columns,
                        data,
                    })
                    .unwrap(),
                ),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_audit(State(state): State<Arc<AppState>>, Json(req): Json<AuditRequest>) -> impl IntoResponse {
    let src = match req.source.or_else(|| state.default_source.clone()) {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Provide a file or glob path" })),
            )
        }
    };
    let fmt = parse_format_str(req.format.as_deref());
    match evaluate_security_findings(src.trim(), fmt).await {
        Ok((detected, findings)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "detected_format": format!("{:?}", detected),
                "findings": findings
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_schema(State(state): State<Arc<AppState>>, Json(req): Json<AuditRequest>) -> impl IntoResponse {
    let src = match req.source.or_else(|| state.default_source.clone()) {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Provide a file or glob path" })),
            )
        }
    };
    let fmt = parse_format_str(req.format.as_deref());
    let engine = LogEngine::new();
    match engine.inspect_schema_and_intents(src.trim(), fmt).await {
        Ok(discovery) => (StatusCode::OK, Json(serde_json::to_value(discovery).unwrap())),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn handle_browse(Json(req): Json<BrowseRequest>) -> impl IntoResponse {
    let raw_target = req.path.unwrap_or_default();
    let target_trimmed = raw_target.trim();
    let base_dir: PathBuf = if target_trimmed.is_empty() || target_trimmed == "." {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        let p = Path::new(target_trimmed);
        if p.is_dir() {
            p.to_path_buf()
        } else if let Some(parent) = p.parent() {
            if parent.as_os_str().is_empty() {
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            } else if parent.is_dir() {
                parent.to_path_buf()
            } else {
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            }
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    };

    let canonical = std::fs::canonicalize(&base_dir).unwrap_or_else(|_| base_dir.clone());
    let parent_dir = canonical
        .parent()
        .map(|p| p.to_string_lossy().to_string());
    let current_str = canonical.to_string_lossy().to_string();
    let sep = std::path::MAIN_SEPARATOR;
    let glob_all_logs = format!("{}{}*.log", current_str.trim_end_matches(sep), sep);

    let mut entries = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(&canonical) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            if is_dir || is_supported_log_file(&name) {
                entries.push(FileEntry {
                    name,
                    path: path.to_string_lossy().to_string(),
                    is_dir,
                    size_bytes,
                });
            }
        }
    }

    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    (
        StatusCode::OK,
        Json(serde_json::to_value(BrowseResponse {
            current_dir: current_str,
            parent_dir,
            glob_all_logs,
            entries,
        })
        .unwrap()),
    )
}

fn is_supported_log_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    let exts = [
        ".log", ".txt", ".cfg", ".conf", ".json", ".ndjson", ".jsonl", ".csv", ".tsv", ".xlsx",
        ".xls", ".ods", ".parquet", ".evtx", ".gz", ".zst", ".zip", ".cef", ".ias",
    ];
    exts.iter().any(|ext| lower.ends_with(ext))
}

async fn handle_metrics(State(state): State<Arc<AppState>>) -> String {
    let count = state.total_queries.load(Ordering::Relaxed);
    format!(
        "# HELP lpr_queries_total Total log queries\n# TYPE lpr_queries_total counter\nlpr_queries_total {}\n",
        count
    )
}
