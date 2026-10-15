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
