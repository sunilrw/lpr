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
                    "serverInfo": { "name": "lpr-mcp", "version": env!("CARGO_PKG_VERSION") }
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
                            "description": "Execute ANSI SQL, Microsoft Log Parser 2.2 SQL, or lnav filters against logs (W3C/IIS, JSON, AWS S3/VPC, Azure Blob, Cisco Config/ASA, FortiGate, Excel, CSV, Parquet, EVTX). Supports LogFilename, LogRow, detect_threat, cluster_template, ip_in_cidr, shannon_entropy, win32_error_description, extract_token, extract_extension.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string", "description": "Optional if specified in SQL FROM '<path>'" },
                                    "sql": { "type": "string" },
                                    "format": { "type": "string" }
                                },
                                "required": ["sql"]
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
                        },
                        {
                            "name": "suggest_queries",
                            "description": "Inspect a log file's schema and return context-aware, intent-based SQL query suggestions.",
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

    if name == "suggest_queries" {
        let engine = LogEngine::new();
        return match engine.inspect_schema_and_intents(path, fmt).await {
            Ok(discovery) => serde_json::to_string_pretty(&discovery).unwrap_or_default(),
            Err(e) => format!("Schema Discovery Error: {}", e),
        };
    }

    let sql = args["sql"].as_str().unwrap_or("SELECT * FROM logs LIMIT 25");
    let (rewritten_sql, extracted_path) = crate::engine::extract_source_from_sql(sql);
    let effective_path = if !path.trim().is_empty() {
        path.trim()
    } else {
        extracted_path.as_deref().unwrap_or("")
    };

    let engine = LogEngine::new();
    if let Err(e) = engine.register_source("logs", effective_path, fmt, None).await {
        return format!("Error loading log source `{}`: {}", effective_path, e);
    }

    match engine.query(&rewritten_sql).await {
        Ok(batches) => batches_to_json_value(&batches).map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default(),
        Err(e) => format!("SQL Execution Error: {}", e),
    }
}
