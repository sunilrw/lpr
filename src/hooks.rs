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
