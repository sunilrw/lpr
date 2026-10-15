use crate::engine::LogEngine;
use crate::parsers::InputFormat;
use crate::sinks::batches_to_json_value;
use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct SecurityFinding {
    pub severity: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub matched_count: usize,
    pub remediation: &'static str,
    pub sample_evidence: String,
    pub rows: serde_json::Value,
}

pub struct AuditRule {
    pub severity: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub sql: &'static str,
    pub remediation: &'static str,
}

pub async fn evaluate_security_findings(path_pattern: &str, explicit_format: InputFormat) -> Result<(InputFormat, Vec<SecurityFinding>)> {
    let engine = LogEngine::new();
    let detected_fmt = engine.register_source("logs", path_pattern, explicit_format, None).await?;
    let rules = get_rules_for_format(detected_fmt);
    let mut findings = Vec::new();

    for rule in rules {
        if let Ok(batches) = engine.query(rule.sql).await {
            let count: usize = batches.iter().map(|b| b.num_rows()).sum();
            if count > 0 {
                let sample = pretty_format_batches(&batches).map(|s| s.to_string()).unwrap_or_default();
                let rows = batches_to_json_value(&batches).unwrap_or_default();
                findings.push(SecurityFinding {
                    severity: rule.severity,
                    category: rule.category,
                    title: rule.title,
                    matched_count: count,
                    remediation: rule.remediation,
                    sample_evidence: sample,
                    rows,
                });
            }
        }
    }
    Ok((detected_fmt, findings))
}

pub async fn run_automated_security_audit(path_pattern: &str, explicit_format: InputFormat, json_output: bool) -> Result<()> {
    let (fmt, findings) = evaluate_security_findings(path_pattern, explicit_format).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }

    println!("================================================================================");
    println!(" 🛡️  LPR AUTOMATED MULTI-CLOUD, NETWORK & LOG SECURITY AUDIT REPORT");
    println!(" 📁 Target: {} | Detected Profile: {:?}", path_pattern, fmt);
    println!("================================================================================\n");

    if findings.is_empty() {
        println!("✅ No security findings or policy violations triggered across audit rules.");
        return Ok(());
    }

    for (idx, f) in findings.iter().enumerate() {
        println!("[{}] {} | {} — {} ({} matches)", idx + 1, f.severity, f.category, f.title, f.matched_count);
        println!("    💡 Remediation: {}", f.remediation);
        for line in f.sample_evidence.lines() { println!("    {}", line); }
        println!();
    }
    Ok(())
}

fn get_rules_for_format(fmt: InputFormat) -> Vec<AuditRule> {
    match fmt {
        InputFormat::CiscoConfig => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "CISCO_ACL_ANY_ANY",
                title: "Overly Permissive Firewall Rule ('permit ip/tcp any any')",
                sql: "SELECT file, line_number, section, directive FROM logs WHERE LOWER(directive) LIKE '%permit ip any any%' OR LOWER(directive) LIKE '%permit tcp any any%'",
                remediation: "Restrict ACL rules to explicit source/destination subnets and required ports.",
            },
            AuditRule {
                severity: "CRITICAL",
                category: "CISCO_WEAK_SECRET",
                title: "Weak or Reversible Password Hash ('enable password' or Type 0/7)",
                sql: "SELECT file, line_number, directive FROM logs WHERE LOWER(directive) LIKE 'enable password%' OR LOWER(directive) LIKE '%password 7 %' OR LOWER(directive) LIKE '%password 0 %'",
                remediation: "Replace enable password and Type 7 passwords with enable secret (Type 8/9).",
            },
        ],
        InputFormat::AwsS3 => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "AWS_S3_EXPLOIT_OR_ACL",
                title: "Suspicious S3 Bucket ACL/Policy Modification or Exploit URI",
                sql: "SELECT remote_ip, requester, operation, key, http_status FROM logs WHERE operation LIKE '%ACL%' OR operation LIKE '%POLICY%' OR detect_threat(request_uri) != 'CLEAN' LIMIT 25",
                remediation: "Enable S3 Block Public Access and review IAM principals modifying bucket policies.",
            },
        ],
        InputFormat::Nginx => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "WEB_OWASP_PAYLOAD",
                title: "Exploit Payloads Detected in Request URI (SQLi / XSS / LFI / RCE / Log4Shell)",
                sql: "SELECT remote_addr, detect_threat(request_uri) AS threat_type, status, COUNT(*) AS attempts, MIN(request_uri) AS sample_uri FROM logs WHERE detect_threat(request_uri) != 'CLEAN' GROUP BY 1, 2, 3 ORDER BY attempts DESC LIMIT 20",
                remediation: "Block offending source IPs at WAF/Firewall and inspect any HTTP 200 responses.",
            },
        ],
        _ => vec![
            AuditRule {
                severity: "HIGH",
                category: "UNIVERSAL_THREAT_SCAN",
                title: "Exploit Signatures Detected in Log Lines",
                sql: "SELECT file, line_number, detect_threat(raw_line) AS threat, raw_line FROM logs WHERE detect_threat(raw_line) != 'CLEAN' LIMIT 25",
                remediation: "Investigate matching log lines for injection or command execution attempts.",
            },
        ],
    }
}
