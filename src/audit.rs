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
            AuditRule {
                severity: "CRITICAL",
                category: "WEB_HEADER_EXPLOIT",
                title: "Exploit Signatures in User-Agent or Referer Headers (Log4Shell / Shellshock)",
                sql: "SELECT remote_addr, http_user_agent, detect_threat(http_user_agent) AS threat, status FROM logs WHERE detect_threat(http_user_agent) != 'CLEAN' LIMIT 20",
                remediation: "Patch JNDI/Log4j vulnerabilities and block scanner User-Agent strings at the edge.",
            },
        ],
        InputFormat::W3c => vec![
            AuditRule {
                severity: "CRITICAL",
                category: "IIS_THREAT_SUMMARY",
                title: "Executive Threat Classification Breakdown (SQLi / RCE / LFI / SSRF / Scanners)",
                sql: "SELECT detect_threat(cs_uri_stem || ' ' || COALESCE(cs_uri_query, '')) AS threat_type, sc_status, COUNT(*) AS total_hits, COUNT(DISTINCT cs_uri_stem) AS unique_endpoints FROM logs WHERE detect_threat(cs_uri_stem || ' ' || COALESCE(cs_uri_query, '')) != 'CLEAN' GROUP BY 1, 2 ORDER BY total_hits DESC",
                remediation: "Prioritize any HIGH or CRITICAL threats returning HTTP 200/500, and block automated scanner IPs at WAF.",
            },
            AuditRule {
                severity: "CRITICAL",
                category: "IIS_SQLI_AND_RCE_EVIDENCE",
                title: "High-Severity SQL Injection & RCE / Command Injection Attempts (Exact Log File & Line)",
                sql: "SELECT date, time, c_ip, cs_method, cs_uri_stem, SUBSTR(COALESCE(cs_uri_query, ''), 1, 70) AS payload_preview, sc_status, detect_threat(cs_uri_stem || ' ' || COALESCE(cs_uri_query, '')) AS threat, log_filename, log_row FROM logs WHERE detect_threat(cs_uri_stem || ' ' || COALESCE(cs_uri_query, '')) IN ('CRITICAL:RCE_OR_LOG4SHELL', 'HIGH:SQL_INJECTION') LIMIT 25",
                remediation: "Parameterize SQL queries in targeted .asp/.aspx endpoints and block offending client IPs.",
            },
            AuditRule {
                severity: "HIGH",
                category: "IIS_LFI_AND_SSRF_EVIDENCE",
                title: "Path Traversal (LFI) & Cloud Metadata SSRF Probes",
                sql: "SELECT cs_uri_stem, SUBSTR(COALESCE(cs_uri_query, ''), 1, 60) AS query_preview, sc_status, detect_threat(cs_uri_stem || ' ' || COALESCE(cs_uri_query, '')) AS threat, COUNT(*) AS attempts FROM logs WHERE detect_threat(cs_uri_stem || ' ' || COALESCE(cs_uri_query, '')) IN ('HIGH:PATH_TRAVERSAL_LFI', 'HIGH:SSRF_CLOUD_METADATA') GROUP BY 1, 2, 3, 4 ORDER BY attempts DESC LIMIT 20",
                remediation: "Ensure IIS Request Filtering blocks '..' sequences and sensitive system paths.",
            },
            AuditRule {
                severity: "HIGH",
                category: "IIS_5XX_SERVER_ERRORS",
                title: "HTTP/SMTP 5xx Server, VBScript, Database Deadlock & Relay Failures",
                sql: "SELECT cs_method, cs_uri_stem, sc_status, sc_substatus, sc_win32_status, COUNT(*) AS failures, MAX(CAST(time_taken AS INT)) AS max_latency_ms, SUBSTR(MIN(COALESCE(cs_uri_query, '')), 1, 65) AS sample_error_detail FROM logs WHERE sc_status LIKE '5%' GROUP BY 1, 2, 3, 4, 5 ORDER BY failures DESC LIMIT 25",
                remediation: "Review IIS/SMTP 5xx status, SQL Server deadlocks (80004005), VBScript errors (800a000d), or SMTP 550/554 relay rejections.",
            },
            AuditRule {
                severity: "HIGH",
                category: "IIS_SMTP_AUTH_AND_RELAY_AUDIT",
                title: "IIS SMTP Failed Authentication, Relay Denials (550/535/554) & Suspicious Commands",
                sql: "SELECT date, time, c_ip, cs_username, cs_method AS smtp_verb, cs_uri_stem AS smtp_target, cs_uri_query AS smtp_response, sc_status, sc_win32_status, win32_error_description(sc_win32_status) AS win32_desc FROM logs WHERE UPPER(cs_method) IN ('EHLO', 'HELO', 'AUTH', 'MAIL', 'RCPT', 'DATA', 'VRFY', 'EXPN', 'STARTTLS') AND (sc_status LIKE '5%' OR sc_status LIKE '4%' OR sc_win32_status != '0' OR UPPER(cs_method) IN ('VRFY', 'EXPN')) LIMIT 25",
                remediation: "Lock down IIS SMTP Relay restrictions, disable VRFY/EXPN commands, and block IPs brute-forcing SMTP AUTH.",
            },
        ],
        InputFormat::FirewallKv => vec![
            AuditRule {
                severity: "HIGH",
                category: "FIREWALL_SENSITIVE_PORT_PROBING",
                title: "Blocked Reconnaissance / Brute-Force Probes Against Sensitive Ports (SSH/Telnet/RDP/SMB)",
                sql: "SELECT srcip, dstip, dstport, action, COUNT(*) AS blocked_attempts FROM logs WHERE LOWER(action) IN ('deny', 'block', 'drop') GROUP BY 1, 2, 3, 4 ORDER BY blocked_attempts DESC LIMIT 25",
                remediation: "Verify perimeter blocklists and ensure management ports (22, 23, 3389, 445) are never exposed to untrusted WANs.",
            },
        ],
        InputFormat::Json | InputFormat::Gcp | InputFormat::Akamai => vec![
            AuditRule {
                severity: "HIGH",
                category: "CLOUD_AUTH_OR_EVENT_FAILURE",
                title: "Failed Cloud Authentication or Sensitive Event Failures",
                sql: "SELECT * FROM logs WHERE LOWER(status) LIKE '%fail%' OR LOWER(status) LIKE '%deny%' OR LOWER(status) LIKE '%err%' LIMIT 25",
                remediation: "Investigate failed authentication or password reset events for credential stuffing or brute-force activity.",
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
