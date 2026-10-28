//! SATGuardian to SafeLine PostgreSQL Exporter & Live Telemetry Synchronizer.
//! Automatically streams SAT evaluation events, LaTeX proofs, and metrics
//! directly into SafeLine's reporting database (detect_log_basic, detect_log_detail, system_statistics).

use crate::types::{AttackCategory, HttpRequestPayload, ProofChain};
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use tracing::{debug, info};

/// Live telemetry and reporting synchronizer with SafeLine's PostgreSQL database.
#[derive(Clone)]
pub struct SafeLinePgReporter {
    pool: PgPool,
}

impl SafeLinePgReporter {
    /// Connects to SafeLine's PostgreSQL instance.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        info!("🔌 Connecting to SafeLine PostgreSQL at {}", database_url);
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(3))
            .connect(database_url)
            .await?;

        info!("✅ Connected to SafeLine PostgreSQL (Reporting & Telemetry active)");
        Ok(Self { pool })
    }

    /// Maps SATGuardian's formal AttackCategory to SafeLine's native integer AttackType.
    pub fn map_attack_category(category: &AttackCategory) -> i32 {
        match category {
            AttackCategory::SqlInjection => 0,       // SQL 注入
            AttackCategory::Xss => 1,                // XSS
            AttackCategory::Ssrf => 3,               // SSRF
            AttackCategory::RateLimitDdos => 4,      // 拒绝服务 (DDoS / Rate Limit)
            AttackCategory::CommandInjection => 9,   // 命令注入 (RCE)
            AttackCategory::PathTraversal => 20,     // 目录穿越 (Path Traversal / LFI)
            AttackCategory::CredentialStuffing => 15,// 未授权访问 (Credential Stuffing)
            AttackCategory::GraphqlAbuse => 35,      // HTTP 协议违规 (Protocol Anomaly)
            AttackCategory::PrototypePollution => 35,// HTTP 协议违规
            AttackCategory::GrpcSmuggling => 35,     // HTTP 协议违规
            AttackCategory::JwtTampering => 35,      // HTTP 协议违规
            AttackCategory::CmsWordpressProbe => 26, // Web 后门 / CMS 扫描 (Web Shell / Scanner)
            AttackCategory::SensitiveExposureProbe => 22, // 信息泄露 (Information Disclosure)
            AttackCategory::FrameworkExploitProbe => 9,  // 命令注入 (RCE / Framework Exploit)
            AttackCategory::BusinessRuleViolation => 35, // HTTP 协议违规 / 自定义规则 (Policy Violation)
            AttackCategory::Benign => -1,            // 非攻击
            AttackCategory::Unknown => 62,           // 未知
        }
    }

    /// Inserts a formal security violation into SafeLine's detect_log tables.
    pub async fn record_blocked_event(
        &self,
        proof: &ProofChain,
        payload: &HttpRequestPayload,
        site_uuid: &str,
        client_ip: &str,
    ) {
        let pool = self.pool.clone();
        let proof = proof.clone();
        let payload = payload.clone();
        let site_uuid = site_uuid.to_string();
        let client_ip = client_ip.to_string();

        tokio::spawn(async move {
            let event_id = proof.request_id.clone();
            let attack_type = Self::map_attack_category(&proof.category);
            let timestamp = Utc::now().timestamp();
            let host = payload
                .headers
                .get("host")
                .cloned()
                .unwrap_or_else(|| "default".to_string());
            let rule_id = proof
                .matched_rules
                .first()
                .map(|r| r.rule_id.clone())
                .unwrap_or_else(|| "SAT-VIOLATION".to_string());

            let mut req_headers_formatted = String::new();
            for (k, v) in &payload.headers {
                req_headers_formatted.push_str(&format!("{}: {}\r\n", k, v));
            }

            // Rich mathematical proof documentation formatted for SafeLine's detail view
            let rich_payload_report = format!(
                "=== [EXACTOR NEURO-SYMBOLIC SAT VERIFICATION] ===\n\
                Action: BLOCKED (403)\n\
                Category: {}\n\
                Violated Invariant: {}\n\
                Formula: {}\n\
                Causal Proof:\n  {}\n\
                Active Syntactic Tokens:\n  {}\n\
                Formal LaTeX Proof:\n{}\n\
                Execution Latency: {:.2} µs\n\
                Backend Security: ZERO-HALLUCINATION PROVABLE DEFENSE",
                proof.category.display_name(),
                rule_id,
                proof.matched_rules.first().map(|r| r.invariant_formula.as_str()).unwrap_or("N/A"),
                proof.causal_proof,
                proof.active_tokens.join(", "),
                proof.formal_proof_latex,
                proof.execution_time_us
            );

            // 1. Insert into detect_log_basic
            let res_basic = sqlx::query(
                "INSERT INTO detect_log_basic (
                    event_id, site_uuid, src_ip, socket_ip, protocol, host, url_path, dst_port,
                    country, province, city, attack_type, risk_level, action, rule_id, timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                ON CONFLICT (event_id) DO NOTHING"
            )
            .bind(&event_id)
            .bind(&site_uuid)
            .bind(&client_ip)
            .bind(&client_ip)
            .bind(0i32) // ProtocolHTTP
            .bind(&host)
            .bind(&payload.path)
            .bind(80i32)
            .bind("US")
            .bind("")
            .bind("")
            .bind(attack_type)
            .bind(3i32) // High risk level
            .bind(1i32) // Block action
            .bind(&rule_id)
            .bind(timestamp)
            .execute(&pool)
            .await;

            if let Err(e) = res_basic {
                debug!("SafeLine DB detect_log_basic insert note: {}", e);
            }

            // 2. Insert into detect_log_detail
            let res_detail = sqlx::query(
                "INSERT INTO detect_log_detail (
                    event_id, src_port, dst_ip, method, query_string, status_code,
                    req_header, req_body, rsp_header, rsp_body, payload, location, decode_path
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (event_id) DO NOTHING"
            )
            .bind(&event_id)
            .bind(0i32)
            .bind("127.0.0.1")
            .bind(&payload.method)
            .bind(&payload.query_string)
            .bind(403i32)
            .bind(&req_headers_formatted)
            .bind(&payload.body)
            .bind("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n")
            .bind("{\"code\":403,\"success\":false,\"message\":\"Blocked by SATGuardian Edge WAF\"}")
            .bind(&rich_payload_report)
            .bind("satguardian_sat_solver")
            .bind("")
            .execute(&pool)
            .await;

            if let Err(e) = res_detail {
                debug!("SafeLine DB detect_log_detail insert note: {}", e);
            }

            // 3. Update system_statistics for SafeLine live dashboard QPS & totals
            let _ = sqlx::query(
                "INSERT INTO system_statistics (type, value, created_at, website)
                VALUES ('total-denied', 1, NOW(), $1)"
            )
            .bind(&host)
            .execute(&pool)
            .await;
        });
    }

    /// Records allowed traffic statistics for SafeLine's live dashboard QPS graph.
    pub async fn record_allowed_stat(&self, host: &str) {
        let pool = self.pool.clone();
        let host = host.to_string();

        tokio::spawn(async move {
            let _ = sqlx::query(
                "INSERT INTO system_statistics (type, value, created_at, website)
                VALUES ('total-req', 1, NOW(), $1)"
            )
            .bind(&host)
            .execute(&pool)
            .await;
        });
    }
}
