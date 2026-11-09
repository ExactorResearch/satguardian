use crate::cloud::SimplifyResponse;
use crate::engine::DynamicCompiledClause;
use crate::types::{AttackCategory, ProofChain};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::info;

pub struct AuditRecord {
    pub request_id: String,
    pub client_ip: Option<String>,
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub proof: ProofChain,
    pub minterm: u128,
}

#[derive(Clone)]
pub struct SqliteLedger {
    pool: Pool<Sqlite>,
    sender: Arc<UnboundedSender<AuditRecord>>,
}

impl SqliteLedger {
    pub async fn init(
        database_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db_path = std::path::Path::new(database_path);
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let opts = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_millis(5000));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(|e| {
                format!(
                    "cannot open SQLite ledger at '{}': {} (check that the directory exists and is writable)",
                    database_path, e
                )
            })?;

        // Create Tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT,
                method TEXT,
                path TEXT,
                query_string TEXT,
                action TEXT,
                category TEXT,
                execution_path TEXT,
                latency_us REAL,
                matched_rules TEXT,
                active_tokens TEXT,
                rule_match_details TEXT,
                is_violation INTEGER
            );

            CREATE TABLE IF NOT EXISTS novel_anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                minterm_u128 TEXT UNIQUE NOT NULL,
                feature_bits TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'PENDING'
            );

            CREATE TABLE IF NOT EXISTS cloud_simplification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                variables_count INTEGER,
                minterms_count INTEGER,
                reduction_percent REAL,
                original_gates INTEGER,
                new_gates INTEGER,
                execution_time_ms INTEGER,
                su_used INTEGER,
                equation TEXT
            );

            CREATE TABLE IF NOT EXISTS dynamic_clauses (
                clause_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                required_mask TEXT NOT NULL,
                expected_bits TEXT NOT NULL,
                category TEXT NOT NULL,
                applied INTEGER NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_novel_status ON novel_anomalies(status);
            "#,
        )
        .execute(&pool)
        .await?;

        // Ledgers written before the approval gate have no `applied` column. Every clause they
        // hold was already enforcing, so the default keeps those nodes protected after the update.
        let _ = sqlx::query(
            "ALTER TABLE dynamic_clauses ADD COLUMN applied INTEGER NOT NULL DEFAULT 1",
        )
        .execute(&pool)
        .await;

        let (tx, mut rx) = unbounded_channel::<AuditRecord>();
        let pool_bg = pool.clone();

        // Background worker for non-blocking WAL ledger ingestion with micro-batching
        tokio::spawn(async move {
            let mut batch: Vec<AuditRecord> = Vec::with_capacity(64);
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    maybe_rec = rx.recv() => {
                        match maybe_rec {
                            Some(rec) => {
                                batch.push(rec);
                                if batch.len() >= 64 {
                                    Self::flush_batch(&pool_bg, &mut batch).await;
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    Self::flush_batch(&pool_bg, &mut batch).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::flush_batch(&pool_bg, &mut batch).await;
                        }
                    }
                }
            }
        });

        info!(target: "satguardian::ledger", "Initialized SQLite WAL Ledger at {}", database_path);

        Ok(Self {
            pool,
            sender: Arc::new(tx),
        })
    }

    async fn flush_batch(pool: &Pool<Sqlite>, batch: &mut Vec<AuditRecord>) {
        if batch.is_empty() {
            return;
        }

        let mut tx = match pool.begin().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(target: "satguardian::ledger", "Failed to begin batch audit transaction: {}", e);
                batch.clear();
                return;
            }
        };

        for rec in batch.drain(..) {
            let matched_rules_str = rec
                .proof
                .matched_rules
                .iter()
                .map(|r| r.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let active_tokens_str = rec.proof.active_tokens.join(",");
            let is_violation = rec.proof.is_violation;
            let is_viol = if is_violation { 1 } else { 0 };

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO audit_log 
                (request_id, client_ip, method, path, query_string, action, category, execution_path, latency_us, matched_rules, active_tokens, rule_match_details, is_violation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&rec.request_id)
            .bind(&rec.client_ip)
            .bind(&rec.method)
            .bind(&rec.path)
            .bind(&rec.query_string)
            .bind(format!("{:?}", rec.proof.action))
            .bind(rec.proof.category.as_str())
            .bind(format!("{:?}", rec.proof.execution_path))
            .bind(rec.proof.execution_time_us)
            .bind(&matched_rules_str)
            .bind(&active_tokens_str)
            .bind(&rec.proof.rule_match_details)
            .bind(is_viol)
            .execute(&mut *tx)
            .await
            {
                tracing::error!(
                    target: "satguardian::ledger",
                    request_id = %rec.request_id,
                    error = %e,
                    "Failed to persist audit record"
                );
            }

            if is_violation {
                let minterm_str = rec.minterm.to_string();
                let bits_str = format!("{:#034x}", rec.minterm);
                if let Err(e) = sqlx::query(
                    r#"
                    INSERT INTO novel_anomalies (minterm_u128, feature_bits, occurrence_count, last_seen)
                    VALUES (?, ?, 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(minterm_u128) DO UPDATE SET 
                        occurrence_count = occurrence_count + 1,
                        last_seen = CURRENT_TIMESTAMP
                    "#
                )
                .bind(&minterm_str)
                .bind(&bits_str)
                .execute(&mut *tx)
                .await
                {
                    tracing::error!(
                        target: "satguardian::ledger",
                        minterm = %minterm_str,
                        error = %e,
                        "Failed to persist novel anomaly"
                    );
                }
            }
        }

        if let Err(e) = tx.commit().await {
            tracing::error!(target: "satguardian::ledger", "Failed to commit batch audit transaction: {}", e);
        }
    }

    /// Non-blocking ledger record logging (0 µs overhead to the HTTP request pipeline).
    pub fn log_event(&self, record: AuditRecord) {
        if let Err(e) = self.sender.send(record) {
            tracing::error!(
                target: "satguardian::ledger",
                error = %e,
                "Ledger worker unavailable; audit record dropped"
            );
        }
    }

    /// Fetches minterms of novel patterns marked as PENDING for cloud simplification.
    pub async fn get_pending_anomalies(&self, limit: i64) -> Result<Vec<u128>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT minterm_u128 FROM novel_anomalies WHERE status = 'PENDING' ORDER BY occurrence_count DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut res = Vec::new();
        for (m_str,) in rows {
            if let Ok(val) = m_str.parse::<u128>() {
                res.push(val);
            }
        }
        Ok(res)
    }

    /// Marks minterms as successfully simplified by the EXACTOR Cloud service.
    pub async fn mark_anomalies_simplified(&self, minterms: &[u128]) -> Result<(), sqlx::Error> {
        for m in minterms {
            let m_str = m.to_string();
            if let Err(e) = sqlx::query(
                "UPDATE novel_anomalies SET status = 'SIMPLIFIED' WHERE minterm_u128 = ?",
            )
            .bind(&m_str)
            .execute(&self.pool)
            .await
            {
                tracing::error!(
                    target: "satguardian::ledger",
                    minterm = %m_str,
                    error = %e,
                    "Failed to mark anomaly as simplified"
                );
            }
        }
        Ok(())
    }

    /// Records cloud synthesis statistics returned by the configured SATGuardian endpoint.
    pub async fn record_simplification(
        &self,
        resp: &SimplifyResponse,
        vars_count: usize,
        minterms_count: usize,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO cloud_simplification_history
            (variables_count, minterms_count, reduction_percent, original_gates, new_gates, execution_time_ms, su_used, equation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(vars_count as i64)
        .bind(minterms_count as i64)
        .bind(resp.reduction_percent)
        .bind(resp.original_gates as i64)
        .bind(resp.new_gates as i64)
        .bind(resp.execution_time_ms as i64)
        .bind(resp.su_used.unwrap_or(1))
        .bind(&resp.result)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Stores a cloud-synthesized clause as a pending proposal. It is not evaluated by the engine
    /// and is not loaded on restart until an operator approves it.
    pub async fn propose_dynamic_clause(
        &self,
        clause: &DynamicCompiledClause,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO dynamic_clauses (clause_id, description, required_mask, expected_bits, category, applied)
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT(clause_id) DO NOTHING
            "#,
        )
        .bind(&clause.clause_id)
        .bind(&clause.description)
        .bind(clause.required_mask.to_string())
        .bind(clause.expected_bits.to_string())
        .bind(clause.category.as_str())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Loads the clauses an operator has approved; pending proposals are deliberately excluded.
    pub async fn load_applied_clauses(&self) -> Result<Vec<DynamicCompiledClause>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT clause_id, description, required_mask, expected_bits, category \
             FROM dynamic_clauses WHERE applied = 1 ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(Self::decode_clause_row)
            .collect())
    }

    /// Proposals waiting for a decision, newest last.
    pub async fn load_pending_clauses(
        &self,
    ) -> Result<Vec<(DynamicCompiledClause, String)>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
            "SELECT clause_id, description, required_mask, expected_bits, category, \
             CAST(created_at AS TEXT) FROM dynamic_clauses WHERE applied = 0 ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(id, desc, mask, expected, category, created_at)| {
                Self::decode_clause_row((id, desc, mask, expected, category))
                    .map(|clause| (clause, created_at))
            })
            .collect())
    }

    /// Marks one proposal as approved and returns it so the caller can register it in the engine.
    pub async fn approve_dynamic_clause(
        &self,
        clause_id: &str,
    ) -> Result<Option<DynamicCompiledClause>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT clause_id, description, required_mask, expected_bits, category \
             FROM dynamic_clauses WHERE clause_id = ? AND applied = 0",
        )
        .bind(clause_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(clause) = row.and_then(Self::decode_clause_row) else {
            return Ok(None);
        };

        sqlx::query("UPDATE dynamic_clauses SET applied = 1 WHERE clause_id = ?")
            .bind(clause_id)
            .execute(&self.pool)
            .await?;

        Ok(Some(clause))
    }

    /// Discards a proposal. Enforced clauses are never deleted here: rejecting an update has to
    /// leave the protection that is already running untouched.
    pub async fn reject_dynamic_clause(&self, clause_id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM dynamic_clauses WHERE clause_id = ? AND applied = 0")
            .bind(clause_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn decode_clause_row(
        row: (String, String, String, String, String),
    ) -> Option<DynamicCompiledClause> {
        let (clause_id, description, required_mask, expected_bits, category) = row;
        Some(DynamicCompiledClause {
            required_mask: required_mask.parse().ok()?,
            expected_bits: expected_bits.parse().ok()?,
            clause_id,
            description,
            category: AttackCategory::parse(&category),
        })
    }

    pub async fn count_pending_anomalies(&self) -> usize {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM novel_anomalies WHERE status = 'PENDING'")
                .fetch_one(&self.pool)
                .await
                .unwrap_or((0,));
        count.0 as usize
    }
}
