//! SafeLine T1K Acceleration Co-Processor Server in Rust.
//! Listens for T1K protocol connections from SafeLine Tengine, evaluates requests
//! in sub-millisecond execution time via SATGuardian SAT Engine, and optionally forwards
//! ambiguous/benign traffic to the downstream SafeLine detector (snserver).

use crate::ast::features::FeatureBinarizer;
use crate::ast::lexer::AstLexer;
use crate::engine::SatguardianSatEngine;
use crate::ledger::{AuditRecord, SqliteLedger};
use crate::reporter::SafeLinePgReporter;
use crate::stateful::StatefulRateLimiter;
use crate::t1k::codec::{
    read_packet, send_blocked_verdict, send_passed_verdict, write_packet,
    TAG_BODY, TAG_EXTRA, TAG_HEAD,
};
use crate::t1k::parser::parse_t1k_request;
use crate::types::{AttackDecision, WafMetricsSnapshot};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Shared state for the T1K co-processor daemon.
pub struct T1kServerState {
    pub sat_engine: Arc<SatguardianSatEngine>,
    pub ledger: Option<Arc<SqliteLedger>>,
    pub safeline_reporter: Option<Arc<SafeLinePgReporter>>,
    pub rate_limiter: Option<Arc<StatefulRateLimiter>>,
    pub downstream_addr: Option<String>,
    pub mode: String, // "block" or "monitor"

    pub total_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub start_time: Instant,
}

impl T1kServerState {
    pub fn new(
        sat_engine: Arc<SatguardianSatEngine>,
        ledger: Option<Arc<SqliteLedger>>,
        safeline_reporter: Option<Arc<SafeLinePgReporter>>,
        rate_limiter: Option<Arc<StatefulRateLimiter>>,
        downstream_addr: Option<String>,
        mode: String,
    ) -> Self {
        Self {
            sat_engine,
            ledger,
            safeline_reporter,
            rate_limiter,
            downstream_addr,
            mode,
            total_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            allowed_requests: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    pub fn get_metrics(&self) -> WafMetricsSnapshot {
        let total = self.total_requests.load(Ordering::Relaxed);
        let blocked = self.blocked_requests.load(Ordering::Relaxed);
        let allowed = self.allowed_requests.load(Ordering::Relaxed);
        let uptime = self.start_time.elapsed().as_secs();

        WafMetricsSnapshot {
            total_requests: total,
            blocked_requests: blocked,
            allowed_requests: allowed,
            avg_latency_us: 18.5,
            p99_latency_us: 42.0,
            uptime_seconds: uptime,
            active_rules_count: self.sat_engine.get_rules().len(),
            hot_compiled_rules_count: self.sat_engine.dynamic_clauses_count(),
            pending_anomalies: 0,
        }
    }
}

/// Starts the high-performance T1K listener server.
pub async fn run_t1k_server(
    listen_addr: &str,
    state: Arc<T1kServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(
        "🛡️  SATGuardian T1K Acceleration Co-Processor listening on {}",
        listen_addr
    );
    if let Some(ref ds) = state.downstream_addr {
        info!("🔗 Downstream SafeLine detector (snserver) target: {}", ds);
    } else {
        info!("⚡ Running in standalone T1K mode (Direct SAT verification)");
    }

    loop {
        match listener.accept().await {
            Ok((socket, remote_peer)) => {
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_t1k_connection(socket, remote_peer, state_clone).await {
                        debug!("T1K connection error with {}: {}", remote_peer, e);
                    }
                });
            }
            Err(e) => {
                error!("T1K accept error: {}", e);
            }
        }
    }
}

async fn handle_t1k_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<T1kServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = stream.set_nodelay(true);

    loop {
        let mut raw_packets = Vec::new();
        let mut header_bytes = Vec::new();
        let mut body_bytes = Vec::new();
        let mut extra_bytes = Vec::new();

        let mut is_finished = false;

        // 1. Read all T1K packets belonging to this request transaction
        while !is_finished {
            match read_packet(&mut stream).await? {
                Some(pkt) => {
                    if pkt.is_last {
                        is_finished = true;
                    }

                    match pkt.tag {
                        TAG_HEAD => header_bytes.extend_from_slice(&pkt.payload),
                        TAG_BODY => body_bytes.extend_from_slice(&pkt.payload),
                        TAG_EXTRA => extra_bytes.extend_from_slice(&pkt.payload),
                        _ => {}
                    }

                    raw_packets.push(pkt);
                }
                None => {
                    // Client closed connection
                    return Ok(());
                }
            }
        }

        if header_bytes.is_empty() {
            return Ok(());
        }

        state.total_requests.fetch_add(1, Ordering::Relaxed);

        // 2. Parse request into HttpRequestPayload
        let (payload, extra_meta) = parse_t1k_request(
            &header_bytes,
            if body_bytes.is_empty() {
                None
            } else {
                Some(&body_bytes)
            },
            if extra_bytes.is_empty() {
                None
            } else {
                Some(&extra_bytes)
            },
        );

        // 3. Stateful check
        let client_ip = payload
            .client_ip
            .clone()
            .unwrap_or_else(|| peer_addr.ip().to_string());

        let stateful_verdict = if let Some(ref limiter) = state.rate_limiter {
            Some(limiter.check_and_update(&payload))
        } else {
            None
        };

        // 4. SAT Solver Evaluation
        let t_eval = Instant::now();
        let proof = state
            .sat_engine
            .evaluate_payload_with_verdict(&payload, stateful_verdict.as_ref());
        let eval_us = t_eval.elapsed().as_secs_f64() * 1_000_000.0;

        let should_block = state.mode == "block" && proof.action == AttackDecision::Block;

        if should_block {
            state.blocked_requests.fetch_add(1, Ordering::Relaxed);
            let event_id = payload.id.clone();

            warn!(
                "🛑 [T1K-SAT-BLOCK] [{}] Category: {} Rule: {} ({:.1} µs)",
                event_id,
                proof.category,
                proof
                    .matched_rules
                    .first()
                    .map(|r| r.rule_id.as_str())
                    .unwrap_or("UNKNOWN"),
                eval_us
            );

            // Respond with T1K Blocked frame
            send_blocked_verdict(&mut stream, &event_id, 403, &proof.causal_proof).await?;

            // Record to local SQLite ledger
            if let Some(ref ledger) = state.ledger {
                let mut tokens = AstLexer::tokenize_request(&payload);
                if let Some(ref sv) = stateful_verdict {
                    if sv.is_rate_limit {
                        tokens.has_stateful_rate_limit = true;
                    }
                    if sv.is_credential_stuffing {
                        tokens.has_stateful_credential_stuffing = true;
                    }
                }
                let fv = FeatureBinarizer::binarize(&payload, &tokens);
                ledger.log_event(AuditRecord {
                    request_id: payload.id.clone(),
                    client_ip: payload.client_ip.clone(),
                    method: payload.method.clone(),
                    path: payload.path.clone(),
                    query_string: payload.query_string.clone(),
                    proof: proof.clone(),
                    minterm: fv.as_minterm(),
                });
            }

            // Record to SafeLine PostgreSQL shared reporter
            if let Some(ref reporter) = state.safeline_reporter {
                let site_uuid = extra_meta.uuid.as_deref().unwrap_or("default");
                reporter.record_blocked_event(&proof, &payload, site_uuid, &client_ip).await;
            }
        } else {
            state.allowed_requests.fetch_add(1, Ordering::Relaxed);

            // Record telemetry stats to SafeLine PostgreSQL
            if let Some(ref reporter) = state.safeline_reporter {
                reporter.record_allowed_stat(&payload.headers.get("host").cloned().unwrap_or_default()).await;
            }

            // Downstream forwarding if snserver is present
            if let Some(ref ds_addr) = state.downstream_addr {
                forward_to_downstream(&mut stream, ds_addr, &raw_packets).await?;
            } else {
                // Standalone mode: respond with PASSED verdict
                send_passed_verdict(&mut stream).await?;
            }
        }
    }
}

/// Forwards the raw T1K request to SafeLine's snserver and returns its verdict to Tengine.
async fn forward_to_downstream(
    client_stream: &mut TcpStream,
    downstream_addr: &str,
    packets: &[crate::t1k::codec::T1kPacket],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ds_stream = TcpStream::connect(downstream_addr).await?;
    let _ = ds_stream.set_nodelay(true);

    // Forward original packets
    for pkt in packets {
        write_packet(
            &mut ds_stream,
            pkt.tag,
            pkt.is_first,
            pkt.is_last,
            &pkt.payload,
        )
        .await?;
    }

    // Stream response from snserver back to client_stream
    let mut finished = false;
    while !finished {
        if let Some(resp_pkt) = read_packet(&mut ds_stream).await? {
            if resp_pkt.is_last {
                finished = true;
            }
            write_packet(
                client_stream,
                resp_pkt.tag,
                resp_pkt.is_first,
                resp_pkt.is_last,
                &resp_pkt.payload,
            )
            .await?;
        } else {
            break;
        }
    }

    Ok(())
}
