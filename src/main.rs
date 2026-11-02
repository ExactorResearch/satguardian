use clap::{Parser, Subcommand};
use satguardian_waf::api::create_api_router;
use satguardian_waf::ast::features::FeatureBinarizer;
use satguardian_waf::benchmark::BenchmarkSuite;
use satguardian_waf::cloud::{SatguardianCloudClient, SimplifyRequest};
use satguardian_waf::config::WafConfig;
use satguardian_waf::engine::SatguardianSatEngine;
use satguardian_waf::envoy::{create_envoy_authz_router, EnvoyAuthzState};
use satguardian_waf::ledger::SqliteLedger;
use satguardian_waf::metrics::LatencyHistogram;
use satguardian_waf::proxy::{proxy_handler, ProxyState, TrustedProxies};
use satguardian_waf::reporter::SafeLinePgReporter;
use satguardian_waf::stateful::StatefulRateLimiter;
use satguardian_waf::t1k::{run_t1k_server, T1kServerState};
use satguardian_waf::types::HttpRequestPayload;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "satguardian-waf",
    author = "Satguardian Research",
    version = env!("CARGO_PKG_VERSION"),
    about = "SATGuardian Edge WAF: research prototype for lexical normalization and u128 bitmask rule evaluation (free edge traffic), with optional Boolean optimization via satguardian.tech"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to configuration TOML file
    #[arg(short, long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the high-performance WAF reverse-proxy server (default)
    Proxy {
        /// Inbound listen address (e.g. 0.0.0.0:8080)
        #[arg(short, long)]
        listen: Option<String>,

        /// Upstream target application URL (e.g. http://127.0.0.1:3000)
        #[arg(short, long)]
        upstream: Option<String>,

        /// Defense mode: 'block' (active drop) or 'monitor' (dry-run detection)
        #[arg(short, long)]
        mode: Option<String>,

        /// Stealth mode: minimal 403 Forbidden without leaking rules, proof or latex
        #[arg(short = 's', long)]
        stealth: bool,

        /// Disable stealth mode and emit verbose diagnostic proofs (development only)
        #[arg(long)]
        verbose: bool,
    },

    /// Inspect a single HTTP request payload and display formal mathematical proof
    Inspect {
        /// HTTP Method (GET, POST, etc.)
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Request URI Path
        #[arg(short, long, default_value = "/")]
        path: String,

        /// Query string (e.g. q=admin' OR 1=1--)
        #[arg(short, long, default_value = "")]
        query: String,

        /// Request Body string
        #[arg(short, long, default_value = "")]
        body: String,
    },

    /// Force immediate exact Boolean simplification with https://satguardian.tech
    SyncSimplify {
        /// Number of pending anomaly minterms to batch-simplify
        #[arg(short, long, default_value_t = 100)]
        limit: i64,
    },

    /// Run the multi-vector SAT engine performance benchmark
    Benchmark {
        /// Total request count for the benchmark run
        #[arg(short, long, default_value_t = 10000)]
        requests: usize,
    },

    /// Run as an Envoy ext_authz HTTP verification service
    EnvoyAuthz {
        /// Inbound listen address for Envoy ext_authz (e.g. 0.0.0.0:9002)
        #[arg(short, long)]
        listen: Option<String>,

        /// Inbound Unix Domain Socket path for Envoy ext_authz (e.g. /var/run/waf.sock)
        #[arg(long)]
        socket: Option<String>,
    },

    /// Run as a dedicated SafeLine T1K protocol acceleration co-processor
    T1kServer {
        /// T1K listen address (e.g. 0.0.0.0:8000)
        #[arg(short, long)]
        listen: Option<String>,

        /// Optional downstream SafeLine detector address to forward benign traffic
        #[arg(short, long)]
        downstream: Option<String>,

        /// SafeLine PostgreSQL connection URL for live reporting & metrics
        #[arg(long)]
        safeline_pg: Option<String>,
    },

    /// Check Cloud Security Units (SU) balance and Edge entitlement from satguardian.tech
    #[command(alias = "status", alias = "check-license")]
    Entitlement,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let mut config = WafConfig::load_or_default(cli.config.as_deref());

    match cli.command {
        Some(Commands::Inspect {
            method,
            path,
            query,
            body,
        }) => {
            run_cli_inspect(&config, &method, &path, &query, &body);
            Ok(())
        }
        Some(Commands::Benchmark { requests }) => {
            BenchmarkSuite::run_benchmark(requests);
            Ok(())
        }
        Some(Commands::Entitlement) => {
            run_check_entitlement(&config).await
        }
        Some(Commands::SyncSimplify { limit }) => {
            run_sync_simplify(&config, limit).await
        }
        Some(Commands::T1kServer {
            listen,
            downstream,
            safeline_pg,
        }) => {
            if let Some(l) = listen {
                config.t1k_listen_addr = Some(l);
            }
            if let Some(d) = downstream {
                config.t1k_downstream_addr = Some(d);
            }
            if let Some(p) = safeline_pg {
                config.safeline_pg_url = Some(p);
            }
            run_t1k_standalone(config).await
        }
        Some(Commands::Proxy {
            listen,
            upstream,
            mode,
            stealth,
            verbose,
        }) => {
            if let Some(l) = listen {
                config.listen_addr = l;
            }
            if let Some(u) = upstream {
                config.upstream_url = u;
            }
            if let Some(m) = mode {
                config.mode = m;
            }
            if stealth {
                config.stealth_mode = true;
            }
            if verbose {
                config.stealth_mode = false;
            }
            run_server(config).await
        }
        Some(Commands::EnvoyAuthz { listen, socket }) => {
            if let Some(l) = listen {
                config.envoy_ext_authz_addr = Some(l);
            }
            if let Some(s) = socket {
                config.envoy_ext_authz_socket = Some(s);
            }
            run_envoy_authz_standalone(config).await
        }
        None => {
            // Default command is to run the server
            run_server(config).await
        }
    }
}

/// Runs the server with Reverse Proxy, Management API, and Autonomous Minimization Loop.
async fn run_server(config: WafConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        r#"
   ███████╗ █████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
   ██╔════╝██╔══██╗╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
   ███████╗███████║   ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
   ╚════██║██╔══██║   ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
   ███████║██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
             SATGUARDIAN EDGE WAF - FREE LOCAL DEFENSE (RESEARCH PROTOTYPE)
        Cloud Boolean Optimization Powered by Security Units (SU)
                         https://satguardian.tech
    "#
    );

    info!(target: "satguardian::server", "Starting SATGuardian Edge WAF Server v{}", env!("CARGO_PKG_VERSION"));
    info!(target: "satguardian::server", "Listen Address : {}", config.listen_addr);
    info!(target: "satguardian::server", "Upstream Target: {}", config.upstream_url);
    info!(target: "satguardian::server", "Defense Mode   : {}", config.mode.to_uppercase());
    info!(target: "satguardian::server", "Stealth Mode   : {}", if config.stealth_mode { "ENABLED (Minimal 403 Forbidden)" } else { "DISABLED (Verbose LaTeX/JSON)" });
    info!(target: "satguardian::server", "Cloud API URL  : {}", config.satguardian_api_url);
    info!(target: "satguardian::server", "SQLite Ledger  : {}", config.database_path);
    info!(target: "satguardian::server", "Max Body Bytes : {}", config.max_body_bytes);
    info!(
        target: "satguardian::server",
        "Management API : {}",
        config
            .admin_listen_addr
            .as_deref()
            .map(|addr| format!("http://{} (Bearer token required)", addr))
            .unwrap_or_else(|| "disabled (WAF_ADMIN_LISTEN_ADDR=off)".to_string())
    );

    if !(config.upstream_url.starts_with("http://") || config.upstream_url.starts_with("https://")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "upstream_url must start with http:// or https:// (got '{}')",
                config.upstream_url
            ),
        )
        .into());
    }
    let trusted_proxies = TrustedProxies::parse(&config.trusted_proxies)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let engine = Arc::new(SatguardianSatEngine::with_config(
        config.islands.clone(),
        config.business_rules.clone(),
    ));
    let ledger = SqliteLedger::init(&config.database_path).await?;
    match ledger.load_dynamic_clauses().await {
        Ok(clauses) if !clauses.is_empty() => {
            let loaded = clauses.len();
            for clause in clauses {
                engine.register_dynamic_clause(clause);
            }
            info!(target: "satguardian::server", "Loaded {} persisted dynamic clauses", loaded);
        }
        Ok(_) => {}
        Err(e) => warn!(target: "satguardian::server", "Could not load persisted dynamic clauses: {}", e),
    }
    let cloud_client = SatguardianCloudClient::new(
        config.satguardian_api_url.clone(),
        config.satguardian_api_token.clone(),
    );

    let stateful_limiter = Arc::new(StatefulRateLimiter::new(config.to_stateful_config()));

    let proxy_state = Arc::new(ProxyState {
        config: config.clone(),
        engine: engine.clone(),
        ledger: ledger.clone(),
        stateful_limiter: stateful_limiter.clone(),
        cloud_client: cloud_client.clone(),
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
        trusted_proxies,
        latency_histogram: LatencyHistogram::new(),
        start_time: Instant::now(),
        counter_total: AtomicU64::new(0),
        counter_blocked: AtomicU64::new(0),
        counter_allowed: AtomicU64::new(0),
        sum_latency_us: AtomicU64::new(0),
    });

    // Autonomous background minimization sync worker
    if config.auto_sync_enabled && config.autonomous_sync_interval_secs > 0 {
        let bg_ledger = ledger.clone();
        let bg_engine = engine.clone();
        let bg_cloud = cloud_client.clone();
        let interval_secs = config.autonomous_sync_interval_secs;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                if let Ok(pending) = bg_ledger.get_pending_anomalies(50).await {
                    if !pending.is_empty() {
                        info!(
                            target: "satguardian::sync",
                            count = pending.len(),
                            "Autonomous worker: Syncing novel anomaly minterms with https://satguardian.tech"
                        );
                        let vars = FeatureBinarizer::get_variable_catalog(40);
                        let req = SimplifyRequest {
                            variables: vars.clone(),
                            minterms: pending.clone(),
                            dont_cares: None,
                            format: Some("equation".to_string()),
                        };
                        match bg_cloud.simplify(&req).await {
                            Ok(resp) => {
                                match bg_cloud.compile_equation_to_clauses(&resp.result, &vars) {
                                    Ok(clauses) if !clauses.is_empty() => {
                                        let mut added = 0usize;
                                        for clause in clauses {
                                            if bg_engine.register_dynamic_clause(clause.clone()) {
                                                if let Err(e) =
                                                    bg_ledger.save_dynamic_clause(&clause).await
                                                {
                                                    error!(
                                                        target: "satguardian::ledger",
                                                        "Failed to persist dynamic clause: {}", e
                                                    );
                                                }
                                                added += 1;
                                            }
                                        }
                                        if let Err(e) = bg_ledger
                                            .record_simplification(
                                                &resp,
                                                vars.len(),
                                                pending.len(),
                                            )
                                            .await
                                        {
                                            error!(
                                                target: "satguardian::ledger",
                                                "Failed to record simplification history: {}", e
                                            );
                                        }
                                        if let Err(e) = bg_ledger
                                            .mark_anomalies_simplified(&pending)
                                            .await
                                        {
                                            error!(
                                                target: "satguardian::ledger",
                                                "Failed to mark anomalies as simplified: {}", e
                                            );
                                        }
                                        info!(
                                            target: "satguardian::sync",
                                            reduction = %format!("{:.1}%", resp.reduction_percent),
                                            clauses_added = added,
                                            "Autonomous worker: Hot Boolean Minimization complete. Invariants updated."
                                        );
                                    }
                                    Ok(_) => warn!(
                                        target: "satguardian::sync",
                                        "Cloud returned no usable clauses; ledger left unchanged"
                                    ),
                                    Err(e) => warn!(
                                        target: "satguardian::sync",
                                        equation = %resp.result,
                                        error = %e,
                                        "Invalid cloud equation rejected; clauses not loaded"
                                    ),
                                }
                            }
                            Err(e) => {
                                warn!(target: "satguardian::sync", "Autonomous sync skipped or failed: {}", e);
                            }
                        }
                    }
                }
            }
        });
    }

    // Optional concurrent Envoy ext_authz HTTP verification service
    if let Some(ref envoy_addr_str) = config.envoy_ext_authz_addr {
        let envoy_state = EnvoyAuthzState::new(
            engine.clone(),
            ledger.clone(),
            stateful_limiter.clone(),
            config.mode.clone(),
        )
        .with_stealth(config.stealth_mode)
        .with_trusted_proxies(proxy_state.trusted_proxies.clone());
        let envoy_app = create_envoy_authz_router(envoy_state);
        let envoy_addr: SocketAddr = envoy_addr_str.parse()?;
        let envoy_listener = tokio::net::TcpListener::bind(envoy_addr).await?;
        info!(target: "satguardian::envoy", "Envoy ext_authz HTTP verification listener ready on http://{}", envoy_addr);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                envoy_listener,
                envoy_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                tracing::error!(target: "satguardian::envoy", "Envoy ext_authz service error: {}", e);
            }
        });
    }

    // Optional concurrent SafeLine T1K server listener
    if let Some(ref t1k_addr) = config.t1k_listen_addr {
        let safeline_reporter = if let Some(ref pg_url) = config.safeline_pg_url {
            match SafeLinePgReporter::connect(pg_url).await {
                Ok(rep) => Some(Arc::new(rep)),
                Err(e) => {
                    warn!(target: "satguardian::server", "Could not connect to SafeLine PostgreSQL at {}: {}", pg_url, e);
                    None
                }
            }
        } else {
            None
        };

        let t1k_state = Arc::new(T1kServerState::new(
            engine.clone(),
            Some(Arc::new(ledger.clone())),
            safeline_reporter,
            Some(stateful_limiter.clone()),
            config.t1k_downstream_addr.clone(),
            config.mode.clone(),
        ));
        let addr_clone = t1k_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = run_t1k_server(&addr_clone, t1k_state).await {
                error!(target: "satguardian::t1k", "T1K server background error: {}", e);
            }
        });
    }

    // Management API is isolated on its own listener and never mounted on the data plane.
    if let Some(admin_addr_str) = config.admin_listen_addr.clone() {
        match admin_addr_str.parse::<SocketAddr>() {
            Ok(admin_addr) => {
                let admin_app = create_api_router(proxy_state.clone());
                match tokio::net::TcpListener::bind(admin_addr).await {
                    Ok(admin_listener) => {
                        info!(
                            target: "satguardian::server",
                            "Management API listening on http://{} (Bearer auth required)",
                            admin_addr
                        );
                        tokio::spawn(async move {
                            if let Err(e) = axum::serve(admin_listener, admin_app).await {
                                error!(target: "satguardian::server", "Management API listener error: {}", e);
                            }
                        });
                    }
                    Err(e) => error!(
                        target: "satguardian::server",
                        "Could not bind management API on {}: {}. Management routes stay off the public listener.",
                        admin_addr,
                        e
                    ),
                }
            }
            Err(e) => error!(
                target: "satguardian::server",
                "Invalid management listen address '{}': {}",
                admin_addr_str,
                e
            ),
        }
    }

    let app = axum::Router::new()
        .fallback(proxy_handler)
        .with_state(proxy_state);

    let addr: SocketAddr = config.listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    if !addr.ip().is_loopback() {
        warn!(
            target: "satguardian::server",
            "Proxy listener {} speaks plain HTTP. Terminate TLS at a trusted reverse proxy or Envoy before exposing it.",
            addr
        );
    }
    info!(target: "satguardian::server", "SATGuardian Edge WAF Server ready and listening on http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Runs the standalone T1K Acceleration Co-Processor daemon for SafeLine.
async fn run_t1k_standalone(config: WafConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        r#"
   ███████╗ █████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
   ██╔════╝██╔══██╗╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
   ███████╗███████║   ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
   ╚════██║██╔══██║   ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
   ███████║██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
             T1K ACCELERATION CO-PROCESSOR FOR SAFELINE WAF
        Cloud Boolean Optimization Powered by Security Units (SU)
                         https://satguardian.tech
    "#
    );

    let t1k_addr = config
        .t1k_listen_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:8000".to_string());

    info!(target: "satguardian::t1k", "Starting SATGuardian Edge WAF T1K Acceleration Co-Processor v{}", env!("CARGO_PKG_VERSION"));
    info!(target: "satguardian::t1k", "T1K Listen Address : {}", t1k_addr);
    info!(target: "satguardian::t1k", "Defense Mode       : {}", config.mode.to_uppercase());
    if let Some(ref ds) = config.t1k_downstream_addr {
        info!(target: "satguardian::t1k", "Downstream snserver: {}", ds);
    }
    if let Some(ref pg) = config.safeline_pg_url {
        info!(target: "satguardian::t1k", "SafeLine PostgreSQL: {}", pg);
    }

    let engine = Arc::new(SatguardianSatEngine::with_config(
        config.islands.clone(),
        config.business_rules.clone(),
    ));
    let ledger = SqliteLedger::init(&config.database_path).await?;
    let stateful_limiter = Arc::new(StatefulRateLimiter::new(config.to_stateful_config()));

    let safeline_reporter = if let Some(ref pg_url) = config.safeline_pg_url {
        match SafeLinePgReporter::connect(pg_url).await {
            Ok(rep) => {
                info!(target: "satguardian::t1k", "SafeLine PostgreSQL reporting enabled at {}", pg_url);
                Some(Arc::new(rep))
            }
            Err(e) => {
                warn!(target: "satguardian::t1k", "Failed to connect to SafeLine PostgreSQL at {}: {}. Continuing without PG sync.", pg_url, e);
                None
            }
        }
    } else {
        None
    };

    let t1k_state = Arc::new(T1kServerState::new(
        engine,
        Some(Arc::new(ledger)),
        safeline_reporter,
        Some(stateful_limiter),
        config.t1k_downstream_addr,
        config.mode,
    ));

    run_t1k_server(&t1k_addr, t1k_state).await
}

/// Standalone CLI single-payload inspector.
fn run_cli_inspect(config: &WafConfig, method: &str, path: &str, query: &str, body: &str) {
    let payload = HttpRequestPayload {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        method: method.to_string(),
        path: path.to_string(),
        query_string: query.to_string(),
        headers: HashMap::new(),
        body: body.to_string(),
        client_ip: None,
    };

    let engine = SatguardianSatEngine::with_config(config.islands.clone(), config.business_rules.clone());
    let proof = engine.evaluate_payload(&payload);

    println!("\n🔍 SATGuardian Edge WAF: Payload Inspection Report");
    println!("============================================================");
    println!("Request ID       : {}", proof.request_id);
    println!("Target Path      : {}", payload.path);
    println!("Query String     : {}", payload.query_string);
    println!("Action Decision  : {:?}", proof.action);
    println!("Attack Category  : {}", proof.category.display_name());
    println!("Latency          : {:.2} µs ({:.4} ms)", proof.execution_time_us, proof.execution_time_us / 1000.0);
    println!("Active Tokens    : {:?}", proof.active_tokens);
    println!("Certainty Islands: {:?}", proof.active_islands);
    println!("------------------------------------------------------------");
    println!("Causal Proof     :\n{}", proof.rule_match_details);
    println!("------------------------------------------------------------");
    println!("LaTeX Formal SAT Proof:\n{}", proof.decision_reason);
    println!("============================================================\n");
}

/// CLI command to check entitlement and Security Units (SU) balance from https://satguardian.tech.
async fn run_check_entitlement(
    config: &WafConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🔐 SATGuardian Edge WAF: Checking Cloud Entitlement & Security Units");
    println!("   Target API: {}", config.satguardian_api_url);

    let cloud = SatguardianCloudClient::new(
        config.satguardian_api_url.clone(),
        config.satguardian_api_token.clone(),
    );

    match cloud.get_entitlement().await {
        Ok(ent) => {
            println!("\n✅ Entitlement verified successfully!");
            println!("   Edge Traffic Inspection : {}", if ent.edge_traffic_unlimited { "UNLIMITED & FREE (Open Source Edge)" } else { "Restricted" });
            println!("   Cloud Synthesis Service : {}", if ent.cloud_synthesis_enabled { "ACTIVE" } else { "PAUSED (Quota reached - edge keeps serving with last rules)" });
            println!("   Subscription Tier       : {}", ent.subscription_tier);
            println!("   Security Units (SU)     : {} SU available", ent.su_available);
            println!("   Included Monthly SU     : {} SU/month", ent.included_su_month);
            if let Some(rate) = ent.overage_usd_per_1k_su {
                println!("   Overage Rate            : ${:.2} USD per 1,000 SU", rate);
            } else {
                println!("   Overage Policy          : Hard cap (Optimization pauses; Edge inspection never stops)");
            }
            println!("   Max Synthesis Variables : {} variables", ent.max_variables);
            if let Some(m) = ent.max_minterms {
                println!("   Max Synthesis Minterms  : {} minterms", m);
            }
            if let Some(exp) = ent.su_expires_at {
                println!("   SU Expiration           : {}", exp);
            }
            if let Some(expl) = ent.explanation {
                println!("   Details                 : {}", expl);
            }
        }
        Err(e) => {
            eprintln!("\n⚠️ Entitlement check query returned: {}", e);
            eprintln!("   Note: Local Edge WAF continues operating locally with unlimited requests.");
            eprintln!("   Ensure SATGUARDIAN_API_KEY is configured to enable Cloud Boolean Synthesis.");
        }
    }

    Ok(())
}

/// CLI command to trigger cloud simplification with https://satguardian.tech.
async fn run_sync_simplify(
    config: &WafConfig,
    limit: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("⚡ SATGuardian Edge WAF: Initiating Exact Boolean Simplification");
    println!("   Target: {}", config.satguardian_api_url);

    let ledger = SqliteLedger::init(&config.database_path).await?;
    let pending = ledger.get_pending_anomalies(limit).await?;

    if pending.is_empty() {
        println!("ℹ️  No pending novel anomalies found in {}.", config.database_path);
        return Ok(());
    }

    println!("📥 Found {} anomaly minterms to simplify.", pending.len());
    let cloud = SatguardianCloudClient::new(
        config.satguardian_api_url.clone(),
        config.satguardian_api_token.clone(),
    );

    let vars = FeatureBinarizer::get_variable_catalog(40);
    let req = SimplifyRequest {
        variables: vars.clone(),
        minterms: pending.clone(),
        dont_cares: None,
        format: Some("equation".to_string()),
    };

    let resp = cloud.simplify(&req).await?;

    println!("\n✅ Cloud Simplification Succeeded!");
    println!("   Reduction Percentage : {:.2}%", resp.reduction_percent);
    println!("   Original Gates       : {}", resp.original_gates);
    println!("   New Minimal Gates    : {}", resp.new_gates);
    println!("   Cloud Execution Time : {} ms", resp.execution_time_ms);
    println!("   SU Deducted          : {:?}", resp.su_used);
    println!("   Minimized Equation   : {}", resp.result);

    let clauses = match cloud.compile_equation_to_clauses(&resp.result, &vars) {
        Ok(clauses) if !clauses.is_empty() => clauses,
        Ok(_) => {
            eprintln!("❌ Cloud returned no usable clauses. Ledger left unchanged.");
            return Ok(());
        }
        Err(e) => {
            eprintln!(
                "❌ Cloud returned an invalid equation: {}. Ledger left unchanged.",
                e
            );
            return Ok(());
        }
    };

    let mut persisted = 0usize;
    for clause in &clauses {
        ledger.save_dynamic_clause(clause).await?;
        persisted += 1;
    }

    ledger
        .record_simplification(&resp, vars.len(), pending.len())
        .await?;
    ledger.mark_anomalies_simplified(&pending).await?;
    println!(
        "💾 Ledger updated. Anomalies marked as SIMPLIFIED and {} dynamic clauses persisted.",
        persisted
    );

    Ok(())
}

/// Runs the standalone Envoy ext_authz verification service.
async fn run_envoy_authz_standalone(config: WafConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        r#"
   ███████╗ █████╗ ████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
   ██╔════╝██╔══██╗╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
   ███████╗███████║   ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
   ╚════██║██╔══██║   ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
   ███████║██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
             SATGUARDIAN EDGE WAF - ENVOY EXT_AUTHZ SERVICE
        Cloud Boolean Optimization Powered by Security Units (SU)
                         https://satguardian.tech
    "#
    );

    let listen_addr = config
        .envoy_ext_authz_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:9002".to_string());

    info!(target: "satguardian::envoy", "Starting SATGuardian Edge WAF Envoy ext_authz Service v{}", env!("CARGO_PKG_VERSION"));
    info!(target: "satguardian::envoy", "ext_authz Listen Address: {}", listen_addr);
    info!(target: "satguardian::envoy", "Defense Mode            : {}", config.mode.to_uppercase());
    info!(target: "satguardian::envoy", "Cloud API URL           : {}", config.satguardian_api_url);
    info!(target: "satguardian::envoy", "SQLite Ledger           : {}", config.database_path);

    let engine = Arc::new(SatguardianSatEngine::with_config(
        config.islands.clone(),
        config.business_rules.clone(),
    ));
    let ledger = SqliteLedger::init(&config.database_path).await?;
    let stateful_limiter = Arc::new(StatefulRateLimiter::new(config.to_stateful_config()));
    let trusted_proxies = TrustedProxies::parse(&config.trusted_proxies)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let envoy_state = EnvoyAuthzState::new(
        engine,
        ledger,
        stateful_limiter,
        config.mode.clone(),
    )
    .with_stealth(config.stealth_mode)
    .with_trusted_proxies(trusted_proxies);

    let app = create_envoy_authz_router(envoy_state);

    if let Some(_socket_path) = config.envoy_ext_authz_socket {
        #[cfg(unix)]
        {
            info!(target: "satguardian::envoy", "Envoy ext_authz starting in Unix Domain Socket mode: {}", _socket_path);
            return satguardian_waf::envoy::serve_uds(app, &_socket_path).await;
        }
        #[cfg(not(unix))]
        {
            warn!(target: "satguardian::envoy", "Unix Domain Sockets (UDS) are only supported natively on Unix/Linux systems. Falling back to TCP address: {}", listen_addr);
        }
    }

    let addr: SocketAddr = listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(target: "satguardian::envoy", "SATGuardian Edge WAF Envoy ext_authz listening on http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
