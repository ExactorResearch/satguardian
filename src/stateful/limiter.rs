use crate::stateful::sliding_window::SlidingWindowRingCounter;
use crate::types::HttpRequestPayload;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Configuration parameters for stateful and behavioral defense.
#[derive(Debug, Clone)]
pub struct StatefulConfig {
    pub enabled: bool,
    pub window_secs: u64,
    pub num_buckets: usize,
    pub global_limit_per_window: u32,
    pub auth_limit_per_window: u32,
    pub ban_duration_secs: u64,
    pub max_tracked_clients: usize,
    pub redis_url: Option<String>,
}

impl Default for StatefulConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 60,
            num_buckets: 12, // 5 seconds per bucket
            global_limit_per_window: 300, // 5 req/sec avg
            auth_limit_per_window: 15,    // Credential stuffing limit on /login
            ban_duration_secs: 180,       // 3-minute temporary jail
            max_tracked_clients: 50_000,  // Bounded memory ceiling (DoS defense)
            redis_url: None,
        }
    }
}

/// Evaluation outcome from the stateful inspection layer.
#[derive(Debug, Clone, Default)]
pub struct StatefulVerdict {
    pub is_violation: bool,
    pub is_rate_limit: bool,
    pub is_credential_stuffing: bool,
    pub is_banned: bool,
    pub global_count: u32,
    pub auth_count: u32,
    pub reason: String,
}

struct ClientRecord {
    global_counter: SlidingWindowRingCounter,
    auth_counter: SlidingWindowRingCounter,
    last_seen_epoch: AtomicU64,
    banned_until_epoch: AtomicU64,
}

impl ClientRecord {
    fn new(window_secs: u64, num_buckets: usize) -> Self {
        Self {
            global_counter: SlidingWindowRingCounter::new(window_secs, num_buckets),
            auth_counter: SlidingWindowRingCounter::new(window_secs, num_buckets),
            last_seen_epoch: AtomicU64::new(SlidingWindowRingCounter::current_epoch_secs()),
            banned_until_epoch: AtomicU64::new(0),
        }
    }
}

/// Thread-safe Stateful Behavioral Limiter defending against L7 DDoS, Distributed Brute Force, and Credential Stuffing.
pub struct StatefulRateLimiter {
    pub config: StatefulConfig,
    clients: RwLock<HashMap<String, Arc<ClientRecord>>>,
}

impl StatefulRateLimiter {
    pub fn new(config: StatefulConfig) -> Self {
        Self {
            config,
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the current number of tracked IP records in memory.
    pub fn tracked_clients_count(&self) -> usize {
        self.clients.read().unwrap().len()
    }

    /// Evaluates an incoming request against temporal sliding windows.
    pub fn check_and_update(&self, req: &HttpRequestPayload) -> StatefulVerdict {
        if !self.config.enabled {
            return StatefulVerdict::default();
        }

        let client_ip = req
            .client_ip
            .as_deref()
            .unwrap_or_else(|| {
                req.headers
                    .get("x-forwarded-for")
                    .map(|s| s.as_str())
                    .unwrap_or("127.0.0.1")
            })
            .split(',')
            .next()
            .unwrap_or("127.0.0.1")
            .trim()
            .to_string();

        let now_secs = SlidingWindowRingCounter::current_epoch_secs();

        // Retrieve or create client record with bounded memory guarantee
        let record = {
            let r = self.clients.read().unwrap();
            if let Some(rec) = r.get(&client_ip) {
                Arc::clone(rec)
            } else {
                drop(r);
                let mut w = self.clients.write().unwrap();
                if w.len() >= self.config.max_tracked_clients {
                    // Prune stale records where last_seen_epoch is older than window_secs + ban_duration_secs
                    let cutoff = now_secs.saturating_sub(self.config.window_secs + self.config.ban_duration_secs);
                    w.retain(|_, rec| rec.last_seen_epoch.load(Ordering::Relaxed) > cutoff);

                    // If still at capacity under adversarial IP flooding, evict oldest 10%
                    if w.len() >= self.config.max_tracked_clients {
                        let mut entries: Vec<(String, u64)> = w
                            .iter()
                            .map(|(k, v)| (k.clone(), v.last_seen_epoch.load(Ordering::Relaxed)))
                            .collect();
                        entries.sort_unstable_by_key(|e| e.1);
                        let evict_count = (self.config.max_tracked_clients / 10).max(1);
                        for (old_ip, _) in entries.into_iter().take(evict_count) {
                            w.remove(&old_ip);
                        }
                    }
                }
                w.entry(client_ip.clone())
                    .or_insert_with(|| Arc::new(ClientRecord::new(self.config.window_secs, self.config.num_buckets)))
                    .clone()
            }
        };

        record.last_seen_epoch.store(now_secs, Ordering::Release);

        // 1. Check if client is currently in ban jail
        let banned_until = record.banned_until_epoch.load(Ordering::Acquire);
        if banned_until > now_secs {
            let remaining = banned_until - now_secs;
            return StatefulVerdict {
                is_violation: true,
                is_rate_limit: true,
                is_credential_stuffing: false,
                is_banned: true,
                global_count: record.global_counter.get_window_count(now_secs),
                auth_count: record.auth_counter.get_window_count(now_secs),
                reason: format!("Client IP [{}] is temporarily quarantined in stateful jail ({}s remaining)", client_ip, remaining),
            };
        }

        // 2. Record global request hit
        let global_count = record.global_counter.record_hit(now_secs);
        if global_count > self.config.global_limit_per_window {
            let ban_until = now_secs + self.config.ban_duration_secs;
            record.banned_until_epoch.store(ban_until, Ordering::Release);
            return StatefulVerdict {
                is_violation: true,
                is_rate_limit: true,
                is_credential_stuffing: false,
                is_banned: false,
                global_count,
                auth_count: record.auth_counter.get_window_count(now_secs),
                reason: format!(
                    "L7 Request Burst Limit Exceeded: {} requests in {}s sliding window (threshold: {})",
                    global_count, self.config.window_secs, self.config.global_limit_per_window
                ),
            };
        }

        // 3. Inspect sensitive auth endpoints for Credential Stuffing / Brute Force
        let is_sensitive_auth = Self::is_auth_endpoint(&req.path)
            && (req.method.eq_ignore_ascii_case("POST") || req.method.eq_ignore_ascii_case("PUT"));

        if is_sensitive_auth {
            let auth_count = record.auth_counter.record_hit(now_secs);
            if auth_count > self.config.auth_limit_per_window {
                let ban_until = now_secs + self.config.ban_duration_secs;
                record.banned_until_epoch.store(ban_until, Ordering::Release);
                return StatefulVerdict {
                    is_violation: true,
                    is_rate_limit: false,
                    is_credential_stuffing: true,
                    is_banned: false,
                    global_count,
                    auth_count,
                    reason: format!(
                        "Credential Stuffing / Auth Endpoint Flooding: {} attempts in {}s sliding window (threshold: {})",
                        auth_count, self.config.window_secs, self.config.auth_limit_per_window
                    ),
                };
            }
        }

        StatefulVerdict {
            is_violation: false,
            is_rate_limit: false,
            is_credential_stuffing: false,
            is_banned: false,
            global_count,
            auth_count: record.auth_counter.get_window_count(now_secs),
            reason: "Within normal behavioral sliding window thresholds".to_string(),
        }
    }

    /// Identifies high-risk authentication and credential endpoints.
    pub fn is_auth_endpoint(path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        p.contains("/login")
            || p.contains("/signin")
            || p.contains("/auth")
            || p.contains("/oauth")
            || p.contains("/token")
            || p.contains("/password")
            || p.contains("/session")
            || p.contains("/v1/auth")
            || p.contains("/api/auth")
    }

    /// Prunes stale IP records older than 10 minutes to maintain constant memory footprint.
    pub fn prune_stale_records(&self) {
        let now = SlidingWindowRingCounter::current_epoch_secs();
        let mut w = self.clients.write().unwrap();
        w.retain(|_, record| {
            let last_seen = record.last_seen_epoch.load(Ordering::Acquire);
            let banned_until = record.banned_until_epoch.load(Ordering::Acquire);
            (now.saturating_sub(last_seen) < 600) || (banned_until > now)
        });
    }
}
