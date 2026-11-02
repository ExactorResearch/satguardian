//! Lightweight latency statistics shared by the proxy, T1K co-processor and API.
//! Uses fixed log2 buckets so observation is lock-free and p99 is measured, not estimated.

use std::sync::atomic::{AtomicU64, Ordering};

const BUCKETS: usize = 64;

pub struct LatencyHistogram {
    buckets: [AtomicU64; BUCKETS],
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl LatencyHistogram {
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, us: u64) {
        let idx = if us <= 1 {
            0
        } else {
            (63 - us.leading_zeros() as usize).min(BUCKETS - 1)
        };
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn avg_us(&self) -> f64 {
        let count = self.count();
        if count == 0 {
            return 0.0;
        }
        self.sum_us.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Upper bound of the bucket containing the requested percentile.
    pub fn percentile_us(&self, p: f64) -> f64 {
        let total = self.count();
        if total == 0 {
            return 0.0;
        }
        let target = ((total as f64) * p.clamp(0.0, 1.0)).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;
        for (idx, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                return if idx == 0 {
                    1.0
                } else if idx == BUCKETS - 1 {
                    u64::MAX as f64
                } else {
                    ((1u64 << (idx + 1)) - 1) as f64
                };
            }
        }
        self.avg_us()
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}
