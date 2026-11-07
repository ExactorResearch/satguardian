use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Single temporal bucket inside the atomic ring buffer.
pub struct Bucket {
    pub epoch_slot: AtomicU64,
    pub count: AtomicU32,
}

impl Bucket {
    pub fn new() -> Self {
        Self {
            epoch_slot: AtomicU64::new(0),
            count: AtomicU32::new(0),
        }
    }
}

/// Ultra-high performance, lock-free temporal sliding window implemented via an atomic ring buffer.
/// Execution time is deterministic and in the order of nanoseconds ($O(1)$).
pub struct SlidingWindowRingCounter {
    pub window_secs: u64,
    pub bucket_duration_secs: u64,
    pub num_buckets: usize,
    pub buckets: Box<[Bucket]>,
}

impl SlidingWindowRingCounter {
    /// Creates a new sliding window.
    /// E.g. window_secs = 60, num_buckets = 12 -> 5 seconds per bucket.
    pub fn new(window_secs: u64, num_buckets: usize) -> Self {
        let bucket_duration_secs = (window_secs / num_buckets as u64).max(1);
        let mut buckets = Vec::with_capacity(num_buckets);
        for _ in 0..num_buckets {
            buckets.push(Bucket::new());
        }

        Self {
            window_secs,
            bucket_duration_secs,
            num_buckets,
            buckets: buckets.into_boxed_slice(),
        }
    }

    /// Records an event hit and returns the current total count within the sliding window.
    pub fn record_hit(&self, now_secs: u64) -> u32 {
        let current_slot = now_secs / self.bucket_duration_secs;
        let idx = (current_slot as usize) % self.num_buckets;
        let bucket = &self.buckets[idx];

        let prev_slot = bucket.epoch_slot.swap(current_slot, Ordering::AcqRel);
        if prev_slot != current_slot {
            // Bucket expired in a previous cycle; reset count
            bucket.count.store(1, Ordering::Release);
        } else {
            bucket.count.fetch_add(1, Ordering::Relaxed);
        }

        self.get_window_count(now_secs)
    }

    /// Computes the sum of counts across all buckets valid in [now - window_secs, now].
    pub fn get_window_count(&self, now_secs: u64) -> u32 {
        let current_slot = now_secs / self.bucket_duration_secs;
        let oldest_valid_slot =
            now_secs.saturating_sub(self.window_secs) / self.bucket_duration_secs;

        let mut sum = 0u32;
        for b in self.buckets.iter() {
            let slot = b.epoch_slot.load(Ordering::Acquire);
            if slot >= oldest_valid_slot && slot <= current_slot {
                sum += b.count.load(Ordering::Relaxed);
            }
        }
        sum
    }

    /// Helper to get current epoch in seconds.
    pub fn current_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
