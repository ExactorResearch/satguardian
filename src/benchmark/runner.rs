use crate::engine::SatguardianSatEngine;
use crate::types::{AttackCategory, HttpRequestPayload};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Deserialize)]
struct Corpus {
    version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    category: String,
    label: String,
    request: RequestSpec,
}

#[derive(Debug, Deserialize)]
struct RequestSpec {
    method: String,
    path: String,
    query: String,
    body: String,
    #[serde(default)]
    headers: HashMap<String, String>,
}

pub struct BenchmarkSuite;

impl BenchmarkSuite {
    fn load_corpus() -> (Corpus, Vec<HttpRequestPayload>) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/independent_v1.json");
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "Cannot read the versioned corpus at {}. Benchmarks must use a checked-in, \
                 labelled corpus rather than an ad-hoc payload list: {e}",
                path.display()
            )
        });
        let corpus: Corpus =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Invalid corpus JSON: {e}"));

        let payloads = corpus
            .cases
            .iter()
            .map(|case| {
                let mut req = HttpRequestPayload::new(
                    case.request.method.clone(),
                    case.request.path.clone(),
                    case.request.query.clone(),
                    case.request.body.clone(),
                );
                req.headers = case
                    .request
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
                    .collect();
                req
            })
            .collect();

        (corpus, payloads)
    }

    /// Runs the in-memory engine benchmark over the checked-in regression corpus.
    ///
    /// This measures rule evaluation only (no network hop, no upstream, no TLS).
    /// Accuracy is computed on the same cases used for latency, and the corpus is
    /// in-sample: it is a regression floor, not a held-out quality estimate.
    pub fn run_benchmark(num_requests: usize) {
        if num_requests == 0 {
            println!("Benchmark skipped: request count must be greater than zero.");
            return;
        }

        let (corpus, dataset) = Self::load_corpus();
        let dataset_len = dataset.len();
        let engine = SatguardianSatEngine::new();

        println!("============================================================");
        println!("SATGuardian Edge WAF: In-Memory Engine Benchmark");
        println!("   Engine        : deterministic SAT + Certainty Islands (Rust)");
        println!("   Corpus        : corpus/independent_v1.json ({})", corpus.version);
        println!(
            "   Cases         : {} ({} labelled attacks, {} benign)",
            corpus.cases.len(),
            corpus.cases.iter().filter(|c| c.label == "malicious").count(),
            corpus.cases.iter().filter(|c| c.label == "benign").count()
        );
        println!("   Requests      : {} (corpus cycled)", num_requests);
        println!("============================================================");
        println!("   Scope: in-memory rule evaluation only. No network, proxy,");
        println!("   TLS, upstream or stateful tracking is included.");
        println!("   Accuracy is in-sample regression, not a held-out estimate.");
        println!("============================================================\n");

        // Accuracy pass: one proof per labelled case.
        let mut true_positives = 0usize;
        let mut false_negatives = Vec::new();
        let mut true_negatives = 0usize;
        let mut false_positives = Vec::new();
        let mut category_mismatches = 0usize;

        for (case, req) in corpus.cases.iter().zip(dataset.iter()) {
            let proof = engine.evaluate_payload(req);
            if case.label == "malicious" {
                if proof.is_violation {
                    true_positives += 1;
                    if proof.category != AttackCategory::parse(&case.category) {
                        category_mismatches += 1;
                    }
                } else {
                    false_negatives.push(case.id.clone());
                }
            } else if proof.is_violation {
                false_positives.push(format!("{} ({})", case.id, proof.category));
            } else {
                true_negatives += 1;
            }
        }

        let malicious = true_positives + false_negatives.len();
        let benign = true_negatives + false_positives.len();
        let recall = if malicious == 0 {
            1.0
        } else {
            true_positives as f64 / malicious as f64
        };
        let fpr = if benign == 0 {
            0.0
        } else {
            false_positives.len() as f64 / benign as f64
        };

        // Latency pass: cycle the same corpus to reach the requested request count.
        let mut latencies_us = Vec::with_capacity(num_requests);
        let t_total_start = Instant::now();
        for i in 0..num_requests {
            let req = &dataset[i % dataset_len];
            let proof = engine.evaluate_payload(req);
            latencies_us.push(proof.execution_time_us);
        }
        let total_duration = t_total_start.elapsed();
        let total_secs = total_duration.as_secs_f64();
        let throughput = (num_requests as f64) / total_secs;

        latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let min_lat = latencies_us.first().copied().unwrap_or(0.0);
        let max_lat = latencies_us.last().copied().unwrap_or(0.0);
        let avg_lat: f64 = latencies_us.iter().sum::<f64>() / (num_requests as f64);
        let percentile = |p: f64| -> f64 {
            let rank = ((num_requests as f64 * p).ceil() as usize).saturating_sub(1);
            latencies_us[rank.min(num_requests - 1)]
        };
        let p50 = percentile(0.50);
        let p90 = percentile(0.90);
        let p99 = percentile(0.99);

        println!("Detection on the labelled corpus (in-sample regression):");
        println!("   True positives       : {} / {}", true_positives, malicious);
        println!("   False negatives      : {}{}", false_negatives.len(), if false_negatives.is_empty() { String::new() } else { format!(" -> {}", false_negatives.join(", ")) });
        println!("   True negatives       : {} / {}", true_negatives, benign);
        println!("   False positives      : {}{}", false_positives.len(), if false_positives.is_empty() { String::new() } else { format!(" -> {}", false_positives.join(", ")) });
        println!("   Recall               : {:.2}%", recall * 100.0);
        println!("   False-positive rate  : {:.2}%", fpr * 100.0);
        println!("   Category mismatches  : {}", category_mismatches);
        println!();
        println!("Latency distribution (microseconds, in-memory only):");
        println!("   Min                  : {:>10.2} µs", min_lat);
        println!("   Average              : {:>10.2} µs", avg_lat);
        println!("   p50 (median)         : {:>10.2} µs", p50);
        println!("   p90                  : {:>10.2} µs", p90);
        println!("   p99                  : {:>10.2} µs", p99);
        println!("   Max                  : {:>10.2} µs", max_lat);
        println!("   Throughput           : {:>10.2} req/sec (single thread)", throughput);
        println!();
        if p99 < 50.0 {
            println!("Verification: p99 engine latency {:.2} µs is under the 50 µs target.", p99);
        } else {
            println!("Verification: p99 engine latency is {:.2} µs, above the 50 µs target.", p99);
        }
        println!("Do not compare these numbers with the Python benchmark harness: its");
        println!("Coraza/SafeLine/Regex agents are Python stand-ins, not the real products.");
        println!("============================================================\n");

        if !false_negatives.is_empty() || !false_positives.is_empty() {
            println!(
                "WARNING: the corpus regression is not clean (FN={}, FP={}).",
                false_negatives.len(),
                false_positives.len()
            );
        }
    }
}
