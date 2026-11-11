//! Runs the native SATGuardian engine over a shared comparison corpus and writes
//! per-case verdicts in the format every external-engine adapter must emit.
//!
//! This is the comparison harness, not the shipped benchmark: it never blends the
//! in-sample regression floor with the held-out batch, because a number computed
//! over both would overstate generalisation.
//!
//! Usage:
//!   cargo run --release --bin satbench -- \
//!     --corpus benchmarks/real_comparative/corpus/unified_v1.jsonl \
//!     --out    benchmarks/real_comparative/results/satguardian/verdicts.jsonl

use satguardian_waf::engine::SatguardianSatEngine;
use satguardian_waf::types::HttpRequestPayload;
use satguardian_waf::{AstLexer, FeatureBinarizer};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Debug, Deserialize)]
struct Case {
    case_id: String,
    corpus: String,
    split: String,
    label: String,
    category: String,
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

#[derive(Debug)]
struct Args {
    corpus: PathBuf,
    out: Option<PathBuf>,
    engine_tag: String,
    limit: Option<usize>,
    dump_features: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut corpus = None;
    let mut out = None;
    let mut engine_tag = "satguardian-edge".to_string();
    let mut limit = None;
    let mut dump_features = None;
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut take = |name: &str| match argv.next() {
            Some(v) => v,
            None => die(&format!("--{name} needs a value")),
        };
        match flag.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(take("corpus"))),
            "--out" => out = Some(PathBuf::from(take("out"))),
            "--engine-tag" => engine_tag = take("engine-tag"),
            "--limit" => {
                let v = take("limit");
                limit = Some(
                    v.parse::<usize>()
                        .unwrap_or_else(|_| die("--limit must be a number")),
                );
            }
            "--dump-features" => dump_features = Some(PathBuf::from(take("dump-features"))),
            other => die(&format!("unknown argument {other}")),
        }
    }
    Args {
        corpus: corpus.unwrap_or_else(|| die("--corpus is required")),
        out,
        engine_tag,
        limit,
        dump_features,
    }
}

fn die(msg: &str) -> ! {
    eprintln!("satbench: {msg}");
    eprintln!("hint: python3 benchmarks/real_comparative/tools/normalize_corpus.py");
    process::exit(2);
}

/// Wilson score interval at 95%. Reported alongside every rate so a small
/// held-out batch cannot be presented as a precise measurement.
fn wilson(successes: usize, total: usize) -> (f64, f64) {
    if total == 0 {
        return (0.0, 1.0);
    }
    let z = 1.959_963_984_051_f64;
    let n = total as f64;
    let p = successes as f64 / n;
    let denom = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denom;
    let spread = (z / denom) * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt();
    (centre - spread, centre + spread)
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((sorted.len() as f64 * q).ceil() as usize).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn load_cases(path: &Path, limit: Option<usize>) -> Vec<Case> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => die(&format!("cannot open corpus {}: {e}", path.display())),
    };
    let reader = BufReader::new(file);
    let mut cases = Vec::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.unwrap_or_else(|e| die(&format!("{}:{}: {e}", path.display(), lineno + 1)));
        if line.trim().is_empty() {
            continue;
        }
        let case: Case = serde_json::from_str(&line).unwrap_or_else(|e| {
            die(&format!(
                "{}:{}: bad record: {e}",
                path.display(),
                lineno + 1
            ))
        });
        cases.push(case);
        if let Some(n) = limit {
            if cases.len() >= n {
                break;
            }
        }
    }
    if cases.is_empty() {
        die("the corpus produced zero cases");
    }
    cases
}

fn to_payload(case: &Case) -> HttpRequestPayload {
    let mut req = HttpRequestPayload::new(
        case.request.method.clone(),
        case.request.path.clone(),
        case.request.query.clone(),
        case.request.body.clone(),
    );
    req.id = case.case_id.clone();
    req.headers = case
        .request
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    req
}

/// One labelled case scored by one engine. Every adapter for an external engine
/// must emit records with these same keys, otherwise the comparison silently
/// compares different measurements.
fn verdict_record(
    args: &Args,
    case: &Case,
    blocked: bool,
    category: &str,
    reason: &str,
    latency_us: f64,
) -> serde_json::Value {
    json!({
        "case_id": case.case_id,
        "corpus": case.corpus,
        "split": case.split,
        "label": case.label,
        "true_category": case.category,
        "engine": args.engine_tag,
        "engine_kind": "native",
        "blocked": blocked,
        "engine_category": category,
        "matched_rules": [],
        "reason": reason,
        "latency_us": latency_us,
    })
}

/// Aggregated metrics for one (split, subset) pair.
#[derive(Default)]
struct Acc {
    attacks: usize,
    detected: usize,
    controls: usize,
    blocked_controls: usize,
    latencies: Vec<f64>,
    by_category: BTreeMap<String, (usize, usize)>,
}

impl Acc {
    fn observe(&mut self, case: &Case, blocked: bool, latency_us: f64) {
        self.latencies.push(latency_us);
        if case.label == "malicious" {
            self.attacks += 1;
            if blocked {
                self.detected += 1;
            }
            let e = self
                .by_category
                .entry(case.category.clone())
                .or_insert((0, 0));
            e.1 += 1;
            if blocked {
                e.0 += 1;
            }
        } else {
            self.controls += 1;
            if blocked {
                self.blocked_controls += 1;
            }
        }
    }

    fn report(&self, name: &str) {
        println!("--- {name} ---");
        if self.attacks == 0 && self.controls == 0 {
            println!("  no cases in this subset; no rate is computed rather than showing 0/0");
            return;
        }
        let recall = self.detected as f64 / self.attacks.max(1) as f64;
        let (rl, ru) = wilson(self.detected, self.attacks);
        let fpr = self.blocked_controls as f64 / self.controls.max(1) as f64;
        let (fl, fu) = wilson(self.blocked_controls, self.controls);
        println!(
            "  recall : {:.1}% ({}/{})  95% CI [{:.1}%, {:.1}%]",
            recall * 100.0,
            self.detected,
            self.attacks,
            rl * 100.0,
            ru * 100.0
        );
        println!(
            "  fpr    : {:.1}% ({}/{})  95% CI [{:.1}%, {:.1}%]",
            fpr * 100.0,
            self.blocked_controls,
            self.controls,
            fl * 100.0,
            fu * 100.0
        );
        let mut lat = self.latencies.clone();
        lat.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mean = lat.iter().sum::<f64>() / lat.len() as f64;
        println!(
            "  latency: p50 {:.1} us  p99 {:.1} us  mean {:.1} us  (in-memory rule evaluation only)",
            percentile(&lat, 0.50),
            percentile(&lat, 0.99),
            mean
        );
        println!("  per-category detected/attacks:");
        for (cat, (hit, total)) in &self.by_category {
            if *hit != *total {
                println!("    {cat:26} {hit}/{total}");
            }
        }
    }
}

fn main() {
    let args = parse_args();
    let cases = load_cases(&args.corpus, args.limit);
    let engine = SatguardianSatEngine::new();

    let mut out: Option<std::fs::File> = args.out.as_ref().map(|p| {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::File::create(p)
            .unwrap_or_else(|e| die(&format!("cannot write verdicts to {}: {e}", p.display())))
    });

    // Optional feature-bit dump for the offline generalizer: the exact
    // v0..vN bitmask the engine computed for each case, with its label.
    let mut feat_out: Option<std::fs::File> = args.dump_features.as_ref().map(|p| {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::File::create(p)
            .unwrap_or_else(|e| die(&format!("cannot write features to {}: {e}", p.display())))
    });

    let mut held_out = Acc::default();
    let mut tuning = Acc::default();
    let mut vendor = Acc::default();
    let mut all = Acc::default();
    let mut seen = HashSet::new();
    let mut unknown_splits = Vec::new();

    for case in &cases {
        if !seen.insert(&case.case_id) {
            die(&format!("duplicate case_id {} in the corpus", case.case_id));
        }
        let payload = to_payload(case);
        let proof = engine.evaluate_payload(&payload);
        let category = proof.category.as_str().to_string();
        let reason = format!("{} :: {}", proof.decision_reason, proof.rule_match_details);

        match case.split.as_str() {
            "held_out" | "vendor_in_sample" => {
                if case.split == "vendor_in_sample" {
                    vendor.observe(case, proof.is_violation, proof.execution_time_us)
                } else {
                    held_out.observe(case, proof.is_violation, proof.execution_time_us)
                }
            }
            "in_sample_regression" | "consumed_for_tuning" => {
                tuning.observe(case, proof.is_violation, proof.execution_time_us)
            }
            "unlabelled" => {}
            other => unknown_splits.push(other.to_string()),
        }
        if case.label != "unlabelled" {
            all.observe(case, proof.is_violation, proof.execution_time_us);
        }

        let rec = verdict_record(
            &args,
            case,
            proof.is_violation,
            &category,
            &reason,
            proof.execution_time_us,
        );
        if let Some(f) = out.as_mut() {
            writeln!(f, "{rec}").expect("writing verdicts");
        }
        if let Some(f) = feat_out.as_mut() {
            let tokens = AstLexer::tokenize_request(&payload);
            let fv = FeatureBinarizer::binarize(&payload, &tokens);
            let frec = json!({
                "case_id": case.case_id,
                "corpus": case.corpus,
                "split": case.split,
                "label": case.label,
                "category": case.category,
                "bits_lo": fv.bits as u64,
                "bits_hi": (fv.bits >> 64) as u64,
                "blocked": proof.is_violation,
            });
            writeln!(f, "{frec}").expect("writing features");
        }
    }

    if !unknown_splits.is_empty() {
        die(&format!(
            "corpus carries splits this harness does not know how to interpret: {}; \
             refusing to guess whether they may be published",
            unknown_splits.join(", ")
        ));
    }

    println!("SATGuardian comparison run");
    println!("  engine      : {}", args.engine_tag);
    println!("  corpus      {}", args.corpus.display());
    println!("  cases       {}", cases.len());
    if let Some(p) = &args.out {
        println!("  verdicts    {}", p.display());
    }
    held_out.report("HELD-OUT (the only publishable quality estimate)");
    vendor.report("VENDOR IN-SAMPLE (the rule set's own tests: near-perfect by construction)");
    tuning.report("TUNING SETS (regression floor only - never quote as accuracy)");
    all.report("ALL CASES COMBINED (not comparable across engines; listed for completeness)");

    // Same stdout shape for scripts that scrape it without reading the verdict file.
    let compact = json!({
        "engine": args.engine_tag,
        "corpus": args.corpus.display().to_string(),
        "cases": cases.len(),
        "held_out": {
            "attacks": held_out.attacks,
            "detected": held_out.detected,
            "controls": held_out.controls,
            "blocked_controls": held_out.blocked_controls,
        },
        "tuning": {
            "attacks": tuning.attacks,
            "detected": tuning.detected,
            "controls": tuning.controls,
            "blocked_controls": tuning.blocked_controls,
        },
        "vendor_in_sample": {
            "attacks": vendor.attacks,
            "detected": vendor.detected,
            "controls": vendor.controls,
            "blocked_controls": vendor.blocked_controls,
        },
        "unlabelled_cases": cases.iter().filter(|c| c.label == "unlabelled").count(),
    });
    println!("\nSUMMARY_JSON {compact}");
}
