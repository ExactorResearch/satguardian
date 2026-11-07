//! One-shot measurement of the held-out batch, written before it was ever run against the engine.
//!
//! Unlike `independent_corpus_test.rs` this file asserts nothing about detection quality: a
//! held-out estimate is only honest if the run that produces it cannot fail into a fix and then be
//! re-measured. What it does assert is that the batch itself is intact (labels, provenance, size),
//! because a silently shrinking corpus is how an estimate becomes flattering.
//!
//! Run it with `HELDOUT_V2_REPORT=corpus/heldout_v2_report.json` exactly once, when the batch is
//! still held out, and commit the JSON it writes. Without that variable it only prints.

use satguardian_waf::engine::SatguardianSatEngine;
use satguardian_waf::types::{AttackCategory, HttpRequestPayload};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Corpus {
    version: String,
    provenance: Provenance,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    description: String,
    authorship: String,
    labeling_protocol: String,
    benign_set: String,
    new_categories: String,
    status: String,
    known_limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    category: String,
    label: String,
    note: String,
    request: RequestSpec,
}

#[derive(Debug, Deserialize)]
struct RequestSpec {
    method: String,
    path: String,
    query: String,
    body: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct Measurement {
    detected: usize,
    missed: Vec<String>,
    cleared: usize,
    blocked_benign: Vec<String>,
    per_category: BTreeMap<String, (usize, usize)>,
    unknown_categories: Vec<String>,
}

impl Measurement {
    fn attacks(&self) -> usize {
        self.detected + self.missed.len()
    }

    fn benign(&self) -> usize {
        self.cleared + self.blocked_benign.len()
    }

    fn recall(&self) -> f64 {
        if self.attacks() == 0 {
            1.0
        } else {
            self.detected as f64 / self.attacks() as f64
        }
    }

    fn fpr(&self) -> f64 {
        if self.benign() == 0 {
            0.0
        } else {
            self.blocked_benign.len() as f64 / self.benign() as f64
        }
    }
}

/// 95% Wilson score interval: with 57 controls, "0 false positives" only bounds the rate near 5%.
fn wilson(successes: usize, total: usize) -> (f64, f64) {
    if total == 0 {
        return (0.0, 0.0);
    }
    let n = total as f64;
    let p = successes as f64 / n;
    let z = 1.959_963_984_f64;
    let denom = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denom;
    let spread = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt() / denom;
    ((centre - spread).max(0.0), (centre + spread).min(1.0))
}

fn load() -> Corpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("heldout_v2.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid heldout_v2 JSON: {e}"))
}

fn measure(corpus: &Corpus) -> Measurement {
    let engine = SatguardianSatEngine::new();
    let _ = engine.evaluate_payload(&HttpRequestPayload::new("GET", "/", "", ""));

    let mut m = Measurement::default();
    for case in &corpus.cases {
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

        let proof = engine.evaluate_payload(&req);
        let entry = m
            .per_category
            .entry(case.category.clone())
            .or_insert((0, 0));
        entry.1 += 1;

        if case.label == "malicious"
            && AttackCategory::parse(&case.category) == AttackCategory::Unknown
        {
            m.unknown_categories.push(case.category.clone());
        }

        if case.label == "malicious" {
            if proof.is_violation {
                m.detected += 1;
                entry.0 += 1;
            } else {
                m.missed.push(format!("{} ({})", case.id, case.category));
            }
        } else if proof.is_violation {
            m.blocked_benign.push(format!(
                "{}: blocked as {} via {}",
                case.id, proof.category, proof.rule_match_details
            ));
        } else {
            m.cleared += 1;
        }
    }
    m.unknown_categories.sort();
    m.unknown_categories.dedup();
    m
}

#[test]
fn batch_is_intact() {
    let corpus = load();
    assert_eq!(corpus.version, "heldout-v2");
    assert!(
        corpus.provenance.labeling_protocol.contains("before"),
        "the labeling protocol note was edited away"
    );
    assert!(!corpus.provenance.description.trim().is_empty());
    assert!(
        corpus.provenance.new_categories.contains("nosql_injection"),
        "the batch lost the note about categories the engine cannot name"
    );
    assert!(
        corpus.provenance.status.starts_with("HELD OUT"),
        "this batch was tuned against; cut heldout_v3"
    );
    assert!(!corpus.provenance.authorship.trim().is_empty());
    assert!(!corpus.provenance.known_limitations.is_empty());

    let mut ids = std::collections::HashSet::new();
    for case in &corpus.cases {
        assert!(ids.insert(case.id.clone()), "duplicate id {}", case.id);
        assert!(
            case.label == "malicious" || case.label == "benign",
            "{}: invalid label",
            case.id
        );
        assert!(
            !case.note.trim().is_empty(),
            "{}: no provenance note",
            case.id
        );
        assert!(
            !case.request.path.is_empty()
                || !case.request.query.is_empty()
                || !case.request.body.is_empty()
                || !case.request.headers.is_empty(),
            "{}: empty request",
            case.id
        );
    }

    let malicious = corpus
        .cases
        .iter()
        .filter(|c| c.label == "malicious")
        .count();
    let benign = corpus.cases.len() - malicious;
    assert!(
        malicious >= 90,
        "held-out batch shrank to {malicious} attacks"
    );
    assert!(benign >= 50, "held-out batch shrank to {benign} controls");
}

#[test]
fn measure_heldout_v2_once() {
    let corpus = load();
    let m = measure(&corpus);

    let recall = m.recall();
    let fpr = m.fpr();
    // Two-sided 95% intervals on both rates. FPR is reported on the false-positive count, so the
    // interval is taken over the complement and mirrored back.
    let (recall_lo, recall_hi) = wilson(m.detected, m.attacks());
    let (fpr_lo, fpr_hi) = wilson(m.cleared, m.benign());
    let (fpr_lo, fpr_lo_hi) = (1.0 - fpr_hi, 1.0 - fpr_lo);

    println!("\n=== held-out batch {} ===", corpus.version);
    println!("attacks={} controls={}", m.attacks(), m.benign());
    println!(
        "recall={:.4} (95% CI {:.4}..{:.4})  false_positive_rate={:.4} (95% CI {:.4}..{:.4})",
        recall, recall_lo, recall_hi, fpr, fpr_lo, fpr_lo_hi
    );
    println!("per-category detection:");
    for (category, (hits, total)) in &m.per_category {
        println!(
            "  {category:30} {hits:3}/{total:<3} ({:.1}%)",
            *hits as f64 / *total as f64 * 100.0
        );
    }
    for miss in &m.missed {
        println!("  MISS {miss}");
    }
    for fp in &m.blocked_benign {
        println!("  FP   {fp}");
    }

    if let Ok(out) = std::env::var("HELDOUT_V2_REPORT") {
        let body = json!({
            "version": corpus.version,
            "measured_on": "2026-11-04",
            "engine": "SatguardianSatEngine::new() with default configuration, one request per evaluation",
            "note": "First run of a batch labelled before any engine call. Tuning against these cases invalidates this file and requires heldout_v3.",
            "counts": {
                "attacks": m.attacks(),
                "controls": m.benign(),
                "detected": m.detected,
                "missed": m.missed.len(),
                "cleared": m.cleared,
                "blocked_controls": m.blocked_benign.len(),
            },
            "recall": { "value": recall, "ci95": [recall_lo, recall_hi] },
            "false_positive_rate": { "value": fpr, "ci95": [fpr_lo, fpr_lo_hi] },
            "per_category": m.per_category.iter().map(|(k, (hits, total))| (k.clone(), json!({"detected": hits, "total": total}))).collect::<serde_json::Map<String, serde_json::Value>>(),
            "missed": m.missed,
            "false_positives": m.blocked_benign,
            "categories_the_engine_does_not_name": m.unknown_categories,
            "provenance": {
                "authorship": corpus.provenance.authorship,
                "benign_set": corpus.provenance.benign_set,
                "known_limitations": corpus.provenance.known_limitations,
            },
        });
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(out);
        std::fs::write(&path, serde_json::to_string_pretty(&body).unwrap() + "\n")
            .unwrap_or_else(|e| panic!("cannot write report {}: {e}", path.display()));
        println!("report written to {}", path.display());
    }
}
