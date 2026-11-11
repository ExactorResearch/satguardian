use satguardian_waf::engine::SatguardianSatEngine;
use satguardian_waf::types::{AttackCategory, HttpRequestPayload};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

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
struct Report {
    true_positives: usize,
    true_negatives: usize,
    false_negatives: Vec<String>,
    false_positives: Vec<String>,
    category_mismatches: Vec<String>,
    per_category: BTreeMap<String, (usize, usize)>,
}

impl Report {
    fn recall(&self) -> f64 {
        let total = self.true_positives + self.false_negatives.len();
        if total == 0 {
            1.0
        } else {
            self.true_positives as f64 / total as f64
        }
    }

    fn fpr(&self) -> f64 {
        let total = self.true_negatives + self.false_positives.len();
        if total == 0 {
            0.0
        } else {
            self.false_positives.len() as f64 / total as f64
        }
    }
}

fn load_corpus(file: &str) -> Corpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read corpus {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid corpus JSON: {e}"))
}

fn run_corpus(corpus: &Corpus) -> Report {
    let engine = SatguardianSatEngine::new();

    // Warm up lazily compiled regex singletons so latency is not part of this assertion.
    let warmup = HttpRequestPayload::new("GET", "/", "", "");
    let _ = engine.evaluate_payload(&warmup);

    let mut report = Report::default();

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

        if case.label == "malicious" {
            let entry = report
                .per_category
                .entry(case.category.clone())
                .or_insert((0, 0));
            entry.1 += 1;
            if proof.is_violation {
                report.true_positives += 1;
                entry.0 += 1;
                let expected = AttackCategory::parse(&case.category);
                if proof.category != expected {
                    report.category_mismatches.push(format!(
                        "{}: expected {}, got {}",
                        case.id, expected, proof.category
                    ));
                }
            } else {
                report
                    .false_negatives
                    .push(format!("{} ({})", case.id, case.category));
            }
        } else if proof.is_violation {
            report.false_positives.push(format!(
                "{}: blocked as {} via {}",
                case.id, proof.category, proof.rule_match_details
            ));
        } else {
            report.true_negatives += 1;
        }
    }

    report
}

fn print_report(label: &str, corpus: &Corpus, report: &Report) {
    let malicious = report.true_positives + report.false_negatives.len();
    let benign = report.true_negatives + report.false_positives.len();
    println!("\n=== {label} ({}) ===", corpus.version);
    println!("malicious={malicious} benign={benign}");
    println!(
        "TP={} FN={} TN={} FP={}",
        report.true_positives,
        report.false_negatives.len(),
        report.true_negatives,
        report.false_positives.len()
    );
    println!(
        "recall={:.4} false_positive_rate={:.4}",
        report.recall(),
        report.fpr()
    );
    println!("per-category recall:");
    for (category, (hits, total)) in &report.per_category {
        println!(
            "  {category:28} {hits:3}/{total:<3} ({:.1}%)",
            *hits as f64 / *total as f64 * 100.0
        );
    }
    for miss in &report.false_negatives {
        println!("  MISS {miss}");
    }
    for fp in &report.false_positives {
        println!("  FP   {fp}");
    }
    for mismatch in &report.category_mismatches {
        println!("  CAT  {mismatch}");
    }
}

fn assert_clean(label: &str, report: &Report) {
    assert!(
        report.false_negatives.is_empty(),
        "{label} false negatives ({}): {}",
        report.false_negatives.len(),
        report.false_negatives.join(", ")
    );
    assert!(
        report.false_positives.is_empty(),
        "{label} false positives ({}): {}",
        report.false_positives.len(),
        report.false_positives.join(" | ")
    );
    assert!(
        report.category_mismatches.is_empty(),
        "{label} category attribution errors: {}",
        report.category_mismatches.join(" | ")
    );
    assert!(
        report.recall() >= 0.99,
        "{label} recall regression: {:.4}",
        report.recall()
    );
    assert!(
        report.fpr() <= 0.01,
        "{label} FPR regression: {:.4}",
        report.fpr()
    );
}

fn validate_corpus(corpus: &Corpus) {
    let mut seen = std::collections::HashSet::new();
    for case in &corpus.cases {
        assert!(
            seen.insert(case.id.clone()),
            "duplicate corpus id: {}",
            case.id
        );
        assert!(
            case.label == "malicious" || case.label == "benign",
            "{}: invalid label '{}'",
            case.id,
            case.label
        );
        assert!(
            !case.note.trim().is_empty(),
            "{}: missing provenance note",
            case.id
        );
    }
}

#[test]
fn independent_corpus_detection_quality() {
    let corpus = load_corpus("independent_v1.json");
    assert_eq!(corpus.version, "independent-v1");
    validate_corpus(&corpus);
    let report = run_corpus(&corpus);
    print_report("Independent corpus regression", &corpus, &report);
    assert_clean("independent corpus", &report);
}

#[test]
fn heldout_corpus_regression_quality() {
    let corpus = load_corpus("heldout_v1.json");
    assert_eq!(corpus.version, "heldout-v1");
    validate_corpus(&corpus);
    let report = run_corpus(&corpus);
    print_report("Held-out corpus regression", &corpus, &report);
    assert_clean("held-out corpus", &report);
}

#[test]
fn corpus_has_cross_category_coverage() {
    let corpus = load_corpus("independent_v1.json");
    let mut attacks = BTreeMap::new();
    let mut benign = 0usize;
    for case in &corpus.cases {
        if case.label == "malicious" {
            *attacks.entry(case.category.clone()).or_insert(0usize) += 1;
        } else {
            benign += 1;
        }
    }

    for required in [
        "sql_injection",
        "xss",
        "command_injection",
        "path_traversal",
        "ssrf",
        "graphql_abuse",
        "prototype_pollution",
        "jwt_tampering",
        "framework_exploit_probe",
        "cms_wordpress_probe",
        "sensitive_exposure_probe",
    ] {
        assert!(
            attacks.get(required).copied().unwrap_or(0) > 0,
            "corpus lost coverage for {required}"
        );
    }
    assert!(
        benign >= 15,
        "corpus must keep a meaningful benign control set"
    );
}
