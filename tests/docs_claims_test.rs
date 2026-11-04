// Guardrails against the claims retracted in STATUS.md: fabricated vendor
// comparisons, capped/floored metrics and unlabelled stand-ins must not
// reappear in published documentation or benchmark tooling.

use std::fs;
use std::path::{Path, PathBuf};

// Numeric or compliance claims that were fabricated. Checked in docs and code.
const BANNED_METRICS: &[&str] = &[
    "99.9%",
    "< 0.1%",
    "<0.1%",
    "15.0x",
    "3.38x",
    "4.4x",
    "Realism Capping",
    "Realism Policy",
    "(Capped)",
    "(Floored)",
    "up to 80%",
    "SOC 2",
    "PCI-DSS",
    "FP Verified",
    "Production-grade",
    "Sub-Microsecond",
];

// Product names that must only appear in docs when explicitly labelled as stand-ins.
// Code may name a protocol target (e.g. the T1K codec), so these are docs-only.
const BANNED_VENDOR_LABELS: &[&str] = &[
    "Coraza WAF",
    "SafeLine WAF",
    "Classical ModSecurity",
    "ModSecurity CRS v3",
];

const RETRACTION_MARKERS: &[&str] = &[
    "fabricated",
    "correction notice",
    "earlier releases",
    "earlier revisions",
    "earlier versions",
    "were removed",
    "have been removed",
    "retract",
];

const SKIP_DIRS: &[&str] = &[
    "target",
    "site",
    "node_modules",
    "__pycache__",
    ".git",
    ".qoder",
    ".idea",
    ".venv",
    "dist",
    "releases",
    "bin",
    "build",
];

const SCAN_EXTENSIONS: &[&str] = &["md", "py", "rs", "js", "html", "toml", "txt"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn collect_scannable(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect_scannable(&path, out);
        } else if name != "docs_claims_test.rs" {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if SCAN_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()) {
                out.push(path);
            }
        }
    }
}

#[test]
fn published_docs_do_not_repeat_retracted_claims() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_scannable(&root, &mut files);
    assert!(
        files.len() >= 50,
        "expected to scan docs and source, found only {} files",
        files.len()
    );

    let mut violations = Vec::new();
    for file in &files {
        let content = read(file);
        let lines: Vec<&str> = content.lines().collect();
        let is_markdown = file.extension().and_then(|e| e.to_str()) == Some("md");
        let banned: Vec<&str> = if is_markdown {
            BANNED_METRICS
                .iter()
                .chain(BANNED_VENDOR_LABELS.iter())
                .copied()
                .collect()
        } else {
            BANNED_METRICS.to_vec()
        };

        let mut sections = Vec::with_capacity(lines.len());
        let mut section = 0usize;
        for line in &lines {
            if line.trim_start().starts_with('#') {
                section += 1;
            }
            sections.push(section);
        }

        for (idx, line) in lines.iter().enumerate() {
            for &claim in &banned {
                if !line.contains(claim) {
                    continue;
                }
                let lo = idx.saturating_sub(6);
                let hi = (idx + 6).min(lines.len() - 1);
                let in_retraction_block = (lo..=hi).any(|j| {
                    sections[j] == sections[idx]
                        && RETRACTION_MARKERS
                            .iter()
                            .any(|m| lines[j].to_ascii_lowercase().contains(m))
                });
                if !in_retraction_block {
                    let rel = file.strip_prefix(&root).unwrap_or(file);
                    violations.push(format!(
                        "{}:{}: banned claim {:?} -> {}",
                        rel.display(),
                        idx + 1,
                        claim,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "retracted claims reappeared; either remove them or document the removal in a retraction block:\n{}",
        violations.join("\n")
    );
}

#[test]
fn status_file_states_the_project_is_a_prototype() {
    let root = repo_root();
    let status = read(&root.join("STATUS.md")).to_ascii_lowercase();
    assert!(status.contains("research prototype"));
    assert!(status.contains("not a production-ready waf"));
    assert!(status.contains("no independent or third-party evaluation"));
    assert!(status.contains("tests/docs_claims_test.rs"));

    assert_eq!(
        read(&root.join("STATUS.md")),
        read(&root.join("docs/status.md")),
        "docs/status.md is stale; copy STATUS.md over it"
    );
}

#[test]
fn corpus_files_are_versioned_and_labelled() {
    for (name, min_cases) in [
        ("corpus/independent_v1.json", 79usize),
        ("corpus/heldout_v1.json", 21usize),
        ("corpus/heldout_v2.json", 155usize),
    ] {
        let raw = read(&repo_root().join(name));
        let corpus: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"));
        assert!(
            corpus.get("version").and_then(|v| v.as_str()).is_some(),
            "{name} must declare a version"
        );
        assert!(corpus.get("provenance").is_some(), "{name} must declare provenance");
        let cases = corpus
            .get("cases")
            .and_then(|c| c.as_array())
            .unwrap_or_else(|| panic!("{name} must contain a cases array"));
        assert!(
            cases.len() >= min_cases,
            "{name} shrank below the documented {min_cases} cases"
        );

        for case in cases {
            let id = case.get("id").and_then(|v| v.as_str()).unwrap_or("<missing id>");
            let label = case.get("label").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                label == "malicious" || label == "benign",
                "{name} case {id} has label {label:?}; expected malicious or benign"
            );
            let note = case.get("note").and_then(|v| v.as_str()).unwrap_or("");
            assert!(!note.trim().is_empty(), "{name} case {id} needs a note for review");
            assert!(
                case.get("request").and_then(|r| r.get("method")).is_some(),
                "{name} case {id} needs a request with a method"
            );
        }
    }
}

/// The held-out numbers may only be written down the way the committed report says them.
///
/// Rewriting a published percentage is how a measurement turns into marketing. This recomputes
/// recall and the false-positive rate from `corpus/heldout_v2_report.json` and requires every
/// document that quotes them to carry the same figures.
#[test]
fn published_heldout_numbers_match_the_committed_report() {
    let root = repo_root();
    let report: serde_json::Value = serde_json::from_str(&read(&root.join("corpus/heldout_v2_report.json")))
        .expect("corpus/heldout_v2_report.json must be valid JSON");
    let counts = &report["counts"];
    let detected = counts["detected"].as_u64().expect("counts.detected");
    let attacks = counts["attacks"].as_u64().expect("counts.attacks");
    let blocked = counts["blocked_controls"].as_u64().expect("counts.blocked_controls");
    let controls = counts["controls"].as_u64().expect("counts.controls");

    let recall = format!("{:.1}", detected as f64 / attacks as f64 * 100.0);
    let fpr = format!("{:.1}", blocked as f64 / controls as f64 * 100.0);

    for name in ["STATUS.md", "docs/status.md", "corpus/README.md"] {
        let text = read(&root.join(name));
        assert!(text.contains(&format!("{recall}%")), "{name} does not carry the measured recall ({recall}%)");
        assert!(text.contains(&format!("{fpr}%")), "{name} does not carry the measured false-positive rate ({fpr}%)");
        assert!(
            text.to_lowercase().contains("held-out") && text.to_lowercase().contains("in-sample"),
            "{name} must keep both the held-out and the in-sample numbers, and say which is which"
        );
    }
}

#[test]
fn rust_benchmark_is_corpus_backed_and_scoped() {
    let runner = read(&repo_root().join("src/benchmark/runner.rs"));
    assert!(runner.contains("corpus/independent_v1.json"));
    assert!(runner.contains("Scope: in-memory rule evaluation only"));
    assert!(runner.contains("Accuracy is in-sample regression, not a held-out estimate"));
    assert!(runner.contains("Do not compare these numbers with the Python benchmark harness"));
}

#[test]
fn python_harness_labels_stand_ins_and_provenance() {
    let root = repo_root();
    let runner = read(&root.join("satguardian_waf/benchmark/runner.py"));
    assert!(runner.contains("DATASET_PROVENANCE"));
    assert!(runner.contains("BENCHMARK_DISCLAIMER"));
    assert!(runner.contains("not a held-out corpus"));

    for (file, marker) in [
        ("coraza_agent.py", "not the Coraza engine"),
        ("safeline_agent.py", "not the Chaitin SafeLine engine"),
        ("regex_baseline_agent.py", "not ModSecurity or the CRS"),
        ("jev_pure_agent.py", "not a trained or commercial model"),
        ("satguardian_agent.py", "not the native Rust engine"),
    ] {
        let src = read(&root.join("satguardian_waf/agents").join(file));
        assert!(src.contains(marker), "{file} must state {marker:?}");
    }

    let metrics = read(&root.join("satguardian_waf/benchmark/metrics.py"));
    assert!(!metrics.contains("0.999"), "metrics.py must not cap reported values");
    assert!(
        !metrics.to_ascii_lowercase().contains("floor("),
        "metrics.py must not floor reported error rates"
    );
}

#[test]
fn crate_metadata_does_not_claim_production_readiness() {
    let manifest = read(&repo_root().join("Cargo.toml")).to_ascii_lowercase();
    assert!(!manifest.contains("production-grade"));
    assert!(manifest.contains("research prototype"));
}
