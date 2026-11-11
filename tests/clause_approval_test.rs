//! The control boundary of the product: cloud synthesis arrives as proposals and only an
//! operator's approval puts a clause into force.

use satguardian_waf::engine::DynamicCompiledClause;
use satguardian_waf::ledger::SqliteLedger;
use satguardian_waf::types::AttackCategory;

fn clause(id: &str) -> DynamicCompiledClause {
    DynamicCompiledClause {
        clause_id: id.to_string(),
        description: format!("synthesized proposal {id}"),
        required_mask: 0b1011,
        expected_bits: 0b1001,
        category: AttackCategory::Unknown,
    }
}

async fn ledger_in_temp_dir(tag: &str) -> (SqliteLedger, std::path::PathBuf) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "satguardian_approval_{}_{}_{}.db",
        tag,
        std::process::id(),
        nonce
    ));
    let ledger = SqliteLedger::init(path.to_str().expect("temp ledger path must be valid utf-8"))
        .await
        .expect("ledger init");
    (ledger, path)
}

fn remove_ledger_files(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_os_string();
        p.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(p));
    }
}

#[tokio::test]
async fn a_proposal_waits_for_approval_and_survives_it() {
    let (ledger, path) = ledger_in_temp_dir("wait").await;

    assert!(ledger
        .propose_dynamic_clause(&clause("sat-prop-1"))
        .await
        .unwrap());

    let pending = ledger.load_pending_clauses().await.unwrap();
    assert_eq!(pending.len(), 1, "the proposal must be visible for review");
    assert_eq!(pending[0].0.clause_id, "sat-prop-1");

    // This is the call the proxy makes at boot: a proposal must never come back in it.
    assert!(
        ledger.load_applied_clauses().await.unwrap().is_empty(),
        "an unapproved proposal must not be loaded as an enforcing rule"
    );

    let approved = ledger.approve_dynamic_clause("sat-prop-1").await.unwrap();
    assert!(
        approved.is_some(),
        "approving a known proposal returns the clause"
    );
    assert!(ledger.load_pending_clauses().await.unwrap().is_empty());

    let applied = ledger.load_applied_clauses().await.unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].required_mask, 0b1011);
    assert_eq!(applied[0].expected_bits, 0b1001);

    remove_ledger_files(&path);
}

#[tokio::test]
async fn approving_or_rejecting_an_unknown_clause_changes_nothing() {
    let (ledger, path) = ledger_in_temp_dir("unknown").await;

    assert!(ledger
        .approve_dynamic_clause("ghost")
        .await
        .unwrap()
        .is_none());
    assert!(
        !ledger.reject_dynamic_clause("ghost").await.unwrap(),
        "a decision about a clause that does not exist must report that"
    );

    remove_ledger_files(&path);
}

#[tokio::test]
async fn rejecting_removes_the_proposal_but_never_an_enforcing_rule() {
    let (ledger, path) = ledger_in_temp_dir("reject").await;

    ledger
        .propose_dynamic_clause(&clause("sat-enforced"))
        .await
        .unwrap();
    assert!(ledger
        .approve_dynamic_clause("sat-enforced")
        .await
        .unwrap()
        .is_some());

    assert!(
        !ledger.reject_dynamic_clause("sat-enforced").await.unwrap(),
        "rejecting an update must not delete protection that is already running"
    );
    assert_eq!(ledger.load_applied_clauses().await.unwrap().len(), 1);

    ledger
        .propose_dynamic_clause(&clause("sat-discard"))
        .await
        .unwrap();
    assert!(ledger.reject_dynamic_clause("sat-discard").await.unwrap());
    assert!(ledger.load_pending_clauses().await.unwrap().is_empty());
    assert_eq!(ledger.load_applied_clauses().await.unwrap().len(), 1);

    remove_ledger_files(&path);
}

#[tokio::test]
async fn the_same_proposal_is_not_stored_twice() {
    let (ledger, path) = ledger_in_temp_dir("duplicate").await;

    assert!(ledger
        .propose_dynamic_clause(&clause("sat-prop-3"))
        .await
        .unwrap());
    assert!(
        !ledger
            .propose_dynamic_clause(&clause("sat-prop-3"))
            .await
            .unwrap(),
        "a repeated sync must not queue the same clause twice"
    );
    assert_eq!(ledger.load_pending_clauses().await.unwrap().len(), 1);

    remove_ledger_files(&path);
}
