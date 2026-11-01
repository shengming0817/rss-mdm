use rss_mdm_install_support::{accepted_ledger, resumable_ledger, transaction_body};
use sha2::{Digest, Sha256};
#[test]
fn resumable_prefix_requires_exact_complete_ordered_source_units() {
    let source = vec![("a", "SELECT 1;"), ("b", "SELECT 2;"), ("c", "SELECT 3;")];
    let row = |i: usize| {
        (
            source[i].0.to_owned(),
            format!("{:x}", Sha256::digest(source[i].1)),
            true,
        )
    };
    assert!(resumable_ledger(&[], &source));
    assert!(resumable_ledger(&[row(0)], &source));
    assert!(resumable_ledger(&[row(1), row(0)], &source)); // Database row order is irrelevant.
    assert!(!resumable_ledger(&[row(0), row(2)], &source));
    assert!(!resumable_ledger(&[row(0), row(0)], &source));
    let mut incomplete = row(0);
    incomplete.2 = false;
    assert!(!resumable_ledger(&[incomplete], &source));
    let mut changed = row(0);
    changed.1 = "changed".into();
    assert!(!resumable_ledger(&[changed], &source));
    assert!(!accepted_ledger(&[row(0)], &source)); // Runtime never admits a partial installation.
}

#[test]
fn envelopes_reject_nested_or_unclosed_transactions() {
    assert_eq!(
        transaction_body("-- header\nBEGIN;\nSELECT 1;\nCOMMIT;\n-- end").unwrap(),
        vec!["SELECT 1;\n"]
    );
    assert_eq!(
        transaction_body("SELECT 1;\nBEGIN;\nSELECT 2;\nCOMMIT;\nBEGIN;\nSELECT 3;\nCOMMIT;")
            .unwrap(),
        vec!["SELECT 1;\n", "SELECT 2;\n", "SELECT 3;\n"]
    );
    for invalid in [
        "BEGIN;\nBEGIN;\nSELECT 1;\nCOMMIT;\nCOMMIT;",
        "SELECT 1;\nCOMMIT;\nSELECT 2;",
        "BEGIN;\nSELECT 1;",
    ] {
        assert!(transaction_body(invalid).is_err());
    }
}
