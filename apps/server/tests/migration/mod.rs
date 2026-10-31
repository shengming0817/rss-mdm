use super::*;
#[test]
fn installation_validates_stable_coordinates() {
    let mut installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: "33333333-3333-4333-8333-333333333333".into(),
        target: [1; 16],
        lineage: [2; 16],
    };
    assert!(installation.validate().is_ok());
    installation.target = [0; 16];
    assert!(installation.validate().is_err());
}

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
fn every_component_keeps_transaction_control_with_the_installer() {
    for (name, sql) in units() {
        assert!(
            transaction_body(sql).is_ok(),
            "unsupported transaction envelope in {name}"
        );
    }
    assert_eq!(
        transaction_body("-- header\nBEGIN;\nSELECT 1;\nCOMMIT;\n-- end").unwrap(),
        vec!["SELECT 1;\n"]
    );
    assert_eq!(
        transaction_body("SELECT 1;\nBEGIN;\nSELECT 2;\nCOMMIT;\nBEGIN;\nSELECT 3;\nCOMMIT;")
            .unwrap(),
        vec!["SELECT 1;\n", "SELECT 2;\n", "SELECT 3;\n"]
    );
    assert!(transaction_body("BEGIN;\nBEGIN;\nSELECT 1;\nCOMMIT;\nCOMMIT;").is_err());
    assert!(transaction_body("SELECT 1;\nCOMMIT;\nSELECT 2;").is_err());
    assert!(transaction_body("BEGIN;\nSELECT 1;").is_err());
}
