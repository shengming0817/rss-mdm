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
fn every_component_keeps_transaction_control_with_the_installer() {
    for (name, sql) in units() {
        assert!(
            rss_mdm_install_support::transaction_body(sql).is_ok(),
            "unsupported transaction envelope in {name}"
        );
    }
}
