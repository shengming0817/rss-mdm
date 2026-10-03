use super::*;
#[test]
fn identity_is_canonical_tenant_scoped_and_not_a_csr_claim() {
    let tenant = Uuid::new_v4();
    assert_ne!(
        identity(tenant, "device").unwrap(),
        identity(Uuid::new_v4(), "device").unwrap()
    );
    assert!(
        identity(tenant, "设备:one")
            .unwrap()
            .starts_with(&format!("urn:rss-mdm:agent:v1:{tenant}:"))
    );
    assert!(identity(Uuid::nil(), "device").is_err());
    assert!(identity(tenant, "").is_err());
    assert!(identity(tenant, "device\n").is_err());
}
#[test]
fn malformed_requests_do_not_produce_verified_csr() {
    for bytes in [vec![], vec![0; MAX_CSR + 1], vec![0x30, 0]] {
        assert!(VerifiedAgentCsr::verify(&bytes).is_err());
    }
}
