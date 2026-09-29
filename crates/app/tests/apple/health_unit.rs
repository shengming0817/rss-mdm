use super::*;
#[test]
fn certificate_health_warns_before_expiry_and_fails_closed_at_expiry() {
    for (remaining, level) in [
        (31 * 86400, CertificateLevel::Healthy),
        (30 * 86400, CertificateLevel::RenewSoon),
        (7 * 86400, CertificateLevel::Critical),
        (1, CertificateLevel::Critical),
        (0, CertificateLevel::Expired),
    ] {
        assert_eq!(
            CertificateHealth::new("fixture", 100 + remaining, 100).level,
            level
        );
    }
    assert_eq!(
        CertificateHealth::new("fixture", 100, 101).level,
        CertificateLevel::Expired
    );
    assert_eq!(
        CertificateHealth::new("fixture", 100, -1).level,
        CertificateLevel::Expired
    );
}
