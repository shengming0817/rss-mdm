use super::*;
#[test]
fn health_warns_before_the_last_full_issuance_window() {
    for days in [365, 3650] {
        let required = days * 86400;
        assert_eq!(health(required + 200 * 86400, 1, required), "healthy");
        assert_eq!(health(required + 30 * 86400, 1, required), "renew_soon");
        assert_eq!(health(required + 7 * 86400, 1, required), "critical");
        assert_eq!(health(required, 1, required), "issuance_unavailable");
        assert_eq!(health(1, 1, required), "expired");
    }
}
