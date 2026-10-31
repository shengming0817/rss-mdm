use super::*;
#[test]
fn imported_provider_compares_semantics_and_rejects_privilege_expansion() {
    let public = json!({"kty":"RSA","kid":"original","n":"AQ","e":"AQAB"});
    let expected = jwk_provisioner(Purpose::Agent, public.clone()).unwrap();
    let mut actual = jwk_provisioner(Purpose::Agent, public.clone()).unwrap();
    actual.id = "server-assigned".into();
    actual.details.jwk.as_mut().unwrap().public_key =
        STANDARD.encode(serde_json::to_string_pretty(&public).unwrap());
    assert!(actual.matches(&expected).is_ok());
    actual.deleted_at = Some("0001-01-01T00:00:00Z".into());
    assert!(actual.matches(&expected).is_ok());
    for deleted_at in ["2026-10-19T00:00:00Z", "invalid", ""] {
        actual.deleted_at = Some(deleted_at.into());
        assert!(actual.matches(&expected).is_err());
    }
    actual.deleted_at = None;
    actual.claims.ssh.enabled = true;
    assert!(actual.matches(&expected).is_err());
    actual.claims.ssh.enabled = false;
    actual.details.jwk.as_mut().unwrap().encrypted_private_key =
        Some("unexpected-online-private-key".to_owned().into());
    assert!(actual.matches(&expected).is_err());
}
