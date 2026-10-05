use super::*;

fn input(tenant: Uuid) -> Register {
    Register {
        database: config::Database {
            host: "localhost".into(),
            port: 5432,
            name: "fixture".into(),
            user: "mdm_owner".into(),
            password_file: "fixture-password".into(),
            ca_file: "fixture-ca".into(),
        },
        installation: Installation {
            instance_id: crate::test_support::identity::INSTANCE.into(),
            target: [1; 16],
            lineage: [2; 16],
            audit_mode: migration::AuditMode::Plain,
        },
        tenant_id: tenant.to_string(),
        initial_epoch: 1,
        operation_id: Uuid::new_v4(),
    }
}
#[test]
fn registration_requires_canonical_tenant_positive_epoch_and_operation() {
    let mut request = input(Uuid::from_u128(0xab));
    assert!(validate(&request).is_ok());
    request.tenant_id = request.tenant_id.to_uppercase();
    assert_eq!(validate(&request), Err(Reason::Invalid));
    request.tenant_id = Uuid::nil().to_string();
    assert_eq!(validate(&request), Err(Reason::Invalid));
    request.tenant_id = Uuid::new_v4().to_string();
    request.initial_epoch = 0;
    assert_eq!(validate(&request), Err(Reason::Invalid));
    request.initial_epoch = 1;
    request.operation_id = Uuid::nil();
    assert_eq!(validate(&request), Err(Reason::Invalid));
}
