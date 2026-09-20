use super::*;

#[test]
fn user_group_requires_an_explicit_enabled_state() {
    assert!(
        serde_json::from_value::<UserGroup>(serde_json::json!({"name":"operators","members":[]}))
            .is_err()
    );
    for enabled in [true, false] {
        assert!(
            serde_json::from_value::<UserGroup>(
                serde_json::json!({"name":"operators","enabled":enabled,"members":[]})
            )
            .is_ok()
        );
    }
}

#[test]
fn grants_keep_each_operation_with_its_scope() {
    let read = Grant {
        operation: Permission::InventoryRead,
        scope: Scope::Device { id: "a".into() },
    };
    let wipe = Grant {
        operation: Permission::DeviceWipe,
        scope: Scope::Device { id: "b".into() },
    };
    assert!(read.covers(Permission::InventoryRead, Some("a")));
    assert!(!read.covers(Permission::DeviceWipe, Some("a")));
    assert!(!wipe.covers(Permission::DeviceWipe, Some("a")));
    assert!(!read.covers(Permission::InventoryRead, Some("b")));
    assert!(
        Grant {
            operation: Permission::AuthorizationWrite,
            scope: Scope::AllDevices
        }
        .validate()
        .is_err()
    );
    assert!(
        Grant {
            operation: Permission::DeviceWipe,
            scope: Scope::Tenant
        }
        .validate()
        .is_err()
    );
}

#[test]
fn department_ancestry_uses_only_exact_nodes_in_the_complete_assertion() {
    let tree = serde_json::from_value(
        serde_json::json!({"version":1,"sourceRevision":"r1","nodes":[
        {"id":"root","displayName":"Root","parentId":null},
        {"id":"a","displayName":"Same name","parentId":"root"},
        {"id":"b","displayName":"Same name","parentId":"a"}],"memberships":["b"]}),
    )
    .unwrap();
    assert!(department_matches(&tree, "a", DepartmentMatch::Subtree));
    assert!(!department_matches(&tree, "a", DepartmentMatch::Exact));
    assert!(department_matches(&tree, "b", DepartmentMatch::Exact));
    assert!(!department_matches(
        &tree,
        "Same name",
        DepartmentMatch::Subtree
    ));
    assert!(!department_matches(
        &tree,
        "deleted",
        DepartmentMatch::Subtree
    ));
}

#[test]
fn model_capacity_limits_and_scope_categories_are_closed() {
    let tenant = "11111111-1111-4111-8111-111111111111";
    let instance = "22222222-2222-4222-8222-222222222222";
    let user = |id| User {
        tenant_id: tenant.into(),
        instance_id: instance.into(),
        principal_id: uuid::Uuid::from_u128(id).to_string(),
    };
    let mut group = UserGroup {
        name: "boundary".into(),
        enabled: true,
        members: (1..=10000).map(user).collect(),
    };
    assert!(group.validate(tenant, instance).is_ok());
    group.members.push(user(10001));
    assert!(group.validate(tenant, instance).is_err());
    group.members.pop();
    group.members[9999] = user(1);
    assert!(group.validate(tenant, instance).is_err());
    let mut rule = Rule {
        subject: Subject::User { user: user(1) },
        grants: (0..256)
            .map(|i| Grant {
                operation: Permission::InventoryRead,
                scope: Scope::Device {
                    id: format!("device-{i}"),
                },
            })
            .collect(),
    };
    assert!(rule.validate(tenant, instance).is_ok());
    rule.grants.push(Grant {
        operation: Permission::InventoryRead,
        scope: Scope::AllDevices,
    });
    assert!(rule.validate(tenant, instance).is_err());
    for (device, names) in [
        (true, "inventory_read enrollment credentials device_wipe"),
        (
            false,
            "authorization_read authorization_write user_group_read user_group_write department_read group_read group_write group_recompute scope_read scope_write policy_read policy_write plan_preview plan_save resource_read resource_write release_read release_write release_validate release_approve release_publish release_withdraw release_recover",
        ),
    ] {
        for name in names.split_whitespace() {
            let operation: Permission = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert_eq!(
                Grant {
                    operation,
                    scope: Scope::AllDevices
                }
                .validate()
                .is_ok(),
                device
            );
            assert_eq!(
                Grant {
                    operation,
                    scope: Scope::Tenant
                }
                .validate()
                .is_ok(),
                !device
            );
        }
    }
    let mut snapshot = Snapshot {
        rules: (1..=10000)
            .map(|id| Revision {
                id: uuid::Uuid::from_u128(id),
                revision: 1,
                value: None,
            })
            .collect(),
        groups: vec![],
    };
    assert!(snapshot.validate(tenant, instance).is_ok());
    snapshot.rules.push(Revision {
        id: uuid::Uuid::from_u128(10001),
        revision: 1,
        value: None,
    });
    assert!(snapshot.validate(tenant, instance).is_err());
}
