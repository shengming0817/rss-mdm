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
