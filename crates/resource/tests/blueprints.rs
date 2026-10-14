use rss_mdm_resource::{Id, blueprints};
#[test]
fn official_templates_are_nonempty_exact_versions_and_tenant_resources() {
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    assert_eq!(blueprints::CATEGORIES.len(), 6);
    let catalog = blueprints::catalog();
    assert_eq!(catalog.len(), 4);
    for blueprint in catalog {
        let a = blueprint
            .instantiate(tenant, Id::new("tenant-default").unwrap())
            .unwrap();
        let b = blueprint
            .instantiate(tenant, Id::new("upgrade-candidate").unwrap())
            .unwrap();
        assert_eq!(a.variants().len(), 2);
        assert_ne!(a.resource(), b.resource());
        assert!(!blueprint.definition.spec().mappings.is_empty());
        blueprint
            .definition
            .validate_platform(blueprint.platform)
            .unwrap();
        assert!(blueprints::get(&blueprint.id, "latest").is_none());
    }
}
