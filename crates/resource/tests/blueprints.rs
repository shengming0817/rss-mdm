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

#[test]
fn mdm_templates_cannot_claim_unverified_architecture_constraints() {
    use rss_mdm_resource::{Architecture, Kind, Variant, Version};
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let blueprint = blueprints::get("windows.hardware", "1").unwrap();
    let version = blueprint
        .instantiate(tenant, Id::new("native").unwrap())
        .unwrap();
    let variants = version.variants().to_vec();
    assert!(
        Version::new(
            tenant,
            Id::new("native").unwrap(),
            Id::new("single").unwrap(),
            Kind::NativeCollection,
            vec![variants[0].clone()]
        )
        .is_err()
    );
    let mut distinct = variants.clone();
    let other = blueprints::get("windows.identity", "1")
        .unwrap()
        .instantiate(tenant, Id::new("other").unwrap())
        .unwrap();
    distinct[1] = Variant::new(
        blueprint.platform,
        Architecture::Aarch64,
        Id::new("different").unwrap(),
        other.variants()[0].declaration().clone(),
    );
    assert!(
        Version::new(
            tenant,
            Id::new("native").unwrap(),
            Id::new("different").unwrap(),
            Kind::NativeCollection,
            distinct
        )
        .is_err()
    );
}
