use rss_mdm_resource::{Id, blueprints};
#[test]
fn official_templates_are_nonempty_exact_versions_and_tenant_resources() {
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let catalog = blueprints::catalog();
    assert!(
        blueprints::CATEGORIES
            .iter()
            .all(|category| catalog.iter().any(|b| b
                .presentation
                .get("category")
                .and_then(serde_json::Value::as_str)
                == Some(*category)))
    );
    for (index, blueprint) in catalog.into_iter().enumerate() {
        let a = blueprint
            .instantiate(tenant, Id::new("tenant-default").unwrap())
            .unwrap();
        assert_eq!(a.variants().len(), 2);
        if index == 0 {
            let b = blueprint
                .instantiate(tenant, Id::new("upgrade-candidate").unwrap())
                .unwrap();
            assert_ne!(a.resource(), b.resource());
        }
        match &blueprint.definition {
            blueprints::Definition::AgentCollection { template } => {
                assert!(!template.spec().mappings.is_empty());
                template.validate_platform(blueprint.platform).unwrap();
            }
            blueprints::Definition::NativeCollection { template } => {
                assert!(!template.spec().mappings.is_empty());
                template.validate_platform(blueprint.platform).unwrap();
            }
            blueprints::Definition::Configuration { content } => {
                assert_eq!(
                    serde_json::to_value(content).unwrap()["apply"]["request"]["kind"],
                    "declarations"
                );
                assert_eq!(blueprint.definition.reference(), "configuration.json");
            }
        }
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

#[test]
fn origin_survives_snapshot_restore_without_catalog_lookup() {
    use rss_mdm_resource::{BlueprintOrigin, Kind, Resource};
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let mut resource = Resource::new(tenant, Id::new("origin").unwrap(), Kind::NativeCollection);
    let origin = BlueprintOrigin {
        blueprint: "removed.from.catalog".into(),
        version: "2".into(),
        digest: [9; 32],
    };
    resource.set_origin(origin.clone()).unwrap();
    assert!(resource.set_origin(origin.clone()).is_err());
    let restored = Resource::restore(resource.snapshot()).unwrap();
    assert_eq!(restored.snapshot().origin, Some(origin));
}
