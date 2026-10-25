use rss_mdm_inventory::*;
#[test]
fn all_seed_definitions_use_the_same_catalog_and_frozen_collection_contract() {
    let catalog = Catalog::new(builtin::fields()).unwrap();
    for field in catalog.fields() {
        assert_eq!(FieldKey::parse(field.key.as_str()).unwrap(), field.key);
        assert!(field.validate().is_ok());
        for source in field.sources.keys().filter(|s| **s != Source::Manual) {
            CollectionDefinition::new("published-template", 1, *source, {
                let scope = rss_mdm_inventory::CollectionScope::Device;
                let fields: Vec<rss_mdm_inventory::FieldDefinition> = vec![field.clone()];
                fields
                    .into_iter()
                    .map(|definition| rss_mdm_inventory::CollectionField {
                        definition,
                        scope: scope.clone(),
                    })
                    .collect()
            })
            .unwrap();
        }
    }
    let health = catalog
        .definition(builtin::CORPORATE_AGENT_HEALTHY)
        .unwrap();
    assert!(health.validate_scalar(&Scalar::Boolean(false)).is_ok());
    assert!(
        health
            .validate_scalar(&Scalar::String("false".into()))
            .is_err()
    );
    assert!(
        CollectionDefinition::new("collector", 1, Source::AgentBuiltin, {
            let scope = rss_mdm_inventory::CollectionScope::Device;
            let fields: Vec<rss_mdm_inventory::FieldDefinition> = vec![health.clone()];
            fields
                .into_iter()
                .map(|definition| rss_mdm_inventory::CollectionField {
                    definition,
                    scope: scope.clone(),
                })
                .collect()
        })
        .is_err()
    );
}
