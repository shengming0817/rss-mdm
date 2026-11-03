use super::*;
use rss_mdm_inventory_service::{assets as a, inventory_runtime as rt};
#[tokio::test]
#[ignore = "T2: field pages include every source and foreign saved-query composite identity, exclude archived mappings, and keep reads separate from retirement"]
async fn field_blockers_and_profile_lifecycle() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::InventoryFieldsWrite,
            P::ResourceRead,
            P::ResourceWrite,
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::ComplianceWrite,
        ])
        .await?;
    let writer = c.authenticate(&account).await?;
    let field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.os.name")
        .unwrap();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    tx.commit().await?;
    let owners = Owners::open(&c).await?;
    let criteria = json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":field.key,"op":"eq","value":{"kind":"string","value":"Windows"}}});
    let group = owners
        .create(&c, &writer, Some(serde_json::from_value(criteria.clone())?))
        .await?;
    let compliance = Uuid::new_v4();
    owners.compliance.execute(&rss_mdm_compliance_service::Command::Put{id:compliance,request:Box::new(rss_mdm_compliance_service::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:0,input:serde_json::from_value(json!({"presentation":{"name":"private rule"},"severity":"low","enabled":false,"platform":"all","target":{"kind":"groups","ids":[group]},"criteria":criteria}))?})},&c.request(&writer)?,&writer).await?;
    let mut blueprint = r::blueprints::catalog()
        .into_iter()
        .find(|b| b.id == "windows.agent.identity")
        .expect("Windows agent identity blueprint");
    let r::blueprints::Definition::AgentCollection { template } = &mut blueprint.definition else {
        panic!("agent collection blueprint");
    };
    let mut spec = template.spec().clone();
    spec.mappings.retain(|key, _| key == field.key.as_str());
    *template = r::AgentCollectionDefinition::new(spec)?;
    let template = blueprint.instantiate(c.tenant, r::Id::new("field-template")?)?;
    let label = template.label().as_str().to_owned();
    version(&c, template.clone()).await?;
    let (resource_owner, resources) = catalog(&c).await?;
    for name in [
        "profile-frozen",
        "profile-active",
        "profile-deprecated",
        "profile-archived",
    ] {
        let profile = r::TelemetryProfile::new(r::TelemetryProfileSpec {
            template: r::TelemetryTemplate {
                resource: "field-template".into(),
                version: label.clone(),
                variant: template.variants()[0].key().as_str().into(),
                platform: r::Platform::Windows,
                architecture: r::Architecture::X86_64,
            },
            parameters: Default::default(),
            fields: vec![r::TelemetryFieldReference {
                key: field.key.as_str().into(),
                version: 1,
            }],
            projection: r::TelemetryProjection::Current,
            sample_millis: 10000,
            upload_millis: 60000,
            budget: r::TelemetryBudget {
                points: 64,
                bytes: 65536,
                resources: 4,
                execution_millis: 100,
                output_bytes: 4096,
            },
            boost: None,
            backfill_seconds: 3600,
        })?;
        rss_mdm_telemetry_service::profile_validation::validate(
            &template,
            &profile,
            std::slice::from_ref(&field),
        )?;
        let bytes = serde_json::to_vec(&profile)?;
        let v = r::Version::new(
            c.tenant,
            r::Id::new(name)?,
            r::Id::new("1")?,
            r::Kind::TelemetryProfile,
            vec![r::Variant::new(
                r::Platform::Windows,
                r::Architecture::X86_64,
                r::Id::new("default")?,
                r::Declaration::TelemetryProfile {
                    artifact: r::Artifact::new(
                        r::Id::new("profile.json")?,
                        bytes.len() as u64,
                        r::Digest::of(&bytes),
                    )?,
                    definition: profile,
                },
            )],
        )?;
        version(&c, v).await?;
        if name == "profile-active" || name == "profile-deprecated" {
            let store = rss_mdm_resource_postgres::ResourceStore::new(
                resource_owner.runtime.clone(),
                c.tenant,
                crate::authority_t2_support::deadline(),
            )
            .await?;
            for (revision, command) in [
                (
                    2,
                    rss_mdm_resource_postgres::Command::Activate(r::Id::new("1")?),
                ),
                (
                    3,
                    rss_mdm_resource_postgres::Command::Deprecate(r::Id::new("1")?),
                ),
            ] {
                if revision == 3 && name == "profile-active" {
                    break;
                }
                store
                    .execute(
                        &rss_mdm_resource_postgres::Request {
                            id: r::Id::new(Uuid::new_v4().to_string())?,
                            resource: r::Id::new(name)?,
                            expected_storage_revision: revision,
                            as_of: rss_contract::Timepoint::try_from(support::now())?,
                            command,
                        },
                        crate::authority_t2_support::deadline(),
                    )
                    .await?;
            }
        }
        if name == "profile-archived" {
            archive(&resources, &c, &writer, name, "1", 2).await?;
        }
    }
    let refs = resources
        .references(
            &writer,
            "field-template",
            &label,
            &rss_mdm_resource_service::references::SCHEMA.parse("")?.0,
        )
        .await?;
    assert_eq!(refs.items.len(), 3);
    assert!(refs.items.iter().all(|r| r.id != "profile-archived"));
    assert!(matches!(
        archive(&resources, &c, &writer, "field-template", &label, 2).await,
        Err(rss_mdm_resource_service::Error::Referenced)
    ));
    let query = Uuid::new_v4();
    let foreign = [Uuid::new_v4(), Uuid::new_v4()];
    let instance = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    for owner in foreign {
        sqlx::query("INSERT INTO mdm_assets.saved_queries(tenant_id,instance,owner,id,revision,document) VALUES($1::uuid,$2,$3,$4,1,$5)").bind(c.tenant.to_string()).bind(instance).bind(owner).bind(query).bind(json!({"name":"private saved query","query":{"fields":[field.key],"criteria":criteria}})).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO mdm_assets.saved_queries(tenant_id,instance,owner,id,revision,document) VALUES($1::uuid,$2,$3,$4,1,NULL)").bind(c.tenant.to_string()).bind(instance).bind(foreign[0]).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    let clock = rt::Clock::new(crate::clock::monotonic());
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_projection::Control::new(&clock, clock.cutoff(), &cancel);
    let observation = rt::ObservationResource::open(
        c.inputs.database("shared", "mdm_runtime").options()?,
        clock.clone(),
    )
    .await?;
    let projection = rt::ProjectionResource::open(
        c.inputs.database("shared", "mdm_runtime").options()?,
        clock.clone(),
        &control,
    )
    .await?;
    let inventory = Arc::new(rt::InventoryRuntime::new(
        observation.store.clone(),
        projection.store.clone(),
        c.database.inventory(),
        c.audit.clone(),
        c.tenant,
        clock.clone(),
        Arc::new(rt::Readiness::default()),
    ));
    let owner = planning::owner(&c, "mdm_inventory_runtime").await?;
    let messaging = rss_reconcile_postgres::PgMessagingStore::new(
        owner.runtime.clone(),
        c.tenant,
        rss_mdm_inventory_service::transaction::deadline(),
    )
    .await?;
    let assets = Arc::new(a::AssetService::new(
        inventory,
        owner.audit.clone(),
        owner.runtime.clone(),
        c.tenant,
        Arc::new(crate::clock::SystemClock),
        &[7; 32],
        messaging,
    ));
    let reader = c.account(&[P::InventoryFieldsWrite]).await?;
    let reader = Arc::new(c.authenticate(&reader).await?);
    let http = Http::open(
        rss_mdm_management_http::assets::routes()
            .into_axum()
            .with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {
                assets: assets.clone(),
            })),
        &c,
        reader.clone(),
    )
    .await?;
    let rows = http
        .pages("/asset-fields/device.os.name/references")
        .await?;
    assert_eq!(rows.len(), 8);
    let saved: Vec<_> = rows
        .iter()
        .filter(|r| r["source"]["kind"] == "saved_query")
        .collect();
    assert_eq!(saved.len(), 2);
    assert!(foreign.iter().all(|owner| {
        saved.iter().any(|r| {
            r["source"]["owner"] == owner.to_string()
                && r["source"]["instance"] == instance.to_string()
                && r["source"]["id"] == query.to_string()
        })
    }));
    assert!(rows.iter().any(|r| r["source"]["id"] == group.to_string()));
    assert!(
        rows.iter()
            .any(|r| r["source"]["id"] == compliance.to_string())
    );
    for row in &rows {
        assert_eq!(row.as_object().unwrap().len(), 3);
        assert!(row["source"].get("name").is_none());
    }
    assert_eq!(
        http.get("/asset-fields/custom.missing/references").await?.0,
        404
    );
    let mut custom = field.clone();
    custom.key = rss_mdm_inventory::FieldKey::parse("custom.reference")?;
    custom.value_type = rss_mdm_inventory::ValueType::Object {
        properties: [("child".into(), field.value_type.clone())].into(),
    };
    custom.validate()?;
    let custom_query: a::Query = serde_json::from_value(
        json!({"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.reference.child","op":"eq","value":{"kind":"string","value":"Windows"}}},"fields":[]}),
    )?;
    let custom_catalog = rss_mdm_inventory::Catalog::new(vec![custom.clone()])?;
    let condition = custom_query.criteria.as_ref().unwrap();
    condition.validate()?;
    a::rule(c.tenant, Uuid::nil(), &condition.criteria, &custom_catalog)?;

    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &custom).await?);
    sqlx::query("INSERT INTO mdm_assets.saved_queries(tenant_id,instance,owner,id,revision,document) VALUES($1::uuid,$2,$3,$4,1,$5)").bind(c.tenant.to_string()).bind(instance).bind(foreign[0]).bind(Uuid::new_v4()).bind(json!({"name":"legal nested reference","query":custom_query})).execute(&mut *tx).await?;
    tx.commit().await?;
    let change = a::Command::FieldWrite {
        field: custom.key,
        change: rss_mdm_inventory_service::operation::Operation {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            input: a::FieldChange::Delete {},
        },
    };
    assert!(matches!(
        assets
            .execute_authorized(&change, &c.request(&reader)?, &reader, &|| Ok(()))
            .await,
        Err(rss_mdm_inventory_service::Error::Referenced)
    ));
    let error = rss_mdm_management_http::Error::from(rss_mdm_inventory_service::Error::Referenced);
    use axum::response::IntoResponse;
    let response = error.into_response();
    assert_eq!(response.status(), 409);
    let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes)?,
        json!({"code":"object_referenced"})
    );
    drop(http);
    drop(assets);
    owner.runtime.close().await;
    drop(resources);
    resource_owner.runtime.close().await;
    use rss_runtime::ManagedResource;
    observation.shutdown().await?;
    projection.shutdown().await?;
    drop(owners);
    c.close().await;
    Ok(())
}
