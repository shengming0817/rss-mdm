use super::*;
use crate::{command_runtime_t2_support::seed_transaction, planning_t2_support as planning};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_inventory_service::assets;
use rss_mdm_resource as r;
use rss_mdm_resource_postgres::{Command, Request, ResourceStore};

pub(super) struct Fixtures {
    pub cases: Vec<(String, String, Value)>,
    pub resource: String,
}
fn case(
    cases: &mut Vec<(String, String, Value)>,
    path: &str,
    filter: String,
    id: impl serde::Serialize,
) {
    cases.push((path.into(), filter, serde_json::to_value(id).unwrap()));
}
pub(super) async fn all(c: &Context, p: &AuthorizedPrincipal) -> Result<Fixtures> {
    let mut cases = Vec::new();
    let software = super::super::software_t2::support::software(c, "z-directory-software").await?;
    let owner = planning::owner(c, "mdm_resource_runtime").await?;
    let store = ResourceStore::new(
        owner.runtime.clone(),
        c.tenant,
        crate::authority_t2_support::deadline(),
    )
    .await?;
    let kinds = [
        (r::Kind::Software, "software"),
        (r::Kind::Script, "script"),
        (r::Kind::Configuration, "configuration"),
        (r::Kind::NativeCollection, "native_collection"),
        (r::Kind::AgentCollection, "agent_collection"),
        (r::Kind::TelemetryProfile, "telemetry_profile"),
    ];
    for (kind, name) in kinds {
        let target = format!("z-directory-{name}");
        for (id, selected) in [
            (format!("a-directory-{name}"), false),
            (format!("b-directory-{name}"), false),
            (target.clone(), true),
        ] {
            let mut revision = if kind == r::Kind::Software && selected {
                2
            } else {
                resource_change(&store, &id, 0, Command::Create(kind)).await?;
                1
            };
            resource_change(&store, &id, revision, Command::Present(serde_json::from_value(json!({
                "name":if selected {"Zulu Éclair %_ O'Reilly\\工具"} else {"Earlier unrelated item"},
                "category":if selected {"Tools"} else {"Other"}, "description":"A public description", "publisher":"Acme",
                "vendor":{"unknown":true}
            }))?)).await?;
            revision += 1;
            if kind == r::Kind::Software && selected {
                resource_change(&store, &id, revision, Command::Activate(r::Id::new("1")?)).await?;
            }
        }
        case(
            &mut cases,
            "/api/v1/resources",
            format!(
                "kind=={name};presentation.name=icontains=éclair;presentation.category=in=(Tools,Office);active=={}",
                kind == r::Kind::Software
            ),
            &target,
        );
    }
    let foreign = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    crate::authority_t2_support::seed_tenant(&c.operator, foreign).await?;
    let foreign_store = ResourceStore::new(
        owner.runtime.clone(),
        foreign,
        crate::authority_t2_support::deadline(),
    )
    .await?;
    resource_change(
        &foreign_store,
        "foreign-directory-hidden",
        0,
        Command::Create(r::Kind::Script),
    )
    .await?;
    resource_change(
        &foreign_store,
        "foreign-directory-hidden",
        1,
        Command::Present(serde_json::from_value(
            json!({"name":"Zulu Éclair hidden","category":"Tools"}),
        )?),
    )
    .await?;
    owner.runtime.close().await;
    let groups = super::super::owner_boundaries_t2::Owners::open(c).await?;
    let group = groups.create(c, p, None).await?;
    let _filler1 = groups.create(c, p, None).await?;
    let _filler2 = groups.create(c, p, None).await?;
    let scope = super::super::owner_boundaries_t2::scope(c, &[group]).await?;
    let (policy, _) = super::super::software_t2::support::policy(
        c,
        &software,
        scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![super::super::software_t2::support::stage(scope)],
    )
    .await?;
    groups.storage.runtime.close().await;
    let organization = Uuid::new_v4();
    let instance = Uuid::parse_str(p.instance_id())?;
    let principal = Uuid::parse_str(p.principal_id())?;
    let tenant = Uuid::parse_str(p.tenant_id())?;
    let mut tx = seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_group.groups SET presentation=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(group)
        .bind(json!({"name":"Zulu directory group","description":"Éclair target group"}))
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE mdm_policy.policies SET state='disabled',definition=jsonb_set(definition,'{alias}','\"directory-target\"') WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(policy).execute(&mut *tx).await?;
    case(
        &mut cases,
        "/api/v1/groups",
        "presentation.description=icontains=éclair;kind==static".into(),
        group,
    );
    case(&mut cases,"/api/v1/policies","definition.alias==directory-target;definition.action.schedule.trigger.kind==manual;state==disabled".into(),policy);
    // Encrypted material is outside this metadata proof. These inert, locked rows meet storage constraints.
    sqlx::query("INSERT INTO mdm_certificate_archive.vaults(tenant_id,generation,salt,wrapped_key,kdf,updated_at) VALUES($1,1,$2,$3,'argon2id-v19-m65536-t3-p1',1)")
        .bind(tenant).bind(vec![1u8;16]).bind(vec![2u8;100]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_apple.organizations VALUES($1,$2)")
        .bind(tenant)
        .bind(organization)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_apple.ade_servers(tenant_id,organization,revision,enabled,server_uuid,org_id,key_id,certificate,private_key) VALUES($1,$2,1,false,$3,'directory-test',$4,$5,$5)")
        .bind(tenant).bind(organization).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(Vec::<u8>::new()).execute(&mut *tx).await?;
    for index in 0..3 {
        let selected = index == 2;
        let name = if selected {
            "Zulu Éclair directory"
        } else {
            "Earlier unrelated entry"
        };
        let certificate = Uuid::from_u128(1000 + index);
        let metadata = rss_mdm_certificate_archive_service::Metadata(serde_json::from_value(
            json!({"name":name,"category":"Identity","owner":"IT","notes":"directory proof","labels":["managed","mac"],"usages":["client"]}),
        )?);
        metadata.validate()?;
        sqlx::query("INSERT INTO mdm_certificate_archive.entries(tenant_id,id,revision,retired,recommended_version) VALUES($1,$2,1,false,1)").bind(tenant).bind(certificate).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_certificate_archive.versions(tenant_id,entry_id,version,actor,instance,operation_id,created_at,metadata,facts,sealed,source) VALUES($1,$2,1,$3,$4,$5,1,$6,'[]',$7,'metadata')")
            .bind(tenant).bind(certificate).bind(p.principal_id()).bind(instance).bind(Uuid::new_v4()).bind(serde_json::to_value(metadata)?).bind(Vec::<u8>::new()).execute(&mut *tx).await?;
        let webhook = Uuid::from_u128(1000 + index);
        let settings = json!({"presentation":{"name":name},"endpoint":"https://receiver.example.test/hook","eventTypes":["device.registered"],"selection":{"kind":"allDevices"},"keyReference":"test-key","networkReference":"test-network"});
        serde_json::from_value::<rss_mdm_webhook_service::model::Settings>(settings.clone())?
            .validate()?;
        sqlx::query("INSERT INTO mdm_webhook.subscriptions(tenant_id,id,revision,target_version,enabled,settings) VALUES($1,$2,1,1,true,$3)").bind(tenant).bind(webhook).bind(&settings).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_webhook.versions(tenant_id,subscription,version,settings) VALUES($1,$2,1,$3)").bind(tenant).bind(webhook).bind(&settings).execute(&mut *tx).await?;
        let profile = Uuid::from_u128(1000 + index);
        sqlx::query("INSERT INTO mdm_apple.ade_profiles(tenant_id,organization,id,revision,configuration) VALUES($1,$2,$3,1,$4)")
            .bind(tenant).bind(organization).bind(profile).bind(json!({"name":name,"mandatory":true,"removable":false,"skip":["AppleID","Siri"]})).execute(&mut *tx).await?;
        let compliance = Uuid::from_u128(1000 + index);
        let condition: assets::InventoryCondition = serde_json::from_value(
            json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.name","op":"eq","value":{"kind":"string","value":"test"}}}),
        )?;
        condition.validate()?;
        let definition: rss_mdm_compliance_service::Definition = serde_json::from_value(
            json!({"presentation":{"name":name},"severity":"low","enabled":true,"platform":"all","target":{"kind":"groups","ids":[group]},"criteria":condition}),
        )?;
        definition.validate()?;
        sqlx::query(
            "INSERT INTO mdm_compliance.rules(tenant_id,id,revision,enabled) VALUES($1,$2,1,true)",
        )
        .bind(tenant)
        .bind(compliance)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO mdm_compliance.versions(tenant_id,rule_id,revision,definition) VALUES($1,$2,1,$3)").bind(tenant).bind(compliance).bind(serde_json::to_value(definition)?).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO mdm_compliance.groups(tenant_id,rule_id,group_id) VALUES($1,$2,$3)",
        )
        .bind(tenant)
        .bind(compliance)
        .bind(group)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO mdm_compliance.fields(tenant_id,rule_id,field) VALUES($1,$2,'device.name')").bind(tenant).bind(compliance).execute(&mut *tx).await?;
        let saved = Uuid::from_u128(1000 + index);
        let query = assets::Query {
            criteria: Some(condition),
            fields: vec![rss_mdm_inventory::FieldKey::parse("device.name")?],
            sort: vec![],
        };
        let canonical = assets::rsql::QueryInput::from_query(query.clone())?;
        sqlx::query("INSERT INTO mdm_assets.saved_queries(tenant_id,instance,owner,id,revision,document,filter_text) VALUES($1,$2,$3,$4,1,$5,$6)")
            .bind(tenant).bind(instance).bind(principal).bind(saved).bind(json!({"name":name,"query":query})).bind(canonical.filter).execute(&mut *tx).await?;
        let user_group = Uuid::from_u128(1000 + index);
        sqlx::query("INSERT INTO mdm_access.user_groups(tenant_id,instance,id,revision,document) VALUES($1,$2,$3,1,$4)")
            .bind(tenant).bind(instance).bind(user_group).bind(json!({"name":name,"enabled":true,"members":[]})).execute(&mut *tx).await?;
        let key = Uuid::from_u128(1000 + index);
        let metadata: access::api_key::KeyMetadata = serde_json::from_value(
            json!({"name":name,"enabled":true,"expiresAt":null,"grants":[{"operation":"resource_read","scope":{"kind":"tenant"}}]}),
        )?;
        metadata.validate()?;
        sqlx::query("INSERT INTO mdm_access.api_keys(tenant_id,instance,id,revision,authority_revision,credential_revision,metadata,secret_digest,created_by,created_at) VALUES($1,$2,$3,1,1,1,$4,$5,$6,1)")
            .bind(tenant).bind(instance).bind(key).bind(serde_json::to_value(metadata)?).bind(vec![9u8;32]).bind(serde_json::to_value(c.user(principal))?).execute(&mut *tx).await?;
        if selected {
            case(&mut cases,"/api/v1/certificate-archive/entries","latest.metadata.name=icontains=éclair;latest.metadata.labels=containsall=(managed,mac);retired==false".into(),certificate);
            case(&mut cases,"/api/v1/webhooks/subscriptions","settings.presentation.name=icontains=éclair;settings.eventTypes=containsany=(device.registered);enabled==true".into(),webhook);
            case(&mut cases,&format!("/api/v1/apple/organizations/{organization}/ade/profiles"),"configuration.name=icontains=éclair;configuration.skip=containsall=(Siri,AppleID);remoteUuid=isnull=true".into(),profile);
            case(
                &mut cases,
                "/api/v1/compliance-rules",
                format!(
                    "definition.presentation.name=icontains=éclair;definition.target.ids=containsany=({group})"
                ),
                compliance,
            );
            case(&mut cases,"/api/v1/saved-queries","name=icontains=éclair;definition.query.filter=icontains='device.name';definition.query.fields=containsall=(device.name)".into(),saved);
            case(
                &mut cases,
                "/api/v1/authorization/user-groups",
                "value.name=icontains=éclair;value.enabled==true".into(),
                user_group,
            );
            case(
                &mut cases,
                "/api/v1/api-keys",
                format!(
                    "metadata.name=icontains=éclair;createdBy.principalId=={principal};authorityRevision==1"
                ),
                key,
            );
        }
    }
    tx.commit().await?;
    let endpoint = planning::endpoint(c).await?.members[0].device.clone();
    let mut tx = seed_transaction(c).await?;
    let evidence = rss_mdm_inventory::Evidence {
        scope: rss_mdm_inventory::CollectionScope::Device,
        source: rss_mdm_inventory::Source::Manual,
        dataset: None,
        registration: None,
        registration_generation: None,
        epoch: None,
        snapshot_id: Uuid::new_v4().to_string(),
        observed_at: 1,
        received_at: 1,
        actor: Some(p.principal_id().into()),
    };
    assert_eq!(
        rss_mdm_inventory_postgres::assign_in(
            &mut tx,
            c.tenant,
            &endpoint,
            rss_mdm_inventory::FieldKey::parse("device.name")?,
            0,
            &rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(
                "Zulu Éclair directory device".into()
            )),
            &evidence
        )
        .await?,
        Some(1)
    );
    tx.commit().await?;
    case(
        &mut cases,
        "/api/v1/device-views",
        "search=icontains=éclair".into(),
        format!("endpoint:{endpoint}"),
    );
    Ok(Fixtures {
        cases,
        resource: "z-directory-software".into(),
    })
}
async fn resource_change(
    store: &ResourceStore,
    id: &str,
    revision: u64,
    command: Command,
) -> Result<()> {
    store.execute(&Request { id:r::Id::new(Uuid::new_v4().to_string())?,resource:r::Id::new(id)?,expected_storage_revision:revision,
        as_of:rss_contract::Timepoint::try_from(super::super::software_t2::support::now())?,command },crate::authority_t2_support::deadline()).await?;
    Ok(())
}

pub(super) async fn projection_atomicity(c: &Context, p: &AuthorizedPrincipal) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid ORDER BY id LIMIT 1")
        .bind(c.tenant.to_string()).bind(p.instance_id()).bind(p.principal_id()).fetch_one(&mut *tx).await?;
    let before: Option<String> = sqlx::query_scalar(
        "SELECT filter_text FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE mdm_assets.saved_queries SET filter_text=NULL WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    assets::saved_directory::rebuild_filter_text(&mut tx, Uuid::parse_str(p.tenant_id())?).await?;
    let rebuilt: Option<String> = sqlx::query_scalar(
        "SELECT filter_text FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(before, rebuilt);
    sqlx::query("UPDATE mdm_assets.saved_queries SET document=NULL,filter_text=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).execute(&mut *tx).await?;
    tx.rollback().await?;
    let mut tx = seed_transaction(c).await?;
    let after: Option<String> = sqlx::query_scalar(
        "SELECT filter_text FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(before, after);
    tx.rollback().await?;
    Ok(())
}

pub(super) async fn execution_plans(c: &Context) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    // Bulk legal headers and projections derive from one real Resource in this isolated tenant.
    sqlx::query("WITH template AS (SELECT revision,directory,convert_from(document,'UTF8')::jsonb AS header FROM mdm_resource.aggregates WHERE tenant_id=$1::uuid AND id='a-directory-script'), rows AS (SELECT revision,'bench-directory-'||n AS id,jsonb_set(jsonb_set(directory,'{id}',to_jsonb('bench-directory-'||n)),'{presentation,description}',to_jsonb(repeat('d',4096))) AS directory,convert_to(jsonb_set(jsonb_set(header,'{2}',to_jsonb('bench-directory-'||n)),'{7,description}',to_jsonb(repeat('d',4096)))::text,'UTF8') AS document FROM template CROSS JOIN generate_series(1,10000) n) INSERT INTO mdm_resource.aggregates(tenant_id,id,revision,document,digest,directory) SELECT $1::uuid,id,revision,document,sha256(document),directory FROM rows ON CONFLICT DO NOTHING")
        .bind(c.tenant.to_string()).execute(&mut *tx).await?;
    sqlx::query("ANALYZE mdm_resource.aggregates")
        .execute(&mut *tx)
        .await?;
    for (label, predicate) in [
        (
            "name",
            "strpos(lower((directory#>>'{presentation,name}') COLLATE pg_catalog.\"pg_c_utf8\"),lower('éclair' COLLATE pg_catalog.\"pg_c_utf8\"))>0",
        ),
        (
            "category",
            "(directory#>>'{presentation,category}') COLLATE \"C\"='Tools'",
        ),
        ("status", "(directory#>>'{active}')::boolean=true"),
    ] {
        let mut sql = sqlx::QueryBuilder::new(
            "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT id,revision,document,digest,directory FROM mdm_resource.aggregates WHERE tenant_id=",
        );
        sql.push_bind(c.tenant.to_string())
            .push("::uuid AND ")
            .push(predicate)
            .push(" ORDER BY id COLLATE \"C\" LIMIT 2");
        let plan: Value = sql.build_query_scalar().fetch_one(&mut *tx).await?;
        eprintln!("Resource directory {label} EXPLAIN: {plan}");
        assert!(plan[0]["Plan"].is_object());
        assert!(!plan.to_string().contains("convert_from"));
    }
    tx.commit().await?;
    Ok(())
}

pub(super) async fn saved_projection(
    c: &Context,
    id: Uuid,
    filter: Option<&str>,
    revision: i64,
) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    let (actual_revision,document,text):(i64,Option<Value>,Option<String>)=sqlx::query_as("SELECT revision,document,filter_text FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&mut *tx).await?;
    assert_eq!(actual_revision, revision);
    assert_eq!(text.as_deref(), filter);
    if let Some(document) = document {
        let query: assets::Query = serde_json::from_value(document["query"].clone())?;
        assert_eq!(assets::rsql::QueryInput::from_query(query)?.filter, text);
    } else {
        assert!(filter.is_none());
    }
    tx.rollback().await?;
    Ok(())
}
