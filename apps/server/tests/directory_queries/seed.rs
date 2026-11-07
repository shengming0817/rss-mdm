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
    let software = resources(c, &mut cases)
        .await
        .context("Resource directory fixture")?;
    let group = planning_rows(c, p, &software, &mut cases)
        .await
        .context("planning directory fixture")?;
    metadata_rows(c, p, group, &mut cases)
        .await
        .context("metadata directory fixture")?;
    device_row(c, p, &mut cases)
        .await
        .context("device directory fixture")?;
    Ok(Fixtures {
        cases,
        resource: "z-directory-software".into(),
    })
}
type Cases = Vec<(String, String, Value)>;
async fn resources(c: &Context, cases: &mut Cases) -> Result<r::Version> {
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
        resource_kind(&store, kind, name, cases).await?;
    }
    foreign_resource(c).await?;
    resource_rollback(c, &store, &owner.runtime).await?;
    let long_name = (0..256)
        .map(|i| {
            ring::digest::digest(&ring::digest::SHA256, format!("directory-{i}").as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<String>();
    resource_change(&store, "long-name", 0, Command::Create(r::Kind::Script)).await?;
    resource_change(
        &store,
        "long-name",
        1,
        Command::Present(serde_json::from_value(
            json!({"name":long_name,"description":"合法\n多行","category":"Unindexed"}),
        )?),
    )
    .await?;
    resource_change(
        &store,
        "scripts/install",
        0,
        Command::Create(r::Kind::Script),
    )
    .await?;
    resource_change(
        &store,
        "scripts/install",
        1,
        Command::Present(serde_json::from_value(json!({"name":"Σ.[*] O'Reilly"}))?),
    )
    .await?;
    owner.runtime.close().await;
    Ok(software)
}
async fn foreign_resource(c: &Context) -> Result<()> {
    let foreign = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    crate::authority_t2_support::seed_tenant(&c.operator, foreign).await?;
    let foreign_runtime = crate::identity::open_runtime(
        &c.inputs.database("shared", "mdm_resource_runtime"),
        &c.inputs.installation.target,
        &c.inputs.installation.lineage,
        &[(foreign, 1)],
        4,
    )
    .await?;
    let foreign_store = ResourceStore::new(
        foreign_runtime.clone(),
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
    foreign_runtime.close().await;
    Ok(())
}
async fn resource_kind(
    store: &ResourceStore,
    kind: r::Kind,
    name: &str,
    cases: &mut Cases,
) -> Result<()> {
    let target = format!("z-directory-{name}");
    for (id, selected) in [
        (format!("a-directory-{name}"), false),
        (format!("b-directory-{name}"), false),
        (target.clone(), true),
    ] {
        let mut revision = if kind == r::Kind::Software && selected {
            2
        } else {
            resource_change(store, &id, 0, Command::Create(kind)).await?;
            1
        };
        resource_change(store, &id, revision, Command::Present(serde_json::from_value(json!({
                "name":if selected {"Zulu Éclair %_ O'Reilly\\工具"} else {"Earlier unrelated item"},
                "category":if selected {"Tools"} else {"Other"}, "description":"A public description", "publisher":"Acme",
                "vendor":{"unknown":true,"metric":1e18}
            }))?)).await?;
        revision += 1;
        if kind == r::Kind::Software && selected {
            resource_change(store, &id, revision, Command::Activate(r::Id::new("1")?)).await?;
        }
    }
    case(
        cases,
        "/api/v1/resources",
        format!(
            "kind=={name};presentation.name=icontains=éclair;presentation.category=in=(Tools,Office);active=={}",
            kind == r::Kind::Software
        ),
        &target,
    );
    Ok(())
}
async fn resource_rollback(
    c: &Context,
    store: &ResourceStore,
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
) -> Result<()> {
    let before = store
        .get(
            &r::Id::new("a-directory-script")?,
            crate::authority_t2_support::deadline(),
        )
        .await?
        .context("Resource before rollback")?
        .storage_revision;
    let rollback_request = Request {
        id: r::Id::new(Uuid::new_v4().to_string())?,
        resource: r::Id::new("a-directory-script")?,
        expected_storage_revision: before,
        as_of: rss_contract::Timepoint::try_from(super::super::software_t2::support::now())?,
        command: Command::Present(serde_json::from_value(json!({"name":"rollback"}))?),
    };
    let rollback = runtime
        .local_tx_with_context(
            c.tenant,
            crate::authority_t2_support::deadline(),
            (store, &rollback_request),
            |(store, request), tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(&[store.partition(request.resource.as_str())?])
                        .await?;
                    assert!(store.execute_in(tx, request).await?.is_ok());
                    tx.with_connection(|connection| {
                        Box::pin(async move {
                            sqlx::query("SELECT 1/0").execute(connection).await?;
                            Ok(())
                        })
                    })
                    .await?;
                    Ok(())
                })
            },
        )
        .await;
    assert!(rollback.fold(|_| false, |_| true, |_| true, |_| true, |_| true, |_| true));
    assert_eq!(
        store
            .get(
                &r::Id::new("a-directory-script")?,
                crate::authority_t2_support::deadline()
            )
            .await?
            .unwrap()
            .storage_revision,
        before
    );
    Ok(())
}
async fn planning_rows(
    c: &Context,
    p: &AuthorizedPrincipal,
    software: &r::Version,
    cases: &mut Cases,
) -> Result<Uuid> {
    let groups = super::super::owner_boundaries_t2::Owners::open(c).await?;
    let group = groups.create(c, p, None).await?;
    let _filler1 = groups.create(c, p, None).await?;
    let _filler2 = groups.create(c, p, None).await?;
    let scope = super::super::owner_boundaries_t2::scope(c, &[group]).await?;
    let (policy, _) = super::super::software_t2::support::policy(
        c,
        software,
        scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![super::super::software_t2::support::stage(scope)],
    )
    .await?;
    let (other_policy, _) = super::super::software_t2::support::policy(
        c,
        software,
        scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![super::super::software_t2::support::stage(scope)],
    )
    .await?;
    groups.storage.runtime.close().await;
    let mut tx = seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_policy.policies SET state='disabled',definition=jsonb_set(jsonb_set(definition,'{alias}','\"directory-z\"'),'{customEvent}','\"directory-event\"') WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(other_policy).execute(&mut *tx).await?;
    sqlx::query("UPDATE mdm_group.groups SET presentation=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(group)
        .bind(json!({"name":"Zulu directory group","description":"Éclair target group"}))
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE mdm_policy.policies SET state='disabled',definition=jsonb_set(definition,'{alias}','\"directory-target\"') WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(policy).execute(&mut *tx).await?;
    case(
        cases,
        "/api/v1/groups",
        "presentation.description=icontains=éclair;kind==static".into(),
        group,
    );
    case(cases,"/api/v1/policies","definition.alias==directory-target;definition.action.schedule.trigger.kind==manual;state==disabled".into(),policy);
    case(cases,"/api/v1/policies","definition.alias==directory-target;definition.action.resource.variants.windows_x86_64==msi".into(),policy);
    tx.commit().await?;
    Ok(group)
}
async fn metadata_rows(
    c: &Context,
    p: &AuthorizedPrincipal,
    group: Uuid,
    cases: &mut Cases,
) -> Result<()> {
    let organization = Uuid::new_v4();
    let tenant = Uuid::parse_str(p.tenant_id())?;
    let mut tx = seed_transaction(c).await?;
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
        metadata_row(&mut tx, p, organization, group, index, cases).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn metadata_row(
    tx: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    organization: Uuid,
    group: Uuid,
    index: u128,
    cases: &mut Cases,
) -> Result<()> {
    let tenant = Uuid::parse_str(p.tenant_id())?;
    let instance = Uuid::parse_str(p.instance_id())?;
    let principal = Uuid::parse_str(p.principal_id())?;
    let selected = index == 2;
    let name = [
        "Earlier unrelated entry",
        "Zulu Éclair directory",
        "Zulu Éclair directory",
    ][index as usize];
    let certificate = Uuid::from_u128(1000 + index);
    let labels = [
        &["managed", "mac"][..],
        &["managed"][..],
        &["managed", "mac"][..],
    ][index as usize];
    let metadata = rss_mdm_certificate_archive_service::Metadata(serde_json::from_value(
        json!({"name":name,"category":"Identity","owner":"IT","notes":"directory proof","labels":labels,"usages":["client"]}),
    )?);
    metadata.validate()?;
    sqlx::query("INSERT INTO mdm_certificate_archive.entries(tenant_id,id,revision,retired,recommended_version) VALUES($1,$2,1,false,1)").bind(tenant).bind(certificate).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_certificate_archive.versions(tenant_id,entry_id,version,actor,instance,operation_id,created_at,metadata,facts,sealed,source) VALUES($1,$2,1,$3,$4,$5,1,$6,'[]',$7,'metadata')")
            .bind(tenant).bind(certificate).bind(p.principal_id()).bind(instance).bind(Uuid::new_v4()).bind(serde_json::to_value(metadata)?).bind(Vec::<u8>::new()).execute(&mut *tx).await?;
    let ordinary_name = [
        "Earlier unrelated entry",
        "Earlier unrelated entry",
        "Zulu Éclair directory",
    ][index as usize];
    let webhook = Uuid::from_u128(1000 + index);
    let settings = json!({"presentation":{"name":ordinary_name},"endpoint":"https://receiver.example.test/hook","eventTypes":["device.registered"],"selection":{"kind":"allDevices"},"keyReference":"test-key","networkReference":"test-network"});
    serde_json::from_value::<rss_mdm_webhook_service::model::Settings>(settings.clone())?
        .validate()?;
    sqlx::query("INSERT INTO mdm_webhook.subscriptions(tenant_id,id,revision,target_version,enabled,settings) VALUES($1,$2,1,1,true,$3)").bind(tenant).bind(webhook).bind(&settings).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_webhook.versions(tenant_id,subscription,version,settings) VALUES($1,$2,1,$3)").bind(tenant).bind(webhook).bind(&settings).execute(&mut *tx).await?;
    let profile = Uuid::from_u128(1000 + index);
    sqlx::query("INSERT INTO mdm_apple.ade_profiles(tenant_id,organization,id,revision,configuration) VALUES($1,$2,$3,1,$4)")
            .bind(tenant).bind(organization).bind(profile).bind(json!({"name":name,"mandatory":true,"removable":false,"skip":if index==1 {vec!["AppleID"]} else {vec!["AppleID","Siri"]}})).execute(&mut *tx).await?;
    let compliance = Uuid::from_u128(1000 + index);
    let condition: assets::InventoryCondition = serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.name","op":"eq","value":{"kind":"string","value":"test"}}}),
    )?;
    condition.validate()?;
    let definition: rss_mdm_compliance_service::Definition = serde_json::from_value(
        json!({"presentation":{"name":ordinary_name},"severity":"low","enabled":true,"platform":"all","target":{"kind":"groups","ids":[group]},"criteria":condition}),
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
    sqlx::query("INSERT INTO mdm_compliance.groups(tenant_id,rule_id,group_id) VALUES($1,$2,$3)")
        .bind(tenant)
        .bind(compliance)
        .bind(group)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO mdm_compliance.fields(tenant_id,rule_id,field) VALUES($1,$2,'device.name')",
    )
    .bind(tenant)
    .bind(compliance)
    .execute(&mut *tx)
    .await?;
    let saved = Uuid::from_u128(1000 + index);
    let query = assets::Query {
        criteria: Some(condition),
        fields: vec![rss_mdm_inventory::FieldKey::parse("device.name")?],
        sort: vec![],
    };
    let canonical = assets::rsql::QueryInput::from_query(query.clone())?;
    sqlx::query("INSERT INTO mdm_assets.saved_queries(tenant_id,instance,owner,id,revision,document,filter_text) VALUES($1,$2,$3,$4,1,$5,$6)")
            .bind(tenant).bind(instance).bind(principal).bind(saved).bind(json!({"name":ordinary_name,"query":query})).bind(canonical.filter).execute(&mut *tx).await?;
    let user_group = Uuid::from_u128(1000 + index);
    sqlx::query("INSERT INTO mdm_access.user_groups(tenant_id,instance,id,revision,document) VALUES($1,$2,$3,1,$4)")
            .bind(tenant).bind(instance).bind(user_group).bind(json!({"name":ordinary_name,"enabled":true,"members":[]})).execute(&mut *tx).await?;
    let key = Uuid::from_u128(1000 + index);
    let metadata: access::api_key::KeyMetadata = serde_json::from_value(
        json!({"name":ordinary_name,"enabled":true,"expiresAt":null,"grants":[{"operation":"resource_read","scope":{"kind":"tenant"}}]}),
    )?;
    metadata.validate()?;
    sqlx::query("INSERT INTO mdm_access.api_keys(tenant_id,instance,id,revision,authority_revision,credential_revision,metadata,secret_digest,created_by,created_at) VALUES($1,$2,$3,1,1,1,$4,$5,$6,1)")
            .bind(tenant).bind(instance).bind(key).bind(serde_json::to_value(metadata)?).bind(vec![9u8;32]).bind(serde_json::to_value(access::User {instance_id:p.instance_id().into(),tenant_id:p.tenant_id().into(),principal_id:p.principal_id().into()})?).execute(&mut *tx).await?;
    if selected {
        case(cases,"/api/v1/certificate-archive/entries","latest.metadata.name=icontains=éclair;latest.metadata.labels=containsall=(managed,mac);retired==false".into(),certificate);
        case(cases,"/api/v1/webhooks/subscriptions","settings.presentation.name=icontains=éclair;settings.eventTypes=containsany=(device.registered);enabled==true".into(),webhook);
        case(cases,&format!("/api/v1/apple/organizations/{organization}/ade/profiles"),"configuration.name=icontains=éclair;configuration.skip=containsall=(Siri,AppleID);remoteUuid=isnull=true".into(),profile);
        case(
            cases,
            "/api/v1/compliance-rules",
            format!(
                "definition.presentation.name=icontains=éclair;definition.target.ids=containsany=({group})"
            ),
            compliance,
        );
        case(cases,"/api/v1/saved-queries","name=icontains=éclair;definition.query.filter=icontains='device.name';definition.query.fields=containsall=(device.name)".into(),saved);
        case(
            cases,
            "/api/v1/authorization/user-groups",
            "value.name=icontains=éclair;value.enabled==true".into(),
            user_group,
        );
        case(
            cases,
            "/api/v1/api-keys",
            format!(
                "metadata.name=icontains=éclair;createdBy.principalId=={principal};authorityRevision==1"
            ),
            key,
        );
    }
    Ok(())
}
async fn device_row(c: &Context, _p: &AuthorizedPrincipal, cases: &mut Cases) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    for key in [
        "device.name",
        "device.serial_number",
        "device.network.apple.host_name",
    ] {
        let field = rss_mdm_inventory::builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == key)
            .context("built-in search field")?;
        assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    }
    tx.commit().await?;
    let sensitive = device_observations(
        c,
        rss_mdm_inventory::Source::MdmApple,
        &[(
            "device.network.apple.host_name",
            "Zulu Éclair directory device",
        )],
    )
    .await?;
    let ordinary = device_observations(
        c,
        rss_mdm_inventory::Source::MdmWindows,
        &[
            ("device.name", "ordinary-name-target"),
            ("device.serial_number", "serial-number-target"),
        ],
    )
    .await?;
    for (term, endpoint) in [
        ("éclair", &sensitive),
        ("ordinary-name-target", &ordinary),
        ("serial-number-target", &ordinary),
    ] {
        case(
            cases,
            "/api/v1/device-views",
            format!("search=icontains={term}"),
            format!("endpoint:{endpoint}"),
        );
    }
    Ok(())
}
async fn device_observations(
    c: &Context,
    source: rss_mdm_inventory::Source,
    observations: &[(&str, &str)],
) -> Result<String> {
    let object = planning::endpoint(c).await?;
    let member = &object.members[0];
    let registration = member.registration_id;
    let mut tx = seed_transaction(c).await?;
    if source == rss_mdm_inventory::Source::MdmApple {
        sqlx::query("UPDATE mdm_access.requests SET source='mdm.apple',windows_profile=NULL WHERE tenant_id=$1::uuid AND id=(SELECT request_id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2)").bind(c.tenant.to_string()).bind(registration).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_access.report_sources SET source='mdm.apple' WHERE tenant_id=$1::uuid AND registration=$2").bind(c.tenant.to_string()).bind(registration).execute(&mut *tx).await?;
    }
    let collection = Uuid::new_v4().to_string();
    let fields = observations
        .iter()
        .map(|(key, _)| {
            Ok(rss_mdm_inventory::CollectionField {
                definition: rss_mdm_inventory::builtin::fields()
                    .into_iter()
                    .find(|f| f.key.as_str() == *key)
                    .context("built-in field")?,
                scope: rss_mdm_inventory::CollectionScope::Device,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let definition =
        rss_mdm_inventory::CollectionDefinition::new(&collection, "1", source, fields)?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source=$3").bind(c.tenant.to_string()).bind(registration).bind(source.as_str()).fetch_one(&mut *tx).await?;
    let stream = rss_mdm_registration_service::device::scope_dataset(
        rss_mdm_install_support::StorageProfile::Mdm,
        c.tenant,
        registration,
        source.as_str(),
        epoch,
        &collection,
    )?;
    let scope = stream.encode()?;
    let batch = Uuid::new_v4().to_string();
    let projection = rss_mdm_inventory_postgres::projection_scope(c.tenant);
    for (field, value) in observations {
        let key = rss_mdm_inventory::FieldKey::parse(field)?;
        let value = definition
            .field(key)?
            .canonical_value(rss_mdm_inventory::Scalar::String((*value).into()))?;
        sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,1,2,'known',$9,$11,$10,1,'{\"kind\":\"device\"}')")
            .bind(c.tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(&scope).bind(serde_json::to_string(&definition.coverage()?)?).bind(field).bind(serde_json::to_string(&value)?).bind(&batch).bind(registration.to_string()).bind(epoch.to_string()).bind(source.as_str()).execute(&mut *tx).await?;
    }
    let fields = observations
        .iter()
        .map(|(key, _)| rss_mdm_inventory::FieldKey::parse(key))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let facts = rss_mdm_inventory_postgres::read_in(&mut tx, c.tenant, &[stream], &fields)
        .await
        .context("typed directory observations")?;
    assert_eq!(facts.scalars.len(), observations.len());
    tx.commit().await?;
    check_device_snapshot(c, &member.device).await?;
    Ok(member.device.clone())
}

async fn check_device_snapshot(c: &Context, device: &str) -> Result<()> {
    let cut = rss_mdm_inventory_postgres::capture_asset_cut(&c.operator, c.tenant).await?;
    let mut tx = seed_transaction(c).await?;
    let catalog = rss_mdm_inventory_postgres::catalog_at_in(&mut tx, c.tenant, &cut).await?;
    assets::raw_snapshot::scalar_devices_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        c.tenant,
        &cut,
        &[device.to_owned()],
        &catalog,
    )
    .await
    .context("committed device snapshot")?;
    tx.rollback().await?;
    Ok(())
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

pub(super) async fn execution_plans(c: &Context) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    // Bulk legal headers and projections derive from one real Resource in this isolated tenant.
    sqlx::query("WITH template AS (SELECT revision,directory,convert_from(document,'UTF8')::jsonb AS header FROM mdm_resource.aggregates WHERE tenant_id=$1::uuid AND id='a-directory-script'), rows AS (SELECT revision,'bench-directory-'||lpad(n::text,5,'0') AS id,jsonb_set(jsonb_set(directory,'{id}',to_jsonb('bench-directory-'||lpad(n::text,5,'0'))),'{presentation,description}',to_jsonb(repeat('d',4096))) AS directory,convert_to(jsonb_set(jsonb_set(header,'{2}',to_jsonb('bench-directory-'||lpad(n::text,5,'0'))),'{7,description}',to_jsonb(repeat('d',4096)))::text,'UTF8') AS document FROM template CROSS JOIN generate_series(1,50000) n) INSERT INTO mdm_resource.aggregates(tenant_id,id,revision,document,digest,directory) SELECT $1::uuid,id,revision,document,sha256(document),directory FROM rows ON CONFLICT DO NOTHING")
        .bind(c.tenant.to_string()).execute(&mut *tx).await?;
    sqlx::query("ANALYZE mdm_resource.aggregates")
        .execute(&mut *tx)
        .await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_resource.aggregates WHERE tenant_id=$1::uuid AND id LIKE 'bench-directory-%'").bind(c.tenant.to_string()).fetch_one(&mut *tx).await?;
    assert_eq!(count, 50000);
    for (label, filter, expected) in [
        ("name", "presentation.name=icontains=éclair", 2),
        ("category", "presentation.category==Tools", 2),
        ("status", "active==true", 1),
    ] {
        let q = rss_mdm_resource_postgres::directory::schema()
            .parse(&format!("filter={filter}&limit=1"))?;
        let mut sql = sqlx::QueryBuilder::new("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) ");
        rss_mdm_resource_postgres::directory::select(&mut sql, c.tenant, &q, None)?;
        let plan: Value = sql.build_query_scalar().fetch_one(&mut *tx).await?;
        eprintln!("Resource directory {label} EXPLAIN: {plan}");
        assert_eq!(plan[0]["Plan"]["Actual Rows"], expected);
        assert!(!plan.to_string().contains("convert_from"));
        if label == "status" {
            assert!(plan.to_string().contains("resource_directory_active"));
        }
    }

    for (label, filter) in [
        ("late-kind", "kind==script"),
        ("late-status", "active==false"),
    ] {
        let q = rss_mdm_resource_postgres::directory::schema()
            .parse(&format!("filter={filter}&limit=64"))?;
        let after = rss_mdm_query::directory::Position(vec![json!("bench-directory-45000")]);
        let mut sql = sqlx::QueryBuilder::new("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) ");
        rss_mdm_resource_postgres::directory::select(&mut sql, c.tenant, &q, Some(&after))?;
        let plan: Value = sql.build_query_scalar().fetch_one(&mut *tx).await?;
        eprintln!("Resource directory {label} EXPLAIN: {plan}");
        assert_seek_index(&plan);
    }
    tx.rollback().await?;
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

pub(super) async fn corrupt_resource(c: &Context, corrupt: bool) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_resource.aggregates SET directory=jsonb_set(directory,'{presentation,name}',to_jsonb($2::text)) WHERE tenant_id=$1::uuid AND id='b-directory-script'")
        .bind(c.tenant.to_string()).bind(if corrupt {"corrupt projection"} else {"Earlier unrelated item"}).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
pub(super) async fn corrupt_saved(c: &Context, corrupt: bool) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    sqlx::query(
        "UPDATE mdm_assets.saved_queries SET filter_text=$2 WHERE tenant_id=$1::uuid AND id=$3",
    )
    .bind(c.tenant.to_string())
    .bind(if corrupt {
        "device.name==corrupt"
    } else {
        "device.name==test"
    })
    .bind(Uuid::from_u128(1000))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct CollectionRow {
    id: i64,
    tags: Option<Vec<String>>,
}
static COLLECTION_SCHEMA: std::sync::LazyLock<rss_mdm_query::directory::Schema> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query::directory::Schema::derived::<CollectionRow>(
            "collection_proof",
            &["id"],
            100,
            100,
            &[],
        )
        .unwrap()
    });
pub(super) async fn collection_semantics(c: &Context) -> Result<()> {
    use rss_mdm_query_postgres::{Bindings, Source};
    let bindings = Bindings::new(&COLLECTION_SCHEMA, &[Source::json("", "doc")])?;
    let mut tx = seed_transaction(c).await?;
    let rows = json!([{"id":1},{"id":2,"tags":null},{"id":3,"tags":[]},{"id":4,"tags":["a"]},{"id":5,"tags":["a","b"]}]);
    for (filter, expected) in [
        ("tags==a", vec![4, 5]),
        ("tags!=a", vec![3]),
        ("tags=in=(a,b)", vec![4, 5]),
        ("tags=out=(b,c)", vec![3, 4]),
        ("tags=containsall=(a,b)", vec![5]),
        ("tags=containsany=(b,c)", vec![5]),
        ("tags=isnull=true", vec![1, 2]),
        ("tags=isnotnull=true", vec![3, 4, 5]),
    ] {
        let q = COLLECTION_SCHEMA.parse(&format!("filter={filter}"))?;
        let mut sql =
            sqlx::QueryBuilder::new("SELECT (doc->>'id')::bigint FROM jsonb_array_elements(");
        sql.push_bind(rows.clone())
            .push("::jsonb) AS candidates(doc) WHERE TRUE");
        rss_mdm_query_postgres::append(&mut sql, &q, None, &bindings)?;
        let actual: Vec<i64> = sql.build_query_scalar().fetch_all(&mut *tx).await?;
        assert_eq!(actual, expected, "{filter}");
    }
    let tags = (0..251).map(|i| format!("field{i}")).collect::<Vec<_>>();
    let mut terms = tags[..63].to_vec();
    terms.push("zz_missing".into());
    let q = COLLECTION_SCHEMA.parse(&format!("filter=tags=containsall=({})", terms.join(",")))?;
    let mut sql = sqlx::QueryBuilder::new(
        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) WITH candidates AS MATERIALIZED (SELECT jsonb_build_object('id',n,'tags',",
    );
    sql.push_bind(json!(tags)).push(
        "::jsonb) AS doc FROM generate_series(1,1000) n) SELECT doc FROM candidates WHERE TRUE",
    );
    rss_mdm_query_postgres::append(&mut sql, &q, None, &bindings)?;
    let plan: Value = sql.build_query_scalar().fetch_one(&mut *tx).await?;
    eprintln!("Collection directory 64 terms EXPLAIN: {plan}");
    assert_eq!(plan[0]["Plan"]["Actual Rows"], 0);
    let mut nodes = vec![&plan[0]["Plan"]];
    let mut expansions = 0;
    while let Some(node) = nodes.pop() {
        if node["Function Name"] == "jsonb_array_elements_text" {
            expansions += node["Actual Loops"]
                .as_u64()
                .context("array expansion loops")?;
        }
        nodes.extend(node["Plans"].as_array().into_iter().flatten());
    }
    assert_eq!(
        expansions, 1000,
        "each candidate must expand its collection only once: {plan}"
    );
    tx.rollback().await?;
    Ok(())
}

fn assert_seek_index(plan: &Value) {
    assert_eq!(plan[0]["Plan"]["Actual Rows"], 65);
    let mut nodes = vec![&plan[0]["Plan"]];
    let mut indexed = false;
    while let Some(node) = nodes.pop() {
        indexed |= node["Index Cond"]
            .as_str()
            .is_some_and(|cond| cond.contains("id") && cond.contains("bench-directory-45000"));
        assert!(
            node["Rows Removed by Filter"].as_u64().unwrap_or(0) < 128,
            "late page scans discarded prefix: {plan}"
        );
        nodes.extend(node["Plans"].as_array().into_iter().flatten());
    }
    assert!(indexed, "late cursor is not an index range: {plan}");
}

pub(super) async fn literal_name(c: &Context, name: &str, revision: u64) -> Result<()> {
    let owner = planning::owner(c, "mdm_resource_runtime").await?;
    let store = ResourceStore::new(
        owner.runtime.clone(),
        c.tenant,
        crate::authority_t2_support::deadline(),
    )
    .await?;
    let result = resource_change(
        &store,
        "scripts/install",
        revision,
        Command::Present(serde_json::from_value(json!({"name":name}))?),
    )
    .await;
    owner.runtime.close().await;
    result
}
