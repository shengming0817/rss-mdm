//! Product startup owns installation compatibility; capability owners retain security checks.
use super::*;
use crate::test_support::{Config, authority::Authority, http::Browser, runtime};
use anyhow::{Result, ensure};
use axum::http::{Method, StatusCode};

fn configuration() -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(std::env::var(
        "MDM_TEST_CONFIG",
    )?)?)?)
}

fn administrator(journal: &Journal) -> Result<crate::config::Database> {
    let url = url::Url::parse(&std::env::var("MDM_ADMIN_URL")?)?;
    Ok(crate::config::Database {
        host: url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("admin host"))?
            .into(),
        port: url.port().ok_or_else(|| anyhow::anyhow!("admin port"))?,
        name: url.path().trim_start_matches('/').into(),
        user: url.username().into(),
        password_file: journal.secret(
            "administrator-password",
            url.password()
                .ok_or_else(|| anyhow::anyhow!("admin password"))?
                .as_bytes(),
        )?,
        ca_file: std::env::var("PG_CA_FILE")?.into(),
    })
}

async fn connected(config: &Config) -> Result<()> {
    let db = crate::Database::connect(config.access_options()?, &config.audit).await?;
    db.close().await;
    Ok(())
}

async fn reject_and_restore(
    root: &mut sqlx::PgConnection,
    config: &Config,
    damage: String,
    restore: String,
) -> Result<()> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(damage.clone()))
        .execute(&mut *root)
        .await?;
    let admitted = crate::Database::connect(config.access_options()?, &config.audit).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
        .execute(root)
        .await?;
    let rejected = match admitted {
        Ok(db) => {
            db.close().await;
            false
        }
        Err(_) => true,
    };
    ensure!(rejected, "unsafe startup admitted: {damage}");
    connected(config).await
}

async fn reject_changed_authority(root: &mut sqlx::PgConnection, config: &Config) -> Result<()> {
    for (signature, from, to) in [
        (
            "mdm_devices.advance_relation_revision()",
            "relation_revision+1",
            "relation_revision",
        ),
        (
            "mdm.asset_cut_contains(jsonb,uuid,xid8)",
            "RETURN pg_visible_in_snapshot(event_xid,visibility)",
            "RETURN true",
        ),
        (
            "mdm_devices.guard_object_evidence()",
            "object evidence is immutable",
            "object evidence altered",
        ),
        (
            "mdm_apple.profile_qualifications(uuid[])",
            "THEN p.verification ELSE 'unknown'",
            "THEN 'matched'::text ELSE 'matched'::text",
        ),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
            .bind(signature)
            .fetch_one(&mut *root)
            .await?;
        let damaged = original.replace(from, to);
        ensure!(damaged != original, "fault was not injected: {signature}");
        reject_and_restore(root, config, damaged, original).await?;
    }
    Ok(())
}

async fn reject_missing_fences(root: &mut sqlx::PgConnection, config: &Config) -> Result<()> {
    for (relation, trigger) in [
        ("mdm_devices.associations", "association_revision"),
        ("mdm_devices.members", "association_member_revision"),
        ("mdm_devices.object_cuts", "immutable_object_cut"),
        ("mdm_devices.object_versions", "immutable_object_evidence"),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgname=$2")
            .bind(relation).bind(trigger).fetch_one(&mut *root).await?;
        reject_and_restore(
            root,
            config,
            format!("DROP TRIGGER {trigger} ON {relation}"),
            original,
        )
        .await?;
    }
    reject_and_restore(
        root,
        config,
        "ALTER TABLE mdm_devices.associations DISABLE TRIGGER association_revision".into(),
        "ALTER TABLE mdm_devices.associations ENABLE TRIGGER association_revision".into(),
    )
    .await
}

#[tokio::test]
#[ignore = "MODULE=installation.storage: runtime installation and safety prerequisites"]
async fn incomplete_installation_and_unsafe_authority_are_rejected() -> Result<()> {
    let config: Config = serde_json::from_value(configuration()?)?;
    let temp = tempfile::tempdir()?;
    let journal = Journal::open(&temp.path().canonicalize()?.join("proof"))?;
    let mut root = sqlx::PgConnection::connect_with(&administrator(&journal)?.options()?).await?;
    connected(&config).await?;
    for (damage, restore) in [
        (
            "UPDATE public.mdm_migrations SET complete=false WHERE name='execution-service-schema-v1'",
            "UPDATE public.mdm_migrations SET complete=true WHERE name='execution-service-schema-v1'",
        ),
        (
            "GRANT UPDATE ON public.mdm_migrations TO mdm_access",
            "REVOKE UPDATE ON public.mdm_migrations FROM mdm_access",
        ),
        (
            "ALTER TABLE mdm_access.authorization_rules DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_access.authorization_rules ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant ON mdm_policy.versions USING(true)",
            "ALTER POLICY tenant ON mdm_policy.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "ALTER FUNCTION mdm_access.operation_authority_valid(jsonb,text,bigint) SET search_path=public",
            "ALTER FUNCTION mdm_access.operation_authority_valid(jsonb,text,bigint) SET search_path=pg_catalog",
        ),
        (
            "GRANT EXECUTE ON FUNCTION mdm_commands.active_access_binding(uuid,bigint,bigint) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION mdm_commands.active_access_binding(uuid,bigint,bigint) FROM PUBLIC",
        ),
        (
            "ALTER TABLE mdm_access.collection_runs DISABLE TRIGGER immutable_collection",
            "ALTER TABLE mdm_access.collection_runs ENABLE TRIGGER immutable_collection",
        ),
        (
            "ALTER TABLE mdm_commands.operations RENAME TO missing_operations",
            "ALTER TABLE mdm_commands.missing_operations RENAME TO operations",
        ),
    ] {
        let changed = sqlx::raw_sql(damage).execute(&mut root).await?;
        if damage.starts_with("UPDATE") {
            ensure!(changed.rows_affected() == 1, "missing installation unit");
        }
        let admitted = crate::Database::connect(config.access_options()?, &config.audit).await;
        sqlx::raw_sql(restore).execute(&mut root).await?;
        let rejected = match admitted {
            Ok(db) => {
                db.close().await;
                false
            }
            Err(_) => true,
        };
        ensure!(rejected, "unsafe startup admitted: {damage}");
        connected(&config).await?;
    }
    // A valid ledger is not proof of a trustworthy authorization implementation.
    for (signature, declaration) in [
        (
            "mdm_access.operation_authority_valid(jsonb,text,bigint)",
            "mdm_access.operation_authority_valid(authority jsonb,requested text,as_of bigint)",
        ),
        (
            "mdm_devices.association_grant_current(uuid,bigint,uuid,bigint)",
            "mdm_devices.association_grant_current(p_id uuid,p_version bigint,p_registration uuid,p_generation bigint)",
        ),
        (
            "mdm_apple.platform_registration_matches(uuid,bigint,jsonb)",
            "mdm_apple.platform_registration_matches(p_source uuid,p_version bigint,p_binding jsonb)",
        ),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
            .bind(signature)
            .fetch_one(&mut root)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE OR REPLACE FUNCTION {declaration} RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT true'"))).execute(&mut root).await?;
        let admitted = crate::Database::connect(config.access_options()?, &config.audit).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(original))
            .execute(&mut root)
            .await?;
        let rejected = match admitted {
            Ok(db) => {
                db.close().await;
                false
            }
            Err(_) => true,
        };
        ensure!(rejected, "always-allow authority accepted: {signature}");
        connected(&config).await?;
    }
    reject_missing_fences(&mut root, &config).await?;
    reject_changed_authority(&mut root, &config).await?;
    root.close().await?;
    Ok(())
}

async fn open_and_write(
    base: &Value,
    path: &str,
    input: &Value,
    replay: Option<&Value>,
) -> Result<Value> {
    let (router, resources) = runtime::app(base).await?;
    resources
        .finish(async {
            let mut browser: Browser = Authority::prepared_browser("admin")?;
            let (status, receipt) = browser
                .call(&router, Method::PUT, path, Some(input.clone()))
                .await?;
            ensure!(
                status == StatusCode::OK,
                "product write after startup: {status} {receipt}"
            );
            if let Some(expected) = replay {
                ensure!(&receipt == expected, "recovery changed original receipt");
            }
            let (status, record) = browser.call(&router, Method::GET, path, None).await?;
            ensure!(
                status == StatusCode::OK && !record.is_null(),
                "restored read: {status} {record}"
            );
            Ok(receipt)
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=installation.storage: real product restart and pg_dump/pg_restore"]
async fn product_restarts_and_restores_without_structural_snapshot() -> Result<()> {
    let base = configuration()?;
    let path = format!("/api/v1/user-attribute-definitions/{}", Uuid::new_v4());
    let definition = serde_json::json!({"key":"restoreProof","displayName":"Restore proof","source":{"kind":"identity_local"},"pointer":"/extensions/restoreProof","valueType":"string","maxLength":64,"maxItems":null,"minimum":null,"maximum":null,"enabled":true,"sensitive":false,"visibility":"both","displayUse":"profile","required":false,"useExistingObservation":false});
    let input =
        serde_json::json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":definition});
    let receipt = open_and_write(&base, &path, &input, None).await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;

    let temp = tempfile::tempdir()?;
    let journal = Journal::open(&temp.path().canonicalize()?.join("proof"))?;
    let admin = administrator(&journal)?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    let tenant: Uuid =
        sqlx::query_scalar("SELECT management_tenant_id FROM public.mdm_installation")
            .fetch_one(&mut root)
            .await?;
    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut root)
        .await?;
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|field| field.key == rss_mdm_inventory::builtin::MODEL)
        .unwrap();
    field.key = rss_mdm_inventory::FieldKey::parse("custom.restore_cut")?;
    ensure!(rss_mdm_inventory_postgres::publish_field_in(&mut root, tenant, 0, &field).await?);
    let old_cut = asset_restore_cut(&mut root, tenant).await?;
    field.version = 2;
    field.searchable = !field.searchable;
    ensure!(rss_mdm_inventory_postgres::publish_field_in(&mut root, tenant, 1, &field).await?);
    let baseline_cut = asset_restore_cut(&mut root, tenant).await?;
    // Ordinary shape changes do not change the installation receipt or runtime authority.
    sqlx::raw_sql("CREATE VIEW public.restore_diagnostic AS SELECT 1 AS value; CREATE OR REPLACE VIEW public.restore_diagnostic AS SELECT * FROM (SELECT 1 AS value) equivalent; ALTER INDEX mdm.inventory_source RENAME TO restored_source_lookup; CREATE INDEX restore_diagnostic_index ON mdm_commands.operations(tenant_id); ALTER TABLE mdm.manual_assignments ADD COLUMN restore_note text; ALTER TABLE mdm_agent_packages.releases ADD COLUMN restore_note text; ALTER TABLE mdm_agent_packages.releases ADD CONSTRAINT restore_note_check CHECK(restore_note IS NULL OR length(restore_note)<=128)")
        .execute(&mut root).await?;
    leave_incomplete_ordinary_index(&mut root, &admin).await?;
    root.close().await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;

    let (task, task_input) = prepare_unfinished_asset_task(tenant).await?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut root)
        .await?;
    let unfinished:Value=sqlx::query_scalar("SELECT jsonb_build_array(from_cut,to_cut,event_after,page_through,cursor) FROM mdm_assets.group_dispatch WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(&mut root).await?;
    ensure!(
        !unfinished[1].is_null(),
        "owner did not leave a fixed input window"
    );
    connection_fence(&mut root, &journal, true).await?;
    no_writers(&mut root).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut root)
        .await?;
    root.close().await?;
    // This case proves the database seam; the complete bundle has its own backup tests.
    let backup = archive::capture(&journal, &admin).await?;
    let hash = backup.sha256;
    telemetry_fixture::recreate(&admin).await?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    let restore_operation = Uuid::new_v4();
    reserve_restore(&mut root, restore_operation, &hash).await?;
    root.close().await?;
    archive::restore_database(&journal, &admin).await?;
    let mut root = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    let epoch = advance_asset_history(&mut root, restore_operation).await?;
    ensure!(
        advance_asset_history(&mut root, restore_operation).await? == epoch,
        "restore retry switched the asset epoch twice"
    );
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut root)
        .await?;
    let assigned: Uuid =
        sqlx::query_scalar("SELECT asset_epoch FROM public.mdm_restore_operation WHERE singleton")
            .fetch_one(&mut root)
            .await?;
    ensure!(
        assigned == epoch,
        "epoch and recovery marker did not commit together"
    );
    // A freshly reserved restore cannot treat an operation copied from its backup as its own acknowledgement.
    sqlx::query("UPDATE public.mdm_restore_operation SET asset_epoch=NULL WHERE singleton")
        .execute(&mut root)
        .await?;
    let reused = advance_asset_history(&mut root, restore_operation).await;
    sqlx::query("UPDATE public.mdm_restore_operation SET asset_epoch=$1 WHERE singleton")
        .bind(epoch)
        .execute(&mut root)
        .await?;
    ensure!(
        matches!(reused, Err(Error::Conflict)),
        "historical restore identity skipped epoch rotation"
    );
    let recovered:Value=sqlx::query_scalar("SELECT jsonb_build_array(from_cut,to_cut,event_after,page_through,cursor) FROM mdm_assets.group_dispatch WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(&mut root).await?;
    ensure!(
        recovered == unfinished,
        "restore changed the fixed unfinished fanout window"
    );
    let old = rss_mdm_inventory_postgres::catalog_at_in(&mut root, tenant, &old_cut).await?;
    let baseline =
        rss_mdm_inventory_postgres::catalog_at_in(&mut root, tenant, &baseline_cut).await?;
    ensure!(
        old.definition(field.key)?.version == 1 && baseline.definition(field.key)?.version == 2
    );
    let previous: i64 = sqlx::query_scalar("SELECT max(revision) FROM mdm.asset_changes")
        .fetch_one(&mut root)
        .await?;
    field.version = 3;
    field.searchable = !field.searchable;
    ensure!(rss_mdm_inventory_postgres::publish_field_in(&mut root, tenant, 2, &field).await?);
    let new_cut = asset_restore_cut(&mut root, tenant).await?;
    let new = rss_mdm_inventory_postgres::catalog_at_in(&mut root, tenant, &new_cut).await?;
    ensure!(
        new.definition(field.key)?.version == 3
            && rss_mdm_inventory_postgres::catalog_at_in(&mut root, tenant, &old_cut)
                .await?
                .definition(field.key)?
                .version
                == 1
    );
    let (event,source_epoch):(i64,Uuid)=sqlx::query_as("SELECT revision,source_epoch FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND identity->>'field'=$2 ORDER BY revision DESC LIMIT 1").bind(tenant.to_string()).bind(field.key.as_str()).fetch_one(&mut root).await?;
    ensure!(
        event > previous && source_epoch == epoch,
        "restored allocator reused an asset event or wrote the old epoch"
    );

    connection_fence(&mut root, &journal, false).await?;
    root.close().await?;
    resume_asset_task(tenant, task, &task_input, &unfinished).await?;
    open_and_write(&base, &path, &input, Some(&receipt)).await?;
    let mut update = input;
    update["operationId"] = Uuid::new_v4().to_string().into();
    update["expectedRevision"] = 1.into();
    update["value"]["displayName"] = "After recovery".into();
    let changed = open_and_write(&base, &path, &update, None).await?;
    ensure!(
        changed["definition"]["revision"] == 2,
        "post-restore write was not committed"
    );
    Ok(())
}

// A cancelled concurrent build leaves a real invalid optimization index, not a failed identity key.
async fn leave_incomplete_ordinary_index(
    root: &mut sqlx::PgConnection,
    admin: &crate::config::Database,
) -> Result<()> {
    let mut blocker = root.begin().await?;
    sqlx::query("LOCK TABLE mdm_agent_packages.releases IN ROW EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let mut builder = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    sqlx::query("SET statement_timeout='500ms'")
        .execute(&mut builder)
        .await?;
    let result = sqlx::query(
        "CREATE INDEX CONCURRENTLY restore_package_lookup ON mdm_agent_packages.releases(platform)",
    )
    .execute(&mut builder)
    .await;
    blocker.rollback().await?;
    builder.close().await?;
    ensure!(
        result.is_err_and(|error| error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("57014")),
        "concurrent build must be cancelled while waiting for the writer"
    );
    let invalid: bool = sqlx::query_scalar("SELECT NOT indisvalid AND NOT indisunique FROM pg_index WHERE indexrelid='mdm_agent_packages.restore_package_lookup'::regclass")
        .fetch_one(root).await?;
    ensure!(invalid, "missing incomplete ordinary index");
    Ok(())
}

async fn asset_restore_cut(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
) -> Result<rss_mdm_inventory::AssetCut> {
    let mut tx = c.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    let cut = rss_mdm_inventory_postgres::capture_asset_cut_on_read(&mut tx, tenant).await?;
    tx.rollback().await?;
    Ok(cut)
}

async fn prepare_unfinished_asset_task(
    tenant: rss_request_context::TenantId,
) -> Result<(Uuid, Value)> {
    use crate::planning::test_support as plan;
    use rss_reconcile::{DurableStore, Reconciler};
    let owner = plan::planning(tenant).await;
    let device = crate::test_support::case::name("restore-fixed-input");
    plan::seed_device_in(tenant, device);
    let group = Uuid::new_v4();
    let accepted = plan::seed_group(
        &owner,
        &plan::GroupCommand::Group {
            id: group,
            change: Box::new(plan::group_operation(
                0,
                plan::GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"restore fixed input"})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(rss_mdm_inventory_service::assets::InventoryCondition {
                        selector: rss_mdm_inventory_service::assets::ScopeSelector::Device,
                        quantifier: rss_mdm_inventory_service::assets::ScopeQuantifier::One,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::IS_LOANER,
                                op: rss_mdm_inventory_service::assets::Operator::Eq,
                                value: Some(rss_mdm_inventory_service::assets::Scalar::Boolean(
                                    true,
                                )),
                                values: None,
                            },
                    }),
                },
            )),
        },
    )
    .await?;
    let task = Uuid::parse_str(accepted["task"].as_str().unwrap())?;
    let worker = plan::GroupWorker::open(&owner).await;
    let claim = plan::claim_group(&worker, task, std::time::Duration::from_secs(60)).await;
    let timer = crate::planning::automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, std::time::Duration::from_secs(20), &cancel);
    let diff = worker.observe(&claim, &control).await?;
    worker.apply(&claim, diff, &control).await?;
    worker.release(&claim, &control).await?;
    plan::input_step(worker.as_ref(), "mdm.groups").await?;
    let saved: Value = serde_json::from_str(&plan::sql(&format!(
        "SELECT jsonb_build_array(j.input,j.completed,r.input_version,r.phase,r.processed_count) FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{tenant}' AND j.id='{task}'"
    )))?;
    ensure!(
        saved[1] == false,
        "fixture finished before the logical backup"
    );
    worker.close().await;
    owner.close().await;
    Ok((task, saved))
}
async fn resume_asset_task(
    tenant: rss_request_context::TenantId,
    task: Uuid,
    saved: &Value,
    window: &Value,
) -> Result<()> {
    use crate::planning::test_support as plan;
    let owner = plan::planning(tenant).await;
    let worker = plan::GroupWorker::open(&owner).await;
    let restored: Value = serde_json::from_str(&plan::sql(&format!(
        "SELECT jsonb_build_array(j.input,j.completed,r.input_version,r.phase,r.processed_count) FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{tenant}' AND j.id='{task}'"
    )))?;
    ensure!(
        &restored == saved,
        "unfinished calculation input or committed page changed on restore"
    );
    let claim = plan::claim_group(&worker, task, std::time::Duration::from_secs(60)).await;
    plan::finish_group_claim(&worker, &claim).await;
    let finished: Value = serde_json::from_str(&plan::sql(&format!(
        "SELECT jsonb_build_array(j.input,j.completed,j.failure,r.input_version) FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{tenant}' AND j.id='{task}'"
    )))?;
    ensure!(
        finished[0] == saved[0]
            && finished[1] == true
            && finished[2].is_null()
            && finished[3] == saved[2],
        "old task silently changed its fixed input or failed to finish"
    );
    // First resume closes the old frozen event page; the new epoch remains for the next window.
    plan::input_step(worker.as_ref(), "mdm.groups").await?;
    let resumed: Value = serde_json::from_str(&plan::sql(&format!(
        "SELECT jsonb_build_array(from_cut,to_cut) FROM mdm_assets.group_dispatch WHERE tenant_id='{tenant}'"
    )))?;
    ensure!(
        resumed[0] == window[1] && resumed[1].is_null(),
        "restore replaced the active window with a fresh candidate"
    );
    while plan::input_step(worker.as_ref(), "mdm.groups").await? {}
    ensure!(
        plan::sql(&format!(
            "SELECT NOT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=d.tenant_id AND NOT mdm.asset_visible(d.from_cut,e.revision)) FROM mdm_assets.group_dispatch d WHERE tenant_id='{tenant}'"
        )) == "t"
    );
    worker.close().await;
    owner.close().await;
    Ok(())
}
