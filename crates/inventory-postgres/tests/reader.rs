#[path = "../../../tests/support/context.rs"]
mod case;
use rss_mdm_inventory_postgres::InventoryReader;
use sqlx::{
    Connection, Executor, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
fn options(user: &str) -> anyhow::Result<PgConnectOptions> {
    Ok(std::env::var("DATABASE_URL")?
        .parse::<PgConnectOptions>()?
        .username(user)
        .password(if user == "mdm_api" {
            "api-fixture"
        } else {
            "runtime-fixture"
        })
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?))
}
fn scope(tenant: &str, source: &str) -> rss_observation::Scope {
    serde_json::from_value(serde_json::json!({"tenant":tenant,"object":"reader-device","registration":"reg","source":source,"dataset":"inventory","epoch":"one"})).unwrap()
}
#[tokio::test]
#[ignore = "make t2: real TLS PostgreSQL"]
async fn reader_is_exact_tenant_scoped_and_read_only() -> anyhow::Result<()> {
    let mut writer = PgConnection::connect_with(&options("mdm_runtime")?).await?;
    let mut catalog_writer = PgConnection::connect_with(&options("mdm_inventory_runtime")?).await?;
    let a = case::tenant();
    let b = case::peer();
    for (tenant, source, value) in [
        (a, "mdm.windows", "A"),
        (b, "mdm.windows", "B"),
        (a, "agent.builtin", "C"),
    ] {
        let definition = rss_mdm_inventory::CollectionDefinition::new(
            "inventory",
            1,
            rss_mdm_inventory::Source::parse(source)?,
            {
                let scope = rss_mdm_inventory::CollectionScope::Device;
                let fields: Vec<rss_mdm_inventory::FieldDefinition> =
                    rss_mdm_inventory::builtin::fields()
                        .into_iter()
                        .filter(|f| f.key == rss_mdm_inventory::builtin::MODEL)
                        .collect();
                fields
                    .into_iter()
                    .map(|definition| rss_mdm_inventory::CollectionField {
                        definition,
                        scope: scope.clone(),
                    })
                    .collect()
            },
        )?;
        let mut catalog_tx = catalog_writer.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *catalog_tx)
            .await?;
        sqlx::query("INSERT INTO mdm.collection_definitions(tenant_id,dataset,version,source,fingerprint,coverage,definition) VALUES($1::uuid,'inventory','1',$2,$3,$4,$5::jsonb) ON CONFLICT DO NOTHING")
            .bind(tenant).bind(source).bind(definition.fingerprint()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(serde_json::to_string(&definition)?).execute(&mut *catalog_tx).await?;
        catalog_tx.commit().await?;
        let mut tx = writer.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let projection =
            rss_mdm_inventory_postgres::projection_scope(scope(tenant, source).tenant());
        sqlx::query("INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),$1::uuid,$5,$6,$2,$4,'device.model',$3,'read-test',1,2,'known','reg',$7,'one',0) ON CONFLICT DO NOTHING")
            .bind(tenant).bind(scope(tenant,source).encode()?).bind(serde_json::to_string(&rss_mdm_inventory::Scalar::String(value.into()))?).bind(serde_json::to_string(&definition.coverage()?)?).bind(projection.source().source()).bind(projection.generation()).bind(source).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    assert!(
        InventoryReader::connect(options("mdm_runtime")?)
            .await
            .is_err()
    );
    let reader = InventoryReader::connect(options("mdm_api")?).await?;
    for (tenant, source, value) in [
        (a, "mdm.windows", "A"),
        (b, "mdm.windows", "B"),
        (a, "agent.builtin", "C"),
    ] {
        let selected = scope(tenant, source);
        let rows = reader
            .read(
                selected.tenant(),
                std::slice::from_ref(&selected),
                &[rss_mdm_inventory::builtin::MODEL],
            )
            .await?;
        assert_eq!(rows.scalars.len(), 1);
        assert_eq!(rows.scalars[0].scope, selected.encode()?);
        assert_eq!(rows.scalars[0].field, rss_mdm_inventory::builtin::MODEL);
        assert_eq!(
            rows.scalars[0].fact.state,
            rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(value.into()))
        );
    }
    assert!(
        reader
            .read(
                scope(a, "absent").tenant(),
                &[scope(a, "absent")],
                &[rss_mdm_inventory::builtin::MODEL]
            )
            .await
            .is_err()
    );
    let mut api = PgConnection::connect_with(&options("mdm_api")?).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mdm.inventory")
            .fetch_one(&mut api)
            .await?,
        0
    );
    for statement in [
        "DELETE FROM mdm.inventory",
        "SELECT * FROM rss_observation.batches",
    ] {
        let error = api.execute(statement).await.unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        );
    }
    let owner: PgConnectOptions = std::env::var("MDM_OWNER_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = PgConnection::connect_with(&owner).await?;
    for (grant, revoke, field) in [
        (
            "GRANT INSERT ON public.mdm_migrations TO mdm_api",
            "REVOKE INSERT ON public.mdm_migrations FROM mdm_api",
            "dml",
        ),
        (
            "GRANT SELECT ON public.mdm_migrations TO mdm_api",
            "REVOKE SELECT ON public.mdm_migrations FROM mdm_api",
            "dml",
        ),
        (
            "REVOKE USAGE ON SCHEMA mdm FROM mdm_api",
            "GRANT USAGE ON SCHEMA mdm TO mdm_api",
            "42501",
        ),
        (
            "GRANT INSERT ON mdm.inventory TO mdm_api",
            "REVOKE INSERT ON mdm.inventory FROM mdm_api",
            "dml",
        ),
        (
            "GRANT SELECT(scope) ON rss_observation.batches TO mdm_api",
            "REVOKE SELECT(scope) ON rss_observation.batches FROM mdm_api",
            "dml",
        ),
        (
            "ALTER TABLE mdm.inventory ALTER COLUMN epoch DROP NOT NULL",
            "ALTER TABLE mdm.inventory ALTER COLUMN epoch SET NOT NULL",
            "assets",
        ),
        (
            "ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_state; ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_state CHECK(true)",
            "ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_state; ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_state CHECK((state='known')=(value IS NOT NULL OR value_version IS NOT NULL))",
            "assets",
        ),
        (
            "ALTER TABLE mdm.inventory NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm.inventory FORCE ROW LEVEL SECURITY",
            "rls",
        ),
    ] {
        owner.execute(grant).await?;
        let rejected = InventoryReader::connect(options("mdm_api")?)
            .await
            .err()
            .expect("damaged admission must reject");
        owner.execute(revoke).await?;
        if field == "42501" {
            assert_eq!(
                rejected
                    .downcast_ref::<sqlx::Error>()
                    .and_then(|e| e.as_database_error())
                    .and_then(|e| e.code())
                    .as_deref(),
                Some("42501"),
                "{grant}: {rejected:#}"
            );
        } else {
            assert_eq!(
                rejected.to_string(),
                format!("Inventory admission rejected: {field}"),
                "{grant}"
            );
        }
        InventoryReader::connect(options("mdm_api")?)
            .await?
            .close()
            .await;
    }
    for (create, drop) in [
        (
            "CREATE SEQUENCE mdm.reader_test_sequence; GRANT USAGE ON SEQUENCE mdm.reader_test_sequence TO mdm_api",
            "DROP SEQUENCE mdm.reader_test_sequence",
        ),
        (
            "CREATE FUNCTION mdm.reader_test_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "DROP FUNCTION mdm.reader_test_function()",
        ),
    ] {
        sqlx::raw_sql(create).execute(&mut owner).await?;
        let rejected = InventoryReader::connect(options("mdm_api")?)
            .await
            .err()
            .expect("damaged admission must reject");
        owner.execute(drop).await?;
        assert!(
            rejected.to_string() == "Inventory admission rejected: dml",
            "unexpected rejection: {rejected:#}"
        );
        InventoryReader::connect(options("mdm_api")?)
            .await?
            .close()
            .await;
    }
    let administrator: PgConnectOptions = std::env::var("MDM_ADMIN_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let database = administrator
        .get_database()
        .ok_or_else(|| anyhow::anyhow!("fixture database absent"))?
        .replace('"', "\"\"");
    let grant_database = format!("GRANT CREATE ON DATABASE \"{database}\" TO mdm_api");
    let revoke_database = format!("REVOKE CREATE ON DATABASE \"{database}\" FROM mdm_api");
    let mut administrator = PgConnection::connect_with(&administrator).await?;
    for (grant, revoke) in [
        (grant_database.as_str(), revoke_database.as_str()),
        (
            "GRANT CREATE ON SCHEMA public TO mdm_api",
            "REVOKE CREATE ON SCHEMA public FROM mdm_api",
        ),
    ] {
        InventoryReader::connect(options("mdm_api")?)
            .await?
            .close()
            .await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grant))
            .execute(&mut administrator)
            .await?;
        let rejected = InventoryReader::connect(options("mdm_api")?)
            .await
            .err()
            .expect("damaged admission must reject");
        sqlx::raw_sql(sqlx::AssertSqlSafe(revoke))
            .execute(&mut administrator)
            .await?;
        assert_eq!(rejected.to_string(), "Inventory admission rejected: dml");
        InventoryReader::connect(options("mdm_api")?)
            .await?
            .close()
            .await;
    }
    administrator
        .execute("CREATE ROLE reader_inheritor LOGIN")
        .await?;
    administrator
        .execute("GRANT mdm_api TO reader_inheritor")
        .await?;
    let rejected = InventoryReader::connect(options("mdm_api")?)
        .await
        .err()
        .expect("damaged admission must reject");
    administrator
        .execute("REVOKE mdm_api FROM reader_inheritor")
        .await?;
    administrator.execute("DROP ROLE reader_inheritor").await?;
    assert_eq!(rejected.to_string(), "Inventory admission rejected: dml");
    normal_reader().await?;
    administrator.close().await?;
    owner.close().await?;
    api.close().await?;
    reader.close().await;
    writer.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=inventory.reader: asset visibility privileges fail closed"]
async fn asset_visibility_rejects_public_or_restore_authority() -> anyhow::Result<()> {
    let mut connection = PgConnection::connect_with(&options("mdm_inventory_runtime")?).await?;
    let admin = std::env::var("MDM_ADMIN_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut root = PgConnection::connect_with(&admin).await?;
    rss_mdm_inventory_postgres::verify_asset_history(&mut connection).await?;
    for (grant, revoke) in [
        (
            "GRANT EXECUTE ON FUNCTION mdm.asset_visible(jsonb,bigint) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION mdm.asset_visible(jsonb,bigint) FROM PUBLIC",
        ),
        (
            "GRANT EXECUTE ON FUNCTION mdm.advance_asset_epoch(uuid) TO mdm_inventory_runtime",
            "REVOKE EXECUTE ON FUNCTION mdm.advance_asset_epoch(uuid) FROM mdm_inventory_runtime",
        ),
    ] {
        root.execute(grant).await?;
        let result = rss_mdm_inventory_postgres::verify_asset_history(&mut connection).await;
        root.execute(revoke).await?;
        assert!(result.is_err());
    }
    rss_mdm_inventory_postgres::verify_asset_history(&mut connection).await?;
    for (damage, repair) in [
        (
            "ALTER SEQUENCE mdm.asset_event_ids CACHE 32",
            "ALTER SEQUENCE mdm.asset_event_ids CACHE 1",
        ),
        (
            "ALTER SEQUENCE mdm.asset_event_ids INCREMENT BY 2",
            "ALTER SEQUENCE mdm.asset_event_ids INCREMENT BY 1",
        ),
        (
            "ALTER SEQUENCE mdm.asset_event_ids CYCLE",
            "ALTER SEQUENCE mdm.asset_event_ids NO CYCLE",
        ),
    ] {
        root.execute(damage).await?;
        let rejected = rss_mdm_inventory_postgres::verify_asset_history(&mut connection).await;
        let restore = sqlx::query_scalar::<_, uuid::Uuid>("SELECT mdm.advance_asset_epoch($1)")
            .bind(uuid::Uuid::new_v4())
            .fetch_one(&mut root)
            .await;
        root.execute(repair).await?;
        assert!(rejected.is_err() && restore.is_err());
    }
    for (damage, repair) in [
        (
            "ALTER FUNCTION mdm.capture_asset_cut(uuid) SECURITY INVOKER",
            "ALTER FUNCTION mdm.capture_asset_cut(uuid) SECURITY DEFINER",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION mdm.capture_asset_cut(uuid) FROM mdm_api",
            "GRANT EXECUTE ON FUNCTION mdm.capture_asset_cut(uuid) TO mdm_api",
        ),
    ] {
        root.execute(damage).await?;
        let result = InventoryReader::connect(options("mdm_api")?).await;
        root.execute(repair).await?;
        match result {
            Ok(reader) => {
                reader.close().await;
                panic!("unsafe capture reader admitted")
            }
            Err(_) => {}
        }
    }
    InventoryReader::connect(options("mdm_api")?)
        .await?
        .close()
        .await;
    root.close().await?;
    connection.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=inventory.reader: concurrent facts and reverse commit visibility"]
async fn committed_cut_excludes_late_low_identity_and_keeps_it_for_the_next_window()
-> anyhow::Result<()> {
    let tenant = scope(case::tenant(), "mdm.windows").tenant();
    let mut first = PgConnection::connect_with(&options("mdm_runtime")?).await?;
    let mut second = PgConnection::connect_with(&options("mdm_runtime")?).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options("mdm_inventory_runtime")?)
        .await?;
    let mut a = first.begin().await?;
    let mut b = second.begin().await?;
    for c in [&mut *a, &mut *b] {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(c)
            .await?;
    }
    let low:i64=sqlx::query_scalar("SELECT mdm.record_asset_change($1::uuid,'manual',jsonb_build_object('device','first'),ARRAY['device.model'])").bind(tenant.to_string()).fetch_one(&mut *a).await?;
    let high:i64=tokio::time::timeout(std::time::Duration::from_secs(3),sqlx::query_scalar("SELECT mdm.record_asset_change($1::uuid,'manual',jsonb_build_object('device','second'),ARRAY['device.model'])").bind(tenant.to_string()).fetch_one(&mut *b)).await??;
    assert!(high > low);
    b.commit().await?; // A remains uncommitted; B must not wait for its tenant.
    let old = rss_mdm_inventory_postgres::capture_asset_cut(&pool, tenant).await?;
    a.commit().await?;
    let new = rss_mdm_inventory_postgres::capture_asset_cut(&pool, tenant).await?;
    let mut c = pool.acquire().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await?;
    let observed:(bool,bool,bool,bool)=sqlx::query_as("SELECT mdm.asset_visible($1,$3),mdm.asset_visible($1,$4),mdm.asset_visible($2,$3),mdm.asset_visible($2,$4)")
        .bind(old.to_json()).bind(new.to_json()).bind(low).bind(high).fetch_one(&mut *c).await?;
    assert_eq!(observed, (false, true, true, true));
    let delta:Vec<i64>=sqlx::query_scalar("SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND mdm.asset_visible($3,revision) AND NOT mdm.asset_visible($2,revision) AND revision=ANY($4) ORDER BY revision")
        .bind(tenant.to_string()).bind(old.to_json()).bind(new.to_json()).bind(vec![low,high]).fetch_all(&mut *c).await?;
    assert_eq!(delta, vec![low]);
    let mut foreign = old.to_json();
    foreign["tenant"] = case::peer().into();
    let denied = sqlx::query_scalar::<_, bool>("SELECT mdm.asset_visible($1,$2)")
        .bind(foreign)
        .bind(low)
        .fetch_one(&mut *c)
        .await
        .unwrap_err();
    assert_eq!(
        denied.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    let write_capture =
        sqlx::query_scalar::<_, serde_json::Value>("SELECT mdm.capture_asset_cut($1::uuid)")
            .bind(tenant.to_string())
            .fetch_one(&mut *c)
            .await
            .unwrap_err();
    assert_eq!(
        write_capture
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("25006")
    );
    drop(c);
    pool.close().await;
    first.close().await?;
    second.close().await?;
    Ok(())
}

async fn normal_reader() -> anyhow::Result<()> {
    let reader = InventoryReader::connect(options("mdm_api")?).await?;
    let selected = scope(case::tenant(), "mdm.windows");
    let rows = reader
        .read(
            selected.tenant(),
            std::slice::from_ref(&selected),
            &[rss_mdm_inventory::builtin::MODEL],
        )
        .await;
    reader.close().await;
    let rows = rows?;
    assert_eq!(rows.scalars.len(), 1);
    assert_eq!(rows.scalars[0].scope, selected.encode()?);
    assert_eq!(
        rows.scalars[0].fact.state,
        rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("A".into()))
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=inventory.reader: authoritative frozen field versions"]
async fn frozen_collection_requires_authoritative_active_source_definition() -> anyhow::Result<()> {
    use rss_mdm_inventory::{CollectionDefinition, CollectionField, CollectionScope, Source};
    use rss_mdm_inventory_postgres as pg;
    let mut c = PgConnection::connect_with(&options("mdm_inventory_runtime")?).await?;
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let mut original = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key == rss_mdm_inventory::builtin::MODEL)
        .unwrap();
    original.key = rss_mdm_inventory::FieldKey::parse("custom.frozen_model")?;
    original.sources = [(Source::AgentNative, 0)].into();
    assert!(pg::publish_field_in(&mut tx, tenant, 0, &original).await?);
    let definition = |name: &str, field| {
        CollectionDefinition::new(
            name,
            "one",
            Source::AgentNative,
            vec![CollectionField {
                definition: field,
                scope: CollectionScope::Device,
            }],
        )
    };
    let frozen = definition("frozen", original.clone())?;
    let mut upgraded = original.clone();
    upgraded.version += 1;
    upgraded.searchable = !upgraded.searchable;
    assert!(pg::publish_field_in(&mut tx, tenant, 1, &upgraded).await?);
    pg::register_collection_in(&mut tx, tenant, &frozen).await?;
    pg::register_collection_in(&mut tx, tenant, &frozen).await?;
    let mut forged = original.clone();
    forged.searchable = !forged.searchable;
    assert!(
        pg::register_collection_in(&mut tx, tenant, &definition("forged", forged)?)
            .await
            .is_err()
    );
    let mut absent = original.clone();
    absent.version = 99;
    assert!(
        pg::register_collection_in(&mut tx, tenant, &definition("absent", absent)?)
            .await
            .is_err()
    );
    upgraded.version += 1;
    upgraded.sources = [(Source::MdmWindows, 0)].into();
    assert!(pg::publish_field_in(&mut tx, tenant, 2, &upgraded).await?);
    assert!(
        pg::register_collection_in(&mut tx, tenant, &definition("revoked", original.clone())?)
            .await
            .is_err()
    );
    assert!(pg::retire_field_in(&mut tx, tenant, original.key, 3).await?);
    assert!(
        pg::register_collection_in(&mut tx, tenant, &definition("retired", original)?)
            .await
            .is_err()
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}
