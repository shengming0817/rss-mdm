//! Manual inventory transaction behavior. The host supplies the tenant transaction.
#[path = "../../../tests/support/context.rs"]
mod case;
use rss_mdm_inventory::{Evidence, KnownValue, Scalar, Source, SourceFact, State};
use rss_mdm_inventory_postgres as pg;
use sqlx::{
    Connection,
    postgres::{PgConnectOptions, PgSslMode},
};
#[tokio::test]
#[ignore = "make t2 MODULE=inventory.manual: real TLS PostgreSQL"]
async fn public_manual_cas_rollback_and_tenant_isolation() -> Result<(), Box<dyn std::error::Error>>
{
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_inventory_runtime")
        .password("runtime-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let foreign = rss_request_context::TenantId::parse(case::peer())?;
    let evidence = Evidence {
        scope: rss_mdm_inventory::CollectionScope::Device,
        source: Source::Manual,
        dataset: None,
        registration: None,
        registration_generation: None,
        epoch: None,
        snapshot_id: "manual-operation".into(),
        observed_at: 1,
        received_at: 2,
        actor: Some("fixture-authority".into()),
    };
    let fact = SourceFact {
        state: State::Known(Scalar::Integer(7)),
        last_known: Some(KnownValue {
            value: Scalar::Integer(7),
            evidence: evidence.clone(),
        }),
        evidence,
    };
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        pg::manual_scalars_at_in(
            &mut tx,
            foreign,
            &["manual-device".into()],
            i64::MAX,
            &[rss_mdm_inventory::builtin::OFFICE_FLOOR]
        )
        .await
        .unwrap_err()
        .to_string(),
        "asset transaction tenant mismatch"
    );
    assert_eq!(
        pg::assign_in(
            &mut tx,
            tenant,
            "manual-device",
            rss_mdm_inventory::builtin::OFFICE_FLOOR,
            0,
            &fact.state,
            &fact.evidence
        )
        .await?,
        Some(1)
    );
    assert_eq!(
        pg::assign_in(
            &mut tx,
            tenant,
            "manual-device",
            rss_mdm_inventory::builtin::OFFICE_FLOOR,
            0,
            &fact.state,
            &fact.evidence
        )
        .await?,
        None
    );
    assert_eq!(
        pg::manual_scalars_at_in(
            &mut tx,
            tenant,
            &["manual-device".into()],
            i64::MAX,
            &[rss_mdm_inventory::builtin::OFFICE_FLOOR]
        )
        .await?[0]
            .fact,
        fact
    );
    // Exercise the storage page byte bound independently of the HTTP item-count bound.
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|field| field.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
        .unwrap();
    field.key = rss_mdm_inventory::FieldKey::parse("custom.array_page")?;
    field.value_type = rss_mdm_inventory::ValueType::Array {
        items: Box::new(rss_mdm_inventory::ValueType::String {
            max_length: 64,
            allow_empty: true,
        }),
        max_items: 8,
    };
    sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4::jsonb)")
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .bind(field.version as i64)
        .bind(serde_json::to_value(&field)?)
        .execute(&mut *tx)
        .await?;
    let items = vec![
        Scalar::String("中文🙂".into()),
        Scalar::String("second".into()),
        Scalar::String("last".into()),
    ];
    assert_eq!(
        pg::assign_in(
            &mut tx,
            tenant,
            "array-device",
            field.key,
            0,
            &State::Known(Scalar::Array(items.clone())),
            &fact.evidence
        )
        .await?,
        Some(1)
    );
    let version: String = sqlx::query_scalar("SELECT value_version FROM mdm.manual_assignments WHERE tenant_id=$1::uuid AND device='array-device' AND field=$2")
        .bind(tenant.to_string()).bind(field.key.as_str()).fetch_one(&mut *tx).await?;
    let budget = serde_json::to_vec(&items[0])?.len();
    let first = pg::arrays::page(&mut tx, tenant, &version, 0, 8, budget).await?;
    assert_eq!(first.items, items[..1]);
    assert_eq!(first.next, Some(1));
    let second =
        pg::arrays::page(&mut tx, tenant, &version, first.next.unwrap(), 8, budget).await?;
    assert_eq!(second.items, items[1..2]);
    assert_eq!(second.next, Some(2));
    let last = pg::arrays::page(&mut tx, tenant, &version, second.next.unwrap(), 8, budget).await?;
    assert_eq!(last.items, items[2..]);
    assert_eq!(last.next, None);
    assert!(
        pg::arrays::page(&mut tx, tenant, &version, 0, 8, budget - 1)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        pg::manual_scalars_at_in(
            &mut tx,
            tenant,
            &["manual-device".into()],
            i64::MAX,
            &[rss_mdm_inventory::builtin::OFFICE_FLOOR]
        )
        .await?
        .is_empty()
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=inventory.manual: real TLS PostgreSQL"]
async fn field_catalog_cas_history_and_rollback_are_atomic()
-> Result<(), Box<dyn std::error::Error>> {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_inventory_runtime")
        .password("runtime-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
        .unwrap();
    field.key = rss_mdm_inventory::FieldKey::parse("custom.catalog_test.floor")?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    pg::verify_collections(&mut tx).await?;
    let before = pg::watermark_in(&mut tx, tenant).await?;
    sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4::jsonb)")
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .bind(field.version as i64)
        .bind(serde_json::to_value(&field)?)
        .execute(&mut *tx)
        .await?;
    assert!(!pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
    assert!(
        pg::catalog_at_in(&mut tx, tenant, before)
            .await?
            .definition(field.key)
            .is_err()
    );
    assert_eq!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)?,
        &field
    );
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)
            .is_err()
    );
    sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4::jsonb)")
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .bind(field.version as i64)
        .bind(serde_json::to_value(&field)?)
        .execute(&mut *tx)
        .await?;
    let published = pg::watermark_in(&mut tx, tenant).await?;
    assert!(pg::retire_field_in(&mut tx, tenant, field.key, 1).await?);
    assert!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)
            .is_err()
    );
    assert_eq!(
        pg::catalog_at_in(&mut tx, tenant, published)
            .await?
            .definition(field.key)?,
        &field
    );
    field.version = 3;
    assert!(!pg::publish_field_in(&mut tx, tenant, 2, &field).await?);
    // Retired identities stay reserved without consuming the active catalog budget.
    field.version = 1;
    // Batch legitimate v1 publications and v2 retirements through the schema owner primitive.
    // Only the final active publication is the capacity operation under test.
    let document = serde_json::to_string(&field)?.replace('\'', "''");
    let seed = format!(
        "DO $seed$ DECLARE i integer; f text; BEGIN FOR i IN 0..1024 LOOP f='custom.retired_'||i; PERFORM mdm.append_field_version('{tenant}'::uuid,f,1,jsonb_set('{document}'::jsonb,'{{key}}',to_jsonb(f))); PERFORM mdm.append_field_version('{tenant}'::uuid,f,2,NULL); END LOOP; END $seed$"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(seed.as_str()))
        .execute(&mut *tx)
        .await?;
    let retired: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field LIKE 'custom.retired_%' AND version=2 AND definition IS NULL")
        .bind(tenant.to_string()).fetch_one(&mut *tx).await?;
    assert_eq!(retired, 1025);
    field.key = rss_mdm_inventory::FieldKey::parse("custom.after_retirement")?;
    sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4::jsonb)")
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .bind(field.version as i64)
        .bind(serde_json::to_value(&field)?)
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)?,
        &field
    );
    assert!(
        pg::catalog_at_in(&mut tx, tenant, published)
            .await?
            .definition(rss_mdm_inventory::FieldKey::parse(
                "custom.catalog_test.floor"
            )?)
            .is_ok()
    );
    tx.commit().await?;
    c.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=inventory.manual: real TLS PostgreSQL"]
async fn seed_retirement_and_reinitialization_preserve_tenant_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_inventory_runtime")
        .password("runtime-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    pg::initialize_fields_in(&mut tx, tenant).await?;
    let key = rss_mdm_inventory::builtin::OFFICE_FLOOR;
    let before = pg::watermark_in(&mut tx, tenant).await?;
    assert!(pg::retire_field_in(&mut tx, tenant, key, 1).await?);
    pg::initialize_fields_in(&mut tx, tenant).await?;
    assert!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(key)
            .is_err()
    );
    assert!(
        pg::catalog_at_in(&mut tx, tenant, before)
            .await?
            .definition(key)
            .is_ok()
    );
    let core = rss_mdm_inventory::FieldKey::parse("device.hardware_uuid")?;
    assert_eq!(
        pg::retire_field_in(&mut tx, tenant, core, 1)
            .await
            .unwrap_err()
            .to_string(),
        "system field cannot be removed"
    );
    assert_eq!(
        pg::catalog_in(&mut tx, tenant).await?.definition(core)?.key,
        core
    );
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=inventory.manual: resumable canonical array verification"]
async fn array_scan_recovers_across_transactions_and_rejects_incomplete_payloads()
-> anyhow::Result<()> {
    use rss_mdm_inventory::{FieldKey, ValueType};
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_inventory_runtime")
        .password("runtime-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
        .unwrap();
    field.key = FieldKey::parse("custom.scan_recovery")?;
    field.value_type = ValueType::Array {
        items: Box::new(ValueType::String {
            max_length: 64,
            allow_empty: false,
        }),
        max_items: 3000,
    };
    assert!(pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
    let items = (0..2001)
        .map(|n| Scalar::String(format!("value-{n}")))
        .collect::<Vec<_>>();
    let evidence = Evidence {
        scope: rss_mdm_inventory::CollectionScope::Device,
        source: Source::Manual,
        dataset: None,
        registration: None,
        registration_generation: None,
        epoch: None,
        snapshot_id: "scan".into(),
        observed_at: 1,
        received_at: 1,
        actor: Some("fixture".into()),
    };
    assert_eq!(
        pg::assign_in(
            &mut tx,
            tenant,
            "scan-device",
            field.key,
            0,
            &State::Known(Scalar::Array(items.clone())),
            &evidence
        )
        .await?,
        Some(1)
    );
    let version:String=sqlx::query_scalar("SELECT value_version FROM mdm.manual_assignments WHERE tenant_id=$1::uuid AND device='scan-device' AND field=$2").bind(tenant.to_string()).bind(field.key.as_str()).fetch_one(&mut *tx).await?;
    let state = pg::arrays::start_scan(&mut tx, tenant, &version).await?;
    let first = pg::arrays::advance_scan(&mut tx, tenant, state).await?;
    assert_eq!(first.items, items[..1000]);
    assert!(!first.state.verified());
    let checkpoint = serde_json::to_vec(&first.state)?;
    tx.commit().await?;
    c.close().await?;
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let recovered = serde_json::from_slice(&checkpoint)?;
    let second = pg::arrays::advance_scan(&mut tx, tenant, recovered).await?;
    assert_eq!(second.items, items[1000..2000]);
    assert!(!second.state.verified());
    // A rolled-back attempt does not consume the persisted checkpoint.
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let second =
        pg::arrays::advance_scan(&mut tx, tenant, serde_json::from_slice(&checkpoint)?).await?;
    assert_eq!(second.items, items[1000..2000]);
    let last = pg::arrays::advance_scan(&mut tx, tenant, second.state).await?;
    assert_eq!(last.items, items[2000..]);
    assert!(last.state.verified());
    assert_eq!(last.state.next_ordinal(), items.len());
    // Valid row-level hashes are insufficient: a missing final row must still fail.
    let damaged = "e".repeat(64);
    sqlx::query("INSERT INTO mdm.array_versions SELECT tenant_id,$3,format,field,definition_digest,item_count,canonical_bytes,digest,definition FROM mdm.array_versions WHERE tenant_id=$1::uuid AND version=$2")
        .bind(tenant.to_string()).bind(&version).bind(&damaged).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm.array_items(tenant_id,version,ordinal,payload,digest,prefix_bytes) SELECT tenant_id,$3,ordinal,payload,digest,prefix_bytes FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2 AND ordinal<2000")
        .bind(tenant.to_string()).bind(&version).bind(&damaged).execute(&mut *tx).await?;
    let mut state = pg::arrays::start_scan(&mut tx, tenant, &damaged).await?;
    for _ in 0..2 {
        let chunk = pg::arrays::advance_scan(&mut tx, tenant, state).await?;
        assert!(!chunk.state.verified());
        state = chunk.state;
    }
    assert!(
        pg::arrays::advance_scan(&mut tx, tenant, state)
            .await
            .is_err()
    );
    // Preserve every row, length, ordinal and prefix; only the full canonical hash can
    // detect this equal-length substitution after resuming the serialized hash state.
    let substituted = "f".repeat(64);
    let replacement = serde_json::to_vec(&Scalar::String("value-200X".into()))?;
    assert_eq!(replacement.len(), serde_json::to_vec(&items[2000])?.len());
    sqlx::query("INSERT INTO mdm.array_versions SELECT tenant_id,$3,format,field,definition_digest,item_count,canonical_bytes,digest,definition FROM mdm.array_versions WHERE tenant_id=$1::uuid AND version=$2")
        .bind(tenant.to_string()).bind(&version).bind(&substituted).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm.array_items(tenant_id,version,ordinal,payload,digest,prefix_bytes) SELECT tenant_id,$3,ordinal,CASE WHEN ordinal=2000 THEN $4::bytea ELSE payload END,sha256(CASE WHEN ordinal=2000 THEN $4::bytea ELSE payload END),prefix_bytes FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2")
        .bind(tenant.to_string()).bind(&version).bind(&substituted).bind(replacement).execute(&mut *tx).await?;
    let mut state = pg::arrays::start_scan(&mut tx, tenant, &substituted).await?;
    for _ in 0..2 {
        state = pg::arrays::advance_scan(&mut tx, tenant, state)
            .await?
            .state;
    }
    let state = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    let rejected = pg::arrays::advance_scan(&mut tx, tenant, state).await;
    assert!(rejected.is_err());
    assert!(
        rejected
            .err()
            .unwrap()
            .to_string()
            .contains("canonical digest")
    );
    let foreign = rss_request_context::TenantId::parse(case::peer())?;
    assert!(
        pg::arrays::start_scan(&mut tx, foreign, &version)
            .await
            .is_err()
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}
