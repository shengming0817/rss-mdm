use super::*;

pub(super) async fn copy_batches(
    c: &Context,
    batch: Uuid,
    count: i32,
    field: Option<&str>,
    policy: Option<Uuid>,
) -> Result<()> {
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let copied=sqlx::query("INSERT INTO mdm_telemetry.batches(expected_epoch,tenant_id,id,device,credential,source,epoch,policy,policy_version,input_digest,context_digest,fields,received_at,delivery,first_observed,last_observed,quality,observations,current_assets)
            SELECT expected_epoch,tenant_id,gen_random_uuid(),device,credential,source,epoch,coalesce($5,policy),policy_version,input_digest,context_digest,CASE WHEN $4::text IS NULL THEN fields ELSE ARRAY[$4::text] END,received_at,delivery,first_observed,last_observed,quality,observations,current_assets
            FROM mdm_telemetry.batches CROSS JOIN generate_series(1,$3::int) WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(batch).bind(count).bind(field).bind(policy).execute(&mut *tx).await?.rows_affected();
    anyhow::ensure!(copied == count as u64);
    tx.commit().await?;
    Ok(())
}

// A PostgreSQL sequence records the first and last publication visited even when
// the caller rolls back on deadline. Delay each real frozen read by 30 ms.
pub(super) async fn fixed_budget(
    c: &Context,
    http: &http::Http,
    request: &Value,
    duplicate_batch: Uuid,
) -> Result<()> {
    let probe = format!("probe_{}", Uuid::new_v4().simple());
    let install = format!("CREATE SCHEMA {probe}; CREATE SEQUENCE {probe}.first; CREATE SEQUENCE {probe}.last;
      CREATE FUNCTION {probe}.visit(p uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
      DECLARE n bigint := ('x'||right(replace(p::text,'-',''),8))::bit(32)::bigint;
      BEGIN IF NOT (SELECT is_called FROM {probe}.first) THEN PERFORM setval('{probe}.first',n); END IF;
      PERFORM setval('{probe}.last',n); PERFORM pg_sleep(0.03); RETURN true; END $$;
      REVOKE ALL ON FUNCTION {probe}.visit(uuid) FROM PUBLIC; GRANT EXECUTE ON FUNCTION {probe}.visit(uuid) TO mdm_telemetry_runtime;
      CREATE POLICY {probe} ON mdm_policy.versions AS RESTRICTIVE FOR SELECT TO mdm_telemetry_runtime
      USING (CASE WHEN tenant_id='{}'::uuid THEN {probe}.visit(policy) ELSE true END)", c.tenant);
    sqlx::raw_sql(sqlx::AssertSqlSafe(install))
        .execute(&c.operator)
        .await?;
    let result = async {
        let id=Uuid::parse_str(request["id"].as_str().unwrap())?;
        let clock=crate::clock::monotonic();
        let mut ranges=Vec::new();
        let mut previous = 0i64;
        let mut completed = false;
        for _ in 0..=49 {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SELECT setval('{probe}.first',1,false),setval('{probe}.last',1,false)"))).execute(&c.operator).await?;
            let started = clock.now();
            let response = http.call("/telemetry/maintenance",request.clone()).await?;
            let range:(i64,i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT (SELECT last_value FROM {probe}.first),last_value FROM {probe}.last")))
                .fetch_one(&c.operator).await?;
            ranges.push(json!({"first":range.0,"last":range.1,"status":response.0,
                "elapsedMs":(clock.now()-started).as_millis()}));
            if response.0==200 {
                anyhow::ensure!(response.1["state"]=="complete" && previous>0);
                completed=true;
                break;
            }
            anyhow::ensure!(response == (504,json!({"code":"request_deadline"})));
            let cursor:Uuid=sqlx::query_scalar("SELECT policy FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2")
                .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
            let current=i64::try_from(cursor.as_u128())?;
            anyhow::ensure!(range.0==previous+1 && current>previous && current<=range.1,
                "saved prefix {previous} advanced to {current} after reading {range:?}");
            copy_batches(c,duplicate_batch,1,None,None).await?;
            previous=current;
        }
        anyhow::ensure!(completed,"all 49 publications must finish with the same original ID");
        let cleared:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2)")
            .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
        anyhow::ensure!(cleared);
        let output=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/local-t2");
        std::fs::create_dir_all(&output)?;
        std::fs::write(output.join("stream-qualification.json"),serde_json::to_vec_pretty(&ranges)?)?;
        anyhow::Ok(())
    }.await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP POLICY {probe} ON mdm_policy.versions; DROP SCHEMA {probe} CASCADE"
    )))
    .execute(&c.operator)
    .await?;
    result
}

pub(super) async fn boundaries(
    c: &Context,
    short: &http::Http,
    http: &http::Http,
    request: &Value,
    account: &crate::authority_t2_support::Account,
    batch: Uuid,
) -> Result<()> {
    let id = Uuid::parse_str(request["id"].as_str().unwrap())?;
    let mut altered = request.clone();
    altered["resource"] = json!("different");
    assert_eq!(http.call("/telemetry/maintenance", altered).await?.0, 409);

    sqlx::query("DELETE FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(account.rule)
        .execute(&c.operator)
        .await?;
    assert_eq!(
        http.call("/telemetry/maintenance", request.clone())
            .await?
            .0,
        403
    );
    crate::authority_t2_support::seed_rule(
        &c.operator,
        &account.user,
        account.rule,
        &[Permission::InventoryRead, Permission::TelemetryMaintain],
    )
    .await?;

    let rows=sqlx::query("INSERT INTO mdm_telemetry.stream_checks
        SELECT tenant_id,gen_random_uuid(),sha256('quota'),device,source,epoch,catalog_revision,byte_limit,policy,version,found,expires_at
        FROM mdm_telemetry.stream_checks CROSS JOIN generate_series(1,255) WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(id).execute(&c.operator).await?.rows_affected();
    assert_eq!(rows, 255);
    let fresh = || {
        let mut next = request.clone();
        next["id"] = json!(Uuid::new_v4());
        next
    };
    let (a, b) = tokio::join!(
        http.call("/telemetry/maintenance", fresh()),
        http.call("/telemetry/maintenance", fresh())
    );
    for response in [a?, b?] {
        assert_eq!(response, (422, json!({"code":"capacity_exceeded"})));
    }
    super::late_page_deadline(c, short, request, 17).await?;
    sqlx::query("UPDATE mdm_telemetry.stream_checks SET expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1::uuid")
        .bind(c.tenant.to_string()).execute(&c.operator).await?;
    // Expiry and an actual catalog publication must both send a saved prefix back to the first read.
    super::late_page_deadline(c, short, request, 1).await?;
    super::late_page_deadline(c, short, request, 17).await?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    rss_mdm_inventory_postgres::lock_catalog_write_in(&mut tx, c.tenant).await?;
    sqlx::query("SELECT mdm.append_field_version(tenant_id,'custom.checkpoint_marker',1,
        jsonb_set(definition,'{key}',to_jsonb('custom.checkpoint_marker'::text))) FROM mdm.field_versions
        WHERE tenant_id=$1::uuid AND field='custom.history_0000' AND version=1")
        .bind(c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    super::late_page_deadline(c, short, request, 1).await?;
    super::late_page_deadline(c, short, request, 17).await?;

    // A new digest behind the cursor invalidates the checked prefix. A new
    // publication beyond it remains visible to the final tail seek.
    for (field, policy) in [
        (Some("unknown.checkpoint"), None),
        (None, Some(Uuid::from_u128(50))),
    ] {
        copy_batches(c, batch, 1, field, policy).await?;
        let cursor: Option<Uuid> = sqlx::query_scalar(
            "SELECT policy FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(id)
        .fetch_one(&c.operator)
        .await?;
        assert_eq!(cursor, policy.map(|_| Uuid::from_u128(16)));
        assert_eq!(
            http.call("/telemetry/maintenance", request.clone())
                .await?
                .0,
            403
        );
        let residue:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2),
            (SELECT count(*) FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2)")
            .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
        assert_eq!(residue, (0, 0));
        let removed=sqlx::query("DELETE FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND (fields=ARRAY[$2::text] OR policy=$3)")
            .bind(c.tenant.to_string()).bind(field).bind(policy).execute(&c.operator).await?.rows_affected();
        assert_eq!(removed, 1);
        super::late_page_deadline(c, short, request, 17).await?;
    }
    let mut corrupt = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("UPDATE mdm.field_versions SET definition=jsonb_set(definition,'{sensitivity}',to_jsonb('secret'::text))
        WHERE tenant_id=$1::uuid AND field='custom.history_0001'").bind(c.tenant.to_string()).execute(&mut *corrupt).await?;
    corrupt.commit().await?;
    assert_eq!(
        http.call("/telemetry/maintenance", request.clone())
            .await?
            .0,
        403
    );
    sqlx::query("UPDATE mdm.field_versions SET definition=jsonb_set(definition,'{sensitivity}',to_jsonb('standard'::text))
        WHERE tenant_id=$1::uuid AND field='custom.history_0001'").bind(c.tenant.to_string()).execute(&c.operator).await?;
}
