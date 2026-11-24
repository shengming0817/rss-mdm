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
    binding_and_revocation(c, http, request, account).await?;
    let other = last_slot(c, http, request, batch, id).await?;
    expiry_and_publication(c, short, http, request, other, id).await?;
    changed_membership(c, short, http, request, batch, id).await?;
    correct_qualified_prefix(c, http, request).await
}

async fn binding_and_revocation(
    c: &Context,
    http: &http::Http,
    request: &Value,
    account: &crate::authority_t2_support::Account,
) -> Result<()> {
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

    Ok(())
}

async fn last_slot(
    c: &Context,
    http: &http::Http,
    request: &Value,
    batch: Uuid,
    id: Uuid,
) -> Result<rss_mdm_agent_wire::DeviceId> {
    let rows=sqlx::query("INSERT INTO mdm_telemetry.stream_checks
        SELECT tenant_id,gen_random_uuid(),sha256('quota'),device,source,epoch,catalog_revision,byte_limit,policy,version,found,expires_at
        FROM mdm_telemetry.stream_checks CROSS JOIN generate_series(1,254) WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(id).execute(&c.operator).await?.rows_affected();
    assert_eq!(rows, 254);
    let (other_device, _) = materials::seed_registration(c).await?;
    let seeded=sqlx::query("INSERT INTO mdm_telemetry.batches(expected_epoch,tenant_id,id,device,credential,source,epoch,policy,policy_version,input_digest,context_digest,fields,received_at,delivery,first_observed,last_observed,quality,observations,current_assets)
      SELECT expected_epoch,tenant_id,gen_random_uuid(),$3,credential,source,epoch,policy,policy_version,input_digest,context_digest,fields,received_at,delivery,first_observed,last_observed,quality,observations,current_assets FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2")
      .bind(c.tenant.to_string()).bind(batch).bind(other_device.into_uuid()).execute(&c.operator).await?.rows_affected();
    assert_eq!(seeded, 1);
    // Hold admission past both callers' deadlines so the winning check cannot
    // finish and free its slot while the other endpoint is competing for it.
    let mut gate = crate::command_runtime_t2_support::seed_transaction(c).await?;
    rss_mdm_telemetry_service::selection::lock_change(&mut gate, c.tenant).await?;
    let fresh = || {
        let mut value = request.clone();
        value["id"] = json!(Uuid::new_v4());
        value
    };
    let one = fresh();
    let mut two = fresh();
    two["device"] = json!(other_device);
    let (a, b) = race(c, http, one, two).await?;
    gate.rollback().await?;
    let mut statuses = [a, b];
    statuses.sort();
    assert_eq!(statuses, [422, 504]);
    let size: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(size, 256);

    Ok(other_device)
}

async fn race(c: &Context, http: &http::Http, one: Value, two: Value) -> Result<(u16, u16)> {
    // Pause the first INSERT after its capacity read. The contender must wait
    // behind that transaction (or the same gate if serialization regresses).
    let probe = format!("quota_{}", Uuid::new_v4().simple());
    let key = Uuid::new_v4().as_u128() as i64;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {probe}; CREATE FUNCTION {probe}.wait() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN PERFORM pg_advisory_xact_lock({key}::bigint); RETURN NEW; END $$;
        REVOKE ALL ON FUNCTION {probe}.wait() FROM PUBLIC;
        CREATE TRIGGER {probe} BEFORE INSERT ON mdm_telemetry.stream_checks FOR EACH ROW WHEN (NEW.tenant_id='{}'::uuid) EXECUTE FUNCTION {probe}.wait()",c.tenant))).execute(&c.operator).await?;
    let mut insert = c.operator.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock($1)")
        .bind(key)
        .fetch_one(&mut *insert)
        .await?;
    let (a, b, ()) = tokio::try_join!(
        http.call("/telemetry/maintenance", one),
        http.call("/telemetry/maintenance", two),
        wait_for_contenders(insert, blocker)
    )?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {probe} ON mdm_telemetry.stream_checks; DROP SCHEMA {probe} CASCADE"
    )))
    .execute(&c.operator)
    .await?;
    Ok((a.0, b.0))
}

async fn wait_for_contenders(
    mut insert: sqlx::Transaction<'_, sqlx::Postgres>,
    blocker: i32,
) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(4),async {
            loop {
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *insert).await?;
                let blocked:i64=sqlx::query_scalar("WITH RECURSIVE waiting(pid) AS (SELECT $1::int UNION SELECT p.pid FROM waiting w JOIN pg_stat_activity p ON w.pid=ANY(pg_blocking_pids(p.pid))) SELECT count(*)-1 FROM waiting")
                    .bind(blocker).fetch_one(&mut *insert).await?;
                if blocked>=2 {break anyhow::Ok(());}
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await??;
    insert.rollback().await?;
    Ok(())
}

async fn expiry_and_publication(
    c: &Context,
    short: &http::Http,
    http: &http::Http,
    request: &Value,
    other: rss_mdm_agent_wire::DeviceId,
    id: Uuid,
) -> Result<()> {
    super::late_page_deadline(c, short, request, 17).await?;
    sqlx::query("UPDATE mdm_telemetry.stream_checks SET expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1::uuid")
        .bind(c.tenant.to_string()).execute(&c.operator).await?;
    expired_device_wait(c, short, request).await?;
    expired_peer_wait(c, http, request, id, other).await?;
    let mut replacement = request.clone();
    replacement["resource"] = json!("after-expiry");
    super::late_page_deadline(c, short, &replacement, 1).await?;
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

    Ok(())
}

async fn changed_membership(
    c: &Context,
    short: &http::Http,
    http: &http::Http,
    request: &Value,
    batch: Uuid,
    id: Uuid,
) -> Result<()> {
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
    Ok(())
}

async fn correct_qualified_prefix(c: &Context, http: &http::Http, request: &Value) -> Result<()> {
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
    Ok(())
}

pub(super) async fn resume_final_pass(
    c: &Context,
    short: &http::Http,
    request: &Value,
) -> Result<()> {
    let id = Uuid::parse_str(request["id"].as_str().unwrap())?;
    let mut held = crate::command_runtime_t2_support::seed_transaction(c).await?;
    rss_mdm_telemetry_service::selection::lock_change(&mut held, c.tenant).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    super::wait_for_cutoff(c, short, request, pid).await?;
    held.rollback().await?;
    let ready:(Uuid,bool)=sqlx::query_as("SELECT policy,EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2)
        FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(ready, (Uuid::from_u128(49), false));
    // One live qualification fits; two cannot fit the same 750 ms host budget.
    let probe = format!("finish_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {probe};
        CREATE FUNCTION {probe}.visit() RETURNS boolean VOLATILE LANGUAGE plpgsql SET search_path=pg_catalog AS $$
        BEGIN IF current_setting('mdm_test.visited',true) IS DISTINCT FROM 'yes' THEN
          PERFORM set_config('mdm_test.visited','yes',true); PERFORM pg_sleep(0.39); END IF; RETURN true; END $$;
        REVOKE ALL ON FUNCTION {probe}.visit() FROM PUBLIC; GRANT EXECUTE ON FUNCTION {probe}.visit() TO mdm_telemetry_runtime;
        CREATE POLICY {probe} ON mdm.field_versions AS RESTRICTIVE FOR SELECT TO mdm_telemetry_runtime
        USING(CASE WHEN tenant_id='{}'::uuid AND field='custom.history_0000' THEN {probe}.visit() ELSE true END)",c.tenant))).execute(&c.operator).await?;
    let proof=async {
        assert_eq!(short.call("/telemetry/maintenance",request.clone()).await?,(504,json!({"code":"request_deadline"})));
        let accepted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2 AND result IS NULL)")
            .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
        anyhow::ensure!(accepted,"the first budget must admit the verified tail");
        let result=short.post("/telemetry/maintenance",request.clone()).await?;
        anyhow::ensure!(result["state"]=="complete");
        assert_eq!(short.post("/telemetry/maintenance",request.clone()).await?,result);
        anyhow::Ok(())
    }.await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP POLICY {probe} ON mdm.field_versions; DROP SCHEMA {probe} CASCADE"
    )))
    .execute(&c.operator)
    .await?;
    proof
}

// Additional historical publications use one already delivered Current profile.
// The first 17 uploads still exercise signing, intake, delivery and the provider.
pub(super) async fn extend_history(c: &Context, batch: Uuid) -> Result<()> {
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let n=sqlx::query("WITH ids AS MATERIALIZED (
      SELECT lpad(to_hex(n),32,'0')::uuid policy,gen_random_uuid() version FROM generate_series(18,49)n),
      base AS MATERIALIZED(SELECT * FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2 AND delivery='published'),
      policies AS (INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at)
        SELECT p.tenant_id,i.policy,1,i.version,1,p.state,p.definition,p.author,p.updated_at FROM base b JOIN mdm_policy.policies p
          ON (p.tenant_id,p.id)=(b.tenant_id,b.policy) CROSS JOIN ids i RETURNING id,current_version),
      versions AS (INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint)
        SELECT v.tenant_id,p.current_version,p.id,1,v.action_kind,v.resource,v.resource_version,v.frozen,v.fingerprint
          FROM base b JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(b.tenant_id,b.policy_version) CROSS JOIN policies p RETURNING id,policy)
      INSERT INTO mdm_telemetry.batches(expected_epoch,tenant_id,id,device,credential,source,epoch,policy,policy_version,input_digest,context_digest,fields,received_at,delivery,first_observed,last_observed,quality,observations,current_assets)
        SELECT b.expected_epoch,b.tenant_id,gen_random_uuid(),b.device,b.credential,b.source,b.epoch,v.policy,v.id,b.input_digest,b.context_digest,b.fields,b.received_at,b.delivery,b.first_observed,b.last_observed,b.quality,b.observations,b.current_assets FROM base b CROSS JOIN versions v")
        .bind(c.tenant.to_string()).bind(batch).execute(&mut *tx).await?.rows_affected();
    anyhow::ensure!(n == 32);
    tx.commit().await?;
    Ok(())
}

pub(super) async fn assert_blocked_releases_slot(
    c: &Context,
    http: &http::Http,
    reclaim: &Value,
) -> Result<()> {
    let id = Uuid::parse_str(reclaim["id"].as_str().unwrap())?;
    let added=sqlx::query("INSERT INTO mdm_telemetry.stream_checks SELECT $1::uuid,gen_random_uuid(),sha256('busy'),gen_random_uuid(),
        'agent.script',gen_random_uuid(),0,1,NULL,NULL,false,clock_timestamp()+interval '1 hour' FROM generate_series(1,255)")
        .bind(c.tenant.to_string()).execute(&c.operator).await?.rows_affected();
    assert_eq!(added, 255);
    let progress = http.post("/telemetry/maintenance", reclaim.clone()).await?;
    assert_eq!(progress["state"], "blocked");
    let facts:(i64,bool)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid),
        EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND id=$2 AND result->>'state'='blocked')")
       .bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(
        facts,
        (255, true),
        "close must have a free slot while the original blocked receipt survives"
    );
    Ok(())
}

// The expired retry waits for the endpoint. Its own row must still be available
// to the transaction already holding that endpoint and invalidating old data.
async fn expired_device_wait(c: &Context, short: &http::Http, request: &Value) -> Result<()> {
    let id = Uuid::parse_str(request["id"].as_str().unwrap())?;
    let device = serde_json::from_value(request["device"].clone())?;
    let mut write = crate::command_runtime_t2_support::seed_transaction(c).await?;
    rss_mdm_registration_service::device::store::lock_channel(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut write,
        &c.tenant.to_string(),
        &device,
        inv::Channel::Agent,
    )
    .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *write)
        .await?;
    let check = async {
        c.wait_blocked(pid).await?;
        sqlx::query("SELECT id FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE NOWAIT")
            .bind(c.tenant.to_string()).bind(id).fetch_one(&mut *write).await?;
        anyhow::Ok(())
    };
    let ((), response) =
        tokio::try_join!(check, short.call("/telemetry/maintenance", request.clone()))?;
    assert_eq!(response.0, 504);
    write.rollback().await?;
    Ok(())
}

async fn expired_peer_wait(
    c: &Context,
    http: &http::Http,
    request: &Value,
    id: Uuid,
    other: rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
    let mut held = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query(
        "SELECT id FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&mut *held)
    .await?;
    let mut peer = request.clone();
    peer["id"] = json!(Uuid::new_v4());
    peer["device"] = json!(other);
    peer["action"]["before_micros"] = json!(0);
    assert_eq!(
        http.post("/telemetry/maintenance", peer).await?["state"],
        "complete"
    );
    held.rollback().await?;
    Ok(())
}

pub(super) async fn reject_trigger_drift(c: &Context, service: &Service) -> Result<()> {
    let saved: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('mdm_telemetry.invalidate_batch_prefix()'::regprocedure)",
    )
    .fetch_one(&c.operator)
    .await?;
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION mdm_telemetry.invalidate_batch_prefix() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN RETURN NEW; END$$")
        .execute(&c.operator).await?;
    let replaced = service
        .admit_default(c.execution(), crate::authority_t2_support::deadline())
        .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(saved))
        .execute(&c.operator)
        .await?;
    anyhow::ensure!(
        replaced.is_err(),
        "substituted trigger function passed admission"
    );
    sqlx::query("GRANT EXECUTE ON FUNCTION mdm_telemetry.invalidate_frozen_prefix() TO PUBLIC")
        .execute(&c.operator)
        .await?;
    let granted = service
        .admit_default(c.execution(), crate::authority_t2_support::deadline())
        .await;
    sqlx::query("REVOKE EXECUTE ON FUNCTION mdm_telemetry.invalidate_frozen_prefix() FROM PUBLIC")
        .execute(&c.operator)
        .await?;
    anyhow::ensure!(
        granted.is_err(),
        "unexpected function EXECUTE passed admission"
    );
    Ok(())
}
