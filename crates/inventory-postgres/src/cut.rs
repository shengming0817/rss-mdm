//! Committed input capture, kept outside the initiating business transaction.
use rss_mdm_inventory::AssetCut;
use rss_request_context::TenantId;
use sqlx::PgPool;

/// Capture committed facts using the host's existing read pool, then release it.
/// Call before opening the business transaction. No own writes are included.
pub async fn capture_asset_cut(pool: &PgPool, tenant: TenantId) -> Result<AssetCut, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let cut = capture_asset_cut_on_read(&mut tx, tenant).await?;
    tx.rollback().await?;
    Ok(cut)
}

/// Capture on an already-owned read-only connection. The SQL contract rejects
/// write transactions, so uncommitted caller facts can never enter this input.
pub async fn capture_asset_cut_on_read(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
) -> Result<AssetCut, sqlx::Error> {
    let value = sqlx::query_scalar("SELECT mdm.capture_asset_cut($1::uuid)")
        .bind(tenant.to_string())
        .fetch_one(c)
        .await?;
    AssetCut::from_json(value)
        .map_err(|_| sqlx::Error::Protocol("invalid committed asset cut".into()))
}

/// SQL defining the current visibility and stopped-restore contracts.
pub const ASSET_CUT_SQL: &str = include_str!("../migrations/asset-cuts.sql");

/// Validate the exact privileged visibility kernels and prohibit runtime epoch writes.
pub async fn verify_asset_history(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    verify_history(c, false).await
}

/// Verify the reader's sole privileged capture kernel without granting history writes.
pub(crate) async fn verify_asset_reader(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    verify_history(c, true).await
}
async fn verify_history(c: &mut sqlx::PgConnection, reader: bool) -> Result<(), sqlx::Error> {
    for (name, signature, result, volatility) in [
        (
            "capture_asset_cut",
            "mdm.capture_asset_cut(uuid)",
            "jsonb",
            "s",
        ),
        (
            "asset_cut_context",
            "mdm.asset_cut_context(jsonb)",
            "record",
            "s",
        ),
        (
            "asset_context_contains",
            "mdm.asset_context_contains(uuid,pg_snapshot,uuid[],uuid,xid8)",
            "boolean",
            "i",
        ),
        (
            "asset_cut_contains",
            "mdm.asset_cut_contains(jsonb,uuid,xid8)",
            "boolean",
            "s",
        ),
        (
            "asset_visible",
            "mdm.asset_visible(jsonb,bigint)",
            "boolean",
            "s",
        ),
    ] {
        if reader && name != "capture_asset_cut" {
            continue;
        }
        let declaration = format!("CREATE FUNCTION mdm.{name}(");
        let source = ASSET_CUT_SQL
            .split_once(&declaration)
            .expect("owned declaration")
            .1
            .split("$$")
            .nth(1)
            .expect("owned body");
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_proc p WHERE p.oid=to_regprocedure($1) AND p.prosecdef AND p.provolatile::text=$4 AND NOT p.proleakproof AND p.prorettype=to_regtype($2) AND p.proconfig=ARRAY['search_path=pg_catalog, mdm'] AND p.prosrc=$3 AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='mdm.asset_epochs'::regclass) AND NOT pg_has_role(current_user,p.proowner,'MEMBER') AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(SELECT FROM pg_roles r WHERE r.oid=a.grantee AND r.rolname IN('mdm_api','mdm_runtime','mdm_access','mdm_identity_runtime','mdm_inventory_runtime','mdm_scope_runtime','mdm_policy_runtime','mdm_resource_runtime','mdm_telemetry_runtime','mdm_command_runtime','da_api','da_runtime','da_access','da_identity_runtime','da_inventory_runtime','da_scope_runtime','da_policy_runtime','da_resource_runtime','da_telemetry_runtime','da_command_runtime')))))")
            .bind(signature).bind(result).bind(source).bind(volatility).fetch_one(&mut *c).await?;
        if !valid {
            return Err(sqlx::Error::Protocol("asset visibility contract".into()));
        }
    }
    if !reader {
        verify_input_publisher(c).await?;
    }
    let allocator: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid WHERE s.seqrelid='mdm.asset_event_ids'::regclass AND s.seqtypid='bigint'::regtype AND s.seqincrement=1 AND s.seqcache=1 AND NOT s.seqcycle AND s.seqmin=1 AND s.seqmax=9223372036854775807 AND c.relowner=(SELECT relowner FROM pg_class WHERE oid='mdm.asset_epochs'::regclass))")
        .fetch_one(&mut *c).await?;
    if !allocator {
        return Err(sqlx::Error::Protocol(
            "asset event allocator contract".into(),
        ));
    }
    let writable: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'mdm.asset_epochs','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,'mdm.asset_epochs','INSERT,UPDATE,REFERENCES') OR has_function_privilege(current_user,'mdm.advance_asset_epoch(uuid)','EXECUTE') OR has_sequence_privilege(current_user,'mdm.asset_event_ids','USAGE,UPDATE')")
        .fetch_one(c).await?;
    if writable {
        return Err(sqlx::Error::Protocol("asset epoch writer isolation".into()));
    }
    Ok(())
}

/// Admit the one product SQL publisher, including its private public-wire encoder.
async fn verify_input_publisher(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    for (signature, name, definer, path) in [
        (
            "mdm.input_frame(integer,bytea)",
            "input_frame",
            false,
            "search_path=pg_catalog",
        ),
        (
            "mdm.append_input_event(uuid,text,text,text,text,jsonb)",
            "append_input_event",
            true,
            "search_path=pg_catalog, mdm",
        ),
        (
            "mdm.record_asset_change(uuid,text,jsonb,text[])",
            "record_asset_change",
            true,
            "search_path=pg_catalog, mdm",
        ),
    ] {
        let declaration = format!("CREATE FUNCTION mdm.{name}(");
        let body = crate::MIGRATION_SQL
            .split_once(&declaration)
            .expect("owned function")
            .1
            .split("$$")
            .nth(1)
            .expect("owned body");
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_proc p WHERE p.oid=to_regprocedure($1) AND p.prosecdef=$2 AND p.proconfig=ARRAY[$3] AND p.prosrc=$4 AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='mdm.asset_epochs'::regclass) AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR a.is_grantable OR (p.proname<>'record_asset_change' AND a.grantee<>p.proowner)))")
            .bind(signature).bind(definer).bind(path).bind(body).fetch_one(&mut *c).await?;
        if !valid {
            return Err(sqlx::Error::Protocol("asset publisher contract".into()));
        }
    }
    Ok(())
}
