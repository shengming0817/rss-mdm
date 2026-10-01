//! Product-owned Inventory deployment contract, checked before accepting runtime work.
use anyhow::{Result, ensure};
use sqlx::{PgPool, Row};

/// Check the projection writer's Inventory RLS, policy, role/ACL, DML and primary-key contract.
/// Uses its own transaction with a 5s statement timeout, reads PostgreSQL catalogs
/// and commits on success; applies no migrations or business writes. Rejected checks
/// or SQL/commit failures return an error. The host must reject admission on failure;
/// success does not verify product resource authorization or future configuration drift.
pub async fn verify(pool: &PgPool) -> Result<()> {
    verify_profile(pool, false).await
}
pub(super) async fn verify_reader(pool: &PgPool) -> Result<()> {
    verify_profile(pool, true).await
}
async fn verify_profile(pool: &PgPool, reader: bool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query(r#"
WITH target AS (SELECT * FROM pg_class WHERE oid='mdm.inventory'::regclass),
reachable AS (SELECT * FROM pg_roles WHERE oid=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR pg_has_role(current_user,oid,'MEMBER'))
SELECT
 t.relrowsecurity AND t.relforcerowsecurity AS rls,
 (SELECT count(*)=1 AND bool_and(polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text','')) = 'tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text','')) = 'tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid') FROM pg_policy WHERE polrelid=t.oid) AS policy,
 NOT EXISTS(SELECT 1 FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.oid=t.relowner
  OR has_schema_privilege(r.oid,'mdm','CREATE') OR has_table_privilege(r.oid,t.oid,'TRUNCATE,REFERENCES,TRIGGER')) AS roles,
 NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN (SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n, LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.oid=t.relnamespace AND (a.grantee=0 OR (a.grantee IN (SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a WHERE c.attrelid=t.oid AND (a.grantee=0 OR (a.grantee IN (SELECT oid FROM reachable) AND (a.is_grantable OR a.privilege_type='REFERENCES')))) AS acl,
 CASE WHEN $1 THEN
 session_user=current_user
 AND has_schema_privilege(current_user,'mdm','USAGE')
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_temp_%' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND has_table_privilege(current_user,t.oid,'SELECT')
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE')
 OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.oid NOT IN(t.oid,'mdm.field_versions'::regclass,'mdm.collection_definitions'::regclass) AND n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind IN ('r','p','v','m','f')
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema') AND CASE WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 ELSE (SELECT bool_and(has_table_privilege(current_user,t.oid,p)) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p) END AS dml,
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, journal, generation, scope, field)') AS identity,
 (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=t.oid AND attnum>0 AND NOT attisdropped) =
 '[ ["tenant_id","uuid",true],["journal","text",true],["generation","text",true],["scope","text",true],["coverage","text",true],["field","text",true],["value","text",false],["batch_id","text",true],["observed_at","bigint",true],["received_at","bigint",true],["state","text",true],["last_known","text",false],["last_known_batch","text",false],["last_known_observed","bigint",false],["last_known_received","bigint",false],["registration","text",true],["source","text",true],["epoch","text",true],["collection_sequence","bigint",true] ]'::jsonb
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND conname='inventory_value_state' AND convalidated
 AND pg_get_constraintdef(oid)='CHECK (((state = ''known''::text) = (value IS NOT NULL)))')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND conname='inventory_state_check' AND convalidated
 AND pg_get_constraintdef(oid)='CHECK ((state = ANY (ARRAY[''known''::text, ''null''::text, ''deleted''::text, ''unsupported''::text])))')
 AND EXISTS(SELECT 1 FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid WHERE i.indrelid=t.oid AND idx.relname='inventory_source'
 AND i.indisvalid AND i.indisready AND i.indislive AND pg_get_indexdef(i.indexrelid)='CREATE INDEX inventory_source ON mdm.inventory USING btree (tenant_id, registration, source, epoch)') AS assets
FROM target t
"#).bind(reader).fetch_one(&mut *transaction).await?;
    for field in ["rls", "policy", "roles", "acl", "dml", "identity", "assets"] {
        ensure!(
            row.try_get::<bool, _>(field)?,
            "Inventory admission rejected: {field}"
        );
    }
    verify_collections(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// Check the immutable collection/catalog tables for the calling product role.
/// Runtime pools cannot acquire owner, update/delete, column-only or RLS-bypass privileges.
pub async fn verify_collections(c: &mut sqlx::PgConnection) -> Result<()> {
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut *c)
        .await?;
    ensure!(
        matches!(
            role.as_str(),
            "mdm_runtime" | "mdm_api" | "mdm_access" | "mdm_command_runtime" | "mdm_flow_runtime"
        ),
        "unknown collection runtime"
    );
    for (table, identity, columns) in [
        (
            "field_versions",
            "PRIMARY KEY (tenant_id, field, version)",
            serde_json::json!([
                ["tenant_id", "uuid", true],
                ["field", "text", true],
                ["version", "bigint", true],
                ["revision", "bigint", true],
                ["definition", "jsonb", false]
            ]),
        ),
        (
            "collection_definitions",
            "PRIMARY KEY (tenant_id, dataset, source, version)",
            serde_json::json!([
                ["tenant_id", "uuid", true],
                ["dataset", "text", true],
                ["version", "text", true],
                ["source", "text", true],
                ["fingerprint", "text", true],
                ["coverage", "text", true],
                ["definition", "jsonb", true]
            ]),
        ),
        (
            "collection_results",
            "PRIMARY KEY (tenant_id, run)",
            serde_json::json!([
                ["tenant_id", "uuid", true],
                ["run", "text", true],
                ["scope", "text", true],
                ["coverage", "text", true],
                ["sequence", "bigint", true],
                ["observed_at", "bigint", true],
                ["digest", "text", true],
                ["document", "bytea", true]
            ]),
        ),
    ] {
        let select = table != "collection_results"
            || matches!(
                role.as_str(),
                "mdm_runtime" | "mdm_access" | "mdm_command_runtime"
            );
        let insert = match table {
            "field_versions" => role == "mdm_flow_runtime",
            "collection_definitions" => matches!(
                role.as_str(),
                "mdm_access" | "mdm_command_runtime" | "mdm_flow_runtime"
            ),
            _ => matches!(role.as_str(), "mdm_access" | "mdm_command_runtime"),
        };
        let valid:bool=sqlx::query_scalar(r#"
        SELECT c.relrowsecurity AND c.relforcerowsecurity AND c.relkind='r'
         AND NOT pg_has_role(current_user,c.relowner,'MEMBER')
         AND NOT has_schema_privilege(current_user,n.oid,'CREATE')
         AND has_schema_privilege(current_user,n.oid,'USAGE')
         AND has_table_privilege(current_user,c.oid,'SELECT')=$2
         AND has_table_privilege(current_user,c.oid,'INSERT')=$3
         AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         AND NOT has_any_column_privilege(current_user,c.oid,'UPDATE,REFERENCES')
         AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND
            (has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>$2 OR has_column_privilege(current_user,c.oid,a.attnum,'INSERT')<>$3))
         AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))
         AND (SELECT count(*)=1 AND bool_and(polcmd='*' AND polname='tenant' AND polpermissive AND polroles=ARRAY[0::oid]
           AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
           AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid)) FROM pg_policy WHERE polrelid=c.oid)
         AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype='p' AND convalidated AND pg_get_constraintdef(oid)=$4)
         AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum) FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)=$5::jsonb
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm' AND c.relname=$1
        "#).bind(table).bind(select).bind(insert).bind(identity).bind(columns.to_string()).fetch_one(&mut *c).await?;
        ensure!(valid, "collection table admission rejected: {role}.{table}");
    }
    Ok(())
}
