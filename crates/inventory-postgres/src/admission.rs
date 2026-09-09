//! Product-owned Inventory deployment contract, checked before accepting runtime work.
use anyhow::{Result, ensure};
use sqlx::{PgPool, Row};

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
 WHERE c.oid<>t.oid AND n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind IN ('r','p','v','m','f')
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema') AND CASE WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 ELSE (SELECT bool_and(has_table_privilege(current_user,t.oid,p)) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p) END AS dml,
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=t.oid AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, journal, generation, scope, coverage, field)') AS identity
FROM target t
"#).bind(reader).fetch_one(&mut *transaction).await?;
    for field in ["rls", "policy", "roles", "acl", "dml", "identity"] {
        ensure!(
            row.try_get::<bool, _>(field)?,
            "Inventory admission rejected: {field}"
        );
    }
    transaction.commit().await?;
    Ok(())
}
