-- Only immutable association reads are granted to the application role.
WITH expected(name) AS (VALUES
 ('mdm_commands.action_runs'),
 ('mdm_assets.operations'),('mdm_commands.requests')
), relations AS (
 SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name)
)
SELECT (SELECT count(*) FROM relations)=3
 AND NOT EXISTS(SELECT 1 FROM relations c WHERE c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
  OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR NOT has_table_privilege(current_user,c.oid,'SELECT')
  OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM relations c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
