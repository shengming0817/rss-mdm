-- The native registration transaction can inspect frozen execution authority, never mutate it.
WITH expected(name) AS (VALUES
 ('mdm_commands.operations'),
 ('mdm_commands.attempts'),
 ('mdm_policy.policies'),
 ('mdm_policy.versions'),
 ('mdm_resource.aggregates'),
 ('mdm_resource.immutable'),
 ('mdm_software.sources'),
 ('mdm_software.approvals')
), relations AS (
 SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name)
)
SELECT (SELECT count(*) FROM relations)=(SELECT count(*) FROM expected)
 AND NOT EXISTS(SELECT 1 FROM relations c WHERE c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
  OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR NOT has_table_privilege(current_user,c.oid,'SELECT')
  OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM relations c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM relations c JOIN pg_attribute col ON col.attrelid=c.oid,LATERAL aclexplode(col.attacl) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
