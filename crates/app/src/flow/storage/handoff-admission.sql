-- Exact host authority for borrowed execution handoff and current authorization.
WITH capabilities(name,append) AS (VALUES
 ('mdm_access.agent_bindings',false),('mdm_access.authorization_rules',false),('mdm_access.user_groups',false)
), objects AS (
 SELECT name,append,to_regclass(name) AS oid FROM capabilities
), reachable AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 (SELECT count(*)=3 AND bool_and(o.oid IS NOT NULL AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
  AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
  AND has_table_privilege(current_user,c.oid,'SELECT')
  AND (NOT o.append OR has_table_privilege(current_user,c.oid,'INSERT')))
  FROM objects o LEFT JOIN pg_class c ON c.oid=o.oid)
 AND NOT EXISTS(SELECT 1 FROM objects o JOIN pg_class c ON c.oid=o.oid CROSS JOIN reachable r
  WHERE c.relowner=r.oid
   OR has_table_privilege(r.oid,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,c.oid,'UPDATE,REFERENCES')
   OR (NOT o.append AND (has_table_privilege(r.oid,c.oid,'INSERT') OR has_any_column_privilege(r.oid,c.oid,'INSERT'))))
 AND NOT EXISTS(SELECT 1 FROM objects o JOIN pg_class c ON c.oid=o.oid,
  LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable)
   AND (a.is_grantable OR a.privilege_type NOT IN('SELECT','INSERT') OR (a.privilege_type='INSERT' AND NOT o.append))))
 AND NOT EXISTS(SELECT 1 FROM objects o JOIN pg_attribute c ON c.attrelid=o.oid,
  LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable)
   AND (a.is_grantable OR a.privilege_type NOT IN('SELECT','INSERT') OR (a.privilege_type='INSERT' AND NOT o.append))))
