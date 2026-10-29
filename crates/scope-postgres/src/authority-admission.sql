-- Privileged kernels: exact bodies come from the corresponding owner's installation SQL.
WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
 ('mdm_scope.scope_admission(uuid,text)', 'plpgsql', 'jsonb', true, false, 'v', ARRAY['p_scope','p_device']::text[], ARRAY['search_path=pg_catalog']::text[], $1::text, ARRAY['mdm_access','mdm_command_runtime','mdm_scope_runtime','mdm_policy_runtime','mdm_inventory_runtime','mdm_telemetry_runtime','mdm_identity_runtime','mdm_owner']::text[]),
 ('mdm_scope.scope_state(uuid,text)', 'plpgsql', 'jsonb', true, false, 's', ARRAY['p_scope','p_device']::text[], ARRAY['search_path=pg_catalog']::text[], $2::text, ARRAY['mdm_access','mdm_command_runtime','mdm_scope_runtime','mdm_policy_runtime','mdm_inventory_runtime','mdm_telemetry_runtime','mdm_identity_runtime','mdm_owner']::text[])
)
SELECT e.signature FROM expected e
LEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)
LEFT JOIN pg_language l ON l.oid=p.prolang
LEFT JOIN pg_roles r ON r.oid=p.proowner
WHERE p.oid IS NULL OR l.lanname<>e.language OR p.prorettype<>to_regtype(e.result)
 OR p.prokind<>'f' OR p.prosecdef<>e.definer OR p.proretset<>e.returns_set
 OR p.provolatile::text<>e.volatility OR p.proleakproof OR p.prosrc<>e.body
 OR coalesce(p.proargnames,ARRAY[]::text[]) IS DISTINCT FROM e.names OR p.proconfig IS DISTINCT FROM e.config
 OR r.rolname<>'mdm_owner' OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
 OR pg_has_role(current_user,r.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))
ORDER BY e.signature LIMIT 1
