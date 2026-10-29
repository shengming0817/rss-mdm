-- Only authorization/fencing kernels; bodies come directly from their owner's installation SQL.
WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
 ('mdm_devices.object_current(jsonb,text)', 'plpgsql', 'jsonb', true, false, 's', ARRAY['p_input','p_channel']::text[], ARRAY['search_path=pg_catalog']::text[], $1::text, ARRAY['mdm_access','mdm_command_runtime','mdm_flow_runtime','mdm_identity_runtime','mdm_owner']::text[]),
 ('mdm_devices.association_grant_current(uuid,bigint,uuid,bigint)', 'sql', 'boolean', true, false, 's', ARRAY['p_id','p_version','p_registration','p_generation']::text[], ARRAY['search_path=pg_catalog']::text[], $2::text, ARRAY['mdm_access','mdm_command_runtime','mdm_identity_runtime','mdm_owner']::text[]),
 ('mdm_devices.advance_relation_revision()', 'plpgsql', 'trigger', true, false, 'v', ARRAY[]::text[], ARRAY['search_path=pg_catalog']::text[], $3::text, ARRAY['mdm_owner']::text[]),
 ('mdm_devices.capture_identity_watermark()', 'plpgsql', 'trigger', true, false, 'v', ARRAY[]::text[], ARRAY['search_path=pg_catalog']::text[], $4::text, ARRAY['mdm_owner']::text[]),
 ('mdm_devices.guard_object_evidence()', 'plpgsql', 'trigger', false, false, 'v', ARRAY[]::text[], ARRAY['search_path=pg_catalog']::text[], $5::text, ARRAY['mdm_owner']::text[]),
 ('mdm_devices.read_world(uuid[],text[],text[])', 'sql', 'jsonb', true, false, 's', ARRAY['p_associations','p_devices','p_fields']::text[], ARRAY['search_path=pg_catalog']::text[], $6::text, ARRAY['mdm_access','mdm_identity_runtime','mdm_owner']::text[])
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
UNION ALL
-- These writes invalidate or seal the evidence consumed by object_current.
SELECT required.name FROM (VALUES
 ('mdm_devices.associations','association_revision','mdm_devices.advance_relation_revision()',21),
 ('mdm_devices.members','association_member_revision','mdm_devices.advance_relation_revision()',21),
 ('mdm.asset_changes','device_identity_watermark','mdm_devices.capture_identity_watermark()',5),
 ('mdm_devices.object_cuts','immutable_object_cut','mdm_devices.guard_object_evidence()',27),
 ('mdm_devices.object_versions','immutable_object_evidence','mdm_devices.guard_object_evidence()',27)
) required(relation,name,function,events)
WHERE NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass(required.relation)
 AND t.tgname=required.name AND t.tgfoid=to_regprocedure(required.function)
 AND t.tgtype=required.events AND t.tgenabled IN('O','A') AND NOT t.tgisinternal
 AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector)
ORDER BY signature LIMIT 1
