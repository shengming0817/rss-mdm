CREATE VIEW mdm_user_profiles.device_fields WITH(security_barrier=true) AS
SELECT field_id,revision,collected_after_micros,value FROM mdm_user_profiles.definitions
 WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND value->'enabled'='true' AND value->'sensitive'='false'
 AND value->>'visibility' IN ('profiles_read','both') AND value->>'valueType' IN ('string','boolean','integer','number');
CREATE VIEW mdm_user_profiles.device_group_members WITH(security_barrier=true) AS
SELECT g.instance,(member->>'principalId')::uuid AS principal,g.id FROM mdm_access.user_groups g
 CROSS JOIN LATERAL jsonb_array_elements(g.document->'members') member
 WHERE g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.document->'enabled'='true'
 AND (member->>'tenantId')::uuid=g.tenant_id AND (member->>'instanceId')::uuid=g.instance;
GRANT USAGE ON SCHEMA mdm_user_profiles TO mdm_inventory_runtime;
GRANT SELECT ON mdm_user_profiles.device_fields,mdm_user_profiles.device_group_members TO mdm_inventory_runtime;
CREATE VIEW mdm_user_profiles.attributed_devices WITH(security_barrier=true) AS
 SELECT tenant_id,device FROM mdm_access.directory_users;
GRANT SELECT ON mdm_user_profiles.attributed_devices TO mdm_inventory_runtime;
