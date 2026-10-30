WITH execution_roles AS (SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')),
reachable AS (SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE')))
SELECT true
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_agent_packages.releases'::regclass
 AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
 AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_schema_privilege(r.oid,c.relnamespace,'CREATE')
 OR has_table_privilege(r.oid,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped) @> '[["tenant_id","uuid",true],["id","uuid",true],["document","jsonb",true],["binding","jsonb",true],["state","text",true],["platform","text",true],["architecture","text",true],["format","text",true],["product_version","text",true]]'::jsonb
 AND (SELECT count(*)=5 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'releases_business_key' THEN 'UNIQUE (tenant_id, platform, architecture, format, product_version)'
 WHEN 'releases_binding_check' THEN 'CHECK ((octet_length((binding)::text) <= 32768))'
 WHEN 'releases_document_check' THEN 'CHECK ((octet_length((document)::text) <= 32768))'
 WHEN 'releases_state_check' THEN 'CHECK ((state = ANY (ARRAY[''published''::text, ''withdrawn''::text])))'
 WHEN 'releases_pkey' THEN 'PRIMARY KEY (tenant_id, id)' ELSE '' END)
 FROM pg_constraint WHERE conrelid=c.oid
 AND conname IN('releases_business_key','releases_binding_check','releases_document_check','releases_state_check','releases_pkey'))
 AND (SELECT count(*)=4 AND bool_and(a.attgenerated='s' AND regexp_replace(pg_get_expr(d.adbin,d.adrelid),'[[:space:]()]','','g')=CASE a.attname
 WHEN 'platform' THEN 'document#>>''{target,platform}''::text[]'
 WHEN 'architecture' THEN 'document#>>''{target,architecture}''::text[]'
 WHEN 'format' THEN 'document->>''format''::text'
 WHEN 'product_version' THEN 'document->>''version''::text' ELSE '' END)
 FROM pg_attribute a JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum)
 WHERE a.attrelid=c.oid AND a.attname IN('platform','architecture','format','product_version'))
 -- Only the required identity constraints depend on usable unique indexes.
 AND NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=c.oid
 AND indexrelid IN(SELECT conindid FROM pg_constraint WHERE conrelid=c.oid AND conname IN('releases_business_key','releases_pkey'))
 AND (NOT indisunique OR NOT indisvalid OR NOT indisready OR NOT indislive OR NOT indimmediate))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname='state')
 OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,c.oid,a.attnum,'REFERENCES')
 OR (has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE') AND a.attname<>'state'))))
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col,LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))))

