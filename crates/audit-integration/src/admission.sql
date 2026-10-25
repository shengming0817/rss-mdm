WITH reachable AS MATERIALIZED (
 SELECT oid FROM pg_roles WHERE pg_has_role(current_user,oid,'SET')
), relations AS MATERIALIZED (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_audit' AND c.relkind IN('r','p','v','m','f')
), constraints AS (
 SELECT r.relname||':'||lower(regexp_replace(pg_get_constraintdef(c.oid),'[[:space:]()]','','g')) AS shape,
 c.convalidated AND NOT c.condeferrable AS valid
 FROM pg_constraint c JOIN relations r ON r.oid=c.conrelid
)
SELECT
 (SELECT count(*)=2 AND bool_and(relkind='r' AND relpersistence='p' AND NOT relispartition AND NOT relhassubclass
 AND relname IN ('receipts','backlog') AND relrowsecurity AND relforcerowsecurity) FROM relations)
 AND has_schema_privilege(current_user,'mdm_audit','USAGE')
 AND NOT EXISTS(SELECT FROM reachable r WHERE has_schema_privilege(r.oid,'mdm_audit','CREATE'))
 AND NOT EXISTS(SELECT FROM relations c CROSS JOIN reachable r WHERE pg_has_role(r.oid,c.relowner,'USAGE')
 OR has_table_privilege(r.oid,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(r.oid,c.oid,'REFERENCES')
 OR (c.relname='receipts' AND (has_table_privilege(r.oid,c.oid,'UPDATE') OR has_any_column_privilege(r.oid,c.oid,'UPDATE'))))
 AND (SELECT bool_and(has_table_privilege(current_user,oid,'SELECT')
 AND (relname<>'backlog' OR (has_table_privilege(current_user,oid,'INSERT') AND has_table_privilege(current_user,oid,'UPDATE')))) FROM relations)
 AND (SELECT bool_and(has_column_privilege(current_user,r.oid,a.attnum,'INSERT')) FROM pg_attribute a JOIN relations r ON r.oid=a.attrelid
 WHERE r.relname='receipts' AND a.attnum>0 AND a.attname<>'projected_at')
 AND NOT EXISTS(SELECT FROM reachable r WHERE has_column_privilege(r.oid,'mdm_audit.receipts','projected_at','INSERT'))
 AND (SELECT array_agg(r.relname||':'||a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull::text ORDER BY r.relname,a.attnum)
 = ARRAY['backlog:tenant_id:uuid:true','backlog:source_id:text:true','backlog:events:bigint:true','backlog:bytes:bigint:true','backlog:reserved_events:bigint:true','backlog:reserved_bytes:bigint:true',
 'receipts:tenant_id:uuid:true','receipts:source_id:text:true','receipts:event_id:text:true','receipts:fingerprint:bytea:true','receipts:source_bytes:bytea:true','receipts:message_id:text:true','receipts:projected_at:bigint:false','receipts:reserved:boolean:true','receipts:enqueued_at:bigint:true']
 AND bool_and(NOT a.attisdropped AND a.attgenerated='' AND a.attidentity='' AND a.atthasdef=(r.relname='backlog' AND a.attname NOT IN ('tenant_id','source_id')))
 FROM pg_attribute a JOIN relations r ON r.oid=a.attrelid WHERE a.attnum>0)
 AND (SELECT count(*)=4 AND bool_and(pg_get_expr(d.adbin,d.adrelid)='0') FROM pg_attrdef d JOIN relations r ON r.oid=d.adrelid)
 AND (SELECT count(*)=2 AND bool_and(p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN relations r ON r.oid=p.polrelid)
 AND NOT EXISTS(SELECT FROM pg_trigger t JOIN relations r ON r.oid=t.tgrelid WHERE NOT t.tgisinternal)
 AND NOT EXISTS(SELECT FROM pg_rewrite w JOIN relations r ON r.oid=w.ev_class)
 AND NOT EXISTS(SELECT FROM relations r,LATERAL aclexplode(coalesce(r.relacl,acldefault('r',r.relowner))) a WHERE a.grantee=0 OR a.is_grantable)
 AND NOT EXISTS(SELECT FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a CROSS JOIN reachable r
 WHERE a.privilege_type='MAINTAIN' AND CASE WHEN a.grantee=0 THEN true ELSE pg_has_role(r.oid,a.grantee,'USAGE') END)
 AND NOT EXISTS(SELECT FROM pg_attribute c JOIN relations r ON r.oid=c.attrelid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR a.is_grantable)
 AND (SELECT bool_and(valid) AND array_agg(shape ORDER BY shape COLLATE "C") = ARRAY(
 SELECT shape FROM (VALUES
 ('backlog:primarykeytenant_id,source_id'),('backlog:checksource_id=anyarray[''mdm.business''::text,''mdm.request''::text]'),('backlog:checkevents>=0andbytes>=0andreserved_events>=0andreserved_bytes>=0'),
 ('receipts:primarykeytenant_id,source_id,event_id'),('receipts:checkoctet_lengthfingerprint=32'),
 ('receipts:checkoctet_lengthsource_bytes>=1andoctet_lengthsource_bytes<=262144'),
 ('receipts:checkoctet_lengthmessage_id>=1andoctet_lengthmessage_id<=255'),
 ('receipts:checkprojected_atisnullorprojected_at>=0'),('receipts:checkenqueued_at>=0')) expected(shape) ORDER BY shape COLLATE "C") FROM constraints)
 AND (SELECT count(*)=2 FROM pg_index i JOIN relations r ON r.oid=i.indrelid WHERE i.indisprimary AND i.indisvalid AND i.indisready AND i.indislive)
 AND EXISTS(SELECT FROM pg_index i JOIN relations r ON r.oid=i.indrelid WHERE r.relname='receipts'
 AND i.indisvalid AND i.indisready AND i.indislive AND i.indkey::text='1 2 9'
 AND lower(regexp_replace(pg_get_expr(i.indpred,i.indrelid),'[[:space:]()]','','g'))='projected_atisnull')
 AND NOT EXISTS(SELECT FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='mdm_audit' AND (a.grantee=0 OR a.is_grantable))
