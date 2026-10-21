WITH tables AS (SELECT c.oid,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_planning' AND c.relkind='r')
SELECT jsonb_build_object(
 'groupCurrent',(SELECT pg_get_functiondef('mdm_planning.group_current(uuid)'::regprocedure)),
 'policyLock',(SELECT pg_get_functiondef('mdm_planning.policy_lock(uuid)'::regprocedure)),
 'scopeAdmission',(SELECT pg_get_functiondef('mdm_planning.scope_admission(uuid,text)'::regprocedure)),
 'channelGuard',(SELECT pg_get_functiondef('mdm_planning.guard_scope_channel_result()'::regprocedure)),
 'channelGuardTrigger',(SELECT jsonb_build_array(tgenabled,pg_get_triggerdef(oid)) FROM pg_trigger WHERE tgrelid='mdm_planning.scope_channel_results'::regclass AND tgname='scope_channel_result_guard'),
 'columns', (SELECT jsonb_agg(jsonb_build_array(t.relname,a.attname,
   format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),
   a.attidentity,a.attgenerated) ORDER BY t.relname COLLATE "C",a.attnum)
 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped),
 'constraints', (SELECT jsonb_agg(jsonb_build_array(t.relname,c.conname,c.contype,
   CASE WHEN c.contype='f' THEN replace(pg_get_constraintdef(c.oid),'REFERENCES '||c.confrelid::regclass::text,'REFERENCES '||(SELECT format('%I.%I',n.nspname,r.relname) FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace WHERE r.oid=c.confrelid)) ELSE pg_get_constraintdef(c.oid) END,c.convalidated) ORDER BY t.relname COLLATE "C",c.conname COLLATE "C")
 FROM tables t JOIN pg_constraint c ON c.conrelid=t.oid),
 'indexes', (SELECT jsonb_agg(jsonb_build_array(t.relname,c.relname,pg_get_indexdef(i.indexrelid),
   i.indisvalid,i.indisready,i.indislive) ORDER BY t.relname COLLATE "C",c.relname COLLATE "C")
 FROM tables t JOIN pg_index i ON i.indrelid=t.oid JOIN pg_class c ON c.oid=i.indexrelid)
)::text
