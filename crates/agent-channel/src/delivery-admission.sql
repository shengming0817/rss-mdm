WITH expected(name) AS (VALUES ('mdm_agent.task_attempts'),('mdm_agent.task_receipts'),('mdm_agent.task_polls')), tables AS (SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name))
SELECT (SELECT count(*) FROM tables)=3 AND NOT EXISTS(
 SELECT FROM tables t WHERE t.relkind<>'r' OR t.relpersistence<>'p' OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR t.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1
 OR EXISTS(SELECT FROM pg_trigger WHERE tgrelid=t.oid AND NOT tgisinternal)
 OR EXISTS(SELECT FROM pg_rewrite WHERE ev_class=t.oid)
)

 AND (SELECT count(*) FROM pg_attribute WHERE attrelid='mdm_agent.task_attempts'::regclass AND attname='deadline' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped)=1
 AND (SELECT count(*) FROM pg_attribute WHERE attrelid='mdm_agent.task_polls'::regclass AND NOT attnotnull AND NOT attisdropped AND ((attname='offer_after_at' AND atttypid='bigint'::regtype) OR (attname='offer_after_id' AND atttypid='uuid'::regtype)))=2
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='mdm_agent.task_polls'::regclass AND contype='c' AND convalidated AND lower(regexp_replace(pg_get_expr(conbin,conrelid),'[[:space:]()]','','g'))='offer_after_atisnull=offer_after_idisnull')
