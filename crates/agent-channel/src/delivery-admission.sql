WITH expected(name) AS (VALUES ('mdm_agent.task_attempts'),('mdm_agent.task_receipts'),('mdm_agent.task_polls')), tables AS (SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name))
SELECT (SELECT count(*) FROM tables)=3 AND NOT EXISTS(
 SELECT FROM tables t WHERE t.relkind<>'r' OR t.relpersistence<>'p' OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR t.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1
 OR EXISTS(SELECT FROM pg_trigger WHERE tgrelid=t.oid AND NOT tgisinternal)
 OR EXISTS(SELECT FROM pg_rewrite WHERE ev_class=t.oid)
)
