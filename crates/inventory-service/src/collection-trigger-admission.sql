-- The producer's history and immutable metadata must run on every relevant write.
WITH required(name,function,events) AS (VALUES
 ('collection_history','mdm_access.capture_collection_history()',29),
 ('immutable_collection','mdm_access.immutable_collection()',19),
 ('capture_collection_metadata','mdm_access.capture_collection_metadata()',23)
)
SELECT NOT EXISTS(SELECT 1 FROM required r WHERE NOT EXISTS(
 SELECT 1 FROM pg_trigger t WHERE t.tgrelid='mdm_access.collection_runs'::regclass
 AND t.tgname=r.name AND t.tgfoid=to_regprocedure(r.function) AND t.tgtype=r.events
 AND t.tgenabled IN('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
 AND t.tgnargs=0 AND t.tgattr=''::int2vector))
