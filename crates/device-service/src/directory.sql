), page AS MATERIALIZED (
 SELECT * FROM objects WHERE $10::text IS NULL OR CASE WHEN $11 THEN object_key COLLATE "C"<$10 COLLATE "C" ELSE object_key COLLATE "C">$10 COLLATE "C" END
 ORDER BY CASE WHEN NOT $11 THEN object_key END COLLATE "C",CASE WHEN $11 THEN object_key END COLLATE "C" DESC LIMIT $12
), selected_objects AS MATERIALIZED (
 SELECT * FROM page ORDER BY CASE WHEN NOT $11 THEN object_key END COLLATE "C",CASE WHEN $11 THEN object_key END COLLATE "C" DESC LIMIT ($12-1)
), read_input AS (
 SELECT $13::text[] AS fields,(SELECT count(*) FROM page)>($12-1) AS more,
 (SELECT jsonb_build_object('rows',rows,'bytes',bytes,'ok',ok,'inputRows',(SELECT rows FROM source_budget)) FROM candidate_budget) AS budget
)
