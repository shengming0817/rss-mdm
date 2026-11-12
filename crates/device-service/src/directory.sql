), page AS MATERIALIZED (
 SELECT * FROM objects WHERE $10::smallint IS NULL OR CASE WHEN $12 THEN (object_kind,object_id)<($10,$11::uuid) ELSE (object_kind,object_id)>($10,$11::uuid) END
 ORDER BY CASE WHEN NOT $12 THEN object_kind END,CASE WHEN NOT $12 THEN object_id END,CASE WHEN $12 THEN object_kind END DESC,CASE WHEN $12 THEN object_id END DESC LIMIT $13
), selected_objects AS MATERIALIZED (
 SELECT * FROM page ORDER BY CASE WHEN NOT $12 THEN object_kind END,CASE WHEN NOT $12 THEN object_id END,CASE WHEN $12 THEN object_kind END DESC,CASE WHEN $12 THEN object_id END DESC LIMIT ($13-1)
), read_input AS (
 SELECT $14::text[] AS fields,(SELECT count(*) FROM page)>($13-1) AS more,
 (SELECT jsonb_build_object('rows',rows,'bytes',bytes,'ok',ok,'inputRows',(SELECT rows FROM source_budget)) FROM candidate_budget) AS budget
)
