), page AS MATERIALIZED (
 SELECT * FROM objects WHERE $10::smallint IS NULL OR
 CASE WHEN $14 THEN
   CASE WHEN $13 THEN object_id<$11::uuid ELSE object_id>$11::uuid END
   OR object_id=$11::uuid AND CASE WHEN $12 THEN object_kind<$10 ELSE object_kind>$10 END
 ELSE
   CASE WHEN $12 THEN object_kind<$10 ELSE object_kind>$10 END
   OR object_kind=$10 AND CASE WHEN $13 THEN object_id<$11::uuid ELSE object_id>$11::uuid END
 END
 ORDER BY
   CASE WHEN $14 AND NOT $13 THEN object_id END,
   CASE WHEN $14 AND $13 THEN object_id END DESC,
   CASE WHEN NOT $12 THEN object_kind END,
   CASE WHEN $12 THEN object_kind END DESC,
   CASE WHEN NOT $14 AND NOT $13 THEN object_id END,
   CASE WHEN NOT $14 AND $13 THEN object_id END DESC
 LIMIT $15
), selected_objects AS MATERIALIZED (
 SELECT * FROM page ORDER BY
   CASE WHEN $14 AND NOT $13 THEN object_id END,
   CASE WHEN $14 AND $13 THEN object_id END DESC,
   CASE WHEN NOT $12 THEN object_kind END,
   CASE WHEN $12 THEN object_kind END DESC,
   CASE WHEN NOT $14 AND NOT $13 THEN object_id END,
   CASE WHEN NOT $14 AND $13 THEN object_id END DESC
 LIMIT ($15-1)
), read_input AS (
 SELECT $16::text[] AS fields,(SELECT count(*) FROM page)>($15-1) AS more,
 (SELECT jsonb_build_object('rows',rows,'bytes',bytes,'ok',ok,'inputRows',(SELECT rows FROM source_budget)) FROM candidate_budget) AS budget
)
