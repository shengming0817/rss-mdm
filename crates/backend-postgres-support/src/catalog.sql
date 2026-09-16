-- PostgreSQL catalog projection; no OIDs, owners or locale-sensitive order.
WITH tables AS (
 SELECT c.oid,c.relname FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1::text AND c.relkind='r'
)
SELECT jsonb_build_object(
 'columns', (SELECT jsonb_agg(jsonb_build_array(t.relname,a.attname,
   format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),
   a.attidentity,a.attgenerated) ORDER BY t.relname COLLATE "C",a.attnum)
 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped),
 'constraints', (SELECT jsonb_agg(jsonb_build_array(t.relname,c.conname,c.contype,
   pg_get_constraintdef(c.oid),c.convalidated) ORDER BY t.relname COLLATE "C",c.conname COLLATE "C")
 FROM tables t JOIN pg_constraint c ON c.conrelid=t.oid),
 'indexes', (SELECT jsonb_agg(jsonb_build_array(t.relname,c.relname,pg_get_indexdef(i.indexrelid),
   i.indisvalid,i.indisready,i.indislive) ORDER BY t.relname COLLATE "C",c.relname COLLATE "C")
 FROM tables t JOIN pg_index i ON i.indrelid=t.oid JOIN pg_class c ON c.oid=i.indexrelid)
)::text
