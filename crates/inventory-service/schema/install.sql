-- Fresh installation: inventory-service owns these objects.
BEGIN;

SET LOCAL check_function_bodies = false;


CREATE SCHEMA mdm_assets;


CREATE SCHEMA mdm_inventory;


CREATE TABLE mdm_assets.asset_query_facets (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    kind text NOT NULL,
    label text NOT NULL COLLATE pg_catalog."C",
    total bigint NOT NULL,
    CONSTRAINT asset_query_facets_kind_check CHECK ((kind = ANY (ARRAY['os_versions'::text, 'channels'::text, 'asset_states'::text]))),
    CONSTRAINT asset_query_facets_label_check CHECK ((octet_length(label) <= 256)),
    CONSTRAINT asset_query_facets_total_check CHECK ((total > 0))
);


ALTER TABLE ONLY mdm_assets.asset_query_facets FORCE ROW LEVEL SECURITY;


CREATE TABLE mdm_assets.asset_query_results (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    sort_key bytea NOT NULL,
    document bytea NOT NULL,
    digest bytea NOT NULL,
    CONSTRAINT asset_query_results_device_check CHECK (((octet_length(device) >= 1) AND (octet_length(device) <= 256))),
    CONSTRAINT asset_query_results_digest_check CHECK ((octet_length(digest) = 32)),
    CONSTRAINT asset_query_results_document_check CHECK ((octet_length(document) <= 1048576)),
    CONSTRAINT asset_query_results_sort_key_check CHECK ((octet_length(sort_key) <= 1024))
);


ALTER TABLE ONLY mdm_assets.asset_query_results FORCE ROW LEVEL SECURITY;


CREATE TABLE mdm_assets.asset_query_runs (
    input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576),
    started boolean NOT NULL DEFAULT false,
    completed boolean NOT NULL DEFAULT false,
    failure text CONSTRAINT asset_query_failure_terminal CHECK(failure IS NULL OR completed),
    cursor text,
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    total bigint DEFAULT 0 NOT NULL,
    matched bigint DEFAULT 0 NOT NULL,
    unknown bigint DEFAULT 0 NOT NULL,
    CONSTRAINT asset_query_runs_check CHECK (((matched >= 0) AND (matched <= total))),
    CONSTRAINT asset_query_runs_check1 CHECK (((unknown >= 0) AND (unknown <= total))),
    CONSTRAINT asset_query_runs_total_check CHECK (((total >= 0) AND (total <= 1000000)))
);


ALTER TABLE ONLY mdm_assets.asset_query_runs FORCE ROW LEVEL SECURITY;


CREATE TABLE mdm_assets.field_layouts (
    tenant_id uuid NOT NULL,
    revision bigint NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT field_layouts_pkey PRIMARY KEY (tenant_id),
    CONSTRAINT field_layouts_revision_check CHECK (revision > 0),
    CONSTRAINT field_layouts_document_check CHECK (octet_length(document::text) <= 16384)
);

ALTER TABLE mdm_assets.field_layouts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.field_layouts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_assets.field_layouts
    USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);










CREATE TABLE mdm_assets.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    instance uuid NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);


ALTER TABLE ONLY mdm_assets.operations FORCE ROW LEVEL SECURITY;


CREATE TABLE mdm_assets.saved_queries (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    owner uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT saved_queries_document_check CHECK ((octet_length((document)::text) <= 16384)),
    CONSTRAINT saved_queries_revision_check CHECK ((revision > 0))
);


ALTER TABLE ONLY mdm_assets.saved_queries FORCE ROW LEVEL SECURITY;


CREATE TABLE mdm_inventory.collection_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    CONSTRAINT operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT operations_result_check CHECK ((length(result) <= 2048))
);


ALTER TABLE ONLY mdm_inventory.collection_operations FORCE ROW LEVEL SECURITY;


ALTER TABLE ONLY mdm_assets.asset_query_facets
    ADD CONSTRAINT asset_query_facets_pkey PRIMARY KEY (tenant_id, run, kind, label);


ALTER TABLE ONLY mdm_assets.asset_query_results
    ADD CONSTRAINT asset_query_results_pkey PRIMARY KEY (tenant_id, run, device);


ALTER TABLE ONLY mdm_assets.asset_query_runs
    ADD CONSTRAINT asset_query_runs_pkey PRIMARY KEY (tenant_id, id);






ALTER TABLE ONLY mdm_assets.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);


ALTER TABLE ONLY mdm_assets.saved_queries
    ADD CONSTRAINT saved_queries_pkey PRIMARY KEY (tenant_id, instance, owner, id);


ALTER TABLE ONLY mdm_inventory.collection_operations
    ADD CONSTRAINT collection_operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);


CREATE INDEX asset_query_results_order ON mdm_assets.asset_query_results USING btree (tenant_id, run, sort_key, device);


ALTER TABLE mdm_assets.asset_query_facets ENABLE ROW LEVEL SECURITY;


ALTER TABLE mdm_assets.asset_query_results ENABLE ROW LEVEL SECURITY;


ALTER TABLE mdm_assets.asset_query_runs ENABLE ROW LEVEL SECURITY;






ALTER TABLE mdm_assets.operations ENABLE ROW LEVEL SECURITY;


ALTER TABLE mdm_assets.saved_queries ENABLE ROW LEVEL SECURITY;


CREATE POLICY tenant ON mdm_assets.asset_query_facets USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));


CREATE POLICY tenant ON mdm_assets.asset_query_results USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));


CREATE POLICY tenant ON mdm_assets.asset_query_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));






CREATE POLICY tenant ON mdm_assets.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));


CREATE POLICY tenant ON mdm_assets.saved_queries USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));


ALTER TABLE mdm_inventory.collection_operations ENABLE ROW LEVEL SECURITY;


CREATE POLICY tenant ON mdm_inventory.collection_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

COMMIT;


CREATE TABLE mdm_assets.query_evaluations (
 tenant_id uuid NOT NULL,task uuid NOT NULL,binding text NOT NULL CHECK(binding ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,task),FOREIGN KEY(tenant_id,task) REFERENCES mdm_assets.asset_query_runs(tenant_id,id)
);

CREATE TABLE mdm_assets.query_evaluation_arrays (
 tenant_id uuid NOT NULL,task uuid NOT NULL,version text NOT NULL CHECK(version ~ '^[0-9a-f]{64}$'),
 state jsonb NOT NULL CHECK(octet_length(state::text)<=1048576),
 PRIMARY KEY(tenant_id,task,version),
 FOREIGN KEY(tenant_id,task) REFERENCES mdm_assets.query_evaluations(tenant_id,task) ON DELETE CASCADE
);

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['query_evaluations','query_evaluation_arrays'] LOOP
  EXECUTE format('ALTER TABLE mdm_assets.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_assets.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format($policy$CREATE POLICY tenant ON mdm_assets.%I USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)$policy$,t);
  EXECUTE format('REVOKE ALL ON mdm_assets.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_assets.%I TO mdm_inventory_runtime',t);
 END LOOP;
END $$;

GRANT UPDATE(binding) ON mdm_assets.query_evaluations TO mdm_inventory_runtime;

GRANT UPDATE(state) ON mdm_assets.query_evaluation_arrays TO mdm_inventory_runtime;

GRANT DELETE ON mdm_assets.query_evaluations,mdm_assets.query_evaluation_arrays TO mdm_inventory_runtime;