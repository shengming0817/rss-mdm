-- Fresh installation: inventory-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_assets;

CREATE SCHEMA mdm_inventory;

CREATE FUNCTION mdm_access.capture_collection_history() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'mdm_access'
    AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 t=(r->>'tenant_id')::uuid;
 v=mdm.record_asset_change(t,'collection',jsonb_build_object('run',r->>'id'),ARRAY[]::text[]);
 IF TG_OP<>'DELETE' THEN
  d=jsonb_build_object('id',r->>'id','result',r->>'result','attempts',r->>'attempts','delivery_pending',r->'delivery_pending');
 END IF;
 INSERT INTO mdm_access.collection_history VALUES(t,(r->>'id')::uuid,r->>'scope',(r->>'sequence')::bigint,v,d);
 RETURN NULL;
END $$;

CREATE FUNCTION mdm_access.immutable_collection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF OLD.sealed_at IS NOT NULL AND (to_jsonb(OLD)-'delivery_pending') IS DISTINCT FROM (to_jsonb(NEW)-'delivery_pending') THEN
  RAISE EXCEPTION 'sealed collection is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION mdm_access.prune_agent_collections(p_registration uuid, p_epoch uuid) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE removed bigint;
BEGIN
 DELETE FROM mdm_access.collection_runs r
 WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND r.registration=p_registration AND r.source='agent.builtin' AND r.epoch=p_epoch
   AND NOT r.delivery_pending AND r.id IN (
    SELECT id FROM mdm_access.collection_runs
    WHERE tenant_id=r.tenant_id AND registration=p_registration
      AND source='agent.builtin' AND epoch=p_epoch AND NOT delivery_pending
    ORDER BY sealed_at DESC,id DESC OFFSET 224
   );
 GET DIAGNOSTICS removed = ROW_COUNT;
 RETURN removed;
END $$;

CREATE TABLE mdm_access.collection_history (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    scope text NOT NULL,
    sequence bigint NOT NULL,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT collection_history_document_check CHECK (((document IS NULL) OR (octet_length((document)::text) <= 16384)))
);

ALTER TABLE ONLY mdm_access.collection_history FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.collection_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    registration uuid NOT NULL,
    source text NOT NULL,
    epoch uuid NOT NULL,
    scope text NOT NULL,
    sequence bigint NOT NULL,
    started_at bigint NOT NULL,
    attempts text NOT NULL,
    result text NOT NULL,
    reason text,
    batch bytea,
    digest text,
    sealed_at bigint,
    delivery_pending boolean DEFAULT false NOT NULL,
    apple_approval jsonb,
    apple_deadline timestamp with time zone,
    CONSTRAINT collection_runs_attempts_check CHECK ((octet_length(attempts) <= 8192)),
    CONSTRAINT collection_runs_batch_check CHECK (((octet_length(batch) >= 1) AND (octet_length(batch) <= 8192))),
    CONSTRAINT collection_runs_check CHECK (((result = 'pending'::text) = (sealed_at IS NULL))),
    CONSTRAINT collection_runs_check1 CHECK (((sealed_at IS NULL) = (reason IS NULL))),
    CONSTRAINT collection_runs_check2 CHECK (((batch IS NULL) = (digest IS NULL))),
    CONSTRAINT collection_runs_check3 CHECK (((NOT delivery_pending) OR (batch IS NOT NULL))),
    CONSTRAINT collection_runs_check4 CHECK (((batch IS NULL) OR (sealed_at IS NOT NULL))),
    CONSTRAINT collection_runs_digest_check CHECK ((digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT collection_runs_reason_check CHECK ((reason = ANY (ARRAY['complete'::text, 'message_budget'::text, 'timeout'::text, 'superseded'::text, 'revoked'::text]))),
    CONSTRAINT collection_runs_result_check CHECK ((result = ANY (ARRAY['pending'::text, 'snapshot'::text, 'partial'::text, 'failed'::text]))),
    CONSTRAINT collection_runs_scope_check CHECK ((octet_length(scope) <= 4096)),
    CONSTRAINT collection_runs_sequence_check CHECK ((sequence >= 0)),
    CONSTRAINT collection_runs_started_at_check CHECK ((started_at >= 0)),
    CONSTRAINT collection_source_profile CHECK ((((source = 'mdm.windows'::text) AND (apple_approval IS NULL) AND (apple_deadline IS NULL)) OR ((source = ANY (ARRAY['agent.builtin'::text, 'agent.script'::text, 'agent.osquery'::text])) AND (sealed_at IS NOT NULL) AND (result <> 'pending'::text) AND (reason = 'complete'::text) AND (batch IS NOT NULL) AND (apple_approval IS NULL) AND (apple_deadline IS NULL)) OR ((source = 'mdm.apple'::text) AND (apple_approval IS NOT NULL) AND (apple_deadline IS NOT NULL))))
);

ALTER TABLE ONLY mdm_access.collection_runs FORCE ROW LEVEL SECURITY;

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

CREATE TABLE mdm_assets.group_fields (
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    field text NOT NULL
);

ALTER TABLE ONLY mdm_assets.group_fields FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_assets.group_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    CONSTRAINT group_operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT group_operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY mdm_assets.group_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_assets.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
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

ALTER TABLE ONLY mdm_access.collection_history
    ADD CONSTRAINT collection_history_pkey PRIMARY KEY (tenant_id, run, revision);

ALTER TABLE ONLY mdm_access.collection_runs
    ADD CONSTRAINT collection_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_assets.asset_query_facets
    ADD CONSTRAINT asset_query_facets_pkey PRIMARY KEY (tenant_id, run, kind, label);

ALTER TABLE ONLY mdm_assets.asset_query_results
    ADD CONSTRAINT asset_query_results_pkey PRIMARY KEY (tenant_id, run, device);

ALTER TABLE ONLY mdm_assets.asset_query_runs
    ADD CONSTRAINT asset_query_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_assets.group_fields
    ADD CONSTRAINT group_fields_pkey PRIMARY KEY (tenant_id, group_id, field);

ALTER TABLE ONLY mdm_assets.group_operations
    ADD CONSTRAINT group_operations_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_assets.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_assets.saved_queries
    ADD CONSTRAINT saved_queries_pkey PRIMARY KEY (tenant_id, instance, owner, id);

ALTER TABLE ONLY mdm_inventory.collection_operations
    ADD CONSTRAINT collection_operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);

CREATE INDEX collection_agent_retention ON mdm_access.collection_runs USING btree (tenant_id, registration, source, epoch, sealed_at DESC, id DESC) WHERE ((source = 'agent.builtin'::text) AND (NOT delivery_pending));

CREATE INDEX collection_apple_pending ON mdm_access.collection_runs USING btree (tenant_id, apple_deadline, id) WHERE ((source = 'mdm.apple'::text) AND (sealed_at IS NULL));

CREATE UNIQUE INDEX collection_apple_sequence ON mdm_access.collection_runs USING btree (tenant_id, registration, source, epoch, sequence) WHERE (source = 'mdm.apple'::text);

CREATE INDEX collection_delivery ON mdm_access.collection_runs USING btree (tenant_id, registration, source, epoch, sequence) WHERE delivery_pending;

CREATE UNIQUE INDEX collection_enterprise_sequence ON mdm_access.collection_runs USING btree (tenant_id, registration, source, epoch, sequence) WHERE (source = ANY (ARRAY['agent.script'::text, 'agent.osquery'::text]));

CREATE INDEX collection_history_scope ON mdm_access.collection_history USING btree (tenant_id, scope, run, revision DESC);

CREATE INDEX collection_latest ON mdm_access.collection_runs USING btree (tenant_id, registration, source, epoch, sequence DESC);

CREATE UNIQUE INDEX collection_windows_sequence ON mdm_access.collection_runs USING btree (tenant_id, registration, source, epoch, sequence) WHERE (source = 'mdm.windows'::text);

CREATE INDEX asset_query_results_order ON mdm_assets.asset_query_results USING btree (tenant_id, run, sort_key, device);

CREATE INDEX group_fields_field ON mdm_assets.group_fields USING btree (tenant_id, field, group_id);

ALTER TABLE mdm_access.collection_history ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.collection_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_access.collection_history USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.collection_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_assets.asset_query_facets ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.asset_query_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.asset_query_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.group_fields ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.group_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.saved_queries ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_assets.asset_query_facets USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.asset_query_results USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.asset_query_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.group_fields USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.group_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.saved_queries USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_inventory.collection_operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_inventory.collection_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
COMMIT;
