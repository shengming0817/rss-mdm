-- Fresh installation: flow owns these objects.
BEGIN;

SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_automation;

CREATE SCHEMA mdm_flow;

CREATE SCHEMA mdm_planning;

CREATE SCHEMA mdm_publication;



CREATE FUNCTION mdm_planning.policy_lock(p_policy uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT FROM mdm_policy.policies WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_policy FOR SHARE;
$$;

CREATE TABLE mdm_automation.automation_jobs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    kind text NOT NULL,
    target text NOT NULL,
    input jsonb NOT NULL,
    forwarded boolean DEFAULT false NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    cursor text,
    replacement_task uuid,
    authority_revision bigint DEFAULT 0 NOT NULL,
    failure text,
    failure_detail jsonb,
    CONSTRAINT automation_jobs_authority_revision_check CHECK ((authority_revision >= 0)),
    CONSTRAINT automation_jobs_failure_check CHECK ((failure = ANY (ARRAY['superseded'::text, 'capacity_exceeded'::text, 'source_unavailable'::text, 'invalid_input'::text, 'storage_invariant'::text, 'automation_suspended'::text, 'configuration_target_limit'::text, 'capability_unknown'::text, 'platform_unsupported'::text, 'stale_plan'::text, 'owner_conflict'::text, 'permission_denied'::text]))),
    CONSTRAINT automation_jobs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT automation_jobs_kind_check CHECK ((kind = ANY (ARRAY['policy_scope'::text, 'policy_reconcile'::text, 'policy_event'::text]))),
    CONSTRAINT automation_jobs_target_check CHECK (((octet_length(target) >= 1) AND (octet_length(target) <= 256)))
);

ALTER TABLE ONLY mdm_automation.automation_jobs FORCE ROW LEVEL SECURITY;








CREATE TABLE mdm_publication.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY mdm_publication.operations FORCE ROW LEVEL SECURITY;





ALTER TABLE ONLY mdm_automation.automation_jobs
    ADD CONSTRAINT automation_jobs_pkey PRIMARY KEY (tenant_id, id);




ALTER TABLE ONLY mdm_publication.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);



CREATE INDEX automation_jobs_pending ON mdm_automation.automation_jobs USING btree (tenant_id, id) WHERE (NOT forwarded);

ALTER TABLE mdm_automation.automation_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_automation.automation_jobs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));







ALTER TABLE mdm_publication.operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_publication.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));





CREATE TABLE mdm_planning.event_batches (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request uuid NOT NULL, actor text NOT NULL,
 caller jsonb NOT NULL, device text NOT NULL, input jsonb NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 created_at bigint NOT NULL, deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,actor,request)
);

CREATE TABLE mdm_planning.event_members (
 tenant_id uuid NOT NULL,batch uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,
 revision bigint NOT NULL,version uuid NOT NULL,target jsonb NOT NULL,authority jsonb NOT NULL,decision jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,batch,policy),
 FOREIGN KEY(tenant_id,batch) REFERENCES mdm_planning.event_batches(tenant_id,id)
);

CREATE INDEX event_members_pending ON mdm_planning.event_members(tenant_id,batch,id) WHERE decision->>'state'='pending';

CREATE INDEX event_batches_device ON mdm_planning.event_batches(tenant_id,device,id);

ALTER TABLE mdm_planning.event_batches ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.event_batches FORCE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.event_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.event_members FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_planning.event_batches USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY tenant ON mdm_planning.event_members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

GRANT SELECT,INSERT ON mdm_planning.event_batches TO mdm_flow_runtime,mdm_command_runtime;

GRANT SELECT,INSERT ON mdm_planning.event_members TO mdm_flow_runtime;

GRANT INSERT ON mdm_planning.event_members TO mdm_command_runtime;

COMMIT;
