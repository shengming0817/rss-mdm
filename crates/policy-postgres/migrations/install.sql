BEGIN;
CREATE SCHEMA mdm_policy;
REVOKE ALL ON SCHEMA mdm_policy FROM PUBLIC;
CREATE TABLE mdm_policy.policies (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 current_version uuid NOT NULL, version_number bigint NOT NULL CHECK(version_number>0),
 execution_binding bytea CHECK(execution_binding IS NULL OR octet_length(execution_binding)=32),
 state text NOT NULL CHECK(state IN ('enabled','disabled','archived')), definition jsonb NOT NULL CHECK(octet_length(definition::text)<=4194304),
 CHECK(definition->'action'->>'kind'<>'software' OR coalesce(definition->'action'->>'channel' IN ('agent','mdm'),false)),
 author jsonb NOT NULL, updated_at bigint NOT NULL CHECK(updated_at>=0), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_policy.versions (
 tenant_id uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,number bigint NOT NULL CHECK(number>0),
 action_kind text NOT NULL CHECK(action_kind IN ('device_access','credential','execution','agent_collection','telemetry_profile','native_collection','configuration','software','ensure_agent_installed','request_mdm_enrollment','unmanage_device')),
 resource text,resource_version text,
 CHECK((resource IS NULL) = (resource_version IS NULL)),
 CHECK((action_kind IN ('device_access','credential','ensure_agent_installed','request_mdm_enrollment','unmanage_device')) = (resource IS NULL)),
 frozen jsonb NOT NULL CHECK(octet_length(frozen::text)<=25165824),
 CHECK(action_kind<>'software' OR coalesce(frozen->'action'->>'channel' IN ('agent','mdm'),false)),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,policy,number),
 FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id)
);
ALTER TABLE mdm_policy.policies ADD FOREIGN KEY(tenant_id,current_version) REFERENCES mdm_policy.versions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX policy_alias_unique ON mdm_policy.policies(tenant_id, (definition->>'alias')) WHERE state<>'archived' AND definition->>'alias' IS NOT NULL;
CREATE INDEX policy_custom_event ON mdm_policy.policies(tenant_id, (definition->>'customEvent'), id) WHERE state<>'archived' AND definition->>'customEvent' IS NOT NULL;
CREATE INDEX policy_scope ON mdm_policy.policies(tenant_id,((definition->>'scope')::uuid),id);
CREATE TABLE mdm_policy.triggers (
 tenant_id uuid NOT NULL,id uuid NOT NULL,version uuid NOT NULL,created_at bigint NOT NULL,deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id)
);
CREATE INDEX policy_triggers_due ON mdm_policy.triggers(tenant_id,version,deadline,created_at,id);

CREATE TABLE mdm_policy.requests (
 tenant_id uuid NOT NULL,id uuid NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),receipt jsonb NOT NULL CHECK(octet_length(receipt::text)<=16777216),PRIMARY KEY(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['policies','versions','triggers','requests'] LOOP
 EXECUTE format('ALTER TABLE mdm_policy.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_policy.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_policy.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('GRANT SELECT,INSERT ON mdm_policy.%I TO mdm_policy_runtime',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_policy TO mdm_policy_runtime;
GRANT UPDATE(revision,current_version,version_number,state,definition,author,updated_at,execution_binding) ON mdm_policy.policies TO mdm_policy_runtime;
-- Policy application data; installation only, never runtime DDL.
CREATE FUNCTION mdm_policy.lock_policy(p_policy uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT FROM mdm_policy.policies WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_policy FOR SHARE;
$$;
REVOKE ALL ON FUNCTION mdm_policy.lock_policy(uuid) FROM PUBLIC;
CREATE TABLE mdm_policy.work (
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
    CONSTRAINT policy_work_authority_revision_check CHECK ((authority_revision >= 0)),
    CONSTRAINT policy_work_failure_check CHECK ((failure = ANY (ARRAY['superseded'::text, 'capacity_exceeded'::text, 'source_unavailable'::text, 'invalid_input'::text, 'storage_invariant'::text, 'automation_suspended'::text, 'configuration_target_limit'::text, 'capability_unknown'::text, 'platform_unsupported'::text, 'stale_plan'::text, 'owner_conflict'::text, 'permission_denied'::text]))),
    CONSTRAINT policy_work_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT policy_work_kind_check CHECK ((kind = ANY (ARRAY['policy_scope'::text, 'policy_reconcile'::text, 'policy_event'::text]))),
    CONSTRAINT policy_work_target_check CHECK (((octet_length(target) >= 1) AND (octet_length(target) <= 256)))
);

ALTER TABLE ONLY mdm_policy.work FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_policy.work
    ADD CONSTRAINT policy_work_pkey PRIMARY KEY (tenant_id, id);

CREATE INDEX policy_work_pending ON mdm_policy.work USING btree (tenant_id, id) WHERE (NOT forwarded);

ALTER TABLE mdm_policy.work ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_policy.work USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE TABLE mdm_policy.event_batches (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request uuid NOT NULL, actor text NOT NULL,
 caller jsonb NOT NULL, device text NOT NULL, input jsonb NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 created_at bigint NOT NULL, deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,actor,request)
);

CREATE TABLE mdm_policy.event_members (
 tenant_id uuid NOT NULL,batch uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,
 revision bigint NOT NULL,version uuid NOT NULL,target jsonb NOT NULL,authority jsonb NOT NULL,decision jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,batch,policy),
 FOREIGN KEY(tenant_id,batch) REFERENCES mdm_policy.event_batches(tenant_id,id)
);

CREATE INDEX event_members_pending ON mdm_policy.event_members(tenant_id,batch,id) WHERE decision->>'state'='pending';

CREATE INDEX event_batches_device ON mdm_policy.event_batches(tenant_id,device,id);

ALTER TABLE mdm_policy.event_batches ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_policy.event_batches FORCE ROW LEVEL SECURITY;

ALTER TABLE mdm_policy.event_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_policy.event_members FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_policy.event_batches USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY tenant ON mdm_policy.event_members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);




CREATE TABLE mdm_policy.assignments (
 tenant_id uuid NOT NULL, policy uuid NOT NULL, version uuid NOT NULL,
 entry_revision bigint NOT NULL CHECK(entry_revision>=0),
 object text COLLATE "C" NOT NULL, channel text NOT NULL CHECK(channel IN('agent','mdm')),
 input jsonb NOT NULL, availability text NOT NULL CHECK(availability IN('ready','unavailable')),
 reason text, target jsonb, scope_result uuid NOT NULL,
 PRIMARY KEY(tenant_id,policy,version,object,channel),
 FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id),
 CHECK((availability='ready')=(reason IS NULL)), CHECK(availability<>'ready' OR target IS NOT NULL)
);
ALTER TABLE mdm_policy.assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_policy.assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_policy.assignments USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_policy.assignments,mdm_policy.work,mdm_policy.event_batches,mdm_policy.event_members TO mdm_policy_runtime;
GRANT UPDATE(input,availability,reason,target,scope_result,entry_revision) ON mdm_policy.assignments TO mdm_policy_runtime;
GRANT UPDATE(forwarded,completed,cursor,replacement_task,authority_revision,failure,failure_detail) ON mdm_policy.work TO mdm_policy_runtime;
GRANT UPDATE(decision) ON mdm_policy.event_members TO mdm_policy_runtime;

COMMIT;
