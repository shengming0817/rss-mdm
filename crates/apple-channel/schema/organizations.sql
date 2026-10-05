-- Current Apple organization identity is independent of enrollment protocol configuration.
BEGIN;
CREATE TABLE mdm_apple.organizations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, PRIMARY KEY(tenant_id,id), CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid)
);
ALTER TABLE mdm_apple.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.organizations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_apple.organizations TO mdm_access;
INSERT INTO mdm_apple.organizations SELECT tenant_id,id FROM mdm_apple.account_organizations;
ALTER TABLE mdm_apple.account_organizations RENAME TO account_configuration;
ALTER TABLE mdm_apple.account_configuration ADD FOREIGN KEY(tenant_id,id) REFERENCES mdm_apple.organizations(tenant_id,id);
CREATE OR REPLACE FUNCTION mdm_apple.account_current(p_tenant uuid,p_enrollment uuid,p_version bigint,p_flow uuid,p_hash text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog' AS $$
DECLARE organization uuid;
BEGIN
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT f.organization INTO organization FROM mdm_apple.account_flows f
 WHERE f.tenant_id=p_tenant AND f.enrollment=p_enrollment AND NOT f.revoked ORDER BY f.authorization_version DESC LIMIT 1;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM o.id FROM mdm_apple.account_configuration o WHERE o.tenant_id=p_tenant AND o.id=organization FOR SHARE;
 PERFORM f.id FROM mdm_apple.account_flows f WHERE f.tenant_id=p_tenant AND f.enrollment=p_enrollment AND NOT f.revoked FOR UPDATE;
 PERFORM f.id FROM mdm_apple.account_flows f
 JOIN mdm_apple.account_configuration o ON(o.tenant_id,o.id,o.revision)=(f.tenant_id,f.organization,f.organization_revision)
 JOIN mdm_apple.account_bindings b ON(b.tenant_id,b.organization,b.account,b.revision)=(f.tenant_id,f.organization,f.account,f.binding_revision)
 JOIN mdm_access.requests q ON(q.tenant_id,q.id,q.account_version)=(f.tenant_id,f.enrollment,f.authorization_version)
 JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
 WHERE f.tenant_id=p_tenant AND f.enrollment=p_enrollment AND f.authorization_version=p_version
 AND (p_flow IS NULL OR f.id=p_flow) AND (p_hash IS NULL OR f.token_hash=p_hash)
 AND NOT f.revoked AND o.enabled AND b.enabled AND b.principal::text=g.actor AND b.instance::text=g.instance
 AND q.authority_kind='apple_account' AND q.state<>'cancelled'
 AND (q.state='pending' OR EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.state='active'))
 FOR SHARE OF f,o,b,q;
 RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION mdm_apple.account_current(uuid,uuid,bigint,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_apple.account_current(uuid,uuid,bigint,uuid,text) TO mdm_access,mdm_command_runtime;
COMMIT;
