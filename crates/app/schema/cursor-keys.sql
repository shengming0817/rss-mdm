-- Host-owned tenant cursor material; current installation only.
BEGIN;
CREATE TABLE public.mdm_cursor_keys (
    tenant_id uuid NOT NULL,
    secret bytea NOT NULL,
    CONSTRAINT cursor_keys_secret_check CHECK ((octet_length(secret) = 32))
);
ALTER TABLE ONLY public.mdm_cursor_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.mdm_cursor_keys
    ADD CONSTRAINT cursor_keys_pkey PRIMARY KEY (tenant_id);
ALTER TABLE public.mdm_cursor_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON public.mdm_cursor_keys USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
REVOKE ALL ON public.mdm_cursor_keys FROM PUBLIC;
GRANT SELECT,INSERT ON public.mdm_cursor_keys TO mdm_access;
COMMIT;
