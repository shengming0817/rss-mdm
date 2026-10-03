BEGIN;
CREATE SCHEMA mdm_certificate_archive;
REVOKE ALL ON SCHEMA mdm_certificate_archive FROM PUBLIC;
CREATE TABLE mdm_certificate_archive.vaults (
 tenant_id uuid PRIMARY KEY, generation bigint NOT NULL CHECK(generation>0),
 salt bytea NOT NULL CHECK(octet_length(salt)=16), wrapped_key bytea NOT NULL CHECK(octet_length(wrapped_key)=100),
 kdf text NOT NULL CHECK(kdf='argon2id-v19-m65536-t3-p1'),
 updated_at bigint NOT NULL
);
CREATE TABLE mdm_certificate_archive.entries (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 retired boolean NOT NULL DEFAULT false, recommended_version bigint,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id) REFERENCES mdm_certificate_archive.vaults(tenant_id)
);
CREATE TABLE mdm_certificate_archive.versions (
 tenant_id uuid NOT NULL, entry_id uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 actor uuid NOT NULL, instance uuid NOT NULL, operation_id uuid NOT NULL, created_at bigint NOT NULL,
 metadata jsonb NOT NULL CHECK(octet_length(metadata::text)<=16384),
 facts jsonb NOT NULL CHECK(octet_length(facts::text)<=262144),
 sealed bytea NOT NULL CHECK(octet_length(sealed)<=3145728), source text NOT NULL CHECK(source IN ('import','generate','metadata')),
 request_entry_id uuid, request_version bigint CHECK(request_version>0),
 CHECK((request_entry_id IS NULL)=(request_version IS NULL)),
 PRIMARY KEY(tenant_id,entry_id,version), FOREIGN KEY(tenant_id,entry_id) REFERENCES mdm_certificate_archive.entries(tenant_id,id),
 FOREIGN KEY(tenant_id,request_entry_id,request_version) REFERENCES mdm_certificate_archive.versions(tenant_id,entry_id,version)
);
CREATE TABLE mdm_certificate_archive.operations (
 tenant_id uuid NOT NULL, actor uuid NOT NULL, instance uuid NOT NULL, id uuid NOT NULL,
 action text NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32),
 result jsonb NOT NULL CHECK(octet_length(result::text)<=16384), created_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,actor,instance,id)
);
CREATE TABLE mdm_certificate_archive.settings (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0), document jsonb NOT NULL CHECK(octet_length(document::text)<=16384)
);
ALTER TABLE mdm_certificate_archive.vaults ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.vaults FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.entries FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.versions FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.operations FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_certificate_archive.settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_certificate_archive.vaults USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_certificate_archive.entries USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_certificate_archive.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_certificate_archive.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_certificate_archive.settings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_certificate_archive FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_certificate_archive TO mdm_access;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_certificate_archive TO mdm_access;
GRANT UPDATE(generation,salt,wrapped_key,kdf,updated_at) ON mdm_certificate_archive.vaults TO mdm_access;
GRANT UPDATE(revision,retired,recommended_version) ON mdm_certificate_archive.entries TO mdm_access;
GRANT UPDATE(revision,document) ON mdm_certificate_archive.settings TO mdm_access;
COMMIT;
