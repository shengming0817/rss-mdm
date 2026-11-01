//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub install: &'static str,
    pub admission: &'static str,
    pub insert: &'static str,
    pub read: &'static str,
    pub object_manifest: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $schema:literal, $table:literal, $command:literal, $policy:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                install: concat!("CREATE SCHEMA IF NOT EXISTS ", $schema, r###";
CREATE TABLE "###, $table, r###" (
    tenant_id uuid PRIMARY KEY,
    key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$')
);

ALTER TABLE "###, $table, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $table, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $table, r###" USING (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $table, " TO ", $command, ",", $policy, r###";

GRANT USAGE ON SCHEMA "###, $schema, " TO ", $command, ",", $policy, r###";
"###),
                admission: concat!(r###"SELECT c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
 AND current_user IN('"###, $policy, "','", $command, r###"') AND session_user=current_user
 AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=current_user AND(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND(SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND NOT EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR(a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))
 FROM pg_class c WHERE c.oid='"###, $table, r###"'::regclass;
"###),
                insert: concat!("INSERT INTO ", $table, "(tenant_id,key_id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING"),
                read: concat!("SELECT key_id=$2 FROM ", $table, " WHERE tenant_id=$1::uuid"),
                object_manifest: concat!(r###"{"tables":[""###, $table, r###""],"functions":[]}"###),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_flow",
    "mdm_flow.native_protection",
    "mdm_command_runtime",
    "mdm_policy_runtime"
);
define_storage!(
    da,
    "rss_da",
    "rss_da.protection_keys",
    "da_command_runtime",
    "da_policy_runtime"
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
