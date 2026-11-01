//! Closed product installations. SQL identifiers are source literals, never request data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProfile {
    Mdm,
    Da,
}

impl StorageProfile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mdm => "mdm",
            Self::Da => "da",
        }
    }
    pub const fn owner(self) -> &'static str {
        match self {
            Self::Mdm => "mdm_owner",
            Self::Da => "da_owner",
        }
    }
    pub(crate) const fn statements(self) -> &'static Statements {
        match self {
            Self::Mdm => &mdm::SQL,
            Self::Da => &da::SQL,
        }
    }
}

pub(crate) struct Statements {
    pub initialize: &'static str,
    pub progress_exists: &'static str,
    pub initialize_progress: &'static str,
    pub reserve: &'static str,
    pub matches: &'static str,
    pub read: &'static str,
    pub record: &'static str,
}

macro_rules! installation {
    ($module:ident, $schema:literal, $ledger:literal, $progress:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                initialize: concat!($schema, "CREATE TABLE IF NOT EXISTS ", $ledger,
                    "(name text PRIMARY KEY,digest text NOT NULL,complete boolean NOT NULL DEFAULT false); REVOKE ALL ON ", $ledger, " FROM PUBLIC;"),
                progress_exists: concat!("SELECT to_regclass('", $progress, "') IS NOT NULL"),
                initialize_progress: concat!("CREATE TABLE IF NOT EXISTS ", $progress,
                    "(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),instance_id uuid NOT NULL UNIQUE,target bytea NOT NULL CHECK(octet_length(target)=16),lineage bytea NOT NULL CHECK(octet_length(lineage)=16),configuration text NOT NULL,manifest text NOT NULL); REVOKE ALL ON ", $progress, " FROM PUBLIC;"),
                reserve: concat!("INSERT INTO ", $progress,
                    "(singleton,instance_id,target,lineage,configuration,manifest) VALUES(true,$1,$2,$3,$4,$5) ON CONFLICT DO NOTHING"),
                matches: concat!("SELECT count(*)=1 AND coalesce(bool_and(instance_id=$1 AND target=$2 AND lineage=$3 AND configuration=$4 AND manifest=$5),false) FROM ", $progress),
                read: concat!("SELECT name,digest,complete FROM ", $ledger),
                record: concat!("INSERT INTO ", $ledger, "(name,digest,complete) VALUES($1,$2,true)"),
            };
        }
    }
}
installation!(
    mdm,
    "",
    "public.mdm_migrations",
    "public.mdm_installation_progress"
);
installation!(
    da,
    "CREATE SCHEMA IF NOT EXISTS rss_da; REVOKE ALL ON SCHEMA rss_da FROM PUBLIC; ",
    "rss_da.installation_units",
    "rss_da.installation_binding"
);
