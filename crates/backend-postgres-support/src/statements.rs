pub(crate) struct Statements {
    pub statement_0: &'static str,
    pub statement_1: &'static str,
    pub statement_2: &'static str,
    pub statement_3: &'static str,
    pub statement_4: &'static str,
    pub statement_5: &'static str,
    pub statement_6: &'static str,
    pub statement_7: &'static str,
}
macro_rules! statements { ($module:ident,$aggregates:literal,$requests:literal,$immutable:literal) => { mod $module { pub(super) const SQL: super::Statements = super::Statements {
                statement_0: concat!("SELECT revision,document,digest FROM ", $aggregates, " WHERE tenant_id=$1::uuid AND id=$2"),
                statement_1: concat!("UPDATE ", $aggregates, " SET revision=$3,document=$4,digest=$5 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$6"),
                statement_2: concat!("INSERT INTO ", $aggregates, "(tenant_id,id,revision,document,digest) SELECT $1::uuid,$2,$3,$4,$5 WHERE $6::bigint IS NULL"),
                statement_3: concat!("SELECT owner,fingerprint,request,receipt,digest FROM ", $requests, " WHERE tenant_id=$1::uuid AND id=$2"),
                statement_4: concat!("INSERT INTO ", $requests, "(tenant_id,id,owner,fingerprint,request,receipt,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)"),
                statement_5: concat!("SELECT document,digest FROM ", $immutable, " WHERE tenant_id=$1::uuid AND owner=$2 AND kind=$3 AND key=$4"),
                statement_6: concat!("INSERT INTO ", $immutable, "(tenant_id,owner,kind,key,document,digest) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"),
                statement_7: concat!("SELECT document FROM ", $immutable, " WHERE tenant_id=$1::uuid AND owner=$2 AND kind=$3 AND key=$4"),
}; } }; }
statements!(
    policy,
    "mdm_policy.aggregates",
    "mdm_policy.requests",
    "mdm_policy.immutable"
);
statements!(
    da_policy,
    "rss_da.policy_aggregates",
    "rss_da.policy_requests",
    "rss_da.policy_immutable"
);
statements!(
    resource,
    "mdm_resource.aggregates",
    "mdm_resource.requests",
    "mdm_resource.immutable"
);
statements!(
    release,
    "mdm_software_release.aggregates",
    "mdm_software_release.requests",
    "mdm_software_release.immutable"
);
impl crate::BackendKind {
    pub(crate) const fn statements(self) -> &'static Statements {
        match self {
            Self::Policy => &policy::SQL,
            Self::DaPolicy => &da_policy::SQL,
            Self::Resource => &resource::SQL,
            Self::SoftwareRelease => &release::SQL,
        }
    }
}
