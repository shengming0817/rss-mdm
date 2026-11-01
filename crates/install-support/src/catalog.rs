//! Exact host union for a shared product schema; each owner supplies only its own objects.
use crate::StorageProfile;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Objects {
    pub tables: Vec<String>,
    pub functions: Vec<String>,
    #[serde(default)]
    pub views: Vec<String>,
}
/// Compare the complete installation manifest, including unexpected objects and privileged owners.
/// Owners still verify their function bodies, RLS expressions and individual role privileges.
pub async fn verify_schema(
    connection: &mut sqlx::PgConnection,
    profile: StorageProfile,
    contracts: &[&str],
) -> Result<(), sqlx::Error> {
    use std::collections::BTreeSet;
    let mut tables = BTreeSet::new();
    let mut functions = BTreeSet::new();
    let mut views = BTreeSet::new();
    for contract in contracts {
        let objects: Objects = serde_json::from_str(contract)
            .map_err(|_| sqlx::Error::Protocol("invalid owner object manifest".into()))?;
        for name in objects.tables {
            if !tables.insert(name) {
                return Err(sqlx::Error::Protocol("duplicate table owner".into()));
            }
        }
        for name in objects.views {
            if !views.insert(name) {
                return Err(sqlx::Error::Protocol("duplicate view owner".into()));
            }
        }
        for name in objects.functions {
            if !functions.insert(name) {
                return Err(sqlx::Error::Protocol("duplicate function owner".into()));
            }
        }
    }
    // rss_da is deliberately shared; MDM retains its independently verified owner schemas.
    if profile != StorageProfile::Da {
        return Err(sqlx::Error::Protocol(
            "shared schema profile required".into(),
        ));
    }
    tables.extend([
        "rss_da.installation_units".to_owned(),
        "rss_da.installation_binding".to_owned(),
    ]);
    let tables = local_names(tables)?;
    let functions = local_names(functions)?;
    let views = local_names(views)?;
    let valid: bool = sqlx::query_scalar(
        "WITH relations AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_da'), functions AS (SELECT p.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_da')
        SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='rss_da' AND pg_get_userbyid(nspowner)=$3)
        AND (SELECT array_agg(relname::text ORDER BY relname) FROM relations WHERE relkind='r') IS NOT DISTINCT FROM $1::text[]
        AND NOT EXISTS(SELECT FROM relations WHERE relkind NOT IN('r','i','v') OR pg_get_userbyid(relowner)<>$3
            OR relkind='r' AND relname NOT IN('installation_units','installation_binding','authorization_installation') AND (NOT relrowsecurity OR NOT relforcerowsecurity))
        AND coalesce((SELECT array_agg(relname::text ORDER BY relname) FROM relations WHERE relkind='v'),'{}')=$4::text[]
        AND NOT EXISTS(SELECT FROM relations WHERE relkind='v' AND NOT coalesce(reloptions @> ARRAY['security_barrier=true'],false))
        AND coalesce((SELECT array_agg(proname::text ORDER BY proname) FROM functions),'{}')=$2::text[]
        AND NOT EXISTS(SELECT FROM functions WHERE pg_get_userbyid(proowner)<>$3 OR prokind<>'f' OR proleakproof)
        AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=$3 AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
        AND NOT EXISTS(SELECT FROM relations r,LATERAL aclexplode(coalesce(r.relacl,acldefault('r',r.relowner))) a WHERE a.grantee=0)
        AND NOT EXISTS(SELECT FROM functions f,LATERAL aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantee=0)",
    ).bind(tables).bind(functions).bind(profile.owner()).bind(views).fetch_one(connection).await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "shared product catalog differs from owner manifest".into(),
        ));
    }
    Ok(())
}

fn local_names(names: std::collections::BTreeSet<String>) -> Result<Vec<String>, sqlx::Error> {
    names
        .into_iter()
        .map(|name| {
            name.strip_prefix("rss_da.")
                .map(str::to_owned)
                .ok_or_else(|| {
                    sqlx::Error::Protocol("object belongs to another product schema".into())
                })
        })
        .collect()
}
