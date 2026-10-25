//! Apple management metadata, separate from enrollment protocols and secret material.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0
use crate::{Error, HttpState, database::db};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::directory::{Field, Kind, Schema};
use serde_json::{Value, json};
use uuid::Uuid;
pub(crate) static ORGANIZATIONS: Schema = Schema {
    id: "apple_organizations",
    keys: &["id"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::output("ade"),
        Field::output("accountEnrollment"),
    ],
};
pub(crate) static ACCOUNTS: Schema = Schema {
    id: "apple_accounts",
    keys: &["account"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("account", Kind::Text),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("principalId", Kind::Uuid),
        Field::scalar("instanceId", Kind::Uuid),
    ],
};
pub(crate) static DEVICES: Schema = Schema {
    id: "ade_devices",
    keys: &["serial"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("serial", Kind::Text),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar("profileUuid", Kind::Uuid),
        Field::scalar("observedAt", Kind::Integer),
        Field::output("registration"),
    ],
};
pub(crate) static PROFILES: Schema = Schema {
    id: "ade_profiles",
    keys: &["id"],
    default_limit: 100,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("remoteUuid", Kind::Uuid),
        Field::output("configuration"),
    ],
};
pub(crate) fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
fn column(n: &str) -> &'static str {
    match n {
        "id" => "(row->>'id') COLLATE \"C\"",
        "account" => "(row->>'account') COLLATE \"C\"",
        "serial" => "(row->>'serial') COLLATE \"C\"",
        "principalId" => "(row->>'principalId') COLLATE \"C\"",
        "instanceId" => "(row->>'instanceId') COLLATE \"C\"",
        "profileUuid" => "(row->>'profileUuid') COLLATE \"C\"",
        "remoteUuid" => "(row->>'remoteUuid') COLLATE \"C\"",
        "revision" => "(row->>'revision')::bigint",
        "observedAt" => "(row->>'observedAt')::bigint",
        "enabled" => "(row->>'enabled')::boolean",
        "deleted" => "(row->>'deleted')::boolean",
        _ => unreachable!("checked Apple field"),
    }
}
const CONFIG: &str = "jsonb_build_object('domain',a.domain,'serverUuid',a.server_uuid,'signingKey',a.signing_key,'enabled',a.enabled,'revision',a.revision,'externalOrganizationVerification','not_observed')";
const ACCOUNT: &str = "jsonb_build_object('account',a.account,'principalId',a.principal,'instanceId',a.instance,'revision',a.revision,'enabled',a.enabled)";
#[derive(Clone, Copy)]
pub(crate) enum Collection {
    Organizations,
    Accounts(Uuid),
    Devices(Uuid),
    Profiles(Uuid),
}
impl Collection {
    fn schema(self) -> &'static Schema {
        match self {
            Self::Organizations => &ORGANIZATIONS,
            Self::Accounts(_) => &ACCOUNTS,
            Self::Devices(_) => &DEVICES,
            Self::Profiles(_) => &PROFILES,
        }
    }
}
fn configured(app: &HttpState, value: &mut Value, now: i64) {
    if value.is_null() {
        return;
    }
    let key = value["signingKey"].as_str().unwrap_or("");
    let configured = app
        .apple
        .as_ref()
        .and_then(|a| a.account_keys.get(key))
        .is_some_and(|s| s.expires() > now as u64);
    value["signingKeyConfigured"] = json!(configured);
}
pub(crate) async fn page(
    app: &HttpState,
    p: &AuthorizedPrincipal,
    kind: Collection,
    raw: &str,
) -> Result<Value, Error> {
    if p.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    p.manage(Permission::RegistrationConfigurationRead)?;
    let q = kind.schema().parse(raw).map_err(error)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    rss_mdm_authorization_service::lock_on(&mut tx, p.tenant_id(), p.instance_id()).await?;
    let current =
        rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id()).await?;
    current
        .require(p, Permission::RegistrationConfigurationRead, None)
        .map_err(rss_mdm_authorization_service::Error::from)?;
    let parent = match kind {
        Collection::Organizations => None,
        Collection::Accounts(id) | Collection::Devices(id) | Collection::Profiles(id) => Some(id),
    };
    let binding = q
        .binding(&(
            p.tenant_id(),
            p.instance_id(),
            current.query_binding(p)?,
            parent,
        ))
        .map_err(error)?;
    let after = q.after(&app.query_cursor, &binding).map_err(error)?;
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(crate::Failure::Clock))?;
    let source=match kind{
 Collection::Organizations=>format!("SELECT jsonb_build_object('id',o.id,'accountEnrollment',CASE WHEN a.id IS NULL THEN NULL ELSE {CONFIG} END,'ade',CASE WHEN d.organization IS NULL THEN NULL ELSE jsonb_build_object('organizationId',d.organization,'revision',d.revision,'enabled',d.enabled,'serverUuid',d.server_uuid,'orgId',d.org_id,'keyId',d.key_id,'tokenRevision',d.token_revision,'tokenExpiresAt',d.token_expires,'tokenState',CASE WHEN d.token_expires IS NULL THEN 'missing' WHEN d.token_expires<=extract(epoch FROM statement_timestamp()) THEN 'expired' WHEN d.token_invalid THEN 'invalid' WHEN d.verified THEN 'verified' ELSE 'unverified' END,'syncedAt',d.synced_at,'externalDeviceVerification','not_observed') END) row FROM mdm_apple.organizations o LEFT JOIN mdm_apple.account_configuration a ON(a.tenant_id,a.id)=(o.tenant_id,o.id) LEFT JOIN mdm_apple.ade_servers d ON(d.tenant_id,d.organization)=(o.tenant_id,o.id) WHERE o.tenant_id="),
 Collection::Accounts(_)=>format!("SELECT {ACCOUNT} row FROM mdm_apple.account_bindings a WHERE a.tenant_id="),
 Collection::Devices(_)=>"SELECT jsonb_build_object('serial',serial,'deleted',deleted,'profileUuid',remote_profile,'observedAt',observed_at,'registration','not_implied') row FROM mdm_apple.ade_devices WHERE tenant_id=".into(),
 Collection::Profiles(_)=>"SELECT jsonb_build_object('id',id,'revision',revision,'configuration',configuration,'remoteUuid',remote_uuid) row FROM mdm_apple.ade_profiles WHERE tenant_id=".into()};
    let mut sql = sqlx::QueryBuilder::new(format!("SELECT row FROM ({source}"));
    sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
    if let Some(id) = parent {
        sql.push(" AND organization=").push_bind(id);
    }
    sql.push(") records WHERE true");
    rss_mdm_query_postgres::append(&mut sql, &q, after.as_ref(), column).map_err(error)?;
    let mut rows: Vec<Value> = sql
        .build_query_scalar()
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
    if matches!(kind, Collection::Organizations) {
        for row in &mut rows {
            configured(app, &mut row["accountEnrollment"], now);
        }
    }
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    serde_json::to_value(q.page(rows, &app.query_cursor, &binding).map_err(error)?)
        .map_err(|_| Error::Malformed)
}
pub(crate) async fn detail(
    app: &HttpState,
    p: &AuthorizedPrincipal,
    id: Uuid,
    account: Option<&str>,
) -> Result<Value, Error> {
    if p.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    p.manage(Permission::RegistrationConfigurationRead)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    rss_mdm_authorization_service::lock_on(&mut tx, p.tenant_id(), p.instance_id()).await?;
    let current =
        rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id()).await?;
    current
        .require(p, Permission::RegistrationConfigurationRead, None)
        .map_err(rss_mdm_authorization_service::Error::from)?;
    let source = if account.is_some() {
        format!("SELECT {ACCOUNT} FROM mdm_apple.account_bindings a WHERE tenant_id=")
    } else {
        format!("SELECT {CONFIG} FROM mdm_apple.account_configuration a WHERE tenant_id=")
    };
    let mut sql = sqlx::QueryBuilder::new(source);
    sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
    if let Some(account) = account {
        sql.push(" AND organization=")
            .push_bind(id)
            .push(" AND account=")
            .push_bind(account.to_owned());
    } else {
        sql.push(" AND id=").push_bind(id);
    }
    let mut value: Value = sql
        .build_query_scalar()
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::NotFound)?;
    if account.is_none() {
        configured(
            app,
            &mut value,
            app.clock
                .unix_seconds()
                .ok_or(Error::Unavailable(crate::Failure::Clock))?,
        );
    }
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(value)
}
/// Settings needs aggregate state, not every organization or account.
pub async fn summary(
    store: &crate::Store,
    apple: Option<&crate::Apple>,
    clock: &dyn rss_mdm_inventory_service::clock::Clock,
    p: &AuthorizedPrincipal,
) -> Result<Value, Error> {
    p.manage(Permission::RegistrationConfigurationRead)?;
    let now = clock
        .unix_seconds()
        .ok_or(Error::Unavailable(crate::Failure::Clock))?;
    let keys: Vec<String> = apple
        .map(|a| {
            a.account_keys
                .iter()
                .filter(|(_, s)| s.expires() > now as u64)
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();
    let mut tx = store.begin_read(p.tenant_id()).await?;
    let ade:Value=sqlx::query_scalar("SELECT jsonb_build_object('count',count(*),'unavailable',count(*) FILTER(WHERE token_expires<=$2 OR token_invalid),'pending',count(*) FILTER(WHERE token_expires IS NULL OR (token_expires>$2 AND NOT token_invalid AND NOT verified)),'ready',coalesce(bool_or(enabled AND verified AND NOT token_invalid AND token_expires>$2),false)) FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid").bind(p.tenant_id()).bind(now).fetch_one(&mut *tx).await.map_err(db)?;
    let account:Value=sqlx::query_scalar("SELECT jsonb_build_object('count',count(*),'unavailable',count(*) FILTER(WHERE enabled AND NOT(signing_key=ANY($2))),'pending',0,'ready',coalesce(bool_or(enabled AND signing_key=ANY($2)),false)) FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid").bind(p.tenant_id()).bind(keys).fetch_one(&mut *tx).await.map_err(db)?;
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(json!({"ade":ade,"account":account}))
}
