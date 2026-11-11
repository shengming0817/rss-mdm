//! Apple management metadata, separate from enrollment protocols and secret material.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0
use crate::{Error, HttpState, database::db};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::directory::{Schema};
use serde_json::{Value, json};
use uuid::Uuid;
pub static ORGANIZATIONS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Organization>("apple_organizations", &["id"], 100, 1000, &[]).expect("Public directory model"));
pub static ACCOUNTS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Account>("apple_accounts", &["account"], 100, 1000, &[]).expect("Public directory model"));
pub static DEVICES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Device>("ade_devices", &["serial"], 100, 1000, &[]).expect("Public directory model"));
pub(crate) static PROFILES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Profile>("ade_profiles", &["id"], 100, 1000, &[])
        .expect("ADE profile model is fully described")
});
static PROFILE_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(
            &PROFILES,
            &[
                Source::column("id", "(row->>'id') COLLATE \"C\""),
                Source::column("revision", "(row->>'revision')::bigint"),
                Source::column("remoteUuid", "(row->>'remoteUuid') COLLATE \"C\""),
                Source::json("configuration", "row->'configuration'"),
            ],
        )
        .expect("ADE profile storage binds every field")
    });
pub(crate) fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
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
    fn bindings(self) -> &'static rss_mdm_query_postgres::Bindings {
        match self { Self::Organizations => &ORGANIZATION_BINDINGS, Self::Accounts(_) => &ACCOUNT_BINDINGS, Self::Devices(_) => &DEVICE_BINDINGS, Self::Profiles(_) => &PROFILE_BINDINGS }
    }
    fn schema(self) -> &'static Schema {
        match self {
            Self::Organizations => &ORGANIZATIONS,
            Self::Accounts(_) => &ACCOUNTS,
            Self::Devices(_) => &DEVICES,
            Self::Profiles(_) => PROFILE_BINDINGS.schema(),
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
pub(crate) async fn page<Q: rss_mdm_http_contract::query::DirectoryOwner>(
    app: &HttpState,
    p: &AuthorizedPrincipal,
    kind: Collection,
    query: rss_mdm_http_contract::query::OwnedQuery<rss_mdm_http_contract::query::Directory<Q>>,
) -> Result<Pages, Error> {
    if p.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    p.manage(Permission::RegistrationConfigurationRead)?;
    let q = query.parse().map_err(error)?;
    q.require_schema(kind.schema()).map_err(error)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    rss_mdm_authorization_service::lock_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    let current = rss_mdm_authorization_service::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    current
        .require(p, Permission::RegistrationConfigurationRead, None)
        .map_err(rss_mdm_authorization_service::Error::from)?;
    let parent = match kind {
        Collection::Organizations => None,
        Collection::Accounts(id) | Collection::Devices(id) | Collection::Profiles(id) => Some(id),
    };
    let now = app.clock.unix_seconds().ok_or(Error::Unavailable(crate::Failure::Clock))?;
    let configured_keys = app.apple.as_ref().map(|a| a.account_keys.iter().filter(|(_,s)| s.expires() > now as u64).map(|(k,_)| k.clone()).collect::<Vec<_>>()).unwrap_or_default();
    let binding = q.binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?, parent, &configured_keys)).map_err(error)?;
    let after = q.after(&app.query_cursor, &binding).map_err(error)?;
    let source=match kind{
 Collection::Organizations=>format!("SELECT jsonb_build_object('id',o.id,'accountEnrollment',CASE WHEN a.id IS NULL THEN NULL ELSE {CONFIG} END,'ade',CASE WHEN d.organization IS NULL THEN NULL ELSE jsonb_build_object('organizationId',d.organization,'revision',d.revision,'enabled',d.enabled,'serverUuid',d.server_uuid,'orgId',d.org_id,'keyId',d.key_id,'tokenRevision',d.token_revision,'tokenExpiresAt',d.token_expires,'tokenState',CASE WHEN d.token_expires IS NULL THEN 'missing' WHEN d.token_expires<=extract(epoch FROM statement_timestamp()) THEN 'expired' WHEN d.token_invalid THEN 'invalid' WHEN d.verified THEN 'verified' ELSE 'unverified' END,'syncedAt',d.synced_at,'externalDeviceVerification','not_observed') END) row FROM mdm_apple.organizations o LEFT JOIN mdm_apple.account_configuration a ON(a.tenant_id,a.id)=(o.tenant_id,o.id) LEFT JOIN mdm_apple.ade_servers d ON(d.tenant_id,d.organization)=(o.tenant_id,o.id) WHERE o.tenant_id="),
 Collection::Accounts(_)=>format!("SELECT {ACCOUNT} row FROM mdm_apple.account_bindings a WHERE a.tenant_id="),
 Collection::Devices(_)=>"SELECT jsonb_build_object('serial',serial,'deleted',deleted,'profileUuid',remote_profile,'observedAt',observed_at,'registration','not_implied') row FROM mdm_apple.ade_devices WHERE tenant_id=".into(),
 Collection::Profiles(_)=>"SELECT jsonb_build_object('id',id,'revision',revision,'configuration',configuration,'remoteUuid',remote_uuid) row FROM mdm_apple.ade_profiles WHERE tenant_id=".into()};
    let mut sql = sqlx::QueryBuilder::new("WITH configured AS (SELECT ");
    sql.push_bind(configured_keys).push("::text[] AS keys) SELECT row FROM (").push(source);
    sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
    if let Some(id) = parent {
        sql.push(" AND organization=").push_bind(id);
    }
    sql.push(") records CROSS JOIN configured WHERE true");
    rss_mdm_query_postgres::append(&mut sql, &q, after.as_ref(), kind.bindings()).map_err(error)?;
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
    macro_rules! page {
        ($variant:ident,$row:ty) => {{
            let rows = rows
                .into_iter()
                .map(decode::<$row>)
                .collect::<Result<Vec<_>, _>>()?;
            Pages::$variant(
                q.page_typed(rows, &app.query_cursor, &binding)
                    .map_err(error)?,
            )
        }};
    }
    Ok(match kind {
        Collection::Organizations => page!(Organizations, Organization),
        Collection::Accounts(_) => page!(Accounts, Account),
        Collection::Devices(_) => page!(Devices, Device),
        Collection::Profiles(_) => page!(Profiles, Profile),
    })
}
pub(crate) async fn detail(
    app: &HttpState,
    p: &AuthorizedPrincipal,
    id: Uuid,
    account: Option<&str>,
) -> Result<Detail, Error> {
    if p.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    p.manage(Permission::RegistrationConfigurationRead)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    rss_mdm_authorization_service::lock_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    let current = rss_mdm_authorization_service::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
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
    if account.is_some() {
        decode(value).map(Detail::Account)
    } else {
        decode(value).map(Detail::Configuration)
    }
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

pub(crate) struct OrganizationsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for OrganizationsQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        ORGANIZATION_BINDINGS.execution()
    }
}

pub(crate) struct AccountsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for AccountsQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        ACCOUNT_BINDINGS.execution()
    }
}

pub(crate) struct DevicesQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DevicesQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        DEVICE_BINDINGS.execution()
    }
}

pub(crate) struct ProfilesQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ProfilesQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        PROFILE_BINDINGS.execution()
    }
}

#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Organization {
    pub id: Uuid,
    pub ade: Option<Ade>,
    pub account_enrollment: Option<AccountConfiguration>,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountConfiguration {
    pub domain: String,
    pub server_uuid: Uuid,
    pub signing_key: String,
    pub enabled: bool,
    pub revision: i64,
    pub external_organization_verification: NotObserved,
    pub signing_key_configured: bool,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NotObserved {
    NotObserved,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Account {
    #[schemars(extend("x-rss-maxUtf8Bytes" = 1024))]
    pub account: String,
    pub principal_id: Uuid,
    pub instance_id: Uuid,
    pub revision: i64,
    pub enabled: bool,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Ade {
    pub organization_id: Uuid,
    pub revision: i64,
    pub enabled: bool,
    pub server_uuid: Uuid,
    pub org_id: String,
    pub key_id: Uuid,
    pub token_revision: i64,
    pub token_expires_at: Option<i64>,
    pub token_state: TokenState,
    pub synced_at: Option<i64>,
    pub external_device_verification: NotObserved,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenState {
    Missing,
    Expired,
    Invalid,
    Verified,
    Unverified,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Device {
    #[schemars(extend("x-rss-maxUtf8Bytes" = 256))]
    pub serial: String,
    pub deleted: bool,
    pub profile_uuid: Option<Uuid>,
    pub observed_at: i64,
    pub registration: NotImplied,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NotImplied {
    NotImplied,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Profile {
    pub id: Uuid,
    pub revision: i64,
    pub configuration: crate::ade::management::Setup,
    pub remote_uuid: Option<Uuid>,
}
pub(crate) type Page<T> = rss_mdm_query::Page<rss_mdm_query::directory::Projection<T>>;
pub(crate) enum Pages {
    Organizations(Page<Organization>),
    Accounts(Page<Account>),
    Devices(Page<Device>),
    Profiles(Page<Profile>),
}
pub(crate) enum Detail {
    Configuration(AccountConfiguration),
    Account(Account),
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_json::from_value(value).map_err(|_| Error::Unavailable(crate::Failure::Database))
}
impl Pages {
    pub(crate) fn organizations(self) -> Result<Page<Organization>, Error> {
        if let Self::Organizations(v) = self {
            Ok(v)
        } else {
            Err(Error::Malformed)
        }
    }
}
impl Pages {
    pub(crate) fn accounts(self) -> Result<Page<Account>, Error> {
        if let Self::Accounts(v) = self {
            Ok(v)
        } else {
            Err(Error::Malformed)
        }
    }
}
impl Pages {
    pub(crate) fn devices(self) -> Result<Page<Device>, Error> {
        if let Self::Devices(v) = self {
            Ok(v)
        } else {
            Err(Error::Malformed)
        }
    }
}
impl Pages {
    pub(crate) fn profiles(self) -> Result<Page<Profile>, Error> {
        if let Self::Profiles(v) = self {
            Ok(v)
        } else {
            Err(Error::Malformed)
        }
    }
}
impl Detail {
    pub(crate) fn configuration(self) -> Result<AccountConfiguration, Error> {
        if let Self::Configuration(v) = self {
            Ok(v)
        } else {
            Err(Error::Malformed)
        }
    }
}
impl Detail {
    pub(crate) fn account(self) -> Result<Account, Error> {
        if let Self::Account(v) = self {
            Ok(v)
        } else {
            Err(Error::Malformed)
        }
    }
}

pub static ORGANIZATION_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&ORGANIZATIONS, &[rss_mdm_query_postgres::Source::json("", "row"),
rss_mdm_query_postgres::Source::column("accountEnrollment.signingKeyConfigured", "((row->'accountEnrollment'->>'signingKey')=ANY(configured.keys))")]).expect("Complete public model storage binding"));

pub static ACCOUNT_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&ACCOUNTS, &[rss_mdm_query_postgres::Source::json("", "row")]).expect("Complete public model storage binding"));

pub static DEVICE_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&DEVICES, &[rss_mdm_query_postgres::Source::json("", "row")]).expect("Complete public model storage binding"));
