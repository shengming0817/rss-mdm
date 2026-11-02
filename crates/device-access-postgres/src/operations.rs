//! DA operation receipts participate in the caller's audited transaction.
use crate::{Error, database::db};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub(crate) struct Operation<'a> {
    actor: &'a AuthorizedPrincipal,
    key: Uuid,
    digest: &'a str,
}
impl<'a> Operation<'a> {
    pub(crate) fn new(
        actor: &'a AuthorizedPrincipal,
        key: Uuid,
        digest: &'a str,
    ) -> Result<Self, Error> {
        actor.check_live()?;
        if key.is_nil() || digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Malformed);
        }
        Ok(Self { actor, key, digest })
    }
}
pub(crate) async fn replay(
    c: &mut PgConnection,
    o: &Operation<'_>,
) -> Result<Option<String>, Error> {
    let key = serde_json::to_string(&(
        "da.operation",
        o.actor.tenant_id(),
        o.actor.instance_id(),
        o.actor.principal_id(),
        o.key,
    ))
    .map_err(|_| Error::Malformed)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3092))")
        .bind(key)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    read(c, o).await
}
pub(crate) async fn read(c: &mut PgConnection, o: &Operation<'_>) -> Result<Option<String>, Error> {
    o.actor.check_live()?;
    let r=sqlx::query("SELECT digest,result FROM rss_da.operations WHERE tenant_id=$1::uuid AND instance=$2::uuid AND actor=$3::uuid AND operation_id=$4")
        .bind(o.actor.tenant_id()).bind(o.actor.instance_id()).bind(o.actor.principal_id()).bind(o.key).fetch_optional(c).await.map_err(db)?;
    r.map(|r| {
        if r.try_get::<String, _>("digest").map_err(db)? != o.digest {
            return Err(Error::Conflict);
        }
        r.try_get("result").map_err(db)
    })
    .transpose()
}
pub(crate) async fn save(
    c: &mut PgConnection,
    o: &Operation<'_>,
    result: &str,
    a: &RequestAudit,
) -> Result<(), Error> {
    o.actor.bind_audit(a)?;
    let f = a.snapshot();
    if f.operation_id != Some(o.key) {
        return Err(Error::Forbidden);
    }
    sqlx::query("INSERT INTO rss_da.operations(tenant_id,instance,actor,operation_id,digest,result) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6)")
        .bind(o.actor.tenant_id()).bind(o.actor.instance_id()).bind(o.actor.principal_id()).bind(o.key).bind(o.digest).bind(result).execute(c).await.map_err(db)?;
    Ok(())
}
