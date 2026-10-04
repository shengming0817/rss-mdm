//! The Apple owner supplies the organization gate required by registration's native seam.
use super::*;
use crate::database::db;
use rss_mdm_registration_service::enrollment::native::{AccountAuthority, Coordinates};
use std::{future::Future, pin::Pin};
struct Authority;
type Pending<'a> =
    Pin<Box<dyn Future<Output = Result<(), rss_mdm_registration_service::Error>> + Send + 'a>>;
/// Wire this owner into the product composition, alongside the Identity session authority.
pub fn authority() -> Arc<dyn AccountAuthority> {
    Arc::new(Authority)
}
impl AccountAuthority for Authority {
    fn authorize_issue<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        proof: &'a AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
    ) -> Pending<'a> {
        Box::pin(async move {
            let result = async {
                let row = store::flow(c, proof.tenant_id(), operation).await?;
                if row.try_get::<Uuid, _>("target_enrollment").map_err(db)? != id {
                    return Err(Error::Unauthorized);
                }
                let account: String = row.try_get("account").map_err(db)?;
                let binding = store::bound_account(
                    c,
                    proof.tenant_id(),
                    row.try_get("organization").map_err(db)?,
                    &account,
                )
                .await?;
                if binding
                    .try_get::<Uuid, _>("principal")
                    .map_err(db)?
                    .to_string()
                    != proof.principal_id()
                    || binding
                        .try_get::<Uuid, _>("instance")
                        .map_err(db)?
                        .to_string()
                        != proof.instance_id()
                    || binding.try_get::<i64, _>("revision").map_err(db)?
                        != row.try_get::<i64, _>("binding_revision").map_err(db)?
                {
                    return Err(Error::Unauthorized);
                }
                Ok(())
            }
            .await;
            result.map_err(registration_error)
        })
    }
    fn current<'a>(&'a self, c: &'a mut sqlx::PgConnection, d: &'a Coordinates) -> Pending<'a> {
        Box::pin(async move {
            let row = store::binding(c, &d.tenant, d.id)
                .await
                .map_err(registration_error)?;
            if row
                .try_get::<i64, _>("authorization_version")
                .map_err(|_| rss_mdm_registration_service::Error::Storage)?
                != d.version
            {
                return Err(rss_mdm_registration_service::Error::Unauthorized);
            }
            Ok(())
        })
    }
}
fn registration_error(error: Error) -> rss_mdm_registration_service::Error {
    use rss_mdm_registration_service::Error as R;
    match error {
        Error::Unauthorized => R::Unauthorized,
        Error::Forbidden => R::Forbidden,
        Error::CommitUnknown => R::CommitUnknown,
        Error::RollbackFailed => R::RollbackFailed,
        _ => R::Storage,
    }
}
