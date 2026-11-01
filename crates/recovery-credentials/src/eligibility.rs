//! Host-owned subject eligibility participates in the original material transaction.
use crate::{Binding, Error, Material};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_install_support::StorageProfile;
use sqlx::PgConnection;
use uuid::Uuid;

pub type Pending<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;

/// Product qualification for subjects whose lifecycle belongs to another owner.
/// Implementations acquire their subject fence before Registration/material locks.
pub trait Eligibility: Send + Sync {
    fn storage_profile(&self) -> StorageProfile;
    fn active<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        binding: &'a Binding,
    ) -> Pending<'a, ()>;
    fn disclose<'a>(
        &'a self,
        c: &'a mut PgConnection,
        principal: &'a AuthorizedPrincipal,
        binding: &'a Binding,
    ) -> Pending<'a, ()>;
}

/// Retention authority for a currently selected product-specific material.
/// Return true only while holding the subject fence through the caller's transaction.
pub trait Retention: Send + Sync {
    fn storage_profile(&self) -> StorageProfile;
    fn releasable<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        material: &'a Material,
    ) -> Pending<'a, bool>;
}

/// Fixed provider profile and optional product qualification. Absence rejects product subjects.
#[derive(Clone, Copy)]
pub struct Custody<'a> {
    profile: StorageProfile,
    eligibility: Option<&'a dyn Eligibility>,
}
impl<'a> Custody<'a> {
    pub const fn new(profile: StorageProfile, eligibility: Option<&'a dyn Eligibility>) -> Self {
        Self {
            profile,
            eligibility,
        }
    }
    pub const fn profile(self) -> StorageProfile {
        self.profile
    }
    pub async fn active(
        self,
        c: &mut PgConnection,
        tenant: Uuid,
        binding: &Binding,
    ) -> Result<(), Error> {
        if matches!(binding.subject, crate::Subject::RssLogin { .. }) {
            let eligibility = self.eligibility.ok_or(Error::Unsupported)?;
            if eligibility.storage_profile() != self.profile {
                return Err(Error::Forbidden);
            }
            eligibility.active(c, tenant, binding).await?;
        }
        Ok(())
    }
}

/// Coordinates accepted only after the external lifecycle owner verified its correlated Unbound effect.
/// A host adapter constructs this at the same borrowed transaction boundary.
pub struct Unbound {
    pub tenant: Uuid,
    pub device: String,
    pub registration: Uuid,
    pub registration_generation: i64,
    pub binding: Uuid,
    pub generation: i64,
}
