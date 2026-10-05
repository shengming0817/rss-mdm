//! Host mapping between registration authority and fixed software publication admission.
use crate::{Error, task_signing};
use rss_mdm_registration_service::{
    Error as RegistrationError,
    agent::{Pending, configurations},
};
pub(crate) fn signer(c: &task_signing::Config) -> Result<configurations::Signer, Error> {
    let private = crate::config::read(&c.private_key_file, 4096, true)?;
    configurations::Signer::new(&private, &c.key_id, &c.trusted_keys).map_err(Into::into)
}
pub(crate) struct Installations;
impl configurations::InstallationAdmission for Installations {
    fn verify<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: &'a str,
        i: &'a rss_mdm_agent_wire::enroll::configuration::Installation,
    ) -> Pending<'a, rss_mdm_agent_wire::enroll::configuration::Package> {
        Box::pin(async move {
            let tenant = rss_request_context::TenantId::parse(tenant)
                .map_err(|_| RegistrationError::Configuration)?;
            rss_mdm_software_service::agent_packages::admitted_on(c, tenant, i)
                .await
                .map_err(|e| match e {
                    rss_mdm_software_service::management::Error::Forbidden
                    | rss_mdm_software_service::management::Error::ResourceMissing => {
                        RegistrationError::Forbidden
                    }
                    _ => RegistrationError::Storage,
                })
        })
    }
}
