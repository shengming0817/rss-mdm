use super::*;
use rss_mdm_install_support::{Binding, Host, Pending, Receipt, Unit, execute_schema};
pub fn units() -> Vec<Unit> {
    vec![
        ("audit", rss_audit_postgres::MIGRATION_SQL),
        ("observation", rss_observation_postgres::MIGRATION_SQL),
        ("projection", rss_projection_postgres::MIGRATION_SQL),
        (
            "messaging",
            rss_transactional_messaging_postgres::MIGRATION_SQL,
        ),
        ("inventory", rss_mdm_inventory_postgres::MIGRATION_SQL),
        ("identity", rss_identity_postgres::MIGRATION_SQL),
        (
            "authorization-installation",
            rss_mdm_authorization_service::installation::DA_INSTALL_SQL,
        ),
        ("registration", registration::install_sql(DA)),
        (
            "authorization",
            rss_mdm_authorization_service::install_sql(DA),
        ),
        (
            "authorization-authority",
            rss_mdm_authorization_service::authority_sql(DA),
        ),
        ("pki", rss_mdm_pki_service::install_sql(DA)),
        (
            "pki-observations",
            rss_mdm_pki_service::observations::install_sql(DA),
        ),
        ("signing", rss_mdm_task_trust::trust::install_sql(DA)),
        (
            "signing-observations",
            rss_mdm_task_trust::observations::install_sql(DA),
        ),
        ("registration-relations", registration::relations_sql(DA)),
        (
            "authorization-relations",
            rss_mdm_authorization_service::relations_sql(DA),
        ),
        (
            "current-da",
            registration::device::endpoints::DA_INSTALL_SQL,
        ),
        ("policy", rss_mdm_policy_postgres::migration_sql(DA)),
        (
            "policy-targets",
            rss_mdm_policy_postgres::device_access::INSTALL_SQL,
        ),
        (
            "bindings",
            rss_mdm_device_access_postgres::device_access::INSTALL_SQL,
        ),
        (
            "business-authority",
            rss_mdm_device_access_postgres::AUTHORITY_SQL,
        ),
        (
            "enterprise",
            rss_mdm_device_access_postgres::enterprise::INSTALL_SQL,
        ),
        (
            "access-tasks",
            rss_mdm_device_access_postgres::device_access::execution::INSTALL_SQL,
        ),
        (
            "platform-sso",
            rss_mdm_device_access_postgres::platform_sso::INSTALL_SQL,
        ),
        ("recovery", rss_mdm_recovery_credentials::install_sql(DA)),
        (
            "credential-tasks",
            rss_mdm_recovery_credentials::tasks_sql(DA),
        ),
        (
            "credential-relations",
            rss_mdm_recovery_credentials::task_relations_sql(DA),
        ),
        (
            "business-directory",
            rss_mdm_device_access_postgres::DIRECTORY_SQL,
        ),
        ("identity-proof", rss_mdm_device_access_postgres::PROOF_SQL),
        ("host-grants", include_str!("grants.sql")),
    ]
}

pub struct Installation<'a> {
    pub inputs: &'a Inputs,
    pub fail_before: Option<&'static str>,
}
impl Installation<'_> {
    pub fn binding(&self) -> Result<Binding> {
        Ok(Binding::new(
            DA,
            Uuid::parse_str(&self.inputs.installation.instance_id)?,
            self.inputs.installation.target,
            self.inputs.installation.lineage,
            "da-foundation-plain-v1".into(),
        )?)
    }
}
impl Host for Installation<'_> {
    fn check_existing<'a>(
        &'a self,
        _c: &'a mut sqlx::PgConnection,
        _receipts: &'a [Receipt],
    ) -> Pending<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn apply<'a>(
        &'a self,
        tx: &'a mut sqlx::Transaction<'_, sqlx::Postgres>,
        (name, sql): Unit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if self.fail_before == Some(name) {
                return Err(rss_mdm_install_support::Error::at(
                    name,
                    "injected interruption before unit",
                ));
            }
            if name == "audit" {
                sqlx::query("SET LOCAL ROLE mdm_audit_owner")
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| rss_mdm_install_support::Error::at(name, "Audit owner"))?;
                execute_schema(tx, name, sql, "schema").await?;
                sqlx::query("RESET ROLE")
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| rss_mdm_install_support::Error::at(name, "restore installer"))?;
            } else if name == "identity" {
                rss_identity_postgres::install(
                    tx,
                    rss_identity_core::InstanceId::parse(&self.inputs.installation.instance_id)
                        .unwrap(),
                )
                .await
                .map_err(|_| rss_mdm_install_support::Error::at(name, "Identity installation"))?;
                for (role, profile) in [
                    (
                        "da_identity_runtime",
                        rss_identity_postgres::AuthorityProfile::Runtime,
                    ),
                    (
                        "da_identity_maintenance",
                        rss_identity_postgres::AuthorityProfile::Maintenance,
                    ),
                    (
                        "da_identity_provisioning",
                        rss_identity_postgres::AuthorityProfile::Provisioning,
                    ),
                ] {
                    rss_identity_postgres::grant_profile(tx, role, profile)
                        .await
                        .map_err(|_| rss_mdm_install_support::Error::at(name, "Identity grants"))?;
                }
                rss_identity_postgres::grant_platform_subject_admission(tx, "da_access")
                    .await
                    .map_err(|_| rss_mdm_install_support::Error::at(name, "subject admission"))?;
            } else {
                execute_schema(tx, name, sql, "schema").await?;
            }
            Ok(())
        })
    }
    fn verify<'a>(&'a self, c: &'a mut sqlx::PgConnection) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_install_support::verify_manifest(c, DA, &units())
                .await
                .map_err(|_| rss_mdm_install_support::Error::at("fixture", "manifest"))?;
            rss_mdm_install_support::catalog::verify_schema(
                c,
                DA,
                &[
                    registration::identity_object_manifest(DA),
                    registration::DA_IDENTITY_PROJECTION_MANIFEST,
                    rss_mdm_policy_postgres::object_manifest(DA),
                    rss_mdm_recovery_credentials::object_manifest(DA),
                    rss_mdm_device_access_postgres::admission::OBJECTS,
                    rss_mdm_pki_service::object_manifest(DA),
                    rss_mdm_authorization_service::object_manifest(DA),
                    rss_mdm_task_trust::object_manifest(DA),
                    rss_mdm_authorization_service::installation::DA_OBJECT_MANIFEST,
                ],
            )
            .await
            .map_err(|_| rss_mdm_install_support::Error::at("fixture", "object union"))?;
            Ok(())
        })
    }
}
