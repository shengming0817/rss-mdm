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
        ("reconcile", rss_reconcile_postgres::MIGRATION_SQL),
        ("inventory", rss_mdm_inventory_postgres::MIGRATION_SQL),
        (
            "inventory-reader",
            rss_mdm_inventory_postgres::READER_MIGRATION_SQL,
        ),
        ("group", rss_mdm_group_postgres::MIGRATION_SQL),
        ("group-scope-facts", rss_mdm_group_postgres::SCOPE_FACTS_SQL),
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
        ("registration-quotas", registration::quotas_sql(DA)),
        ("registration-admission", registration::admission_sql(DA)),
        (
            "agent-configurations",
            registration::agent_configurations_sql(DA),
        ),
        ("agent-bootstrap", registration::agent_bootstrap_sql(DA)),
        ("member-authority", registration::member_authority_sql(DA)),
        ("pki", rss_mdm_pki_service::install_sql(DA)),
        (
            "pki-observations",
            rss_mdm_pki_service::observations::install_sql(DA),
        ),
        ("registration-directory", registration::directory_sql(DA)),
        (
            "registration-tenant-seed",
            registration::agent::settings::tenant_seed_sql(DA),
        ),
        ("policy", rss_mdm_policy_postgres::migration_sql(DA)),
        ("scope", rss_mdm_scope_postgres::install_sql(DA)),
        (
            "scope-group-changes",
            rss_mdm_scope_postgres::group_changes_sql(DA),
        ),
        (
            "scope-projection",
            rss_mdm_scope_postgres::projections_sql(DA),
        ),
        ("collections", rss_mdm_inventory_service::collection_sql(DA)),
        (
            "collection-metadata",
            rss_mdm_inventory_service::collection_metadata_sql(DA),
        ),
        ("agent", rss_mdm_agent_channel::install_sql(DA)),
        ("enrollment-tasks", registration::enrollment_tasks_sql(DA)),
        (
            "enrollment-retirement",
            registration::enrollment_retirement_sql(DA),
        ),
        ("recovery", rss_mdm_recovery_credentials::install_sql(DA)),
        (
            "credential-tasks",
            rss_mdm_recovery_credentials::tasks_sql(DA),
        ),
        ("protection", rss_mdm_native_protection::install_sql(DA)),
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
        ("agent-relations", rss_mdm_agent_channel::relations_sql(DA)),
        (
            "policy-relations",
            rss_mdm_policy_postgres::relations_sql(DA),
        ),
        ("scope-relations", rss_mdm_scope_postgres::relations_sql(DA)),
        (
            "scope-projection-relations",
            rss_mdm_scope_postgres::projection_relations_sql(DA),
        ),
        ("enrollment-relations", registration::task_relations_sql(DA)),
        (
            "credential-relations",
            rss_mdm_recovery_credentials::task_relations_sql(DA),
        ),
        (
            "inventory-snapshot",
            rss_mdm_inventory_service::read_snapshot_sql(DA),
        ),
        (
            "collection-relations",
            rss_mdm_inventory_service::collection_relations_sql(DA),
        ),
        (
            "inventory-tenants",
            rss_mdm_inventory_postgres::tenant_seed_sql(),
        ),
        (
            "ingestion-grants",
            rss_mdm_inventory_service::ingestion_grants_sql(DA),
        ),
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
            "agent-foundation-plain-v1".into(),
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
            if name == "identity" {
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
                    registration::object_manifest(DA),
                    rss_mdm_pki_service::object_manifest(DA),
                    rss_mdm_authorization_service::object_manifest(DA),
                    rss_mdm_agent_channel::object_manifest(DA),
                    rss_mdm_task_trust::object_manifest(DA),
                    rss_mdm_policy_postgres::object_manifest(DA),
                    rss_mdm_scope_postgres::object_manifest(DA),
                    rss_mdm_inventory_service::object_manifest(DA),
                    rss_mdm_recovery_credentials::object_manifest(DA),
                    rss_mdm_authorization_service::installation::DA_OBJECT_MANIFEST,
                    rss_mdm_native_protection::object_manifest(DA),
                ],
            )
            .await
            .map_err(|_| rss_mdm_install_support::Error::at("fixture", "object union"))?;
            Ok(())
        })
    }
}
