//! DA-owned installation composition; hosts explicitly supply the existing Identity binding.
//! ref: sqlx v0.9.0 sqlx-core/src/migrate/migrator.rs.
use rss_mdm_install_support::{
    Error, Host, Pending, Receipt, StorageProfile, Unit, execute_schema,
};
use sqlx::{PgConnection, Postgres, Transaction};
const DA: StorageProfile = StorageProfile::Da;
pub fn units() -> Vec<Unit> {
    vec![
        ("vault-sync-v1", rss_mdm_vault_sync::INSTALL_SQL),
        (
            "authorization-installation-v1",
            rss_mdm_authorization_service::installation::DA_INSTALL_SQL,
        ),
        (
            "registration-identity-v1",
            rss_mdm_registration_service::identity_install_sql(DA),
        ),
        (
            "authorization-v1",
            rss_mdm_authorization_service::install_sql(DA),
        ),
        (
            "authorization-authority-v1",
            rss_mdm_authorization_service::authority_sql(DA),
        ),
        ("pki-v1", rss_mdm_pki_service::install_sql(DA)),
        (
            "pki-observations-v1",
            rss_mdm_pki_service::observations::install_sql(DA),
        ),
        ("signing-v1", rss_mdm_task_trust::trust::install_sql(DA)),
        (
            "signing-observations-v1",
            rss_mdm_task_trust::observations::install_sql(DA),
        ),
        (
            "registration-relations-v1",
            rss_mdm_registration_service::identity_relations_sql(DA),
        ),
        (
            "authorization-relations-v1",
            rss_mdm_authorization_service::relations_sql(DA),
        ),
        (
            "registration-current-da-v1",
            rss_mdm_registration_service::device::endpoints::DA_INSTALL_SQL,
        ),
        ("policy-v1", rss_mdm_policy_postgres::migration_sql(DA)),
        (
            "policy-targets-v1",
            rss_mdm_policy_postgres::device_access::INSTALL_SQL,
        ),
        (
            "bindings-v1",
            rss_mdm_device_access_postgres::device_access::INSTALL_SQL,
        ),
        (
            "authority-v1",
            rss_mdm_device_access_postgres::AUTHORITY_SQL,
        ),
        (
            "enterprise-v1",
            rss_mdm_device_access_postgres::enterprise::INSTALL_SQL,
        ),
        (
            "tasks-v1",
            rss_mdm_device_access_postgres::device_access::execution::INSTALL_SQL,
        ),
        (
            "platform-sso-v1",
            rss_mdm_device_access_postgres::platform_sso::INSTALL_SQL,
        ),
        (
            "recovery-material-v1",
            rss_mdm_recovery_credentials::install_sql(DA),
        ),
        (
            "credential-tasks-v1",
            rss_mdm_recovery_credentials::tasks_sql(DA),
        ),
        (
            "credential-relations-v1",
            rss_mdm_recovery_credentials::task_relations_sql(DA),
        ),
        (
            "identity-proof-v1",
            rss_mdm_device_access_postgres::PROOF_SQL,
        ),
        (
            "host-grants-v1",
            include_str!("../schema/install-grants.sql"),
        ),
    ]
}
pub fn manifests() -> Vec<&'static str> {
    vec![
        rss_mdm_vault_sync::OBJECTS,
        rss_mdm_authorization_service::installation::DA_OBJECT_MANIFEST,
        rss_mdm_registration_service::identity_object_manifest(DA),
        rss_mdm_registration_service::DA_IDENTITY_PROJECTION_MANIFEST,
        rss_mdm_authorization_service::object_manifest(DA),
        rss_mdm_pki_service::object_manifest(DA),
        rss_mdm_task_trust::object_manifest(DA),
        rss_mdm_policy_postgres::object_manifest(DA),
        rss_mdm_recovery_credentials::object_manifest(DA),
        rss_mdm_device_access_postgres::admission::OBJECTS,
    ]
}

/// Product binding is supplied by the authenticated installation owner, never an HTTP request.
pub struct Composition {
    pub instance: uuid::Uuid,
    pub management_tenant: uuid::Uuid,
}
impl Host for Composition {
    fn check_existing<'a>(
        &'a self,
        c: &'a mut PgConnection,
        receipts: &'a [Receipt],
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if self.instance.is_nil() || self.management_tenant.is_nil() {
                return Err(Error::at("da", "installation identity"));
            }
            if receipts
                .iter()
                .any(|(name, _, _)| name == "authorization-installation-v1")
            {
                let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_da.authorization_installation WHERE instance_id=$1 AND management_tenant_id=$2)").bind(self.instance).bind(self.management_tenant).fetch_one(c).await.map_err(|_| Error::at("da", "installation identity"))?;
                if !valid {
                    return Err(Error::at("da", "installation binding mismatch"));
                }
            }
            Ok(())
        })
    }
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        (name, sql): Unit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            execute_schema(tx, name, sql, "DA owner schema").await?;
            if name == "authorization-installation-v1" {
                rss_mdm_authorization_service::installation::bind_da_in(
                    tx,
                    self.instance,
                    self.management_tenant,
                )
                .await
                .map_err(|_| Error::at(name, "authorization installation"))?;
            }
            Ok(())
        })
    }
    fn verify<'a>(&'a self, c: &'a mut PgConnection) -> Pending<'a, ()> {
        Box::pin(async move {
            verify_catalog(c)
                .await
                .map_err(|_| Error::at("da", "complete owner catalog"))
        })
    }
}
pub async fn verify_catalog(c: &mut PgConnection) -> Result<(), sqlx::Error> {
    rss_mdm_install_support::catalog::verify_schema(c, DA, &manifests()).await?;
    rss_mdm_vault_sync::verify_catalog(c).await?;
    rss_mdm_device_access_postgres::admission::verify_authority(c).await
}
/// Owner contracts are common; each host adds only its actual integration grants.
pub fn access_contracts() -> Vec<&'static str> {
    vec![
        rss_mdm_registration_service::identity_access_contract(DA),
        rss_mdm_authorization_service::access_contract(DA),
        rss_mdm_task_trust::access_contract(DA),
        rss_mdm_pki_service::access_contract(DA),
        rss_mdm_policy_postgres::device_access::ACCESS_CONTRACT,
        rss_mdm_recovery_credentials::access_contract(DA),
        rss_mdm_device_access_postgres::admission::ACCESS_CONTRACT,
        rss_mdm_audit_integration::ACCESS_CONTRACT,
        include_str!("../schema/access.json"),
    ]
}

/// Standalone components precede the exact same DA-owned units used by MDM.
pub fn standalone_units(ledger: bool) -> Vec<Unit> {
    let mut result = vec![("audit-v1", rss_audit_postgres::MIGRATION_SQL)];
    if ledger {
        result.push(("audit-ledger-v1", rss_ledger_postgres::MIGRATION_SQL));
    }
    result.extend([
        ("observation-v1", rss_observation_postgres::MIGRATION_SQL),
        ("projection-v1", rss_projection_postgres::MIGRATION_SQL),
        (
            "messaging-v1",
            rss_transactional_messaging_postgres::MIGRATION_SQL,
        ),
        ("identity-v1", rss_identity_postgres::MIGRATION_SQL),
    ]);
    result.extend(units());
    result.push((
        "standalone-grants-v1",
        include_str!("../schema/standalone-grants.sql"),
    ));
    if ledger {
        result.push((
            "standalone-ledger-grants-v1",
            include_str!("../schema/standalone-ledger.sql"),
        ));
    }
    result
}
pub struct Standalone {
    pub product: Composition,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub tenants: Vec<(rss_request_context::TenantId, i64)>,
    pub ledger: bool,
}
impl Standalone {
    pub fn binding(&self) -> Result<rss_mdm_install_support::Binding, Error> {
        let configuration = serde_json::to_string(&(
            "da-standalone-v1",
            self.product.management_tenant,
            self.ledger,
            self.tenants
                .iter()
                .map(|(t, e)| (t.to_string(), *e))
                .collect::<Vec<_>>(),
        ))
        .map_err(|_| Error::at("da", "configuration"))?;
        rss_mdm_install_support::Binding::new(
            DA,
            self.product.instance,
            self.target,
            self.lineage,
            configuration,
        )
    }
}
impl Host for Standalone {
    fn check_existing<'a>(&'a self, c: &'a mut PgConnection, r: &'a [Receipt]) -> Pending<'a, ()> {
        self.product.check_existing(c, r)
    }
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        (name, sql): Unit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if matches!(name, "audit-v1" | "audit-ledger-v1") {
                let role = if name == "audit-v1" {
                    "mdm_audit_owner"
                } else {
                    "mdm_ledger_owner"
                };
                sqlx::query("SELECT set_config('role',$1,true)")
                    .bind(role)
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| Error::at(name, "component owner"))?;
                execute_schema(tx, name, sql, "component schema").await?;
                sqlx::query("SET LOCAL ROLE da_owner")
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| Error::at(name, "restore installer"))?;
            } else if name == "identity-v1" {
                let instance =
                    rss_identity_core::InstanceId::parse(&self.product.instance.to_string())
                        .map_err(|_| Error::at(name, "instance"))?;
                rss_identity_postgres::install(tx, instance)
                    .await
                    .map_err(|_| Error::at(name, "Identity installation"))?;
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
                        .map_err(|_| Error::at(name, "Identity grants"))?;
                }
                rss_identity_postgres::grant_platform_subject_admission(tx, "da_access")
                    .await
                    .map_err(|_| Error::at(name, "subject admission"))?;
            } else {
                self.product.apply(tx, (name, sql)).await?;
                if name == "messaging-v1" {
                    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES($1,$2)").bind(self.target.as_slice()).bind(self.lineage.as_slice()).execute(&mut **tx).await.map_err(|_|Error::at(name,"storage lineage"))?;
                    for (tenant, epoch) in &self.tenants {
                        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                            .bind(tenant.to_string())
                            .execute(&mut **tx)
                            .await
                            .map_err(|_| Error::at(name, "tenant context"))?;
                        sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,$2)").bind(tenant.to_string()).bind(epoch).execute(&mut **tx).await.map_err(|_|Error::at(name,"tenant fencing"))?;
                    }
                }
            }
            Ok(())
        })
    }
    fn verify<'a>(&'a self, c: &'a mut PgConnection) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_install_support::verify_manifest(c, DA, &standalone_units(self.ledger))
                .await
                .map_err(|_| Error::at("da", "complete standalone manifest"))?;
            self.product.verify(c).await
        })
    }
}
pub async fn verify_standalone_access(
    c: &mut PgConnection,
    ledger: bool,
) -> Result<(), sqlx::Error> {
    rss_mdm_install_support::verify_manifest(c, DA, &standalone_units(ledger)).await?;
    verify_catalog(c).await?;
    let mut contracts = access_contracts();
    contracts.push(r#"{"tables":[],"functions":[],"external_relations":["public.da_restore_operation"],"verified_schemas":[]}"#);
    if ledger {
        contracts.push(r#"{"tables":[],"functions":[{"name":"rss_ledger.prepare_append","search_path":"search_path=pg_catalog, rss_ledger"},{"name":"rss_ledger.insert_entry","search_path":"search_path=pg_catalog, rss_ledger"}],"external_relations":["rss_ledger.heads","rss_ledger.entries"],"verified_schemas":[]}"#);
    }
    if !rss_mdm_install_support::access_admission::verify(c, "da_access", &contracts).await? {
        return Err(sqlx::Error::Protocol(
            "DA standalone access rejected".into(),
        ));
    }
    Ok(())
}

pub const ROLES_SQL: &str = include_str!("../schema/roles.sql");
