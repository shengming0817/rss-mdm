//! Recovery validity is settled from an accepted, precisely correlated native receipt.
//! The protocol owner calls this participant on its original transaction connection.
use crate::{Error, Protection, storage as vault};
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    Acknowledged,
    Error,
    Pending,
}
/// Material capability; it owns no command runtime or business service.
pub struct NativeReceipts {
    protection: Arc<Protection>,
}
impl NativeReceipts {
    pub fn new(protection: Arc<Protection>) -> Self {
        Self { protection }
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "exact tenant, registration and operation receipt identity"
    )]
    pub async fn receive_in(
        &self,
        c: &mut PgConnection,
        tenant: Uuid,
        operation: Uuid,
        device: &rss_mdm_agent_wire::DeviceId,
        report: &plist::Dictionary,
        status: ReceiptStatus,
    ) -> Result<(), Error> {
        let Some(action) = vault::native_action_in(
            crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
            c,
            tenant,
            operation,
            device,
        )
        .await?
        else {
            return Ok(());
        };
        if status != ReceiptStatus::Acknowledged {
            if status == ReceiptStatus::Error {
                vault::unknown_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    operation,
                )
                .await?;
            }
            return Ok(());
        }
        let Some(coordinates) = action.coordinates else {
            return Ok(());
        };
        match action.action.as_str() {
            "collect_filevault" | "rotate_filevault" => {
                let value = if action.action == "collect_filevault" {
                    report
                        .get("SecurityInfo")
                        .and_then(plist::Value::as_dictionary)
                        .and_then(|v| v.get("FDE_PersonalRecoveryKeyCMS"))
                } else {
                    report
                        .get("RotateResult")
                        .and_then(plist::Value::as_dictionary)
                        .and_then(|v| v.get("EncryptedNewRecoveryKey"))
                };
                let Some(cms) = value.and_then(plist::Value::as_data) else {
                    vault::unknown_in(
                        crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                        c,
                        tenant,
                        operation,
                    )
                    .await?;
                    return Ok(());
                };
                let source_operation = vault::source_operation_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    &coordinates,
                )
                .await?;
                let value = crate::filevault::receive_reserved_cms(
                    c,
                    &self.protection,
                    &coordinates,
                    source_operation,
                    &action.recipient,
                    cms,
                )
                .await?;
                vault::replace_native_coordinates_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    operation,
                    &value,
                )
                .await?;
            }
            "verify_recovery_lock" => {
                if report
                    .get("PasswordVerified")
                    .and_then(plist::Value::as_boolean)
                    == Some(true)
                {
                    let operation = vault::source_operation_in(
                        crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                        c,
                        &coordinates,
                    )
                    .await?;
                    if let Some(original) = action.reconciles {
                        vault::reconcile_in(
                            crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                            c,
                            &coordinates,
                            original,
                        )
                        .await?;
                    } else {
                        vault::verify_in(
                            crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                            c,
                            &coordinates,
                            operation,
                        )
                        .await?;
                    }
                } else {
                    vault::uncertain_version_in(
                        crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                        c,
                        &coordinates,
                    )
                    .await?;
                }
            }
            "clear_recovery_lock" => {
                vault::cleared_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    &coordinates,
                )
                .await?;
            }
            "set_recovery_lock" => {
                vault::unknown_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    operation,
                )
                .await?;
            }
            "lock_pin" => {
                vault::settled_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    &coordinates,
                    operation,
                )
                .await?;
            }
            _ => return Err(Error::Malformed),
        }
        Ok(())
    }
}
