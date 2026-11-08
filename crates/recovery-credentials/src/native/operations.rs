//! Closed native credential operations reuse the command transaction, queue and authority.
use super::{
    authority::Authority,
    authorization::{Permission, context::AuthorizedPrincipal},
    *,
};
use crate::{self as credentials, Binding, Subject, storage as vault};
use base64::Engine;
use rss_mdm_apple_mdm::native::{
    input::{CommandInput, FieldValue, Fields},
    request::Request,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    ConfigureFilevault,
    ReconcileFilevault {
        material: Version,
        recipient: Option<String>,
    },
    CollectFilevault {
        expected_revision: i64,
        recipient: Option<String>,
    },
    RotateFilevault {
        expected_revision: i64,
        #[schemars(with = "String")]
        unlock_password: Zeroizing<String>,
    },
    SetRecoveryLock {
        expected_revision: i64,
        current: Option<Version>,
        clear: bool,
    },
    ReconcileRecoveryLock {
        material: Version,
        operation: Uuid,
    },
    VerifyRecoveryLock {
        material: Version,
    },
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Version {
    pub id: Uuid,
    pub version: i64,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub operation_id: Uuid,
    pub deadline: i64,
    pub action: Action,
}
impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryOperation([REDACTED])")
    }
}
pub(crate) fn error(value: credentials::Error) -> Error {
    match value {
        credentials::Error::Malformed => Error::Malformed,
        credentials::Error::Forbidden => Error::Forbidden,
        credentials::Error::Unauthorized => Error::Unauthorized,
        credentials::Error::NotFound => Error::NotFound,
        credentials::Error::Conflict => Error::Conflict,
        credentials::Error::ReadConflict => Error::ReadConflict,
        credentials::Error::CursorInvalidated => Error::CursorInvalidated,
        credentials::Error::Unsupported => Error::Unsupported,
        credentials::Error::CommitUnknown => Error::CommitUnknown,
        credentials::Error::RollbackFailed => Error::RollbackFailed,
        _ => Error::Unavailable(Failure::NativeProtection),
    }
}
impl Service {
    pub async fn create_recovery_credential(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &Input,
        audit: &RequestAudit,
    ) -> std::result::Result<super::AcceptedReceipt, Error> {
        proof.require(Permission::SecurityOperate, Some(device))?;
        proof.bind_audit(audit)?;
        audit.operation(
            input.operation_id,
            "command_accept",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);
        let protection = &self.transactions.materials.credentials;
        if input.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        transaction::run(
            &self.transactions.audit_store,
            &self.transactions.runtime,
            self.transactions.tenant,
            audit,
            (self, proof, device, input, audit, protection),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, proof, device, input, audit, protection) = *ctx;
                    if proof.tenant_id() != service.transactions.tenant.to_string() {
                        return Err(Error::Forbidden.into());
                    }

                    let mut permissions = vec![Permission::SecurityOperate];
                    if matches!(input.action, Action::ConfigureFilevault) {
                        permissions.push(Permission::ConfigurationWrite);
                    }
                    let snapshot =
                        storage::authorized_native(tx, proof, device, &permissions).await?;
                    storage::lock_request(tx, input.operation_id).await?;
                    super::action_admission::lock_device(tx, device).await?;
                    super::transaction::prepare_audit_in(
                        &service.transactions.audit_store,
                        tx,
                        audit,
                        &[],
                    )
                    .await?;
                    service
                        .transactions
                        .reconcile_messaging
                        .wake_in(
                            tx,
                            &super::service::target(service.transactions.tenant, device),
                            &rss_reconcile::ResourceSet::empty(service.transactions.tenant),
                            (),
                            |_, _| Box::pin(async { Ok(()) }),
                        )
                        .await?;
                    super::worker_wake::notify_in(tx, super::worker_wake::Work::CommandRecovery)
                        .await?;

                    let fingerprint = super::protection::fingerprint(
                        &service.transactions.protection,
                        service.transactions.tenant,
                        device,
                        "recovery-credential-create/v1",
                        &(proof.actor(), input),
                    )?;
                    if let Some(value) =
                        super::service::replay(tx, input.operation_id, &fingerprint, audit).await?
                    {
                        return super::transaction::stored(serde_json::from_value(value));
                    }
                    super::service::reject_existing_operation(tx, input.operation_id).await?;
                    storage::current_registration(tx, device).await?;
                    if let Action::ReconcileRecoveryLock { operation, .. } = &input.action {
                        let original =
                            storage::load(tx, &service.transactions.protection, *operation).await?;
                        if original.device != device
                            || !service
                                .transactions
                                .required_command(tx, &original)
                                .await?
                                .status()
                                .is_terminal()
                        {
                            return Err(Error::Conflict.into());
                        }
                    }
                    let tenant = Uuid::parse_str(&service.transactions.tenant.to_string())
                        .map_err(|_| Error::Malformed)?;
                    let prepared_protection = protection.clone();
                    let prepared_device = device.to_owned();
                    let prepared_input = input.clone();
                    let (request, link) = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(prepare(
                                    c,
                                    &prepared_protection,
                                    tenant,
                                    &prepared_device,
                                    &prepared_input,
                                )
                                .await)
                            })
                        })
                        .await?
                        .map_err(error)?;
                    let native = Create {
                        operation_id: input.operation_id,
                        input_version: "recovery-credential/v1".into(),
                        target: NativeTarget::Device,
                        task: Task::Macos { request },
                        deadline: input.deadline,
                    };
                    let required = native.task.permissions()?;
                    for permission in &required {
                        snapshot.require(proof, *permission, Some(device))?;
                    }
                    let mut permissions = required.clone();
                    permissions.push(Permission::SecurityOperate);
                    permissions.sort();
                    permissions.dedup();
                    let authority = Authority::admitted(
                        &snapshot,
                        proof,
                        device,
                        input.operation_id,
                        permissions,
                    )?;
                    let result = service
                        .transactions
                        .queue_authorized_in(tx, device, &native, authority, fingerprint, audit)
                        .await?;
                    let binding = Binding {
                        device: device.into(),

                        subject: Subject::RecoveryLock,
                    };
                    {
                        let operation = input.operation_id;
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(vault::link_native_in(
                                    crate::Custody::new(
                                        rss_mdm_install_support::StorageProfile::Mdm,
                                        None,
                                    ),
                                    c,
                                    tenant,
                                    operation,
                                    &binding,
                                    &link,
                                )
                                .await)
                            })
                        })
                    }
                    .await?
                    .map_err(error)?;
                    proof.check_live()?;
                    Ok(result)
                })
            },
        )
        .await
    }
}
fn text(value: impl Into<String>) -> FieldValue {
    FieldValue::String(value.into())
}
fn command(name: &str, values: Vec<(&str, FieldValue)>) -> Request {
    Request::Command {
        command: CommandInput {
            request_type: name.into(),
            fields: Fields(values.into_iter().map(|(k, v)| (k.into(), v)).collect()),
        },
    }
}
async fn prepare(
    c: &mut sqlx::PgConnection,
    protection: &credentials::Protection,
    tenant: Uuid,
    device: &str,
    input: &Input,
) -> std::result::Result<(Request, vault::NativeAction), credentials::Error> {
    use credentials::Error as E;
    let recipient = protection.active_recipient();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await?;
    recipient.require_current(now)?;
    let mut link = vault::NativeAction {
        reconciles: None,
        action: String::new(),
        coordinates: None,
        recipient: recipient.id().into(),
    };
    let filevault = if matches!(
        input.action,
        Action::ConfigureFilevault
            | Action::CollectFilevault { .. }
            | Action::RotateFilevault { .. }
            | Action::ReconcileFilevault { .. }
    ) {
        credentials::filevault::source_binding(
            c,
            &credentials::filevault::Source {
                tenant,
                device: device.into(),
            },
            true,
        )
        .await?
    } else {
        None
    };
    let binding = |subject| Binding {
        device: device.into(),

        subject,
    };
    let reserve = async |c: &mut sqlx::PgConnection, subject: Subject, expected: i64| {
        vault::reserve_in(
            crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
            c,
            tenant,
            &binding(subject),
            input.operation_id,
            expected,
        )
        .await
    };
    let request = match &input.action {
        Action::ConfigureFilevault => {
            use rss_mdm_apple_mdm::native::profiles::{PayloadInput, ProfileInput};
            link.action = "configure_filevault".into();
            let cert_id = Uuid::new_v4();
            let prefix = format!("rss.recovery.{tenant}");
            Request::InstallProfile {
                profile: ProfileInput {
                    identifier: format!("{prefix}.filevault"),
                    uuid: Uuid::new_v4(),
                    metadata: Fields::default(),
                    payloads: vec![
                        PayloadInput {
                            schema: "mdm/profiles/com.apple.security.pkcs1.yaml".into(),
                            identifier: format!("{prefix}.recipient"),
                            uuid: cert_id,
                            metadata: Fields::default(),
                            fields: Fields::from_plist(&plist::Dictionary::from_iter([(
                                "PayloadContent",
                                plist::Value::Data(recipient.certificate_der()?),
                            )]))
                            .map_err(|_| E::Malformed)?,
                        },
                        PayloadInput {
                            schema: "mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml"
                                .into(),
                            identifier: format!("{prefix}.escrow"),
                            uuid: Uuid::new_v4(),
                            metadata: Fields::default(),
                            fields: Fields(
                                [
                                    ("Location".into(), text("RSS MDM")),
                                    ("EncryptCertPayloadUUID".into(), text(cert_id.to_string())),
                                ]
                                .into(),
                            ),
                        },
                    ],
                },
            }
        }
        Action::ReconcileFilevault {
            material,
            recipient: selected,
        } => {
            let coordinates = credentials::filevault::material_coordinates(
                c,
                tenant,
                filevault.as_ref().ok_or(E::Conflict)?,
                material.id,
                material.version,
            )
            .await?;
            if filevault.as_ref() != Some(&coordinates.binding) {
                return Err(E::Conflict);
            }
            link.action = "collect_filevault".into();
            if let Some(selected) = selected {
                link.recipient = protection.recipient(selected)?.id().into();
            }
            link.coordinates = Some(coordinates);
            command("SecurityInfo", vec![])
        }
        Action::CollectFilevault {
            expected_revision,
            recipient: selected,
        } => {
            link.action = "collect_filevault".into();
            if let Some(selected) = selected {
                link.recipient = protection.recipient(selected)?.id().into();
            }
            link.coordinates = Some(
                vault::reserve_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    filevault.as_ref().ok_or(E::Conflict)?,
                    input.operation_id,
                    *expected_revision,
                )
                .await?,
            );
            command("SecurityInfo", vec![])
        }
        Action::RotateFilevault {
            expected_revision,
            unlock_password,
        } => {
            if unlock_password.is_empty() || unlock_password.len() > 4096 {
                return Err(E::Malformed);
            }
            link.action = "rotate_filevault".into();
            link.coordinates = Some(
                vault::reserve_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    filevault.as_ref().ok_or(E::Conflict)?,
                    input.operation_id,
                    *expected_revision,
                )
                .await?,
            );
            command(
                "RotateFileVaultKey",
                vec![
                    ("KeyType", text("personal")),
                    (
                        "FileVaultUnlock",
                        FieldValue::Dictionary(Fields(
                            [("Password".into(), text(unlock_password.as_str()))].into(),
                        )),
                    ),
                    (
                        "ReplyEncryptionCertificate",
                        FieldValue::Data(
                            base64::engine::general_purpose::STANDARD
                                .encode(recipient.certificate_der()?),
                        ),
                    ),
                ],
            )
        }
        Action::SetRecoveryLock {
            expected_revision,
            current,
            clear,
        } => {
            let mut fields = Vec::new();
            if let Some(current) = current {
                let old = vault::coordinates_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    device,
                    current.id,
                    current.version,
                )
                .await?;
                if old.binding != binding(Subject::RecoveryLock) {
                    return Err(E::Conflict);
                }
                let value = vault::secret_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    &protection.keys,
                    &old,
                )
                .await?;
                fields.push((
                    "CurrentPassword",
                    text(std::str::from_utf8(value.expose()).map_err(|_| E::Integrity)?),
                ));
                if *clear {
                    link.coordinates = Some(old);
                }
            } else if *clear {
                return Err(E::Malformed);
            }
            if *clear {
                link.action = "clear_recovery_lock".into();
                fields.push(("NewPassword", text("")));
            } else {
                link.action = "set_recovery_lock".into();
                let coordinates = reserve(c, Subject::RecoveryLock, *expected_revision).await?;
                let mut random = Zeroizing::new([0u8; 32]);
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), random.as_mut())
                    .map_err(|_| E::Integrity)?;
                let password = Zeroizing::new(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random.as_ref()),
                );
                vault::ingest_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    &protection.keys,
                    &coordinates,
                    input.operation_id,
                    password.as_bytes(),
                )
                .await?;
                fields.push(("NewPassword", text(password.as_str())));
                link.coordinates = Some(coordinates);
            }
            command("SetRecoveryLock", fields)
        }
        Action::VerifyRecoveryLock { material }
        | Action::ReconcileRecoveryLock { material, .. } => {
            link.action = "verify_recovery_lock".into();
            let coordinates = vault::coordinates_in(
                crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                c,
                tenant,
                device,
                material.id,
                material.version,
            )
            .await?;
            if coordinates.binding != binding(Subject::RecoveryLock) {
                return Err(E::Conflict);
            }
            if let Action::ReconcileRecoveryLock { operation, .. } = &input.action {
                let original = vault::native_action_in(
                    crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                    c,
                    tenant,
                    *operation,
                    device,
                )
                .await?
                .ok_or(E::Conflict)?;
                if original.action != "set_recovery_lock"
                    || original.coordinates.as_ref().is_none_or(|v| {
                        v.material != coordinates.material || v.version != coordinates.version
                    })
                {
                    return Err(E::Conflict);
                }
                link.reconciles = Some(*operation);
            }
            let value = vault::secret_in(
                crate::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None),
                c,
                &protection.keys,
                &coordinates,
            )
            .await?;
            let request = command(
                "VerifyRecoveryLock",
                vec![(
                    "Password",
                    text(std::str::from_utf8(value.expose()).map_err(|_| E::Integrity)?),
                )],
            );
            link.coordinates = Some(coordinates);
            request
        }
    };
    Ok((request, link))
}
