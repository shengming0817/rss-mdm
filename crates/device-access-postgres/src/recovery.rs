pub mod credential_tasks;
pub mod eligibility;
// Material participation in the original DA transaction.
use crate::{
    Pending,
    device_access::{
        self as access,
        participants::{AccessRecovery, BindingDisposition},
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_recovery_credentials::{
    Binding, Coordinates, Error, Protection, Subject, Validity, storage,
};
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub struct AccessMaterials {
    protection: Arc<Protection>,
    eligibility: Arc<dyn rss_mdm_recovery_credentials::eligibility::Eligibility>,
}
impl AccessMaterials {
    pub fn custody(&self) -> rss_mdm_recovery_credentials::Custody<'_> {
        rss_mdm_recovery_credentials::Custody::new(self.profile(), Some(self.eligibility.as_ref()))
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        rss_mdm_install_support::StorageProfile::Da
    }
    pub fn new(
        protection: Arc<Protection>,
        eligibility: Arc<dyn rss_mdm_recovery_credentials::eligibility::Eligibility>,
    ) -> Self {
        Self {
            protection,
            eligibility,
        }
    }
}
fn error(e: Error) -> crate::Error {
    use crate::Error as R;
    match e {
        Error::Malformed => R::Malformed,
        Error::Unauthorized => R::Unauthorized,
        Error::Forbidden => R::Forbidden,
        Error::NotFound => R::NotFound,
        Error::Conflict => R::Conflict,
        Error::Integrity => R::Corrupt,
        Error::CommitUnknown => R::CommitUnknown,
        Error::RollbackFailed => R::RollbackFailed,
        _ => R::Storage,
    }
}
fn subject(value: &wire::CredentialSubject) -> Result<Subject, Error> {
    match value {
        wire::CredentialSubject::RssLogin {
            binding,
            binding_generation,
            sid,
        } => Ok(Subject::RssLogin {
            binding: *binding,
            binding_generation: *binding_generation,
            sid: sid.clone(),
        }),
        _ => Err(Error::Conflict),
    }
}
fn custody_error(e: crate::Error) -> Error {
    match e {
        crate::Error::Malformed => Error::Malformed,
        crate::Error::Forbidden | crate::Error::Unauthorized => Error::Forbidden,
        crate::Error::NotFound => Error::NotFound,
        crate::Error::Conflict => Error::Conflict,
        crate::Error::Corrupt => Error::Integrity,
        _ => Error::Storage,
    }
}
async fn task_binding(
    c: &mut PgConnection,
    task: &wire::AccessTaskSpec,
    value: &wire::CredentialSubject,
) -> Result<Binding, Error> {
    let wire::CredentialSubject::RssLogin {
        binding,
        binding_generation,
        ..
    } = value
    else {
        return Err(Error::Conflict);
    };
    if *binding != task.binding_id || *binding_generation != task.binding_generation {
        return Err(Error::Conflict);
    }
    let b = access::storage::locked_in(c, task.tenant_id, task.binding_id)
        .await
        .map_err(custody_error)?;
    let agent = crate::delivery::for_binding_on(c, &b)
        .await
        .map_err(custody_error)?
        .ok_or(Error::Forbidden)?;
    if agent.device != task.device_id || b.generation != task.binding_generation {
        return Err(Error::Conflict);
    }
    Ok(Binding {
        device: b.device,

        subject: subject(value)?,
    })
}
impl AccessRecovery for AccessMaterials {
    fn plan<'a>(
        &'a self,
        c: &'a mut PgConnection,
        b: &'a access::Binding,
        now: i64,
    ) -> Pending<'a, wire::AccessWindowsPlan> {
        Box::pin(async move {
            async {
                let expected = match &b.account {
                    Some(wire::AccessAccount::Windows { sid, .. }) => {
                        Some(wire::CredentialSubject::RssLogin {
                            binding: b.id,
                            binding_generation: b.generation,
                            sid: sid.clone(),
                        })
                    }
                    _ => None,
                };
                if let Some(wire::AccessWindowsFacts::RssFactor(facts)) = &b.applied_windows
                    && facts.factor_generation == b.factor_generation
                    && expected.as_ref() == Some(&facts.recovery.subject)
                {
                    let binding = Binding {
                        device: b.device.clone(),

                        subject: subject(&facts.recovery.subject)?,
                    };
                    let current = storage::current_in(self.custody(), c, b.tenant, &binding)
                        .await?
                        .ok_or(Error::Conflict)?;
                    if current.validity != Validity::Verified || !current.escrowed {
                        return Err(Error::Conflict);
                    }
                    let mut facts = facts.clone();
                    facts.recovery.material = current.id;
                    facts.recovery.version = current.version;
                    return Ok(wire::AccessWindowsPlan::Preserve { facts });
                }
                let recipient = self.protection.active_recipient();
                recipient.require_current(now)?;
                let recipient = wire::CredentialRecipient {
                    key_id: recipient.id().into(),
                    public_key: STANDARD.encode(recipient.public_key_der()?),
                };
                let expected_revision = if let Some(subject) = expected {
                    let subject = self::subject(&subject)?;
                    storage::revisions_in(self.custody(), c, b.tenant, &b.device)
                        .await?
                        .into_iter()
                        .find(|(s, _)| s == &subject)
                        .map(|(_, revision)| revision)
                        .unwrap_or(0)
                } else {
                    0
                };
                Ok(wire::AccessWindowsPlan::Initialize {
                    recipient,
                    expected_revision,
                })
            }
            .await
            .map_err(error)
        })
    }
    fn escrow<'a>(
        &'a self,
        c: &'a mut PgConnection,
        task: &'a wire::AccessTaskSpec,
        value: &'a wire::CredentialEscrow,
    ) -> Pending<'a, Vec<wire::CredentialReceipt>> {
        Box::pin(async move {
            async {
            value.validate().map_err(|_| Error::Malformed)?;
            if value.materials.len() != 1 || value.definition_digest != task.definition_digest { return Err(Error::Conflict) }
            let Some(wire::AccessWindowsPlan::Initialize { recipient, .. }) = &task.windows else { return Err(Error::Conflict) };
            let item = &value.materials[0];
            let aad = task.material_aad(&item.subject, item.expected_revision).map_err(|_| Error::Malformed)?;
            let secret = self.protection.recipient(&recipient.key_id)?.open_envelope(
                &STANDARD.decode(&item.wrapped_key).map_err(|_| Error::Malformed)?, item.nonce,
                &STANDARD.decode(&item.ciphertext).map_err(|_| Error::Malformed)?, &aad)?;
            let b = access::storage::locked_in(c, task.tenant_id, task.binding_id).await.map_err(custody_error)?;
            let wire::CredentialSubject::RssLogin { sid, .. } = &item.subject else { return Err(Error::Conflict) };
            if b.generation != task.binding_generation || b.factor_generation != task.factor_generation
                || b.revision != task.revision || b.definition_digest().map_err(custody_error)? != task.definition_digest
                || !matches!(&b.account, Some(wire::AccessAccount::Windows { sid: current, .. }) if current == sid) { return Err(Error::Conflict) }
            let binding = task_binding(c, task, &item.subject).await?;
            let coordinates = storage::reserve_in(self.custody(), c, task.tenant_id, &binding, task.task_id, item.expected_revision).await?;
            storage::ingest_in(self.custody(), c, &self.protection.keys, &coordinates, task.task_id, &secret).await?;
            storage::link_agent_in(self.custody(), c, task.task_id, task.attempt_id, &coordinates).await?;
            Ok(vec![wire::CredentialReceipt { subject: item.subject.clone(), material: coordinates.material, version: coordinates.version }])
        }.await.map_err(error)
        })
    }
    fn settle<'a>(
        &'a self,
        c: &'a mut PgConnection,
        task: &'a wire::AccessTaskSpec,
        facts: &'a wire::AccessRssFacts,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            async {
                let binding = task_binding(c, task, &facts.recovery.subject).await?;
                let coordinates = storage::coordinates_in(
                    self.custody(),
                    c,
                    task.tenant_id,
                    &binding.device,
                    facts.recovery.material,
                    facts.recovery.version,
                )
                .await?;
                if coordinates.binding != binding {
                    return Err(Error::Conflict);
                }
                match &task.windows {
                    Some(wire::AccessWindowsPlan::Initialize { .. }) => {
                        let stored = storage::agent_materials_in(
                            self.custody(),
                            c,
                            task.tenant_id,
                            task.task_id,
                            task.attempt_id,
                        )
                        .await?;
                        if stored.len() != 1
                            || stored[0].id != coordinates.material
                            || stored[0].version != coordinates.version
                        {
                            return Err(Error::Conflict);
                        }
                        storage::verify_in(self.custody(), c, &coordinates, task.task_id).await?;
                    }
                    Some(wire::AccessWindowsPlan::Preserve { facts: expected })
                        if facts == expected =>
                    {
                        let current =
                            storage::current_in(self.custody(), c, task.tenant_id, &binding)
                                .await?
                                .ok_or(Error::Conflict)?;
                        if current.id != coordinates.material
                            || current.version != coordinates.version
                            || current.validity != Validity::Verified
                            || !current.escrowed
                        {
                            return Err(Error::Conflict);
                        }
                    }
                    _ => return Err(Error::Conflict),
                }
                Ok(())
            }
            .await
            .map_err(error)
        })
    }
    fn unresolved<'a>(
        &'a self,
        c: &'a mut PgConnection,
        task: &'a wire::AccessTaskSpec,
        disposition: BindingDisposition,
        terminal: bool,
    ) -> Pending<'a, bool> {
        let profile = self.profile();

        Box::pin(async move {
            async {
                let values = storage::agent_materials_in(
                    self.custody(),
                    c,
                    task.tenant_id,
                    task.task_id,
                    task.attempt_id,
                )
                .await?;
                if matches!(disposition, BindingDisposition::Withdrawn) {
                    if terminal {
                        for v in values {
                            storage::settled_in(
                                self.custody(),
                                c,
                                &Coordinates {
                                    profile,
                                    tenant: task.tenant_id,
                                    material: v.id,
                                    version: v.version,
                                    binding: v.binding,
                                },
                                v.operation,
                            )
                            .await?;
                        }
                    }
                    return Ok(false);
                }
                Ok(values.iter().any(|v| v.validity != Validity::Verified))
            }
            .await
            .map_err(error)
        })
    }
    fn unknown<'a>(&'a self, c: &'a mut PgConnection, tenant: Uuid, run: Uuid) -> Pending<'a, ()> {
        Box::pin(async move {
            storage::unknown_in(self.custody(), c, tenant, run)
                .await
                .map_err(error)
        })
    }
    fn unbound<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        binding: Uuid,
        generation: i64,
        revision: i64,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let b = access::storage::locked_observation_in(c, tenant, binding).await?;
            if b.state != rss_mdm_device_access::State::Revoked
                || b.generation != generation
                || b.revision != revision
                || b.applied_revision != Some(revision)
                || !matches!(b.effect, Some(wire::AccessEffect::Unbound { .. }))
            {
                return Err(crate::Error::Conflict);
            }
            storage::access_unbound_in(
                self.custody(),
                c,
                &rss_mdm_recovery_credentials::eligibility::Unbound {
                    tenant,
                    device: b.device,

                    binding,
                    generation,
                },
            )
            .await
            .map_err(error)
        })
    }
}

impl crate::Service {
    pub async fn record_access_recovery_use(
        &self,
        device: &rss_mdm_registration_service::DevicePrincipal,
        input: &wire::AccessRecoveryUse,
        audit: &rss_mdm_audit_integration::RequestAudit,
    ) -> Result<(), crate::Error> {
        if device.tenant() != self.tenant {
            return Err(crate::Error::Forbidden);
        }
        input.validate().map_err(|_| crate::Error::Malformed)?;
        audit.operation(
            input.operation_id,
            "device_access_recovery_use",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(audit, (device, input), |ctx, c| {
            Box::pin(async move {
                let endpoint = crate::delivery::resolve_on(c, ctx.0).await?;
                let anchor = rss_mdm_registration_service::device::endpoints::DaRegistration {
                    device: endpoint.device().into(),
                };
                let tenant = Uuid::parse_str(&endpoint.tenant().to_string())
                    .map_err(|_| crate::Error::Malformed)?;
                let replay = storage::rss_use_in(
                    rss_mdm_recovery_credentials::Custody::new(
                        rss_mdm_install_support::StorageProfile::Da,
                        None,
                    ),
                    c,
                    tenant,
                    &anchor,
                    ctx.1,
                )
                .await
                .map_err(error)?;
                Ok(crate::service::Change { value: (), replay })
            })
        })
        .await
    }
}
