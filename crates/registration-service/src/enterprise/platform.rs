//! One Identity verifier dispatches by trusted native binding provenance, never by browser hints.
use super::*;
use crate::device_access::{Admission, Binding};
use rss_identity_core::InstanceId;
use rss_identity_postgres::platform::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock, Weak},
    time::Duration,
};
type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, PlatformError>> + Send + 'a>>;
pub struct Verifier {
    audience: String,
    tenant: TenantId,
    runtime: Arc<PgRuntime>,
    apple: Option<Arc<dyn PlatformVerifier>>,
    targets: BTreeMap<String, String>,
    admission: OnceLock<Weak<dyn Admission>>,
}
impl Verifier {
    pub fn new(
        origin: &str,
        tenant: TenantId,
        runtime: Arc<PgRuntime>,
        apple: Option<Arc<dyn PlatformVerifier>>,
        targets: BTreeMap<String, String>,
    ) -> Self {
        Self {
            audience: format!("{origin}/login"),
            tenant,
            runtime,
            apple,
            targets,
            admission: OnceLock::new(),
        }
    }
    pub fn bind(&self, admission: Arc<dyn Admission>) -> Result<(), Error> {
        let weak = Arc::downgrade(&admission);
        if let Some(old) = self.admission.get() {
            return if Weak::ptr_eq(old, &weak) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.admission.set(weak).map_err(|_| Error::Conflict)
    }
    fn admission(&self) -> Result<Arc<dyn Admission>, PlatformError> {
        self.admission
            .get()
            .and_then(Weak::upgrade)
            .ok_or(PlatformError::Unavailable)
    }
    async fn binding(&self, c: &mut PgConnection, id: Uuid) -> Result<Binding, PlatformError> {
        let tenant =
            Uuid::parse_str(&self.tenant.to_string()).map_err(|_| PlatformError::Rejected)?;
        crate::admission::lock_in(c, &self.tenant.to_string())
            .await
            .map_err(failure)?;
        let candidate = crate::device_access::storage::get_in(c, tenant, id)
            .await
            .map_err(failure)?;
        let binding =
            crate::device_access::storage::require_active_in(c, tenant, id, candidate.generation)
                .await
                .map_err(failure)?;
        crate::device_access::lifecycle::require_subject_on(c, tenant, &binding.person)
            .await
            .map_err(failure)?;
        let admission = self.admission()?;
        let policy = admission
            .policy(c, tenant, &binding.device, binding.policy)
            .await
            .map_err(failure)?;
        if policy.version != binding.policy_version
            || policy.configuration != binding.configuration
            || !policy.configuration.enabled
        {
            return Err(PlatformError::Rejected);
        }
        admission
            .binding_session(c, tenant, &binding)
            .await
            .map_err(failure)?;
        Ok(binding)
    }
    async fn windows(
        &self,
        c: &mut PgConnection,
        binding: &Binding,
    ) -> Result<(PlatformBinding, WindowsSource), PlatformError> {
        let document: serde_json::Value = sqlx::query_scalar(
            "SELECT document FROM mdm_enterprise.windows_sources WHERE tenant_id=$1 AND binding=$2",
        )
        .bind(binding.tenant)
        .bind(binding.id)
        .fetch_optional(c)
        .await
        .map_err(|_| PlatformError::Unavailable)?
        .ok_or(PlatformError::Rejected)?;
        let source: WindowsSource =
            serde_json::from_value(document).map_err(|_| PlatformError::Unavailable)?;
        if source.binding_id != binding.id
            || source.binding_generation != binding.generation
            || source.factor_generation != binding.factor_generation
            || source.binding_revision != binding.revision
            || source.person != binding.person
            || source.version < 1
        {
            return Err(PlatformError::Rejected);
        }
        let value = PlatformBinding {
            instance: InstanceId::parse(&binding.person.instance.to_string())
                .map_err(|_| PlatformError::Rejected)?,
            account: rss_identity_core::account::AccountKey {
                tenant: self.tenant,
                principal: rss_identity_core::PrincipalId::parse(
                    &binding.person.principal.to_string(),
                )
                .map_err(|_| PlatformError::Rejected)?,
            },
            binding_id: binding.id,
            binding_epoch: binding.generation,
            source_id: source.id,
            source_version: source.version,
            external_identity: None,
        };
        Ok((value, source))
    }
}
fn failure(error: Error) -> PlatformError {
    match error {
        Error::Storage | Error::Runtime | Error::Deadline | Error::Corrupt => {
            PlatformError::Unavailable
        }
        _ => PlatformError::Rejected,
    }
}
impl PlatformVerifier for Verifier {
    fn audience(&self) -> &str {
        &self.audience
    }
    fn resolve<'a>(
        &'a self,
        instance: InstanceId,
        tenant: TenantId,
        id: Uuid,
        c: &'a mut PgConnection,
    ) -> Pending<'a, PlatformBinding> {
        Box::pin(async move {
            if tenant != self.tenant {
                return Err(PlatformError::Rejected);
            }
            let binding = self.binding(c, id).await?;
            if binding.person.instance != instance.as_uuid() {
                return Err(PlatformError::Rejected);
            }
            if binding.intent.platform() == rss_mdm_agent_wire::runtime::TaskPlatform::Windows {
                self.windows(c, &binding).await.map(|v| v.0)
            } else {
                self.apple
                    .as_ref()
                    .ok_or(PlatformError::Unavailable)?
                    .resolve(instance, tenant, id, c)
                    .await
            }
        })
    }
    fn recheck<'a>(
        &'a self,
        subject: &'a PlatformBinding,
        c: &'a mut PgConnection,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if subject.account.tenant != self.tenant {
                return Err(PlatformError::Rejected);
            }
            let binding = self.binding(c, subject.binding_id).await?;
            if binding.intent.platform() == rss_mdm_agent_wire::runtime::TaskPlatform::Windows {
                if self.windows(c, &binding).await?.0 != *subject {
                    return Err(PlatformError::Rejected);
                }
                Ok(())
            } else {
                self.apple
                    .as_ref()
                    .ok_or(PlatformError::Unavailable)?
                    .recheck(subject, c)
                    .await
            }
        })
    }
    fn authorize_purpose<'a>(
        &'a self,
        subject: &'a PlatformBinding,
        purpose: &'a PlatformPurpose,
        c: &'a mut PgConnection,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.recheck(subject, c).await?;
            if let PlatformPurpose::EnterpriseRp(id) = purpose {
                let rp = relying_party_on(
                    c,
                    Uuid::parse_str(&self.tenant.to_string())
                        .map_err(|_| PlatformError::Rejected)?,
                    id,
                )
                .await
                .map_err(failure)?;
                let binding = self.binding(c, subject.binding_id).await?;
                let mode = if binding.configuration.mac.as_ref().is_some_and(|m| {
                    binding.intent.platform() == rss_mdm_agent_wire::runtime::TaskPlatform::Macos
                        && m.authentication
                            == rss_mdm_agent_wire::platform_sso::AuthenticationMode::Password
                }) {
                    ProofKind::Password
                } else {
                    ProofKind::NativeKey
                };
                if !rp.enabled
                    || self.targets.get(id) != Some(&rp.target_fingerprint)
                    || !rp.capabilities.contains(&mode)
                {
                    return Err(PlatformError::Rejected);
                }
            }
            Ok(())
        })
    }
    fn verify<'a>(
        &'a self,
        challenge: &'a PlatformChallengeContext,
        evidence: &'a [u8],
    ) -> Pending<'a, PlatformEvidence> {
        Box::pin(async move {
            let attempt = self
                .runtime
                .local_tx_with_context(
                    self.tenant,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        Duration::from_secs(5),
                    ),
                    (self, challenge),
                    |ctx, tx| {
                        Box::pin(async move {
                            tx.with_connection_context(ctx, |ctx, c| {
                                Box::pin(async move {
                                    let (this, challenge) = ctx;
                                    let admitted =
                                        rss_identity_postgres::platform::admit_platform_subject_on(
                                            c,
                                            challenge.binding.instance,
                                            &challenge.binding,
                                            None,
                                        )
                                        .await;
                                    if let Err(error) = admitted {
                                        return Ok(Err(match error {
                                            PlatformSubjectAdmissionError::Rejected => {
                                                PlatformError::Rejected
                                            }
                                            PlatformSubjectAdmissionError::Storage(_) => {
                                                PlatformError::Unavailable
                                            }
                                        }));
                                    }
                                    let result = async {
                                        let binding =
                                            this.binding(c, challenge.binding.binding_id).await?;
                                        if binding.intent.platform()
                                            == rss_mdm_agent_wire::runtime::TaskPlatform::Windows
                                        {
                                            let (subject, source) =
                                                this.windows(c, &binding).await?;
                                            if subject != challenge.binding {
                                                return Err(PlatformError::Rejected);
                                            }
                                            Ok(Some(source))
                                        } else {
                                            Ok(None)
                                        }
                                    }
                                    .await;
                                    Ok(result)
                                })
                            })
                            .await
                        })
                    },
                )
                .await;
            let source = attempt.fold(
                |v| v,
                |_| Err(PlatformError::Unavailable),
                |_| Err(PlatformError::Unavailable),
                |_| Err(PlatformError::Unavailable),
                |_| Err(PlatformError::Unavailable),
                |_| Err(PlatformError::Unavailable),
            )?;
            if let Some(source) = source {
                if challenge.audience != self.audience {
                    return Err(PlatformError::Rejected);
                }
                let proof: rss_mdm_agent_wire::enterprise::NativeProof =
                    serde_json::from_slice(evidence).map_err(|_| PlatformError::Rejected)?;
                if proof.access_token.is_some() {
                    return Err(PlatformError::Rejected);
                }
                verify_signature(
                    &source.public_key,
                    &proof.signature,
                    &challenge.signing_payload()?,
                )
                .map_err(failure)?;
                Ok(PlatformEvidence {
                    key_possession: true,
                    hardware_key: false,
                    user_presence: false,
                    user_verification: false,
                    authenticated_at: None,
                    profile: PlatformProfile::Unavailable,
                })
            } else {
                self.apple
                    .as_ref()
                    .ok_or(PlatformError::Unavailable)?
                    .verify(challenge, evidence)
                    .await
            }
        })
    }
}
