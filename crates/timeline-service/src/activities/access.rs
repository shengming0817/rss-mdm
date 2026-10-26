use super::model::*;
use crate::{Error, Timeline};
use rss_mdm_audit_integration::activity::ActivityUser;
use rss_mdm_authorization_service::Permission;
use rss_mdm_device_service::planning::{ActivityPair, PlanningObjects};
use rss_mdm_inventory::Channel;
use rss_mdm_registration_service::device::{endpoints, store};
use sqlx::PgConnection;
use uuid::Uuid;
impl Timeline {
    pub(super) async fn activity_scope(
        &self,
        c: &mut PgConnection,
        reader: &Reader<'_>,
    ) -> Result<Scope, Error> {
        let mut reasons = Vec::new();
        let mut personal = None;
        let (device, authority, anchor) = match reader {
            Reader::Management { proof, device } => {
                if proof.tenant_id() != self.tenant.to_string() {
                    return Err(Error::Forbidden);
                }
                proof
                    .check_live()
                    .map_err(crate::service::authorization_error)?;
                rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
                    .await
                    .map_err(crate::service::authorization_error)?;
                let permissions = rss_mdm_authorization_service::snapshot_on(
                    c,
                    proof.tenant_id(),
                    proof.instance_id(),
                )
                .await
                .map_err(crate::service::authorization_error)?;
                permissions
                    .require(proof, Permission::OperationRead, Some(device))
                    .map_err(|_| Error::Forbidden)?;
                let binding = permissions
                    .query_binding(proof)
                    .map_err(crate::service::authorization_error)?;
                (
                    (*device).to_owned(),
                    serde_json::json!([
                        "management",
                        proof.instance_id(),
                        proof.principal_id(),
                        binding
                    ]),
                    None,
                )
            }
            Reader::Agent { device: p, user } => {
                if p.tenant() != self.tenant {
                    return Err(Error::Forbidden);
                }
                store::revalidate_management(c, p)
                    .await
                    .map_err(registration_error)?;
                let binding = rss_mdm_registration_service::agent::current_user::binding_on(
                    c,
                    &self.tenant.to_string(),
                    p.device(),
                )
                .await
                .map_err(registration_error)?;
                let context:Option<serde_json::Value>=sqlx::query_scalar("SELECT execution_context FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=$2").bind(self.tenant.to_string()).bind(p.registration()).fetch_optional(&mut *c).await?;
                let os = context
                    .as_ref()
                    .and_then(|v| v.get("interactiveUser"))
                    .filter(|v| !v.is_null());
                if let Some(proof) = user {
                    proof
                        .check_live()
                        .map_err(crate::service::authorization_error)?;
                    if proof.tenant_id() != self.tenant.to_string()
                        || !binding.registration_valid
                        || binding.reference.as_ref()
                            != Some(
                                &proof
                                    .session()
                                    .map_err(crate::service::authorization_error)?
                                    .reference()
                                    .map_err(|_| Error::Forbidden)?,
                            )
                    {
                        return Err(Error::Forbidden);
                    }
                    let os = os.ok_or(Error::Forbidden)?;
                    let os: rss_mdm_agent_wire::runtime::SoftwareInteractiveUser =
                        serde_json::from_value(os.clone()).map_err(|_| Error::Integrity)?;
                    personal = Some(ActivityUser {
                        instance: Uuid::parse_str(proof.instance_id())
                            .map_err(|_| Error::Integrity)?,
                        principal: Uuid::parse_str(proof.principal_id())
                            .map_err(|_| Error::Integrity)?,
                        os_identity: os.identity,
                        generated_uid: os.generated_uid,
                        session: os.session_id,
                    });
                }
                (
                    p.device().to_owned(),
                    serde_json::json!([
                        "agent",
                        p.registration(),
                        p.generation(),
                        binding.revision,
                        binding.registration_valid,
                        os,
                        personal
                    ]),
                    Some(Member {
                        device: p.device().into(),
                        registration: p.registration(),
                        generation: p.generation(),
                    }),
                )
            }
        };
        let pair = PlanningObjects::activity_pair_in(c, self.tenant, &device).await?;
        let (mut members, relation) = match pair {
            ActivityPair::Paired(object) => {
                let members = object
                    .members
                    .iter()
                    .map(|m| Member {
                        device: m.device.clone(),
                        registration: m.registration_id,
                        generation: m.generation,
                    })
                    .collect::<Vec<_>>();
                if let Some(anchor) = &anchor
                    && !members.contains(anchor)
                {
                    return Err(Error::Forbidden);
                }
                (
                    members,
                    serde_json::to_value(&(&object.object, object.association_version))
                        .map_err(|_| Error::Integrity)?,
                )
            }
            ActivityPair::Unpaired | ActivityPair::Pending => {
                if matches!(pair, ActivityPair::Pending) {
                    reasons.push("association_pending".into());
                }
                let members = if let Some(anchor) = anchor {
                    vec![anchor]
                } else {
                    let mut members = Vec::new();
                    for channel in [Channel::Agent, Channel::Mdm] {
                        if let Some(m) =
                            endpoints::current_in(c, &self.tenant.to_string(), &device, channel)
                                .await
                                .map_err(registration_error)?
                        {
                            members.push(Member {
                                device: m.device,
                                registration: m.registration_id,
                                generation: m.generation,
                            });
                        }
                    }
                    members
                };
                (members, serde_json::Value::Null)
            }
        };
        if let Reader::Management { proof, .. } = reader {
            let permissions = rss_mdm_authorization_service::snapshot_on(
                c,
                proof.tenant_id(),
                proof.instance_id(),
            )
            .await
            .map_err(crate::service::authorization_error)?;
            members.retain(|m| {
                permissions
                    .require(proof, Permission::OperationRead, Some(&m.device))
                    .is_ok()
            });
        }
        members.sort_by(|a, b| a.device.cmp(&b.device));
        let binding = rss_mdm_query::cursor::fingerprint(&(
            self.tenant.to_string(),
            authority,
            relation,
            &members,
        ))
        .map_err(|_| Error::Integrity)?;
        Ok(Scope {
            members,
            binding,
            reasons,
            personal,
        })
    }
}
fn registration_error(error: rss_mdm_registration_service::Error) -> Error {
    match error {
        rss_mdm_registration_service::Error::Unauthorized
        | rss_mdm_registration_service::Error::Forbidden => Error::Forbidden,
        rss_mdm_registration_service::Error::Conflict => Error::Conflict,
        _ => Error::Storage,
    }
}
