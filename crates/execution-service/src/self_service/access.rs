//! Policy data is mapped here; the authorization owner alone interprets trusted subjects.
use super::*;
use crate::authorization::{Subject, SubjectFacts};
use rss_mdm_policy::{SelfServiceAccess as Access, SelfServiceSelector as Selector};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Basis {
    Device,
    User {
        reference: crate::authorization::session::SessionReference,
    },
    /// One-way migration terminal marker. It can never authorize new execution.
    Withdrawn,
}
pub fn select(
    config: &rss_mdm_policy::SelfService,
    proof: Option<&AuthorizedPrincipal>,
) -> Result<Option<Basis>> {
    match config.access.as_ref() {
        Some(Access::Device) => Ok(Some(Basis::Device)),
        Some(Access::AuthenticatedUser | Access::Users { .. }) => proof
            .map(|proof| {
                proof.check_live()?;
                Ok(Basis::User {
                    reference: proof
                        .session()
                        .reference()
                        .map_err(|_| Error::Unauthorized)?,
                })
            })
            .transpose(),
        None => Ok(None),
    }
}
pub fn selectors(
    config: &rss_mdm_policy::SelfService,
    tenant: &str,
    instance: &str,
) -> Result<Vec<Subject>> {
    let Some(Access::Users { selectors }) = &config.access else {
        return Ok(Vec::new());
    };
    let subjects: Vec<_> = selectors
        .iter()
        .map(|selector| match selector {
            Selector::User {
                instance_id,
                tenant_id,
                principal_id,
            } => Subject::User {
                user: crate::authorization::User {
                    instance_id: instance_id.to_string(),
                    tenant_id: tenant_id.to_string(),
                    principal_id: principal_id.to_string(),
                },
            },
            Selector::UserGroup { id } => Subject::UserGroup { id: *id },
            Selector::IdpGroup { source, id } => Subject::IdpGroup {
                source: source_coordinates(source),
                id: id.clone(),
            },
            Selector::Department {
                source,
                id,
                matching,
            } => Subject::Department {
                source: source_coordinates(source),
                id: id.clone(),
                matching: match matching {
                    rss_mdm_policy::SelfServiceDepartmentMatch::Exact => {
                        crate::authorization::DepartmentMatch::Exact
                    }
                    rss_mdm_policy::SelfServiceDepartmentMatch::Subtree => {
                        crate::authorization::DepartmentMatch::Subtree
                    }
                },
            },
        })
        .collect();
    for subject in &subjects {
        checked_input(subject.validate(tenant, instance))?;
    }
    Ok(subjects)
}
fn source_coordinates(source: &rss_mdm_policy::SelfServiceSource) -> crate::authorization::Source {
    crate::authorization::Source {
        provider_id: source.provider_id,
        issuer: source.issuer.clone(),
        configuration_version: source.configuration_version,
    }
}
pub async fn qualify_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    config: &rss_mdm_policy::SelfService,
    basis: &Basis,
) -> Result<Option<wire::SelfServiceSubject>> {
    match (config.access.as_ref(), basis) {
        (Some(Access::Device), Basis::Device) => Ok(Some(wire::SelfServiceSubject::Device {})),
        (Some(Access::AuthenticatedUser | Access::Users { .. }), Basis::User { reference }) => {
            let facts = match service.sessions.recheck(reference).await {
                Ok(facts) => facts,
                Err(
                    crate::authorization::Error::Unauthorized
                    | crate::authorization::Error::Forbidden,
                ) => return Ok(None),
                Err(error) => return Err(Error::from(error).into()),
            };
            let user = SubjectFacts::Revalidated(&facts).user();
            if user.tenant_id != tx.tenant_id().to_string() || user.instance_id != service.instance
            {
                return Ok(None);
            }
            let subjects = selectors(config, &user.tenant_id, &user.instance_id)?;
            if matches!(config.access, Some(Access::Users { .. })) {
                let tenant = user.tenant_id.clone();
                let instance = user.instance_id.clone();
                let snapshot = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            crate::authorization::lock_on(c, &tenant, &instance)
                                .await
                                .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                            Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
                        })
                    })
                    .await?
                    .map_err(Error::from)?;
                if !snapshot
                    .matches_subjects(SubjectFacts::Revalidated(&facts), &subjects)
                    .map_err(crate::authorization::Error::from)
                    .map_err(Error::from)?
                {
                    return Ok(None);
                }
            }
            facts.check_live().map_err(|_| Error::Unauthorized)?;
            Ok(Some(wire::SelfServiceSubject::User {
                user: wire::SelfServiceUser {
                    tenant_id: checked_input(Uuid::parse_str(&user.tenant_id))?,
                    instance_id: checked_input(Uuid::parse_str(&user.instance_id))?,
                    principal_id: checked_input(Uuid::parse_str(&user.principal_id))?,
                },
            }))
        }
        _ => Ok(None),
    }
}
