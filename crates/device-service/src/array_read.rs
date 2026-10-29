//! Fixed array continuations read the original immutable version, independently of detail hydration.
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_inventory::{ArrayState, EndpointArrayFact, Evidence, FieldKey, Sensitivity, Source};
use rss_mdm_query::cursor::CursorCodec;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArrayCursor {
    reference: ViewRef,
    field: FieldKey,
    endpoint: String,
    evidence: Evidence,
    version: Option<String>,
    offset: usize,
    association: Option<(uuid::Uuid, i64, Vec<Member>)>,
}
fn binding(proof: &AuthorizedPrincipal, grant: &str) -> Result<String> {
    rss_mdm_query::cursor::fingerprint(&(
        "fixed-device-array",
        proof.tenant_id(),
        proof.instance_id(),
        proof.principal_id(),
        grant,
    ))
    .map_err(|_| Error::Storage)
}
impl Associations {
    pub(crate) fn array_cursor(
        &self,
        proof: &AuthorizedPrincipal,
        grant: &str,
        group: &views::Group,
        field: FieldKey,
        source: &EndpointArrayFact,
    ) -> Result<String> {
        CursorCodec::from_key(self.key.clone())
            .encode(
                &binding(proof, grant)?,
                &ArrayCursor {
                    reference: group.reference.clone(),
                    field,
                    endpoint: source.endpoint.clone(),
                    evidence: source.fact.evidence.clone(),
                    version: match &source.fact.state {
                        ArrayState::Known(value) => Some(value.version.clone()),
                        _ => None,
                    },
                    offset: 0,
                    association: group
                        .association
                        .as_ref()
                        .map(|a| (a.id, a.version, a.members.clone())),
                },
            )
            .map(|c| c.as_str().to_owned())
            .map_err(|_| Error::Storage)
    }
    pub async fn list_items(
        &self,
        proof: &AuthorizedPrincipal,
        reference: &ViewRef,
        field: FieldKey,
        token: &str,
        limit: usize,
        personnel: &personnel::Reader<'_>,
    ) -> Result<crate::view_response::ListItems> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Malformed);
        }
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        let subject = personnel.revalidate(proof).await?;
        let (page,grant,cursor)=self.audit.read(self.tenant,&budget.control(),(self,proof,reference,field,token,subject.as_ref()),|ctx,tx|Box::pin(async move {
            tx.with_connection_context(ctx,|ctx,c|Box::pin(async move{
                let (s,p,reference,field,token,subject)=*ctx;
                let current=read::authorization(c,p).await?;
                let grant=current.query_binding(p)?;
                if let Some(facts)=subject && current.query_binding_revalidated(p,facts)?!=grant{return Err(Error::ReadConflict);}
                let codec=CursorCodec::from_key(s.key.clone());
                let binding=binding(p,&grant)?;
                let cursor:ArrayCursor=codec.decode(&rss_contract::PageCursor::parse(token).map_err(|_|Error::Malformed)?,&binding).map_err(|_|Error::CursorInvalidated)?;
                if &cursor.reference!=reference||cursor.field!=field{return Err(Error::CursorInvalidated);}
                validate(c,s.tenant,p,&current,&cursor).await?;
                let version=cursor.version.as_ref().ok_or(Error::ResultUnavailable)?;
                let page=rss_mdm_inventory_postgres::arrays::page(c,s.tenant,version,cursor.offset,limit,16*1024*1024).await.map_err(|_|Error::ResultUnavailable)?;
                if page.metadata.field!=field{return Err(Error::ResultUnavailable);}
                let next=page.next.map(|offset|codec.encode(&binding,&ArrayCursor{offset,..cursor.clone()})).transpose().map_err(|_|Error::Storage)?.map(|c|c.as_str().to_owned());
                p.check_live()?;
                crate::view_response::decode(json!({"reference":reference,"field":field,"source":cursor.evidence,"endpoint":cursor.endpoint,"total":page.metadata.count,"items":page.items,"nextCursor":next})).map(|page|(page,grant,cursor))
            })).await
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::Storage),|e|Err(model::transaction_error(e)))?;
        let subject = personnel.revalidate(proof).await?;
        self.audit
            .write(
                self.tenant,
                &budget.source_control(),
                (proof, grant, subject.as_ref(), cursor),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |(proof, grant, subject, cursor), c| {
                            Box::pin(async move {
                                let current = read::authorization(c, proof).await?;
                                let binding = match subject {
                                    Some(subject) => {
                                        current.query_binding_revalidated(proof, subject)?
                                    }
                                    None => current.query_binding(proof)?,
                                };
                                if binding != *grant {
                                    return Err(Error::ReadConflict);
                                }
                                validate(c, self.tenant, proof, &current, cursor).await?;
                                proof.check_live()?;
                                Ok(())
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(model::transaction_error(e)),
                |e| Err(model::transaction_error(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(model::transaction_error(e)),
            )?;
        Ok(page)
    }
}
async fn validate(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    proof: &AuthorizedPrincipal,
    grant: &rss_mdm_authorization_service::Snapshot,
    cursor: &ArrayCursor,
) -> Result<()> {
    grant.require(proof, Permission::InventoryRead, Some(&cursor.endpoint))?;
    match (&cursor.reference, &cursor.association) {
        (ViewRef::Endpoint(id), None) if id == &cursor.endpoint => {}
        (ViewRef::Association(id), Some((expected, version, members))) if id == expected => {
            let current = read::load(c, proof.tenant_id(), *id).await.map_err(|e| {
                if matches!(e, Error::NotFound) {
                    Error::CursorInvalidated
                } else {
                    e
                }
            })?;
            if current.version != *version
                || current.members != *members
                || current.state == State::Revoked
                || !members.iter().any(|m| m.device == cursor.endpoint)
            {
                return Err(Error::CursorInvalidated);
            }
            read::authorize(grant, proof, members, false)?;
            for member in members {
                let current = rss_mdm_registration_service::device::endpoints::current_in(
                    c,
                    proof.tenant_id(),
                    &member.device,
                    member.channel,
                )
                .await?;
                if !current.is_some_and(|r| {
                    r.registration_id == member.registration_id && r.generation == member.generation
                }) {
                    return Err(Error::CursorInvalidated);
                }
            }
        }
        _ => return Err(Error::CursorInvalidated),
    }
    let catalog = rss_mdm_inventory_postgres::catalog_in(c, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let definition = catalog
        .definition(cursor.field)
        .map_err(|_| Error::ResultUnavailable)?;
    if !matches!(
        definition.value_type,
        rss_mdm_inventory::ValueType::Array { .. }
    ) {
        return Err(Error::ResultUnavailable);
    }
    if definition.sensitivity == Sensitivity::Secret {
        return Err(Error::Forbidden);
    }
    if definition.sensitivity != Sensitivity::Standard {
        grant.require(proof, Permission::InventorySensitiveRead, None)?;
    }
    if !definition.sources.contains_key(&cursor.evidence.source) {
        return Err(Error::CursorInvalidated);
    }
    if cursor.evidence.source != Source::Manual {
        let generation = cursor
            .evidence
            .registration_generation
            .ok_or(Error::CursorInvalidated)? as i64;
        let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.id::text=$3 AND r.generation=$4 AND r.state='active' AND s.source=$5 AND s.epoch::text=$6 AND s.enabled AND EXISTS(SELECT FROM mdm_access.credentials k WHERE(k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active'))")
            .bind(proof.tenant_id()).bind(&cursor.endpoint).bind(&cursor.evidence.registration).bind(generation).bind(cursor.evidence.source.as_str()).bind(&cursor.evidence.epoch).fetch_one(c).await?;
        if !live {
            return Err(Error::CursorInvalidated);
        }
    }
    Ok(())
}
