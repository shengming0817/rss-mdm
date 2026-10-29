//! Device-level declarations preserve the same protected native evidence as operation details.
use super::*;
use rss_mdm_query::{cursor::CursorCodec, window::Query};

pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "device_declarations",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "declaration operation identity",
    context: &[],
};
pub struct Page {
    pub items: Vec<Item>,
    pub next_cursor: Option<String>,
    pub current_registration: bool,
}
pub struct Item {
    pub operation: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub user: String,
    pub redacted: bool,
    pub observation: records::NativeObservation,
}
impl Queries {
    pub async fn ddm(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        query: &Query,
        audit: &RequestAudit,
        codec: &CursorCodec,
    ) -> std::result::Result<Page, QueryError> {
        query
            .require_schema(&SCHEMA)
            .map_err(|_| Error::Malformed)?;
        audit.target_device(device);
        audit.set_action(
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        self.snapshot(
            proof,
            (self, proof, device, query, audit, codec),
            |ctx, c, basis| {
                Box::pin(async move {
                    let (s, p, device, q, _audit, codec) = *ctx;
                    let authorization = &basis.grant;
                    authorization.require(p, Permission::OperationRead, Some(device))?;
                    let authority = authorization.query_binding(p)?;
                    let tenant = s.tenant.to_string();
                    let device_owned = device.to_owned();
                    let registration = rss_mdm_registration_service::device::endpoints::current_in(c, &tenant, &device_owned, rss_mdm_inventory::Channel::Mdm).await?;
                    basis.registration = Some((device.to_owned(), registration.clone()));
                    let Some(registration) = registration else {
                        if q.cursor().is_some() {
                            return Err(Error::CursorInvalidated.into());
                        }

                        return Ok(Page {
                            items: Vec::new(),
                            next_cursor: None,
                            current_registration: false,
                        });
                    };
                    let binding = rss_mdm_query::cursor::fingerprint(&(
                        "live-device-ddm",
                        s.tenant.to_string(),
                        p.instance_id(),
                        p.principal_id(),
                        device,
                        &registration,
                        &authority,
                    ))
                    .map_err(|_| Error::Malformed)?;
                    let after: Option<Uuid> = q.cursor()
                        .as_ref()
                        .map(|token| {
                            codec
                                .decode(
                                    &rss_contract::PageCursor::parse(token)
                                        .map_err(|_| Error::Malformed)?,
                                    &binding,
                                )
                                .map_err(|_| Error::CursorInvalidated)
                        })
                        .transpose()?;
                    let apple = s.apple_results.clone();
                    let tenant = s.tenant.to_string();
                    let selected = registration.clone();
                    let limit = q.limit();
                    let keys = { let c = &mut *c;
                                apple
                                    .declaration_page(
                                        c,
                                        tenant,
                                        selected.registration_id,
                                        selected.generation,
                                        after,
                                        limit + 1,
                                    )
                                    .await
                                    .map_err(|_| sqlx::Error::Protocol("declaration page".into()))
                             }?;
                    let ids=keys.iter().take(q.limit()).map(|(id,_)|*id).collect::<Vec<_>>();
                    let operations=storage::load_many_on(c,s.tenant,&s.protection,ids.clone()).await?;
                    let tenant=s.tenant.to_string();
                    let statuses={ let c = &mut *c; sqlx::query_as::<_,(String,String)>("SELECT command_id,status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=ANY($2)").bind(tenant).bind(ids.iter().map(Uuid::to_string).collect::<Vec<_>>()).fetch_all(c).await }?;
                    let statuses=statuses.into_iter().map(|(id,status)|Ok((stored(Uuid::parse_str(&id))?,stored(dc::Status::restore(&status))?))).collect::<Result<std::collections::BTreeMap<_,_>>>()?;
                    let mut permission=std::collections::BTreeMap::new();let mut observations=std::collections::BTreeMap::new();
                    for values in [false,true]{
                     let mut selected=Vec::new();
                     for op in operations.values(){
                      if op.device!=device||op.registration!=registration.registration_id||op.registration_generation!=registration.generation{return Err(Error::Conflict.into());}
                      let allow=s.native_values(&authorization,p,device,op)?;permission.insert(op.id,allow);
                      if allow==values {selected.push((op,*statuses.get(&op.id).ok_or(Error::Conflict)?));}
                     }
                     observations.extend(crate::apple::observations_on(c,s.tenant,s.apple_results.clone(),&selected,values).await?);
                    }
                    let mut items = Vec::new();
                    let mut bytes = 0;
                    let mut last = None;
                    let mut more = keys.len() > q.limit();
                    for (id, user) in keys.into_iter().take(q.limit()) {
                        let op=operations.get(&id).ok_or(Error::Conflict)?;
                        let native_values=*permission.get(&id).ok_or(Error::Conflict)?;
                        let observation=observations.remove(&id).ok_or(Error::Conflict)?;
                        let records::NativeObservation::Declarations { facts, .. } = &observation
                        else {
                            return Err(Error::Conflict.into());
                        };
                        let size = if let Some(facts) = facts {
                            serde_json::to_vec(&(&facts.expected, &facts.status))
                                .map_err(|_| Error::Malformed)?
                                .len()
                                + 1024
                        } else {
                            1024
                        };
                        let item = Item {
                            operation: id,
                            registration: op.registration,
                            generation: op.registration_generation,
                            user,
                            redacted: !native_values,
                            observation,
                        };
                        if bytes + size > 8 * 1024 * 1024 {
                            if items.is_empty() {
                                return Err(Error::Conflict.into());
                            }
                            more = true;
                            break;
                        }
                        bytes += size;
                        items.push(item);
                        last = Some(id);
                    }
                    let next = if more {
                        Some(
                            codec
                                .encode(&binding, &last.ok_or(Error::Conflict)?)
                                .map_err(|_| Error::Malformed)?
                                .as_str()
                                .to_owned(),
                        )
                    } else {
                        None
                    };
                    p.check_live()?;

                    Ok(Page {
                        items,
                        next_cursor: next,
                        current_registration: true,
                    })
                })
            },
        )
        .await
        .map_err(Into::into)
    }
}
