use super::*;
use rss_mdm_apple_channel::protocol_types::AppleResults;
use rss_mdm_management_http::execution::declarations::{Item, Page, SCHEMA};
use rss_mdm_policy_service::configuration::queries::records;
use rss_mdm_query::window::Query;
impl Operations {
    pub(super) async fn declarations_read(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        query: &Query,
        audit: &RequestAudit,
        codec: &CursorCodec,
    ) -> std::result::Result<Page, Error> {
        query
            .require_schema(&SCHEMA)
            .map_err(|_| Error::Malformed)?;
        audit.target_device(device);
        audit.set_action(
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        self.tasks
            .snapshot_registered(
                proof,
                (self, proof, device, query, audit, codec),
                |ctx, c, authorization, _, fence| {
                    Box::pin(async move {
                        let (s, p, device, q, _audit, codec) = *ctx;
                        authorization.require(p, Permission::OperationRead, Some(device))?;
                        let authority = authorization.query_binding(p)?;
                        let tenant = s.tasks.tenant.to_string();
                        let device_owned = device.to_owned();
                        let registration =
                            rss_mdm_registration_service::device::endpoints::current_in(
                                c,
                                &tenant,
                                &device_owned,
                                rss_mdm_inventory::Channel::Mdm,
                            )
                            .await?;
                        *fence = Some((device.to_owned(), registration.clone()));
                        let Some(registration) = registration else {
                            if q.cursor().is_some() {
                                return Err(Error::QueryCursorInvalidated.into());
                            }

                            return Ok(Page {
                                items: Vec::new(),
                                next_cursor: None,
                                current_registration: false,
                            });
                        };
                        let binding = rss_mdm_query::cursor::fingerprint(&(
                            "live-device-ddm",
                            s.tasks.tenant.to_string(),
                            p.instance_id(),
                            p.principal_id(),
                            device,
                            &registration,
                            &authority,
                        ))
                        .map_err(|_| Error::Malformed)?;
                        let after: Option<Uuid> = q
                            .cursor()
                            .as_ref()
                            .map(|token| {
                                codec
                                    .decode(
                                        &rss_contract::PageCursor::parse(token)
                                            .map_err(|_| Error::Malformed)?,
                                        &binding,
                                    )
                                    .map_err(|_| Error::QueryCursorInvalidated)
                            })
                            .transpose()?;
                        let apple = s.apple.clone();
                        let tenant = s.tasks.tenant.to_string();
                        let selected = registration.clone();
                        let limit = q.limit();
                        let keys = {
                            let c = &mut *c;
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
                                .map_err(|_| Error::Unavailable(Failure::Database))
                        }?;
                        let ids = keys
                            .iter()
                            .take(q.limit())
                            .map(|(id, _)| *id)
                            .collect::<Vec<_>>();
                        let mut configuration = s
                            .tasks
                            .configuration
                            .declarations_on(c, p, authorization, &registration, ids)
                            .await
                            .map_err(super::super::task_reads::configuration_fault)?;
                        let mut items = Vec::new();
                        let mut bytes = 0;
                        let mut last = None;
                        let mut more = keys.len() > q.limit();
                        for (id, user) in keys.into_iter().take(q.limit()) {
                            let value = configuration.remove(&id).ok_or(Error::Conflict)?;
                            let (registration, generation, native_values, observation) = (
                                value.registration,
                                value.generation,
                                !value.redacted,
                                value.observation,
                            );
                            let records::NativeObservation::Declarations { facts, .. } =
                                &observation
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
                                registration,
                                generation,
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
    }
}
