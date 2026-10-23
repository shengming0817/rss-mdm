//! Device-level declarations preserve the same protected native evidence as operation details.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    #[serde(default = "limit")]
    pub limit: usize,
    pub cursor: Option<String>,
}
fn limit() -> usize {
    16
}
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
    ) -> std::result::Result<Page, QueryError> {
        if !(1..=64).contains(&query.limit) || query.cursor.as_ref().is_some_and(|s| s.len() > 4096)
        {
            return Err(Error::Malformed.into());
        }
        audit.target_device(device);
        audit.set_action("command_read");
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, device, query, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, device, q, audit) = *ctx;
                    let authorization = crate::action_admission::authorized(
                        tx,
                        p,
                        device,
                        Permission::OperationRead,
                    )
                    .await?;
                    let authority = authorization.query_binding(p)?;
                    let tenant = s.tenant.to_string();
                    let device_owned = device.to_owned();
                    let registration = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                use rss_mdm_registration_service::device::endpoints;
                                endpoints::lock_in(
                                    c,
                                    &tenant,
                                    &device_owned,
                                    rss_mdm_inventory::Channel::Mdm,
                                )
                                .await
                                .map_err(|_| sqlx::Error::Protocol("registration lock".into()))?;
                                endpoints::current_in(
                                    c,
                                    &tenant,
                                    &device_owned,
                                    rss_mdm_inventory::Channel::Mdm,
                                )
                                .await
                                .map_err(|_| sqlx::Error::Protocol("registration read".into()))
                            })
                        })
                        .await?;
                    let Some(registration) = registration else {
                        if q.cursor.is_some() {
                            return Err(Error::Conflict.into());
                        }
                        audit.require_request_settlement();
                        return Ok(Page {
                            items: Vec::new(),
                            next_cursor: None,
                            current_registration: false,
                        });
                    };
                    let aad = crate::protection::aad(
                        s.tenant,
                        "ddm.cursor",
                        &(device, &registration, &authority),
                    )?;
                    let after = if let Some(token) = &q.cursor {
                        let bytes = URL_SAFE_NO_PAD
                            .decode(token)
                            .map_err(|_| Error::Malformed)?;
                        let plain = s
                            .protection
                            .open_bytes(&bytes, &aad)
                            .map_err(|_| Error::Conflict)?;
                        Some(
                            serde_json::from_slice::<Uuid>(plain.expose())
                                .map_err(|_| Error::Conflict)?,
                        )
                    } else {
                        None
                    };
                    let apple = s.apple_results.clone();
                    let tenant = s.tenant.to_string();
                    let selected = registration.clone();
                    let limit = q.limit;
                    let keys = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
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
                            })
                        })
                        .await?;
                    let mut items = Vec::new();
                    let mut bytes = 0;
                    let mut last = None;
                    let mut more = keys.len() > q.limit;
                    for (id, user) in keys.into_iter().take(q.limit) {
                        let op = storage::load(tx, &s.protection, id).await?;
                        if op.device != device
                            || op.registration != registration.registration_id
                            || op.registration_generation != registration.generation
                        {
                            return Err(Error::Conflict.into());
                        }
                        let native_values = s.native_values_in(tx, p, device, &op).await?;
                        let command = s.command_status(tx, &op).await?;
                        let observation = protocol::observation(
                            tx,
                            &s.protection,
                            s.apple_results.clone(),
                            &op,
                            command,
                            native_values,
                        )
                        .await?;
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
                        let encoded = serde_json::to_vec(&last.ok_or(Error::Conflict)?)
                            .map_err(|_| Error::Malformed)?;
                        Some(
                            URL_SAFE_NO_PAD.encode(
                                s.protection
                                    .seal_bytes(&encoded, &aad)
                                    .map_err(|_| Error::Conflict)?,
                            ),
                        )
                    } else {
                        None
                    };
                    p.check_live()?;
                    audit.require_request_settlement();
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
