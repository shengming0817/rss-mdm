//! Maps Windows-owned durable facts into business read projections.
use rss_mdm_software_service::deployment::queries::records::{WindowsFrame, WindowsReceipt};
use rss_mdm_software_service::deployment::windows_results::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::collections::BTreeMap;
use uuid::Uuid;
pub(super) struct WindowsResults(pub rss_mdm_windows_channel::results::Results);
pub(super) fn error(
    e: rss_mdm_windows_channel::Error,
) -> rss_mdm_software_service::deployment::Error {
    use rss_mdm_software_service::deployment::{Error as E, Failure};
    use rss_mdm_windows_channel::Error as W;
    match e {
        W::Malformed => E::Malformed,
        W::Unauthorized => E::Unauthorized,
        W::Forbidden => E::Forbidden,
        W::Conflict => E::Conflict,
        W::CommitUnknown => E::CommitUnknown,
        W::RollbackFailed => E::RollbackFailed,
        _ => E::Unavailable(Failure::CommandStorage),
    }
}
impl Store for WindowsResults {
    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_windows_channel::command_binding::bind_on(c, tenant, binding)
                .await
                .map_err(error)
        })
    }

    fn installations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reads: Vec<InstallationRead>,
    ) -> Pending<'a, BTreeMap<Uuid, Installation>> {
        Box::pin(async move {
            use rss_mdm_windows_channel::results as channel;
            let reads = reads
                .into_iter()
                .map(|r| channel::InstallationRead {
                    id: r.id,
                    device: r.device,

                    snapshot: r.snapshot,
                })
                .collect::<Vec<_>>();
            Ok(self
                .0
                .installations(c, tenant, &reads)
                .await
                .map_err(error)?
                .into_iter()
                .map(|(id, v)| {
                    (
                        id,
                        Installation {
                            channel_state: v.channel_state,
                            delivery: match v.delivery {
                                channel::InstallationDelivery::Unknown => {
                                    InstallationDelivery::Unknown
                                }
                                channel::InstallationDelivery::Acknowledged => {
                                    InstallationDelivery::Acknowledged
                                }
                                channel::InstallationDelivery::Rejected => {
                                    InstallationDelivery::Rejected
                                }
                            },
                        },
                    )
                })
                .collect())
        })
    }

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reads: Vec<Read>,
    ) -> Pending<'a, BTreeMap<Uuid, Evidence>> {
        Box::pin(async move {
            let reads = reads
                .into_iter()
                .map(|r| rss_mdm_windows_channel::results::Read {
                    id: r.id,
                    device: r.device,

                    request: r.request,
                    values: r.values,
                })
                .collect::<Vec<_>>();
            Ok(self.0.observations(c,tenant,&reads).await.map_err(error)?.into_iter().map(|(id,v)|(id,Evidence{assessment:v.assessment,receipts:v.receipts.into_iter().map(|r|WindowsReceipt{
 phase:match r.phase{rss_mdm_windows_channel::participants::AttemptPhase::Prepare=>rss_mdm_software_service::deployment::AttemptPhase::Prepare,rss_mdm_windows_channel::participants::AttemptPhase::Execute=>rss_mdm_software_service::deployment::AttemptPhase::Execute,rss_mdm_windows_channel::participants::AttemptPhase::Observe=>rss_mdm_software_service::deployment::AttemptPhase::Observe},
ordinal:r.ordinal,session:r.session,message:r.message,command:r.command,parent_command:r.parent_command,item:r.item,kind:r.kind,uri:r.uri,status:r.status,value:r.value,accepted:r.accepted,received_at:r.received_at,result_accepted:r.result_accepted,result_received_at:r.result_received_at,redacted:r.redacted,frames:r.frames.into_iter().map(|f|WindowsFrame{message:f.message,command:f.command,start_byte:f.start_byte,end_byte:f.end_byte,total_bytes:f.total_bytes,status:f.status,accepted:f.accepted,received_at:f.received_at}).collect()}).collect()})).collect())
        })
    }
    fn received<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a rss_mdm_registration_service::DevicePrincipal,
        session: u32,
        after: Option<Uuid>,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move { self.0.received(c, p, session, after).await.map_err(error) })
    }
    fn settlement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        complete: bool,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::receipt::Settlement> {
        Box::pin(async move {
            self.0
                .settlement(c, tenant, id, complete)
                .await
                .map_err(error)
        })
    }
}
