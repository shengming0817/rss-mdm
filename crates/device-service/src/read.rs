use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::Channel;
use rss_mdm_registration_service::device::endpoints;
use sqlx::{PgConnection, Row};
use std::time::Duration;
use uuid::Uuid;

/// The original receipt owner has exactly two author namespaces.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReceiptNamespace {
    CurrentPrincipal,
    AutomaticAssociation,
}
impl ReceiptNamespace {
    pub const AUTOMATIC_ACTOR: &str = "device-associations";
    pub(crate) const AUTOMATIC_INSTANCE: &str = "system";
    fn coordinates(self, p: &AuthorizedPrincipal) -> (&str, &str) {
        match self {
            Self::CurrentPrincipal => (p.principal_id(), p.instance_id()),
            Self::AutomaticAssociation => (Self::AUTOMATIC_ACTOR, Self::AUTOMATIC_INSTANCE),
        }
    }
}

pub(crate) async fn authorization(
    c: &mut PgConnection,
    proof: &AuthorizedPrincipal,
) -> Result<Snapshot> {
    proof.check_live()?;
    rss_mdm_authorization_service::lock_shared_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        proof.tenant_id(),
        proof.instance_id(),
    )
    .await?;
    Ok(rss_mdm_authorization_service::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        proof.tenant_id(),
        proof.instance_id(),
    )
    .await?)
}
pub(crate) fn authorize(
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    members: &[Member],
    write: bool,
) -> Result<()> {
    for m in members {
        snapshot.require(proof, Permission::InventoryRead, Some(&m.device))?;
        if write {
            snapshot.require(proof, Permission::DeviceAssociationWrite, Some(&m.device))?;
        }
    }
    Ok(())
}
pub(crate) async fn load(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<Association> {
    load_page(c, tenant, &[id])
        .await?
        .pop()
        .ok_or(Error::NotFound)
}
pub(crate) async fn load_page(
    c: &mut PgConnection,
    tenant: &str,
    ids: &[Uuid],
) -> Result<Vec<Association>> {
    if ids.len() > 100 {
        return Err(Error::Malformed);
    }
    let rows:Vec<String>=sqlx::query_scalar("SELECT CAST(jsonb_build_object('id', a.id, 'version', a.version, 'state', a.state, 'evidence', a.evidence, 'hardware', a.hardware, 'confirmedBy', a.confirmed_by, 'confirmedAt', a.confirmed_at, 'revokedBy', a.revoked_by, 'revokedAt', a.revoked_at, 'reason', a.reason, 'members', (SELECT jsonb_agg(jsonb_build_object('device', m.device, 'channel', m.channel) ORDER BY m.channel) FROM mdm_devices.members AS m WHERE (m.tenant_id, m.association_id) = (a.tenant_id, a.id))) AS text) FROM mdm_devices.associations AS a WHERE a.tenant_id = CAST($1 AS uuid) AND a.id = ANY($2)")
        .bind(tenant).bind(ids).fetch_all(c).await?;
    rows.into_iter()
        .map(|value| {
            let value: Association = serde_json::from_str(&value).map_err(|_| Error::Storage)?;
            if value.members.len() != 2
                || value.members[0].device == value.members[1].device
                || value.members[0].channel == value.members[1].channel
            {
                return Err(Error::Storage);
            }
            Ok(value)
        })
        .collect()
}
pub(crate) async fn lock_members(
    c: &mut PgConnection,
    tenant: &str,
    members: &[Member],
) -> Result<()> {
    let mut ordered: Vec<_> = members.iter().collect();
    ordered.sort_by(|a, b| {
        a.device
            .cmp(&b.device)
            .then(a.channel.as_str().cmp(b.channel.as_str()))
    });
    for m in ordered {
        endpoints::lock_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            tenant,
            &m.device,
            m.channel,
        )
        .await?;
    }
    Ok(())
}
impl Associations {
    /// Requires visibility of both members, including for revoked history.
    pub async fn get(&self, proof: &AuthorizedPrincipal, id: Uuid) -> Result<Association> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        let (value,grants)=self.audit.read(self.tenant,&budget.control(),(self,proof,id),|ctx,tx|Box::pin(async move {
            tx.with_connection_context(ctx,|ctx,c|Box::pin(async move {
                let (service,proof,id)=*ctx;
                let grant=authorization(c,proof).await?;
                let raw:serde_json::Value=sqlx::query_scalar("SELECT mdm_devices.read_world(ARRAY[$2::uuid],ARRAY(SELECT device FROM mdm_devices.members WHERE tenant_id=$1::uuid AND association_id=$2),ARRAY[]::text[])").bind(proof.tenant_id()).bind(id).fetch_one(c).await?;
                let associations:Vec<Association>=serde_json::from_value(raw["associations"].clone()).map_err(|_|Error::Storage)?;
                let association=associations.first().ok_or(Error::NotFound)?;
                authorize(&grant,proof,&association.members,false).map_err(|e|if matches!(e,Error::Forbidden){Error::NotFound}else{e})?;
                let ids=association.members.iter().map(|m|m.device.clone()).collect::<Vec<_>>();
                let (world,_,_,_)=crate::snapshot::decode_world(&raw,service.tenant,&ids)?;
                proof.check_live()?;
                Ok((world.effective(association.clone()),grant.query_binding(proof)?))
            })).await
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::Storage),|e|Err(model::transaction_error(e)))?;
        self.confirm_scope(proof, &grants, None, &budget).await?;
        Ok(value)
    }
    /// Candidate identities support explicit exception handling alongside automatic reconciliation.
    /// Searches only endpoints for which both read and association-management grants are current.
    pub async fn candidates(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        selected: Channel,
        token: Option<&str>,
        limit: usize,
    ) -> Result<CandidatePage> {
        if !(1..=1000).contains(&limit) || !model::text(device) {
            return Err(Error::Malformed);
        }
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        let (value,grants)=self.audit.read(self.tenant,&budget.control(),(self,proof,device,token,selected),|(service,proof,device,token,selected),tx|Box::pin(async move {
            tx.with_connection_context(&mut (*service,*proof,*device,*token,*selected),|(service,proof,device,token,selected),c|Box::pin(async move {
                let snapshot=authorization(c,proof).await?;
                snapshot.require(proof,Permission::InventoryRead,Some(device))?;
                snapshot.require(proof,Permission::DeviceAssociationWrite,Some(device))?;
                let registration=endpoints::current_in(rss_mdm_install_support::StorageProfile::Mdm, c,proof.tenant_id(),device,*selected).await?.ok_or(Error::Conflict)?;
                let binding=rss_mdm_query::cursor::fingerprint(&("association-candidates",proof.tenant_id(),proof.instance_id(),proof.principal_id(),*device,*selected,snapshot.query_binding(proof)?,registration)).map_err(|_|Error::Malformed)?;
                let codec=rss_mdm_query::cursor::CursorCodec::from_key(service.key.clone());
                let after:Option<String>=token.map(|token|codec.decode(&rss_contract::PageCursor::parse(token).map_err(|_|Error::Malformed)?,&binding).map_err(|_|Error::CursorInvalidated)).transpose()?;
                let channel=if *selected==Channel::Mdm{Channel::Agent}else{Channel::Mdm};
                let allowed=snapshot.inventory_devices(proof)?.map(|s|s.into_iter().collect::<Vec<_>>());
                let writable=snapshot.devices_for(proof,Permission::DeviceAssociationWrite)?.map(|s|s.into_iter().collect::<Vec<_>>());
                let rows=sqlx::query("SELECT r.id AS device, r.id FROM mdm_access.devices AS r WHERE r.tenant_id = CAST($1 AS uuid) AND r.channel = $2 AND r.purpose = 'primary' AND r.state = 'active' AND r.id <> $3 AND (CAST($4 AS text) IS NULL OR r.id COLLATE \"C\" > $4 COLLATE \"C\") AND (CAST($5 AS text[]) IS NULL OR r.id = ANY($5)) AND (CAST($6 AS text[]) IS NULL OR r.id = ANY($6)) AND EXISTS (SELECT FROM mdm_access.credentials AS k WHERE (k.tenant_id, k.device) = (r.tenant_id, r.id) AND k.state = 'active') AND NOT EXISTS (SELECT FROM mdm_devices.members AS m WHERE (m.tenant_id, m.device) = (r.tenant_id, r.id) AND NOT m.released) ORDER BY r.id COLLATE \"C\" LIMIT $7")
                    .bind(proof.tenant_id()).bind(channel.as_str()).bind(*device).bind(after).bind(allowed).bind(writable).bind((limit+1) as i64).fetch_all(c).await?;
                let mut items=rows.into_iter().map(|row|Ok(Member {
                    device:row.try_get("device")?,channel,
                })).collect::<Result<Vec<_>>>()?;
                let more=items.len()>limit;items.truncate(limit);
                let next_cursor=if more{Some(codec.encode(&binding,&items.last().ok_or(Error::Storage)?.device).map_err(|_|Error::Malformed)?.as_str().to_owned())}else{None};
                proof.check_live()?;
                Ok((CandidatePage {items,next_cursor},snapshot.query_binding(proof)?))
            })).await
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))?;
        self.confirm_scope(proof, &grants, None, &budget).await?;
        Ok(value)
    }
}

impl Associations {
    /// Original association response, authorized against all its original devices.
    pub async fn operation_receipt(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        namespace: ReceiptNamespace,
    ) -> Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit.read(self.tenant,&budget.control(),(p,namespace),|ctx,tx|Box::pin(async move{
            tx.with_connection_context(ctx,|(p,namespace),c|Box::pin(async move{
                let grant=authorization(c,p).await?;
                let (actor,instance)=namespace.coordinates(p);
                let raw:Option<serde_json::Value>=sqlx::query_scalar("SELECT result FROM mdm_devices.operations WHERE tenant_id=$1::uuid AND operation_id=$2 AND actor=$3 AND instance=$4")
                    .bind(p.tenant_id()).bind(id).bind(actor).bind(instance).fetch_optional(&mut *c).await?;
                let Some(raw)=raw else {return Ok(None)};
                #[derive(serde::Deserialize)]
                #[serde(untagged)]
                enum Stored {
                    Association(Association),
                    Asset(crate::lifecycle_management::AssetReceipt),
                    Force(crate::lifecycle_management::ForceReceipt),
                }
                let result:Stored=match namespace {
                    ReceiptNamespace::CurrentPrincipal=>serde_json::from_value(raw).map_err(|_|Error::Storage)?,
                    ReceiptNamespace::AutomaticAssociation=>Stored::Association(serde_json::from_value(raw).map_err(|_|Error::Storage)?),
                };
                let mut s=rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                match result {
                    Stored::Association(result)=>{
                        if result.members.len()!=2 || result.members[0].device==result.members[1].device || result.members[0].channel==result.members[1].channel {return Err(Error::Storage);}
                        authorize(&grant,p,&result.members,false)?;
                        s.object=Some(result.id.to_string());s.revision=Some(result.version);
                        s.state=serde_json::to_value(result.state).map_err(|_|Error::Storage)?.as_str().map(str::to_owned);
                    },
                    Stored::Asset(result)=>{
                        if result.operation_id!=id || result.devices.is_empty(){return Err(Error::Storage);}
                        for device in &result.devices {grant.require(p,Permission::InventoryRead,Some(device))?;}
                        s.state=serde_json::to_value(result.state).map_err(|_|Error::Storage)?.as_str().map(str::to_owned);
                    },
                    Stored::Force(result)=>{
                        if result.operation_id!=id{return Err(Error::Storage);}
                        let record=crate::lifecycle::read_in(c,rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_|Error::Malformed)?,result.retirement_id).await?;
                        for channel in record.channels {grant.require(p,Permission::InventoryRead,Some(&channel.device))?;}
                        s.object=Some(result.retirement_id.to_string());
                        s.state=Some("revocation_pending".into());
                    },
                }
                p.check_live()?;Ok::<_,Error>(Some(s))
            })).await
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)))
    }
}
