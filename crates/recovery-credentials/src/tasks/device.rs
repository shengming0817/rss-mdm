//! Targeted RSS Login work uses the credential run and custody owners on the DA mTLS channel.
use super::credential_tasks;
use crate::{Binding, Coordinates, Credentials, Error, Validity, storage};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{DeviceId, runtime as wire};
use rss_mdm_authorization_service::{OperationAuthority, Permission};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_policy::CredentialOperation;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

const DA: StorageProfile = StorageProfile::Da;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action { Verify, Rotate }

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request { pub operation_id: Uuid, pub binding_id: Uuid, pub binding_generation: i64, pub action: Action }

#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State { Accepted, PendingApplication, Applied }

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub device: DeviceId,
    pub request: Request,
    pub state: State,
    pub receipt: Option<wire::CredentialReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "event", rename_all="snake_case", rename_all_fields="camelCase", deny_unknown_fields)]
pub enum Event {
    Escrow { attempt_id: Uuid, value: wire::CredentialEscrow },
    Applied { attempt_id: Uuid, definition_digest: [u8;32], receipt: wire::CredentialReceipt },
}

#[derive(Serialize, Deserialize)]
struct Frozen {
    request: Request,
    authority: OperationAuthority,
    instance: String,
    actor: String,
    operation: CredentialOperation,
    spec: wire::CredentialTaskSpec,
}
pub struct Run {
    frozen: Frozen,
    anchor: Binding,
    state: State,
    receipt: Option<wire::CredentialReceipt>,
    escrow_digest: Option<[u8;32]>,
    permit_until: i64,
}
impl Run {
    pub fn status(&self) -> Status {
        Status { device: self.anchor.device, request: self.frozen.request.clone(), state:self.state, receipt:self.receipt.clone() }
    }
    pub fn owned(&self, p: &rss_mdm_authorization_service::context::AuthorizedPrincipal) -> bool {
        self.frozen.actor == p.principal_id() && self.frozen.instance == p.instance_id()
    }
    pub fn operation(&self) -> &CredentialOperation { &self.frozen.operation }
    pub fn spec(&self) -> &wire::CredentialTaskSpec { &self.frozen.spec }
    pub async fn admit(&self,c:&mut PgConnection,anchor:&Binding,policy:Uuid,version:Uuid,now:i64)->Result<(),Error>{
        if anchor != &self.anchor || self.spec().authorization != (wire::TaskAuthorization::Policy {policy_id:policy,policy_version:version})
            || !self.frozen.authority.valid(DA,c,Permission::AccountWrite,now).await? {return Err(Error::Forbidden);}
        Ok(())
    }
}
fn decode<T:serde::de::DeserializeOwned>(v:serde_json::Value)->Result<T,Error>{serde_json::from_value(v).map_err(|_|Error::Integrity)}
fn encode<T:Serialize>(v:&T)->Result<serde_json::Value,Error>{serde_json::to_value(v).map_err(|_|Error::Malformed)}
pub async fn load(c:&mut PgConnection,tenant:Uuid,device:DeviceId,id:Option<Uuid>,lock:bool)->Result<Option<Run>,Error>{
    let query = if lock {
        "SELECT da_execution,material_binding,state,result,da_permit_until,da_escrow_digest FROM rss_da.credential_runs WHERE tenant_id=$1 AND device=$2 AND da_execution IS NOT NULL AND (id=$3 OR ($3 IS NULL AND state <> '\"applied\"'::jsonb)) FOR UPDATE"
    } else {
        "SELECT da_execution,material_binding,state,result,da_permit_until,da_escrow_digest FROM rss_da.credential_runs WHERE tenant_id=$1 AND device=$2 AND da_execution IS NOT NULL AND id=$3"
    };
    sqlx::query(query).bind(tenant).bind(device.into_uuid()).bind(id).fetch_optional(c).await?.map(|row| Ok(Run{
        permit_until:row.try_get("da_permit_until")?, escrow_digest:row.try_get::<Option<Vec<u8>>,_>("da_escrow_digest")?.map(|v| v.try_into().map_err(|_|Error::Integrity)).transpose()?,
        frozen:decode(row.try_get("da_execution")?)?, anchor:decode(row.try_get("material_binding")?)?,
        state:decode(row.try_get("state")?)?,receipt:row.try_get::<Option<serde_json::Value>,_>("result")?.map(decode).transpose()?,
    })).transpose()
}

#[allow(clippy::too_many_arguments,reason="The caller fences the authenticated actor, policy version, registration and material in one transaction")]
pub async fn accept(c:&mut PgConnection,credentials:&Credentials,p:&rss_mdm_authorization_service::context::AuthorizedPrincipal, request:&Request,
    anchor:Binding,operation:CredentialOperation,policy:Uuid,version:Uuid,authority:OperationAuthority,now:i64)->Result<Status,Error>{
    if credentials.profile() != DA || request.operation_id.is_nil() { return Err(Error::Malformed); }
    let tenant = Uuid::parse_str(p.tenant_id()).map_err(|_|Error::Malformed)?;
    let current=storage::current_in(credentials.custody(),c,tenant,&anchor).await?.ok_or(Error::NotFound)?;
    if !current.current || !current.escrowed || current.validity != Validity::Verified {return Err(Error::Conflict);}
    let recipient=credentials.protection().selected_on(DA,c,tenant).await?;
    recipient.require_current(now)?;
    let recipient=wire::CredentialRecipient{key_id:recipient.id().into(),public_key:STANDARD.encode(recipient.public_key_der()?)};
    let expected=vec![wire::CredentialVersion{subject:decode(encode(&anchor.subject)?)?,revision:current.version}];
    let action=credential_tasks::operation(&operation);
    let definition_digest=wire::CredentialTaskSpec::digest(&action,&recipient,&expected,&None).map_err(|_|Error::Malformed)?;
    // The operation can wait offline. An mTLS claim issues a short-lived start permit.
    let spec=wire::CredentialTaskSpec{wire_version:wire::WIRE_VERSION,tenant_id:tenant,device_id:anchor.device,platform:wire::TaskPlatform::Windows,
        architecture:wire::TaskArchitecture::X86_64,task_id:request.operation_id,attempt_id:Uuid::new_v4(),permit:wire::TaskPermit::Start,
        expires_at:now,deadline:i64::MAX,authorization:wire::TaskAuthorization::Policy{policy_id:policy,policy_version:version},
        definition_digest,operation:action,recipient,expected,recovery:None};
    spec.validate().map_err(|_|Error::Malformed)?;
    let frozen=Frozen{request:request.clone(),authority,instance:p.instance_id().into(),actor:p.principal_id().into(),operation,spec};
    let run=Run{frozen,anchor,state:State::Accepted,receipt:None,escrow_digest:None,permit_until:0};
    let written=sqlx::query("INSERT INTO rss_da.credential_runs(expected_epoch,tenant_id,id,policy_version,origin,source_objects,material_binding,device,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,da_execution) VALUES($1,$2,$3,$4,'\"human\"','[]',$5,$6,$7,$8,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING")
        .bind(p.binding().epoch().get()).bind(tenant).bind(request.operation_id).bind(version).bind(encode(&run.anchor)?).bind(run.anchor.device.into_uuid())
        .bind(request.operation_id.to_string()).bind(now).bind(run.spec().deadline).bind(encode(&run.state)?).bind(definition_digest.as_slice()).bind(encode(&run.frozen)?)
        .execute(c).await?;
    if written.rows_affected()!=1 { return Err(Error::Conflict); }
    Ok(run.status())
}
impl Run {
    pub async fn permit(&self,c:&mut PgConnection,now:i64)->Result<wire::CredentialTaskSpec,Error> {
        let mut spec=self.spec().clone();
        spec.expires_at=now.saturating_add(300);
        sqlx::query("UPDATE rss_da.credential_runs SET da_permit_until=$3 WHERE tenant_id=$1 AND id=$2 AND da_execution IS NOT NULL")
            .bind(spec.tenant_id).bind(spec.task_id).bind(spec.expires_at).execute(c).await?;
        Ok(spec)
    }
    pub async fn settle(&mut self,c:&mut PgConnection,credentials:&Credentials,event:&Event,now:i64)->Result<bool,Error>{
        if credentials.profile()!=DA {return Err(Error::Forbidden);}
        let spec=self.spec();
        let receipt=match event {
            Event::Escrow{attempt_id,value}=>{
                if spec.attempt_id!=*attempt_id || value.materials.len()!=1 || value.definition_digest!=spec.definition_digest
                    || value.materials[0].subject!=spec.expected[0].subject || value.materials[0].expected_revision!=spec.expected[0].revision {return Err(Error::Conflict);}
                use sha2::{Digest,Sha256};
                let digest:[u8;32]=Sha256::digest(serde_json::to_vec(value).map_err(|_|Error::Malformed)?).into();
                if let Some(previous)=self.escrow_digest { return if previous==digest {Ok(true)} else {Err(Error::Conflict)}; }
                if now>=self.permit_until {return Err(Error::Forbidden);}
                let receipts=credential_tasks::escrow_on(c,credentials.custody(),credentials.protection(),Some(&self.anchor),spec,value).await?;
                let [candidate]=receipts.as_slice() else {return Err(Error::Conflict);};
                self.escrow_digest=Some(digest);
                self.state=State::PendingApplication;
                candidate.clone()
            }
            Event::Applied{attempt_id,definition_digest,receipt}=>{
                if spec.attempt_id!=*attempt_id || spec.definition_digest!=*definition_digest || self.receipt.as_ref()!=Some(receipt){return Err(Error::Conflict);}
                if self.state==State::Applied {return Ok(true);}
                let coordinates=Coordinates{profile:DA, tenant:spec.tenant_id,material:receipt.material,binding:self.anchor.clone(),version:receipt.version};
                if self.frozen.request.action==Action::Rotate {
                    storage::verify_in(credentials.custody(),c,&coordinates,spec.task_id).await?;
                } else {
                    let current=storage::current_in(credentials.custody(),c,spec.tenant_id,&self.anchor).await?.ok_or(Error::Conflict)?;
                    if current.id!=receipt.material || current.version!=receipt.version || current.validity!=Validity::Verified {return Err(Error::Conflict);}
                }
                self.state=State::Applied;
                receipt.clone()
            }
        };
        self.receipt=Some(receipt);
        sqlx::query("UPDATE rss_da.credential_runs SET state=$3,result=$4,da_escrow_digest=$5 WHERE tenant_id=$1 AND id=$2 AND da_execution IS NOT NULL")
            .bind(self.spec().tenant_id).bind(self.spec().task_id).bind(encode(&self.state)?).bind(encode(&self.receipt)?).bind(self.escrow_digest.as_ref().map(|v|v.as_slice())).execute(c).await?;
        Ok(false)
    }
}
