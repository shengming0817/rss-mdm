//! DA deployment evidence verified by an explicitly configured authority.
//! A task ACK, browser input or an unverified observation cannot create this fact.
use crate::{Error, database::db};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_access::deployment::{Observation, PlatformConfiguration};
use rss_mdm_registration_service::device::endpoints::{self, DaRegistration};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::collections::BTreeMap;
use uuid::Uuid;
#[derive(Clone, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedObservation {
    pub payload: String,
    pub signature: String,
}
/// Provisioned by the deployment host, never supplied alongside an untrusted observation.
pub struct Authority {
    pub id: Uuid,
    pub public_key: [u8; 32],
}
#[derive(Clone, Default)]
pub struct Authorities {
    keys: BTreeMap<Uuid, [u8; 32]>,
}
impl Authorities {
    pub fn new(values: Vec<Authority>) -> Result<Self, Error> {
        if values.len() > 16 {
            return Err(Error::Configuration);
        }
        let mut keys = BTreeMap::new();
        for v in values {
            if v.id.is_nil() || keys.insert(v.id, v.public_key).is_some() {
                return Err(Error::Configuration);
            }
        }
        Ok(Self { keys })
    }
    pub fn fingerprints(&self) -> BTreeMap<Uuid, String> {
        self.keys
            .iter()
            .map(|(id, key)| (*id, format!("{:x}", Sha256::digest(key))))
            .collect()
    }
    fn verify(&self, signed: &SignedObservation, now: i64) -> Result<Observation, Error> {
        if signed.payload.len() > 32768 || signed.signature.len() > 128 {
            return Err(Error::Malformed);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&signed.payload)
            .map_err(|_| Error::Malformed)?;
        let o: Observation = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        let key = self.keys.get(&o.authority).ok_or(Error::Forbidden)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .map_err(|_| Error::Malformed)?;
        let mut message = b"rss.da.deployment.v1\0".to_vec();
        message.extend_from_slice(&bytes);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
            .verify(&message, &signature)
            .map_err(|_| Error::Forbidden)?;
        o.validate(now)?;
        Ok(o)
    }
    pub async fn record_on(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        installation: Uuid,
        signed: &SignedObservation,
    ) -> Result<bool, Error> {
        let now = super::platform_sso::store::now(c).await?;
        let o = self.verify(signed, now)?;
        if o.tenant.to_string() != tenant.to_string() || o.installation != installation {
            return Err(Error::Forbidden);
        }
        crate::delivery::lock_da_target(c, &tenant.to_string(), &o.device, None).await?;
        let current = endpoints::current_da_in(c, &tenant.to_string(), &o.device)
            .await?
            .ok_or(Error::Forbidden)?;
        if current.registration_id != o.registration || current.generation != o.generation {
            return Err(Error::Forbidden);
        }
        let old:Option<(i64,String)>=sqlx::query_as("SELECT sequence,payload FROM rss_da.deployment_evidence WHERE tenant_id=$1 AND registration=$2 AND generation=$3 AND authority=$4 FOR UPDATE").bind(o.tenant).bind(o.registration).bind(o.generation).bind(o.authority).fetch_optional(&mut *c).await.map_err(db)?;
        if let Some((sequence, payload)) = old {
            if o.sequence < sequence || (o.sequence == sequence && payload != signed.payload) {
                return Err(Error::Conflict);
            }
            if o.sequence == sequence {
                return Ok(false);
            }
        }
        let fingerprint = self
            .fingerprints()
            .remove(&o.authority)
            .ok_or(Error::Configuration)?;
        sqlx::query("INSERT INTO rss_da.deployment_evidence(tenant_id,registration,generation,authority,sequence,fingerprint,payload,signature,document,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,registration,generation,authority) DO UPDATE SET sequence=excluded.sequence,fingerprint=excluded.fingerprint,payload=excluded.payload,signature=excluded.signature,document=excluded.document,received_at=excluded.received_at")
            .bind(o.tenant).bind(o.registration).bind(o.generation).bind(o.authority).bind(o.sequence).bind(&fingerprint).bind(&signed.payload).bind(&signed.signature).bind(serde_json::to_value(&o).map_err(|_|Error::Malformed)?).bind(now).execute(&mut *c).await.map_err(db)?;
        if !o.revoked {
            for report in &o.applications {
                crate::device_access::storage::deployment_result_in(c, &o, report, &fingerprint)
                    .await?;
            }
        }
        Ok(true)
    }
    pub async fn native_on(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        installation: Uuid,
        anchor: &DaRegistration,
        now: i64,
    ) -> Result<Observation, Error> {
        let rows=sqlx::query("SELECT payload,signature FROM rss_da.deployment_evidence WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 ORDER BY authority LIMIT 17")
            .bind(tenant.to_string()).bind(anchor.registration_id).bind(anchor.generation).fetch_all(&mut *c).await.map_err(db)?;
        if rows.len() > 16 {
            return Err(Error::Capacity);
        }
        let mut selected = None;
        for r in rows {
            let signed = SignedObservation {
                payload: r.try_get("payload").map_err(db)?,
                signature: r.try_get("signature").map_err(db)?,
            };
            let o = self.verify(&signed, now)?;
            if o.tenant.to_string() != tenant.to_string()
                || o.installation != installation
                || o.device != anchor.device
                || o.registration != anchor.registration_id
                || o.generation != anchor.generation
                || o.revoked
            {
                return Err(Error::Forbidden);
            }
            let selection = crate::device_access::execution::admission::policy_on(
                tenant, c, o.tenant, &o.device, o.policy,
            )
            .await?;
            if selection.version != o.policy_version {
                return Err(Error::Forbidden);
            }
            if selected.as_ref().is_some_and(|old: &Observation| {
                old.local_session != o.local_session
                    || old.policy != o.policy
                    || old.policy_version != o.policy_version
                    || serde_json::to_value(&old.deployment).ok()
                        != serde_json::to_value(&o.deployment).ok()
            }) {
                return Err(Error::Conflict);
            }
            selected = Some(o);
        }
        selected.ok_or(Error::Forbidden)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Borrowed transaction, tenant/installation/registration boundary and expected platform/profile/time are independently qualified"
    )]
    pub async fn current_on(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        installation: Uuid,
        anchor: &DaRegistration,
        expected: &PlatformConfiguration,
        profile: Uuid,
        now: i64,
    ) -> Result<Observation, Error> {
        let value = self.native_on(c, tenant, installation, anchor, now).await?;
        if !value.qualifies(expected, profile, now) {
            return Err(Error::Forbidden);
        }
        Ok(value)
    }
}
impl crate::Service {
    pub async fn record_deployment(
        &self,
        authorities: &Authorities,
        value: &SignedObservation,
        a: &RequestAudit,
    ) -> Result<(), Error> {
        // A verifier owns authentication. The resulting fact and its receipt share the Audit transaction.
        a.operation(
            Uuid::new_v4(),
            "da_deployment_evidence",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(
            a,
            (authorities, value, self.tenant, self.service_id()?, a),
            |ctx, c| {
                Box::pin(async move {
                    let now = super::platform_sso::store::now(c).await?;
                    let verified = ctx.0.verify(ctx.1, now)?;
                    ctx.4
                        .identify_service(&format!("da-deployment:{}", verified.authority));
                    let changed = ctx.0.record_on(c, ctx.2, ctx.3, ctx.1).await?;
                    Ok(crate::service::Change {
                        value: (),
                        replay: !changed,
                    })
                })
            },
        )
        .await
    }
}
