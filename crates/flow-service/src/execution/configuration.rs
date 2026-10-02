//! Native configuration claims are isolated by target and native object, not one slot per device.
use super::*;
use crate::planning::{
    configuration::{Configuration, Object},
    policies::{self, Frozen, Policy},
};
use rss_mdm_policy::Exit;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy)]
pub enum Diagnosis {
    WaitingScope,
    WaitingRegistration,
    WaitingCapability,
    NotApplicable,
    Conflict,
    GroupConflict,
    RemovalBlocked,
    Removing,
    Unassigned,
}
impl Diagnosis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitingScope => "waiting_scope",
            Self::WaitingRegistration => "waiting_registration",
            Self::WaitingCapability => "waiting_capability",
            Self::NotApplicable => "not_applicable",
            Self::Conflict => "configuration_conflict",
            Self::GroupConflict => "native_group_conflict",
            Self::RemovalBlocked => "removal_blocked_by_shared_unit",
            Self::Removing => "removing",
            Self::Unassigned => "unassigned",
        }
    }
}
pub async fn pending(tx: &mut PgTransaction<'_>, device: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT coalesce((SELECT input_revision>observed_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2),false)").bind(tenant).bind(device).fetch_one(c).await})).await?)
}
struct Desired<'a> {
    policy: &'a Policy,
    native: Configuration,
    digest: Vec<u8>,
    object_digests: BTreeMap<Object, Vec<u8>>,
    objects: Vec<Object>,
    ready: bool,
}
fn desired<'a>(
    service: &ExecutionService,
    device: &str,
    policy: &'a Policy,
    frozen: &'a Frozen,
    ready: bool,
) -> Result<Desired<'a>> {
    let Frozen::Configuration { native, .. } = frozen else {
        return Err(Error::Malformed.into());
    };
    let native = native.open(
        &service.protection,
        service.tenant,
        crate::planning::configuration::Owner::Policy {
            policy: policy.id,
            version: policy.version,
        },
    )?;
    let objects = native.objects()?;
    let object_digests = native.object_digests(&service.protection, service.tenant, device)?;
    Ok(Desired {
        policy,
        digest: crate::protection::fingerprint(
            &service.protection,
            service.tenant,
            device,
            "native-configuration/v3",
            &(&native.target, &native.apply),
        )?,
        objects,
        object_digests,
        native,
        ready,
    })
}
// Read-only planning over loaded claims; transaction code owns applying the decision.
fn claim_diagnosis(
    index: usize,
    inputs: &[Desired<'_>],
    _owners: &BTreeMap<Object, Vec<usize>>,
) -> Option<Diagnosis> {
    let input = &inputs[index];
    for other in inputs {
        if input
            .objects
            .iter()
            .any(|o| other.objects.iter().any(|p| o.overlaps(p)))
        {
            if input.objects.iter().any(|o| {
                other.objects.iter().any(|p| {
                    o.overlaps(p)
                        && (o != p || input.object_digests.get(o) != other.object_digests.get(p))
                })
            }) {
                return Some(Diagnosis::Conflict);
            }
            if input.digest != other.digest {
                return Some(Diagnosis::GroupConflict);
            }
        }
    }
    if !inputs.iter().any(|d| d.digest == input.digest && d.ready) {
        Some(Diagnosis::WaitingScope)
    } else {
        None
    }
}
impl ExecutionService {
    pub async fn reconcile_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        let tenant = tx.tenant_id().to_string();
        let instance = self.instance.clone();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(crate::authorization::lock_on(c, &tenant, &instance).await) })
        })
        .await??;
        crate::transaction::lock(tx).await?;
        storage::lock(tx, device).await?;
        self.reconcile_agent_install_in(tx, device, audit).await?;
        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let revision=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,i64>("SELECT input_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(name).fetch_one(c).await})).await?;
        let (wanted, waiting) = desired_in(&self.policy_reader, tx, device).await?;
        let prior = prior_claims(&self.policy_reader, tx, device).await?;
        let mut inputs = Vec::new();
        for (p, f) in &wanted {
            inputs.push(desired(self, device, p, f, true)?);
        }
        for (p, f) in &waiting {
            inputs.push(desired(self, device, p, f, false)?);
        }
        // An unresolved prior Scope must retain its own objects, not freeze every device object.
        for (p, f) in &prior {
            if !inputs.iter().any(|d| d.policy.id == p.id)
                && !policies::storage::withdrawn_in(tx, p, device).await?
            {
                inputs.push(desired(self, device, p, f, false)?);
            }
        }
        let mut owners: BTreeMap<Object, Vec<usize>> = BTreeMap::new();
        for (i, input) in inputs.iter().enumerate() {
            for object in &input.objects {
                owners.entry(object.clone()).or_default().push(i);
            }
        }
        let mut done = BTreeSet::new();
        for (index, input) in inputs.iter().enumerate() {
            if !done.insert(input.digest.clone()) {
                continue;
            }
            let same = inputs
                .iter()
                .filter(|d| d.digest == input.digest)
                .collect::<Vec<_>>();
            let diagnosis = claim_diagnosis(index, &inputs, &owners);
            let state = object_state(tx, device, &input.objects).await?;
            if let Some(diagnosis) = diagnosis {
                save_objects(
                    tx,
                    device,
                    &input.objects,
                    state,
                    Some(&input.object_digests),
                    Some(diagnosis),
                )
                .await?;
                desired_claims(tx, device, &input.objects, &inputs, &owners, state).await?;
                continue;
            }
            let first = same
                .iter()
                .find(|d| d.ready)
                .copied()
                .unwrap_or(&inputs[index]);
            let id = if let Some(id) = state
                && self.reuse_configuration_in(tx, id, &input.digest).await?
            {
                id
            } else {
                cancel_objects(self, tx, device, &input.objects).await?;
                let id = Uuid::new_v4();
                let deadline = storage::now(tx)
                    .await?
                    .checked_add(3600)
                    .ok_or(Error::Malformed)?;
                let request =
                    first
                        .native
                        .request(id, first.policy.version.to_string(), deadline, false)?;
                self.queue_policy_configuration(tx, device, first.policy, &request, false, audit)
                    .await?;
                id
            };
            save_objects(
                tx,
                device,
                &input.objects,
                Some(id),
                Some(&input.object_digests),
                None,
            )
            .await?;
            desired_claims(tx, device, &input.objects, &inputs, &owners, Some(id)).await?;
        }
        // Withdraw only when every object addressed by this native operation has no remaining owner.
        let mut removed = BTreeSet::new();
        for (policy, frozen) in &prior {
            let old = desired(self, device, policy, frozen, false)?;
            if !removed.insert(old.digest.clone()) {
                continue;
            }
            let unowned = old
                .objects
                .iter()
                .filter(|o| !owners.keys().any(|current| o.overlaps(current)))
                .cloned()
                .collect::<Vec<_>>();
            if unowned.is_empty() {
                continue;
            }
            let Frozen::Configuration { exit, .. } = frozen else {
                return Err(Error::Malformed.into());
            };
            let state = object_state(tx, device, &old.objects).await?;
            let mut removal_contracts = BTreeSet::new();
            let mut retain = !matches!(exit, Exit::Remove);
            for (co_policy, co_frozen) in &prior {
                let co = desired(self, device, co_policy, co_frozen, false)?;
                if co.digest == old.digest {
                    let Frozen::Configuration { exit, .. } = co_frozen else {
                        return Err(Error::Malformed.into());
                    };
                    retain |= !matches!(exit, Exit::Remove);
                    removal_contracts.insert(
                        serde_json::to_vec(&co.native.remove).map_err(|_| Error::Malformed)?,
                    );
                }
            }
            if !retain && removal_contracts.len() > 1 {
                save_objects(
                    tx,
                    device,
                    &old.objects,
                    state,
                    Some(&old.object_digests),
                    Some(Diagnosis::RemovalBlocked),
                )
                .await?;
                continue;
            }
            if retain || old.native.remove.is_none() {
                replace_claims(tx, device, &unowned, &[], None).await?;
                save_objects(
                    tx,
                    device,
                    &unowned,
                    state,
                    None,
                    Some(Diagnosis::Unassigned),
                )
                .await?;
                continue;
            }
            if unowned.len() != old.objects.len() {
                // Keep the old publication's remaining claims so the last owner's departure
                // wakes this exact native removal. Never cut children from its ordered unit.
                save_objects(
                    tx,
                    device,
                    &unowned,
                    state,
                    Some(&old.object_digests),
                    Some(Diagnosis::RemovalBlocked),
                )
                .await?;
                continue;
            }
            let mut operation = None;
            if let Some(id) = state {
                let op = storage::load(tx, &self.protection, id).await?;
                let command = self.required_command(tx, &op).await?;
                let is_remove = matches!(
                    op.approval,
                    authority::ExecutionAuthority::Policy { remove: true, .. }
                );
                if is_remove && command.status() == dc::Status::Applied {
                    replace_claims(tx, device, &old.objects, &[], None).await?;
                    save_objects(
                        tx,
                        device,
                        &old.objects,
                        Some(id),
                        None,
                        Some(Diagnosis::Unassigned),
                    )
                    .await?;
                    continue;
                }
                if is_remove && (!command.status().is_terminal() || dispatched_in(tx, id).await?) {
                    operation = Some(id);
                }
            }
            let id = if let Some(id) = operation {
                id
            } else {
                cancel_objects(self, tx, device, &old.objects).await?;
                let id = Uuid::new_v4();
                let deadline = storage::now(tx)
                    .await?
                    .checked_add(3600)
                    .ok_or(Error::Malformed)?;
                let request = old
                    .native
                    .request(id, policy.version.to_string(), deadline, true)?;
                self.queue_policy_configuration(tx, device, policy, &request, true, audit)
                    .await?;
                id
            };
            save_objects(
                tx,
                device,
                &old.objects,
                Some(id),
                Some(&old.object_digests),
                Some(Diagnosis::Removing),
            )
            .await?;
            replace_claims(tx, device, &old.objects, &[policy], Some(id)).await?;
        }
        let tenant = tx.tenant_id().to_string();
        let device = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.configuration_devices SET observed_revision=$3 WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(device).bind(revision).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
    async fn reuse_configuration_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        digest: &[u8],
    ) -> Result<bool> {
        let old = storage::load(tx, &self.protection, id).await?;
        let current = storage::current_registration(tx, &old.device).await?;
        let foreign = current != (old.registration, old.registration_generation);
        let previous = crate::protection::fingerprint(
            &self.protection,
            self.tenant,
            &old.device,
            "native-configuration/v3",
            &(&old.request.target, &old.request.task),
        )?;
        let command = self.required_command(tx, &old).await?;
        let now = storage::now(tx).await?;
        if matches!(
            command.status(),
            dc::Status::TimedOut
                | dc::Status::Cancelled
                | dc::Status::Rejected
                | dc::Status::Superseded
        ) || (foreign && !command.status().is_terminal())
        {
            let sent = dispatched_in(tx, id).await?;
            if sent {
                return Ok(true);
            }
        }
        // Historical success cannot establish state for a replacement enrollment. The
        // uncertain-sent branch above remains fenced instead of blindly repeating a mutation.
        if foreign {
            return Ok(false);
        }
        if previous == digest
            && (command.status() == dc::Status::Applied
                || storage::approval_valid(&self.protection, tx, &old, now).await?)
            && !matches!(
                command.status(),
                dc::Status::TimedOut
                    | dc::Status::Cancelled
                    | dc::Status::Superseded
                    | dc::Status::Rejected
            )
        {
            return Ok(true);
        }
        if !command.status().is_terminal()
            && self
                .store
                .cancel(tx, old.scope, &old.command_id()?, old.coordinate)
                .await?
                .outcome
                == dc::Outcome::OutOfOrder
        {
            return Err(Error::Conflict.into());
        }
        Ok(false)
    }
    async fn queue_policy_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        policy: &Policy,
        input: &Create,
        remove: bool,
        audit: &RequestAudit,
    ) -> Result<()> {
        let authority = crate::execution::authority::ExecutionAuthority::Policy {
            tenant: tx.tenant_id().to_string(),
            policy: policy.id,
            version: policy.version,
            device: device.into(),
            remove,
        };
        let fingerprint = crate::protection::fingerprint(
            &self.protection,
            self.tenant,
            device,
            "configuration-command/v3",
            &(input, policy.id, policy.version, remove),
        )?;
        let fact_audit = audit.transaction_copy();
        fact_audit.identify_service("configuration-policy");
        fact_audit.operation(input.operation_id, "command_accept");
        fact_audit.target(device);
        let result = self
            .queue_authorized_in(tx, device, input, authority, fingerprint, &fact_audit)
            .await;
        fact_audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result?;
        let target = service::target(tx.tenant_id(), device);
        rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await?;
        Ok(())
    }
}
async fn desired_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<(Claims, Claims)> {
    let mut desired = Vec::new();
    let mut waiting = Vec::new();
    let mut after = Uuid::nil();
    loop {
        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let ids=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar::<_,Uuid>("SELECT p.id FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.id>$3 AND p.definition->'action'->>'kind'='configuration' AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded') ORDER BY p.id LIMIT 64")
                    .bind(tenant).bind(name).bind(after).fetch_all(c).await
            })).await?;
        if ids.is_empty() {
            break;
        }
        for id in ids {
            after = id;
            let p = policies::storage::read_in(reader, tx, id)
                .await?
                .ok_or(Error::NotFound)?;
            let eligible = policies::storage::eligible_in(tx, &p, device)
                .await?
                .is_some();
            let (_, frozen) = policies::storage::version_in(reader, tx, p.version).await?;
            if eligible {
                desired.push((p, frozen));
            } else {
                waiting.push((p, frozen));
            }
        }
    }
    Ok((desired, waiting))
}
type Claims = Vec<(Policy, Frozen)>;

async fn prior_claims(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<Claims> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let versions=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT DISTINCT version FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2 ORDER BY version").bind(tenant).bind(device).fetch_all(c).await})).await?;
    let mut claims = Vec::new();
    for version in versions {
        let (mut policy, frozen) = policies::storage::version_in(reader, tx, version).await?;
        policy.version = version;
        claims.push((policy, frozen));
    }
    Ok(claims)
}
async fn object_rows(
    tx: &mut PgTransaction<'_>,
    device: &str,
    objects: &[Object],
) -> Result<Vec<(Option<Uuid>, Option<Vec<u8>>)>> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let objects = objects.to_vec();
    Ok(tx.with_connection(move|c|Box::pin(async move {let mut rows=Vec::new();for o in objects {
        let row=sqlx::query_as::<_,(Option<Uuid>,Option<Vec<u8>>)>("SELECT operation,digest FROM mdm_planning.configuration_objects WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND platform=$4 AND object_kind=$5 AND object_key=$6 FOR UPDATE").bind(&tenant).bind(&device).bind(o.user).bind(o.platform).bind(o.kind).bind(o.key).fetch_optional(&mut *c).await?;
        rows.push(row.unwrap_or((None,None)));
    }Ok(rows)})).await?)
}
async fn object_state(
    tx: &mut PgTransaction<'_>,
    device: &str,
    objects: &[Object],
) -> Result<Option<Uuid>> {
    let rows = object_rows(tx, device, objects).await?;
    let Some((Some(id), _)) = rows.first() else {
        return Ok(None);
    };
    Ok(rows.iter().all(|r| r.0 == Some(*id)).then_some(*id))
}
async fn cancel_objects(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    device: &str,
    objects: &[Object],
) -> Result<()> {
    let ids = object_rows(tx, device, objects)
        .await?
        .into_iter()
        .filter_map(|r| r.0)
        .collect::<BTreeSet<_>>();
    for id in ids {
        let op = storage::load(tx, &service.protection, id).await?;
        let command = service.required_command(tx, &op).await?;
        if !command.status().is_terminal()
            && service
                .store
                .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
                .await?
                .outcome
                == dc::Outcome::OutOfOrder
        {
            return Err(Error::Conflict.into());
        }
    }
    Ok(())
}
async fn save_objects(
    tx: &mut PgTransaction<'_>,
    device: &str,
    objects: &[Object],
    operation: Option<Uuid>,
    digests: Option<&BTreeMap<Object, Vec<u8>>>,
    diagnosis: Option<Diagnosis>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let objects = objects.to_vec();
    let digests = digests.cloned();
    let preserve = matches!(
        diagnosis,
        Some(
            Diagnosis::Conflict
                | Diagnosis::GroupConflict
                | Diagnosis::WaitingScope
                | Diagnosis::RemovalBlocked
        )
    );
    let diagnosis = diagnosis.map(Diagnosis::as_str);
    tx.with_connection(move|c|Box::pin(async move {for o in objects {
        let digest = digests.as_ref().and_then(|values| values.get(&o));
        sqlx::query("INSERT INTO mdm_planning.configuration_objects(tenant_id,device,user_key,platform,object_kind,object_key,operation,digest,diagnosis) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,device,user_key,platform,object_kind,object_key) DO UPDATE SET operation=CASE WHEN $10 THEN configuration_objects.operation ELSE excluded.operation END,digest=CASE WHEN $10 THEN configuration_objects.digest ELSE excluded.digest END,diagnosis=excluded.diagnosis").bind(&tenant).bind(&device).bind(o.user).bind(o.platform).bind(o.kind).bind(o.key).bind(operation).bind(digest).bind(diagnosis).bind(preserve).execute(&mut *c).await?;
    }Ok(())})).await?;
    Ok(())
}
async fn replace_claims(
    tx: &mut PgTransaction<'_>,
    device: &str,
    objects: &[Object],
    policies: &[&Policy],
    operation: Option<Uuid>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let objects = objects.to_vec();
    let policies = policies
        .iter()
        .map(|p| (p.id, p.version))
        .collect::<Vec<_>>();
    tx.with_connection(move|c|Box::pin(async move {for o in objects {
        let ids=policies.iter().map(|p|p.0).collect::<Vec<_>>();
        sqlx::query("DELETE FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND platform=$4 AND object_kind=$5 AND object_key=$6 AND NOT(policy=ANY($7))").bind(&tenant).bind(&device).bind(&o.user).bind(&o.platform).bind(&o.kind).bind(&o.key).bind(ids).execute(&mut *c).await?;
        for &(policy,version) in &policies {sqlx::query("INSERT INTO mdm_planning.configuration_claims(tenant_id,device,user_key,platform,object_kind,object_key,policy,version,operation) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,policy,device,user_key,platform,object_kind,object_key) DO UPDATE SET version=excluded.version,operation=excluded.operation").bind(&tenant).bind(&device).bind(&o.user).bind(&o.platform).bind(&o.kind).bind(&o.key).bind(policy).bind(version).bind(operation).execute(&mut *c).await?;}
    }Ok(())})).await?;
    Ok(())
}
async fn desired_claims(
    tx: &mut PgTransaction<'_>,
    device: &str,
    objects: &[Object],
    inputs: &[Desired<'_>],
    owners: &BTreeMap<Object, Vec<usize>>,
    operation: Option<Uuid>,
) -> Result<()> {
    for o in objects {
        let policies = owners[o]
            .iter()
            .map(|&i| inputs[i].policy)
            .collect::<Vec<_>>();
        replace_claims(tx, device, std::slice::from_ref(o), &policies, operation).await?;
    }
    Ok(())
}

async fn dispatched_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move { sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' AND state<>'pending')").bind(tenant).bind(id).fetch_one(c).await })).await?)
}
