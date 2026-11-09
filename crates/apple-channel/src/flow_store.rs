use crate::device::DevicePrincipal;
use crate::protocol_types::{self as channels, AppleCommand, AppleDispatch, Pending};
use crate::{Error, database::db};
use rss_mdm_apple_mdm::protocol as wire;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub struct Store {
    pub protection: std::sync::Arc<rss_mdm_native_protection::Protector>,
}
impl channels::AppleProfiles for Store {
    fn declaration_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user: &'a str,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move { crate::ddm::candidates(c, p, user).await })
    }

    fn previous_declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user: String,
        owner: String,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT d.operation FROM mdm_apple.declarations AS d INNER JOIN mdm_access.devices AS o ON (o.tenant_id, o.id) = (d.tenant_id, d.device) WHERE d.tenant_id = CAST($1 AS uuid) AND o.id = $2 AND d.user_key = $3 AND d.owner = $4 AND d.retired_at IS NULL ORDER BY d.operation")
            .bind(tenant).bind(&device).bind(user).bind(owner).fetch_all(c).await.map_err(storage)
        })
    }

    fn reserve_profile<'a>(
        &'a self,
        c: &'a mut PgConnection,
        target: channels::AppleRegistration,
        command: AppleCommand,
    ) -> Pending<'a, ()> {
        Box::pin(
            async move { crate::profiles::reserve(c, &self.protection, &target, &command).await },
        )
    }
    fn previous_profiles<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user_key: String,
        identifier: String,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT operation FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND identifier=$4 AND retired_at IS NULL ORDER BY operation").bind(tenant).bind(&device).bind(user_key).bind(identifier).fetch_all(c).await.map_err(storage)
        })
    }
}
impl channels::ApplePush for Store {
    fn needs_prerequisites<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT count(*)<>2 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase IN('resolve_device','resolve_security') AND state='acknowledged' AND accepted").bind(tenant).bind(operation).fetch_one(c).await.map_err(storage)
        })
    }
    fn push_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND state='active' AND (push_outcome IS DISTINCT FROM 'rejected' OR push_configuration IS DISTINCT FROM $2) AND next_push<=clock_timestamp() AND (push_lease_until IS NULL OR push_lease_until<clock_timestamp()))").bind(tenant).bind(configuration.as_slice()).fetch_one(c).await.map_err(storage)
        })
    }
    fn push_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, Vec<channels::PushCandidate>> {
        Box::pin(async move {
            let rows=sqlx::query("SELECT device, user_key, material, token_revision FROM mdm_apple.channels WHERE tenant_id = CAST($1 AS uuid) AND state = 'active' AND (push_outcome IS DISTINCT FROM 'rejected' OR push_configuration IS DISTINCT FROM $2) AND next_push <= clock_timestamp() AND (push_lease_until IS NULL OR push_lease_until < clock_timestamp()) ORDER BY next_push, device, user_key LIMIT 32 FOR UPDATE SKIP LOCKED").bind(&tenant).bind(configuration.as_slice()).fetch_all(&mut *c).await.map_err(storage)?;
            let mut result = Vec::new();
            for row in rows {
                let device = row.try_get("device").map_err(storage)?;
                let active = rss_mdm_registration_service::device::store::active_source_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    device,
                    rss_mdm_inventory::ReportSource::MdmApple,
                )
                .await
                .map_err(Error::from)?;
                let user_key: String = row.try_get("user_key").map_err(storage)?;
                let revision: i64 = row.try_get("token_revision").map_err(storage)?;
                let sealed: Vec<u8> = row.try_get("material").map_err(storage)?;
                let aad = crate::material::aad(
                    &tenant,
                    device,
                    &user_key,
                    revision,
                    "apple.push.material",
                )?;
                // The composition root binds this immutable key at startup. Authentication
                // or decoding failure here belongs to this row; DB/AAD failures propagate.
                let material = self
                    .protection
                    .open_bytes(&sealed, &aad)
                    .ok()
                    .and_then(|plain| {
                        serde_json::from_slice::<crate::material::Push>(plain.expose()).ok()
                    })
                    .filter(|value| {
                        !value.token.is_empty()
                            && value.token.len() <= 512
                            && !value.magic.is_empty()
                            && value.magic.len() <= 1024
                    });
                let disposition = if !active {
                    channels::PushDisposition::Inactive
                } else if let Some(material) = material {
                    channels::PushDisposition::Ready {
                        token: material.token,
                        magic: material.magic,
                    }
                } else {
                    let scope = self
                        .protection
                        .mac(user_key.as_bytes(), &aad)
                        .map_err(|_| Error::Unavailable(crate::Failure::AppleStorage))?;
                    let scope: String = scope.iter().map(|byte| format!("{byte:02x}")).collect();
                    channels::PushDisposition::Invalid { scope }
                };
                result.push(channels::PushCandidate {
                    revision,
                    user_key,
                    device: row.try_get("device").map_err(storage)?,
                    disposition,
                });
            }
            Ok(result)
        })
    }
    fn reject_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user_key: String,
        revision: i64,
        scope: String,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_apple.channels SET state = 'pending_token', push_id = NULL, push_lease_until = NULL, push_status = NULL, push_outcome = 'rejected' WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND user_key = $3 AND token_revision = $4")
                        .bind(&tenant).bind(&device).bind(&user_key).bind(revision)
                        .execute(&mut *c).await.map_err(storage)?;
            if user_key.is_empty() {
                sqlx::query("UPDATE mdm_apple.devices SET state = 'pending_token' WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state = 'active'")
                            .bind(&tenant).bind(&device).execute(&mut *c).await.map_err(storage)?;
            }
            eprintln!(
                "{}",
                serde_json::json!({"event":"apple_push_material_rejected","device":device,"token_revision":revision,"channel":if user_key.is_empty(){"device"}else{"user"},"scope":scope,"failure":"material_integrity"})
            );
            Ok(())
        })
    }
    fn defer_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user_key: String,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_apple.channels SET next_push = clock_timestamp() + CAST('30 seconds' AS interval) WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND user_key = $3").bind(tenant).bind(&device).bind(user_key).execute(c).await.map_err(storage)?;
            Ok(())
        })
    }
    fn lease_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Uuid,
        device: String,
        user_key: String,
        configuration: [u8; 32],
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_apple.channels SET push_failures = CASE WHEN push_configuration IS DISTINCT FROM $4 THEN 0 ELSE push_failures END, push_configuration = $4, push_id = CAST($3 AS uuid), push_lease_until = clock_timestamp() + CAST('15 seconds' AS interval), next_push = clock_timestamp() + CAST('30 seconds' AS interval) WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND user_key = $5").bind(tenant).bind(&device).bind(wake).bind(configuration.as_slice()).bind(user_key).execute(c).await.map_err(storage)?;
            Ok(())
        })
    }
    fn settle_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: channels::Wake,
        status: Option<u16>,
        outcome: channels::PushOutcome,
    ) -> Pending<'a, Option<u64>> {
        Box::pin(async move {
            let unregistered = outcome == channels::PushOutcome::Unregistered;
            let outcome = outcome.as_str();
            let old=sqlx::query("SELECT push_lease_until IS NULL AS settled, push_status, push_outcome FROM mdm_apple.channels WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND push_id = CAST($3 AS uuid) AND token_revision = $4 AND user_key = $5 FOR UPDATE").bind(&tenant).bind(&wake.device).bind(wake.id).bind(wake.revision).bind(&wake.user_key).fetch_optional(&mut *c).await.map_err(storage)?;
            let Some(old) = old else { return Ok(None) };
            if old.try_get::<bool, _>("settled").map_err(storage)? {
                return Ok(Some(
                    if old
                        .try_get::<Option<i32>, _>("push_status")
                        .map_err(storage)?
                        == status.map(i32::from)
                        && old
                            .try_get::<Option<String>, _>("push_outcome")
                            .map_err(storage)?
                            .as_deref()
                            == Some(outcome)
                    {
                        0
                    } else {
                        2
                    },
                ));
            }
            let changed=sqlx::query("UPDATE mdm_apple.channels SET push_lease_until = NULL, push_status = $5, push_outcome = $6, next_push = clock_timestamp() + make_interval(secs => CASE WHEN $6 = 'retryable' THEN GREATEST(CASE WHEN $5 >= 500 THEN 900 ELSE 30 END, 30 * (1 << LEAST(push_failures, 5))) ELSE 30 END), push_failures = CASE WHEN $6 = 'retryable' THEN LEAST(push_failures + 1, 6) ELSE 0 END, material = CASE WHEN $7 THEN NULL ELSE material END, material_digest = CASE WHEN $7 THEN NULL ELSE material_digest END, state = CASE WHEN $7 THEN 'pending_token' ELSE state END WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND push_id = CAST($3 AS uuid) AND token_revision = $4 AND user_key = $8 AND state = 'active' AND push_lease_until IS NOT NULL").bind(&tenant).bind(&wake.device).bind(wake.id).bind(wake.revision).bind(status.map(i32::from)).bind(outcome).bind(unregistered).bind(&wake.user_key).execute(&mut *c).await.map_err(storage)?.rows_affected();
            if changed == 1 && unregistered && wake.user_key.is_empty() {
                sqlx::query("UPDATE mdm_apple.devices SET state = 'pending_token' WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state = 'active'").bind(tenant).bind(&wake.device).execute(c).await.map_err(storage)?;
            }
            Ok(Some(changed))
        })
    }
    fn maintenance_due<'a>(
        &'a self,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let existing: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND phase = 'renew' AND state IN ('pending', 'sent', 'not_now') AND next_attempt <= clock_timestamp() AND deadline > clock_timestamp()) OR EXISTS (SELECT 1 FROM mdm_pki.trust AS t WHERE t.tenant_id = CAST($1 AS uuid) AND t.purpose = 'apple' AND NOT EXISTS (SELECT 1 FROM mdm_pki.installations AS i WHERE i.tenant_id = t.tenant_id AND i.purpose = t.purpose AND i.device = CAST($2 AS text) AND i.revision = t.revision) AND NOT EXISTS (SELECT 1 FROM mdm_apple.attempts AS a INNER JOIN mdm_apple.trust_deliveries AS d ON (d.tenant_id, d.id) = (a.tenant_id, a.trust) WHERE d.tenant_id = t.tenant_id AND d.device = CAST($2 AS text) AND d.revision = t.revision AND (a.ordinal = 32 OR a.next_attempt > clock_timestamp()) AND a.ordinal = (SELECT max(b.ordinal) FROM mdm_apple.attempts AS b WHERE b.tenant_id = a.tenant_id AND b.trust = a.trust)))").bind(&tenant).bind(&device).fetch_one(&mut *c).await.map_err(storage)?;
            if existing {
                return Ok(true);
            }
            crate::agent_collection::due(source, c, &tenant, device).await
        })
    }
}
impl channels::AppleCollections for Store {
    fn prepare_native_collection<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: String,
        id: Uuid,
    ) -> channels::Pending<'a, Vec<rss_mdm_audit_integration::Fact>> {
        Box::pin(async move {
            crate::collection::prepare_native(c, &self.protection, &tenant, id).await
        })
    }

    fn pending_collections<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user_key: String,
        limit: usize,
    ) -> Pending<'a, Vec<channels::PendingCollection>> {
        Box::pin(async move {
            let mut result = Vec::new();
            let mut offset = 0i64;
            while result.len() < limit {
                let ids=sqlx::query_scalar::<_,Uuid>("SELECT collection FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND user_key = $4 AND collection IS NOT NULL AND state IN ('pending', 'sent', 'not_now') AND deadline > clock_timestamp() AND next_attempt <= clock_timestamp() GROUP BY collection ORDER BY min(next_attempt), collection LIMIT 64 OFFSET $3").bind(&tenant).bind(&device).bind(offset).bind(&user_key).fetch_all(&mut *c).await.map_err(storage)?;
                let mut pending = rss_mdm_inventory_service::collection::read::pending_apple_in(
                    c,
                    &tenant,
                    device.clone(),
                    &ids,
                )
                .await
                .map_err(Error::from)?;
                for id in &ids {
                    if pending.remove(id) {
                        result.push(channels::PendingCollection { id: *id });
                        if result.len() == limit {
                            break;
                        }
                    }
                }
                if ids.len() < 64 {
                    break;
                }
                offset += 64;
            }
            Ok(result)
        })
    }
}
impl channels::AppleResults for Store {
    fn evidence_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        requests: Vec<(Uuid, rss_mdm_apple_mdm::native::request::Request)>,
        native_values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, channels::AppleEvidence>> {
        Box::pin(async move {
            if requests.len() > 1000 {
                return Err(Error::Malformed);
            }
            let (declarations, other): (Vec<_>, Vec<_>) =
                requests.into_iter().partition(|(_, r)| {
                    matches!(
                        r,
                        rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                    )
                });
            let ids = declarations.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            let mut facts =
                crate::ddm::observations(c, &self.protection, &tenant, ids.clone(), native_values)
                    .await?;
            let mut result = ids
                .into_iter()
                .map(|id| {
                    (
                        id,
                        channels::AppleEvidence::Declarations(facts.remove(&id).map(Box::new)),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            result.extend(
                crate::evidence::observations_many(
                    c,
                    &self.protection,
                    &tenant,
                    other,
                    native_values,
                )
                .await?
                .into_iter()
                .map(|(id, rows)| (id, channels::AppleEvidence::Observations(rows))),
            );
            Ok(result)
        })
    }
    fn declaration_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,

        after: Option<Uuid>,
        limit: usize,
    ) -> Pending<'a, Vec<(Uuid, String)>> {
        Box::pin(async move {
            if !(1..=usize::from(rss_mdm_query::MAX_PAGE_LIMIT) + 1).contains(&limit) {
                return Err(Error::Malformed);
            }
            sqlx::query_as("SELECT operation, user_key FROM mdm_apple.declarations WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND (CAST($3 AS uuid) IS NULL OR operation > $3) ORDER BY operation LIMIT $4")
                .bind(tenant).bind(&device).bind(after).bind(limit as i64).fetch_all(c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))
        })
    }

    fn control_applicability<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        requests: &'a [channels::AppleControlCheck],
    ) -> Pending<'a, std::collections::BTreeMap<usize, Result<(), rss_mdm_apple_mdm::native::Error>>>
    {
        Box::pin(async move {
            crate::native::control_applicability(c, &self.protection, tenant, requests).await
        })
    }
    fn withdrawal_published<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            crate::ddm::withdrawal_published(c, &self.protection, &tenant, operation).await
        })
    }

    fn declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        native_values: bool,
    ) -> Pending<'a, Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>> {
        Box::pin(async move {
            crate::ddm::observation(c, &self.protection, &tenant, operation, native_values).await
        })
    }

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        request: rss_mdm_apple_mdm::native::request::Request,
        native_values: bool,
    ) -> Pending<'a, Vec<rss_mdm_apple_mdm::native::evidence::Observation>> {
        Box::pin(async move {
            crate::evidence::observations(
                c,
                &self.protection,
                &tenant,
                operation,
                &request,
                native_values,
            )
            .await
        })
    }
}
impl channels::Apple for super::Apple {
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        udid: &'a str,
        user_key: &'a str,
    ) -> Pending<'a, ()> {
        Box::pin(async move { current(c, p, udid, user_key).await })
    }
    fn command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch> {
        Box::pin(async move { send_command(c, self, p, command).await })
    }
    fn prerequisites<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch> {
        Box::pin(async move {
            if crate::native::context(c, &self.protection, p, command)
                .await?
                .is_some()
            {
                return Ok(AppleDispatch::Waiting);
            }
            crate::native::resolve(c, &self.protection, p, command).await
        })
    }
    fn trust<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, channels::Reply> {
        Box::pin(async move {
            let (bytes, facts) = crate::trust_installation::send(c, self, p, audit).await?;
            Ok(channels::Reply { bytes, facts })
        })
    }
    fn collection<'a>(
        &'a self,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user_key: &'a str,
    ) -> Pending<'a, channels::Reply> {
        Box::pin(async move {
            let (mut bytes, mut facts) = if user_key.is_empty() {
                crate::agent_collection::send(
                    source,
                    source.software_enabled(),
                    c,
                    &self.protection,
                    p,
                )
                .await?
            } else {
                (Vec::new(), Vec::new())
            };
            if bytes.is_empty() {
                let (native_bytes, native_facts) =
                    crate::collection::send(source, c, &self.protection, p, user_key).await?;
                bytes = native_bytes;
                facts.extend(native_facts);
            }
            Ok(channels::Reply { bytes, facts })
        })
    }
}
pub(crate) async fn current(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    udid: &str,
    user_key: &str,
) -> Result<(), Error> {
    crate::device::store::lock_channel(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &p.tenant().to_string(),
        p.device(),
        p.require_channel()?,
    )
    .await?;
    crate::device::store::revalidate_source(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        p,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?;
    let valid=sqlx::query_scalar::<_,bool>("SELECT TRUE FROM mdm_apple.devices AS d INNER JOIN mdm_apple.channels AS ch USING (tenant_id, device) WHERE d.tenant_id = CAST($1 AS uuid) AND d.device = CAST($2 AS text) AND d.state <> 'retired' AND d.udid = $3 AND ch.user_key = $4 AND ch.state = 'active' FOR UPDATE OF d, ch").bind(p.tenant().to_string()).bind(p.device()).bind(udid).bind(user_key).fetch_optional(c).await.map_err(db)?.unwrap_or(false);
    if !valid {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
async fn send_command(
    c: &mut PgConnection,
    apple: &super::Apple,
    p: &DevicePrincipal,
    command: &AppleCommand,
) -> Result<AppleDispatch, Error> {
    use rss_mdm_apple_mdm::native::{self, request::Request as A};
    let Some(context) = super::native::context(c, &apple.protection, p, command).await? else {
        if !command.target.user_key().is_empty() {
            crate::notify(c, "apple").await.map_err(db)?;
            return Ok(AppleDispatch::Waiting);
        }
        return super::native::resolve(c, &apple.protection, p, command).await;
    };
    let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state <> 'retired'").bind(p.tenant().to_string()).bind(p.device()).fetch_one(&mut *c).await.map_err(db)?;
    let rights = super::native::rights(rights);
    if command.input_version == "device-control-v1" {
        let A::Command { command } = &command.request else {
            return Err(Error::Malformed);
        };
        let action = match command.request_type.as_str() {
            "RestartDevice" => crate::protocol_types::ControlKind::Restart,
            "DeviceLock" => crate::protocol_types::ControlKind::Lock,
            "EraseDevice" => crate::protocol_types::ControlKind::Wipe,
            _ => return Err(Error::Malformed),
        };
        if let Err(error) = action.applicability(&context, command, &rights) {
            return Ok(AppleDispatch::Rejected(error));
        }
    }
    let target = native::Target {
        context: &context,
        access_rights: &rights,
    };
    let tenant = p.tenant().to_string();
    let rows=sqlx::query("SELECT id,phase,ordinal,state,request,next_attempt<=clock_timestamp() AS ready FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase IN('execute','observe') ORDER BY ordinal DESC,phase FOR UPDATE").bind(&tenant).bind(command.operation).fetch_all(&mut *c).await.map_err(db)?;
    let profile = matches!(
        command.request,
        A::InstallProfile { .. } | A::RemoveProfile { .. }
    );
    let software_query = match &command.request {
        A::Command { command } => {
            native::outcome::follow_up(command).map_err(|_| Error::Malformed)?
        }
        _ => None,
    };
    let executed = rows.iter().any(|r| {
        r.try_get::<String, _>("phase").ok().as_deref() == Some("execute")
            && (matches!(
                r.try_get::<String, _>("state").ok().as_deref(),
                Some("sent" | "acknowledged")
            ) || (profile && r.try_get::<String, _>("state").ok().as_deref() == Some("error")))
    });
    let declaration_guards = if matches!(command.request, A::Declarations { .. }) && executed {
        crate::ddm::profile_observation_guards(c, &apple.protection, p, command.target.user_key())
            .await?
    } else {
        Vec::new()
    };
    let ddm_observe = !declaration_guards.is_empty();
    let phase = if (profile || software_query.is_some() || ddm_observe) && executed {
        "observe"
    } else {
        "execute"
    };
    let id = Uuid::new_v4();
    let now = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let mut profile_objects = None;
    let compiled = if phase == "observe" {
        if let Some(query) = software_query {
            query.compile(&target)
        } else {
            native::Command::new(
                "ProfileList",
                crate::protocol::dictionary([("ManagedOnly", true.into())]),
                &target,
            )
        }
    } else {
        match &command.request {
            A::Command { command } => command.compile(&target),
            A::InstallProfile { profile } => {
                let profile = match profile.compile(&target) {
                    Ok(profile) => profile,
                    Err(error) => return Ok(AppleDispatch::Rejected(error)),
                };
                profile_objects = Some(profile.objects);
                let signed = apple.signer.sign(&profile.bytes, now)?;
                native::Command::new(
                    "InstallProfile",
                    wire::dictionary([("Payload", plist::Value::Data(signed))]),
                    &target,
                )
            }
            A::RemoveProfile { identifier, .. } => native::Command::new(
                "RemoveProfile",
                wire::dictionary([("Identifier", identifier.as_str().into())]),
                &target,
            ),
            A::Declarations { .. } => {
                let tokens = match crate::ddm::publish(c, apple, p, command, &context).await? {
                    Ok(value) => value,
                    Err(error) => return Ok(AppleDispatch::Rejected(error)),
                };
                native::Command::new(
                    "DeclarativeManagement",
                    wire::dictionary([(
                        "Data",
                        plist::Value::Data(
                            serde_json::to_vec(&tokens).map_err(|_| Error::Malformed)?,
                        ),
                    )]),
                    &target,
                )
            }
        }
    };
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => return Ok(AppleDispatch::Rejected(error)),
    };
    let mut ordinal = 0;
    if let Some(row) = rows
        .iter()
        .find(|r| r.try_get::<String, _>("phase").ok().as_deref() == Some(phase))
    {
        if !row.try_get::<bool, _>("ready").map_err(db)? {
            return Ok(AppleDispatch::Waiting);
        }
        let state: String = row.try_get("state").map_err(db)?;
        if matches!(state.as_str(), "pending" | "not_now") {
            // Explicit refusal permits only the same immutable native command.
            let id: Uuid = row.try_get("id").map_err(db)?;
            sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).execute(&mut *c).await.map_err(db)?;
            let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
            let plain = crate::protection::open(
                &apple.protection,
                &tenant,
                p.device(),
                id,
                crate::protection::Part::Request,
                &sealed,
            )?;
            return Ok(AppleDispatch::Ready(plain.expose().to_vec()));
        }
        // Unknown mutations are never reissued. Only an independent native read can advance.
        if (phase != "observe"
            && !matches!(&command.request, A::Command{command} if native::outcome::family(&command.request_type)==Ok(native::outcome::Family::Query)))
            || !matches!(state.as_str(), "sent" | "acknowledged" | "error")
        {
            return Ok(AppleDispatch::Waiting);
        }
        ordinal = row
            .try_get::<i32, _>("ordinal")
            .map_err(db)?
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        if ordinal > 32 {
            return Ok(AppleDispatch::Waiting);
        }
    }
    if phase == "execute"
        && profile
        && !crate::profiles::dispatch(
            c,
            &apple.protection,
            p,
            command.operation,
            profile_objects.as_deref(),
        )
        .await?
    {
        return Ok(AppleDispatch::Rejected(native::Error::Constraint));
    }
    let bytes = compiled.encode(id).map_err(|_| Error::Malformed)?;
    let sealed = crate::protection::seal(
        &apple.protection,
        &tenant,
        p.device(),
        id,
        crate::protection::Part::Request,
        &bytes,
    )?;
    sqlx::query("INSERT INTO mdm_apple.attempts (tenant_id, id, device, operation, phase, request, state, deadline, next_attempt, ordinal, context, user_key, declaration_guards) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, 'sent', to_timestamp($7), clock_timestamp() + CAST('30 seconds' AS interval), $8, $9, $10, $11)").bind(&tenant).bind(id).bind(p.device()).bind(command.operation).bind(phase).bind(sealed).bind(command.deadline as f64).bind(ordinal).bind(serde_json::to_value(&context).map_err(|_| Error::Malformed)?).bind(command.target.user_key()).bind(if phase == "observe" { declaration_guards } else { Vec::new() }).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    Ok(AppleDispatch::Ready(bytes))
}

fn storage(e: sqlx::Error) -> Error {
    db(e)
}

impl rss_mdm_recovery_credentials::cleanup::ChannelCopies for Store {
    fn purge_in<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        operation: Uuid,
        command: &'a rss_device_command::Command,
    ) -> rss_mdm_recovery_credentials::cleanup::Pending<
        'a,
        rss_mdm_recovery_credentials::cleanup::CopyState,
    > {
        Box::pin(async move {
            crate::recovery_credentials::purge_inputs(
                c,
                &self.protection,
                tenant,
                operation,
                command,
            )
            .await
            .map_err(|_| rss_mdm_recovery_credentials::Error::Storage)
        })
    }
}

impl Store {
    /// Operations with durable execute delivery evidence; a terminal timeout is not a stop acknowledgement.
    pub async fn sent_on(
        &self,
        c: &mut PgConnection,
        tenant: rss_request_context::TenantId,
        ids: Vec<Uuid>,
    ) -> std::result::Result<std::collections::BTreeSet<Uuid>, Error> {
        if ids.len() > 1000 {
            return Err(Error::Malformed);
        }
        let ids:Vec<Uuid>=sqlx::query_scalar("SELECT DISTINCT operation FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=ANY($2) AND phase='execute' AND state<>'pending'").bind(tenant.to_string()).bind(ids).fetch_all(c).await.map_err(storage)?;
        Ok(ids.into_iter().collect())
    }
}
