//! Recovery creates a new bounded attempt; it never replays an unknown native write.
use super::Package;
use crate::{Error, assets::channel::Current, database::db};
use sqlx::PgConnection;
use uuid::Uuid;

const HEALTH_GRACE_SECONDS: i64 = 300;
const RETRY_PROBE_GRACE_SECONDS: i64 = 60;
const MAX_ATTEMPTS_WITHOUT_CONTACT: i64 = 3;

pub(crate) struct Contact {
    pub active: i64,
    bindings: i64,
    pub last: Option<i64>,
}

pub(crate) async fn contact_on(
    c: &mut PgConnection,
    tenant: &str,
    registration: Uuid,
    generation: i64,
) -> Result<Contact, Error> {
    let (active, bindings, last) = sqlx::query_as::<_, (i64, i64, Option<i64>)>(
        "SELECT count(*) FILTER(WHERE r.state='active'),count(*),floor(extract(epoch FROM max(coalesce(r.last_communication_received_at,r.first_authenticated_at,g.created_at))))::bigint FROM mdm_access.agent_grants g JOIN mdm_access.registrations r ON(r.tenant_id,r.agent_grant_id)=(g.tenant_id,g.id) WHERE g.tenant_id=$1::uuid AND g.source='native' AND g.native_authority->>'registration'=$2 AND g.native_authority->>'generation'=$3 AND r.channel='agent' AND r.purpose='primary'",
    )
    .bind(tenant).bind(registration.to_string()).bind(generation.to_string())
    .fetch_one(c).await.map_err(db)?;
    Ok(Contact {
        active,
        bindings,
        last,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Signal {
    Absent,
    Unresponsive,
    Healthy,
    Unknown,
}

pub(crate) fn signal(fact: &Current, package: &Package, contact: &Contact, now: i64) -> Signal {
    if contact.active > 1 || contact.last.is_some_and(|at| at > now) {
        return Signal::Unknown;
    }
    if fact.state == "absent" {
        return Signal::Absent;
    }
    let Some(evidence) = &fact.evidence else {
        return Signal::Unknown;
    };
    let version = match &package.identity {
        super::Identity::WindowsMsix { identity, .. } => identity
            .version
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("."),
        _ => package.version.clone(),
    };
    // Native bundle presence remains unverified. It only selects repair of an
    // installation already bound to this exact MDM registration, never a new identity.
    if contact.bindings == 0
        || evidence.identity != package.detection_identity()
        || evidence.version.as_deref() != Some(version.as_str())
    {
        return Signal::Unknown;
    }
    if contact.active == 1
        && contact
            .last
            .is_some_and(|at| at > now.saturating_sub(HEALTH_GRACE_SECONDS))
    {
        Signal::Healthy
    } else {
        Signal::Unresponsive
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    Ready,
    Pending(Uuid),
    ObservationPending,
    Exhausted,
}

pub(crate) async fn gate_on(
    c: &mut PgConnection,
    tenant: &str,
    target: (Uuid, i64, Uuid),
    snapshot: Uuid,
    last_contact: Option<i64>,
    now: i64,
) -> Result<Gate, Error> {
    let (registration, generation, version) = target;
    // A probe begun before an old attempt ended cannot establish recovery readiness.
    let started: i64 = sqlx::query_scalar("SELECT started_at FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND registration=$3 AND sealed_at IS NOT NULL")
        .bind(tenant).bind(snapshot).bind(registration).fetch_one(&mut *c).await.map_err(db)?;
    let (pending, deadline, attempts, cleanup) = sqlx::query_as::<_, (Option<Uuid>, Option<i64>, i64, bool)>(
        "SELECT (array_agg(o.id ORDER BY d.queued_at DESC,o.id DESC) FILTER(WHERE d.terminal_at IS NULL AND d.deadline>$6::bigint*1000000))[1],max(d.deadline/1000000),count(*) FILTER(WHERE o.policy_version=$4 AND d.queued_at>greatest($5::bigint,coalesce((SELECT max(t.created_at) FROM mdm_policy.triggers t WHERE t.tenant_id=o.tenant_id AND t.version=$4 AND t.deadline>$6::bigint),0))*1000000),coalesce(bool_or(EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps b WHERE (b.tenant_id,b.installation)=(o.tenant_id,o.id) AND b.active AND NOT b.cleanup_complete)),false) FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.authority->>'kind'='agent_install' AND o.authority->>'stage'='install'",
    ).bind(tenant).bind(registration).bind(generation).bind(version)
        .bind(last_contact.unwrap_or(0)).bind(now).fetch_one(c).await.map_err(db)?;
    Ok(decide(pending, deadline, attempts, cleanup, started))
}

fn decide(
    pending: Option<Uuid>,
    deadline: Option<i64>,
    attempts: i64,
    cleanup: bool,
    started: i64,
) -> Gate {
    if let Some(id) = pending {
        return Gate::Pending(id);
    }
    if cleanup || deadline.is_some_and(|at| started <= at.saturating_add(RETRY_PROBE_GRACE_SECONDS))
    {
        return Gate::ObservationPending;
    }
    if attempts >= MAX_ATTEMPTS_WITHOUT_CONTACT {
        Gate::Exhausted
    } else {
        Gate::Ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_presence_repairs_only_a_bound_unresponsive_agent_and_keeps_unknown_facts() {
        let package = Package {
            release: rss_mdm_agent_wire::enroll::configuration::Installation {
                release_id: Uuid::new_v4(),
            },
            identity: super::super::Identity::Macos {
                receipt: "com.rss.agent".into(),
                bundle: "com.rss.agent".into(),
                team: String::new(),
            },
            target: rss_mdm_policy::SoftwareTarget::new(
                rss_mdm_policy::Platform::Macos,
                rss_mdm_policy::Architecture::Aarch64,
            ),
            version: "1.2.3".into(),
            artifact: rss_mdm_resource::SoftwareArtifact {
                reference: "package".into(),
                origin: None,
                length: 1,
                sha256: [1; 32],
            },
            source: rss_mdm_resource::SoftwareSource {
                id: "source".into(),
                revision: "1".into(),
                sha256: [1; 32],
            },
        };
        let mut fact = Current {
            state: "unknown".into(),
            snapshot: Uuid::new_v4(),
            received_at: 1000,
            evidence: Some(crate::collection::channel::AgentEvidence {
                catalog_digest: [1; 32],
                provisioned: false,
                checked_identities: vec!["com.rss.agent".into()],
                identity: "com.rss.agent".into(),
                publisher: None,
                version: Some("1.2.3".into()),
                architecture: Some("aarch64".into()),
            }),
        };
        let mut contact = Contact {
            active: 1,
            bindings: 1,
            last: Some(700),
        };
        assert_eq!(
            signal(&fact, &package, &contact, 1000),
            Signal::Unresponsive
        );
        contact.last = Some(701);
        assert_eq!(signal(&fact, &package, &contact, 1000), Signal::Healthy);
        contact.bindings = 0;
        assert_eq!(signal(&fact, &package, &contact, 1000), Signal::Unknown);
        contact.bindings = 1;
        contact.last = Some(700);
        fact.evidence.as_mut().unwrap().version = Some("other".into());
        assert_eq!(signal(&fact, &package, &contact, 1000), Signal::Unknown);
        assert_eq!(fact.state, "unknown");
    }
    #[test]
    fn recovery_requires_a_new_probe_after_expiry_and_cleanup_with_a_bounded_budget() {
        let id = Uuid::new_v4();
        assert_eq!(
            decide(Some(id), Some(100), 1, false, 500),
            Gate::Pending(id)
        );
        assert_eq!(
            decide(None, Some(100), 1, false, 160),
            Gate::ObservationPending
        );
        assert_eq!(
            decide(None, Some(100), 1, true, 500),
            Gate::ObservationPending
        );
        assert_eq!(decide(None, Some(100), 1, false, 161), Gate::Ready);
        assert_eq!(decide(None, Some(100), 3, false, 500), Gate::Exhausted);
        assert_eq!(decide(None, None, 0, false, 0), Gate::Ready);
    }
}
