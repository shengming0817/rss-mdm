//! Snapshot stage facts at the producer, never reconstruct them from a later Run.
use super::{
    state::{Cancellation, Delivery, Execution},
    storage::Run,
};
use rss_mdm_audit_integration::activity::{Activity, ActivityKind, ActivityPhase, ActivityTarget};

pub(crate) fn run(run: &Run, phase: ActivityPhase) -> Activity {
    let mut fact = Activity::new(ActivityKind::Execution, phase);
    fact.target = Some(ActivityTarget {
        device: run.target.device.clone(),
        registration: run.target.registration,
        generation: run.target.generation,
    });
    fact.links.task = Some(run.id);
    fact.links.version = Some(run.source.columns().1);
    fact.links.attempt = run.state.attempt();
    fact.origin = if run.invocation.is_some() {
        "human"
    } else {
        "policy"
    }
    .into();
    if let Some(invocation) = &run.invocation {
        fact.user = invocation.activity_user.clone();
        if let rss_mdm_agent_wire::runtime::TaskAuthorization::SelfService {
            request_id,
            policy_id,
            source,
            ..
        } = &invocation.authorization
        {
            fact.links.request = Some(*request_id);
            fact.links.policy = Some(*policy_id);
            fact.origin = match source {
                rss_mdm_agent_wire::runtime::SelfServiceCaller::Human => "human",
                rss_mdm_agent_wire::runtime::SelfServiceCaller::Ai => "ai",
            }
            .into();
        }
    }
    fact.delivery = Some(
        match run.state.delivery {
            Delivery::Queued => "queued",
            Delivery::Claimed { .. } => "offered",
            Delivery::Received { .. } => "received",
        }
        .into(),
    );
    fact.execution = Some(
        match run.state.execution {
            Execution::NotStarted => "not_started",
            Execution::Running => "running",
            Execution::Succeeded => "succeeded",
            Execution::Failed => "failed",
            Execution::WaitingReboot => "waiting_reboot",
            Execution::Unknown => "unknown",
        }
        .into(),
    );
    if run.state.cancellation == Cancellation::Confirmed {
        fact.decision = Some("cancelled".into());
    } else if run.state.cancellation == Cancellation::Requested {
        fact.decision = Some("cancellation_requested".into());
    }
    fact.effect = run
        .result
        .as_ref()
        .and_then(|v| v.get("effect"))
        .and_then(|v| v.as_str())
        .filter(|v| matches!(*v, "verified" | "failed" | "unknown" | "waiting_reboot"))
        .map(str::to_owned);
    fact
}

pub(crate) fn phase(event: &rss_mdm_agent_wire::runtime::TaskEvent) -> ActivityPhase {
    use rss_mdm_agent_wire::runtime::TaskEvent as E;
    match event {
        E::Received => ActivityPhase::Received,
        E::Start => ActivityPhase::Started,
        E::Cancelled => ActivityPhase::Cancelled,
        E::OutputChunk(_) | E::CredentialEscrow(_) | E::DeviceAccessPrepared(_) => {
            ActivityPhase::Reporting
        }
        E::Result(_)
        | E::ChunkedResult(_)
        | E::CollectionResult(_)
        | E::ChunkedCollectionResult { .. }
        | E::SoftwareResult(_)
        | E::CredentialResult(_)
        | E::DeviceAccessResult(_)
        | E::UnmanageResult { .. }
        | E::EnrollmentResult { .. } => ActivityPhase::Result,
    }
}

pub(crate) fn step_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
