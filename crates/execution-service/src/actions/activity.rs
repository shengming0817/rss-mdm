//! Snapshot stage facts at the producer, never reconstruct them from a later Run.
use super::{
    state::{Cancellation, Delivery, Execution},
    storage::Run,
};
use rss_mdm_audit_integration::activity::*;

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
        ActivityOrigin::Human
    } else {
        ActivityOrigin::Policy
    };
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
                rss_mdm_agent_wire::runtime::SelfServiceCaller::Human => ActivityOrigin::Human,
                rss_mdm_agent_wire::runtime::SelfServiceCaller::Ai => ActivityOrigin::Ai,
            };
        }
    }
    fact.delivery = Some(match run.state.delivery {
        Delivery::Queued => ActivityDelivery::Queued,
        Delivery::Claimed { .. } => ActivityDelivery::Offered,
        Delivery::Received { .. } => ActivityDelivery::Received,
    });
    fact.execution = Some(match run.state.execution {
        Execution::NotStarted => ActivityExecution::NotStarted,
        Execution::Running => ActivityExecution::Running,
        Execution::Succeeded => ActivityExecution::Succeeded,
        Execution::Failed => ActivityExecution::Failed,
        Execution::WaitingReboot => ActivityExecution::WaitingReboot,
        Execution::Unknown => ActivityExecution::Unknown,
    });
    if run.state.cancellation == Cancellation::Confirmed {
        fact.decision = Some(ActivityDecision::Cancelled);
    } else if run.state.cancellation == Cancellation::Requested {
        fact.decision = Some(ActivityDecision::CancellationRequested);
    }
    fact.effect = match run
        .result
        .as_ref()
        .and_then(|v| v.get("effect"))
        .and_then(|v| v.as_str())
    {
        Some("verified") => Some(ActivityEffect::Verified),
        Some("failed") => Some(ActivityEffect::Failed),
        Some("unknown") => Some(ActivityEffect::Unknown),
        Some("waiting_reboot") => Some(ActivityEffect::WaitingReboot),
        _ => None,
    };
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
