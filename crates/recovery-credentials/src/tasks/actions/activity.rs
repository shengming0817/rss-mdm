//! Snapshot stage facts at the producer, never reconstruct them from a later Run.
use super::storage::Run;
use rss_mdm_audit_integration::activity::*;
use rss_mdm_task_state::{Cancellation, Delivery, Execution};

pub(crate) fn run(run: &Run, phase: ActivityPhase) -> Activity {
    let mut fact = Activity::new(ActivityKind::Execution, phase);
    fact.target = Some(ActivityTarget {
        device: run.target.device.clone(),
        registration: run.target.registration,
        generation: run.target.generation,
    });
    fact.links.task = Some(run.id);
    fact.links.version = Some(run.policy_version);
    fact.links.attempt = run.state.attempt();
    fact.origin = run.origin;

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
