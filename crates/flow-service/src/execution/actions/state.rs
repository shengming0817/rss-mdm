use crate::Error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Delivery {
    Queued,
    Claimed { attempt: Uuid, lease_until: i64 },
    Received { attempt: Uuid, lease_until: i64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Execution {
    NotStarted,
    Running,
    Succeeded,
    Failed,
    WaitingReboot,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cancellation {
    None,
    Requested,
    Confirmed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunState {
    pub delivery: Delivery,
    pub execution: Execution,
    pub cancellation: Cancellation,
    pub deadline: i64,
    pub started_at: Option<i64>,
}
impl RunState {
    pub fn new(deadline: i64, now: i64) -> Result<Self, Error> {
        if deadline <= now || now < 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            delivery: Delivery::Queued,
            execution: Execution::NotStarted,
            cancellation: Cancellation::None,
            deadline,
            started_at: None,
        })
    }
    pub fn claim(&mut self, attempt: Uuid, now: i64) -> Result<(), Error> {
        if attempt.is_nil()
            || now < 0
            || now >= self.deadline
            || self.execution != Execution::NotStarted
            || self.cancellation != Cancellation::None
        {
            return Err(Error::Conflict);
        }
        match self.delivery {
            Delivery::Queued => (),
            Delivery::Claimed {
                attempt: old,
                lease_until,
            }
            | Delivery::Received {
                attempt: old,
                lease_until,
            } => {
                if old == attempt && now < lease_until {
                    return Ok(());
                }
                if now < lease_until || old == attempt {
                    return Err(Error::Conflict);
                }
            }
        }
        self.delivery = Delivery::Claimed {
            attempt,
            lease_until: now
                .checked_add(60)
                .ok_or(Error::Malformed)?
                .min(self.deadline),
        };
        Ok(())
    }
    pub fn received(&mut self, attempt: Uuid, now: i64) -> Result<(), Error> {
        let lease_until = self.live_attempt(attempt, now)?;
        self.delivery = Delivery::Received {
            attempt,
            lease_until,
        };
        Ok(())
    }
    pub fn start(&mut self, attempt: Uuid, now: i64) -> Result<(), Error> {
        if self.execution == Execution::Running
            && self.attempt() == Some(attempt)
            && now < self.deadline
            && self.cancellation == Cancellation::None
        {
            return Ok(());
        }
        self.live_attempt(attempt, now)?;
        if !matches!(self.delivery, Delivery::Received { .. })
            || self.execution != Execution::NotStarted
        {
            return Err(Error::Conflict);
        }
        self.execution = Execution::Running;
        self.started_at = Some(now);
        Ok(())
    }
    pub fn trusts_result(&self, now: i64, timeout: u32) -> bool {
        self.execution == Execution::Running
            && self.cancellation == Cancellation::None
            && now < self.deadline
            && self
                .started_at
                .is_some_and(|start| now >= start && now - start < i64::from(timeout))
    }
    pub fn result(&mut self, attempt: Uuid, success: bool) -> Result<(), Error> {
        // Late evidence from the same attempt can resolve Unknown, but cannot authorize rerun.
        if self.attempt() != Some(attempt)
            || !matches!(
                self.execution,
                Execution::Running | Execution::Unknown | Execution::WaitingReboot
            )
        {
            return Err(Error::Conflict);
        }
        self.execution = if success {
            Execution::Succeeded
        } else {
            Execution::Failed
        };
        Ok(())
    }
    /// Preserve an uncertain software effect and block blind re-execution.
    pub fn uncertain_result(&mut self, attempt: Uuid) -> Result<(), Error> {
        if self.attempt() != Some(attempt)
            || !matches!(
                self.execution,
                Execution::Running | Execution::Unknown | Execution::WaitingReboot
            )
        {
            return Err(Error::Conflict);
        }
        self.execution = Execution::Unknown;
        Ok(())
    }
    pub fn waiting_reboot(&mut self, attempt: Uuid) -> Result<(), Error> {
        if self.attempt() != Some(attempt)
            || !matches!(
                self.execution,
                Execution::Running | Execution::Unknown | Execution::WaitingReboot
            )
        {
            return Err(Error::Conflict);
        }
        self.execution = Execution::WaitingReboot;
        Ok(())
    }
    pub fn cancel(&mut self) {
        self.cancellation = if self.execution == Execution::NotStarted {
            Cancellation::Confirmed
        } else {
            Cancellation::Requested
        };
    }
    pub fn cancelled(&mut self, attempt: Uuid) -> Result<(), Error> {
        if self.attempt() == Some(attempt) && self.cancellation == Cancellation::Confirmed {
            return Ok(());
        }
        if self.attempt() != Some(attempt) || self.cancellation != Cancellation::Requested {
            return Err(Error::Conflict);
        }
        self.cancellation = Cancellation::Confirmed;
        // A killed process can already have made changes. Do not manufacture success or rollback.
        if self.execution == Execution::Running {
            self.execution = Execution::Unknown;
        }
        Ok(())
    }
    pub fn expire(&mut self, now: i64, timeout: u32) {
        if self.execution == Execution::Running
            && (now >= self.deadline
                || self
                    .started_at
                    .is_some_and(|start| now.saturating_sub(start) >= i64::from(timeout)))
        {
            self.execution = Execution::Unknown;
        }
        if now >= self.deadline && self.execution == Execution::NotStarted {
            self.cancellation = Cancellation::Confirmed;
        }
    }
    pub fn attempt(&self) -> Option<Uuid> {
        match self.delivery {
            Delivery::Queued => None,
            Delivery::Claimed { attempt, .. } | Delivery::Received { attempt, .. } => Some(attempt),
        }
    }
    pub fn awaits_user(&self, now: i64) -> bool {
        self.execution == Execution::NotStarted
            && self.cancellation == Cancellation::None
            && matches!(self.delivery,Delivery::Claimed {lease_until,..}|Delivery::Received {lease_until,..} if now<lease_until)
    }
    fn live_attempt(&self, attempt: Uuid, now: i64) -> Result<i64, Error> {
        match self.delivery {
            Delivery::Claimed {
                attempt: old,
                lease_until,
            }
            | Delivery::Received {
                attempt: old,
                lease_until,
            } if old == attempt
                && now >= 0
                && now < lease_until
                && now < self.deadline
                && self.cancellation == Cancellation::None =>
            {
                Ok(lease_until)
            }
            _ => Err(Error::Conflict),
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/execution/actions/state_unit.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/execution/actions/state_schedule_unit.rs"]
mod schedule_tests;
