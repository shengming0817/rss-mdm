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
pub(super) enum Delivery {
    Queued,
    Claimed { attempt: Uuid, lease_until: i64 },
    Received { attempt: Uuid, lease_until: i64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Execution {
    NotStarted,
    Running,
    Succeeded,
    Failed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Cancellation {
    None,
    Requested,
    Confirmed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RunState {
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
            || !matches!(self.execution, Execution::Running | Execution::Unknown)
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
mod tests {
    use super::*;
    #[test]
    fn expired_delivery_can_retry_but_unknown_side_effect_cannot() {
        let mut run = RunState::new(300, 0).unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        run.claim(first, 0).unwrap();
        assert!(run.start(first, 1).is_err());
        assert!(run.claim(second, 59).is_err());
        run.claim(second, 60).unwrap();
        assert!(run.received(first, 61).is_err());
        run.received(second, 61).unwrap();
        run.start(second, 62).unwrap();
        run.expire(122, 60);
        assert_eq!(run.execution, Execution::Unknown);
        assert!(run.claim(Uuid::new_v4(), 123).is_err());
        run.result(second, true).unwrap();
        assert_eq!(run.execution, Execution::Succeeded);
    }
    #[test]
    fn late_or_cancelled_evidence_cannot_become_trusted_facts() {
        let mut run = RunState::new(100, 0).unwrap();
        let attempt = Uuid::new_v4();
        run.claim(attempt, 0).unwrap();
        run.received(attempt, 1).unwrap();
        run.start(attempt, 2).unwrap();
        assert!(run.trusts_result(61, 60));
        assert!(!run.trusts_result(62, 60));
        assert!(!run.trusts_result(100, 3600));
        run.cancel();
        assert!(!run.trusts_result(3, 60));
        run.cancelled(attempt).unwrap();
        assert!(!run.trusts_result(4, 60));
        run.result(attempt, true).unwrap();
        assert_eq!(run.execution, Execution::Succeeded);
        assert!(!run.trusts_result(5, 60));
    }
    #[test]
    fn cancellation_is_separate_from_effect_and_late_execution_evidence() {
        let mut run = RunState::new(300, 0).unwrap();
        let attempt = Uuid::new_v4();
        run.claim(attempt, 0).unwrap();
        run.received(attempt, 1).unwrap();
        run.start(attempt, 2).unwrap();
        run.cancel();
        run.cancelled(attempt).unwrap();
        assert_eq!(run.execution, Execution::Unknown);
        assert_eq!(run.cancellation, Cancellation::Confirmed);
        assert!(run.start(attempt, 3).is_err());
        run.result(attempt, false).unwrap();
        assert_eq!(run.execution, Execution::Failed);
        assert_eq!(run.cancellation, Cancellation::Confirmed);
    }
}
