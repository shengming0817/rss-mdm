//! Product schedule decisions over an injected wall clock, without I/O or a cron engine.
//! ref: jiff 4100a7c71125b9523029566d1d18f8b227ecd18c crates/jiff/src/tz/ambiguous.rs
use crate::Error;
use jiff::{
    Timestamp, ToSpan,
    civil::Date,
    tz::{AmbiguousOffset, TimeZone},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
/// A closed event or calendar trigger evaluated against an explicit clock.
pub enum Trigger {
    /// Only an explicit rerun trigger can admit this Policy.
    Manual,
    /// A single Unix-second occurrence.
    Once {
        /// Unix seconds of the occurrence.
        at: i64,
    },
    /// Fixed elapsed-second spacing from an anchor.
    Interval {
        /// Unix-second interval origin.
        anchor: i64,
        /// Interval length, from one minute through one year.
        seconds: u32,
    },
    /// One IANA-local weekday/time; gap skipped and fold resolved earlier.
    Weekly {
        /// IANA timezone name, or UTC.
        zone: String,
        /// ISO weekday, Monday 1 through Sunday 7.
        weekday: u8,
        /// Minute of the local day, from 0 through 1439.
        minute: u16,
    },
    /// An occurrence bound to a registration identity.
    Registration,
    /// Authenticated Agent check-in, with a minimum interval.
    CheckIn {
        /// Minimum elapsed seconds between admitted check-ins.
        minimum_seconds: u32,
    },
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
/// How to handle a due occurrence missed while the device was offline.
pub enum Misfire {
    /// Reject occurrences later than the explicit tolerance.
    Skip {
        /// Explicit tolerance beyond the computed available time.
        max_lateness_seconds: u32,
    },
    #[default]
    /// Admit only the most recent occurrence after an offline gap.
    CoalesceOne,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// An IANA-local window; an overnight window belongs to its start day.
pub struct Window {
    /// IANA timezone name, or UTC.
    pub zone: String,
    /// ISO weekdays on which windows start.
    pub weekdays: BTreeSet<u8>,
    /// Start minute of the local day.
    pub start_minute: u16,
    /// End minute; less than the start denotes the following day.
    pub end_minute: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Optional-ended calendar conditions, with no durable scheduler state.
pub struct Schedule {
    /// Event or calendar trigger.
    pub trigger: Trigger,
    #[serde(default)]
    /// Late-arrival behavior.
    pub misfire: Misfire,
    /// Earliest allowed Unix second.
    pub not_before: i64,
    /// Exclusive end, or no end for a persistent Policy.
    pub until: Option<i64>,
    /// Deterministic maximum jitter, bounded to one hour.
    pub jitter_seconds: u32,
    /// Optional allowed local-time window.
    pub window: Option<Window>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One stable trigger coordinate and its delivery/start window.
pub struct Occurrence {
    // Base time is the immutable deduplication coordinate, never the delayed window time.
    /// Immutable deduplication time, before jitter or window delay.
    pub coordinate: i64,
    /// Earliest Unix second at which the occurrence can be offered.
    pub available_at: i64,
    // A configured window is also an execution admission boundary.
    /// Exclusive start-permit boundary when a window is present.
    pub window_end: Option<i64>,
}
fn zone(name: &str) -> Result<TimeZone, Error> {
    if name != "UTC" && (!name.contains('/') || name.len() > 128) {
        return Err(Error::Malformed);
    }
    TimeZone::get(name).map_err(|_| Error::Malformed)
}
fn local(zone: &TimeZone, date: Date, minute: u16) -> Result<Option<i64>, Error> {
    let civil = if minute == 1440 {
        date.checked_add(1.days())
            .map_err(|_| Error::Malformed)?
            .at(0, 0, 0, 0)
    } else {
        date.at((minute / 60) as i8, (minute % 60) as i8, 0, 0)
    };
    let ambiguous = zone.to_ambiguous_timestamp(civil);
    if matches!(ambiguous.offset(), AmbiguousOffset::Gap { .. }) {
        return Ok(None);
    }
    Ok(Some(
        ambiguous
            .earlier()
            .map_err(|_| Error::Malformed)?
            .as_second(),
    ))
}
impl Schedule {
    /// Return the configured end, using the largest integer for an unbounded Policy.
    pub fn ends_at(&self) -> i64 {
        self.until.unwrap_or(i64::MAX)
    }
    /// Whether the explicit late-arrival rule rejects this available time.
    pub fn missed(&self, available_at: i64, now: i64) -> bool {
        match self.misfire {
            Misfire::Skip {
                max_lateness_seconds,
            } => now.saturating_sub(available_at) > i64::from(max_lateness_seconds),
            Misfire::CoalesceOne => false,
        }
    }
    /// Check timezone identifiers, trigger bounds and window geometry.
    pub fn validate(&self) -> Result<(), Error> {
        if self.not_before < 0 || self.ends_at() <= self.not_before || self.jitter_seconds > 3600 {
            return Err(Error::Malformed);
        }
        Timestamp::from_second(self.not_before).map_err(|_| Error::Malformed)?;
        if let Some(until) = self.until {
            Timestamp::from_second(until).map_err(|_| Error::Malformed)?;
        }
        match &self.trigger {
            Trigger::Once { at } if *at < self.not_before || *at >= self.ends_at() => {
                return Err(Error::Malformed);
            }
            Trigger::Interval { anchor, seconds } => {
                if *anchor < 0 || !(60..=31_536_000).contains(seconds) {
                    return Err(Error::Malformed);
                }
                let seconds = i64::from(*seconds);
                let first = if *anchor >= self.not_before {
                    *anchor
                } else {
                    let distance = self
                        .not_before
                        .checked_sub(*anchor)
                        .ok_or(Error::Malformed)?;
                    let intervals =
                        distance.checked_add(seconds - 1).ok_or(Error::Malformed)? / seconds;
                    anchor
                        .checked_add(intervals.checked_mul(seconds).ok_or(Error::Malformed)?)
                        .ok_or(Error::Malformed)?
                };
                if first >= self.ends_at() {
                    return Err(Error::Malformed);
                }
            }
            Trigger::Weekly {
                zone: name,
                weekday,
                minute,
            } => {
                zone(name)?;
                if !(1..=7).contains(weekday) || *minute >= 1440 {
                    return Err(Error::Malformed);
                }
            }
            Trigger::CheckIn { minimum_seconds }
                if !(60..=31_536_000).contains(minimum_seconds) =>
            {
                return Err(Error::Malformed);
            }
            _ => (),
        }
        if let Some(window) = &self.window {
            zone(&window.zone)?;
            if window.weekdays.is_empty()
                || window.weekdays.iter().any(|d| !(1..=7).contains(d))
                || window.start_minute == window.end_minute
                || window.start_minute >= 1440
                || window.end_minute > 1440
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    /// Return at most the latest occurrence since the durable scan cursor.
    /// Caller advances that cursor atomically with occurrence insertion, even for skipped work.
    pub fn due(&self, after: i64, now: i64, identity: &[u8]) -> Result<Option<Occurrence>, Error> {
        self.validate()?;
        if now < self.not_before || now >= self.ends_at() || now <= after {
            return Ok(None);
        }
        let base = match &self.trigger {
            Trigger::Once { at } => Some(*at),
            Trigger::Interval { anchor, seconds } if now >= *anchor => {
                Some(anchor + (now - anchor) / i64::from(*seconds) * i64::from(*seconds))
            }
            Trigger::Weekly {
                zone: name,
                weekday,
                minute,
            } => {
                let tz = zone(name)?;
                let mut date = tz
                    .to_datetime(Timestamp::from_second(now).map_err(|_| Error::Malformed)?)
                    .date();
                let mut found = None;
                for _ in 0..15 {
                    if date.weekday().to_monday_one_offset() == *weekday as i8
                        && let Some(at) = local(&tz, date, *minute)?
                        && at <= now
                    {
                        found = Some(at);
                        break;
                    }
                    date = date.checked_sub(1.days()).map_err(|_| Error::Malformed)?;
                }
                found
            }
            _ => None,
        };
        let Some(base) = base.filter(|at| *at > after && *at >= self.not_before && *at <= now)
        else {
            return Ok(None);
        };
        let Some(occurrence) = self.occurrence(base, identity)? else {
            return Ok(None);
        };
        if self.missed(occurrence.available_at, now) {
            return Ok(None);
        }
        Ok(Some(occurrence))
    }
    /// Event triggers reuse this exact deterministic jitter and window calculation.
    pub fn occurrence(
        &self,
        coordinate: i64,
        identity: &[u8],
    ) -> Result<Option<Occurrence>, Error> {
        self.validate()?;
        if coordinate < self.not_before || coordinate >= self.ends_at() {
            return Ok(None);
        }
        let mut hash = Sha256::new();
        hash.update(identity);
        hash.update(coordinate.to_be_bytes());
        let bytes: [u8; 32] = hash.finalize().into();
        let jitter = u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes"))
            % (u64::from(self.jitter_seconds) + 1);
        let earliest = coordinate
            .checked_add(jitter as i64)
            .ok_or(Error::Malformed)?;
        let available = if let Some(window) = &self.window {
            window.next(earliest)?
        } else {
            Some((earliest, None))
        };
        Ok(available
            .filter(|(at, _)| *at < self.ends_at())
            .map(|(available_at, window_end)| Occurrence {
                coordinate,
                available_at,
                window_end,
            }))
    }
}
impl Window {
    fn next(&self, at: i64) -> Result<Option<(i64, Option<i64>)>, Error> {
        let tz = zone(&self.zone)?;
        let mut date = tz
            .to_datetime(Timestamp::from_second(at).map_err(|_| Error::Malformed)?)
            .date()
            .checked_sub(1.days())
            .map_err(|_| Error::Malformed)?;
        for _ in 0..16 {
            if self
                .weekdays
                .contains(&(date.weekday().to_monday_one_offset() as u8))
                && let (Some(start), Some(end)) = (
                    local(&tz, date, self.start_minute)?,
                    local(
                        &tz,
                        if self.end_minute < self.start_minute {
                            date.checked_add(1.days()).map_err(|_| Error::Malformed)?
                        } else {
                            date
                        },
                        self.end_minute,
                    )?,
                )
                && at < end
                && start < end
            {
                return Ok(Some((at.max(start), Some(end))));
            }
            date = date.checked_add(1.days()).map_err(|_| Error::Malformed)?;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ts(s: &str) -> i64 {
        s.parse::<Timestamp>().unwrap().as_second()
    }
    fn schedule() -> Schedule {
        Schedule {
            trigger: Trigger::Weekly {
                zone: "America/New_York".into(),
                weekday: 7,
                minute: 150,
            },
            misfire: Misfire::CoalesceOne,
            not_before: ts("2026-01-01T00:00:00Z"),
            until: Some(ts("2027-01-01T00:00:00Z")),
            jitter_seconds: 0,
            window: None,
        }
    }
    #[test]
    fn perpetual_policy_has_no_end_but_occurrences_keep_window_boundaries() {
        let mut value = serde_json::to_value(schedule()).unwrap();
        value.as_object_mut().unwrap().remove("until");
        let s: Schedule = serde_json::from_value(value).unwrap();
        assert!(s.validate().is_ok());
        assert!(
            s.due(
                ts("2030-01-01T00:00:00Z"),
                ts("2030-01-08T00:00:00Z"),
                b"device"
            )
            .unwrap()
            .is_some()
        );
    }
    #[test]
    fn overnight_window_uses_the_start_day_even_after_midnight() {
        let mut s = schedule();
        s.window = Some(Window {
            zone: "UTC".into(),
            weekdays: BTreeSet::from([1]),
            start_minute: 22 * 60,
            end_minute: 2 * 60,
        });
        assert!(s.validate().is_ok());
        let at = ts("2026-09-22T01:00:00Z");
        let o = s.occurrence(at, b"device").unwrap().unwrap();
        assert_eq!(o.available_at, at);
        assert_eq!(o.window_end, Some(ts("2026-09-22T02:00:00Z")));
        let next = s
            .occurrence(ts("2026-09-22T02:00:00Z"), b"device")
            .unwrap()
            .unwrap();
        assert_eq!(next.available_at, ts("2026-09-28T22:00:00Z"));
    }
    #[test]
    fn dst_gap_is_skipped_and_fold_uses_earlier_instant_once() {
        let mut s = schedule();
        assert_eq!(
            s.due(ts("2026-03-07T00:00:00Z"), ts("2026-03-08T12:00:00Z"), b"x")
                .unwrap(),
            None
        );
        if let Trigger::Weekly { minute, .. } = &mut s.trigger {
            *minute = 90;
        }
        let fold = ts("2026-11-01T05:30:00Z");
        assert_eq!(
            s.due(ts("2026-10-31T00:00:00Z"), ts("2026-11-01T07:00:00Z"), b"x")
                .unwrap()
                .unwrap()
                .coordinate,
            fold
        );
        assert!(
            s.due(fold, ts("2026-11-01T07:00:00Z"), b"x")
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn window_keeps_identity_and_jitter_is_deterministic() {
        let mut s = schedule();
        s.jitter_seconds = 60;
        s.window = Some(Window {
            zone: "UTC".into(),
            weekdays: BTreeSet::from([1]),
            start_minute: 600,
            end_minute: 660,
        });
        let coordinate = ts("2026-09-20T12:00:00Z");
        let occurrence = s
            .occurrence(coordinate, b"tenant/schedule/revision/device")
            .unwrap()
            .unwrap();
        assert_eq!(occurrence.coordinate, coordinate);
        assert_eq!(occurrence.available_at, ts("2026-09-21T10:00:00Z"));
        assert_eq!(occurrence.window_end, Some(ts("2026-09-21T11:00:00Z")));
        assert_eq!(
            Some(occurrence),
            s.occurrence(coordinate, b"tenant/schedule/revision/device")
                .unwrap()
        );
    }
    #[test]
    fn missed_intervals_are_skipped_or_coalesced_once() {
        let s = Schedule {
            trigger: Trigger::Interval {
                anchor: 0,
                seconds: 60,
            },
            misfire: Misfire::Skip {
                max_lateness_seconds: 30,
            },
            not_before: 0,
            until: Some(86400),
            jitter_seconds: 0,
            window: None,
        };
        assert!(s.due(0, 599, b"x").unwrap().is_none());
        let s = Schedule {
            misfire: Misfire::CoalesceOne,
            ..s
        };
        assert_eq!(s.due(0, 599, b"x").unwrap().unwrap().coordinate, 540);
    }

    #[test]
    fn interval_requires_an_occurrence_before_until() {
        let mut s = Schedule {
            trigger: Trigger::Interval {
                anchor: 120,
                seconds: 60,
            },
            misfire: Misfire::CoalesceOne,
            not_before: 60,
            until: Some(120),
            jitter_seconds: 0,
            window: None,
        };
        assert!(s.validate().is_err());
        if let Trigger::Interval { anchor, .. } = &mut s.trigger {
            *anchor = 0;
        }
        assert!(s.validate().is_ok());
        s.not_before = 1;
        s.until = Some(30);
        assert!(s.validate().is_err());
        s.until = Some(61);
        assert!(s.validate().is_ok());
    }
}
