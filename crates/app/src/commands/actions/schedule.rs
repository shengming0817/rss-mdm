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
pub(super) enum Trigger {
    Manual,
    Once {
        at: i64,
    },
    Interval {
        anchor: i64,
        seconds: u32,
    },
    Weekly {
        zone: String,
        weekday: u8,
        minute: u16,
    },
    Registration,
    CheckIn {
        minimum_seconds: u32,
    },
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Misfire {
    #[default]
    Skip,
    CoalesceOne,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Window {
    pub zone: String,
    pub weekdays: BTreeSet<u8>,
    pub start_minute: u16,
    pub end_minute: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Schedule {
    pub trigger: Trigger,
    #[serde(default)]
    pub misfire: Misfire,
    pub not_before: i64,
    pub until: i64,
    pub jitter_seconds: u32,
    pub window: Option<Window>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Occurrence {
    // Base time is the immutable deduplication coordinate, never the delayed window time.
    pub coordinate: i64,
    pub available_at: i64,
    // A configured window is also an execution admission boundary.
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
    pub fn validate(&self) -> Result<(), Error> {
        if self.not_before < 0
            || self.until <= self.not_before
            || self.until - self.not_before > 366 * 86400
            || self.jitter_seconds > 3600
        {
            return Err(Error::Malformed);
        }
        Timestamp::from_second(self.until).map_err(|_| Error::Malformed)?;
        match &self.trigger {
            Trigger::Once { at } if *at < self.not_before || *at >= self.until => {
                return Err(Error::Malformed);
            }
            Trigger::Interval { anchor, seconds }
                if *anchor < 0 || !(60..=31_536_000).contains(seconds) =>
            {
                return Err(Error::Malformed);
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
                || window.start_minute >= window.end_minute
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
        if now < self.not_before || now >= self.until || now <= after {
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
        if matches!(self.misfire, Misfire::Skip) && occurrence.available_at < now.saturating_sub(30)
        {
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
        if coordinate < self.not_before || coordinate >= self.until {
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
            .filter(|(at, _)| *at < self.until)
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
            .date();
        for _ in 0..15 {
            if self
                .weekdays
                .contains(&(date.weekday().to_monday_one_offset() as u8))
                && let (Some(start), Some(end)) = (
                    local(&tz, date, self.start_minute)?,
                    local(&tz, date, self.end_minute)?,
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
            until: ts("2027-01-01T00:00:00Z"),
            jitter_seconds: 0,
            window: None,
        }
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
        let mut run = crate::commands::actions::state::RunState::new(
            occurrence.window_end.unwrap(),
            occurrence.available_at,
        )
        .unwrap();
        assert!(
            run.claim(uuid::Uuid::new_v4(), occurrence.window_end.unwrap())
                .is_err()
        );
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
            misfire: Misfire::Skip,
            not_before: 0,
            until: 86400,
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
}
