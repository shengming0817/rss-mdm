//! Bounded, explicit extraction and conversion shared by native and script collectors.
//! ref: osquery/osquery specs/windows/bitlocker_info.table@5.23.1
use crate::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Closed conversions; unknown native codes never become a successful default value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Conversion {
    /// Preserve the native JSON type, including explicit null.
    Identity,
    /// Convert a fully specified CIM datetime with explicit offset to UTC Unix seconds.
    CimTime,
    /// Parse an exact decimal integer string.
    Integer,
    /// Parse a finite JSON number or decimal number string.
    Number,
    /// Explicit source code to canonical scalar, including boolean values.
    Enum {
        /// Finite exact source tokens. Unknown tokens are invalid.
        values: BTreeMap<String, Value>,
    },
    /// Convert nonnegative integral units using checked exact rational arithmetic.
    Scale {
        /// Numerator.
        numerator: u64,
        /// Nonzero denominator; fractional output is rejected.
        denominator: u64,
    },
    /// Decode a finite nonnegative bitmask to a sorted list of declared flag names.
    Bitmask {
        /// Keys are decimal single-bit masks. Undeclared set bits are invalid.
        flags: BTreeMap<String, String>,
    },
}
/// Extraction relative to a response or list item. Empty pointer selects the whole value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValueMapping {
    /// RFC 6901 pointer, never an expression.
    pub pointer: String,
    /// Conversion of a direct scalar; structured projections require identity.
    pub conversion: Conversion,
    /// Exact output properties for each array item. No undeclared attributes are copied.
    pub columns: BTreeMap<String, ValueMapping>,
}
impl ValueMapping {
    /// Construct an explicit identity extraction.
    pub fn identity(pointer: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            conversion: Conversion::Identity,
            columns: BTreeMap::new(),
        }
    }
    /// Validate cumulative budgets and closed structural rules before publication.
    pub fn validate(&self) -> Result<(), Error> {
        self.check(0, &mut 0)
    }
    fn check(&self, depth: usize, nodes: &mut usize) -> Result<(), Error> {
        *nodes += 1;
        if depth > 4 || *nodes > 128 || !pointer(&self.pointer) || self.columns.len() > 64 {
            return Err(Error::InvalidInput);
        }
        if !self.columns.is_empty() && self.conversion != Conversion::Identity {
            return Err(Error::InvalidInput);
        }
        self.conversion.validate()?;
        for (name, mapping) in &self.columns {
            if name.is_empty()
                || name.len() > 64
                || !name.as_bytes()[0].is_ascii_lowercase()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(Error::InvalidInput);
            }
            mapping.check(depth + 1, nodes)?;
        }
        Ok(())
    }
    /// Convert an already extracted scalar or project one selected list row.
    pub fn project(&self, raw: &Value) -> Result<Value, Error> {
        if self.columns.is_empty() {
            return self.conversion.apply(raw);
        }
        if !raw.is_object() {
            return Err(Error::InvalidInput);
        }
        let mut result = serde_json::Map::new();
        for (name, mapping) in &self.columns {
            let selected = raw.pointer(&mapping.pointer).ok_or(Error::InvalidInput)?;
            result.insert(name.clone(), mapping.project(selected)?);
        }
        Ok(Value::Object(result))
    }
}
impl Conversion {
    /// Check conversion declarations independently of any device value.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Enum { values } => {
                if values.is_empty()
                    || values.len() > 128
                    || values.iter().any(|(k, v)| {
                        k.len() > 256
                            || k.chars().any(char::is_control)
                            || !matches!(v, Value::String(_) | Value::Bool(_) | Value::Number(_))
                            || v.as_str()
                                .is_some_and(|s| s.len() > 256 || s.contains('\0'))
                    })
                {
                    return Err(Error::InvalidInput);
                }
            }
            Self::Scale {
                numerator,
                denominator,
            } if *numerator == 0 || *denominator == 0 => return Err(Error::InvalidInput),
            Self::Bitmask { flags } => {
                let mut names = std::collections::BTreeSet::new();
                if flags.is_empty() || flags.len() > 63 {
                    return Err(Error::InvalidInput);
                }
                for (bit, name) in flags {
                    let mask = bit.parse::<u64>().map_err(|_| Error::InvalidInput)?;
                    if !mask.is_power_of_two()
                        || mask > i64::MAX as u64
                        || mask.to_string() != *bit
                        || name.is_empty()
                        || name.len() > 64
                        || name.chars().any(char::is_control)
                        || !names.insert(name)
                    {
                        return Err(Error::InvalidInput);
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
    /// Apply the exact declared conversion. No truthiness, saturation or implicit rounding.
    pub fn apply(&self, raw: &Value) -> Result<Value, Error> {
        self.validate()?;
        let integer = || match raw {
            Value::String(s) => s.parse::<i64>().map_err(|_| Error::InvalidInput),
            v => v.as_i64().ok_or(Error::InvalidInput),
        };
        match self {
            Self::Identity => Ok(raw.clone()),
            Self::CimTime => {
                let s = raw.as_str().ok_or(Error::InvalidInput)?;
                if s.len() != 25
                    || !s.is_ascii()
                    || s.as_bytes()[14] != b'.'
                    || !matches!(s.as_bytes()[21], b'+' | b'-')
                    || !s[..14]
                        .bytes()
                        .chain(s[15..21].bytes())
                        .chain(s[22..].bytes())
                        .all(|b| b.is_ascii_digit())
                {
                    return Err(Error::InvalidInput);
                }
                let n =
                    |a: usize, b: usize| s[a..b].parse::<i32>().map_err(|_| Error::InvalidInput);
                let month =
                    time::Month::try_from(n(4, 6)? as u8).map_err(|_| Error::InvalidInput)?;
                let date = time::Date::from_calendar_date(n(0, 4)?, month, n(6, 8)? as u8)
                    .map_err(|_| Error::InvalidInput)?;
                let clock = time::Time::from_hms_micro(
                    n(8, 10)? as u8,
                    n(10, 12)? as u8,
                    n(12, 14)? as u8,
                    n(15, 21)? as u32,
                )
                .map_err(|_| Error::InvalidInput)?;
                let seconds = n(22, 25)? * 60 * if s.as_bytes()[21] == b'-' { -1 } else { 1 };
                let offset = time::UtcOffset::from_whole_seconds(seconds)
                    .map_err(|_| Error::InvalidInput)?;
                Ok(Value::from(
                    time::PrimitiveDateTime::new(date, clock)
                        .assume_offset(offset)
                        .unix_timestamp(),
                ))
            }
            Self::Integer => Ok(Value::from(integer()?)),
            Self::Number => {
                let n = match raw {
                    Value::String(s) => s.parse::<f64>().map_err(|_| Error::InvalidInput)?,
                    v => v.as_f64().ok_or(Error::InvalidInput)?,
                };
                serde_json::Number::from_f64(n)
                    .map(Value::Number)
                    .ok_or(Error::InvalidInput)
            }
            Self::Enum { values } => {
                let key = match raw {
                    Value::String(s) => s.clone(),
                    Value::Number(_) | Value::Bool(_) => raw.to_string(),
                    _ => return Err(Error::InvalidInput),
                };
                values.get(&key).cloned().ok_or(Error::InvalidInput)
            }
            Self::Scale {
                numerator,
                denominator,
            } => {
                let input = match raw {
                    Value::String(s) => s.parse::<u64>().map_err(|_| Error::InvalidInput)?,
                    v => v.as_u64().ok_or(Error::InvalidInput)?,
                };
                let n = u128::from(input)
                    .checked_mul(u128::from(*numerator))
                    .ok_or(Error::InvalidInput)?;
                let d = u128::from(*denominator);
                if n % d != 0 {
                    return Err(Error::InvalidInput);
                }
                Ok(Value::from(
                    i64::try_from(n / d).map_err(|_| Error::InvalidInput)?,
                ))
            }
            Self::Bitmask { flags } => {
                let n = u64::try_from(integer()?).map_err(|_| Error::InvalidInput)?;
                let mut known = 0;
                let mut names = Vec::new();
                for (bit, name) in flags {
                    let bit: u64 = bit.parse().map_err(|_| Error::InvalidInput)?;
                    known |= bit;
                    if n & bit != 0 {
                        names.push(name.clone());
                    }
                }
                if n & !known != 0 {
                    return Err(Error::InvalidInput);
                }
                names.sort();
                Ok(serde_json::json!(names))
            }
        }
    }
}
pub(crate) fn pointer(value: &str) -> bool {
    if value.len() > 4096
        || (!value.is_empty() && !value.starts_with('/'))
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}
