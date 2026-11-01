use crate::{Error, Result};
use sha2::{Digest, Sha256};

pub fn transaction_body(sql: &str) -> Result<Vec<&str>> {
    let mut offset = 0;
    let mut start = 0;
    let mut wrapped = false;
    let mut bodies = Vec::new();
    for line in sql.split_inclusive('\n') {
        match line.trim() {
            "BEGIN;" if !wrapped => {
                bodies.push(&sql[start..offset]);
                wrapped = true;
                start = offset + line.len();
            }
            "COMMIT;" if wrapped => {
                bodies.push(&sql[start..offset]);
                wrapped = false;
                start = offset + line.len();
            }
            "BEGIN;" | "COMMIT;" | "ROLLBACK;" | "START TRANSACTION;" => {
                return Err(Error::at(
                    "installation",
                    "unsupported component transaction envelope",
                ));
            }
            _ => {}
        }
        offset += line.len();
    }
    if wrapped {
        return Err(Error::at(
            "installation",
            "unclosed component transaction envelope",
        ));
    }
    bodies.push(&sql[start..]);
    bodies.retain(|body| {
        body.lines()
            .any(|line| !line.trim().is_empty() && !line.trim().starts_with("--"))
    });
    Ok(bodies)
}
pub fn resumable_ledger(
    installed: &[(String, String, bool)],
    current: &[(&'static str, &'static str)],
) -> bool {
    if installed.len() > current.len() || installed.iter().any(|row| !row.2) {
        return false;
    }
    let prefix = &current[..installed.len()];
    installed.iter().all(|(name, digest, _)| {
        prefix
            .iter()
            .any(|(n, sql)| name == n && *digest == format!("{:x}", Sha256::digest(sql)))
    }) && installed
        .iter()
        .map(|row| &row.0)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == installed.len()
}
pub fn accepted_ledger(
    installed: &[(String, String, bool)],
    current: &[(&'static str, &'static str)],
) -> bool {
    use std::collections::BTreeMap;
    if installed.is_empty() {
        return true;
    }
    if installed.iter().any(|(_, _, complete)| !complete) {
        return false;
    }
    let actual = installed
        .iter()
        .map(|(name, digest, _)| (name.as_str(), digest.as_str()))
        .collect::<BTreeMap<_, _>>();
    if actual.len() != installed.len() {
        return false;
    }
    let candidate = current
        .iter()
        .map(|(name, sql)| (*name, format!("{:x}", Sha256::digest(sql))))
        .collect::<BTreeMap<_, _>>();
    let matches = |expected: &BTreeMap<&str, String>| {
        actual.len() == expected.len()
            && actual
                .iter()
                .all(|(name, digest)| expected.get(name).is_some_and(|value| value == digest))
    };
    if matches(&candidate) {
        return true;
    }
    false
}
