//! Item predicates reuse the product parser, binding all leaves to the same installation.
use super::*;
use rss_mdm_query::{Expression, Operator};
pub(super) type Predicate = Expression<String, String>;
pub const FIELDS: &[&str] = &[
    "id",
    "nativeId",
    "name",
    "version",
    "publisher",
    "platform",
    "origin",
    "source",
    "component",
    "location",
];

pub(super) fn compile(text: &str) -> Result<Predicate> {
    let expression = checked_input(rss_mdm_query::parse_filter(text))?;
    fn validate(e: &Predicate) -> Result<()> {
        match e {
            Expression::And(v) | Expression::Or(v) => {
                for child in v {
                    validate(child)?;
                }
            }
            Expression::Compare {
                field,
                operator,
                values,
            } => {
                if !FIELDS.contains(&field.as_str())
                    || values.is_empty()
                    || values.iter().any(|v| v.len() > 4096)
                    || !matches!(
                        operator,
                        Operator::Eq
                            | Operator::Ne
                            | Operator::In
                            | Operator::Out
                            | Operator::Icontains
                    )
                    || !operator.set() && values.len() != 1
                    || field == "version" && !matches!(operator, Operator::Eq | Operator::In)
                    || matches!(operator, Operator::Icontains)
                        && !matches!(field.as_str(), "name" | "publisher" | "component")
                {
                    return Err(Error::Malformed.into());
                }
            }
        }
        Ok(())
    }
    validate(&expression)?;
    Ok(expression)
}
pub(super) fn matches(e: &Predicate, item: &evidence::Item) -> bool {
    match e {
        Expression::And(v) => v.iter().all(|e| matches(e, item)),
        Expression::Or(v) => v.iter().any(|e| matches(e, item)),
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            let Some(actual) = item.fields.get(field) else {
                return false;
            };
            match operator {
                Operator::Eq | Operator::In => values.contains(actual),
                Operator::Ne | Operator::Out => !values.contains(actual),
                Operator::Icontains => actual.to_lowercase().contains(&values[0].to_lowercase()),
                _ => false,
            }
        }
    }
}
/// Every OR branch must identify a package or a publisher-qualified name.
pub(super) fn anchored(e: &Predicate) -> bool {
    fn alternatives(e: &Predicate) -> BTreeSet<u8> {
        match e {
            Expression::Compare {
                field,
                operator: Operator::Eq | Operator::In,
                values,
            } if values.iter().all(|v| !v.is_empty()) => [match field.as_str() {
                "nativeId" | "id" => 4,
                "name" => 1,
                "publisher" | "location" => 2,
                _ => 0,
            }]
            .into(),
            Expression::And(children) => {
                children
                    .iter()
                    .fold([0u8].into(), |left: BTreeSet<u8>, child| {
                        let right = alternatives(child);
                        left.into_iter()
                            .flat_map(|l| right.iter().map(move |r| l | r))
                            .collect()
                    })
            }
            Expression::Or(children) => children.iter().flat_map(alternatives).collect(),
            _ => [0u8].into(),
        }
    }
    let branches = alternatives(e);
    !branches.is_empty() && branches.iter().all(|bits| bits & 4 != 0 || bits & 3 == 3)
}

pub(super) fn validate_standard(s: &Standard) -> Result<()> {
    if s.name.trim().is_empty()
        || s.name.len() > 256
        || s.tags.len() > 32
        || s.tags.iter().any(|v| v.trim().is_empty() || v.len() > 128)
        || s.tags.iter().collect::<BTreeSet<_>>().len() != s.tags.len()
    {
        return Err(Error::Malformed.into());
    }
    for policy in [&s.assessments.endpoint, &s.assessments.associated_device] {
        if policy.threshold.is_some_and(|n| n == 0 || n > 1_000_000) {
            return Err(Error::Malformed.into());
        }
        if let Some(groups) = &policy.allowed_groups {
            validate_groups(groups)?;
        }
    }
    Ok(())
}
pub(super) fn validate_groups(groups: &[Uuid]) -> Result<()> {
    if groups.is_empty()
        || groups.len() > 64
        || groups.iter().any(Uuid::is_nil)
        || groups.iter().collect::<BTreeSet<_>>().len() != groups.len()
    {
        return Err(Error::Malformed.into());
    }
    Ok(())
}
pub(super) fn validate_mapping(m: &Mapping) -> Result<()> {
    let expression = compile(&m.filter)?;
    if m.standard.is_nil()
        || !anchored(&expression)
        || m.origin
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 256)
        || m.source == SoftwareSource::Installations && m.origin.is_none()
        || m.source == SoftwareSource::AppleApplications
            && m.platform != rss_mdm_inventory::Platform::Macos
        || matches!(
            m.source,
            SoftwareSource::WindowsWin32
                | SoftwareSource::WindowsStore
                | SoftwareSource::WindowsNonStore
                | SoftwareSource::WindowsSystem
        ) && m.platform != rss_mdm_inventory::Platform::Windows
    {
        return Err(Error::Malformed.into());
    }
    Ok(())
}
pub(super) fn union(decisions: impl IntoIterator<Item = Decision>) -> Decision {
    let mut unknown = false;
    let mut any = false;
    for decision in decisions {
        any = true;
        match decision {
            Decision::Match => return Decision::Match,
            Decision::Unknown => unknown = true,
            Decision::NoMatch => (),
        }
    }
    if unknown || !any {
        Decision::Unknown
    } else {
        Decision::NoMatch
    }
}
pub(super) fn compliance(policy: &Assessment, groups: &BTreeMap<Uuid, Decision>) -> Compliance {
    match &policy.allowed_groups {
        None => Compliance::Disabled,
        Some(ids) => match union(
            ids.iter()
                .map(|id| groups.get(id).copied().unwrap_or(Decision::Unknown)),
        ) {
            Decision::Match => Compliance::Compliant,
            Decision::NoMatch => Compliance::NonCompliant,
            Decision::Unknown => Compliance::Unknown,
        },
    }
}
