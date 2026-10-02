//! Readback evidence for queryable native mutations. ACKs never satisfy this contract.
use super::{Context, Error, Operation, Request, Verb};
use crate::syncml::Command;
use std::collections::BTreeMap;

/// Native evidence expected after a mutation, separate from its receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    /// Exact compiled native scalar or XML value.
    Value(String),
    /// The native object exists; no unrequested value is inferred.
    Present,
    /// A native 404 for this exact object after its Delete.
    Absent,
}
/// A bounded native query and the object evidence it is intended to observe.
pub struct Verification {
    /// Read-only native operations; Atomic does not permit Get and is not reused here.
    pub request: Request,
    /// Canonical object URI to expected native evidence.
    pub expected: BTreeMap<String, Expected>,
}
impl Request {
    /// Build readback only if every mutation has a valid native Get on the same target.
    /// Exec has no universal effect query; its platform lifecycle must supply one explicitly.
    pub fn verification(&self, context: Context) -> Result<Option<Verification>, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        let mut operations = BTreeMap::new();
        let mut expected = BTreeMap::new();
        while let Some(request) = pending.pop() {
            match request {
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations.iter().rev())
                }
                Self::Node {
                    node,
                    instance,
                    operation,
                    value,
                } => {
                    if *operation == Verb::Get {
                        continue;
                    }
                    if *operation == Verb::Exec {
                        return Ok(None);
                    }
                    let op =
                        Operation::compile(node, instance, *operation, value.clone(), context)?;
                    if Operation::compile(node, instance, Verb::Get, None, context).is_err() {
                        return Ok(None);
                    }
                    let goal = if *operation == Verb::Delete {
                        Expected::Absent
                    } else {
                        match op.command(1) {
                            Command::Add { items, .. } | Command::Replace { items, .. } => items
                                .into_iter()
                                .next()
                                .and_then(|i| i.data)
                                .map(|v| Expected::Value(v.0))
                                .unwrap_or(Expected::Present),
                            _ => return Err(Error::Value),
                        }
                    };
                    // Repeated writes to one object in a Sequence describe its last desired value.
                    expected.insert(op.uri().into(), goal);
                    operations.insert(
                        op.uri().to_owned(),
                        Self::Node {
                            node: node.clone(),
                            instance: instance.clone(),
                            operation: Verb::Get,
                            value: None,
                        },
                    );
                }
            }
        }
        if operations.is_empty() {
            return Ok(None);
        }
        let mut operations = operations.into_values().collect::<Vec<_>>();
        let request = if operations.len() == 1 {
            operations.remove(0)
        } else {
            Self::Sequence { operations }
        };
        Ok(Some(Verification { request, expected }))
    }
}
impl Expected {
    /// Interpret a correlated Get only; missing results and protocol failures remain unverified.
    pub fn matches(&self, status: Option<i32>, value: Option<&str>) -> bool {
        match self {
            Self::Absent => status == Some(404) && value.is_none(),
            Self::Present => status == Some(200) && value.is_some(),
            Self::Value(expected) => status == Some(200) && value == Some(expected.as_str()),
        }
    }
}
