//! Typed native input and exact object identities for the flow execution envelope.
use super::{Context, Error, Operation, Scope, Value, Verb};
use crate::{
    CodecLimits,
    syncml::{self, Command},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Windows native operation tree. Target evidence and command IDs are server-owned.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// One frozen native schema object and its dynamic identity.
    Node {
        /// Exact official URI template, with one `*` for each dynamic component.
        node: String,
        /// Unescaped dynamic components, in template order.
        instance: Vec<String>,
        /// Native verb.
        operation: Verb,
        /// Typed native value, absent for queries/deletion/interior nodes.
        #[serde(deserialize_with = "Option::deserialize")]
        value: Option<Value>,
    },
    /// Native atomic operation group, subject to Windows restrictions.
    Atomic {
        /// Ordered native children.
        operations: Vec<Request>,
    },
    /// Native sequential operation group.
    Sequence {
        /// Ordered native children.
        operations: Vec<Request>,
    },
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WindowsNativeRequest([REDACTED])")
    }
}

/// Exact native claim key. Device/registration/tenant are supplied by the execution envelope.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    /// Native management scope.
    pub scope: Scope,
    /// Canonical native object URI, including escaped dynamic components.
    pub uri: String,
}
/// Compiled protocol payload and the native objects it addresses.
pub struct Compiled {
    /// Native command tree, with IDs from the caller's allocated range.
    pub command: Command,
    /// Distinct native object claim identities.
    pub objects: Vec<Object>,
}
impl Request {
    /// Return the bounded number of native command IDs required, including group IDs.
    pub fn command_count(&self) -> Result<u32, Error> {
        let mut pending = vec![(self, 0)];
        let mut count = 0u32;
        while let Some((request, depth)) = pending.pop() {
            count += 1;
            if depth > 32 || count as usize + pending.len() > CodecLimits::default().commands {
                return Err(Error::Limit);
            }
            if let Self::Atomic { operations } | Self::Sequence { operations } = request {
                if operations.is_empty() {
                    return Err(Error::Value);
                }
                if operations.len() + pending.len() + count as usize
                    > CodecLimits::default().commands
                {
                    return Err(Error::Limit);
                }
                pending.extend(operations.iter().map(|r| (r, depth + 1)));
            }
        }
        Ok(count)
    }
    /// Only read-only native trees may be reissued after an unknown transport outcome.
    pub fn read_only(&self) -> Result<bool, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        while let Some(request) = pending.pop() {
            match request {
                Self::Node {
                    operation: Verb::Get,
                    ..
                } => {}
                Self::Node { .. } => return Ok(false),
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations)
                }
            }
        }
        Ok(true)
    }
    /// Compile against authenticated platform evidence after the caller allocates command IDs.
    pub fn compile(&self, context: Context, first: u32) -> Result<Compiled, Error> {
        let count = self.command_count()?;
        if first == 0 || first.checked_add(count - 1).is_none() {
            return Err(Error::Identity);
        }
        let mut next = u64::from(first);
        let mut objects = BTreeSet::new();
        let command = self.lower(context, &mut next, false, &mut objects)?;
        syncml::validate_body(
            std::slice::from_ref(&command),
            true,
            &CodecLimits::default(),
        )
        .map_err(|_| Error::Value)?;
        Ok(Compiled {
            command,
            objects: objects.into_iter().collect(),
        })
    }
    fn lower(
        &self,
        context: Context,
        next: &mut u64,
        atomic: bool,
        objects: &mut BTreeSet<Object>,
    ) -> Result<Command, Error> {
        let id = u32::try_from(*next).map_err(|_| Error::Identity)?;
        *next += 1;
        match self {
            Self::Node {
                node,
                instance,
                operation,
                value,
            } => {
                let op = Operation::compile(node, instance, *operation, value.clone(), context)?;
                if op.semantics().atomic_required && !atomic && !matches!(operation, Verb::Get) {
                    return Err(Error::AtomicRequired);
                }
                objects.insert(Object {
                    scope: context.scope,
                    uri: op.uri().into(),
                });
                Ok(op.command(id))
            }
            Self::Atomic { operations } | Self::Sequence { operations } => {
                let is_atomic = matches!(self, Self::Atomic { .. });
                if atomic && is_atomic {
                    return Err(Error::OperationNotAllowed);
                }
                let commands = operations
                    .iter()
                    .map(|request| request.lower(context, next, atomic || is_atomic, objects))
                    .collect::<Result<_, _>>()?;
                if is_atomic {
                    Ok(Command::Atomic { id, commands })
                } else {
                    Ok(Command::Sequence { id, commands })
                }
            }
        }
    }
}

/// Windows lifecycle input. MSI preparation/execution uses the same SyncML exchange owner.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Execution {
    /// One native tree, including atomic and sequential groups.
    SyncMl {
        /// Validated native operation tree.
        request: Request,
    },
    /// An admitted native software job. Product distribution remains separately authorized.
    Msi {
        /// Immutable native installer input.
        job: crate::software::InstallJob,
    },
}

impl Request {
    /// Resolve native claim identities without claiming OS applicability or execution authority.
    /// Actual dispatch must still call `compile` with authenticated target evidence.
    pub fn objects(&self) -> Result<Vec<Object>, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        let mut objects = BTreeSet::new();
        while let Some(request) = pending.pop() {
            match request {
                Self::Node { node, instance, .. } => {
                    if !super::known_node(node) {
                        return Err(Error::UnknownObject);
                    }
                    objects.insert(Object {
                        scope: if node.starts_with("./User/") {
                            Scope::User
                        } else {
                            Scope::Device
                        },
                        uri: super::identity(node, instance)?,
                    });
                }
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations)
                }
            }
        }
        Ok(objects.into_iter().collect())
    }
}

impl Request {
    /// Resolve schema-owned authorization targets, including descendants of subtree reads/deletes.
    /// This supplies native identities only; the product owns permissions and authenticated scope.
    pub fn authorization_nodes(&self) -> Result<Vec<(String, Verb)>, Error> {
        self.objects()?;
        let mut pending = vec![self];
        let mut result = Vec::new();
        while let Some(request) = pending.pop() {
            match request {
                Self::Node { node, operation, .. } => {
                    result.push((node.clone(), *operation));
                    let selected = super::generated::NODES
                        .binary_search_by_key(&node.as_str(), |n| n.path)
                        .map_err(|_| Error::UnknownObject)?;
                    if *operation == Verb::Delete
                        || (*operation == Verb::Get && matches!(super::generated::NODES[selected].format, super::Format::Node))
                    {
                        let prefix = format!("{node}/");
                        for child in &super::generated::NODES[selected + 1..] {
                            if !child.path.starts_with(&prefix) { break; }
                            result.push((child.path.into(), *operation));
                        }
                    }
                }
                Self::Atomic { operations } | Self::Sequence { operations } => pending.extend(operations),
            }
        }
        Ok(result)
    }
}
