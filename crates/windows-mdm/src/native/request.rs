//! Typed native input and exact object identities for the flow execution envelope.
use super::{Context, Error, Scope, Value, Verb};
use crate::{CodecLimits, syncml::Command};
use serde::{Deserialize, Serialize};

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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Object {
    /// CSP subtree identity, including management scope.
    Csp {
        /// Native management context.
        scope: Scope,
        /// Canonical native URI.
        uri: String,
    },
    /// Conservative class-wide MI ownership; MOF keys are not known by the service.
    Mi {
        /// Native management context.
        scope: Scope,
        /// Canonical namespace and class; keys remain inside the document.
        class: String,
    },
}
impl Object {
    /// Native management scope.
    pub fn scope(&self) -> Scope {
        match self {
            Self::Csp { scope, .. } | Self::Mi { scope, .. } => *scope,
        }
    }
    /// Stable product claim namespace.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Csp { .. } => "csp",
            Self::Mi { .. } => "mi",
        }
    }
    /// Native claim key; MI keys must never be used as wire URIs.
    pub fn key(&self) -> &str {
        match self {
            Self::Csp { uri, .. } => uri,
            Self::Mi { class, .. } => class,
        }
    }
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
        self.resolve()?.prepare(context)?.command(first)
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
    /// Resolve all claims through the same tree used by authorization and dispatch.
    pub fn objects(&self) -> Result<Vec<Object>, Error> {
        Ok(self.resolve()?.objects().to_vec())
    }
}

impl Request {
    /// Resolve a concrete query URI to the frozen schema without inventing platform evidence.
    pub fn from_uri(
        uri: &str,
        operation: Verb,
        value: Option<Value>,
        scope: Scope,
    ) -> Result<Self, Error> {
        let mut candidates = vec![uri.to_owned()];
        if uri.starts_with("./Vendor/MSFT/") {
            candidates = vec![uri.replacen(
                "./Vendor/",
                if scope == Scope::User {
                    "./User/Vendor/"
                } else {
                    "./Device/Vendor/"
                },
                1,
            )];
        }
        let mut selected = None;
        let mut specificity = 0;
        let mut ambiguous = false;
        for concrete in candidates {
            let parts = concrete.split('/').collect::<Vec<_>>();
            for node in super::generated::NODES {
                if node.path.starts_with("./User/") != (scope == Scope::User) {
                    continue;
                }
                let template = node.path.split('/').collect::<Vec<_>>();
                if template.len() != parts.len()
                    || !template
                        .iter()
                        .zip(&parts)
                        .all(|(t, v)| *t == "*" || t == v)
                {
                    continue;
                }
                let score = template.iter().filter(|t| **t != "*").count();
                let instance: Vec<String> = template
                    .iter()
                    .zip(&parts)
                    .filter_map(|(t, v)| (*t == "*").then_some((*v).to_owned()))
                    .map(|v| {
                        percent_encoding::percent_decode_str(&v)
                            .decode_utf8()
                            .map(|v| v.into_owned())
                            .map_err(|_| Error::Identity)
                    })
                    .collect::<Result<_, _>>()?;
                let candidate = Self::Node {
                    node: node.path.into(),
                    instance,
                    operation,
                    value: value.clone(),
                };
                candidate.resolve()?;
                if selected.is_none() || score > specificity {
                    selected = Some(candidate);
                    specificity = score;
                    ambiguous = false;
                } else if score == specificity {
                    ambiguous = true;
                }
            }
        }
        if ambiguous {
            return Err(Error::Identity);
        }
        selected.ok_or(Error::UnknownObject)
    }
}

impl Request {
    /// Bind DMClient maintenance to the provider that owns the authenticated enrollment.
    /// A schema-valid dynamic identity alone does not authorize another MDM provider.
    pub fn validate_provider(&self, provider: &str) -> Result<(), Error> {
        self.command_count()?;
        let mut pending = vec![self];
        while let Some(request) = pending.pop() {
            match request {
                Self::Node {
                    node,
                    instance,
                    operation,
                    value,
                } => {
                    if node.contains("/Vendor/MSFT/DMClient/Provider/*")
                        && instance.first().map(String::as_str) != Some(provider)
                    {
                        return Err(Error::Scope);
                    }
                    if node == "./SyncML/DMAcc/*/ServerID"
                        && matches!(operation, Verb::Add | Verb::Replace)
                        && !matches!(value,Some(Value::Text(v)) if v==provider)
                    {
                        return Err(Error::Scope);
                    }
                    if node == "./Device/Vendor/MSFT/DMClient/Unenroll"
                        && *operation == Verb::Exec
                        && !matches!(value,Some(Value::Text(v)) if v==provider)
                    {
                        return Err(Error::Scope);
                    }
                }
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations)
                }
            }
        }
        Ok(())
    }
}

impl Request {
    /// Declared configuration belongs exclusively to an independently verified linked enrollment.
    pub fn requires_linked_enrollment(&self) -> Result<bool, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        while let Some(request) = pending.pop() {
            match request {
                Self::Node { node, .. }
                    if node.ends_with("/Vendor/MSFT/DeclaredConfiguration")
                        || node.contains("/Vendor/MSFT/DeclaredConfiguration/") =>
                {
                    return Ok(true);
                }
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations)
                }
                _ => {}
            }
        }
        Ok(false)
    }
}

impl Request {
    /// Replace a complete, validated native polling schedule through the existing execution tree.
    pub fn poll_schedule(provider: &str, poll: &crate::provisioning::Poll) -> Result<Self, Error> {
        poll.validate().map_err(|_| Error::Value)?;
        Ok(Self::Sequence {
            operations: poll
                .parameters()
                .into_iter()
                .map(|(name, value, kind)| {
                    Ok(Self::Node {
                        node: format!("./Device/Vendor/MSFT/DMClient/Provider/*/Poll/{name}"),
                        instance: vec![provider.to_owned()],
                        operation: Verb::Replace,
                        value: Some(if kind == "boolean" {
                            Value::Boolean(value == "true")
                        } else {
                            Value::Integer(value.parse().map_err(|_| Error::Value)?)
                        }),
                    })
                })
                .collect::<Result<_, Error>>()?,
        })
    }
    /// Schedule changes are a complete tuple. Partial writes or deletes could silently disable polling.
    pub fn validate_poll(&self) -> Result<(), Error> {
        let mut pending = vec![self];
        let mut parameters = std::collections::BTreeMap::new();
        while let Some(request) = pending.pop() {
            match request {
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations)
                }
                Self::Node {
                    node,
                    operation,
                    value,
                    ..
                } if node.contains("/DMClient/Provider/*/Poll/") && *operation != Verb::Get => {
                    if *operation != Verb::Replace {
                        return Err(Error::Value);
                    }
                    let name = node.rsplit('/').next().ok_or(Error::Value)?;
                    if parameters
                        .insert(name, value.as_ref().ok_or(Error::Value)?)
                        .is_some()
                    {
                        return Err(Error::Value);
                    }
                }
                _ => {}
            }
        }
        if parameters.is_empty() {
            return Ok(());
        }
        let integer = |name| match parameters.get(name) {
            Some(Value::Integer(v)) => u32::try_from(*v).map_err(|_| Error::Value),
            _ => Err(Error::Value),
        };
        let boolean = |name| match parameters.get(name) {
            Some(Value::Boolean(v)) => Ok(*v),
            _ => Err(Error::Value),
        };
        let poll = crate::provisioning::Poll {
            interval_for_first_set_of_retries: integer("IntervalForFirstSetOfRetries")?,
            number_of_first_retries: integer("NumberOfFirstRetries")?,
            interval_for_second_set_of_retries: integer("IntervalForSecondSetOfRetries")?,
            number_of_second_retries: integer("NumberOfSecondRetries")?,
            interval_for_remaining_scheduled_retries: integer(
                "IntervalForRemainingScheduledRetries",
            )?,
            number_of_remaining_scheduled_retries: integer("NumberOfRemainingScheduledRetries")?,
            poll_on_login: boolean("PollOnLogin")?,
            all_users_poll_on_first_login: boolean("AllUsersPollOnFirstLogin")?,
        };
        if parameters.len() != 8 {
            return Err(Error::Value);
        }
        poll.validate().map_err(|_| Error::Value)
    }
}
