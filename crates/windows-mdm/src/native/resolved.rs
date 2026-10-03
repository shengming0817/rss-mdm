//! One resolved tree supplies claims, authorization targets, dispatch and effect expectations.
//! ref: Microsoft DeclaredConfiguration CSP and declared-configuration-extensibility.
use super::verification::{EffectPlan, Expected, Verification};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Schema-owned authorization facts; permissions remain owned by the product.
pub enum AuthorizationTarget {
    /// Ordinary or embedded CSP operation, including subtree descendants.
    Csp {
        /// Frozen schema template.
        node: String,
        /// Actual operation on this target.
        operation: Verb,
    },
    /// Invokes arbitrary installed MI code; never inherits ConfigurationWrite.
    Mi {
        /// Canonical namespace and class.
        class: String,
    },
    /// WinDC's management interval, independent of embedded configuration resources.
    DeclaredInterval,
    /// Reading full results may disclose values from privileged resources.
    DeclaredResult,
}
struct Leaf {
    node: String,
    instance: Vec<String>,
    operation: Verb,
    value: Option<Value>,
    document: Option<declared::Document>,
    embedded: Vec<Request>,
}
/// Immutable resolution; documents are parsed once and retained for effect assessment.
pub struct Resolved<'a> {
    request: &'a Request,
    leaves: Vec<Leaf>,
    objects: Vec<Object>,
    targets: Vec<AuthorizationTarget>,
}
/// Schema checked dispatch and effect contract; protocol IDs are assigned only by `command`.
pub struct Prepared<'a> {
    resolved: Resolved<'a>,
    context: Context,
    /// Exact readback evidence, independently of a SyncML receipt.
    pub effect: EffectPlan,
}
fn scope(node: &str) -> Scope {
    if node.starts_with("./User/") {
        Scope::User
    } else {
        Scope::Device
    }
}
fn schema(node: &str) -> Result<&'static Node, Error> {
    generated::NODES
        .binary_search_by_key(&node, |n| n.path)
        .map(|i| &generated::NODES[i])
        .map_err(|_| Error::UnknownObject)
}
fn csp_targets(
    node: &str,
    operation: Verb,
    targets: &mut Vec<AuthorizationTarget>,
) -> Result<(), Error> {
    let selected = schema(node)?;
    if selected.access & operation.mask() == 0 {
        return Err(Error::OperationNotAllowed);
    }
    targets.push(AuthorizationTarget::Csp {
        node: node.into(),
        operation,
    });
    if operation == Verb::Delete || operation == Verb::Get && selected.format == Format::Node {
        let prefix = format!("{node}/");
        for n in generated::NODES
            .iter()
            .filter(|n| n.path.starts_with(&prefix))
        {
            targets.push(AuthorizationTarget::Csp {
                node: n.path.into(),
                operation,
            });
        }
    }
    Ok(())
}
impl Request {
    /// Resolve all native identities and embedded authorization targets through one parser.
    pub fn resolve(&self) -> Result<Resolved<'_>, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        let (mut leaves, mut objects, mut targets) = (Vec::new(), BTreeSet::new(), Vec::new());
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
                    let selected = schema(node)?;
                    if selected.access & operation.mask() == 0 {
                        return Err(Error::OperationNotAllowed);
                    }
                    let uri = identity(node, instance)?;
                    let mut leaf = Leaf {
                        node: node.clone(),
                        instance: instance.clone(),
                        operation: *operation,
                        value: value.clone(),
                        document: None,
                        embedded: Vec::new(),
                    };
                    if node.contains("/DeclaredConfiguration/") {
                        if node.ends_with("/Documents/*/Document")
                            && matches!(operation, Verb::Add | Verb::Replace | Verb::Delete)
                        {
                            let Some(Value::Xml(xml)) = value else {
                                return Err(Error::Value);
                            };
                            let document = declared::Document::parse(xml)?;
                            let id = instance
                                .first()
                                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                                .ok_or(Error::Identity)?;
                            if instance.len() != 1
                                || id != document.identity.id
                                || scope(node) != document.identity.scope
                            {
                                return Err(Error::Identity);
                            }
                            let inventory = node.contains("/Host/Inventory/");
                            if inventory != document.identity.scenario.ends_with("Inventory")
                                && document.dsc
                            {
                                return Err(Error::Value);
                            }
                            if !node.contains("/Host/Complete/") && !inventory {
                                return Err(Error::Unsupported);
                            }
                            // Canonical GUID prevents case/braces variants from aliasing claim identities.
                            leaf.instance = vec![id.to_string()];
                            objects.insert(Object::Csp {
                                scope: scope(node),
                                uri: identity(node, &leaf.instance)?,
                            });
                            if document.dsc {
                                for class in document
                                    .resources
                                    .keys()
                                    .filter_map(|k| k.split_once("/Key/").map(|(c, _)| c))
                                    .collect::<BTreeSet<_>>()
                                {
                                    objects.insert(Object::Mi {
                                        scope: Scope::Device,
                                        class: class.into(),
                                    });
                                    targets.push(AuthorizationTarget::Mi {
                                        class: class.into(),
                                    });
                                }
                            } else {
                                leaf.embedded =
                                    document.requests(if *operation == Verb::Delete {
                                        Verb::Delete
                                    } else if inventory {
                                        Verb::Get
                                    } else {
                                        Verb::Replace
                                    })?;
                                for embedded in &leaf.embedded {
                                    let Self::Node {
                                        node,
                                        instance,
                                        operation,
                                        ..
                                    } = embedded
                                    else {
                                        return Err(Error::Value);
                                    };
                                    objects.insert(Object::Csp {
                                        scope: scope(node),
                                        uri: identity(node, instance)?,
                                    });
                                    csp_targets(node, *operation, &mut targets)?;
                                }
                            }
                            leaf.document = Some(document);
                        } else if node
                            == "./Device/Vendor/MSFT/DeclaredConfiguration/ManagementServiceConfiguration/RefreshInterval"
                        {
                            targets.push(AuthorizationTarget::DeclaredInterval);
                            objects.insert(Object::Csp {
                                scope: scope(node),
                                uri,
                            });
                        } else if node.ends_with("/Results/*/Document")
                            && *operation == Verb::Get
                            && value.is_none()
                        {
                            let id = instance
                                .first()
                                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                                .filter(|id| !id.is_nil())
                                .ok_or(Error::Identity)?;
                            leaf.instance = vec![id.to_string()];
                            targets.push(AuthorizationTarget::DeclaredResult);
                            objects.insert(Object::Csp {
                                scope: scope(node),
                                uri: identity(node, &leaf.instance)?,
                            });
                        } else {
                            return Err(Error::Unsupported);
                        }
                    } else {
                        objects.insert(Object::Csp {
                            scope: scope(node),
                            uri,
                        });
                        csp_targets(node, *operation, &mut targets)?;
                    }
                    leaves.push(leaf);
                }
            }
        }
        if leaves
            .iter()
            .any(|l| l.node.contains("/DeclaredConfiguration/"))
            && leaves
                .iter()
                .any(|l| !l.node.contains("/DeclaredConfiguration/"))
        {
            return Err(Error::Scope);
        }
        Ok(Resolved {
            request: self,
            leaves,
            objects: objects.into_iter().collect(),
            targets,
        })
    }
}
impl<'a> Resolved<'a> {
    /// Native identities; MI claims are deliberately class-wide without a MOF schema.
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }
    /// Product permissions must cover every returned target.
    pub fn authorization(&self) -> &[AuthorizationTarget] {
        &self.targets
    }
    /// Validate applicability and values before allocating protocol IDs.
    pub fn prepare(self, context: Context) -> Result<Prepared<'a>, Error> {
        for leaf in &self.leaves {
            leaf.compile(context)?;
            for embedded in &leaf.embedded {
                embedded.resolve()?.prepare(Context {
                    enrollment: Enrollment::Primary,
                    ..context
                })?;
            }
        }
        let effect = effect(&self.leaves, context)?;
        Ok(Prepared {
            resolved: self,
            context,
            effect,
        })
    }
}
impl Leaf {
    fn compile(&self, context: Context) -> Result<Operation, Error> {
        let value = if self.document.is_some() && self.operation == Verb::Delete {
            None
        } else {
            self.value.clone()
        };
        // DDF encodes the document as chr; the product input retains typed XML.
        let value = if self.document.is_some() && self.operation != Verb::Delete {
            let Some(Value::Xml(xml)) = value else {
                return Err(Error::Value);
            };
            Some(Value::Text(xml))
        } else {
            value
        };
        Operation::compile(&self.node, &self.instance, self.operation, value, context)
    }
}
impl Prepared<'_> {
    /// Emit a validated tree after allocating IDs on the authenticated registration.
    pub fn command(&self, first: u32) -> Result<Compiled, Error> {
        let count = self.resolved.request.command_count()?;
        if first == 0 || first.checked_add(count - 1).is_none() {
            return Err(Error::Identity);
        }
        let (mut next, mut leaves) = (u64::from(first), self.resolved.leaves.iter());
        fn lower(
            request: &Request,
            context: Context,
            next: &mut u64,
            leaves: &mut std::slice::Iter<'_, Leaf>,
            atomic: bool,
        ) -> Result<Command, Error> {
            let id = u32::try_from(*next).map_err(|_| Error::Identity)?;
            *next += 1;
            match request {
                Request::Node { .. } => {
                    let op = leaves.next().ok_or(Error::Value)?.compile(context)?;
                    if op.semantics().atomic_required && !atomic && op.verb != Verb::Get {
                        return Err(Error::AtomicRequired);
                    }
                    Ok(op.command(id))
                }
                Request::Atomic { operations } | Request::Sequence { operations } => {
                    let is_atomic = matches!(request, Request::Atomic { .. });
                    if atomic && is_atomic {
                        return Err(Error::OperationNotAllowed);
                    }
                    let commands = operations
                        .iter()
                        .map(|r| lower(r, context, next, leaves, atomic || is_atomic))
                        .collect::<Result<_, _>>()?;
                    Ok(if is_atomic {
                        Command::Atomic { id, commands }
                    } else {
                        Command::Sequence { id, commands }
                    })
                }
            }
        }
        let command = lower(
            self.resolved.request,
            self.context,
            &mut next,
            &mut leaves,
            false,
        )?;
        crate::syncml::validate_body(
            std::slice::from_ref(&command),
            true,
            &crate::CodecLimits::default(),
        )
        .map_err(|_| Error::Value)?;
        Ok(Compiled {
            command,
            objects: self.resolved.objects.clone(),
        })
    }
}
fn effect(leaves: &[Leaf], context: Context) -> Result<EffectPlan, Error> {
    let (mut operations, mut expected) = (BTreeMap::new(), BTreeMap::new());
    for leaf in leaves {
        if leaf.operation == Verb::Get {
            continue;
        }
        if leaf.operation == Verb::Exec {
            return Ok(EffectPlan::Unverifiable(
                "operation_requires_family_effect_evidence",
            ));
        }
        let op = leaf.compile(context)?;
        let (node, goal) = if let Some(document) = &leaf.document {
            (
                leaf.node.replacen("/Documents/", "/Results/", 1),
                Expected::Declared {
                    document: document.clone(),
                    operation: if leaf.operation == Verb::Delete {
                        "Delete"
                    } else if leaf.node.contains("/Inventory/") {
                        "Get"
                    } else {
                        "Set"
                    }
                    .into(),
                },
            )
        } else {
            let goal = if leaf.operation == Verb::Delete {
                if leaf.node.ends_with(
                    "/DeclaredConfiguration/ManagementServiceConfiguration/RefreshInterval",
                ) {
                    Expected::Value("240".into())
                } else if leaf.node.contains("/Policy/Config/")
                    || op.semantics().lifetime != "Dynamic"
                {
                    return Ok(EffectPlan::Unverifiable(
                        "delete_restores_default_without_frozen_detector",
                    ));
                } else {
                    Expected::Absent
                }
            } else {
                op.data
                    .as_ref()
                    .map(|v| Expected::Value(v.0.clone()))
                    .unwrap_or(Expected::Present)
            };
            (leaf.node.clone(), goal)
        };
        let query = match Operation::compile(&node, &leaf.instance, Verb::Get, None, context) {
            Ok(query) => query,
            Err(_) => return Ok(EffectPlan::Unverifiable("native_object_is_not_queryable")),
        };
        expected.insert(query.uri().to_owned(), goal);
        operations.insert(
            query.uri().to_owned(),
            Request::Node {
                node,
                instance: leaf.instance.clone(),
                operation: Verb::Get,
                value: None,
            },
        );
    }
    if operations.is_empty() {
        return Ok(EffectPlan::ReadOnly);
    }
    let mut operations = operations.into_values().collect::<Vec<_>>();
    let request = if operations.len() == 1 {
        operations.remove(0)
    } else {
        Request::Sequence { operations }
    };
    Ok(EffectPlan::Readback(Verification { request, expected }))
}
