//! The sole backend defaults; persisted once and edited later through ordinary owners.
use super::*;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_inventory as d;
use rss_mdm_resource as r;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub const RETENTION: &str = "baseline_performance";
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Group {
        selector: rss_mdm_group_postgres::SystemSelector,
        name: String,
    },
    Scope {
        group: Uuid,
    },
    Resource {
        expected: u64,
        input: Value,
    },
    Upload {
        version: String,
        reference: String,
        platform: r::Platform,
        architecture: r::Architecture,
        bytes: Vec<u8>,
    },
    Field {
        definition: d::FieldDefinition,
    },
    Retention {
        policy: d::RetentionPolicy,
    },
    Policy {
        definition: rss_mdm_policy::Definition,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub key: String,
    pub target: String,
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u8,
    pub steps: Vec<Step>,
}
impl Manifest {
    pub fn targets(&self) -> BTreeSet<String> {
        self.steps.iter().map(|s| s.target.clone()).collect()
    }
}
pub fn id(tenant: Uuid, key: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut bytes = Sha256::digest(
        [
            tenant.as_bytes().as_slice(),
            b":baseline-v1:",
            key.as_bytes(),
        ]
        .concat(),
    );
    bytes[6] = (bytes[6] & 15) | 0x50;
    bytes[8] = (bytes[8] & 63) | 0x80;
    Uuid::from_bytes(bytes[..16].try_into().expect("digest prefix"))
}
fn step(steps: &mut Vec<Step>, key: impl Into<String>, target: impl ToString, action: Action) {
    steps.push(Step {
        key: key.into(),
        target: target.to_string(),
        action,
    });
}
fn resource(
    steps: &mut Vec<Step>,
    key: &str,
    target: Uuid,
    kind: &str,
    platform: r::Platform,
    definition: Value,
    bytes: Vec<u8>,
) {
    step(
        steps,
        format!("{key}:create"),
        target,
        Action::Resource {
            expected: 0,
            input: json!({"action":"create","kind":kind}),
        },
    );
    step(
        steps,
        format!("{key}:version"),
        target,
        Action::Resource {
            expected: 1,
            input: json!({"action":"version","version":"v1","kind":kind,"variants":[
                {"platform":platform,"architecture":"x86_64","key":"x86_64","declaration":{"kind":kind,"artifact":{"reference":"definition.json","length":bytes.len(),"sha256":r::Digest::of(&bytes).bytes()},"definition":definition}},
                {"platform":platform,"architecture":"aarch64","key":"aarch64","declaration":{"kind":kind,"artifact":{"reference":"definition.json","length":bytes.len(),"sha256":r::Digest::of(&bytes).bytes()},"definition":definition}}
            ]}),
        },
    );
    step(
        steps,
        format!("{key}:content"),
        target,
        Action::Upload {
            version: "v1".into(),
            reference: "definition.json".into(),
            platform,
            architecture: r::Architecture::X86_64,
            bytes,
        },
    );
    step(
        steps,
        format!("{key}:activate"),
        target,
        Action::Resource {
            expected: 2,
            input: json!({"action":"activate","version":"v1"}),
        },
    );
}
pub fn build(tenant: Uuid) -> Result<Manifest, Error> {
    let mut steps = Vec::new();
    use rss_mdm_group_postgres::SystemSelector as S;
    for (selector, name) in [
        (S::AllActive, "所有受管设备"),
        (S::Windows, "Windows 受管设备"),
        (S::Macos, "macOS 受管设备"),
    ] {
        let group = id(tenant, &format!("group:{}", selector.as_str()));
        step(
            &mut steps,
            format!("group:{}", selector.as_str()),
            group,
            Action::Group {
                selector,
                name: name.into(),
            },
        );
        if selector != S::AllActive {
            step(
                &mut steps,
                format!("scope:{}", selector.as_str()),
                id(tenant, &format!("scope:{}", selector.as_str())),
                Action::Scope { group },
            );
        }
    }
    for b in r::blueprints::catalog().into_iter().filter(|b| {
        matches!(
            b.presentation.get("category").and_then(Value::as_str),
            Some("identity" | "hardware" | "software")
        )
    }) {
        if !matches!(
            b.definition,
            r::blueprints::Definition::AgentCollection { .. }
                | r::blueprints::Definition::NativeCollection { .. }
        ) {
            continue;
        }
        let target = id(tenant, &format!("resource:{}", b.id));
        step(
            &mut steps,
            format!("{}:instantiate", b.id),
            target,
            Action::Resource {
                expected: 0,
                input: json!({"action":"instantiate","blueprint":b.id,"version":b.version}),
            },
        );
        step(
            &mut steps,
            format!("{}:content", b.id),
            target,
            Action::Upload {
                version: b.label(),
                reference: b.definition.reference().into(),
                platform: b.platform,
                architecture: r::Architecture::X86_64,
                bytes: b.definition.canonical(),
            },
        );
        step(
            &mut steps,
            format!("{}:activate", b.id),
            target,
            Action::Resource {
                expected: 2,
                input: json!({"action":"activate","version":b.label()}),
            },
        );
        let platform = match b.platform {
            r::Platform::Windows => "windows",
            r::Platform::MacOS => "macos",
        };
        let kind = match b.definition {
            r::blueprints::Definition::AgentCollection { .. } => "agent_collection",
            _ => "native_collection",
        };
        for architecture in ["x86_64", "aarch64"] {
            let key = format!("{}:policy:{architecture}", b.id);
            let definition=serde_json::from_value(json!({"scope":id(tenant,&format!("scope:{platform}")),"action":{"kind":kind,"resource":{"id":target,"version":b.label(),"platform":platform,"architecture":architecture,"variant":architecture},"runLifetimeSeconds":3600}})).map_err(|_|Error::Malformed)?;
            step(
                &mut steps,
                &key,
                id(tenant, &key),
                Action::Policy { definition },
            );
        }
    }
    step(
        &mut steps,
        "performance:retention",
        RETENTION,
        Action::Retention {
            policy: d::RetentionPolicy {
                key: RETENTION.into(),
                revision: 1,
                raw_seconds: 7 * 86400,
                summary_seconds: 30 * 86400,
                restore_seconds: 86400,
            },
        },
    );
    let fields = fields()?;
    for definition in &fields {
        step(
            &mut steps,
            format!("field:{}", definition.key.as_str()),
            definition.key.as_str(),
            Action::Field {
                definition: definition.clone(),
            },
        );
    }
    for platform in [r::Platform::Windows, r::Platform::MacOS] {
        let label = if platform == r::Platform::Windows {
            "windows"
        } else {
            "macos"
        };
        // Scalar fields expand to 3 resources; the two 64-filesystem fields
        // expand to 128. Each ordinary Profile keeps the requested 128-resource budget.
        for (section, fields) in [("device", &fields[..3]), ("filesystems", &fields[3..])] {
            let template = performance(platform, fields)?;
            let template_id = id(tenant, &format!("performance:{label}:{section}"));
            resource(
                &mut steps,
                &format!("performance:{label}:{section}"),
                template_id,
                "agent_collection",
                platform,
                serde_json::to_value(&template).map_err(|_| Error::Malformed)?,
                template.canonical(),
            );
            for (arch, architecture) in [
                ("x86_64", r::Architecture::X86_64),
                ("aarch64", r::Architecture::Aarch64),
            ] {
                let key = format!("profile:{label}:{section}:{arch}");
                let target = id(tenant, &key);
                let profile = r::TelemetryProfile::new(r::TelemetryProfileSpec {
                    template: r::TelemetryTemplate {
                        resource: template_id.to_string(),
                        version: "v1".into(),
                        variant: arch.into(),
                        platform,
                        architecture,
                    },
                    parameters: BTreeMap::new(),
                    fields: fields
                        .iter()
                        .map(|f| r::TelemetryFieldReference {
                            key: f.key.as_str().to_owned(),
                            version: 1,
                        })
                        .collect(),
                    projection: r::TelemetryProjection::Both,
                    sample_millis: 60000,
                    upload_millis: 300000,
                    budget: r::TelemetryBudget {
                        points: 4096,
                        bytes: 1048576,
                        resources: 128,
                        execution_millis: 10000,
                        output_bytes: 262144,
                    },
                    boost: None,
                    backfill_seconds: 86400,
                })
                .map_err(|_| Error::Malformed)?;
                // A profile's exact template target must match its enclosing variant.
                let bytes = profile.canonical();
                step(
                    &mut steps,
                    format!("{key}:create"),
                    target,
                    Action::Resource {
                        expected: 0,
                        input: json!({"action":"create","kind":"telemetry_profile"}),
                    },
                );
                step(
                    &mut steps,
                    format!("{key}:version"),
                    target,
                    Action::Resource {
                        expected: 1,
                        input: json!({"action":"version","version":"v1","kind":"telemetry_profile","variants":[{"platform":platform,"architecture":architecture,"key":arch,"declaration":{"kind":"telemetry_profile","artifact":{"reference":"definition.json","length":bytes.len(),"sha256":r::Digest::of(&bytes).bytes()},"definition":profile}}]}),
                    },
                );
                step(
                    &mut steps,
                    format!("{key}:content"),
                    target,
                    Action::Upload {
                        version: "v1".into(),
                        reference: "definition.json".into(),
                        platform,
                        architecture,
                        bytes,
                    },
                );
                step(
                    &mut steps,
                    format!("{key}:activate"),
                    target,
                    Action::Resource {
                        expected: 2,
                        input: json!({"action":"activate","version":"v1"}),
                    },
                );
                let definition=serde_json::from_value(json!({"scope":id(tenant,&format!("scope:{label}")),"action":{"kind":"telemetry_profile","resource":{"id":target,"version":"v1","platform":platform,"architecture":architecture,"variant":arch}}})).map_err(|_|Error::Malformed)?;
                let policy_key = format!("{key}:policy");
                step(
                    &mut steps,
                    &policy_key,
                    id(tenant, &policy_key),
                    Action::Policy { definition },
                );
            }
        }
    }
    if steps.is_empty() || steps.len() > 512 {
        return Err(Error::Malformed);
    }
    Ok(Manifest { version: 1, steps })
}
fn fields() -> Result<Vec<d::FieldDefinition>, Error> {
    let mut fields = Vec::new();
    for (key, array, percent) in [
        ("cpu_busy_percent", false, true),
        ("memory_total_bytes", false, false),
        ("memory_available_bytes", false, false),
        ("filesystem_total_bytes", true, false),
        ("filesystem_free_bytes", true, false),
    ] {
        let value = if percent {
            d::ValueType::Number
        } else {
            d::ValueType::Integer
        };
        let value_type = if array {
            d::ValueType::Array {
                items: Box::new(d::ValueType::Object {
                    properties: [
                        (
                            "id".into(),
                            d::ValueType::String {
                                max_length: 1024,
                                allow_empty: false,
                            },
                        ),
                        ("value".into(), value),
                    ]
                    .into(),
                }),
                max_items: 64,
            }
        } else {
            value
        };
        let field = d::FieldDefinition {
            key: d::FieldKey::parse(&format!("custom.baseline.{key}"))
                .map_err(|_| Error::Malformed)?,
            version: 1,
            value_type,
            nullable: false,
            manual: false,
            sources: [(d::Source::AgentNative, 0)].into(),
            platforms: [d::Platform::Windows, d::Platform::Macos].into(),
            sensitivity: d::Sensitivity::Standard,
            unit: Some(if percent { "percent" } else { "bytes" }.into()),
            searchable: false,
            item_key: array.then(|| "id".into()),
            time_series: Some(d::TimeSeriesBinding {
                kind: d::TelemetryKind::Gauge,
                value_path: if array { vec!["value".into()] } else { vec![] },
                interval_start_path: None,
                dimensions: BTreeMap::new(),
                aggregations: [
                    d::TelemetryAggregation::Mean,
                    d::TelemetryAggregation::Min,
                    d::TelemetryAggregation::Max,
                ]
                .into(),
                retention: d::RetentionReference {
                    key: RETENTION.into(),
                    revision: 1,
                },
                max_resources: if array { 64 } else { 1 },
            }),
        };
        field.validate().map_err(|_| Error::Malformed)?;
        fields.push(field);
    }
    Ok(fields)
}
fn performance(
    platform: r::Platform,
    fields: &[d::FieldDefinition],
) -> Result<r::AgentCollectionDefinition, Error> {
    let device = fields.iter().any(|f| f.item_key.is_none());
    let filesystem = fields.iter().any(|f| f.item_key.is_some());
    let budget = w::NativeBudget {
        timeout_seconds: 10,
        output_bytes: 262144,
        max_rows: (if device { 2 } else { 0 }) + (if filesystem { 64 } else { 0 }),
    };
    let queries = [
        ("cpu", w::PerformanceSection::Cpu),
        ("memory", w::PerformanceSection::Memory),
        ("filesystems", w::PerformanceSection::FileSystems),
    ]
    .into_iter()
    .filter(|(name, _)| {
        if *name == "filesystems" {
            filesystem
        } else {
            device
        }
    })
    .map(|(name, section)| {
        (
            name.into(),
            w::NativeQuery {
                version: 1,
                definition: if platform == r::Platform::Windows {
                    w::NativeQueryDefinition::WindowsPerformance { section }
                } else {
                    w::NativeQueryDefinition::MacosPerformance { section }
                },
                cardinality: if name == "filesystems" {
                    w::NativeCardinality::List
                } else {
                    w::NativeCardinality::ExactlyOne
                },
                instance_keys: if name == "filesystems" {
                    vec!["id".into()]
                } else {
                    vec![]
                },
                budget: w::NativeBudget {
                    max_rows: if name == "filesystems" { 64 } else { 1 },
                    ..budget
                },
            },
        )
    })
    .collect();
    let plan = w::NativeCollectionPlan::new(w::NativePlanSpec {
        version: 1,
        scope: rss_mdm_agent_wire::CollectionScope::Device,
        queries,
        budget,
    })
    .map_err(|_| Error::Malformed)?;
    let mappings = fields
        .iter()
        .map(performance_mapping)
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
        applicability: Default::default(),
        plan,
        mappings,
    })
    .map_err(|_| Error::Malformed)
}

fn performance_mapping(
    f: &d::FieldDefinition,
) -> Result<(String, rss_mdm_agent_wire::runtime::AgentCollectionMapping), Error> {
    let (query, path) = match f.key.as_str() {
        "custom.baseline.cpu_busy_percent" => ("cpu", "/busy_percent"),
        "custom.baseline.memory_total_bytes" => ("memory", "/total_bytes"),
        "custom.baseline.memory_available_bytes" => ("memory", "/available_bytes"),
        "custom.baseline.filesystem_total_bytes" => ("filesystems", "/total_bytes"),
        "custom.baseline.filesystem_free_bytes" => ("filesystems", "/free_bytes"),
        _ => return Err(Error::Malformed),
    };
    let array = f.item_key.is_some();
    let scalar = rss_mdm_agent_wire::runtime::ValueMapping {
        pointer: path.into(),
        conversion: if query == "cpu" {
            rss_mdm_agent_wire::runtime::Conversion::Identity
        } else {
            rss_mdm_agent_wire::runtime::Conversion::Integer
        },
        columns: BTreeMap::new(),
    };
    let mapping = if array {
        rss_mdm_agent_wire::runtime::ValueMapping {
            pointer: String::new(),
            conversion: rss_mdm_agent_wire::runtime::Conversion::Identity,
            columns: [
                (
                    "id".into(),
                    rss_mdm_agent_wire::runtime::ValueMapping {
                        pointer: "/id".into(),
                        conversion: rss_mdm_agent_wire::runtime::Conversion::Identity,
                        columns: BTreeMap::new(),
                    },
                ),
                ("value".into(), scalar),
            ]
            .into(),
        }
    } else {
        scalar
    };
    Ok((
        f.key.as_str().to_owned(),
        rss_mdm_agent_wire::runtime::AgentCollectionMapping {
            query: query.into(),
            mapping,
            missing: rss_mdm_agent_wire::runtime::NativeMissing::Missing,
            counter_normalization: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn performance_accepts_64_filesystems_and_rejects_65() {
        for platform in [r::Platform::Windows, r::Platform::MacOS] {
            let template = performance(platform, &fields().unwrap()).unwrap();
            let plan = &template.spec().plan;
            let queries = plan
                .spec()
                .queries
                .iter()
                .map(|(key, q)| {
                    let rows = match key.as_str() {
                        "cpu" => vec![BTreeMap::from([("busy_percent".into(), json!(20))])],
                        "memory" => vec![BTreeMap::from([
                            ("total_bytes".into(), json!("1000")),
                            ("available_bytes".into(), json!("500")),
                        ])],
                        _ => (0..64)
                            .map(|i| {
                                BTreeMap::from([
                                    ("id".into(), json!(format!("volume-{i}"))),
                                    ("total_bytes".into(), json!("1000")),
                                    ("free_bytes".into(), json!("500")),
                                ])
                            })
                            .collect(),
                    };
                    (
                        key.clone(),
                        w::NativeQueryResult {
                            scan: None,
                            query_digest: q.digest(),
                            collected_at: 1,
                            status: w::NativeQueryStatus::Complete,
                            enumeration_complete: true,
                            row_count: rows.len() as u32,
                            rows,
                            users: None,
                        },
                    )
                })
                .collect();
            let mut result = w::NativeCollectionResult {
                plan_digest: plan.digest(),
                collected_at: 1,
                queries,
            };
            assert!(result.validate_for(plan, 1).is_ok());
            assert!(
                result
                    .queries
                    .iter()
                    .all(|(key, r)| r.complete_for(&plan.spec().queries[key], 1))
            );
            let fs = result.queries.get_mut("filesystems").unwrap();
            fs.rows.push(BTreeMap::from([
                ("id".into(), json!("volume-65")),
                ("total_bytes".into(), json!("1000")),
                ("free_bytes".into(), json!("500")),
            ]));
            fs.row_count += 1;
            assert!(!fs.complete_for(&plan.spec().queries["filesystems"], 1));
            assert!(result.validate_for(plan, 1).is_err());
        }
    }
    #[test]
    fn frozen_baseline_has_unique_operations_and_exact_current_contracts() {
        let tenant = Uuid::from_u128(2863);
        let a = build(tenant).expect("valid current baseline");
        let b = build(tenant).expect("stable baseline");
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::to_value(&b).unwrap()
        );
        assert!(a.steps.len() < 512 && a.targets().len() < 512);
        let keys: BTreeSet<_> = a.steps.iter().map(|s| &s.key).collect();
        assert_eq!(keys.len(), a.steps.len());
        assert_ne!(
            id(tenant, "group:windows"),
            id(Uuid::from_u128(2864), "group:windows")
        );
        assert_eq!(
            a.steps
                .iter()
                .filter(|s| matches!(s.action, Action::Group { .. }))
                .count(),
            3
        );
        assert_eq!(
            a.steps
                .iter()
                .filter(|s| matches!(s.action, Action::Scope { .. }))
                .count(),
            2
        );
        assert_eq!(
            a.steps
                .iter()
                .filter(|s| matches!(s.action, Action::Field { .. }))
                .count(),
            5
        );
        assert_current_resources(&a);
    }
    fn assert_current_resources(a: &Manifest) {
        let mut profiles = 0;
        let mut blueprints = 0;
        for step in &a.steps {
            match &step.action {
                Action::Policy { definition } => match &definition.action {
                    rss_mdm_policy::Action::AgentCollection {
                        schedule,
                        frequency,
                        ..
                    }
                    | rss_mdm_policy::Action::NativeCollection {
                        schedule,
                        frequency,
                        ..
                    } => {
                        assert!(matches!(frequency, rss_mdm_policy::Frequency::EveryTrigger));
                        assert!(matches!(
                            schedule.trigger,
                            rss_mdm_policy::schedule::Trigger::Interval {
                                anchor: 0,
                                seconds: 3600
                            }
                        ));
                    }
                    _ => (),
                },
                Action::Resource { input, .. } => {
                    let _: rss_mdm_flow_service::resource_catalog::Change =
                        serde_json::from_value(input.clone()).expect("ordinary Resource contract");
                    if input["action"] == "instantiate" {
                        blueprints += 1;
                    }
                }
                Action::Upload { bytes, .. } if step.key.starts_with("profile:") => {
                    let value: Value = serde_json::from_slice(bytes).unwrap();
                    assert_eq!(value["sampleMillis"], 60000);
                    assert_eq!(value["uploadMillis"], 300000);
                    assert_eq!(value["projection"], "both");
                    assert_eq!(value["budget"]["points"], 4096);
                    assert_eq!(value["backfillSeconds"], 86400);
                    let field_definitions = fields().unwrap();
                    let expanded: u32 = value["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|f| {
                            field_definitions
                                .iter()
                                .find(|d| d.key.as_str() == f["key"].as_str().unwrap())
                                .unwrap()
                                .time_series
                                .as_ref()
                                .unwrap()
                                .max_resources
                        })
                        .sum();
                    assert!(expanded <= 128);
                    profiles += 1;
                }
                _ => {}
            }
        }
        assert!(blueprints >= 6);
        assert_eq!(profiles, 8);
    }
}
