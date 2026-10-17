//! Native template runs share CollectionRun, field quality and immutable result delivery.
use crate::{Error, database::db};
use rss_mdm_inventory::{
    CollectedValue, CollectionDefinition, CollectionProgress, FieldKey, NativeValue, ValueType,
};
use rss_mdm_resource::{NativeAdapter, NativeCollectionDefinition};
use sqlx::PgConnection;
use uuid::Uuid;
pub struct Target {
    pub tenant: rss_request_context::TenantId,
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
pub async fn start(
    c: &mut PgConnection,
    p: &Target,
    id: Uuid,
    definition: CollectionDefinition,
    template: NativeCollectionDefinition,
    deadline: i64,
) -> Result<(), Error> {
    let source = match template.spec().adapter {
        NativeAdapter::WindowsRead => rss_mdm_inventory::ReportSource::MdmWindows,
        NativeAdapter::AppleDeviceInformation
        | NativeAdapter::AppleInstalledApplications
        | NativeAdapter::AppleSecurity
        | NativeAdapter::AppleProfiles
        | NativeAdapter::AppleCertificates
        | NativeAdapter::AppleUsers => rss_mdm_inventory::ReportSource::MdmApple,
    };
    let target =
        crate::device::store::allocate_collection_in(c, &p.tenant.to_string(), &p.device, source)
            .await
            .map_err(|error| {
                #[cfg(feature = "integration")]
                eprintln!("native source allocation: {error:?}");
                Error::from(error)
            })?;
    if target.registration != p.registration || target.generation != p.generation {
        return Err(Error::Conflict);
    }
    let template_scope = match &template.spec().scope {
        rss_mdm_resource::TemplateScope::Device => rss_mdm_inventory::CollectionScope::Device,
        rss_mdm_resource::TemplateScope::User { identity } => {
            rss_mdm_inventory::CollectionScope::AppleUser {
                identity: identity.clone(),
            }
        }
        _ => return Err(Error::Malformed),
    };
    if definition
        .bindings()
        .iter()
        .any(|f| f.scope != template_scope)
    {
        return Err(Error::Malformed);
    }
    if let rss_mdm_inventory::CollectionScope::AppleUser { identity } = &template_scope {
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND state='active')")
            .bind(p.tenant.to_string()).bind(p.registration).bind(p.generation).bind(identity)
            .fetch_one(&mut *c).await.map_err(db)?;
        if !active {
            return Err(Error::Conflict);
        }
    }
    let scope = crate::device::scope_dataset(
        p.tenant,
        p.registration,
        source.as_str(),
        target.epoch,
        definition.dataset(),
    )?;
    definition
        .validate_scope(&scope)
        .map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::register_collection_in(c, p.tenant, &definition)
        .await
        .map_err(|_| Error::Malformed)?;
    let progress = CollectionProgress::new(definition);
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,deadline,evidence) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint,$8,'pending',to_timestamp($9),$10)")
        .bind(p.tenant.to_string()).bind(id).bind(p.registration).bind(source.as_str()).bind(target.epoch).bind(scope.encode().map_err(|_|Error::Malformed)?).bind(target.sequence)
        .bind(serde_json::to_string(&progress).map_err(|_|Error::Malformed)?).bind(deadline as f64).bind(serde_json::json!({"nativeTemplate":template})).execute(&mut *c).await.map_err(db)?;
    crate::wake::notify(c).await.map_err(db)?;
    Ok(())
}
pub async fn template(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Option<NativeCollectionDefinition>, Error> {
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT evidence->'nativeTemplate' FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await.map_err(db)?;
    value
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Malformed))
        .transpose()
}
/// Validate projected columns and converted scalar types before publishing a template.
pub fn validate_mapping(
    field: &rss_mdm_inventory::FieldDefinition,
    mapping: &rss_mdm_resource::ValueMapping,
) -> Result<(), Error> {
    fn check(ty: &ValueType, mapping: &rss_mdm_resource::ValueMapping) -> Result<(), Error> {
        use rss_mdm_resource::Conversion;
        if !mapping.columns.is_empty() {
            let ValueType::Object { properties } = ty else {
                return Err(Error::Malformed);
            };
            if mapping.columns.keys().ne(properties.keys()) {
                return Err(Error::Malformed);
            }
            for (name, column) in &mapping.columns {
                check(&properties[name], column)?;
            }
        } else {
            let valid = match &mapping.conversion {
                Conversion::Identity => true,
                Conversion::ArrayMember {
                    present, absent, ..
                } => ty.decode_json(present).is_ok() && ty.decode_json(absent).is_ok(),
                Conversion::CimTime => matches!(ty, ValueType::Time),
                Conversion::Integer | Conversion::Scale { .. } => {
                    matches!(ty, ValueType::Integer | ValueType::Time)
                }
                Conversion::Number => matches!(ty, ValueType::Number),
                Conversion::Enum { values } => values.values().all(|v| ty.decode_json(v).is_ok()),
                Conversion::Bitmask { flags } => ty
                    .decode_json(&serde_json::json!(flags.values().collect::<Vec<_>>()))
                    .is_ok(),
            };
            if !valid {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    mapping.validate().map_err(|_| Error::Malformed)?;
    let target = match (&field.value_type, &mapping.conversion) {
        (ValueType::Array { items, .. }, conversion)
            if !matches!(conversion, rss_mdm_resource::Conversion::Bitmask { .. }) =>
        {
            items.as_ref()
        }
        (ty, _) => ty,
    };
    check(target, mapping)
}
/// Shared mapping boundary for native, SQL and script output. Missing data is never a tombstone.
pub fn mapped_value(
    field: &rss_mdm_inventory::FieldDefinition,
    mapping: &rss_mdm_resource::ValueMapping,
    raw: &serde_json::Value,
) -> NativeValue {
    let Some(raw) = raw.pointer(&mapping.pointer) else {
        return NativeValue::Missing;
    };
    if let (ValueType::Array { items, .. }, serde_json::Value::Array(rows)) =
        (&field.value_type, raw)
        && !matches!(
            mapping.conversion,
            rss_mdm_resource::Conversion::Bitmask { .. }
        )
    {
        return NativeValue::list(
            field,
            rows.iter()
                .map(|row| {
                    let value = mapping
                        .project(row)
                        .map_err(|_| rss_mdm_inventory::Invalid::Value)?;
                    items.decode_json(&value)
                })
                .collect(),
        )
        .unwrap_or(NativeValue::Invalid);
    }
    let Ok(projected) = mapping.project(raw) else {
        return NativeValue::Invalid;
    };
    if projected.is_null() && field.nullable {
        return NativeValue::Value(CollectedValue::Null);
    }
    match field
        .value_type
        .decode_json(&projected)
        .and_then(|v| field.canonical_value(v))
    {
        Ok(v) => NativeValue::Value(CollectedValue::Value(v)),
        Err(_) => NativeValue::Invalid,
    }
}
pub fn value(
    field: &rss_mdm_inventory::FieldDefinition,
    mapping: &rss_mdm_resource::NativeMapping,
    raw: &serde_json::Value,
) -> NativeValue {
    let parsed = if (!mapping.mapping.pointer.is_empty() || !mapping.mapping.columns.is_empty())
        && raw.is_string()
    {
        serde_json::from_str(raw.as_str().expect("checked string")).ok()
    } else {
        None
    };
    mapped_value(field, &mapping.mapping, parsed.as_ref().unwrap_or(raw))
}

pub fn result(
    template: &NativeCollectionDefinition,
    definition: CollectionDefinition,
    values: &serde_json::Value,
    now: i64,
    success: bool,
) -> Result<CollectionProgress, Error> {
    result_with_unsupported(
        template,
        definition,
        values,
        now,
        success,
        &Default::default(),
    )
}
/// Unavailable native fields retain explicit Unsupported quality, separate from missing replies.
pub fn result_with_unsupported(
    template: &NativeCollectionDefinition,
    definition: CollectionDefinition,
    values: &serde_json::Value,
    now: i64,
    success: bool,
    unsupported: &std::collections::BTreeSet<FieldKey>,
) -> Result<CollectionProgress, Error> {
    let values = template
        .spec()
        .mappings
        .iter()
        .map(|(key, mapping)| {
            let key = FieldKey::parse(key).map_err(|_| Error::Malformed)?;
            let field = definition.field(key).map_err(|_| Error::Malformed)?;
            let query = mapping.query.apple_key().ok_or(Error::Malformed)?;
            let raw = if query.is_empty() {
                Some(values)
            } else {
                values.get(query)
            };
            Ok((
                key,
                if unsupported.contains(&key) {
                    NativeValue::Value(CollectedValue::Unsupported)
                } else if !success {
                    NativeValue::Failed
                } else {
                    raw.map_or(NativeValue::Missing, |v| value(field, mapping, v))
                },
            ))
        })
        .collect::<Result<_, Error>>()?;
    CollectionProgress::native(definition, values, now).map_err(|_| Error::Malformed)
}

/// Validate native query source types against the unique Inventory field definition.
pub fn validate_agent_mapping(
    field: &rss_mdm_inventory::FieldDefinition,
    definition: &rss_mdm_resource::AgentCollectionDefinition,
    binding: &rss_mdm_resource::AgentCollectionMapping,
) -> Result<(), Error> {
    use rss_mdm_agent_wire::runtime::{NativeCardinality, NativeType as N};
    use rss_mdm_resource::{Conversion as C, NativeMissing};
    validate_mapping(field, &binding.mapping)?;
    let query = &definition.spec().plan.spec().queries[&binding.query];
    if !system_field_matches(field.key.as_str(), &query.definition) {
        return Err(Error::Malformed);
    }
    if binding.missing == NativeMissing::Null && !field.nullable {
        return Err(Error::Malformed);
    }
    let query = &definition.spec().plan.spec().queries[&binding.query];
    // Standard installations require a closed installation recipe. Its exact namespace
    // is frozen per field before the Offer, independently of the execution identity.
    if field.key.as_str() == "device.software.installations"
        && !matches!(
            query.definition,
            rss_mdm_agent_wire::runtime::NativeQueryDefinition::WindowsSoftware
                | rss_mdm_agent_wire::runtime::NativeQueryDefinition::MacosApplications { .. }
        )
    {
        return Err(Error::Malformed);
    }
    if (field.key.as_str() == "device.software.receipts"
        && !matches!(
            query.definition,
            rss_mdm_agent_wire::runtime::NativeQueryDefinition::MacosPkgReceipts { .. }
        ))
        || (field.key.as_str() == "device.software.packages"
            && !matches!(
                query.definition,
                rss_mdm_agent_wire::runtime::NativeQueryDefinition::MacosBrew { .. }
            ))
    {
        return Err(Error::Malformed);
    }
    let props = query.definition.properties();
    fn identity(n: &N, t: &ValueType) -> bool {
        match (n, t) {
            (
                N::String | N::UInt64 | N::CimTime,
                ValueType::String { .. } | ValueType::Enum { .. },
            ) => true,
            (N::Integer, ValueType::Integer)
            | (N::Number, ValueType::Number)
            | (N::Boolean, ValueType::Boolean) => true,
            (N::Array { items: a }, ValueType::Array { items: b, .. }) => identity(a, b),
            _ => false,
        }
    }
    fn mapped(
        p: &std::collections::BTreeMap<String, N>,
        m: &rss_mdm_resource::ValueMapping,
        t: &ValueType,
    ) -> bool {
        if !m.columns.is_empty() {
            return match t {
                ValueType::Object { properties } => m
                    .columns
                    .iter()
                    .all(|(k, v)| properties.get(k).is_some_and(|t| mapped(p, v, t))),
                _ => false,
            };
        }
        let Some(n) = m.pointer.strip_prefix('/').and_then(|k| p.get(k)) else {
            return false;
        };
        match &m.conversion {
            C::Identity => identity(n, t),
            C::CimTime => matches!(n, N::CimTime) && matches!(t, ValueType::Time),
            C::Integer | C::Scale { .. } => matches!(t, ValueType::Integer | ValueType::Time),
            C::Number => matches!(t, ValueType::Number),
            C::Enum { values } => values.values().all(|v| t.decode_json(v).is_ok()),
            C::ArrayMember {
                present, absent, ..
            } => {
                matches!(n,N::Array {items} if **items==N::Integer)
                    && t.decode_json(present).is_ok()
                    && t.decode_json(absent).is_ok()
            }
            C::Bitmask { flags } => t
                .decode_json(&serde_json::json!(flags.values().collect::<Vec<_>>()))
                .is_ok(),
        }
    }
    let ty = match (query.cardinality, &field.value_type) {
        (NativeCardinality::List, ValueType::Array { items, .. }) => items.as_ref(),
        (NativeCardinality::List, _) => return Err(Error::Malformed),
        (_, ty) => ty,
    };
    if !mapped(&props, &binding.mapping, ty) {
        return Err(Error::Malformed);
    }
    Ok(())
}

// Only the closed declared native source can assert full account/store/update evidence.
fn system_field_matches(
    field: &str,
    query: &rss_mdm_agent_wire::runtime::NativeQueryDefinition,
) -> bool {
    use rss_mdm_agent_wire::runtime::{
        AccountSection as A, MacosSecuritySection as M, NativeQueryDefinition as D,
        NativeSystemQuery as Q, UpdateSection as U,
    };
    let q = if let D::System { query } = query {
        Some(query)
    } else {
        None
    };
    match field {
        "device.certificates.metadata" => matches!(
            q,
            Some(Q::WindowsCertificates { .. } | Q::MacosCertificates { .. })
        ),
        "device.accounts.windows.identities" => matches!(
            q,
            Some(Q::WindowsAccounts {
                section: A::Accounts,
                ..
            })
        ),
        "device.accounts.macos.identities" => matches!(
            q,
            Some(Q::MacosAccounts {
                section: A::Accounts,
                ..
            })
        ),
        "device.accounts.administrators.direct" => matches!(
            q,
            Some(
                Q::WindowsAccounts {
                    section: A::Administrators,
                    ..
                } | Q::MacosAccounts {
                    section: A::Administrators,
                    ..
                }
            )
        ),
        "device.accounts.sessions" => matches!(
            q,
            Some(
                Q::WindowsAccounts {
                    section: A::Sessions,
                    ..
                } | Q::MacosAccounts {
                    section: A::Sessions,
                    ..
                }
            )
        ),
        "device.accounts.windows.join" => matches!(q, Some(Q::WindowsJoin)),
        "device.updates.available" => matches!(
            q,
            Some(
                Q::WindowsUpdates {
                    section: U::Available,
                    ..
                } | Q::MacosUpdates {
                    section: U::Available,
                    ..
                }
            )
        ),
        "device.updates.installed" => matches!(
            q,
            Some(
                Q::WindowsUpdates {
                    section: U::Installed,
                    ..
                } | Q::MacosUpdates {
                    section: U::Installed,
                    ..
                }
            )
        ),
        "device.updates.history" => matches!(
            q,
            Some(
                Q::WindowsUpdates {
                    section: U::History,
                    ..
                } | Q::MacosUpdates {
                    section: U::History,
                    ..
                }
            )
        ),
        "device.updates.scan" => matches!(
            q,
            Some(
                Q::WindowsUpdates {
                    section: U::Scan,
                    ..
                } | Q::MacosUpdates {
                    section: U::Scan,
                    ..
                }
            )
        ),
        "device.updates.reboot_observation" => matches!(
            q,
            Some(
                Q::WindowsUpdates {
                    section: U::Reboot,
                    ..
                } | Q::MacosUpdates {
                    section: U::Reboot,
                    ..
                }
            )
        ),
        "device.security.windows.bitlocker.volumes" => matches!(q, Some(Q::WindowsBitlocker)),
        "device.security.windows.firewall.profiles" => matches!(q, Some(Q::WindowsFirewall)),
        "device.security.windows.defender.observation" => matches!(q, Some(Q::WindowsDefender)),
        "device.security.windows.secure_boot" => matches!(q, Some(Q::WindowsSecureBoot)),
        "device.security.application.observation" => matches!(
            q,
            Some(Q::WindowsApplication { .. } | Q::MacosApplication { .. })
        ),
        "device.security.application.permissions" => matches!(q, Some(Q::MacosApplication { .. })),
        "device.security.macos.gatekeeper_observation" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::Gatekeeper
            })
        ),
        "device.security.macos.xprotect.observation" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::Xprotect
            })
        ),
        "device.security.macos.system_extensions" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::SystemExtensions
            })
        ),
        "device.security.macos.filevault" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::Filevault
            })
        ),
        "device.security.macos.firewall" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::Firewall
            })
        ),
        "device.security.macos.sip" => matches!(q, Some(Q::MacosSecurity { section: M::Sip })),
        "device.security.macos.hardware_encryption" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::HardwareEncryption
            })
        ),
        "device.security.macos.secure_token.local" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::SecureToken
            })
        ),
        "device.security.macos.bootstrap_token.local" => matches!(
            q,
            Some(Q::MacosSecurity {
                section: M::BootstrapToken
            })
        ),
        _ => true,
    }
}

#[cfg(test)]
mod mapping_tests {
    use super::*;
    use rss_mdm_inventory::{Scalar, builtin};
    use rss_mdm_resource::{Conversion, ValueMapping};
    use serde_json::json;

    #[test]
    fn windows_identity_and_software_blueprints_project_current_asset_semantics() {
        use rss_mdm_resource::blueprints;
        for name in ["windows.agent.identity", "windows.agent.software"] {
            assert!(blueprints::get(name, "1").is_none());
            let blueprints::Definition::AgentCollection { template } =
                blueprints::get(name, "2").unwrap().definition
            else {
                unreachable!()
            };
            for (key, binding) in &template.spec().mappings {
                let field = builtin::fields()
                    .into_iter()
                    .find(|f| f.key.as_str() == key)
                    .unwrap();
                validate_agent_mapping(&field, &template, binding).unwrap();
            }
            let cases = if name.ends_with("identity") {
                vec![
                    (
                        "device.os.edition",
                        json!({"EditionID":"Professional"}),
                        json!("Professional"),
                    ),
                    (
                        "device.architecture",
                        json!({"PROCESSOR_ARCHITECTURE":"AMD64"}),
                        json!("x86_64"),
                    ),
                    (
                        "device.architecture",
                        json!({"PROCESSOR_ARCHITECTURE":"ARM64"}),
                        json!("aarch64"),
                    ),
                    (
                        "device.serial_number",
                        json!({"SerialNumber":" ab-12 "}),
                        json!("AB-12"),
                    ),
                ]
            } else {
                vec![]
            };
            for (key, raw, expected) in cases {
                let field = builtin::fields()
                    .into_iter()
                    .find(|f| f.key.as_str() == key)
                    .unwrap();
                let NativeValue::Value(CollectedValue::Value(value)) =
                    mapped_value(&field, &template.spec().mappings[key].mapping, &raw)
                else {
                    panic!("{key}")
                };
                assert_eq!(value, field.value_type.decode_json(&expected).unwrap());
            }
            if name.ends_with("identity") {
                for (key, raw) in [
                    (
                        "device.serial_number",
                        json!({"SerialNumber":"To Be Filled By O.E.M."}),
                    ),
                    (
                        "device.hardware_uuid",
                        json!({"UUID":"00000000-0000-0000-0000-000000000000"}),
                    ),
                    (
                        "device.architecture",
                        json!({"PROCESSOR_ARCHITECTURE":"unknown"}),
                    ),
                ] {
                    let field = builtin::fields()
                        .into_iter()
                        .find(|f| f.key.as_str() == key)
                        .unwrap();
                    let mapping = &template.spec().mappings[key].mapping;
                    assert!(matches!(
                        mapped_value(&field, mapping, &raw),
                        NativeValue::Invalid
                    ));
                    assert!(matches!(
                        mapped_value(&field, mapping, &json!({})),
                        NativeValue::Missing
                    ));
                }
            } else {
                let field = builtin::fields()
                    .into_iter()
                    .find(|f| f.key.as_str() == "device.software.installations")
                    .unwrap();
                let mapping = &template.spec().mappings[field.key.as_str()].mapping;
                for (origin, state, scope, owner) in [
                    ("win32.uninstall.32", "installed", "device", ""),
                    ("win32.uninstall.64", "installed", "device", ""),
                    (
                        "msix.registered",
                        "registered",
                        "user",
                        "S-1-5-21-1-2-3-1001",
                    ),
                    ("msix.provisioned", "provisioned", "device", ""),
                ] {
                    let row = json!({"id":origin,"native_id":"same","name":"App","version":"1","publisher":"V","scope":scope,"owner":owner,"origin":origin,"location":""});
                    let NativeValue::Value(CollectedValue::Value(Scalar::Array(rows))) =
                        mapped_value(&field, mapping, &json!([row]))
                    else {
                        panic!("{origin}")
                    };
                    let Scalar::Object(row) = &rows[0] else {
                        unreachable!()
                    };
                    assert_eq!(row["installation_state"], Scalar::String(state.into()));
                }
            }
        }
    }

    #[test]
    fn native_conversion_checks_whole_target_shape_and_preserves_bitmask_arrays() {
        use rss_mdm_agent_wire::runtime as w;
        use rss_mdm_resource::{AgentCollectionDefinition, blueprints};
        let blueprint = blueprints::get("windows.agent.memory", "1").unwrap();
        let blueprints::Definition::AgentCollection { template } = blueprint.definition else {
            panic!("native memory template");
        };
        let mut spec = template.spec().clone();
        let binding = spec.mappings.values_mut().next().unwrap();
        binding.mapping.conversion = Conversion::Integer;
        let mut field = builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == "device.memory.bytes")
            .unwrap();
        field.value_type = ValueType::Array {
            items: Box::new(ValueType::Integer),
            max_items: 10,
        };
        let definition = AgentCollectionDefinition::new(spec.clone()).unwrap();
        let binding = definition.spec().mappings.values().next().unwrap();
        assert!(validate_agent_mapping(&field, &definition, binding).is_err());
        field.value_type = ValueType::Integer;
        validate_agent_mapping(&field, &definition, binding).unwrap();
        assert!(matches!(
            mapped_value(
                &field,
                &binding.mapping,
                &json!({"TotalPhysicalMemory":"12"})
            ),
            NativeValue::Value(CollectedValue::Value(Scalar::Integer(12)))
        ));

        let mut plan = spec.plan.spec().clone();
        let query = plan.queries.values_mut().next().unwrap();
        let w::NativeQueryDefinition::WindowsWmi { properties, .. } = &mut query.definition else {
            panic!("WMI");
        };
        properties.get_mut("TotalPhysicalMemory").unwrap().cim_type = w::CimType::Sint32;
        spec.plan = w::NativeCollectionPlan::new(plan).unwrap();
        spec.mappings
            .values_mut()
            .next()
            .unwrap()
            .mapping
            .conversion = Conversion::Bitmask {
            flags: [("1".into(), "enabled".into())].into(),
        };
        field.value_type = ValueType::Array {
            items: Box::new(ValueType::Enum {
                values: ["enabled".into()].into(),
            }),
            max_items: 10,
        };
        let definition = AgentCollectionDefinition::new(spec).unwrap();
        let binding = definition.spec().mappings.values().next().unwrap();
        validate_agent_mapping(&field, &definition, binding).unwrap();
        assert!(
            matches!(mapped_value(&field, &binding.mapping, &json!({"TotalPhysicalMemory":1})), NativeValue::Value(CollectedValue::Value(Scalar::Array(values))) if values == vec![Scalar::String("enabled".into())])
        );
    }

    #[test]
    fn standard_software_requires_whole_device_coverage_but_custom_subsets_remain_valid() {
        use rss_mdm_agent_wire::runtime as w;
        use rss_mdm_resource::{AgentCollectionDefinition, blueprints};
        let blueprint = blueprints::get("windows.agent.software", "2").unwrap();
        let blueprints::Definition::AgentCollection { template } = blueprint.definition else {
            panic!("native software template");
        };
        let key = "device.software.installations";
        let field = builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == key)
            .unwrap();
        let binding = &template.spec().mappings[key];
        validate_agent_mapping(&field, &template, binding).unwrap();
        let names: Vec<_> = binding.mapping.columns.keys().cloned().collect();
        let registry = w::NativeQueryDefinition::WindowsRegistry {
            hive: w::RegistryHive::Users {
                sid: "S-1-5-21-1-2-3-1001".into(),
            },
            view: w::RegistryView::Registry64,
            path: "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall".into(),
            enumerate_subkeys: true,
            values: names
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        w::RegistryValue {
                            name: name.clone(),
                            value_type: w::RegistryType::Sz,
                        },
                    )
                })
                .collect(),
        };
        let wmi = w::NativeQueryDefinition::WindowsWmi {
            namespace: "root\\cimv2".into(),
            class: "VendorSoftware".into(),
            properties: names
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        w::WmiProperty {
                            cim_type: w::CimType::String,
                            array: false,
                        },
                    )
                })
                .collect(),
            filter: None,
        };
        for (definition, instance_key) in [(registry, "key"), (wmi, "id")] {
            let mut spec = template.spec().clone();
            let mut plan = spec.plan.spec().clone();
            let query = plan.queries.get_mut(&binding.query).unwrap();
            query.definition = definition;
            query.instance_keys = vec![instance_key.into()];
            spec.plan = w::NativeCollectionPlan::new(plan).unwrap();
            let subset = AgentCollectionDefinition::new(spec.clone()).unwrap();
            assert!(validate_agent_mapping(&field, &subset, binding).is_err());
            let mut custom_field = field.clone();
            custom_field.key = rss_mdm_inventory::FieldKey::parse("custom.user_software").unwrap();
            let mapping = spec.mappings.remove(key).unwrap();
            spec.mappings
                .insert(custom_field.key.as_str().into(), mapping.clone());
            let custom = AgentCollectionDefinition::new(spec).unwrap();
            validate_agent_mapping(&custom_field, &custom, &mapping).unwrap();
        }
    }

    #[test]
    fn publication_and_collection_agree_on_array_conversions() {
        let mut field = builtin::fields()
            .into_iter()
            .find(|f| f.key == builtin::MODEL)
            .unwrap();
        field.value_type = ValueType::Array {
            items: Box::new(ValueType::Integer),
            max_items: 10,
        };
        let mut mapping = ValueMapping {
            pointer: "".into(),
            conversion: Conversion::Integer,
            columns: Default::default(),
        };
        validate_mapping(&field, &mapping).unwrap();
        assert!(
            matches!(mapped_value(&field, &mapping, &json!(["2048"])), NativeValue::Value(CollectedValue::Value(Scalar::Array(v))) if v == vec![Scalar::Integer(2048)])
        );
        assert!(matches!(
            mapped_value(&field, &mapping, &json!(["bad"])),
            NativeValue::InvalidItems(_)
        ));
        field.value_type = ValueType::Array {
            items: Box::new(ValueType::Enum {
                values: ["a".into(), "b".into()].into(),
            }),
            max_items: 10,
        };
        mapping.conversion = Conversion::Bitmask {
            flags: [("1".into(), "a".into()), ("2".into(), "b".into())].into(),
        };
        validate_mapping(&field, &mapping).unwrap();
        assert!(
            matches!(mapped_value(&field, &mapping, &json!(3)), NativeValue::Value(CollectedValue::Value(Scalar::Array(v))) if v.len() == 2)
        );
        assert!(matches!(
            mapped_value(&field, &mapping, &json!([3])),
            NativeValue::Invalid
        ));
    }

    #[test]
    fn unsupported_nested_array_projection_is_rejected_at_publication() {
        let mut field = builtin::fields()
            .into_iter()
            .find(|f| f.key == builtin::MODEL)
            .unwrap();
        field.value_type = ValueType::Array {
            items: Box::new(ValueType::Object {
                properties: [(
                    "nested".into(),
                    ValueType::Array {
                        items: Box::new(ValueType::Object {
                            properties: [("x".into(), ValueType::Integer)].into(),
                        }),
                        max_items: 10,
                    },
                )]
                .into(),
            }),
            max_items: 10,
        };
        let mapping = ValueMapping {
            pointer: "".into(),
            conversion: Conversion::Identity,
            columns: [(
                "nested".into(),
                ValueMapping {
                    pointer: "/nested".into(),
                    conversion: Conversion::Identity,
                    columns: [(
                        "x".into(),
                        ValueMapping {
                            pointer: "/x".into(),
                            conversion: Conversion::Integer,
                            columns: Default::default(),
                        },
                    )]
                    .into(),
                },
            )]
            .into(),
        };
        mapping.validate().unwrap();
        assert!(validate_mapping(&field, &mapping).is_err());
    }
}
