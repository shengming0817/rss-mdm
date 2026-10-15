//! Pure native collection contracts. No OS execution or Inventory policy.
//! ref: microsoft/windows-rs crates/libs/windows/src/Windows/Win32/System/Wmi/mod.rs@0.61.0
use crate::runtime::{ExecutionIdentity, OUTPUT_MAX_BYTES, TaskPlatform, WireError};
#[path = "native_collection/macos.rs"]
mod macos;
pub use macos::{MacosApplicationRoot, MacosBrewPackage, MacosHardwareSection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// One supported native engine contract (versions are independently negotiated).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum NativeEngine {
    /// Local read-only WMI queries.
    #[serde(rename = "windows.wmi")]
    WindowsWmi,
    /// Local registry reads.
    #[serde(rename = "windows.registry")]
    WindowsRegistry,
    /// Multi-processor summary.
    #[serde(rename = "windows.cpu")]
    WindowsCpu,
    /// Device and all-user installation instances, including MSIX.
    #[serde(rename = "windows.software")]
    WindowsSoftware,
    /// Complete network interface inventory.
    #[serde(rename = "windows.network")]
    WindowsNetwork,
    /// Device battery summary.
    #[serde(rename = "windows.battery")]
    WindowsBattery,
    /// Fixed macOS hardware sections.
    #[serde(rename = "macos.hardware")]
    MacosHardware,
    /// Bounded approved-root application inventory.
    #[serde(rename = "macos.applications")]
    MacosApplications,
    /// PackageInstaller receipt inventory, separate from application presence.
    #[serde(rename = "macos.pkg_receipts")]
    MacosPkgReceipts,
    /// Non-root installed formula/cask metadata in the JSON v2 tool format.
    #[serde(rename = "macos.brew")]
    MacosBrew,
}
/// Exact supported contract versions, not executable names.
pub type NativeEngines = BTreeMap<NativeEngine, u16>;
/// Declared native value representation. Unsigned 64-bit values use decimal strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeType {
    /// UTF-8 string; expandable registry strings remain unexpanded.
    String,
    /// Boolean.
    Boolean,
    /// Signed integral value.
    Integer,
    /// Exact unsigned decimal text, including QWORD.
    UInt64,
    /// Finite floating point value.
    Number,
    /// Original CIM datetime, converted only with complete timezone information.
    CimTime,
    /// Bounded homogeneous values.
    Array {
        /// Element type.
        items: Box<NativeType>,
    },
}
impl NativeType {
    /// Validate a value without lossy numeric coercion.
    pub fn accepts(&self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value
                .as_str()
                .is_some_and(|s| s.len() <= 65536 && !s.contains('\0')),
            Self::Boolean => value.is_boolean(),
            Self::Integer => value.as_i64().is_some(),
            Self::UInt64 => value
                .as_str()
                .is_some_and(|s| s.parse::<u64>().is_ok_and(|v| v.to_string() == s)),
            Self::Number => value.as_f64().is_some_and(f64::is_finite),
            Self::CimTime => value
                .as_str()
                .is_some_and(|s| s.len() == 25 && s.is_ascii() && !s.chars().any(char::is_control)),
            Self::Array { items } => value
                .as_array()
                .is_some_and(|a| a.len() <= 65535 && a.iter().all(|v| items.accepts(v))),
        }
    }
    fn validate(&self, depth: usize) -> Result<(), WireError> {
        if depth > 4 {
            return Err(WireError::InvalidValue);
        }
        if let Self::Array { items } = self {
            items.validate(depth + 1)?;
        }
        Ok(())
    }
}
/// WMI property CIM type, with native widths preserved in the declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CimType {
    /// CIM_STRING.
    String,
    /// CIM_BOOLEAN.
    Boolean,
    /// CIM_SINT8.
    Sint8,
    /// CIM_SINT16.
    Sint16,
    /// CIM_SINT32.
    Sint32,
    /// CIM_SINT64.
    Sint64,
    /// CIM_UINT8.
    Uint8,
    /// CIM_UINT16.
    Uint16,
    /// CIM_UINT32.
    Uint32,
    /// CIM_UINT64.
    Uint64,
    /// CIM_REAL32.
    Real32,
    /// CIM_REAL64.
    Real64,
    /// CIM_DATETIME.
    Datetime,
}
impl CimType {
    /// Check the declared CIM width as well as its transport representation.
    pub fn accepts(self, value: &serde_json::Value) -> bool {
        let signed = |min: i64, max: i64| value.as_i64().is_some_and(|v| (min..=max).contains(&v));
        match self {
            Self::Sint8 => signed(i8::MIN.into(), i8::MAX.into()),
            Self::Sint16 => signed(i16::MIN.into(), i16::MAX.into()),
            Self::Sint32 => signed(i32::MIN.into(), i32::MAX.into()),
            Self::Uint8 => signed(0, u8::MAX.into()),
            Self::Uint16 => signed(0, u16::MAX.into()),
            Self::Uint32 => signed(0, u32::MAX.into()),
            Self::Real32 => value
                .as_f64()
                .is_some_and(|v| v.is_finite() && v.abs() <= f64::from(f32::MAX)),
            _ => self.output().accepts(value),
        }
    }
    /// Canonical transport type.
    pub fn output(self) -> NativeType {
        match self {
            Self::String => NativeType::String,
            Self::Boolean => NativeType::Boolean,
            Self::Uint64 => NativeType::UInt64,
            Self::Real32 | Self::Real64 => NativeType::Number,
            Self::Datetime => NativeType::CimTime,
            _ => NativeType::Integer,
        }
    }
}
/// Selected property with explicit array shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WmiProperty {
    /// Exact CIM primitive.
    pub cim_type: CimType,
    /// Whether CIM_FLAG_ARRAY is required.
    pub array: bool,
}
/// Closed comparison operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeComparison {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
}
/// Bounded structural filter; property names are never query expressions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WmiFilter {
    /// Compare one declared non-array property to a typed literal.
    Compare {
        /// Selected property.
        property: String,
        /// Operator.
        operator: NativeComparison,
        /// Literal interpreted by the property's CIM type.
        value: serde_json::Value,
    },
    /// All predicates must hold.
    And {
        /// Nonempty bounded operands.
        terms: Vec<WmiFilter>,
    },
    /// At least one predicate must hold.
    Or {
        /// Nonempty bounded operands.
        terms: Vec<WmiFilter>,
    },
}
impl WmiFilter {
    fn validate(
        &self,
        properties: &BTreeMap<String, WmiProperty>,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<(), WireError> {
        *nodes += 1;
        if depth > 4 || *nodes > 128 {
            return Err(WireError::InvalidValue);
        }
        match self {
            Self::Compare {
                property,
                operator,
                value,
            } => {
                let p = properties.get(property).ok_or(WireError::InvalidValue)?;
                if p.array
                    || !p.cim_type.accepts(value)
                    || value.as_str().is_some_and(|v| v.len() > 4096)
                    || (!matches!(operator, NativeComparison::Eq | NativeComparison::Ne)
                        && matches!(
                            p.cim_type,
                            CimType::String | CimType::Boolean | CimType::Datetime
                        ))
                {
                    return Err(WireError::InvalidValue);
                }
            }
            Self::And { terms } | Self::Or { terms } => {
                if terms.is_empty() || terms.len() > 32 {
                    return Err(WireError::InvalidValue);
                }
                for t in terms {
                    t.validate(properties, depth + 1, nodes)?;
                }
            }
        }
        Ok(())
    }
}
/// Native registry value type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistryType {
    /// REG_SZ.
    Sz,
    /// REG_EXPAND_SZ, without environment expansion.
    ExpandSz,
    /// REG_DWORD.
    Dword,
    /// REG_QWORD.
    Qword,
    /// REG_MULTI_SZ.
    MultiSz,
}
/// Exact local hive; HKCU is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistryHive {
    /// HKEY_LOCAL_MACHINE.
    LocalMachine,
    /// Already loaded HKEY_USERS SID; never mount an offline hive.
    Users {
        /// Canonical Windows SID.
        sid: String,
    },
}
/// Explicit view independent of executor bitness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistryView {
    /// KEY_WOW64_32KEY.
    Registry32,
    /// KEY_WOW64_64KEY.
    Registry64,
}
/// One registry value projected under a stable property identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryValue {
    /// Literal value name; empty means the default value.
    pub name: String,
    /// Exact expected registry type.
    pub value_type: RegistryType,
}
/// Closed read recipes. Output properties are derived from this declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeQueryDefinition {
    /// Read local WMI instances.
    WindowsWmi {
        /// Local namespace, for example root\\cimv2.
        namespace: String,
        /// Existing class, never created by collection.
        class: String,
        /// Explicit properties; SELECT * is impossible.
        properties: BTreeMap<String, WmiProperty>,
        /// Optional structured predicate.
        filter: Option<WmiFilter>,
    },
    /// Read one key or enumerate its immediate children once.
    WindowsRegistry {
        /// Local hive identity.
        hive: RegistryHive,
        /// Explicit registry view.
        view: RegistryView,
        /// Fixed relative key path.
        path: String,
        /// True enumerates only immediate subkeys; row key is `key`.
        enumerate_subkeys: bool,
        /// Output property to exact value read.
        values: BTreeMap<String, RegistryValue>,
    },
    /// Native multi-CPU summary; model is present only when all processors agree.
    WindowsCpu,
    /// Complete installation list over device and all existing user profiles.
    WindowsSoftware,
    /// Complete interface enumeration.
    WindowsNetwork,
    /// Aggregate battery charge (energy-weighted), or Missing when absent.
    WindowsBattery,
    /// Fixed native macOS hardware section, with no executable parameters.
    MacosHardware {
        /// Closed section and its canonical output shape.
        section: MacosHardwareSection,
    },
    /// One approved application root; partial roots cannot replace a device inventory.
    MacosApplications {
        /// Fixed root selector, resolved by the trusted Agent.
        root: MacosApplicationRoot,
        /// Maximum directory descent (1 through 8); reaching the bound is Truncated.
        max_depth: u8,
    },
    /// Device package receipts, never application-existence evidence.
    MacosPkgReceipts {},
    /// Installed package metadata; the executor must be a bound non-root logged-in user.
    /// Tool contract is Homebrew info JSON v2; no arbitrary flags or executable path.
    MacosBrew {
        /// Approved absolute data prefix, not a command or executable path.
        prefix: String,
        /// Distinct package evidence kind.
        package: MacosBrewPackage,
        /// Exact lowercase owner/tap selectors; empty requests all taps in this prefix.
        taps: BTreeSet<String>,
    },
}
/// Stable primitive identifier grammar (not a WQL token stream).
pub fn native_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn sid_valid(s: &str) -> bool {
    s.len() <= 184
        && s.starts_with("S-1-")
        && s.split('-').skip(2).count() >= 2
        && s.split('-')
            .skip(2)
            .all(|p| !p.is_empty() && p.parse::<u64>().is_ok_and(|v| v.to_string() == p))
}
impl NativeQueryDefinition {
    /// Required native engine.
    pub fn engine(&self) -> NativeEngine {
        match self {
            Self::WindowsWmi { .. } => NativeEngine::WindowsWmi,
            Self::WindowsRegistry { .. } => NativeEngine::WindowsRegistry,
            Self::WindowsCpu => NativeEngine::WindowsCpu,
            Self::WindowsSoftware => NativeEngine::WindowsSoftware,
            Self::WindowsNetwork => NativeEngine::WindowsNetwork,
            Self::WindowsBattery => NativeEngine::WindowsBattery,
            Self::MacosHardware { .. } => NativeEngine::MacosHardware,
            Self::MacosApplications { .. } => NativeEngine::MacosApplications,
            Self::MacosPkgReceipts {} => NativeEngine::MacosPkgReceipts,
            Self::MacosBrew { .. } => NativeEngine::MacosBrew,
        }
    }
    /// Exact native platform; a plan cannot mix definitions from different platforms.
    pub fn platform(&self) -> TaskPlatform {
        match self {
            Self::MacosHardware { .. }
            | Self::MacosApplications { .. }
            | Self::MacosPkgReceipts {}
            | Self::MacosBrew { .. } => TaskPlatform::Macos,
            Self::WindowsWmi { .. }
            | Self::WindowsRegistry { .. }
            | Self::WindowsCpu
            | Self::WindowsSoftware
            | Self::WindowsNetwork
            | Self::WindowsBattery => TaskPlatform::Windows,
        }
    }
    /// Required privilege boundary, never inferred from a script executor profile.
    pub fn execution_identity(&self) -> ExecutionIdentity {
        match self {
            Self::MacosBrew { .. }
            | Self::MacosApplications {
                root: MacosApplicationRoot::UserApplications,
                ..
            } => ExecutionIdentity::LoggedInUser,
            Self::WindowsWmi { .. }
            | Self::WindowsRegistry { .. }
            | Self::WindowsCpu
            | Self::WindowsSoftware
            | Self::WindowsNetwork
            | Self::WindowsBattery
            | Self::MacosHardware { .. }
            | Self::MacosPkgReceipts {}
            | Self::MacosApplications {
                root:
                    MacosApplicationRoot::LocalApplications | MacosApplicationRoot::SystemApplications,
                ..
            } => ExecutionIdentity::System,
        }
    }
    /// Canonical row schema; no independently authored output schema exists.
    pub fn properties(&self) -> BTreeMap<String, NativeType> {
        use NativeType::*;
        match self {
            Self::WindowsWmi { properties, .. } => properties
                .iter()
                .map(|(k, p)| {
                    (
                        k.clone(),
                        if p.array {
                            Array {
                                items: Box::new(p.cim_type.output()),
                            }
                        } else {
                            p.cim_type.output()
                        },
                    )
                })
                .collect(),
            Self::WindowsRegistry {
                values,
                enumerate_subkeys,
                ..
            } => {
                let mut p: BTreeMap<_, _> = values
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            match v.value_type {
                                RegistryType::Sz | RegistryType::ExpandSz => String,
                                RegistryType::Dword => Integer,
                                RegistryType::Qword => UInt64,
                                RegistryType::MultiSz => Array {
                                    items: Box::new(String),
                                },
                            },
                        )
                    })
                    .collect();
                if *enumerate_subkeys {
                    p.insert("key".into(), String);
                }
                p
            }
            Self::WindowsCpu => [
                ("model", String),
                ("physical_cores", Integer),
                ("logical_cores", Integer),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
            Self::WindowsSoftware => [
                "id",
                "native_id",
                "name",
                "version",
                "publisher",
                "scope",
                "owner",
                "origin",
                "location",
            ]
            .into_iter()
            .map(|k| (k.into(), String))
            .collect(),
            Self::WindowsNetwork => [
                ("id", String),
                ("name", String),
                (
                    "addresses",
                    Array {
                        items: Box::new(String),
                    },
                ),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
            Self::WindowsBattery => [("charge_percent".into(), Number)].into(),
            Self::MacosHardware { section } => section.properties(),
            Self::MacosApplications { .. } => macos::software_properties(&[
                ("build_version", String),
                ("signature_status", String),
                ("team_id", String),
            ]),
            Self::MacosPkgReceipts {} => macos::software_properties(&[("install_time", Integer)]),
            Self::MacosBrew { .. } => macos::software_properties(&[
                ("prefix", String),
                ("tap", String),
                ("package_kind", String),
            ]),
        }
    }
    /// Validate each present native property against the declared platform type.
    pub fn accepts_row(&self, row: &BTreeMap<String, serde_json::Value>) -> bool {
        match self {
            Self::WindowsWmi { properties, .. } => row.iter().all(|(k, v)| {
                properties.get(k).is_some_and(|p| {
                    if p.array {
                        v.as_array()
                            .is_some_and(|a| a.iter().all(|v| p.cim_type.accepts(v)))
                    } else {
                        p.cim_type.accepts(v)
                    }
                })
            }),
            Self::WindowsRegistry { values, .. } => row.iter().all(|(k, v)| {
                k == "key"
                    || values.get(k).is_some_and(|p| {
                        p.value_type != RegistryType::Dword
                            || v.as_u64().is_some_and(|v| v <= u64::from(u32::MAX))
                    })
            }),
            Self::WindowsSoftware => match (
                row.get("scope").and_then(|v| v.as_str()),
                row.get("owner").and_then(|v| v.as_str()),
            ) {
                (Some("device"), Some("")) => true,
                (Some("user"), Some(sid)) => sid_valid(sid),
                _ => false,
            },
            Self::WindowsCpu => ["physical_cores", "logical_cores"].iter().all(|k| {
                row.get(*k)
                    .is_some_and(|v| v.as_i64().is_some_and(|v| v > 0))
            }),
            Self::WindowsBattery => row
                .get("charge_percent")
                .is_some_and(|v| v.as_f64().is_some_and(|v| (0.0..=100.0).contains(&v))),
            Self::WindowsNetwork => true,
            Self::MacosHardware { section } => section.accepts_row(row),
            Self::MacosApplications { root, .. } => macos::application_row(*root, row),
            Self::MacosPkgReceipts {} => macos::device_software_row(row, "pkg_receipt"),
            Self::MacosBrew {
                prefix,
                package,
                taps,
            } => macos::brew_row(prefix, *package, taps, row),
        }
    }
    /// Reject executable syntax and unsupported read recipes.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::WindowsWmi {
                namespace,
                class,
                properties,
                filter,
            } => {
                if namespace.len() > 256
                    || !namespace.to_ascii_lowercase().starts_with("root\\")
                    || !namespace.split('\\').all(native_identifier)
                    || !native_identifier(class)
                    || class.eq_ignore_ascii_case("Win32_Product")
                    || properties.is_empty()
                    || properties.len() > 64
                    || !properties.keys().all(|k| native_identifier(k))
                    || properties
                        .keys()
                        .map(|k| k.to_ascii_lowercase())
                        .collect::<BTreeSet<_>>()
                        .len()
                        != properties.len()
                {
                    return Err(WireError::InvalidValue);
                }
                if let Some(f) = filter {
                    f.validate(properties, 0, &mut 0)?;
                }
            }
            Self::WindowsRegistry {
                hive, path, values, ..
            } => {
                if matches!(hive,RegistryHive::Users{sid} if !sid_valid(sid))
                    || path.len() > 1024
                    || path.split('\\').any(|p| {
                        p.is_empty()
                            || p == "."
                            || p == ".."
                            || p.chars().any(|c| c.is_control() || "/*?:".contains(c))
                    })
                    || values.is_empty()
                    || values.len() > 64
                    || values.keys().any(|k| !native_identifier(k) || k == "key")
                    || values
                        .values()
                        .any(|v| v.name.len() > 16383 || v.name.chars().any(char::is_control))
                {
                    return Err(WireError::InvalidValue);
                }
                let p = path.to_ascii_lowercase();
                if matches!(hive, RegistryHive::LocalMachine)
                    && (p == "sam"
                        || p.starts_with("sam\\")
                        || p == "security"
                        || p.starts_with("security\\"))
                {
                    return Err(WireError::InvalidValue);
                }
            }
            Self::MacosApplications { max_depth, .. } if !(1..=8).contains(max_depth) => {
                return Err(WireError::InvalidValue);
            }
            Self::MacosBrew { prefix, taps, .. }
                if !macos::absolute_data_root(prefix)
                    || taps.len() > 64
                    || taps.iter().any(|t| !macos::tap_valid(t)) =>
            {
                return Err(WireError::InvalidValue);
            }
            _ => (),
        }
        for t in self.properties().values() {
            t.validate(0)?;
        }
        Ok(())
    }
}
/// Query row cardinality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeCardinality {
    /// Exactly one row; zero is Missing.
    ExactlyOne,
    /// Complete bounded list, including zero rows.
    List,
}
/// Frozen bounds, shared by collection and query scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeBudget {
    /// Wall-clock bound.
    pub timeout_seconds: u32,
    /// Canonical result byte bound.
    pub output_bytes: u32,
    /// Maximum rows.
    pub max_rows: u16,
}
impl NativeBudget {
    /// Validate against the existing task and transport ceilings.
    pub fn validate(&self) -> Result<(), WireError> {
        if !(1..=3600).contains(&self.timeout_seconds)
            || self.output_bytes == 0
            || self.output_bytes as usize > OUTPUT_MAX_BYTES
            || self.max_rows == 0
        {
            Err(WireError::InvalidValue)
        } else {
            Ok(())
        }
    }
}
/// One frozen query, reusable by several server-side field mappings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeQuery {
    /// Exact engine contract version.
    pub version: u16,
    /// Read recipe.
    pub definition: NativeQueryDefinition,
    /// Row semantics.
    pub cardinality: NativeCardinality,
    /// Stable row properties identifying instances.
    pub instance_keys: Vec<String>,
    /// Query-local bounds.
    pub budget: NativeBudget,
}
impl NativeQuery {
    /// Validate query consistency.
    pub fn validate(&self) -> Result<(), WireError> {
        self.definition.validate()?;
        self.budget.validate()?;
        let p = self.definition.properties();
        if self.version != 1
            || self.instance_keys.len() > 8
            || self.instance_keys.iter().collect::<BTreeSet<_>>().len() != self.instance_keys.len()
            || self.instance_keys.iter().any(|k| {
                !matches!(
                    p.get(k),
                    Some(NativeType::String | NativeType::Integer | NativeType::UInt64)
                )
            })
            || self.cardinality == NativeCardinality::List && self.instance_keys.is_empty()
        {
            return Err(WireError::InvalidValue);
        }
        let required = match &self.definition {
            NativeQueryDefinition::WindowsRegistry {
                enumerate_subkeys, ..
            } => Some(if *enumerate_subkeys {
                NativeCardinality::List
            } else {
                NativeCardinality::ExactlyOne
            }),
            NativeQueryDefinition::WindowsCpu | NativeQueryDefinition::WindowsBattery => {
                Some(NativeCardinality::ExactlyOne)
            }
            NativeQueryDefinition::WindowsSoftware | NativeQueryDefinition::WindowsNetwork => {
                Some(NativeCardinality::List)
            }
            NativeQueryDefinition::MacosHardware { section } => Some(section.cardinality()),
            NativeQueryDefinition::MacosApplications { .. }
            | NativeQueryDefinition::MacosPkgReceipts {}
            | NativeQueryDefinition::MacosBrew { .. } => Some(NativeCardinality::List),
            _ => None,
        };
        if required.is_some_and(|r| r != self.cardinality) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// Canonical query identity.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(serde_json::to_vec(self).expect("closed query")).into()
    }
}
/// Validated immutable plan. Field names and priorities remain server-owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "NativePlanSpec", into = "NativePlanSpec")]
pub struct NativeCollectionPlan(NativePlanSpec);
/// Construction input to a validated native plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePlanSpec {
    /// Exact native plan format.
    pub version: u16,
    /// Namespace of facts, independent of Policy target scope.
    pub scope: crate::CollectionScope,
    /// Stable query IDs, executed once each.
    pub queries: BTreeMap<String, NativeQuery>,
    /// Cumulative execution bounds.
    pub budget: NativeBudget,
}
impl From<NativeCollectionPlan> for NativePlanSpec {
    fn from(p: NativeCollectionPlan) -> Self {
        p.0
    }
}
impl TryFrom<NativePlanSpec> for NativeCollectionPlan {
    type Error = WireError;
    fn try_from(p: NativePlanSpec) -> Result<Self, WireError> {
        Self::new(p)
    }
}
impl NativeCollectionPlan {
    /// Validate structural query, platform, identity and budget constraints.
    pub fn new(p: NativePlanSpec) -> Result<Self, WireError> {
        p.budget.validate()?;
        match &p.scope {
            crate::CollectionScope::Device => {}
            crate::CollectionScope::User { identity } if macos::nonroot_uid(identity) => {}
            crate::CollectionScope::Prefix { path } if macos::absolute_data_root(path) => {}
            _ => return Err(WireError::InvalidValue),
        }
        if p.version != 1
            || p.queries.is_empty()
            || p.queries.len() > 64
            || !p.queries.keys().all(|k| native_identifier(k))
        {
            return Err(WireError::InvalidValue);
        }
        for q in p.queries.values() {
            q.validate()?;
            let first = &p.queries.values().next().expect("nonempty").definition;
            if q.definition.platform() != first.platform()
                || q.definition.execution_identity() != first.execution_identity()
                || (q.definition.platform() == TaskPlatform::Windows
                    && p.scope != crate::CollectionScope::Device)
                || matches!(&p.scope, crate::CollectionScope::Prefix { path }
                    if !matches!(&q.definition, NativeQueryDefinition::MacosBrew { prefix, .. } if prefix == path))
                || (matches!(&p.scope, crate::CollectionScope::User { .. })
                    && q.definition.execution_identity() != ExecutionIdentity::LoggedInUser)
            {
                return Err(WireError::InvalidValue);
            }
            if q.budget.output_bytes > p.budget.output_bytes
                || q.budget.timeout_seconds > p.budget.timeout_seconds
                || q.budget.max_rows > p.budget.max_rows
            {
                return Err(WireError::InvalidValue);
            }
        }
        if serde_json::to_vec(&p)
            .map_err(|_| WireError::InvalidValue)?
            .len()
            > 65536
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(p))
    }
    /// Required operating system, shared by every query.
    pub fn platform(&self) -> TaskPlatform {
        self.0
            .queries
            .values()
            .next()
            .expect("validated plan")
            .definition
            .platform()
    }
    /// Required execution identity, shared by every query.
    pub fn execution_identity(&self) -> ExecutionIdentity {
        self.0
            .queries
            .values()
            .next()
            .expect("validated plan")
            .definition
            .execution_identity()
    }
    /// Immutable construction values.
    pub fn spec(&self) -> &NativePlanSpec {
        &self.0
    }
    /// Domain-specific canonical definition fingerprint.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"rss-mdm-native-plan-v1\0");
        h.update(serde_json::to_vec(&self.0).expect("closed plan"));
        h.finalize().into()
    }
    /// Exact capabilities required for this plan.
    pub fn requirements(&self) -> NativeEngines {
        self.0
            .queries
            .values()
            .map(|q| (q.definition.engine(), q.version))
            .collect()
    }
    /// Whether a current endpoint can execute every query.
    pub fn supported_by(&self, engines: &NativeEngines) -> bool {
        self.requirements()
            .iter()
            .all(|(k, v)| engines.get(k) == Some(v))
    }
}
/// Signed privilege and live-session binding; scan declarations are not Inventory authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeExecutionBinding {
    /// Exact required privilege boundary.
    pub identity: ExecutionIdentity,
    /// Current reported context generation; changes invalidate an outstanding Offer.
    pub context_revision: u64,
    /// Exact device or interactive session. No offline user switching is permitted.
    pub target: crate::runtime::SoftwareExecutionTarget,
}
impl NativeExecutionBinding {
    /// Bind only an available broker/helper and the current non-root login.
    pub fn bind(
        plan: &NativeCollectionPlan,
        context: &crate::runtime::SoftwareExecutionContext,
    ) -> Result<Self, WireError> {
        use crate::runtime::SoftwareExecutionTarget;
        context.validate_for(plan.platform())?;
        let identity = plan.execution_identity();
        let target = match identity {
            ExecutionIdentity::System if context.system_broker => SoftwareExecutionTarget::Device,
            ExecutionIdentity::LoggedInUser if context.user_helper => {
                let user = context
                    .interactive_user
                    .as_ref()
                    .ok_or(WireError::InvalidValue)?;
                SoftwareExecutionTarget::User {
                    identity: user.identity.clone(),
                    session_id: user.session_id,
                }
            }
            _ => return Err(WireError::InvalidValue),
        };
        let binding = Self {
            identity,
            context_revision: context.revision,
            target,
        };
        binding.validate(plan)?;
        Ok(binding)
    }
    /// Check the signed identity against the immutable plan before local execution.
    pub fn validate(&self, plan: &NativeCollectionPlan) -> Result<(), WireError> {
        use crate::runtime::SoftwareExecutionTarget;
        self.target.validate_for(plan.platform())?;
        if self.context_revision == 0
            || self.context_revision > i64::MAX as u64
            || self.identity != plan.execution_identity()
        {
            return Err(WireError::InvalidValue);
        }
        match (&self.target, self.identity) {
            (SoftwareExecutionTarget::Device, ExecutionIdentity::System) => Ok(()),
            (SoftwareExecutionTarget::User { identity, .. }, ExecutionIdentity::LoggedInUser)
                if plan.platform() == TaskPlatform::Macos
                    && macos::nonroot_uid(identity)
                    && !matches!(&plan.spec().scope, crate::CollectionScope::User { identity: owner } if owner != identity) =>
            {
                Ok(())
            }
            _ => Err(WireError::InvalidValue),
        }
    }
    /// Recheck local context at Start; neither a new session nor a new revision may reuse an Offer.
    pub fn matches_context(
        &self,
        plan: &NativeCollectionPlan,
        context: &crate::runtime::SoftwareExecutionContext,
    ) -> bool {
        Self::bind(plan, context).is_ok_and(|current| current == *self)
    }
}
/// Closed query completion status; it never denotes script exit success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeQueryStatus {
    /// Complete enumeration.
    Complete,
    /// Engine or data unavailable.
    Unsupported,
    /// Access denied.
    Denied,
    /// Execution budget elapsed.
    Timeout,
    /// Output or row budget reached.
    Truncated,
    /// Complete absence evidence.
    Missing,
    /// Invalid native value or instance identity.
    Invalid,
}
/// Evidence for all-user device software inventory; no SID-local replacement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeUserCoverage {
    /// User discovery reached its end.
    pub enumeration_complete: bool,
    /// Profiles before collection.
    pub expected: BTreeSet<String>,
    /// Profiles after collection.
    pub observed: BTreeSet<String>,
    /// Profiles whose entire requested inventory completed.
    pub completed: BTreeSet<String>,
}
impl NativeUserCoverage {
    /// Complete stable user coverage, including a legitimately empty set.
    pub fn complete(&self) -> bool {
        self.enumeration_complete
            && self.expected == self.observed
            && self.expected == self.completed
            && self.expected.len() <= 4096
            && self.expected.iter().all(|s| sid_valid(s))
    }
}
/// Evidence and typed native rows for one query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeQueryResult {
    /// Exact frozen query fingerprint.
    pub query_digest: [u8; 32],
    /// Collection Unix time.
    pub collected_at: i64,
    /// Query outcome.
    pub status: NativeQueryStatus,
    /// Iterator reached its natural end.
    pub enumeration_complete: bool,
    /// Reported row count, checked against rows.
    pub row_count: u32,
    /// Values checked against the query-derived native schema.
    pub rows: Vec<BTreeMap<String, serde_json::Value>>,
    /// Required for all-user software collection.
    pub users: Option<NativeUserCoverage>,
}
impl NativeQueryResult {
    /// Validate query-level evidence independently; false never discards other queries.
    pub fn complete_for(&self, q: &NativeQuery, now: i64) -> bool {
        if self.query_digest != q.digest()
            || self.collected_at < 1
            || self.collected_at > now
            || self.status != NativeQueryStatus::Complete
            || !self.enumeration_complete
            || self.rows.len() != self.row_count as usize
            || self.rows.len() > usize::from(q.budget.max_rows)
            || !serde_json::to_vec(self).is_ok_and(|v| v.len() <= q.budget.output_bytes as usize)
        {
            return false;
        }
        if q.cardinality == NativeCardinality::ExactlyOne && self.rows.len() != 1 {
            return false;
        }
        if matches!(q.definition, NativeQueryDefinition::WindowsSoftware)
            && !self
                .users
                .as_ref()
                .is_some_and(NativeUserCoverage::complete)
        {
            return false;
        }
        let schema = q.definition.properties();
        let mut keys = BTreeSet::new();
        for row in &self.rows {
            if matches!(q.definition, NativeQueryDefinition::WindowsSoftware)
                && row.get("scope").and_then(|v| v.as_str()) == Some("user")
                && !row
                    .get("owner")
                    .and_then(|v| v.as_str())
                    .is_some_and(|owner| {
                        self.users
                            .as_ref()
                            .is_some_and(|u| u.expected.contains(owner))
                    })
            {
                return false;
            }
            if !q.definition.accepts_row(row) {
                return false;
            }
            if row.keys().any(|k| !schema.contains_key(k))
                || row.iter().any(|(k, v)| !schema[k].accepts(v))
            {
                return false;
            }
            if !q.instance_keys.is_empty() {
                let key: Option<Vec<_>> = q.instance_keys.iter().map(|k| row.get(k)).collect();
                let Some(key) = key else {
                    return false;
                };
                if key.iter().any(|v| v.as_str() == Some(""))
                    || !keys.insert(serde_json::to_string(&key).expect("closed key"))
                {
                    return false;
                }
            }
        }
        true
    }
}
/// Complete transport document with independently qualified query outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCollectionResult {
    /// Frozen plan identity.
    pub plan_digest: [u8; 32],
    /// Result capture time.
    pub collected_at: i64,
    /// One result for every planned query, including failures.
    pub queries: BTreeMap<String, NativeQueryResult>,
}
impl NativeCollectionResult {
    /// Canonical result identity for handoff vectors and retained evidence.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"rss-mdm-native-result-v1\0");
        h.update(serde_json::to_vec(self).expect("closed result"));
        h.finalize().into()
    }
    /// Check envelope binding; per-query completeness remains independent.
    pub fn validate_for(&self, p: &NativeCollectionPlan, now: i64) -> Result<(), WireError> {
        if self.queries.values().map(|q| q.rows.len()).sum::<usize>()
            > usize::from(p.spec().budget.max_rows)
            || self.plan_digest != p.digest()
            || self.collected_at < 1
            || self.collected_at > now
            || self.queries.keys().ne(p.spec().queries.keys())
            || self.queries.iter().any(|(k, r)| {
                r.query_digest != p.spec().queries[k].digest()
                    || r.collected_at < 1
                    || r.collected_at > self.collected_at
            })
            || serde_json::to_vec(self)
                .map_err(|_| WireError::InvalidValue)?
                .len()
                > p.spec().budget.output_bytes as usize
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
