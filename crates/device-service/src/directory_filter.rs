//! A bound JSONPath predicate for Identity's static, read-only SELECT capability.
//! The field catalog checks names/operators first; values remain JSON literals.
use rss_mdm_query::{
    Expression, Operator,
    directory::{Query, Schema},
};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::view_response::DirectoryRow>("device_views", &["reference.kind", "reference.id"],64,100,&[
        rss_mdm_query::directory::Exclusion { path:"association.members", reason:"Membership object arrays use the same-endpoint selectors; arbitrary member expansion cannot preserve that quantifier" },
        rss_mdm_query::directory::Exclusion { path:"association.state", reason:"Effective association state requires current hardware and competitor qualification; raw stored state is not the public state" },
        rss_mdm_query::directory::Exclusion { path:"endpoints", reason:"Endpoint object arrays evaluate the entire predicate on one endpoint through the typed domain selectors" },
    ]).and_then(|s|s.with_selectors::<Selectors>("Entire predicate matches one authorized endpoint in the device view"))
      .and_then(|s|s.no_sort("association","Association metadata sorting is owned by the association directory; unified views navigate by typed object identity"))
      .expect("Public device-view model")
});
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Selectors {
    status: rss_mdm_registration_service::device::directory::Status,
    asset_state: crate::lifecycle_management::AssetState,
    channel: Vec<rss_mdm_inventory::Channel>,
    source: Vec<rss_mdm_registration_service::device::directory::Source>,
    platform: Vec<rss_mdm_agent_wire::runtime::TaskPlatform>,
    search: String,
}
fn source_field(name: &str) -> rss_mdm_query::Result<()> {
    if matches!(
        name,
        "reference.kind"
            | "reference.id"
            | "association.id"
            | "association.version"
            | "association.evidence"
            | "association.confirmedBy"
            | "association.confirmedAt"
            | "association.revokedBy"
            | "association.revokedAt"
            | "association.reason"
            | "status"
            | "assetState"
            | "channel"
            | "source"
            | "platform"
            | "search"
    ) {
        Ok(())
    } else {
        Err(rss_mdm_query::Error::Invalid)
    }
}
pub static EXECUTION: std::sync::LazyLock<rss_mdm_query::directory::Execution> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query::directory::Execution::bind(
            &SCHEMA,
            SCHEMA
                .fields()
                .iter()
                .filter(|f| f.filter || f.sort)
                .map(|f| {
                    source_field(&f.name).expect("Complete device view relation dispatch");
                    f.name.as_str()
                }),
        )
        .expect("Device view binding")
    });
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    let mut q = SCHEMA.parse(raw)?;
    q.default_filter("assetState", "active")?;
    Ok(q)
}
/// The directory exposes independent direction and precedence for both identity fields.
pub(super) struct Order {
    pub kind_descending: bool,
    pub id_descending: bool,
    pub id_first: bool,
}
impl Order {
    pub fn for_query(query: &Query) -> Self {
        let sort = query.sort();
        Self {
            kind_descending: sort
                .iter()
                .find(|s| s.field == "reference.kind")
                .expect("identity key")
                .descending,
            id_descending: sort
                .iter()
                .find(|s| s.field == "reference.id")
                .expect("identity key")
                .descending,
            id_first: sort[0].field == "reference.id",
        }
    }
    pub fn compare(
        &self,
        left: rss_mdm_agent_wire::ObjectRef,
        right: rss_mdm_agent_wire::ObjectRef,
    ) -> std::cmp::Ordering {
        let kind = left.kind().cmp(&right.kind());
        let id = left.uuid().cmp(&right.uuid());
        let kind = if self.kind_descending {
            kind.reverse()
        } else {
            kind
        };
        let id = if self.id_descending { id.reverse() } else { id };
        if self.id_first {
            id.then(kind)
        } else {
            kind.then(id)
        }
    }
}

pub(super) fn predicate(q: &Query) -> crate::Result<String> {
    EXECUTION
        .require(q.schema())
        .map_err(|_| crate::Error::Malformed)?;
    fn expr(e: &Expression<String, serde_json::Value>) -> crate::Result<String> {
        Ok(match e {
            Expression::And(v) | Expression::Or(v) => format!(
                "({})",
                v.iter().map(expr).collect::<crate::Result<Vec<_>>>()?.join(
                    if matches!(e, Expression::And(_)) {
                        " && "
                    } else {
                        " || "
                    }
                )
            ),
            Expression::Compare {
                field,
                operator,
                values,
            } => {
                if field == "search"
                    && values.iter().any(|v| {
                        v.as_str()
                            .is_none_or(|s| s.trim().is_empty() || s.len() > 256)
                    })
                {
                    return Err(crate::Error::Malformed);
                }
                source_field(field).map_err(|_| crate::Error::Malformed)?;
                let array = field == "search"
                    || SCHEMA
                        .field(field)
                        .map_err(|_| crate::Error::Malformed)?
                        .kind
                        .collection();
                let path = format!(
                    "$.{}{}",
                    field
                        .split('.')
                        .map(serde_json::to_string)
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(|_| crate::Error::Malformed)?
                        .join("."),
                    if array { "[*]" } else { "" }
                );
                if matches!(operator, Operator::IsNull | Operator::IsNotNull) {
                    return Ok(if *operator == Operator::IsNull {
                        format!("(!exists({path}) || {path} == null)")
                    } else {
                        format!("(exists({path}) && {path} != null)")
                    });
                }
                let mut terms = Vec::new();
                for v in values {
                    let term = if *operator == Operator::Icontains {
                        let text = v.as_str().ok_or(crate::Error::Malformed)?;
                        let mut literal = String::new();
                        for c in text.chars() {
                            if ".^$*+?()[]{}|\\".contains(c) {
                                literal.push('\\');
                            }
                            literal.push(c);
                        }
                        format!(
                            "{path} like_regex {} flag \"i\"",
                            serde_json::to_string(&literal).map_err(|_| crate::Error::Malformed)?
                        )
                    } else {
                        let op = match operator {
                            Operator::Eq
                            | Operator::In
                            | Operator::Ne
                            | Operator::Out
                            | Operator::ContainsAny
                            | Operator::ContainsAll => "==",
                            Operator::Lt => "<",
                            Operator::Le => "<=",
                            Operator::Gt => ">",
                            Operator::Ge => ">=",
                            _ => return Err(crate::Error::Malformed),
                        };
                        format!("{path} {op} {v}")
                    };
                    terms.push(format!("({term})"));
                }
                let body = format!(
                    "({})",
                    terms.join(if *operator == Operator::ContainsAll {
                        " && "
                    } else {
                        " || "
                    })
                );
                if matches!(operator, Operator::Ne | Operator::Out) {
                    format!("!{body}")
                } else {
                    body
                }
            }
        })
    }
    q.filter()
        .map(expr)
        .transpose()
        .map(|v| v.unwrap_or_else(|| "true".into()))
}

#[cfg(test)]
mod ordering_tests {
    use super::*;
    use rss_mdm_agent_wire::{DeviceId, ObjectRef};
    #[test]
    fn advertised_sort_fields_accept_independent_direction_and_precedence() {
        let fields = SCHEMA
            .fields()
            .iter()
            .filter(|field| field.sort)
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 2);
        for first in &fields {
            for second in fields.iter().filter(|second| *second != first) {
                for a in ["", "-"] {
                    for b in ["", "-"] {
                        assert!(parse(&format!("sort={a}{first},{b}{second}")).is_ok());
                    }
                }
            }
            assert!(parse(&format!("sort={first}")).is_ok());
            assert!(parse(&format!("sort=-{first}")).is_ok());
        }
        let one = DeviceId::try_from(uuid::Uuid::from_u128(1)).unwrap();
        let two = DeviceId::try_from(uuid::Uuid::from_u128(2)).unwrap();
        let e1 = ObjectRef::Endpoint(one);
        let e2 = ObjectRef::Endpoint(two);
        let a1 = ObjectRef::Association(one.into_uuid());
        let a2 = ObjectRef::Association(two.into_uuid());
        for (sort, expected) in [
            ("", [e1, e2, a1, a2]),
            ("sort=reference.id", [e1, a1, e2, a2]),
            ("sort=-reference.kind", [a1, a2, e1, e2]),
            ("sort=reference.kind,-reference.id", [e2, e1, a2, a1]),
            ("sort=-reference.id,reference.kind", [e2, a2, e1, a1]),
        ] {
            let order = Order::for_query(&parse(sort).unwrap());
            let mut actual = [a1, e2, a2, e1];
            actual.sort_by(|a, b| order.compare(*a, *b));
            assert_eq!(actual, expected, "{sort}");
        }
    }
}
