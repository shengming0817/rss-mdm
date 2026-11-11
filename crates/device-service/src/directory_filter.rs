//! A bound JSONPath predicate for Identity's static, read-only SELECT capability.
//! The field catalog checks names/operators first; values remain JSON literals.
use rss_mdm_query::{
    Expression, Operator,
    directory::{Query, Schema},
};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::view_response::DirectoryRow>("device_views", &["key"],64,100,&[
        rss_mdm_query::directory::Exclusion { path:"association.members", reason:"Membership object arrays use the same-endpoint selectors; arbitrary member expansion cannot preserve that quantifier" },
        rss_mdm_query::directory::Exclusion { path:"association.state", reason:"Effective association state requires current hardware and competitor qualification; raw stored state is not the public state" },
        rss_mdm_query::directory::Exclusion { path:"endpoints", reason:"Endpoint object arrays evaluate the entire predicate on one endpoint through the typed domain selectors" },
    ]).and_then(|s|s.with_selectors::<Selectors>("Entire predicate matches one authorized endpoint in the device view"))
      .and_then(|s|s.no_sort("reference","Unified device views navigate by their canonical object key"))
      .and_then(|s|s.no_sort("association","Association metadata sorting is owned by the association directory; unified views navigate by canonical object key"))
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
        "key"
            | "reference.kind"
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
