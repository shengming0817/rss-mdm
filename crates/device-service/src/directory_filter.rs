//! A bound JSONPath predicate for Identity's static, read-only SELECT capability.
//! The field catalog checks names/operators first; values remain JSON literals.
use rss_mdm_query::{
    Expression, Operator,
    directory::{Field, Kind, Query, Schema},
};
pub static SCHEMA: Schema = Schema {
    id: "device_views",
    keys: &["key"],
    default_limit: 64,
    max_limit: 100,
    fields: &[
        Field::scalar("key", Kind::Text),
        Field::filter_only(
            "status",
            Kind::Enum(&[
                "active",
                "pending",
                "revoked",
                "superseded",
                "registered",
                "cancelled",
                "expired",
            ]),
        ),
        Field::filter_only("assetState", Kind::Enum(&["active", "archived", "deleted"])),
        Field::filter_only("channel", Kind::EnumSet(&["mdm", "agent"])),
        Field::filter_only(
            "source",
            Kind::EnumSet(&["mdm.windows", "mdm.apple", "agent.builtin"]),
        ),
        Field::filter_only("platform", Kind::EnumSet(&["windows", "macos"])),
        Field::filter_only("search", Kind::Text),
        Field::output("reference"),
        Field::output("association"),
        Field::output("endpoints"),
    ],
};
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    let mut q = SCHEMA.parse(raw)?;
    q.default_filter("assetState", "active")?;
    Ok(q)
}
pub(super) fn predicate(q: &Query) -> crate::Result<String> {
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
                let array = matches!(field.as_str(), "search" | "platform" | "source" | "channel");
                let path = format!(
                    "$.{}{}",
                    serde_json::to_string(field).map_err(|_| crate::Error::Malformed)?,
                    if array { "[*]" } else { "" }
                );
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
                            Operator::Eq | Operator::In | Operator::Ne | Operator::Out => "==",
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
                let body = format!("({})", terms.join(" || "));
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
