//! A bound JSONPath predicate for Identity's static, read-only SELECT capability.
//! The field catalog checks names/operators first; values remain JSON literals.
use rss_mdm_query::{
    Expression, Operator,
    directory::{Field, Kind, Query, Schema},
};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema {
    id: "device_views",
    keys: &["key"],
    default_limit: 64,
    max_limit: 100,
    fields: vec![
        Field::scalar("key", Kind::Text),
        Field::filter_only(
            "status",
            Kind::enumeration(&[
                "active",
                "pending",
                "revoked",
                "superseded",
                "registered",
                "cancelled",
                "expired",
            ]),
        ),
        Field::filter_only("assetState", Kind::enumeration(&["active", "archived", "deleted"])),
        Field::filter_only("channel", Kind::enum_set(&["mdm", "agent"])),
        Field::filter_only(
            "source",
            Kind::enum_set(&["mdm.windows", "mdm.apple", "agent.builtin"]),
        ),
        Field::filter_only("platform", Kind::enum_set(&["windows", "macos"])),
        Field::filter_only("search", Kind::Text),
        Field::output("reference").excluded("Object identity is selected through the canonical key selector"),
        Field::output("association").excluded("Association evidence includes domain state and hardware maps; use the association directory"),
        Field::output("endpoints").excluded("Endpoint object arrays use the existing whole-expression per-endpoint selectors; arbitrary child expansion is not supported"),
    ],
}
});
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
