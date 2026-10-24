//! Asset wire syntax compiles once into the existing typed Criteria owner.
//! Saved definitions and jobs persist that definition, never an alternate parser language.
use super::*;
use rss_mdm_inventory::{Catalog, Kind};
use rss_mdm_query::{Expression, Operator as Op};
use serde::{Deserialize, Serialize};

pub static CONTRACT: rss_mdm_query::CatalogQuery = rss_mdm_query::CatalogQuery {
    id: "asset_queries",
    catalog_resource: "asset_fields",
    max_fields: 1024,
    max_sort: 16,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryScope {
    pub selector: ScopeSelector,
    pub quantifier: ScopeQuantifier,
}
impl Default for QueryScope {
    fn default() -> Self {
        Self {
            selector: ScopeSelector::Device,
            quantifier: ScopeQuantifier::One,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryInput {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub scope: QueryScope,
    #[serde(default)]
    pub fields: Vec<FieldKey>,
    #[serde(default)]
    pub sort: Vec<Sort>,
}
impl QueryInput {
    pub(super) fn compile(&self, catalog: &Catalog) -> Result<Query> {
        checked_input(CONTRACT.validate(self.fields.len(), self.sort.len()))?;
        let criteria = self
            .filter
            .as_ref()
            .map(|text| -> Result<_> {
                let expression = checked_input(rss_mdm_query::parse_filter(text))?;
                let condition = InventoryCondition {
                    selector: self.scope.selector.clone(),
                    quantifier: self.scope.quantifier,
                    criteria: bind(expression, catalog)?,
                };
                condition.validate()?;
                Ok(condition)
            })
            .transpose()?;
        // A scope without a predicate must not be silently discarded.
        if criteria.is_none()
            && (!matches!(self.scope.selector, ScopeSelector::Device)
                || self.scope.quantifier != ScopeQuantifier::One)
        {
            return Err(Error::Malformed.into());
        }
        Ok(Query {
            criteria,
            fields: self.fields.clone(),
            sort: self.sort.clone(),
        })
    }
    pub fn from_query(query: Query) -> Result<Self> {
        let (filter, scope) = match query.criteria {
            Some(c) => (
                Some(formatted(&c.criteria)?),
                QueryScope {
                    selector: c.selector,
                    quantifier: c.quantifier,
                },
            ),
            None => (None, QueryScope::default()),
        };
        Ok(Self {
            filter,
            scope,
            fields: query.fields,
            sort: query.sort,
        })
    }
}
fn scalar(kind: Kind, text: String) -> Result<Scalar> {
    let value = match kind {
        Kind::String => Scalar::String(text),
        Kind::Integer => Scalar::Integer(checked_input(text.parse())?),
        Kind::Time => Scalar::Time(checked_input(text.parse())?),
        Kind::Number => {
            // Deserialize through the canonical finite number type owned by Inventory.
            let number: serde_json::Number = checked_input(text.parse())?;
            checked_input(serde_json::from_value(
                serde_json::json!({"kind":"number","value":number}),
            ))?
        }
        Kind::Boolean => match text.as_str() {
            "true" => Scalar::Boolean(true),
            "false" => Scalar::Boolean(false),
            _ => return Err(Error::Malformed.into()),
        },
        Kind::Array | Kind::Object => return Err(Error::Malformed.into()),
    };
    checked_input(value.validate())?;
    Ok(value)
}
fn bind(expression: Expression<String, String>, catalog: &Catalog) -> Result<Criteria> {
    Ok(match expression {
        Expression::And(v) => Criteria::And {
            children: v
                .into_iter()
                .map(|e| bind(e, catalog))
                .collect::<Result<_>>()?,
        },
        Expression::Or(v) => Criteria::Or {
            children: v
                .into_iter()
                .map(|e| bind(e, catalog))
                .collect::<Result<_>>()?,
        },
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            let field = checked_input(FieldKey::parse(&field))?;
            let path = checked_input(catalog.path(field))?;
            let op = match operator {
                Op::Eq => Operator::Eq,
                Op::Ne => Operator::Ne,
                Op::Lt => Operator::Lt,
                Op::Le => Operator::Le,
                Op::Gt => Operator::Gt,
                Op::Ge => Operator::Ge,
                Op::In => Operator::In,
                Op::Out => Operator::NotIn,
                Op::Contains => Operator::Contains,
                Op::NotContains => Operator::NotContains,
                Op::ContainsAny => Operator::ContainsAny,
                Op::ContainsAll => Operator::ContainsAll,
                Op::IsNull => Operator::IsNull,
                Op::IsNotNull => Operator::IsNotNull,
                Op::Icontains => return Err(Error::Malformed.into()),
            };
            let (value, values) = if matches!(op, Operator::IsNull | Operator::IsNotNull) {
                if values != ["true"] {
                    return Err(Error::Malformed.into());
                }
                (None, None)
            } else if operator.set() {
                (
                    None,
                    Some(
                        values
                            .into_iter()
                            .map(|v| scalar(path.value_type.kind(), v))
                            .collect::<Result<_>>()?,
                    ),
                )
            } else {
                let [value]: [String; 1] = values.try_into().map_err(|_| Error::Malformed)?;
                (Some(scalar(path.value_type.kind(), value)?), None)
            };
            Criteria::Predicate {
                field,
                op,
                value,
                values,
            }
        }
    })
}
fn operand(value: &Scalar) -> Result<String> {
    let text = match value {
        Scalar::String(s) => s.clone(),
        Scalar::Integer(n) | Scalar::Time(n) => n.to_string(),
        Scalar::Number(n) => {
            let decimal = n.to_string();
            let scientific = format!("{:e}", n.into_inner());
            if scientific.len() < decimal.len() {
                scientific
            } else {
                decimal
            }
        }
        Scalar::Boolean(b) => b.to_string(),
        Scalar::Array(_) | Scalar::Object(_) => return Err(Error::Malformed.into()),
    };
    // Choose the shortest spelling accepted by our parser, including escaped
    // bare values. Mandatory quoting alone can expand an already full request.
    let mut spellings = Vec::with_capacity(3);
    if !text.is_empty()
        && !text.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '=' | '!' | '<' | '>' | '*')
        })
    {
        let mut bare = String::new();
        for c in text.chars() {
            if matches!(c, ',' | ';' | '(' | ')' | '\\' | '\'' | '"') {
                bare.push('\\');
            }
            bare.push(c);
        }
        spellings.push(bare);
    }
    for quote in ['\'', '"'] {
        let escaped = text
            .replace('\\', "\\\\")
            .replace(quote, &format!("\\{quote}"));
        spellings.push(format!("{quote}{escaped}{quote}"));
    }
    spellings
        .into_iter()
        .min_by_key(String::len)
        .ok_or_else(|| Error::Malformed.into())
}
// Both reads and pre-persistence admission use this boundary. A successfully
// saved definition must produce public syntax accepted by the same bounded parser.
fn formatted(criteria: &Criteria) -> Result<String> {
    let text = format(criteria, 0)?;
    checked_input(rss_mdm_query::parse_filter(&text))?;
    Ok(text)
}

fn format(criteria: &Criteria, parent: u8) -> Result<String> {
    Ok(match criteria {
        Criteria::And { children } | Criteria::Or { children } => {
            let separator = if matches!(criteria, Criteria::And { .. }) {
                ";"
            } else {
                ","
            };
            let precedence = if matches!(criteria, Criteria::And { .. }) {
                2
            } else {
                1
            };
            let text = children
                .iter()
                .map(|child| format(child, precedence))
                .collect::<Result<Vec<_>>>()?
                .join(separator);
            if precedence < parent {
                format!("({text})")
            } else {
                text
            }
        }
        Criteria::Predicate {
            field,
            op,
            value,
            values,
        } => {
            let token = match op {
                Operator::Eq => "==",
                Operator::Ne => "!=",
                Operator::Lt => "=lt=",
                Operator::Le => "=le=",
                Operator::Gt => "=gt=",
                Operator::Ge => "=ge=",
                Operator::In => "=in=",
                Operator::NotIn => "=out=",
                Operator::Contains => "=contains=",
                Operator::NotContains => "=notcontains=",
                Operator::ContainsAny => "=containsany=",
                Operator::ContainsAll => "=containsall=",
                Operator::IsNull => "=isnull=",
                Operator::IsNotNull => "=isnotnull=",
            };
            let operand = if let Some(values) = values {
                format!(
                    "({})",
                    values
                        .iter()
                        .map(operand)
                        .collect::<Result<Vec<_>>>()?
                        .join(",")
                )
            } else if let Some(value) = value {
                operand(value)?
            } else {
                "true".into()
            };
            format!("{}{token}{operand}", field.as_str())
        }
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredDefinition {
    name: String,
    query: Query,
}
impl StoredDefinition {
    pub(super) fn compile(input: &SavedDefinition, catalog: &Catalog) -> Result<Self> {
        let query = input.query.compile(catalog)?;
        if let Some(condition) = &query.criteria {
            formatted(&condition.criteria)?;
        }
        Ok(Self {
            name: input.name.clone(),
            query,
        })
    }
    pub(super) fn query(&self) -> &Query {
        &self.query
    }
    pub(super) fn into_view(self) -> Result<SavedDefinition> {
        Ok(SavedDefinition {
            name: self.name,
            query: QueryInput::from_query(self.query)?,
        })
    }
}

#[cfg(test)]
#[path = "../../tests/assets/rsql_unit.rs"]
mod tests;
