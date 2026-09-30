//! Read-only osquery templates. Parse, admit and bind literals before constructing executor arguments.
use crate::{Error, Platform};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use sqlparser::{ast::*, dialect::SQLiteDialect, parser::Parser};
use std::{collections::BTreeSet, ops::ControlFlow};

/// A bounded single-table SELECT against the product's audited osquery surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SqlTemplate(String);
impl TryFrom<String> for SqlTemplate {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::new(&s)
    }
}
impl From<SqlTemplate> for String {
    fn from(t: SqlTemplate) -> String {
        t.0
    }
}
impl SqlTemplate {
    /// Admit one SELECT. Joins, wildcard projection, subqueries, user limits and writes are rejected.
    pub fn new(sql: &str) -> Result<Self, Error> {
        let query = parse(sql)?;
        check(&query)?;
        Ok(Self(query.to_string()))
    }
    /// Canonical template text, also suitable for immutable artifact content.
    pub fn query(&self) -> &str {
        &self.0
    }
    /// Exact named placeholders; positional placeholders are not supported.
    pub fn parameters(&self) -> Result<BTreeSet<String>, Error> {
        Ok(check(&parse(&self.0)?)?.1)
    }
    /// Check table/platform applicability before dispatch.
    pub fn validate_platform(&self, platform: Platform) -> Result<(), Error> {
        platform_table(&check(&parse(&self.0)?)?.0, platform)
    }
    /// Bind JSON literals through the AST and add one overflow sentinel row.
    /// The consumer must mark max_rows+1 rows incomplete, never truncate into a full snapshot.
    pub fn render(&self, parameters: &Json, max_rows: u32) -> Result<String, Error> {
        if !(1..=100_000).contains(&max_rows) {
            return Err(Error::InvalidInput);
        }
        let mut query = parse(&self.0)?;
        let expected = check(&query)?.1;
        let values = parameters.as_object().ok_or(Error::InvalidInput)?;
        if values.len() > 32 || values.keys().cloned().collect::<BTreeSet<_>>() != expected {
            return Err(Error::InvalidInput);
        }
        struct Bind<'a>(&'a serde_json::Map<String, Json>);
        impl VisitorMut for Bind<'_> {
            type Break = Error;
            fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Error> {
                if let Expr::Value(v) = expr
                    && let Value::Placeholder(name) = &v.value
                {
                    let Some(name) = name.strip_prefix(':') else {
                        return ControlFlow::Break(Error::InvalidInput);
                    };
                    let literal = match self.0.get(name) {
                        Some(Json::String(s)) if s.len() <= 4096 && !s.contains('\0') => {
                            Value::SingleQuotedString(s.clone())
                        }
                        Some(Json::Bool(b)) => {
                            Value::Number(if *b { "1" } else { "0" }.into(), false)
                        }
                        Some(Json::Number(n)) if n.as_i64().is_some() => {
                            Value::Number(n.to_string(), false)
                        }
                        _ => return ControlFlow::Break(Error::InvalidInput),
                    };
                    *expr = Expr::Value(literal.into());
                }
                ControlFlow::Continue(())
            }
        }
        if let ControlFlow::Break(e) = VisitMut::visit(&mut query, &mut Bind(values)) {
            return Err(e);
        }
        query.limit_clause = Some(LimitClause::LimitOffset {
            limit: Some(Expr::Value(
                Value::Number((max_rows + 1).to_string(), false).into(),
            )),
            offset: None,
            limit_by: vec![],
        });
        let sql = query.to_string();
        if sql.len() > 65536 {
            return Err(Error::InvalidInput);
        }
        Ok(sql)
    }
    /// Independently validate the signed, already-bound query at the Agent execution boundary.
    pub fn validate_rendered(sql: &str, max_rows: u32, platform: Platform) -> Result<(), Error> {
        if !(1..=100_000).contains(&max_rows) {
            return Err(Error::InvalidInput);
        }
        let mut query = parse(sql)?;
        let Some(limit) = query.limit_clause.take() else {
            return Err(Error::InvalidInput);
        };
        if limit.to_string().trim() != format!("LIMIT {}", max_rows + 1) {
            return Err(Error::InvalidInput);
        }
        let (table, parameters) = check(&query)?;
        if !parameters.is_empty() {
            return Err(Error::InvalidInput);
        }
        platform_table(&table, platform)
    }
}
fn parse(sql: &str) -> Result<Query, Error> {
    if sql.len() > 65536 || sql.contains('\0') {
        return Err(Error::InvalidInput);
    }
    let mut statements = Parser::new(&SQLiteDialect {})
        .with_recursion_limit(32)
        .try_with_sql(sql)
        .map_err(|_| Error::InvalidInput)?
        .parse_statements()
        .map_err(|_| Error::InvalidInput)?;
    if statements.len() != 1 {
        return Err(Error::InvalidInput);
    }
    match statements.remove(0) {
        Statement::Query(q) => Ok(*q),
        _ => Err(Error::InvalidInput),
    }
}
fn identifier(id: &Ident) -> Result<&str, Error> {
    if id.quote_style.is_some()
        || id.value.is_empty()
        || id.value.len() > 64
        || !id.value.as_bytes()[0].is_ascii_lowercase()
        || !id
            .value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(Error::InvalidInput);
    }
    Ok(&id.value)
}
fn columns(table: &str) -> Result<&'static [&'static str], Error> {
    Ok(match table {
        "osquery_info" => &["version", "build_platform", "build_distro", "start_time"],
        "os_version" => &[
            "name", "version", "major", "minor", "patch", "build", "platform", "arch",
        ],
        "system_info" => &[
            "hostname",
            "uuid",
            "cpu_type",
            "cpu_brand",
            "cpu_physical_cores",
            "cpu_logical_cores",
            "physical_memory",
            "hardware_vendor",
            "hardware_model",
            "hardware_serial",
            "computer_name",
        ],
        "interface_addresses" => &[
            "interface",
            "address",
            "mask",
            "broadcast",
            "point_to_point",
            "type",
        ],
        "programs" => &[
            "name",
            "version",
            "publisher",
            "install_date",
            "identifying_number",
            "package_family_name",
        ],
        "apps" => &[
            "name",
            "path",
            "bundle_identifier",
            "bundle_name",
            "bundle_short_version",
            "bundle_version",
            "minimum_system_version",
            "category",
        ],
        _ => return Err(Error::InvalidInput),
    })
}
fn platform_table(table: &str, platform: Platform) -> Result<(), Error> {
    if matches!(
        (table, platform),
        ("programs", Platform::MacOS) | ("apps", Platform::Windows)
    ) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn check(query: &Query) -> Result<(String, BTreeSet<String>), Error> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(Error::InvalidInput);
    };
    if select.from.len() != 1 || !(1..=64).contains(&select.projection.len()) {
        return Err(Error::InvalidInput);
    }
    // Comparing the complete rendered query with the admitted shape rejects every
    // additional clause, including newly parsed syntax from a dependency update.
    let table = select.from[0].to_string();
    let allowed = columns(&table)?;
    let mut context = Expressions {
        columns: allowed,
        nodes: 0,
        parameters: BTreeSet::new(),
    };
    let mut names = BTreeSet::new();
    for item in &select.projection {
        let name = match item {
            SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                context.check(&Expr::Identifier(id.clone()), 0)?;
                identifier(id)?.to_owned()
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                context.check(expr, 0)?;
                identifier(alias)?.to_owned()
            }
            _ => return Err(Error::InvalidInput),
        };
        if !names.insert(name) {
            return Err(Error::InvalidInput);
        }
    }
    let mut admitted = format!(
        "SELECT {} FROM {}",
        select
            .projection
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        table
    );
    if let Some(expr) = &select.selection {
        context.check(expr, 0)?;
        admitted.push_str(&format!(" WHERE {expr}"));
    }
    if query.to_string() != admitted {
        return Err(Error::InvalidInput);
    }
    Ok((table, context.parameters))
}
struct Expressions {
    columns: &'static [&'static str],
    nodes: usize,
    parameters: BTreeSet<String>,
}
impl Expressions {
    fn check(&mut self, expr: &Expr, depth: usize) -> Result<(), Error> {
        self.nodes += 1;
        if self.nodes > 256 || depth > 16 {
            return Err(Error::InvalidInput);
        }
        match expr {
            Expr::Identifier(id) if self.columns.contains(&identifier(id)?) => (),
            Expr::Value(v) => match &v.value {
                Value::SingleQuotedString(s) if s.len() <= 4096 && !s.contains('\0') => (),
                Value::Number(n, false)
                    if n.len() <= 64 && n.parse::<f64>().is_ok_and(f64::is_finite) =>
                {
                    ()
                }
                Value::Boolean(_) | Value::Null => (),
                Value::Placeholder(p) => {
                    let name = p.strip_prefix(':').ok_or(Error::InvalidInput)?;
                    let id = Ident::new(name);
                    identifier(&id)?;
                    self.parameters.insert(name.into());
                    if self.parameters.len() > 32 {
                        return Err(Error::InvalidInput);
                    }
                }
                _ => return Err(Error::InvalidInput),
            },
            Expr::Nested(e) | Expr::IsNull(e) | Expr::IsNotNull(e) => self.check(e, depth + 1)?,
            Expr::UnaryOp {
                op: UnaryOperator::Not | UnaryOperator::Minus | UnaryOperator::Plus,
                expr,
            } => self.check(expr, depth + 1)?,
            Expr::BinaryOp { left, op, right }
                if matches!(
                    op,
                    BinaryOperator::Eq
                        | BinaryOperator::NotEq
                        | BinaryOperator::Lt
                        | BinaryOperator::LtEq
                        | BinaryOperator::Gt
                        | BinaryOperator::GtEq
                        | BinaryOperator::And
                        | BinaryOperator::Or
                ) =>
            {
                self.check(left, depth + 1)?;
                self.check(right, depth + 1)?;
            }
            Expr::InList { expr, list, .. } if list.len() <= 32 => {
                self.check(expr, depth + 1)?;
                for e in list {
                    self.check(e, depth + 1)?;
                }
            }
            Expr::Function(f) => {
                let name = f.name.to_string();
                if !matches!(name.as_str(), "lower" | "upper" | "length" | "coalesce") {
                    return Err(Error::InvalidInput);
                }
                let FunctionArguments::List(args) = &f.args else {
                    return Err(Error::InvalidInput);
                };
                if !(1..=4).contains(&args.args.len()) {
                    return Err(Error::InvalidInput);
                }
                let mut rendered = Vec::new();
                for arg in &args.args {
                    let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg else {
                        return Err(Error::InvalidInput);
                    };
                    self.check(e, depth + 1)?;
                    rendered.push(e.to_string());
                }
                if f.to_string() != format!("{name}({})", rendered.join(", ")) {
                    return Err(Error::InvalidInput);
                }
            }
            _ => return Err(Error::InvalidInput),
        }
        Ok(())
    }
}
