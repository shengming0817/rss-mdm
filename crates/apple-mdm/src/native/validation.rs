use super::*;

struct Budget {
    nodes: usize,
    bytes: usize,
}
impl Budget {
    fn charge(&mut self, bytes: usize, depth: usize) -> Result<(), Error> {
        self.nodes = self.nodes.checked_add(1).ok_or(Error::Limit)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Error::Limit)?;
        if depth > 64 || self.nodes > 65_536 || self.bytes > 16 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        Ok(())
    }
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), Error> {
        self.charge(0, depth)?;
        match value {
            Value::String(s) => self.charge(s.len(), depth),
            Value::Data(b) => self.charge(b.len(), depth),
            Value::Dictionary(d) => {
                for (key, value) in d {
                    self.charge(key.len(), depth)?;
                    self.value(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Array(a) => {
                for value in a {
                    self.value(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Real(v) if !v.is_finite() => Err(Error::Constraint),
            Value::Boolean(_) | Value::Integer(_) | Value::Real(_) | Value::Date(_) => Ok(()),
            _ => Err(Error::Field),
        }
    }
}

pub(super) fn dictionary(
    definition: &Definition,
    fields: &[usize],
    value: &Dictionary,
    target: &Target<'_>,
) -> Result<(), Error> {
    let mut budget = Budget { nodes: 0, bytes: 0 };
    for (key, child) in value {
        budget.charge(key.len(), 0)?;
        budget.value(child, 1)?;
    }
    let mut conditions = definition.active(target)?.conditions;
    if definition.kind == Kind::Command && definition.identity == "DeviceInformation" {
        conditions.access_rights = None;
    }
    conditions.check(target)?;
    check_dictionary(definition, fields, value, target, conditions, 0)
}

fn check_dictionary(
    d: &Definition,
    fields: &[usize],
    values: &Dictionary,
    target: &Target<'_>,
    parent: Conditions,
    depth: usize,
) -> Result<(), Error> {
    if depth > 64 {
        return Err(Error::Limit);
    }
    for &id in fields {
        let field = d.fields.get(id).ok_or(Error::InvalidSchema)?;
        let rule = match field.active(target) {
            Ok(rule) => rule,
            Err(Error::Unsupported) => continue,
            Err(error) => return Err(error),
        };
        if field.key != "ANY" && rule.required && !values.contains_key(field.key) {
            match rule.conditions.inherit(parent).check(target) {
                Err(
                    Error::Unsupported
                    | Error::Applicability(crate::applicability::Rejection::Unsupported(_)),
                ) => continue,
                result => result?,
            }
            return Err(Error::Field);
        }
    }
    for (key, value) in values {
        let field = fields
            .iter()
            .map(|&i| &d.fields[i])
            .find(|f| f.key == key)
            .or_else(|| {
                fields
                    .iter()
                    .map(|&i| &d.fields[i])
                    .find(|f| f.key == "ANY")
            })
            .ok_or(Error::Field)?;
        check_field(d, field, value, target, parent, depth + 1)?;
    }
    Ok(())
}

pub(super) fn check_field(
    d: &Definition,
    field: &Field,
    value: &Value,
    target: &Target<'_>,
    parent: Conditions,
    depth: usize,
) -> Result<(), Error> {
    if depth > 64 {
        return Err(Error::Limit);
    }
    let field = field.active(target)?;
    let mut conditions = field.conditions.inherit(parent);
    if d.kind == Kind::Command
        && d.identity == "DeviceInformation"
        && !field.children.is_empty()
        && conditions.access_rights == Some("Special Case")
    {
        conditions.access_rights = None;
    }
    conditions.check(target)?;
    let valid_type = matches!(
        (field.atom, value),
        (Atom::String, Value::String(_))
            | (Atom::Integer, Value::Integer(_))
            | (Atom::Real, Value::Real(_))
            | (Atom::Boolean, Value::Boolean(_))
            | (Atom::Date, Value::Date(_))
            | (Atom::Data, Value::Data(_))
            | (Atom::Array, Value::Array(_))
            | (Atom::Dictionary, Value::Dictionary(_))
            | (Atom::Any, _)
    );
    if !valid_type {
        return Err(Error::Field);
    }
    scalar_constraints(field, value)?;
    match value {
        Value::String(text) if !field.children.is_empty() => {
            let child = field
                .children
                .iter()
                .map(|&i| &d.fields[i])
                .find(|f| f.key == text)
                .ok_or(Error::Constraint)?;
            child
                .active(target)?
                .conditions
                .inherit(conditions)
                .check(target)?;
        }
        Value::Dictionary(values) if !field.children.is_empty() => {
            check_dictionary(d, field.children, values, target, conditions, depth + 1)?
        }
        Value::Array(values) => {
            cardinality(field, values.len())?;
            if !field.children.is_empty() {
                for value in values {
                    // Native arrays may describe alternative item types. Acceptance requires
                    // one complete alternative, never merely a matching primitive type.
                    let mut accepted = false;
                    for &child in field.children {
                        if check_field(d, &d.fields[child], value, target, conditions, depth + 1)
                            .is_ok()
                        {
                            accepted = true;
                            break;
                        }
                    }
                    if !accepted {
                        return Err(Error::Constraint);
                    }
                }
            }
        }
        _ => {}
    }
    if !field.asset_types.is_empty() && !matches!(value, Value::String(_)) {
        return Err(Error::Constraint);
    }
    Ok(())
}

fn scalar_constraints(field: &FieldRule, value: &Value) -> Result<(), Error> {
    let text = match value {
        Value::String(s) => Some(s.clone()),
        Value::Boolean(v) => Some(v.to_string()),
        Value::Integer(v) => Some(v.to_string()),
        Value::Real(v) => Some(v.to_string()),
        _ => None,
    };
    if !field.range.is_empty()
        && let Some(text) = &text
        && !field.range.contains(&text.as_str())
    {
        return Err(Error::Constraint);
    }
    if field.min.is_some() || field.max.is_some() {
        match value {
            Value::Integer(v) => {
                let numeric = v
                    .to_string()
                    .parse::<i128>()
                    .map_err(|_| Error::Constraint)?;
                bounds(numeric, field.min, field.max)?;
            }
            Value::Real(v) if v.is_finite() => bounds(*v, field.min, field.max)?,
            _ => return Err(Error::Constraint),
        }
    }
    if let Some(pattern) = field.format {
        let regex = regex::Regex::new(pattern).map_err(|_| Error::InvalidSchema)?;
        if !regex.is_match(text.as_ref().ok_or(Error::Constraint)?) {
            return Err(Error::Constraint);
        }
    }
    if let Some(value_type) = field.value_type {
        let text = text.as_ref().ok_or(Error::Constraint)?;
        match value_type {
            "<url>" => {
                url::Url::parse(text).map_err(|_| Error::Constraint)?;
            }
            "<hostname>" => {
                url::Host::parse(text).map_err(|_| Error::Constraint)?;
            }
            _ => return Err(Error::InvalidSchema),
        }
    }
    Ok(())
}

fn bounds<T: std::str::FromStr + PartialOrd>(
    value: T,
    min: Option<&str>,
    max: Option<&str>,
) -> Result<(), Error> {
    let min = min
        .map(str::parse::<T>)
        .transpose()
        .map_err(|_| Error::InvalidSchema)?;
    let max = max
        .map(str::parse::<T>)
        .transpose()
        .map_err(|_| Error::InvalidSchema)?;
    if min.is_some_and(|min| value < min) || max.is_some_and(|max| value > max) {
        Err(Error::Constraint)
    } else {
        Ok(())
    }
}

fn cardinality(field: &FieldRule, count: usize) -> Result<(), Error> {
    if field
        .min_items
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| Error::InvalidSchema)?
        .is_some_and(|n| count < n)
        || field
            .max_items
            .map(str::parse::<usize>)
            .transpose()
            .map_err(|_| Error::InvalidSchema)?
            .is_some_and(|n| count > n)
    {
        return Err(Error::Constraint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integer_constraints_do_not_round_through_binary_floating_point() {
        let field = FieldRule {
            atom: Atom::Integer,
            required: true,
            conditions: Conditions::INHERIT,
            children: &[],
            range: &[],
            min: None,
            max: Some("9007199254740992"),
            format: None,
            value_type: None,
            min_items: None,
            max_items: None,
            asset_types: &[],
            asset_content_types: &[],
        };
        assert!(
            scalar_constraints(&field, &Value::Integer(9_007_199_254_740_992u64.into())).is_ok()
        );
        assert_eq!(
            scalar_constraints(&field, &Value::Integer(9_007_199_254_740_993u64.into())),
            Err(Error::Constraint)
        );
    }
}
