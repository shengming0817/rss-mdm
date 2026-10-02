use super::{Constraint, Context, Error, Format, Node, Value, Verb};
use base64::Engine;

pub(super) fn compile(
    node: &Node,
    verb: Verb,
    value: Option<Value>,
    target: Context,
) -> Result<Option<String>, Error> {
    if matches!(verb, Verb::Get | Verb::Delete) {
        return if value.is_none() {
            Ok(None)
        } else {
            Err(Error::Value)
        };
    }
    if let Some(constraint) = node.constraints.iter().find(|c| c.kind == "ADMX") {
        let Some(Value::Admx(value)) = value else {
            return Err(Error::Value);
        };
        let (file, name) = constraint.admx.ok_or(Error::UnresolvedConstraint)?;
        return super::admx::compile(file, name, value, target).map(Some);
    }
    if matches!(node.format, Format::Node | Format::Null) {
        return if value.is_none() {
            Ok(None)
        } else {
            Err(Error::Value)
        };
    }
    let value = match (node.format, value.ok_or(Error::Value)?) {
        (Format::Text, Value::Text(v)) | (Format::Xml, Value::Xml(v)) => v,
        (Format::Integer, Value::Integer(v)) => v.to_string(),
        (Format::Boolean, Value::Boolean(v)) => v.to_string(),
        (Format::Base64, Value::Bytes(v)) => {
            if v.len() > crate::CodecLimits::default().decoded_object_bytes {
                return Err(Error::Limit);
            }
            base64::engine::general_purpose::STANDARD.encode(v)
        }
        (Format::Time, Value::Time(v)) => {
            time::Time::parse(&v, &time::format_description::well_known::Iso8601::DEFAULT)
                .map_err(|_| Error::Value)?;
            v
        }
        (Format::Binary, _) => return Err(Error::UnresolvedConstraint),
        _ => return Err(Error::Value),
    };
    if value.len() > crate::CodecLimits::default().object_bytes {
        return Err(Error::Limit);
    }
    if node.format == Format::Xml {
        validate_xml(&value)?;
    }
    for constraint in node.constraints {
        check(constraint, &value, node.format)?;
    }
    Ok(Some(value))
}

fn check(c: &Constraint, value: &str, format: Format) -> Result<(), Error> {
    let delimiter = c
        .delimiter
        .map(|raw| {
            if let Some(hex) = raw.strip_prefix("0x") {
                u32::from_str_radix(hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(|c| c.to_string())
                    .ok_or(Error::UnresolvedConstraint)
            } else if raw.is_empty() {
                Err(Error::UnresolvedConstraint)
            } else {
                Ok(raw.to_owned())
            }
        })
        .transpose()?;
    for part in delimiter
        .as_ref()
        .map(|d| value.split(d).collect())
        .unwrap_or_else(|| vec![value])
    {
        check_one(c, part, format)?;
    }
    Ok(())
}

fn check_one(c: &Constraint, value: &str, format: Format) -> Result<(), Error> {
    match c.kind {
        "None" => Ok(()),
        "ENUM" => {
            if c.values.iter().any(|allowed| {
                if format == Format::Integer {
                    integer(allowed)
                        .ok()
                        .zip(integer(value).ok())
                        .is_some_and(|(a, b)| a == b)
                } else {
                    *allowed == value
                }
            }) {
                Ok(())
            } else {
                Err(Error::Value)
            }
        }
        "Range" => {
            let number = integer(value)?;
            for raw in c.values {
                let (min, max) = range(raw)?;
                if number < min || number > max {
                    return Err(Error::Value);
                }
            }
            Ok(())
        }
        "Flag" => {
            let mask = c
                .values
                .iter()
                .try_fold(0i64, |mask, v| integer(v).map(|v| mask | v))?;
            let value = integer(value)?;
            if value < 0 || value & !mask != 0 {
                Err(Error::Value)
            } else {
                Ok(())
            }
        }
        "RegEx" => {
            for pattern in c.values {
                if pattern.is_empty() {
                    return Err(Error::UnresolvedConstraint);
                }
                let pattern = pattern
                    .strip_prefix('/')
                    .and_then(|s| s.strip_suffix('/'))
                    .unwrap_or(pattern);
                let expression = regex::RegexBuilder::new(&format!("\\A(?:{pattern})\\z"))
                    .size_limit(256 * 1024)
                    .dfa_size_limit(256 * 1024)
                    .build()
                    .map_err(|_| Error::UnresolvedConstraint)?;
                if !expression.is_match(value) {
                    return Err(Error::Value);
                }
            }
            Ok(())
        }
        "ADMX" => {
            let _identity = c.admx.ok_or(Error::UnresolvedConstraint)?;
            Err(Error::UnresolvedConstraint)
        }
        "XSD" => {
            if c.values.is_empty() {
                return Err(Error::UnresolvedConstraint);
            }
            for schema in c.values {
                super::xsd::validate(schema, value)?;
            }
            Ok(())
        }
        "SDDL" | "JSON" => Err(Error::UnresolvedConstraint),
        _ => Err(Error::UnresolvedConstraint),
    }
}

fn integer(raw: &str) -> Result<i64, Error> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|_| Error::Value)
    } else {
        raw.parse().map_err(|_| Error::Value)
    }
}
fn range(raw: &str) -> Result<(i64, i64), Error> {
    let raw = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(Error::UnresolvedConstraint)?;
    let clean = raw.replace(['(', ')'], "");
    let (min, max) = clean
        .rsplit_once('-')
        .or_else(|| clean.split_once(','))
        .ok_or(Error::UnresolvedConstraint)?;
    Ok((integer(min)?, integer(max)?))
}

fn validate_xml(value: &str) -> Result<(), Error> {
    let limits = crate::CodecLimits {
        field_bytes: crate::CodecLimits::default().object_bytes,
        ..Default::default()
    };
    crate::xml::document(value.as_bytes(), limits.object_bytes, &limits).map_err(|error| {
        if error == crate::CodecError::LimitExceeded {
            Error::Limit
        } else {
            Error::Value
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_ranges_preserve_signed_and_unsigned_boundaries() {
        assert_eq!(range("[(-1)-4294967295]").unwrap(), (-1, 4_294_967_295));
        assert_eq!(range("[0,4320]").unwrap(), (0, 4320));
        assert_eq!(integer("0xffffffff").unwrap(), 4_294_967_295);
    }
    #[test]
    fn xml_rejects_external_entities_and_multiple_roots() {
        for bad in [
            "<!DOCTYPE a SYSTEM 'https://bad'><a/>",
            "<a/><b/>",
            "<a>&unknown;</a>",
            "<a>",
            "<x:a/>",
        ] {
            assert!(validate_xml(bad).is_err());
        }
        assert!(validate_xml("<a value='x &amp; y'><b/></a>").is_ok());
    }
}
