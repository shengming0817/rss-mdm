//! JSON transport for generated native fields. Dates/data are interpreted only by schema.
use super::*;
use base64::Engine;
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use std::fmt;

pub(super) fn decode(bytes: &[u8]) -> Result<serde_json::Value, Error> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let value = serde_json::from_slice::<NativeJson>(bytes)
        .map_err(|_| Error::Encoding)?
        .0;
    let mut pending = vec![(&value, 0)];
    let mut nodes = 0;
    while let Some((v, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 65_536 || depth > 64 {
            return Err(Error::Limit);
        }
        match v {
            serde_json::Value::Object(v) => pending.extend(v.values().map(|v| (v, depth + 1))),
            serde_json::Value::Array(v) => pending.extend(v.iter().map(|v| (v, depth + 1))),
            _ => {}
        }
    }
    Ok(value)
}
struct NativeJson(serde_json::Value);
impl<'de> Deserialize<'de> for NativeJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct NativeVisitor;
        impl<'de> Visitor<'de> for NativeVisitor {
            type Value = NativeJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded native JSON")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<NativeJson, E> {
                Ok(NativeJson(serde_json::Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<NativeJson, E> {
                Ok(NativeJson(serde_json::Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<NativeJson, E> {
                Ok(NativeJson(serde_json::Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<NativeJson, E> {
                Ok(NativeJson(serde_json::Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<NativeJson, E> {
                Ok(NativeJson(serde_json::Value::Number(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| E::custom("native JSON number"))?,
                )))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<NativeJson, E> {
                Ok(NativeJson(serde_json::Value::String(v.into())))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<NativeJson, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<NativeJson>()? {
                    if values.len() == 65_536 {
                        return Err(A::Error::custom("native JSON budget"));
                    }
                    values.push(v.0);
                }
                Ok(NativeJson(serde_json::Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<NativeJson, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, NativeJson>()? {
                    if values.len() == 65_536 || values.insert(k, v.0).is_some() {
                        return Err(A::Error::custom("duplicate native key or JSON budget"));
                    }
                }
                Ok(NativeJson(serde_json::Value::Object(values)))
            }
        }
        d.deserialize_any(NativeVisitor)
    }
}
pub(super) fn fields(
    d: &Definition,
    ids: &[usize],
    values: &Dictionary,
    target: &Target<'_>,
) -> Result<Dictionary, Error> {
    values
        .iter()
        .map(|(key, value)| {
            let field = ids
                .iter()
                .map(|&i| &d.fields[i])
                .find(|f| f.key == key)
                .or_else(|| ids.iter().map(|&i| &d.fields[i]).find(|f| f.key == "ANY"))
                .ok_or(Error::Field)?;
            Ok((key.clone(), native(d, field, value, target, 0)?))
        })
        .collect()
}
fn native(
    d: &Definition,
    f: &Field,
    value: &Value,
    target: &Target<'_>,
    depth: usize,
) -> Result<Value, Error> {
    if depth > 64 {
        return Err(Error::Limit);
    }
    let rule = f.active(target)?;
    Ok(match (rule.atom, value) {
        (Atom::Date, Value::String(s)) => {
            Value::Date(plist::Date::from_xml_format(s).map_err(|_| Error::Constraint)?)
        }
        (Atom::Data, Value::String(s)) => Value::Data(
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| Error::Constraint)?,
        ),
        (Atom::Dictionary, Value::Dictionary(values)) if !rule.children.is_empty() => {
            let mut out = Dictionary::new();
            for (k, v) in values {
                let field = rule
                    .children
                    .iter()
                    .map(|&i| &d.fields[i])
                    .find(|f| f.key == k)
                    .or_else(|| {
                        rule.children
                            .iter()
                            .map(|&i| &d.fields[i])
                            .find(|f| f.key == "ANY")
                    })
                    .ok_or(Error::Field)?;
                out.insert(k.clone(), native(d, field, v, target, depth + 1)?);
            }
            Value::Dictionary(out)
        }
        (Atom::Array, Value::Array(values)) if !rule.children.is_empty() => {
            let mut out = Vec::with_capacity(values.len());
            for v in values {
                let mut accepted = None;
                for &id in rule.children {
                    if let Ok(candidate) = native(d, &d.fields[id], v, target, depth + 1)
                        && validation::check_field(
                            d,
                            &d.fields[id],
                            &candidate,
                            target,
                            rule.conditions.inherit(d.active(target)?.conditions),
                            depth + 1,
                        )
                        .is_ok()
                    {
                        accepted = Some(candidate);
                        break;
                    }
                }
                out.push(accepted.ok_or(Error::Constraint)?);
            }
            Value::Array(out)
        }
        _ => value.clone(),
    })
}

pub(super) fn plist(value: &serde_json::Value) -> Result<Value, Error> {
    use serde_json::Value as J;
    Ok(match value {
        J::Null => return Err(Error::Field),
        J::Bool(v) => Value::Boolean(*v),
        J::String(v) => Value::String(v.clone()),
        J::Number(v) => {
            if let Some(v) = v.as_u64() {
                Value::Integer(v.into())
            } else if let Some(v) = v.as_i64() {
                Value::Integer(v.into())
            } else {
                Value::Real(v.as_f64().ok_or(Error::Field)?)
            }
        }
        J::Array(v) => Value::Array(v.iter().map(plist).collect::<Result<_, _>>()?),
        J::Object(v) => Value::Dictionary(
            v.iter()
                .map(|(k, v)| Ok((k.clone(), plist(v)?)))
                .collect::<Result<_, Error>>()?,
        ),
    })
}
