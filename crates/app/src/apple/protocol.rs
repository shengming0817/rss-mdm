//! Bounded native plist decoding; no SyncML status or identity translation.
//! ref: apple/device-management mdm/checkin and mdm/commands@09f249a06e7e3289930bf6d05f38fb562f748ebf
use crate::Error;
use plist::{Dictionary, Value};
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::fmt;
use uuid::Uuid;

struct Bounded(Value);
struct Seed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}
impl<'de> Deserialize<'de> for Bounded {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Seed {
            depth: 0,
            remaining: &mut 8192,
        }
        .deserialize(d)
        .map(Self)
    }
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.depth > 16 || *self.remaining == 0 {
            return Err(de::Error::custom("plist limit"));
        }
        *self.remaining -= 1;
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded native plist")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        let mut out = Dictionary::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate plist key"));
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            out.insert(key, value);
        }
        Ok(Value::Dictionary(out))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Value, S::Error> {
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            depth: self.depth + 1,
            remaining: self.remaining,
        })? {
            out.push(value);
        }
        Ok(Value::Array(out))
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        if v.is_finite() {
            Ok(v.into())
        } else {
            Err(E::custom("non-finite real"))
        }
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Value, E> {
        Ok(Value::Data(v.to_vec()))
    }
    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Value, E> {
        Ok(Value::Data(v))
    }
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Dictionary, Error> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(Error::Malformed);
    }
    let Bounded(value) = plist::from_bytes(bytes).map_err(|_| Error::Malformed)?;
    value.into_dictionary().ok_or(Error::Malformed)
}
pub(crate) fn xml(dict: Dictionary) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    Value::Dictionary(dict)
        .to_writer_xml(&mut bytes)
        .map_err(|_| Error::Malformed)?;
    Ok(bytes)
}
pub(crate) fn dictionary(items: impl IntoIterator<Item = (&'static str, Value)>) -> Dictionary {
    items
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}
pub(crate) fn text<'a>(d: &'a Dictionary, key: &str) -> Result<&'a str, Error> {
    d.get(key)
        .and_then(Value::as_string)
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .ok_or(Error::Malformed)
}
pub(crate) fn device(d: &Dictionary) -> Result<&str, Error> {
    if d.contains_key("UserID") || d.contains_key("UserLongName") || d.contains_key("UserShortName")
    {
        return Err(Error::Unsupported);
    }
    let id = text(d, "UDID")?;
    if id.len() > 255 {
        return Err(Error::Malformed);
    }
    Ok(id)
}
pub(crate) enum CheckIn<'a> {
    Authenticate {
        udid: &'a str,
        topic: &'a str,
    },
    TokenUpdate {
        udid: &'a str,
        topic: &'a str,
        token: &'a [u8],
        magic: &'a str,
    },
    CheckOut {
        udid: &'a str,
    },
    UserAuthenticate,
}
pub(crate) fn checkin(d: &Dictionary) -> Result<CheckIn<'_>, Error> {
    let kind = text(d, "MessageType")?;
    if kind == "UserAuthenticate" {
        text(d, "UDID")?;
        return Ok(CheckIn::UserAuthenticate);
    }
    let udid = device(d)?;
    match kind {
        "Authenticate" => Ok(CheckIn::Authenticate {
            udid,
            topic: text(d, "Topic")?,
        }),
        "TokenUpdate" => {
            let token = d
                .get("Token")
                .and_then(Value::as_data)
                .filter(|v| !v.is_empty() && v.len() <= 512)
                .ok_or(Error::Malformed)?;
            Ok(CheckIn::TokenUpdate {
                udid,
                topic: text(d, "Topic")?,
                token,
                magic: text(d, "PushMagic")?,
            })
        }
        "CheckOut" => Ok(CheckIn::CheckOut { udid }),
        _ => Err(Error::Unsupported),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Idle,
    Acknowledged,
    Error,
    NotNow,
}
pub(crate) struct Management<'a> {
    pub udid: &'a str,
    pub status: Status,
    pub command: Option<Uuid>,
}
pub(crate) fn management(d: &Dictionary) -> Result<Management<'_>, Error> {
    let udid = device(d)?;
    let status = match text(d, "Status")? {
        "Idle" => Status::Idle,
        "Acknowledged" => Status::Acknowledged,
        "Error" | "CommandFormatError" => Status::Error,
        "NotNow" => Status::NotNow,
        _ => return Err(Error::Malformed),
    };
    let command = if status == Status::Idle {
        if d.contains_key("CommandUUID") {
            return Err(Error::Malformed);
        }
        None
    } else {
        Some(Uuid::parse_str(text(d, "CommandUUID")?).map_err(|_| Error::Malformed)?)
    };
    Ok(Management {
        udid,
        status,
        command,
    })
}
pub(crate) fn command(id: Uuid, payload: Dictionary) -> Result<Vec<u8>, Error> {
    xml(dictionary([
        ("CommandUUID", id.to_string().into()),
        ("Command", payload.into()),
    ]))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_keys_are_unique_and_nested_input_is_bounded() {
        let duplicate = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>UDID</key><string>a</string><key>UDID</key><string>b</string></dict></plist>";
        assert!(decode(duplicate).is_err());
        let deep = format!(
            "<plist>{}x{}</plist>",
            "<array>".repeat(128),
            "</array>".repeat(128)
        );
        assert!(decode(deep.as_bytes()).is_err());
    }
    #[test]
    fn acknowledgement_requires_correlation_and_user_messages_do_not_become_devices() {
        let message =
            |xml: &str| format!("<plist version=\"1.0\"><dict>{xml}</dict></plist>").into_bytes();
        assert!(management(&decode(&message("<key>UDID</key><string>d</string><key>Status</key><string>Acknowledged</string>")).unwrap()).is_err());
        let user = decode(&message("<key>UDID</key><string>d</string><key>UserID</key><string>user</string><key>Status</key><string>Idle</string>")).unwrap();
        assert!(management(&user).is_err());
    }
}
