use crate::{Error, Result, Sort};
use rss_contract::PageCursor;
use std::collections::BTreeMap;

/// Strict URL query decoding. Resource budgets for limit/sort/fields remain with the resource.
#[derive(Debug)]
pub struct Parameters {
    pub filter: Option<String>,
    pub sort: Vec<Sort<String>>,
    pub fields: Option<Vec<String>>,
    pub limit: Option<u16>,
    pub cursor: Option<PageCursor>,
}
impl Parameters {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > crate::MAX_RAW_QUERY_BYTES {
            return Err(Error::Budget);
        }
        let mut values = BTreeMap::new();
        if !raw.is_empty() {
            for pair in raw.split('&') {
                let (key, value) = pair.split_once('=').ok_or(Error::Invalid)?;
                let key = decode(key)?;
                if !matches!(
                    key.as_str(),
                    "filter" | "sort" | "fields" | "limit" | "cursor"
                ) {
                    return Err(Error::Invalid);
                }
                let value = decode(value)?;
                if value.is_empty() || values.insert(key, value).is_some() {
                    return Err(Error::Invalid);
                }
            }
        }
        let filter = values.remove("filter");
        if filter
            .as_ref()
            .is_some_and(|v| v.len() > crate::MAX_FILTER_BYTES)
        {
            return Err(Error::Budget);
        }
        let sort = values
            .remove("sort")
            .map(|s| {
                names(&s).map(|v| {
                    v.into_iter()
                        .map(|name| {
                            let descending = name.starts_with('-');
                            Sort {
                                field: name.strip_prefix('-').unwrap_or(&name).to_owned(),
                                descending,
                            }
                        })
                        .collect()
                })
            })
            .transpose()?
            .unwrap_or_default();
        let fields = values.remove("fields").map(|s| names(&s)).transpose()?;
        let limit = values
            .remove("limit")
            .map(|s| {
                if !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Invalid);
                }
                s.parse().map_err(|_| Error::Invalid)
            })
            .transpose()?;
        let cursor = values
            .remove("cursor")
            .map(|s| PageCursor::parse(&s).map_err(|_| Error::Invalid))
            .transpose()?;
        Ok(Self {
            filter,
            sort,
            fields,
            limit,
            cursor,
        })
    }
}
fn names(raw: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for name in raw.split(',') {
        if result.len() == 16 {
            return Err(Error::Budget);
        }
        if name.is_empty() || name.len() > 128 || result.iter().any(|v| v == name) {
            return Err(Error::Invalid);
        }
        result.push(name.to_owned());
    }
    Ok(result)
}
fn decode(raw: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut input = raw.bytes();
    while let Some(b) = input.next() {
        bytes.push(match b {
            b'+' => b' ',
            b'%' => {
                let hi = input.next().and_then(hex).ok_or(Error::Invalid)?;
                let lo = input.next().and_then(hex).ok_or(Error::Invalid)?;
                hi * 16 + lo
            }
            _ => b,
        });
    }
    String::from_utf8(bytes).map_err(|_| Error::Invalid)
}
fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|n| n as u8)
}
