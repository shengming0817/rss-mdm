//! Transport declarations supplied by the middleware owner, never authentication execution.
use crate::signature::Schema;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct Description {
    pub owner: &'static str,
    /// Exactly one credential presentation is accepted; mixing presentations is rejected.
    pub alternatives: Vec<Credential>,
    pub conditional_response_headers: Vec<ConditionalHeader>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Credential {
    pub kind: &'static str,
    pub owner: &'static str,
    pub headers: BTreeMap<String, Schema>,
    pub required_headers: Vec<&'static str>,
    pub constraints: Vec<&'static str>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ConditionalHeader {
    pub status: u16,
    pub name: &'static str,
    pub value: &'static str,
    pub request_header_present: &'static str,
    pub request_headers_absent: Vec<&'static str>,
}
