#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
#![allow(
    dead_code,
    reason = "capability fixtures have multiple independent test consumers"
)]
//! Shared setup only. Assertions remain with each capability's tests.
pub(crate) mod authority;
pub(crate) mod task_signature;
pub(crate) use crate::publication_support::pg::case;
pub(crate) mod identity;
pub(crate) mod pki;
pub(crate) use crate::config::Config;
pub(crate) use crate::publication_support;
pub(crate) use anyhow::{Result, ensure};
pub(crate) use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
pub(crate) use case::admin as case_admin;
pub(crate) use http_body_util::BodyExt;
pub(crate) use identity::{INSTANCE, PASSWORD};
pub(crate) use reqwest::Client;
pub(crate) use rss_mdm_inventory_postgres::InventoryReader;
pub(crate) use serde_json::{Value, json};
pub(crate) use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
pub(crate) use tower::ServiceExt;
pub(crate) use uuid::Uuid;

pub(crate) mod http;
pub(crate) mod inventory;

pub(crate) mod agent;

pub(crate) mod software;

pub(crate) mod process;

pub(crate) mod software_execution;

pub(crate) mod agent_execution;

pub(crate) mod planning_http;
pub(crate) mod publication_http;

pub(crate) mod channel_onboarding;

pub(crate) mod agent_tls;
pub(crate) mod bootstrap;
pub(crate) mod native_handoff;

pub(crate) mod agent_http;

pub(crate) mod task_signing;

pub(crate) mod storage;

#[path = "../../../content-service/tests/fixtures/installers.rs"]
pub(crate) mod installer_fixtures;
pub(crate) mod runtime;

pub(crate) mod gateway;
