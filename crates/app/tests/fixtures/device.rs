pub(crate) use rss_mdm_registration_service::device::*;
#[cfg(test)]
#[path = "../device/mod.rs"]
pub(crate) mod t2;
#[cfg(test)]
#[path = "../device/support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
use crate::{Database, authorization::context::AuthorizedPrincipal};
#[cfg(test)]
use coordinates::Coordinates;
#[cfg(test)]
use rss_mdm_audit_integration::RequestAudit;
#[cfg(test)]
use rss_mdm_inventory::{Channel, ReportSource};
#[cfg(test)]
use rss_mdm_registration_service::Error;
#[cfg(test)]
use rss_request_context::TenantId;
#[cfg(test)]
use std::{sync::Arc, time::Duration};
#[cfg(test)]
use uuid::Uuid;
