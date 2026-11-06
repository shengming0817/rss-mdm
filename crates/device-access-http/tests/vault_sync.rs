//! Real Identity and PostgreSQL proof for the user-owned sync domain.
use anyhow::Result;
use rss_mdm_install_support::StorageProfile;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
const DA: StorageProfile = StorageProfile::Da;
#[allow(
    dead_code,
    reason = "Shared DA fixture also exposes unrelated native-business setup"
)]
#[path = "foundation/context.rs"]
mod context;
#[path = "foundation/installation.rs"]
mod installation;
use context::{Context, Inputs};
#[path = "vault_sync/cases.rs"]
mod vault_sync;
