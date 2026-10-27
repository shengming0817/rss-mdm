//! Stable business ownership coordinates; these values never authenticate a request.
use crate::{Error, User};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Actor {
    Account {
        user: User,
    },
    ApiKey {
        instance: String,
        tenant: String,
        id: Uuid,
    },
}
impl Actor {
    pub fn instance_id(&self) -> &str {
        match self {
            Self::Account { user } => &user.instance_id,
            Self::ApiKey { instance, .. } => instance,
        }
    }
    pub fn tenant_id(&self) -> &str {
        match self {
            Self::Account { user } => &user.tenant_id,
            Self::ApiKey { tenant, .. } => tenant,
        }
    }
    pub fn subject(&self) -> String {
        match self {
            Self::Account { user } => user.principal_id.clone(),
            Self::ApiKey { id, .. } => format!("api-key:{id}"),
        }
    }
    pub fn account(&self) -> Result<&User, Error> {
        match self {
            Self::Account { user } => Ok(user),
            Self::ApiKey { .. } => Err(Error::Forbidden),
        }
    }
}
