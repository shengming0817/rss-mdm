//! Actual management response bodies; delivery and secret-material lifecycles stay with their owners.
use super::{Command, Error};
use rss_mdm_webhook_service::{
    materials,
    model::{EventType, Subscription},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
pub type Subscriptions = rss_mdm_query::Page<rss_mdm_query::directory::Projection<Subscription>>;
pub type Deliveries = rss_mdm_query::Page<rss_mdm_query::directory::Projection<Delivery>>;
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MaterialOperation {
    Material(materials::Material),
    Receipt(materials::Receipt),
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct EventTypes {
    pub items: [EventType; 5],
    #[schemars(extend("const"=1))]
    pub version: u8,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryReceipt {
    pub id: Uuid,
    pub event_id: Uuid,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayReceipt {
    pub id: Uuid,
    pub event_id: Uuid,
    pub source_delivery: Uuid,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedriveReceipt {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub status: Redriven,
    pub recovery_version: i64,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Redriven {
    Redriven,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct Health {
    pub outbox: Vec<OutboxCount>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct OutboxCount {
    pub domain: Domain,
    pub status: OutboxStatus,
    pub count: i64,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub enum Domain {
    #[serde(rename = "mdm-webhook-source")]
    Source,
    #[serde(rename = "mdm-webhook-delivery")]
    Delivery,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    Pending,
    Publishing,
    Published,
    DeadLetter,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivery {
    pub id: Uuid,
    pub event_id: Uuid,
    pub subscription_id: Uuid,
    pub target_version: i64,
    pub source_delivery: Option<Uuid>,
    pub recovery_version: i64,
    pub redrive_window_open: bool,
    pub attempts: i64,
    pub status: OutboxStatus,
    pub transport_observation: Option<TransportObservation>,
    pub failure_stage: Option<String>,
    pub failure_reason: Option<String>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportObservation {
    Received,
    Unknown,
    NotSent,
}
#[derive(Serialize)]
#[serde(untagged)]
pub enum Reply {
    Materials(materials::PublicDirectory),
    MaterialOperation(MaterialOperation),
    Material(materials::Material),
    MaterialReceipt(materials::Receipt),
    Types(EventTypes),
    Subscriptions(Subscriptions),
    Subscription(Subscription),
    DeliveryReceipt(DeliveryReceipt),
    Deliveries(Deliveries),
    Replay(ReplayReceipt),
    Redrive(RedriveReceipt),
    Health(Health),
    Authorized { authorized: bool },
}
pub fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_json::from_value(value).map_err(|_| Error::Unavailable(crate::Failure::Database))
}
impl Reply {
    pub fn from_command(command: &Command, value: Value) -> Result<Self, Error> {
        Ok(match command {
            Command::Materials => Self::Materials(decode(value)?),
            Command::MaterialOperation(_) => Self::MaterialOperation(decode(value)?),
            Command::PrepareMaterial(..) => Self::Material(decode(value)?),
            Command::TransitionMaterial(..) => Self::MaterialReceipt(decode(value)?),
            Command::Types => Self::Types(decode(value)?),
            Command::Health => Self::Health(decode(value)?),
            Command::Subscription(_) | Command::Change(..) => Self::Subscription(decode(value)?),
            Command::Test { .. } => Self::DeliveryReceipt(decode(value)?),
            Command::Replay { .. } => Self::Replay(decode(value)?),
            Command::Redrive { .. } => {
                if value == serde_json::json!({"authorized":true}) {
                    Self::Authorized { authorized: true }
                } else {
                    return Err(Error::Unavailable(crate::Failure::Database));
                }
            }
            Command::Subscriptions(_) | Command::Deliveries(_) | Command::Delivery(_) => {
                return Err(Error::Unavailable(crate::Failure::Database));
            }
        })
    }
}
impl Reply {
    pub fn materials(self) -> Result<materials::PublicDirectory, Error> {
        if let Self::Materials(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn material_operation(self) -> Result<MaterialOperation, Error> {
        if let Self::MaterialOperation(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn material(self) -> Result<materials::Material, Error> {
        if let Self::Material(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn material_receipt(self) -> Result<materials::Receipt, Error> {
        if let Self::MaterialReceipt(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn types(self) -> Result<EventTypes, Error> {
        if let Self::Types(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn subscriptions(self) -> Result<Subscriptions, Error> {
        if let Self::Subscriptions(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn subscription(self) -> Result<Subscription, Error> {
        if let Self::Subscription(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn delivery_receipt(self) -> Result<DeliveryReceipt, Error> {
        if let Self::DeliveryReceipt(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn deliveries(self) -> Result<Deliveries, Error> {
        if let Self::Deliveries(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn replay(self) -> Result<ReplayReceipt, Error> {
        if let Self::Replay(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn redrive(self) -> Result<RedriveReceipt, Error> {
        if let Self::Redrive(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
impl Reply {
    pub fn health(self) -> Result<Health, Error> {
        if let Self::Health(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
}
