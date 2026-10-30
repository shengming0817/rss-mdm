use crate::storage::Mutation;
use uuid::Uuid;
#[derive(Clone, serde::Serialize)]
pub enum Command {
    Materials,
    MaterialOperation(Uuid),
    PrepareMaterial(Uuid, crate::materials::Prepare),
    TransitionMaterial(Uuid, crate::materials::Transition),
    Types,
    Health,
    Subscriptions(crate::directory::SubscriptionInput),
    Subscription(Uuid),
    Change(Uuid, Mutation),
    Test {
        subscription: Uuid,
        operation: Uuid,
        device: String,
    },
    Deliveries(crate::directory::DeliveryInput),
    Delivery(Uuid),
    Replay {
        delivery: Uuid,
        operation: Uuid,
    },
    Redrive {
        delivery: Uuid,
        operation: Uuid,
        version: u64,
    },
}
