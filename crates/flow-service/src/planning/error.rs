//! Missing product-owned management objects.
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum PlanningError {
    #[error("planning object not found")]
    Missing(Missing),
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub enum Missing {
    Device,
    Group,
    Scope,
    Policy,
    Rule,
}
