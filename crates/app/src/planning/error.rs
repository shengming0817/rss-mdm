//! Missing product-owned management objects.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
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
impl IntoResponse for PlanningError {
    fn into_response(self) -> Response {
        let Self::Missing(missing) = self;
        let code = match missing {
            Missing::Device => "planning_device_not_found",
            Missing::Group => "group_not_found",
            Missing::Scope => "scope_not_found",
            Missing::Policy => "policy_not_found",
            Missing::Rule => "group_rule_not_found",
        };
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"code":code})),
        )
            .into_response()
    }
}
