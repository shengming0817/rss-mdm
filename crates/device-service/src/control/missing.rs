#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ExecutionError {
    #[error("operation_not_found")]
    MissingOperation,
    #[error("task_not_found")]
    MissingTask,
}
