//! SMTP 配置、资格与固定测试消息。没有通知订阅或任意邮件发送接口。
pub mod authority;
pub mod store;
pub mod transport;
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mail input rejected")]
    Input,
    #[error("mail operation conflicts with the original request")]
    Conflict,
    #[error("mail provider unavailable")]
    Provider,
    #[error("mail submission rejected by provider")]
    Rejected,
    #[error("mail storage unavailable")]
    Storage,
    #[error("mail submission outcome unknown")]
    Unknown,
}
pub type Result<T> = std::result::Result<T, Error>;
