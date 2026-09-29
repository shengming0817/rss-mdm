pub(crate) use rss_mdm_agent_channel::*;
#[cfg(test)]
#[path = "../agent/mod.rs"]
pub(crate) mod t2;
impl From<crate::Error> for AgentError {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Service(e) => Self::from(e),
            _ => Self::Wire(rss_mdm_agent_wire::ErrorCode::ServiceUnavailable),
        }
    }
}
