//! Closed mapping from authored actions to their target channel.
use rss_mdm_inventory::Channel;
pub fn action_channel(action: &rss_mdm_policy::Action) -> Result<Channel, crate::control::Error> {
    match action.target_channel() {
        Some(rss_mdm_policy::SoftwareChannel::Mdm) => Ok(Channel::Mdm),
        Some(rss_mdm_policy::SoftwareChannel::Agent) => Ok(Channel::Agent),
        None => Err(crate::control::Error::Malformed),
    }
}
