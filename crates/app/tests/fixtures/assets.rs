pub(crate) use rss_mdm_inventory_service::assets::*;
pub(crate) use rss_mdm_inventory_service::collection_service as collection;

#[cfg(test)]
#[path = "../assets/mod.rs"]
pub(crate) mod t2;
