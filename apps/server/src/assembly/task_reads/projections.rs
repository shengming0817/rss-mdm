use rss_mdm_management_http::execution::task_reads as http;
use rss_mdm_scope_service::channels;
use rss_mdm_software_service::deployment::{queries::records as software, scope};
pub(super) fn software_preview(v: software::Preview) -> http::Preview {
    http::Preview {
        action: v.action,
        scope_result: v.scope_result,
        next_cursor: v.next_cursor,
        items: v
            .items
            .into_iter()
            .map(|v| http::PreviewTarget {
                object: match v.object {
                    scope::ObjectRef::Endpoint(id) => channels::ObjectRef::Endpoint(id),
                    scope::ObjectRef::Association(id) => channels::ObjectRef::Association(id),
                },
                channel: v.channel,
                availability: match v.availability {
                    scope::Availability::Ready => channels::Availability::Ready,
                    scope::Availability::Unavailable => channels::Availability::Unavailable,
                },
                reason: v.reason,
                target: v.target,
                eligibility: match v.eligibility {
                    scope::ScopeAdmission::Eligible { entry } => {
                        channels::ScopeAdmission::Eligible { entry }
                    }
                    scope::ScopeAdmission::Pending => channels::ScopeAdmission::Pending,
                    scope::ScopeAdmission::Excluded => channels::ScopeAdmission::Excluded,
                },
                task_admission: v.task_admission,
            })
            .collect(),
    }
}
