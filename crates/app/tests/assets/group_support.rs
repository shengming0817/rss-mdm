use crate::test_support::http::{ok, request};
use crate::test_support::*;
pub(crate) struct GroupEvidence {
    pub(crate) members: Value,
    pub(crate) decisions: Value,
}
pub(crate) async fn preview(
    browser: &mut Browser,
    router: &Router,
    group: &str,
) -> Result<GroupEvidence> {
    let (_, state) = browser.call(router, Method::GET, group, None).await?;
    let accepted = ok(
        browser,
        router,
        Method::POST,
        &format!("{group}/previews"),
        Some(request(
            state["group"]["revision"].as_u64().unwrap(),
            json!({}),
        )),
    )
    .await?;
    let task = accepted["task"].as_str().unwrap();
    let members = ok(
        browser,
        router,
        Method::GET,
        &format!("{group}/results/{task}/members"),
        None,
    )
    .await?;
    let decisions = ok(
        browser,
        router,
        Method::GET,
        &format!("{group}/results/{task}/decisions"),
        None,
    )
    .await?;
    Ok(GroupEvidence { members, decisions })
}
