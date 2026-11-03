use super::*;
use crate::sources::{ScopeInput, SourceSet};
use crate::results::SourceRow;
use rss_mdm_inventory_service::objects::DeviceObject;
use rss_mdm_group_postgres::{DecisionValue, Rejection};
use std::collections::BTreeSet;

pub(super) struct Scan {
    pub items: Vec<ObjectRef>,
    pub has_unknown: bool,
    pub reason: StopReason,
}
struct Reads<'a> { left: usize, bytes: usize, deadline: &'a AuditBudget }
impl Reads<'_> {
    fn take(&mut self,n:usize)->bool {
        if n>self.left || self.deadline.control().total_remaining()<=Duration::from_secs(1) {return false;}
        self.left-=n;true
    }
    fn bytes(&mut self,n:usize)->bool {
        if n>self.bytes {return false;} self.bytes-=n;true
    }
}
impl Scopes {
    pub(super) async fn preview_scan_in(
        &self,tx:&mut PgTransaction<'_>,request:&Request,cut:&AssetCut,
        frozen:&ScopeInput,deadline:&AuditBudget,
    )->transaction::Result<Scan> {
        let mut reads=Reads{left:READ_LIMIT,bytes:BYTE_LIMIT,deadline};
        let mut scan=Scan{items:Vec::new(),has_unknown:false,reason:StopReason::Complete};
        if !reads.take(frozen.sources.len()*2) {scan.reason=StopReason::WorkBudget;return Ok(scan);}
        let mut seen=BTreeSet::new();
        for source in &frozen.sources {
            if !frozen.definition.targets.contains(&source.reference) {continue;}
            let mut after=None;
            loop {
                if !reads.take(1) {scan.reason=StopReason::WorkBudget;return Ok(scan);}
                let records=match &source.reference {
                    Reference::Device(id) if after.is_none()=>vec![(id.clone(),false)],
                    Reference::Device(_)=>Vec::new(),
                    Reference::Group(_)=>{
                        let Some(set)=source.coordinates.member_set else {break;};
                        let limit=reads.left.min(16);
                        if limit==0 {scan.reason=StopReason::WorkBudget;return Ok(scan);}
                        let page=self.groups.build_decisions_in(tx,set,after.clone(),limit,reads.bytes).await?;
                        let page=match page {
                            Ok(page)=>page,
                            Err(Rejection::PageBudgetExceeded)=>{scan.reason=StopReason::WorkBudget;return Ok(scan);}
                            Err(error)=>{ group_checked::<()>(Err(error))?; return Err(Error::Unavailable(Failure::Storage).into()); },
                        };
                        if !reads.bytes(page.bytes) {scan.reason=StopReason::WorkBudget;return Ok(scan);}
                        // A short nonempty page may have hit the byte budget. Only empty proves EOF.
                        if page.items.is_empty() {break;}
                        after=page.items.last().map(|d|d.device.clone());
                        if !reads.take(page.items.len()) {scan.reason=StopReason::WorkBudget;return Ok(scan);}
                        page.items.into_iter().filter_map(|d| match d.decision {
                            DecisionValue::NoMatch=>None,
                            state=>Some((d.device,state!=DecisionValue::Match)),
                        }).collect()
                    }
                };
                // Charge even nonmatching enumeration records through the page reservation above.
                if !reads.take(records.len()) {scan.reason=StopReason::WorkBudget;return Ok(scan);}
                if matches!(source.reference,Reference::Device(_)) {after=Some(String::new());}
                for (key,_) in records {
                    let Some(object)=self.preview_object_in(tx,source,&key,cut,&mut reads).await? else {
                        scan.reason=StopReason::WorkBudget;return Ok(scan);
                    };
                    for member in object.members.iter().filter(|m|m.channel==request.channel) {
                        if seen.contains(&member.device) {continue;}
                        if seen.len()==CANDIDATE_LIMIT {scan.reason=StopReason::WorkBudget;return Ok(scan);}
                        let Some(rows)=self.preview_rows_in(tx,frozen,&member.device,request.channel,cut,&mut reads).await? else {
                            scan.reason=StopReason::WorkBudget;return Ok(scan);
                        };
                        seen.insert(member.device.clone());
                        let explanation=crate::channels::targets::frozen_explanation(self.tenant,frozen,&member.device,&rows)
                            .map_err(crate::projection::source_error)?;
                        let mut identities=BTreeSet::new();
                        for row in &rows {
                            for identity in row.input.members.iter().filter(|m|m.channel==request.channel && m.device==member.device) {
                                identities.insert(checked_input(serde_json::to_string(identity))?);
                            }
                        }
                        let (matched,pending)=crate::channels::targets::qualification(explanation.as_ref(),identities.len());
                        scan.has_unknown|=pending || rows.iter().any(|r|r.unknown || !r.input.verified);
                        if matched {scan.items.push(ObjectRef::Endpoint(member.device.clone()));}
                        if scan.items.len()==SAMPLE_LIMIT {scan.reason=StopReason::SampleLimit;return Ok(scan);}
                    }
                }
            }
        }
        Ok(scan)
    }

    async fn preview_object_in(
        &self,tx:&mut PgTransaction<'_>,source:&SourceSet,key:&str,cut:&AssetCut,reads:&mut Reads<'_>,
    )->transaction::Result<Option<DeviceObject>> {
        if !reads.take(1) {return Ok(None);}
        let object=group_checked(ObjectRef::from_key(source.coordinates.asset_context,key))?;
        let reader=self.objects.clone();let tenant=self.tenant;
        if let Some(snapshot)=&source.snapshot {
            let snapshot=snapshot.id;let allowance=reads.bytes;
            let value=tx.with_connection(move|c|Box::pin(async move {reader.lookup(c,tenant,snapshot,&object,allowance).await})).await?;
            match value {Some((value,bytes)) if reads.bytes(bytes)=>Ok(Some(value)),_=>Ok(None)}
        } else {
            let ObjectRef::Endpoint(device)=object else {return Err(Error::Conflict.into());};
            // Endpoint owner returns at most the two original channel registrations.
            if !reads.bytes(16*1024) {return Ok(None);}
            let cut=cut.clone();
            let value=tx.with_connection(move|c|Box::pin(async move {reader.endpoint_at(c,tenant,&cut,&device).await})).await?;
            let bytes=checked_input(serde_json::to_vec(&value))?.len()+1024;
            if bytes>16*1024 {return Err(Error::Unavailable(Failure::Storage).into());}
            reads.bytes+=16*1024-bytes;
            Ok(Some(value))
        }
    }

    async fn preview_rows_in(
        &self,tx:&mut PgTransaction<'_>,frozen:&ScopeInput,device:&str,channel:Channel,
        cut:&AssetCut,reads:&mut Reads<'_>,
    )->transaction::Result<Option<Vec<SourceRow>>> {
        let mut rows=Vec::new();
        for (index,source) in frozen.sources.iter().enumerate() {
            if !reads.take(1) {return Ok(None);}
            let objects=match &source.reference {
                Reference::Device(id)=>{
                    if id!=device {continue;}
                    let Some(input)=self.preview_object_in(tx,source,id,cut,reads).await? else {return Ok(None);};
                    vec![input]
                }
                Reference::Group(_)=>{
                    let Some(set)=source.coordinates.member_set else {continue;};
                    let objects=if let Some(snapshot)=&source.snapshot {
                        let reader=self.objects.clone();let tenant=self.tenant;let snapshot=snapshot.id;
                        let endpoint=device.to_owned();let allowance=reads.bytes;
                        let input=tx.with_connection(move|c|Box::pin(async move {reader.memberships_at(c,tenant,snapshot,&endpoint,channel,allowance).await})).await?;
                        let Some((objects,bytes))=input else {return Ok(None);};
                        if !reads.bytes(bytes) {return Ok(None);}
                        objects
                    } else {
                        let Some(input)=self.preview_object_in(tx,source,device,cut,reads).await? else {return Ok(None);};
                        vec![input]
                    };
                    if objects.is_empty() {continue;}
                    let keys=objects.iter().map(|o|match source.coordinates.asset_context {
                        rss_mdm_group::AssetContext::Endpoint=>device.to_owned(),
                        rss_mdm_group::AssetContext::AssociatedDevice=>o.object.key(),
                    }).collect::<Vec<_>>();
                    if !reads.take(keys.len()) {return Ok(None);}
                    let outcomes=match self.groups.source_decisions_in(tx,set,&keys,reads.bytes).await? {
                        Ok(value)=>value,
                        Err(Rejection::PageBudgetExceeded)=>return Ok(None),
                        Err(error)=>{ group_checked::<()>(Err(error))?; return Err(Error::Unavailable(Failure::Storage).into()); },
                    };
                    if !reads.bytes(outcomes.bytes) {return Ok(None);}
                    for (input,key) in objects.into_iter().zip(keys) {
                        match outcomes.outcomes.get(&key) {
                            Some(rss_mdm_group::Outcome::NoMatch)=>{},
                            outcome=>rows.push(SourceRow{source:index,unknown:!matches!(outcome,Some(rss_mdm_group::Outcome::Match)),input}),
                        }
                    }
                    continue;
                }
            };
            for input in objects {
                if input.members.iter().any(|m|m.device==device && m.channel==channel) {
                    rows.push(SourceRow{source:index,unknown:false,input});
                }
            }
        }
        Ok(Some(rows))
    }
}
