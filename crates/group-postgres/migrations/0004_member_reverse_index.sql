BEGIN;
CREATE INDEX member_changes_object ON mdm_group.member_changes(tenant_id,object_id,group_id,revision DESC);
CREATE INDEX groups_dynamic ON mdm_group.groups(tenant_id,id) WHERE kind='dynamic' AND NOT deleted;
COMMIT;
