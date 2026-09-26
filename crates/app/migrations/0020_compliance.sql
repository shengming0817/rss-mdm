ALTER TABLE mdm_automation.automation_jobs DROP CONSTRAINT automation_jobs_kind_check;
ALTER TABLE mdm_automation.automation_jobs ADD CONSTRAINT automation_jobs_kind_check CHECK(kind IN('group','group_preview','scope','policy','asset_query','compliance'));

ALTER TABLE mdm_planning.asset_dispatch RENAME COLUMN group_cursor TO cursor;
ALTER TABLE mdm_planning.asset_dispatch DROP CONSTRAINT asset_dispatch_phase_check;
ALTER TABLE mdm_planning.asset_dispatch ADD CONSTRAINT asset_dispatch_phase_check CHECK(phase IN('groups','devices','compliance'));
