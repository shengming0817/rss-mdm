ALTER TABLE mdm_automation.automation_jobs DROP CONSTRAINT automation_jobs_kind_check;
ALTER TABLE mdm_automation.automation_jobs ADD CONSTRAINT automation_jobs_kind_check CHECK(kind IN('group','group_preview','scope','policy','asset_query','compliance'));
