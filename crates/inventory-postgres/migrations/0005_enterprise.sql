BEGIN;
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_field_check;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_field_check CHECK(field IN ('device.model','device.os.version','custom.corporate_agent.version','custom.corporate_agent.healthy','custom.osquery.version'));
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_check;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_check CHECK(octet_length(value) BETWEEN 1 AND 2048);
COMMIT;
