-- The installation owner pre-creates mdm_api. Never use the worker login for HTTP.
BEGIN;
GRANT USAGE ON SCHEMA mdm TO mdm_api;
GRANT SELECT ON mdm.inventory TO mdm_api;
COMMIT;
