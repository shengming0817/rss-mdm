-- Durable observation, not a second registration state or readiness authority.
BEGIN;
ALTER TABLE mdm_access.registrations ADD COLUMN first_authenticated_at timestamptz;
GRANT UPDATE(first_authenticated_at) ON mdm_access.registrations TO mdm_access, mdm_command_runtime;
COMMIT;
