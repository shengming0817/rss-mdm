-- Fresh-install coordinates; this is an installation attestation, never a principal mapping.
BEGIN;
CREATE TABLE public.mdm_installation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    configuration jsonb NOT NULL CHECK(jsonb_typeof(configuration)='object')
);
REVOKE ALL ON public.mdm_installation FROM PUBLIC;
COMMIT;
