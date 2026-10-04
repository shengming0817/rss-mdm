-- One-way product transition. Old signed offers/permits remain byte-for-byte audit evidence.
BEGIN;
ALTER TABLE mdm_commands.action_runs
 ADD COLUMN software_effect jsonb CHECK (software_effect IS NULL OR (jsonb_typeof(software_effect)='object' AND octet_length(software_effect::text)<=4096)),
 ADD COLUMN invocation_archive jsonb CHECK (invocation_archive IS NULL OR octet_length(invocation_archive::text)<=196608);
ALTER TABLE mdm_commands.action_attempts
 ADD COLUMN execution_material jsonb CHECK (execution_material IS NULL OR (jsonb_typeof(execution_material)='object' AND octet_length(execution_material::text)<=6291456));
GRANT UPDATE(software_effect) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT UPDATE(execution_material) ON mdm_commands.action_attempts TO mdm_command_runtime;
CREATE INDEX action_software_effect ON mdm_commands.action_runs(tenant_id,device) WHERE software_effect IS NOT NULL;
DO $$ DECLARE tenant text; BEGIN
 FOR tenant IN SELECT jsonb_array_elements_text(configuration->'tenants') FROM public.mdm_installation LOOP
  PERFORM set_config('rss.tenant_id',tenant,true);
  UPDATE mdm_policy.policies
   SET definition=jsonb_set(jsonb_set(definition,'{selfService,access}','null'),'{selfService,published}','false'),revision=revision+1
   WHERE tenant_id=tenant::uuid AND jsonb_typeof(definition->'selfService')='object' AND NOT (definition->'selfService' ? 'access');
  UPDATE mdm_agent.bindings SET execution_context=jsonb_set(execution_context,'{userHelper}','false')
   WHERE tenant_id=tenant::uuid AND NOT (execution_context ? 'userHelper');
  UPDATE mdm_commands.action_runs SET invocation_archive=invocation,
   invocation=jsonb_build_object('authorization',((invocation->'authorization')-'actor') || jsonb_build_object('subject',jsonb_build_object('kind','user','user',invocation->'authorization'->'actor')),'parameters',invocation->'parameters','basis',jsonb_build_object('kind','withdrawn'),'execution_target',jsonb_build_object('kind','device'))
   WHERE tenant_id=tenant::uuid AND invocation IS NOT NULL;
  -- Every pre-transition unstarted offer uses the retired signed interface. None may Start.
  UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{cancellation}','"confirmed"')
   WHERE tenant_id=tenant::uuid AND state->>'execution'='not_started';
  UPDATE mdm_commands.action_attempts a SET execution_material=jsonb_build_object('kind','software','platform',a.permit->'payload'->'platform','intent',a.permit->'payload'->'intent','definitionDigest',a.permit->'payload'->'definitionDigest','steps',a.permit->'payload'->'steps')
   WHERE a.tenant_id=tenant::uuid AND jsonb_typeof(a.permit->'payload'->'steps')='array';
  -- Existing software evidence participates in the same exact-version/effect-target exclusion.
  UPDATE mdm_commands.action_runs r SET software_effect=jsonb_build_object('generation',r.generation,'resource',v.frozen->'action'->'resource','version',v.frozen->'action'->'version','digest',v.frozen->'action'->'resource_digest','intent',a.offer->'payload'->'intent','target',(a.offer->'payload'->'steps')->-1->'target')
   FROM mdm_policy.versions v,mdm_commands.action_attempts a
   WHERE r.tenant_id=tenant::uuid AND (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) AND v.action_kind='software' AND (a.tenant_id,a.run)=(r.tenant_id,r.id) AND a.id=(r.state->'delivery'->>'attempt')::uuid AND jsonb_typeof(a.offer->'payload'->'steps')='array';
 END LOOP;
END $$;
COMMIT;
