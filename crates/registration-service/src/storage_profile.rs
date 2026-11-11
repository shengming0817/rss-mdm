//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub device_linked_revoke_credentials: &'static str,
    pub device_linked_prior_credentials: &'static str,
    pub device_linked_revoke_state: &'static str,

    pub identity_install: &'static str,
    pub identity_relations: &'static str,
    pub identity_access_contract: &'static str,
    pub identity_object_manifest: &'static str,
    pub device_trust_consumers: &'static str,
    pub da_registration: &'static str,
    pub da_current_registration: &'static str,
    pub da_insert_grant: &'static str,
    pub da_grant_operation: &'static str,
    pub device_installation_identity: &'static str,
    pub device_authenticate_endpoint_in_1: &'static str,
    pub quotas_configuration_on_1: &'static str,
    pub admission_read_in_1: &'static str,
    pub admission_require_request_in_1: &'static str,
    pub admission_change_1: &'static str,
    pub admission_require_windows_in_1: &'static str,
    pub agent_grant_row_1: &'static str,
    pub lifecycle_work_allowed_on_1: &'static str,
    pub lifecycle_begin_retirement_in_1: &'static str,
    pub operations_read_1: &'static str,
    pub operations_save_result_1: &'static str,
    pub enrollment_agent_policy_create_in_1: &'static str,
    pub enrollment_agent_policy_create_in_2: &'static str,
    pub enrollment_agent_policy_create_in_3: &'static str,
    pub enrollment_agent_policy_create_in_4: &'static str,
    pub enrollment_agent_policy_current_source_in_1: &'static str,
    pub enrollment_store_request_1: &'static str,
    pub enrollment_store_create_enrollment_on_2: &'static str,
    pub enrollment_store_create_enrollment_on_3: &'static str,
    pub enrollment_store_change_enrollment_on_1: &'static str,
    pub enrollment_store_change_enrollment_on_2: &'static str,
    pub enrollment_store_mark_bound_in_1: &'static str,
    pub enrollment_read_enrollment_status_1: &'static str,
    pub enrollment_read_record_authenticated_in_1: &'static str,
    pub enrollment_registration_read: &'static str,
    pub quotas_management_change_1: &'static str,
    pub agent_native_source_1: &'static str,
    pub agent_native_native_grant_row_1: &'static str,
    pub agent_native_create_in_1: &'static str,
    pub agent_native_create_in_2: &'static str,
    pub agent_native_source_2: &'static str,
    pub certificate_grants_request_1: &'static str,
    pub certificate_grants_request_2: &'static str,
    pub certificate_grants_request_3: &'static str,
    pub certificate_grants_revoke_1: &'static str,
    pub certificate_grants_renewal_status_1: &'static str,
    pub certificate_grants_authorize_target_3: &'static str,
    pub certificate_grants_revoke_2: &'static str,
    pub certificate_grants_recovery_1: &'static str,
    pub certificate_grants_recovery_2: &'static str,
    pub certificate_grants_recovery_3: &'static str,
    pub certificate_grants_progress_1: &'static str,
    pub certificate_grants_renew_1: &'static str,
    pub certificate_grants_renew_2: &'static str,
    pub certificate_grants_renew_3: &'static str,
    pub agent_connections_retirement_blockers_on_1: &'static str,
    pub agent_connections_retirement_blockers_on_2: &'static str,
    pub agent_connections_signer_on_1: &'static str,
    pub agent_connections_ensure_signer_on_1: &'static str,
    pub agent_connections_ensure_signer_on_2: &'static str,
    pub agent_connections_service_id_on_1: &'static str,
    pub agent_connections_draft_on_1: &'static str,
    pub agent_connections_published_on_1: &'static str,
    pub agent_connections_record_deployment_on_1: &'static str,
    pub agent_connections_record_deployment_on_2: &'static str,
    pub agent_connections_connection_state_1: &'static str,
    pub agent_connections_connection_state_2: &'static str,
    pub agent_connections_connection_state_3: &'static str,
    pub agent_connections_save_connections_1: &'static str,
    pub agent_connections_publish_connections_1: &'static str,
    pub agent_connections_publish_connections_2: &'static str,
    pub agent_connections_publish_connections_3: &'static str,
    pub agent_connections_connection_operation_1: &'static str,
    pub agent_connections_acknowledge_connections_1: &'static str,
    pub agent_connections_acknowledge_connections_2: &'static str,
    pub agent_connections_acknowledge_connections_3: &'static str,
    pub agent_connections_report_connection_failure_1: &'static str,
    pub agent_connections_report_connection_failure_2: &'static str,
    pub agent_connections_unconfirmed_connection_devices_1: &'static str,
    pub agent_connections_connection_observation_1: &'static str,
    pub agent_connections_rewrap_1: &'static str,
    pub agent_connections_rewrap_2: &'static str,
    pub agent_configurations_row_1: &'static str,
    pub agent_configurations_usage_1: &'static str,
    pub agent_configurations_lock_for_grant_1: &'static str,
    pub agent_configurations_create_configuration_1: &'static str,
    pub agent_configurations_create_configuration_2: &'static str,
    pub agent_configurations_configuration_operation_1: &'static str,
    pub agent_configurations_revoke_configuration_1: &'static str,
    pub agent_configurations_exchange_configuration_1: &'static str,
    pub agent_configurations_exchange_configuration_2: &'static str,
    pub agent_configurations_exchange_configuration_3: &'static str,
    pub agent_configurations_configuration_exchange_status_1: &'static str,
    pub agent_configurations_cancel_reservation_1: &'static str,
    pub agent_configurations_cancel_reservation_2: &'static str,
    pub agent_bootstrap_bootstrap_challenge_1: &'static str,
    pub agent_bootstrap_bootstrap_notify_1: &'static str,
    pub agent_bootstrap_native_grant_1: &'static str,
    pub agent_bootstrap_row_1: &'static str,
    pub agent_bootstrap_row_2: &'static str,
    pub agent_bootstrap_require_delivery_1: &'static str,
    pub agent_issuance_issue_1: &'static str,
    pub agent_issuance_issue_2: &'static str,
    pub agent_issuance_issue_3: &'static str,
    pub agent_issuance_record_unknown_1: &'static str,
    pub agent_issuance_save_certificate_1: &'static str,
    pub agent_issuance_save_certificate_2: &'static str,
    pub agent_issuance_save_certificate_3: &'static str,
    pub agent_issuance_recover_issuance_1: &'static str,
    pub agent_current_user_bindings_on_1: &'static str,
    pub agent_current_user_change_current_user_1: &'static str,
    pub agent_current_user_change_current_user_2: &'static str,
    pub agent_current_user_change_current_user_3: &'static str,
    pub agent_queries_issuance_device_1: &'static str,
    pub agent_queries_request_details_1: &'static str,
    pub agent_queries_registration_recovery_operation_1: &'static str,
    pub agent_queries_registration_recovery_operation_2: &'static str,
    pub agent_queries_issuance_recovery_operations_1: &'static str,
    pub agent_queries_issuance_recovery_operation_1: &'static str,
    pub agent_queries_issuance_recovery_operation_2: &'static str,
    pub agent_queries_issuance_recovery_operation_3: &'static str,
    pub agent_settings_initialize_on_1: &'static str,
    pub agent_settings_tenant_seed_sql_1: &'static str,
    pub agent_settings_read_on_1: &'static str,
    pub agent_settings_update_settings_1: &'static str,
    pub agent_settings_update_settings_2: &'static str,
    pub agent_activation_activate_3: &'static str,
    pub agent_activation_activate_4: &'static str,
    pub agent_activation_activate_5: &'static str,
    pub agent_activation_activate_6: &'static str,
    pub agent_activation_activate_7: &'static str,
    pub agent_activation_activate_8: &'static str,
    pub agent_activation_activate_10: &'static str,
    pub agent_activation_activate_11: &'static str,
    pub agent_activation_activate_12: &'static str,
    pub agent_activation_activate_13: &'static str,
    pub agent_activation_authenticate_1: &'static str,
    pub device_registration_user_assign_registration_user_1: &'static str,
    pub device_registration_user_target_on_1: &'static str,
    pub device_registration_user_read_on_1: &'static str,
    pub device_registration_user_initialize_on_1: &'static str,
    pub device_registration_user_page_on_1: &'static str,
    pub device_store_record_communication_in_1: &'static str,
    pub device_store_authorize_report_1: &'static str,
    pub device_store_authorize_report_2: &'static str,
    pub device_store_authorize_report_3: &'static str,
    pub device_store_current_scope_1: &'static str,
    pub device_store_retire_state_in_1: &'static str,
    pub device_store_retire_state_in_2: &'static str,
    pub device_store_retire_state_in_3: &'static str,
    pub device_store_retire_state_in_4: &'static str,
    pub device_store_bind_authorized_in_1: &'static str,
    pub device_store_bind_authorized_in_2: &'static str,
    pub device_store_bind_authorized_in_4: &'static str,
    pub device_store_bind_authorized_in_7: &'static str,
    pub device_store_bind_authorized_in_8: &'static str,
    pub device_store_bind_authorized_in_9: &'static str,
    pub device_store_replace_mdm_credential_in_1: &'static str,
    pub device_store_replace_mdm_credential_in_2: &'static str,
    pub device_store_replace_mdm_credential_in_3: &'static str,
    pub device_store_revalidate_source_1: &'static str,
    pub device_store_revalidate_source_2: &'static str,
    pub device_store_revalidate_source_3: &'static str,
    pub device_store_revoke_on_1: &'static str,
    pub device_store_revoke_on_2: &'static str,
    pub device_store_active_source_in_1: &'static str,
    pub device_store_allocate_collection_in_1: &'static str,
    pub device_store_allocate_collection_in_2: &'static str,
    pub device_store_source_current_in_1: &'static str,
    pub device_store_allocate_report_in_1: &'static str,
    pub device_store_allocate_task_report_in_1: &'static str,
    pub device_store_allocate_commands_in_1: &'static str,
    pub device_store_activate_renewed_mdm_in_1: &'static str,
    pub device_store_revalidate_collection_source_1: &'static str,
    pub device_store_live_collection_streams_on_1: &'static str,
    pub device_store_collection_stream_retired_on_1: &'static str,
    pub device_store_report_epoch_in_1: &'static str,
    pub device_endpoints_current_in_1: &'static str,
    pub device_endpoints_current_page_in_1: &'static str,
    pub device_endpoints_page_in_1: &'static str,
    pub device_endpoints_page_at_1: &'static str,
    pub device_endpoints_candidate_page_in_1: &'static str,
    pub device_endpoints_lifecycle_page_at_1: &'static str,
    pub device_read_find_1: &'static str,
    pub device_read_active_sources_1: &'static str,
    pub device_read_exists_1: &'static str,
    pub device_read_sources_at_1: &'static str,
    pub device_read_registered_1: &'static str,
    pub device_read_active_channel_in_1: &'static str,
    pub device_read_active_sources_in_1: &'static str,
    pub device_read_enabled_source_in_1: &'static str,
    pub device_read_inactive_in_1: &'static str,
    pub device_read_timeline_device_in_1: &'static str,
    pub device_read_timeline_enrollment_in_1: &'static str,
    pub device_read_live_at_1: &'static str,
    pub device_read_page_at_1: &'static str,
    pub device_linked_request_in_1: &'static str,
    pub device_linked_request_in_3: &'static str,
    pub device_linked_bind_in_1: &'static str,
    pub device_linked_bind_in_3: &'static str,
    pub device_linked_bind_in_5: &'static str,
    pub device_linked_bind_in_6: &'static str,
    pub device_linked_ready_in_1: &'static str,
    pub device_coordinates_authority_at_on_1: &'static str,
    pub device_directory_source_budget_1: &'static str,
    pub device_directory_selection_1: &'static str,
    pub device_directory_selection_2: &'static str,
    pub device_directory_directory_statistics_1: &'static str,
    pub device_directory_page_on_1: &'static str,
    pub device_management_read_1: &'static str,
    pub device_management_validate_2: &'static str,
    pub device_management_validate_primary: &'static str,
    pub device_management_validate_3: &'static str,
    pub agent_configurations_directory_configuration_directory_1: &'static str,
    pub agent_configurations_directory_configuration_directory_2: &'static str,
    pub enrollment_tasks_recovery_accept_action_dispatch_1: &'static str,
    pub enrollment_tasks_recovery_accept_action_dispatch_2: &'static str,
    pub enrollment_tasks_worker_pending_in_1: &'static str,
    pub enrollment_tasks_worker_pending_in_2: &'static str,
    pub enrollment_tasks_retirement_retire_in_1: &'static str,
    pub enrollment_tasks_retirement_retire_in_2: &'static str,
    pub enrollment_tasks_retirement_progress_on_1: &'static str,
    pub enrollment_tasks_wake_policy_in_1: &'static str,
    pub enrollment_tasks_poll_offer_candidates_1: &'static str,
    pub enrollment_tasks_poll_cancellations_1: &'static str,
    pub enrollment_tasks_admission_accept_for_device_1: &'static str,
    pub enrollment_tasks_admission_accept_for_device_2: &'static str,
    pub enrollment_tasks_admission_queue_run_in_1: &'static str,
    pub enrollment_tasks_admission_occurrence_available_in_1: &'static str,
    pub enrollment_tasks_policy_recovery_prepare_in_1: &'static str,
    pub enrollment_tasks_policy_recovery_advance_in_1: &'static str,
    pub enrollment_tasks_policy_recovery_advance_in_2: &'static str,
    pub enrollment_tasks_agent_agent_admit_in_1: &'static str,
    pub enrollment_tasks_agent_agent_admit_in_2: &'static str,
    pub enrollment_tasks_agent_agent_admit_in_3: &'static str,
    pub enrollment_tasks_agent_agent_admit_in_4: &'static str,
    pub enrollment_tasks_storage_run_in_1: &'static str,
    pub enrollment_tasks_storage_run_in_2: &'static str,
    pub enrollment_tasks_storage_save_run_1: &'static str,
    pub enrollment_tasks_storage_save_run_2: &'static str,
    pub enrollment_tasks_storage_pending_in_1: &'static str,
    pub enrollment_tasks_storage_active_count_on_1: &'static str,
    pub enrollment_tasks_storage_owned_ids_on_1: &'static str,
    pub enrollment_tasks_storage_replay_1: &'static str,
    pub enrollment_tasks_diagnostic_receipt: &'static str,
    pub enrollment_tasks_storage_receipt_1: &'static str,
    pub enrollment_tasks_storage_association_on_1: &'static str,
    pub enrollment_tasks_self_service_self_service_status_in_1: &'static str,
    pub enrollment_tasks_self_service_advance_waiting_in_1: &'static str,
    pub enrollment_tasks_queries_page_on_1: &'static str,
    pub enrollment_tasks_queries_detail_on_1: &'static str,
    pub enrollment_tasks_queries_detail_on_2: &'static str,
    pub enrollment_tasks_queries_assignment_ids_on_1: &'static str,
    pub enrollment_tasks_queries_assignment_state_on_1: &'static str,
    pub install: &'static str,
    pub relations: &'static str,
    pub agent_bootstrap: &'static str,
    pub agent_configurations: &'static str,
    pub quotas: &'static str,
    pub admission: &'static str,
    pub directory: &'static str,
    pub enrollment_tasks: &'static str,
    pub quota_usage: &'static str,
    pub enrollment_retirement: &'static str,
    pub task_relations: &'static str,
    pub member_authority: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
    pub enrollment_access_contract: &'static str,
    pub current_members: &'static str,
    pub agent_default_values: &'static str,
    pub agent_issuance_save_certificate_4: &'static str,
    pub common_authority_admission: &'static str,
    pub authority_capture_header: &'static str,
    pub authority_sources_header: &'static str,
    pub authority_members_header: &'static str,
    pub authority_seed_header: &'static str,
    pub authority_retire_header: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $access_schema:literal, $access_schema_decl:literal, $access_path:literal, $access_role:literal, $installation:literal, $mdm_registration_tasks_agent_admission:literal, $mdm_registration_tasks_policy_recovery:literal, $mdm_registration_tasks_receipts:literal, $mdm_registration_tasks_runs:literal, $mdm_registration_tasks_save_retired_run:literal, $mdm_registration_tasks_schema:literal, $mdm_policy_policies:literal, $mdm_policy_triggers:literal, $mdm_policy_versions:literal, $owner:literal, $command_runtime:literal, $inventory_runtime:literal, $scope_runtime:literal, $policy_runtime:literal, $telemetry_runtime:literal, $software_driver:literal, $identity_runtime:literal, $create_mdm_registration_tasks:literal, $create_access:literal, $native_retirement_clear:literal, $index_38:literal, $index_39:literal, $index_40:literal, $index_41:literal, $index_43:literal, $index_44:literal, $index_45:literal, $index_46:literal, $index_47:literal, $index_48:literal, $index_49:literal, $index_50:literal, $index_51:literal, $index_55:literal, $index_56:literal, $index_57:literal, $index_58:literal, $index_59:literal, $index_60:literal, $index_62:literal, $index_63:literal, $index_64:literal, $index_67:literal, $index_68:literal, $index_70:literal, $index_71:literal, $index_72:literal, $index_75:literal, $index_76:literal, $index_78:literal, $index_79:literal, $index_80:literal, $index_81:literal, $index_82:literal, $index_83:literal, $index_85:literal, $index_86:literal, $index_87:literal, $index_88:literal, $contract_table_89:literal, $contract_table_90:literal, $contract_table_91:literal, $contract_table_92:literal, $contract_table_93:literal, $contract_table_95:literal, $contract_table_96:literal, $contract_table_97:literal, $contract_table_98:literal, $contract_table_99:literal, $contract_table_100:literal, $contract_table_101:literal, $contract_table_102:literal, $contract_table_103:literal, $contract_table_104:literal, $contract_table_105:literal, $contract_table_106:literal, $contract_table_107:literal, $contract_table_108:literal, $contract_table_109:literal, $contract_table_110:literal, $contract_table_111:literal, $access_contract_tables:literal, $access_contract_functions:literal, $access_contract_external_relations:literal, $contract_table_115:literal, $contract_table_116:literal, $contract_table_117:literal, $contract_table_118:literal, $enrollment_access_contract_tables:literal, $enrollment_access_contract_functions:literal, $default_agent_values:literal, $pki_certificates:literal, $pki_signing:literal, $trigger_path:literal) => {
        mod $module {
            macro_rules! identity_install { () => { concat!(r###"-- Fresh installation: device-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

"###, $create_access, r###";



CREATE TABLE "###, $access_schema, r###"credentials (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    device text NOT NULL,
    purpose text NOT NULL CHECK(purpose IN('primary','windows_declared','da_device')),
    protocol_request uuid,
    CHECK((purpose='windows_declared')=(protocol_request IS NOT NULL)),
    channel text,
    locator text NOT NULL,
    state text NOT NULL,
    CONSTRAINT credentials_channel_check CHECK ((channel = ANY (ARRAY['agent'::text, 'mdm'::text]))),
    CONSTRAINT credentials_locator_check CHECK ((locator ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT credentials_state_check CHECK ((state = ANY (ARRAY['active'::text, 'superseded'::text, 'revoked'::text])))
);

ALTER TABLE ONLY "###, $access_schema, r###"credentials FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"grants (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    device text NOT NULL,
    purpose text NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT grants_actor_check CHECK (((length(actor) >= 1) AND (length(actor) <= 255))),
    CONSTRAINT grants_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:05:00'::interval)))),
    CONSTRAINT grants_client_check CHECK (((length(instance) >= 1) AND (length(instance) <= 255))),
    CONSTRAINT grants_device_check CHECK ((((octet_length(device) >= 1) AND (octet_length(device) <= 256)) AND (device !~ '[[:cntrl:]]'::text))),
    CONSTRAINT grants_purpose_check CHECK ((purpose = 'enrollment'::text)),
    CONSTRAINT grants_state_check CHECK ((state = ANY (ARRAY['available'::text, 'consumed'::text, 'revoked'::text])))
);

ALTER TABLE ONLY "###, $access_schema, r###"grants FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"registration_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    action text NOT NULL CHECK(length(action) BETWEEN 1 AND 128),
    device text,
    self_enrollment boolean NOT NULL,
    CONSTRAINT operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT operations_result_check CHECK ((octet_length(result) <= 65536))
);

ALTER TABLE ONLY "###, $access_schema, r###"registration_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"certificate_grants (
 certificate_purpose text NOT NULL DEFAULT 'agent' CHECK(certificate_purpose IN('agent','da_device')),
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 operation_id uuid NOT NULL,
 source text NOT NULL,
 actor text,
 instance text,
 device text NOT NULL CHECK(octet_length(device) BETWEEN 1 AND 256 AND device !~ '[[:cntrl:]]'),
 platform text CHECK(platform IN('windows','macos')),
 CHECK((certificate_purpose='agent' AND platform IS NOT NULL) OR (certificate_purpose='da_device' AND platform IS NULL)),
 secret_digest text NOT NULL CHECK(secret_digest ~ '^[0-9a-f]{64}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 spki text CHECK(spki ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN('pending','available','consumed','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 predecessor uuid,
 native_authority jsonb CHECK(octet_length(native_authority::text)<=65536),
 CONSTRAINT native_origin CHECK((source='native')=(native_authority IS NOT NULL)),
 CONSTRAINT agent_grant_window CHECK(expires_at>created_at AND expires_at<=created_at+interval '7 days'),
 CONSTRAINT agent_grant_subject CHECK((state IN('pending','revoked') AND source='browser' AND actor IS NULL AND instance IS NULL AND spki IS NOT NULL) OR (state<>'pending' AND actor IS NOT NULL AND instance IS NOT NULL)),
 CONSTRAINT agent_grant_target CHECK((source IN('recovery','renewal'))=(predecessor IS NOT NULL)),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,certificate_purpose,source,operation_id),
 configuration_id uuid,
 configuration_binding jsonb CHECK(octet_length(configuration_binding::text)<=32768),
 CONSTRAINT configuration_authority
 CHECK((source='configuration' AND configuration_id IS NOT NULL AND configuration_binding IS NOT NULL AND spki IS NOT NULL) OR (source<>'configuration' AND configuration_id IS NULL AND configuration_binding IS NULL)),
 CONSTRAINT certificate_grants_source_check CHECK(source IN('download','browser','native','recovery','renewal','configuration','administrator')),
 CONSTRAINT configuration_device_key UNIQUE(tenant_id,configuration_id,spki)

);
CREATE TABLE "###, $access_schema, r###"certificate_issuances (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 grant_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 authority_digest text NOT NULL CHECK(authority_digest ~ '^[0-9a-f]{64}$'),
 csr bytea NOT NULL CHECK(octet_length(csr) BETWEEN 1 AND 32768),
 spki text NOT NULL CHECK(spki ~ '^[0-9a-f]{64}$'),
 identity text NOT NULL,
 profile jsonb NOT NULL CHECK(octet_length(profile::text)<=16384),
 not_before bigint NOT NULL,
 not_after bigint NOT NULL CHECK(not_after>not_before),
 state text NOT NULL CHECK(state IN('signing','unknown','issued')),
 certificate_chain jsonb CHECK(octet_length(certificate_chain::text)<=180000),
 metadata jsonb CHECK(octet_length(metadata::text)<=16384),
 fingerprint text CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 activation_operation uuid,
 activation_digest text CHECK(activation_digest ~ '^[0-9a-f]{64}$'),
 activation_result jsonb CHECK(octet_length(activation_result::text)<=65536),
 credential uuid,
 CONSTRAINT candidate_shape CHECK((state='issued')=(certificate_chain IS NOT NULL AND metadata IS NOT NULL AND fingerprint IS NOT NULL)),
 CONSTRAINT activation_shape CHECK((activation_result IS NULL AND activation_operation IS NULL AND activation_digest IS NULL AND credential IS NULL) OR (state='issued' AND activation_result IS NOT NULL AND activation_operation IS NOT NULL AND activation_digest IS NOT NULL AND credential IS NOT NULL)),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,grant_id),
 UNIQUE(tenant_id,operation_id),
 UNIQUE(tenant_id,fingerprint),
 FOREIGN KEY(tenant_id,grant_id) REFERENCES "###, $access_schema, r###"certificate_grants(tenant_id,id),
 signing_issuer text CHECK(signing_issuer ~ '^[0-9a-f]{64}$')

);
ALTER TABLE "###, $access_schema, r###"registration_operations ADD COLUMN agent_issuance_recovery uuid;
ALTER TABLE "###, $access_schema, "registration_operations ", $index_38, " FOREIGN KEY(tenant_id,agent_issuance_recovery) REFERENCES ", $access_schema, r###"certificate_issuances(tenant_id,id);
ALTER TABLE "###, $access_schema, "registration_operations ", $index_39, r###" CHECK(agent_issuance_recovery IS NULL OR result=to_json(agent_issuance_recovery)::text);
"###, $index_40, " ON ", $access_schema, r###"registration_operations(tenant_id,agent_issuance_recovery,actor,operation_id) WHERE agent_issuance_recovery IS NOT NULL;
"###, $index_41, " ON ", $access_schema, r###"certificate_grants(tenant_id,device,id);

ALTER TABLE "###, $access_schema, r###"certificate_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"certificate_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"certificate_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"certificate_issuances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"certificate_grants USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY insert_only ON "###, $access_schema, "certificate_grants AS RESTRICTIVE FOR INSERT WITH CHECK(current_user <> '", $command_runtime, r###"' OR source='native');
CREATE POLICY tenant ON "###, $access_schema, r###"certificate_issuances USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
"###, $index_43, " ON ", $access_schema, r###"certificate_grants(tenant_id,actor,instance,expires_at);
CREATE TABLE "###, $access_schema, r###"devices (
 tenant_id uuid NOT NULL,
 id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 256 AND id !~ '[[:cntrl:]]'),
 retirement uuid,
 purpose text NOT NULL CHECK(purpose IN('primary','da_device')),
 channel text,
 epoch uuid NOT NULL,
 next_command bigint NOT NULL DEFAULT 1024 CHECK(next_command BETWEEN 1024 AND 4294967296),
 request_id uuid,
 certificate_grant_id uuid,
 state text NOT NULL CHECK(state IN('active','revoked')),
 first_authenticated_at timestamptz,
 last_communication_received_at timestamptz,
 CONSTRAINT device_origin CHECK(
 (channel='mdm' AND purpose='primary' AND request_id IS NOT NULL AND certificate_grant_id IS NULL) OR
 (channel='agent' AND purpose='primary' AND request_id IS NULL AND certificate_grant_id IS NOT NULL) OR
 (channel IS NULL AND purpose='da_device' AND request_id IS NULL AND certificate_grant_id IS NOT NULL))
);

ALTER TABLE ONLY "###, $access_schema, r###"devices FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"report_sources (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    source text NOT NULL,
    epoch uuid NOT NULL,
    enabled boolean NOT NULL,
    next_sequence bigint DEFAULT 0 NOT NULL,
    CONSTRAINT report_sources_next_sequence_check CHECK ((next_sequence >= 0)),
    CONSTRAINT report_sources_source_check CHECK (((length(source) >= 1) AND (length(source) <= 255)))
);

ALTER TABLE ONLY "###, $access_schema, r###"report_sources FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"requests (
 authority_kind text NOT NULL DEFAULT 'password',
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 grant_id uuid,
 device text NOT NULL,
 parent_credential uuid,
 protocol_epoch uuid,
 protocol_ready boolean NOT NULL DEFAULT false,
 next_command bigint NOT NULL DEFAULT 1024 CHECK(next_command BETWEEN 1024 AND 4294967296),
 CHECK((authority_kind='parent_certificate')=(parent_credential IS NOT NULL)),
 CHECK(protocol_epoch IS NULL OR authority_kind='parent_certificate'),
 state text DEFAULT 'cancelled'::text NOT NULL,
 password_digest text,
 password_version bigint DEFAULT 0 NOT NULL,
 credential_ref uuid,
 expires_at timestamp with time zone,
 issuance_operation uuid,
 source text NOT NULL,
 windows_profile text,
 CONSTRAINT requests_windows_profile_check CHECK ((source='mdm.windows' AND windows_profile IS NOT NULL AND windows_profile IN ('Full','Device')) OR (source<>'mdm.windows' AND windows_profile IS NULL)),
 CONSTRAINT requests_password_digest_check CHECK ((password_digest ~ '^[0-9a-f]{64}$'::text)),
 CONSTRAINT requests_password_version_check CHECK ((password_version >= 0)),
 CONSTRAINT requests_source_check CHECK ((source = ANY (ARRAY['mdm.windows'::text, 'mdm.apple'::text]))),
 CONSTRAINT requests_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'bound'::text, 'cancelled'::text]))),
 self_service boolean NOT NULL DEFAULT false,
 account_version bigint NOT NULL DEFAULT 0 CHECK(account_version>=0),
 account_reference jsonb,
 account_challenge text CHECK(account_challenge ~ '^[0-9a-f]{64}$'),
 organization_version bigint NOT NULL DEFAULT 0 CHECK(organization_version>=0),
 organization_challenge text CHECK(organization_challenge ~ '^[0-9a-f]{64}$'),
 CONSTRAINT requests_authority_kind_check CHECK(authority_kind IN('password','parent_certificate','apple_account','apple_ade','windows_entra','agent_policy')),
 CONSTRAINT enrollment_shape CHECK(
 state='cancelled' OR (expires_at IS NOT NULL AND issuance_operation IS NOT NULL AND (
 (authority_kind='password' AND grant_id IS NOT NULL AND password_digest IS NOT NULL AND password_version>0 AND credential_ref IS NOT NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='parent_certificate' AND grant_id IS NULL AND source='mdm.windows' AND parent_credential IS NOT NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='apple_account' AND grant_id IS NOT NULL AND source='mdm.apple' AND self_service AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version>0 AND account_reference IS NOT NULL AND account_challenge IS NOT NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='apple_ade' AND grant_id IS NOT NULL AND source='mdm.apple' AND NOT self_service AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version>0 AND organization_challenge IS NOT NULL) OR
 (authority_kind='windows_entra' AND grant_id IS NOT NULL AND source='mdm.windows' AND NOT self_service AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version>0 AND organization_challenge IS NULL) OR
 (authority_kind='agent_policy' AND grant_id IS NOT NULL AND NOT self_service AND password_digest IS NOT NULL AND password_version=1 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL)
 )))

);

"###, $index_44, " ON ", $access_schema, r###"requests(tenant_id,issuance_operation) WHERE authority_kind='parent_certificate';

ALTER TABLE ONLY "###, $access_schema, r###"requests FORCE ROW LEVEL SECURITY;



ALTER TABLE ONLY "###, $access_schema, r###"credentials
    "###, $index_46, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"credentials
    "###, $index_47, r###" UNIQUE NULLS NOT DISTINCT (tenant_id, channel, locator);

ALTER TABLE ONLY "###, $access_schema, r###"devices
    "###, $index_48, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_49, r###" UNIQUE (tenant_id, issuance_operation);

ALTER TABLE ONLY "###, $access_schema, r###"grants
    "###, $index_50, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"registration_operations
    "###, $index_51, r###" PRIMARY KEY (tenant_id, actor, operation_id);







ALTER TABLE ONLY "###, $access_schema, r###"devices
    "###, $index_55, r###" UNIQUE (tenant_id, id, channel);

ALTER TABLE ONLY "###, $access_schema, r###"devices
    "###, $index_56, r###" UNIQUE (tenant_id, request_id);

ALTER TABLE ONLY "###, $access_schema, r###"report_sources
    "###, $index_57, r###" PRIMARY KEY (tenant_id, device, source);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_58, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_59, r###" UNIQUE (tenant_id, grant_id);



"###, $index_64, " ON ", $access_schema, r###"credentials USING btree (tenant_id, device, purpose) WHERE (state = 'active'::text);







ALTER TABLE "###, $access_schema, r###"credentials ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"grants ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"registration_operations ENABLE ROW LEVEL SECURITY;


ALTER TABLE "###, $access_schema, r###"report_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"requests ENABLE ROW LEVEL SECURITY;



CREATE POLICY tenant ON "###, $access_schema, r###"credentials USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"grants USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"registration_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));


CREATE POLICY tenant ON "###, $access_schema, r###"report_sources USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"requests USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
CREATE TABLE "###, $access_schema, r###"registration_users (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    instance text,
    principal text,
    PRIMARY KEY(tenant_id,device),
    CHECK((instance IS NULL)=(principal IS NULL))
);
ALTER TABLE "###, $access_schema, r###"registration_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"registration_users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"registration_users USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "registration_users TO ", $access_role, r###";
GRANT UPDATE(revision,instance,principal) ON "###, $access_schema, "registration_users TO ", $access_role, r###";
CREATE TABLE "###, $access_schema, r###"current_users (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    session_reference jsonb,
    confirmed_at bigint NOT NULL,
    PRIMARY KEY(tenant_id,device)
);
ALTER TABLE "###, $access_schema, r###"current_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"current_users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"current_users USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "current_users TO ", $access_role, r###";
GRANT UPDATE(revision,session_reference,confirmed_at) ON "###, $access_schema, "current_users TO ", $access_role, r###";
COMMIT;
"###) }; }
            macro_rules! inventory_install { () => { concat!(r###"BEGIN;
SET LOCAL check_function_bodies=false;
CREATE FUNCTION "###, $access_schema, r###"capture_asset_authority() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO "###, $access_path, r###"
    AS $$
DECLARE r jsonb; d jsonb; previous jsonb; k text; i text; dev text; v bigint; t uuid; platform text; registration_epoch uuid; previous_registration_epoch uuid;
BEGIN
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 IF TG_OP='UPDATE' THEN previous=to_jsonb(OLD); END IF;
 t=(r->>'tenant_id')::uuid;
 CASE TG_TABLE_NAME
 WHEN 'devices' THEN
  k='device'; i=r->>'id'; dev=i;
  IF r->>'channel'='agent' THEN
   SELECT g.platform INTO platform FROM "###, $access_schema, r###"certificate_grants g WHERE g.tenant_id=t AND g.id=(r->>'certificate_grant_id')::uuid;
  END IF;
  d=jsonb_build_object('id',i,'channel',r->>'channel','purpose',r->>'purpose','state',r->>'state','platform',platform,'epoch',r->>'epoch');
  IF previous IS NOT NULL AND d=jsonb_build_object('id',previous->>'id','channel',previous->>'channel','purpose',previous->>'purpose','state',previous->>'state','platform',platform,'epoch',previous->>'epoch') THEN RETURN NULL; END IF;
 WHEN 'report_sources' THEN
  dev=r->>'device'; k='source'; i=jsonb_build_array(dev,r->>'source')::text;
  d=jsonb_build_object('device',dev,'source',r->>'source','epoch',r->>'epoch','enabled',r->'enabled');
  IF previous IS NOT NULL AND d=jsonb_build_object('device',previous->>'device','source',previous->>'source','epoch',previous->>'epoch','enabled',previous->'enabled') THEN RETURN NULL; END IF;
 WHEN 'credentials' THEN
  k='credential'; i=r->>'id'; dev=r->>'device';
  -- Locators, secrets and protocol contexts never enter asset history.
  IF r->>'purpose'='windows_declared' THEN RETURN NULL; END IF;
  d=jsonb_build_object('id',i,'device',dev,'channel',r->>'channel','state',r->>'state');
 ELSE RAISE EXCEPTION 'unexpected asset authority';
 END CASE;
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF TG_TABLE_NAME='devices' THEN
  registration_epoch=(r->>'epoch')::uuid;
  previous_registration_epoch=(previous->>'epoch')::uuid;
 ELSE
  SELECT epoch INTO registration_epoch FROM "###, $access_schema, r###"devices WHERE tenant_id=t AND id=dev;
 END IF;
 v=mdm.record_asset_change(t,k,jsonb_build_object('fact',i,'device',dev,
  'registrationEpoch',registration_epoch,'previousRegistrationEpoch',previous_registration_epoch,
  'source',CASE WHEN TG_TABLE_NAME='report_sources' THEN r->>'source' END,
  'sourceEpoch',CASE WHEN TG_TABLE_NAME='report_sources' THEN r->>'epoch' END,
  'previousSourceEpoch',CASE WHEN TG_TABLE_NAME='report_sources' THEN previous->>'epoch' END,
  'operation',CASE WHEN TG_OP='DELETE' THEN 'deleted'
    WHEN (TG_TABLE_NAME='report_sources' AND NOT (r->>'enabled')::boolean)
      OR (TG_TABLE_NAME IN ('devices','credentials') AND r->>'state'<>'active') THEN 'revoked'
    WHEN TG_OP='INSERT' THEN 'created' ELSE 'updated' END),ARRAY[]::text[]);
 IF TG_OP='DELETE' THEN d=NULL; END IF;
 INSERT INTO "###, $access_schema, r###"asset_authority_history VALUES(t,k,i,dev,v,d);
 RETURN NULL;
END $$;

CREATE TABLE "###, $access_schema, r###"asset_authority_history (
    tenant_id uuid NOT NULL,
    kind text NOT NULL,
    identity text NOT NULL,
    device text,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT asset_authority_history_document_check CHECK (((document IS NULL) OR (octet_length((document)::text) <= 16384))),
    CONSTRAINT asset_authority_history_identity_check CHECK (((octet_length(identity) >= 1) AND (octet_length(identity) <= 1024))),
    CONSTRAINT asset_authority_history_kind_check CHECK ((kind = ANY (ARRAY['device'::text, 'source'::text, 'credential'::text])))
);

ALTER TABLE ONLY "###, $access_schema, r###"asset_authority_history FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY "###, $access_schema, r###"asset_authority_history
    "###, $index_45, r###" PRIMARY KEY (tenant_id, kind, identity, revision);
"###, $index_60, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, device, kind, identity, revision);



"###, $index_62, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, revision, device);

"###, $index_63, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, device, revision DESC);
ALTER TABLE "###, $access_schema, r###"asset_authority_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"asset_authority_history USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
COMMIT;
"###) }; }
            macro_rules! identity_relations { () => { concat!(r###"-- Fresh installation: device-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;



ALTER TABLE ONLY "###, $access_schema, r###"credentials
    "###, $index_68, " FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, r###"devices(tenant_id, id);



ALTER TABLE ONLY "###, $access_schema, r###"devices
    "###, $index_70, " FOREIGN KEY (tenant_id, request_id) REFERENCES ", $access_schema, r###"requests(tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"report_sources
    "###, $index_71, " FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, r###"devices(tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_72, " FOREIGN KEY (tenant_id, grant_id) REFERENCES ", $access_schema, r###"grants(tenant_id, id);

ALTER TABLE "###, $access_schema, "credentials ADD FOREIGN KEY(tenant_id,protocol_request) REFERENCES ", $access_schema, r###"requests(tenant_id,id);
GRANT UPDATE(protocol_epoch) ON "###, $access_schema, "requests TO ", $access_role, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $access_role, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $software_driver, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $command_runtime, r###";



GRANT SELECT,INSERT ON TABLE "###, $access_schema, "credentials TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "credentials TO ", $command_runtime, r###";

GRANT SELECT(tenant_id,id) ON TABLE "###, $access_schema, "credentials TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";

GRANT SELECT(device,purpose) ON TABLE "###, $access_schema, "credentials TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";

GRANT UPDATE(state) ON TABLE "###, $access_schema, "credentials TO ", $access_role, r###";
GRANT SELECT(state) ON TABLE "###, $access_schema, "credentials TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "devices TO ", $access_role, r###";
GRANT UPDATE(retirement) ON "###, $access_schema, "devices TO ", $access_role, ",", $policy_runtime, ",", $command_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "devices TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "devices TO ", $command_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "grants TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "registration_operations TO ", $access_role, r###";


GRANT UPDATE(protocol_ready,next_command) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";
GRANT UPDATE(protocol_ready,next_command) ON TABLE "###, $access_schema, "requests TO ", $command_runtime, r###";
GRANT UPDATE(state) ON TABLE "###, $access_schema, "devices TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "report_sources TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "report_sources TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "report_sources TO ", $command_runtime, r###";

GRANT UPDATE(enabled) ON TABLE "###, $access_schema, "report_sources TO ", $access_role, r###";

GRANT UPDATE(next_command) ON TABLE "###, $access_schema, "devices TO ", $access_role, r###";
GRANT UPDATE(next_command) ON TABLE "###, $access_schema, "devices TO ", $command_runtime, r###";

GRANT UPDATE(next_sequence) ON TABLE "###, $access_schema, "report_sources TO ", $access_role, r###";
GRANT UPDATE(next_sequence) ON TABLE "###, $access_schema, "report_sources TO ", $command_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "requests TO ", $command_runtime, r###";
-- Policy native acceptance reads source/profile evidence, never enrollment secrets.
GRANT SELECT(tenant_id,id,source,windows_profile) ON "###, $access_schema, "requests TO ", $policy_runtime, r###";

GRANT UPDATE(state) ON TABLE "###, $access_schema, "requests TO ", $access_role, ",", $command_runtime, r###";

GRANT UPDATE(password_digest) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(password_version) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(credential_ref) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(expires_at) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";


ALTER TABLE "###, $access_schema, "requests ", $index_75, " FOREIGN KEY(tenant_id,parent_credential) REFERENCES ", $access_schema, r###"credentials(tenant_id,id);
ALTER TABLE "###, $access_schema, "devices ", $index_76, " FOREIGN KEY(tenant_id,certificate_grant_id) REFERENCES ", $access_schema, r###"certificate_grants(tenant_id,id);

ALTER TABLE "###, $access_schema, "certificate_grants ", $index_78, " FOREIGN KEY(tenant_id,predecessor) REFERENCES ", $access_schema, r###"credentials(tenant_id,id);
ALTER TABLE "###, $access_schema, "certificate_issuances ", $index_79, " FOREIGN KEY(tenant_id,credential) REFERENCES ", $access_schema, r###"credentials(tenant_id,id);
GRANT SELECT,INSERT ON "###, $access_schema, "certificate_grants,", $access_schema, "certificate_issuances TO ", $access_role, r###";
GRANT UPDATE(actor,instance,state) ON "###, $access_schema, "certificate_grants TO ", $access_role, r###";
GRANT UPDATE(state,certificate_chain,metadata,fingerprint,activation_operation,activation_digest,activation_result,credential) ON "###, $access_schema, "certificate_issuances TO ", $access_role, r###";
GRANT SELECT,INSERT ON "###, $access_schema, "certificate_grants TO ", $command_runtime, r###";
GRANT SELECT(tenant_id,credential,not_after) ON "###, $access_schema, "certificate_issuances TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT UPDATE(last_communication_received_at) ON "###, $access_schema, "devices TO ", $access_role, ", ", $command_runtime, r###";
GRANT UPDATE(first_authenticated_at) ON "###, $access_schema, "devices TO ", $access_role, ", ", $command_runtime, r###";
GRANT UPDATE(account_version,account_reference,account_challenge) ON "###, $access_schema, "requests TO ", $access_role, r###";
GRANT UPDATE(organization_version,organization_challenge) ON "###, $access_schema, "requests TO ", $access_role, r###";
-- Device invokes Registration retirement on the shared audited command transaction.
GRANT UPDATE(state) ON "###, $access_schema, "devices,", $access_schema, "credentials TO ", $command_runtime, r###";
GRANT UPDATE(enabled) ON "###, $access_schema, "report_sources TO ", $command_runtime, r###";
COMMIT;
"###) }; }
            macro_rules! inventory_relations { () => { concat!(r###"BEGIN;
SET LOCAL check_function_bodies=false;
CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "credentials FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "devices FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();


CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "report_sources FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();

ALTER TABLE ONLY "###, $access_schema, r###"asset_authority_history
    "###, $index_67, r###" FOREIGN KEY (tenant_id, revision) REFERENCES mdm.asset_changes(tenant_id, revision);
REVOKE ALL ON FUNCTION "###, $access_schema, r###"capture_asset_authority() FROM PUBLIC;

GRANT SELECT ON TABLE "###, $access_schema, "asset_authority_history TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ",", $access_role, r###";
COMMIT;
"###) }; }
            pub(super) const SQL: super::Statements = super::Statements {
device_linked_prior_credentials: concat!("SELECT id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND device=$2 AND purpose='windows_declared' AND protocol_request<>$3 AND state='active' FOR UPDATE"),
device_linked_revoke_credentials: concat!("SELECT id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND device=$2 AND protocol_request=$3 AND state<>'revoked' FOR UPDATE"),
device_linked_revoke_state: concat!("WITH closed AS (UPDATE ", $access_schema, "requests SET state='cancelled',protocol_ready=false WHERE tenant_id=$1::uuid AND device=$2 AND id=$3 AND authority_kind='parent_certificate') UPDATE ", $access_schema, "credentials SET state='revoked' WHERE tenant_id=$1::uuid AND device=$2 AND protocol_request=$3"),

                identity_access_contract: concat!("{\"tables\":[{", $contract_table_90, ",\"read_write\":true,\"updates\":[\"state\"],\"delete_policy\":null},{", $contract_table_91, ",\"read_write\":true,\"updates\":[\"retirement\",\"state\",\"next_command\",\"first_authenticated_at\",\"last_communication_received_at\"],\"delete_policy\":null},{", $contract_table_92, ",\"read_write\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_93, ",\"read_write\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_95, ",\"read_write\":true,\"updates\":[\"enabled\",\"next_sequence\"],\"delete_policy\":null},{", $contract_table_96, ",\"read_write\":true,\"updates\":[\"state\",\"password_digest\",\"password_version\",\"credential_ref\",\"expires_at\",\"account_version\",\"account_reference\",\"account_challenge\",\"organization_version\",\"organization_challenge\",\"protocol_epoch\",\"protocol_ready\",\"next_command\"],\"delete_policy\":null},{", $contract_table_97, ",\"read_write\":true,\"updates\":[\"actor\",\"instance\",\"state\"],\"delete_policy\":null,\"insert_policy\":\"current_user<>'", $command_runtime, "'::nameorsource='native'::text\"},{", $contract_table_98, ",\"read_write\":true,\"updates\":[\"state\",\"certificate_chain\",\"metadata\",\"fingerprint\",\"activation_operation\",\"activation_digest\",\"activation_result\",\"credential\"],\"delete_policy\":null},{", $contract_table_100, ",\"read_write\":true,\"updates\":[\"revision\",\"instance\",\"principal\"],\"delete_policy\":null},{", $contract_table_105, ",\"read_write\":true,\"updates\":[\"revision\",\"session_reference\",\"confirmed_at\"],\"delete_policy\":null}],\"functions\":[],\"external_relations\":[],\"verified_schemas\":[]}"),
                identity_object_manifest: concat!("{\"tables\":[\"", $access_schema, "certificate_grants\",\"", $access_schema, "certificate_issuances\",\"", $access_schema, "credentials\",\"", $access_schema, "current_users\",\"", $access_schema, "devices\",\"", $access_schema, "grants\",\"", $access_schema, "registration_operations\",\"", $access_schema, "registration_users\",\"", $access_schema, "report_sources\",\"", $access_schema, "requests\"],\"functions\":[],\"views\":[]}"),
                device_trust_consumers: concat!("SELECT DISTINCT r.id FROM ", $access_schema, "devices r JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(r.tenant_id,r.id) JOIN ", $access_schema, "certificate_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE r.tenant_id=$1::uuid AND r.state='active' AND k.state='active' AND ($3::text IS NULL OR r.id=$3) AND i.not_after>floor(extract(epoch FROM clock_timestamp()))::bigint AND (($2='agent_task' AND r.channel='agent' AND r.purpose='primary' AND EXISTS(SELECT 1 FROM ", $access_schema, "report_sources s WHERE(s.tenant_id,s.device)=(r.tenant_id,r.id) AND s.source='agent.builtin' AND s.enabled)) OR ($2='da_configuration' AND r.channel IS NULL AND r.purpose='da_device'))"),
                da_registration: concat!("SELECT id AS device, state FROM ", $access_schema, "devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND purpose = 'da_device' AND channel IS NULL"),
                da_current_registration: concat!("SELECT r.id AS device, k.id AS credential FROM ", $access_schema, "devices AS r INNER JOIN ", $access_schema, "credentials AS k ON (k.tenant_id, k.device) = (r.tenant_id, r.id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.purpose = 'da_device' AND r.channel IS NULL AND r.state = 'active' AND k.state = 'active'"),
                da_insert_grant: concat!("INSERT INTO ", $access_schema, "certificate_grants(tenant_id,id,certificate_purpose,operation_id,source,actor,instance,device,secret_digest,request_digest,spki,state,expires_at,predecessor) VALUES($1::uuid,$2,'da_device',$3,$4,$5,$6,$7,$8,$9,$10,'available',clock_timestamp()+$11*interval '1 second',$12)"),
                da_grant_operation: concat!("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND certificate_purpose='da_device' AND source=$2 AND operation_id=$3"),
                device_installation_identity: concat!("SELECT instance_id FROM ", $installation),
                device_authenticate_endpoint_in_1: concat!("SELECT r.id AS device,r.epoch,r.state,k.id AS credential,k.state AS credential_state,i.identity FROM ", $access_schema, "certificate_issuances i JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.id)=(i.tenant_id,i.credential) JOIN ", $access_schema, "devices r ON(r.tenant_id,r.id)=(k.tenant_id,k.device) WHERE i.tenant_id=$1::uuid AND i.fingerprint=$2 AND r.purpose=$3 AND k.purpose=$3 AND k.channel IS NOT DISTINCT FROM r.channel"),
                quotas_configuration_on_1: concat!("SELECT revision,agent,windows_mdm,macos_mdm FROM ", $access_schema, "registration_quota_settings WHERE tenant_id=$1::uuid AND subject=$2"),
                admission_read_in_1: concat!("SELECT revision,paused FROM ", $access_schema, "registration_admission WHERE tenant_id=$1::uuid AND channel=$2"),
                admission_require_request_in_1: concat!("SELECT EXISTS (SELECT 1 FROM ", $access_schema, "devices AS r INNER JOIN ", $access_schema, "requests AS q ON (q.tenant_id, q.id) = (r.tenant_id, r.request_id) WHERE r.tenant_id = CAST($1 AS uuid) AND q.id = $2 AND r.state = 'active' AND (r.first_authenticated_at IS NOT NULL OR (q.source = 'mdm.apple' AND q.state = 'bound')))"),
                admission_change_1: concat!("INSERT INTO ", $access_schema, "registration_admission(tenant_id,channel,revision,paused) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,channel) DO UPDATE SET revision=EXCLUDED.revision,paused=EXCLUDED.paused"),
                admission_require_windows_in_1: concat!("SELECT first_authenticated_at IS NOT NULL FROM ", $access_schema, "devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active'"),
                agent_grant_row_1: concat!("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),



                lifecycle_work_allowed_on_1: concat!("SELECT retirement FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                lifecycle_begin_retirement_in_1: concat!("UPDATE ", $access_schema, "devices SET retirement=$3 WHERE tenant_id=$1::uuid AND id=$2 AND (retirement IS NULL OR retirement=$3)"),





                operations_read_1: concat!("SELECT digest,result,instance,action,device,self_enrollment FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid"),
                operations_save_result_1: concat!("INSERT INTO ", $access_schema, "registration_operations(tenant_id,actor,operation_id,digest,result,instance,agent_issuance_recovery,action,device,self_enrollment) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10)"),
                enrollment_agent_policy_create_in_1: concat!("SELECT l.*,g.device,r.state,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.source FROM ", $access_schema, "agent_native_enrollments l JOIN ", $access_schema, "requests r ON(r.tenant_id,r.id)=(l.tenant_id,l.request) JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE l.tenant_id=$1::uuid AND l.task=$2"),
                enrollment_agent_policy_create_in_2: concat!("INSERT INTO ", $access_schema, "grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,'enrollment','consumed',clock_timestamp(),to_timestamp($6))"),
                enrollment_agent_policy_create_in_3: concat!("INSERT INTO ", $access_schema, "requests(tenant_id,id,grant_id,state,source,device,password_digest,password_version,expires_at,issuance_operation,windows_profile,self_service,authority_kind) VALUES($1::uuid,$2,$3,'pending',$4,$8,$5,1,to_timestamp($6),$7,$9,false,'agent_policy')"),
                enrollment_agent_policy_create_in_4: concat!("INSERT INTO ", $access_schema, "agent_native_enrollments VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)"),
                enrollment_agent_policy_current_source_in_1: concat!("SELECT decode(k.locator,'hex') FROM ", $access_schema, "agent_native_enrollments l JOIN ", $access_schema, "devices r ON(r.tenant_id,r.id)=(l.tenant_id,l.source_device) JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(r.tenant_id,r.id) WHERE l.tenant_id=$1::uuid AND l.request=$2 AND r.state='active' AND r.channel='agent' AND k.state='active' AND k.channel='agent'"),
                enrollment_store_request_1: concat!("SELECT r.id::text,CASE r.authority_kind WHEN 'apple_account' THEN r.account_version WHEN 'apple_ade' THEN r.organization_version WHEN 'windows_entra' THEN r.organization_version ELSE r.password_version END AS native_version,r.authority_kind,r.account_version,r.account_reference,r.account_challenge,r.organization_version,r.organization_challenge,r.self_service,r.state,r.source,r.windows_profile,r.password_digest,r.password_version,r.credential_ref::text,r.issuance_operation::text,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.expires_at::text AS deadline,r.expires_at>clock_timestamp() AS live,g.actor,g.instance,r.device FROM ", $access_schema, "requests r JOIN ", $access_schema, "grants g ON (g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.issuance_operation IS NOT NULL AND r.authority_kind IN ('password','apple_account','apple_ade','windows_entra','agent_policy') FOR UPDATE OF r"),

                enrollment_store_create_enrollment_on_2: concat!("INSERT INTO ", $access_schema, "grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2::uuid,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t"),
                enrollment_store_create_enrollment_on_3: concat!("INSERT INTO ", $access_schema, "requests(tenant_id,id,grant_id,state,source,device,password_digest,password_version,credential_ref,expires_at,issuance_operation,windows_profile,self_service) VALUES($1::uuid,$2::uuid,$3::uuid,'pending',$4,$5,$6,1,$7::uuid,clock_timestamp()+interval '300 seconds',$8::uuid,$9,$10) RETURNING floor(extract(epoch FROM expires_at))::bigint"),
                enrollment_store_change_enrollment_on_1: concat!("UPDATE ", $access_schema, "requests SET password_digest=$3,password_version=password_version+1,credential_ref=$4::uuid,expires_at=clock_timestamp()+interval '300 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid RETURNING floor(extract(epoch FROM expires_at))::bigint"),
                enrollment_store_change_enrollment_on_2: concat!("UPDATE ", $access_schema, "requests SET state='cancelled' WHERE tenant_id=$1::uuid AND id=$2::uuid"),

                enrollment_store_mark_bound_in_1: concat!("UPDATE ", $access_schema, "requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND password_version=$3 AND expires_at>clock_timestamp() AND self_service=$4"),
                enrollment_read_enrollment_status_1: concat!("SELECT q.device,q.state, q.source, q.authority_kind, CASE q.authority_kind WHEN 'apple_account' THEN q.account_version WHEN 'apple_ade' THEN q.organization_version WHEN 'windows_entra' THEN q.organization_version ELSE q.password_version END AS authorization_version, q.windows_profile, q.credential_ref, CAST(floor(EXTRACT(EPOCH FROM q.expires_at)) AS bigint) AS expires_at, CAST(floor(EXTRACT(EPOCH FROM statement_timestamp())) AS bigint) AS now, r.id AS active_device, r.state AS registration_state, CAST(floor(EXTRACT(EPOCH FROM r.first_authenticated_at)) AS bigint) AS first_authenticated_at, EXISTS (SELECT 1 FROM ", $access_schema, "report_sources AS s WHERE s.tenant_id = r.tenant_id AND s.device = r.id AND s.source = q.source AND s.enabled) AS source_enabled FROM ", $access_schema, "requests AS q INNER JOIN ", $access_schema, "grants AS g ON (g.tenant_id, g.id) = (q.tenant_id, q.grant_id) LEFT JOIN ", $access_schema, "devices AS r ON (r.tenant_id, r.request_id) = (q.tenant_id, q.id) WHERE q.tenant_id = CAST($1 AS uuid) AND q.id = $2 AND g.device = $3 AND q.issuance_operation IS NOT NULL AND (NOT $4 OR (q.self_service AND g.instance = $5 AND g.actor = $6))"),
                enrollment_read_record_authenticated_in_1: concat!("UPDATE ", $access_schema, "devices SET first_authenticated_at = clock_timestamp() WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active' AND first_authenticated_at IS NULL"),
                enrollment_registration_read: concat!("SELECT jsonb_build_object('deviceId',d.id,'enrolledUser',coalesce(q.windows_profile='Full',false),'enrollmentId',d.request_id,'certificateGrantId',d.certificate_grant_id,'source',CASE WHEN d.channel='agent' THEN 'agent.builtin' ELSE q.source END,'status',d.state,'windowsDeclared',(SELECT jsonb_build_object('requestId',w.id,'ready',w.protocol_ready) FROM ", $access_schema, "requests w WHERE w.tenant_id=d.tenant_id AND w.device=d.id AND w.authority_kind='parent_certificate' AND w.state='bound')) FROM ", $access_schema, "devices d LEFT JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(d.tenant_id,d.request_id) WHERE d.tenant_id=$1::uuid AND d.id=$2"),
                quotas_management_change_1: concat!("INSERT INTO ", $access_schema, "registration_quota_settings(tenant_id,subject,revision,agent,windows_mdm,macos_mdm) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,subject) DO UPDATE SET revision=EXCLUDED.revision,agent=EXCLUDED.agent,windows_mdm=EXCLUDED.windows_mdm,macos_mdm=EXCLUDED.macos_mdm"),
                agent_native_source_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 AND installation=$3 AND active AND state<>'revoked' AND (state='consumed' OR deadline>extract(epoch FROM clock_timestamp())) AND source->>'device'=$4 AND source->>'credential'=$5)"),
                agent_native_native_grant_row_1: concat!("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND id=$2 AND source='native'"),
                agent_native_create_in_1: concat!(r###"
SELECT id FROM "###, $access_schema, r###"certificate_grants WHERE tenant_id=$1::uuid AND source='native' AND
native_authority->>'installation'= $2
"###),
                agent_native_create_in_2: concat!(r###"
INSERT INTO
"###, $access_schema, r###"certificate_grants(tenant_id,
id,
operation_id,
source,
actor,
instance,
device,
platform,
secret_digest,
request_digest,
spki,
state,
created_at,
expires_at,
native_authority)
VALUES($1::uuid,
$2,
$3,
'native',
$4,
$5,
$6,
$7,
$8,
$9,
$10,
'available',
statement_timestamp(),
least(to_timestamp($11),
statement_timestamp()+make_interval(secs=>$13)),
$12)
"###),
                agent_native_source_2: concat!("SELECT locator FROM ", $access_schema, "credentials WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $3 AND channel = 'mdm' AND state = 'active'"),
                certificate_grants_request_1: concat!("SELECT id FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND source='browser' AND operation_id=$2"),
                certificate_grants_request_2: concat!("SELECT count(*) FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND state='pending' AND expires_at>clock_timestamp()"),
                certificate_grants_request_3: concat!("INSERT INTO ", $access_schema, "certificate_grants(tenant_id,id,operation_id,source,device,platform,secret_digest,request_digest,spki,state,created_at,expires_at) VALUES($1::uuid,$2,$3,'browser',$4,$5,$6,$7,$8,'pending',statement_timestamp(),statement_timestamp()+make_interval(secs=>$9))"),


                certificate_grants_revoke_1: concat!("SELECT id FROM ", $access_schema, "certificate_issuances WHERE tenant_id=$1::uuid AND grant_id=$2"),
                certificate_grants_renewal_status_1: concat!("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND source='renewal' AND operation_id=$2"),
                certificate_grants_authorize_target_3: concat!(r###"
UPDATE "###, $access_schema, r###"certificate_grants SET actor=$3,instance=$4,state='available' WHERE
tenant_id=$1::uuid AND id=$2
"###),
                certificate_grants_revoke_2: concat!(r###"
UPDATE "###, $access_schema, r###"certificate_grants SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2
"###),
                certificate_grants_recovery_1: concat!("SELECT r.id AS device, r.state, k.id FROM ", $access_schema, "devices AS r INNER JOIN ", $access_schema, "credentials AS k ON (k.tenant_id, k.device) = (r.tenant_id, r.id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.channel = 'agent' AND k.state = 'active' FOR UPDATE OF r, k"),
                certificate_grants_recovery_2: concat!(r###"
SELECT id FROM "###, $access_schema, r###"certificate_grants WHERE tenant_id=$1::uuid AND source='recovery' AND
operation_id=$2
"###),
                certificate_grants_recovery_3: concat!("\nINSERT INTO\n", $access_schema, "certificate_grants(tenant_id,\nid,\noperation_id,\nsource,\nactor,\ninstance,\ndevice,\nplatform,\nsecret_digest,\nrequest_digest,\nspki,\nstate,\ncreated_at,\nexpires_at,\n\npredecessor)\nVALUES($1::uuid,\n$2,\n$3,\n'recovery',\n$4,\n$5,\n$6,\n$7,\n$8,\n$9,\n$10,\n'available',\nstatement_timestamp(),\nstatement_timestamp()+make_interval(secs=>$11),\n$12)\n"),
                certificate_grants_progress_1: concat!(r###"
SELECT id,state,activation_result FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND
grant_id=$2
"###),
                certificate_grants_renew_1: concat!("SELECT g.actor, g.instance, g.platform FROM ", $access_schema, "devices AS r INNER JOIN ", $access_schema, "certificate_grants AS g ON (g.tenant_id, g.id) = (r.tenant_id, r.certificate_grant_id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2"),
                certificate_grants_renew_2: concat!(r###"
SELECT id FROM "###, $access_schema, r###"certificate_grants WHERE tenant_id=$1::uuid AND source='renewal' AND
operation_id=$2
"###),
                certificate_grants_renew_3: concat!("\nINSERT INTO\n", $access_schema, "certificate_grants(tenant_id,\nid,\noperation_id,\nsource,\nactor,\ninstance,\ndevice,\nplatform,\nsecret_digest,\nrequest_digest,\nspki,\nstate,\ncreated_at,\nexpires_at,\n\npredecessor)\nVALUES($1::uuid,\n$2,\n$3,\n'renewal',\n$4,\n$5,\n$6,\n$7,\n$8,\n$9,\n$10,\n'available',\nstatement_timestamp(),\nstatement_timestamp()+make_interval(secs=>$11),\n$12)\n"),
                agent_connections_retirement_blockers_on_1: concat!("SELECT count(*) FROM ", $access_schema, "agent_configurations AS f WHERE f.tenant_id = CAST($1 AS uuid) AND NOT f.document #> '{connections,configuration,origins}' ?| CAST($2 AS text[]) AND ((f.state = 'available' AND f.expires_at > clock_timestamp()) OR EXISTS (SELECT 1 FROM ", $access_schema, "certificate_grants AS g WHERE g.tenant_id = f.tenant_id AND g.configuration_id = f.id AND g.state IN ('available', 'consumed') AND g.expires_at > clock_timestamp() AND NOT EXISTS (SELECT 1 FROM ", $access_schema, "devices AS r WHERE r.tenant_id = g.tenant_id AND r.certificate_grant_id = g.id)))"),
                agent_connections_retirement_blockers_on_2: concat!("SELECT count(*) FROM ", $access_schema, "agent_bootstraps AS b WHERE b.tenant_id = CAST($1 AS uuid) AND b.active AND NOT b.cleanup_complete AND b.state <> 'revoked' AND b.deadline > CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint) AND NOT b.download_origin = ANY(CAST($2 AS text[])) AND NOT EXISTS (SELECT 1 FROM ", $access_schema, "certificate_grants AS g INNER JOIN ", $access_schema, "devices AS r ON (r.tenant_id, r.certificate_grant_id) = (g.tenant_id, g.id) WHERE g.tenant_id = b.tenant_id AND g.native_authority ->> 'installation' = CAST(b.installation AS text) AND r.state = 'active')"),
                agent_connections_signer_on_1: concat!("SELECT key_id,public_key,private_key FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid"),
                agent_connections_ensure_signer_on_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid)"),
                agent_connections_ensure_signer_on_2: concat!("INSERT INTO ", $access_schema, "agent_configuration_keys(tenant_id,key_id,public_key,private_key) VALUES($1::uuid,$2,$3,$4)"),
                agent_connections_service_id_on_1: concat!("SELECT instance_id FROM ", $installation),
                agent_connections_draft_on_1: concat!("SELECT document FROM ", $access_schema, "agent_connection_drafts WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision=$2) ORDER BY revision DESC LIMIT 1"),
                agent_connections_published_on_1: concat!("SELECT document,k.public_key FROM ", $access_schema, "agent_connection_versions v JOIN ", $access_schema, "agent_configuration_keys k USING(tenant_id) WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision=$2) ORDER BY revision DESC LIMIT 1"),
                agent_connections_record_deployment_on_1: concat!("SELECT coalesce(max(revision),0) FROM ", $access_schema, "agent_connection_drafts WHERE tenant_id=$1"),
                agent_connections_record_deployment_on_2: concat!("INSERT INTO ", $access_schema, "agent_connection_deployments(tenant_id,origin,service_id,host_id,revision,configuration_revision,observed_at) VALUES($1,$2,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(tenant_id,origin) DO UPDATE SET service_id=excluded.service_id,host_id=excluded.host_id,revision=excluded.revision,configuration_revision=excluded.configuration_revision,observed_at=excluded.observed_at"),
                agent_connections_connection_state_1: concat!("SELECT origin,host_id,revision,configuration_revision,observed_at FROM ", $access_schema, "agent_connection_deployments WHERE tenant_id=$1::uuid AND service_id=$2 ORDER BY origin"),
                agent_connections_connection_state_2: concat!("SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM ", $access_schema, "agent_connection_observations AS o WHERE o.tenant_id = r.tenant_id AND o.device = r.id AND o.revision = $2)) FROM ", $access_schema, "devices AS r WHERE r.tenant_id = CAST($1 AS uuid) AND r.channel = 'agent' AND r.state = 'active'"),
                agent_connections_connection_state_3: concat!("SELECT key_id,public_key FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid"),
                agent_connections_save_connections_1: concat!("INSERT INTO ", $access_schema, "agent_connection_drafts(tenant_id,revision,document) VALUES($1::uuid,$2,$3)"),
                agent_connections_publish_connections_1: concat!("SELECT EXISTS (SELECT 1 FROM ", $access_schema, "devices AS r WHERE r.tenant_id = CAST($1 AS uuid) AND r.channel = 'agent' AND r.state = 'active' AND NOT EXISTS (SELECT 1 FROM ", $access_schema, "agent_connection_observations AS o WHERE o.tenant_id = r.tenant_id AND o.device = r.id AND o.operation_id = (SELECT n.operation_id FROM ", $access_schema, "agent_connection_observations AS n WHERE n.tenant_id = r.tenant_id AND n.device = r.id ORDER BY n.revision DESC, n.recorded_at DESC LIMIT 1) AND o.document ->> 'origin' = ANY(CAST($2 AS text[]))))"),
                agent_connections_publish_connections_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_connection_deployments WHERE tenant_id=$1::uuid AND origin=$2 AND service_id=$3 AND configuration_revision=$4 AND observed_at>=floor(extract(epoch FROM clock_timestamp()))::bigint-300)"),
                agent_connections_publish_connections_3: concat!("INSERT INTO ", $access_schema, "agent_connection_versions(tenant_id,revision,document) VALUES($1::uuid,$2,$3)"),
                agent_connections_connection_operation_1: concat!("SELECT result FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND instance=$3 AND operation_id=$4"),
                agent_connections_acknowledge_connections_1: concat!("SELECT document FROM ", $access_schema, "agent_connection_observations WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND operation_id = $3"),
                agent_connections_acknowledge_connections_2: concat!("SELECT max(revision) FROM ", $access_schema, "agent_connection_observations WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                agent_connections_acknowledge_connections_3: concat!("INSERT INTO ", $access_schema, "agent_connection_observations (tenant_id, device, operation_id, revision, document, received_at) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint))"),
                agent_connections_report_connection_failure_1: concat!("SELECT document FROM ", $access_schema, "agent_connection_failures WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND operation_id = $3"),
                agent_connections_report_connection_failure_2: concat!("INSERT INTO ", $access_schema, "agent_connection_failures (tenant_id, device, operation_id, revision, document, origin, received_at) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint))"),
                agent_connections_unconfirmed_connection_devices_1: concat!("SELECT r.id, r.id AS device, a.revision, a.document ->> 'origin' AS origin, a.received_at FROM ", $access_schema, "devices AS r LEFT JOIN LATERAL (SELECT revision, document, received_at FROM ", $access_schema, "agent_connection_observations WHERE tenant_id = r.tenant_id AND device = r.id ORDER BY revision DESC, recorded_at DESC LIMIT 1) AS a ON TRUE WHERE r.tenant_id = CAST($1 AS uuid) AND r.channel = 'agent' AND r.state = 'active' AND (CAST($2 AS uuid) IS NULL OR r.id > $2) AND (a.revision IS NULL OR a.revision <> $3) ORDER BY r.id LIMIT 101"),
                agent_connections_connection_observation_1: concat!("SELECT (SELECT max(revision) FROM ", $access_schema, "agent_connection_versions WHERE tenant_id = r.tenant_id) AS target_revision, r.id AS id, a.document, a.received_at, f.document AS failure_document, f.origin AS failure_origin, f.received_at AS failure_received_at FROM ", $access_schema, "devices AS r LEFT JOIN LATERAL (SELECT revision, document, received_at, recorded_at FROM ", $access_schema, "agent_connection_observations WHERE tenant_id = r.tenant_id AND device = r.id ORDER BY revision DESC, recorded_at DESC LIMIT 1) AS a ON TRUE LEFT JOIN LATERAL (SELECT document, origin, received_at FROM ", $access_schema, "agent_connection_failures WHERE tenant_id = r.tenant_id AND device = r.id AND (revision > COALESCE(a.revision, 0) OR (revision = a.revision AND recorded_at > a.recorded_at)) ORDER BY revision DESC, recorded_at DESC LIMIT 1) AS f ON TRUE WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.channel = 'agent' AND r.state = 'active'"),
                agent_connections_rewrap_1: concat!("SELECT key_id,private_key FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid AND substring(private_key FROM 1 FOR $2)<>$3 FOR UPDATE"),
                agent_connections_rewrap_2: concat!("UPDATE ", $access_schema, "agent_configuration_keys SET private_key=$3 WHERE tenant_id=$1::uuid AND key_id=$2"),
                agent_configurations_row_1: concat!("SELECT * FROM ", $access_schema, "agent_configurations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                agent_configurations_usage_1: concat!("SELECT count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM ", $access_schema, "certificate_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id)) AND g.state='available' AND g.expires_at>clock_timestamp()),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM ", $access_schema, "certificate_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id))) FROM ", $access_schema, "certificate_grants g WHERE g.tenant_id=$1::uuid AND g.configuration_id=$2"),
                agent_configurations_lock_for_grant_1: concat!("SELECT configuration_id FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND id=$2"),
                agent_configurations_create_configuration_1: concat!("SELECT id FROM ", $access_schema, "agent_configurations WHERE tenant_id=$1::uuid AND operation_id=$2"),
                agent_configurations_create_configuration_2: concat!("INSERT INTO ", $access_schema, "agent_configurations(tenant_id,id,operation_id,creator,instance,secret_digest,request_digest,signature,document,quantity,state,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',to_timestamp($11))"),
                agent_configurations_configuration_operation_1: concat!("SELECT id FROM ", $access_schema, "agent_configurations WHERE tenant_id=$1::uuid AND operation_id=$2 AND creator=$3 AND instance=$4"),
                agent_configurations_revoke_configuration_1: concat!("UPDATE ", $access_schema, "agent_configurations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2"),
                agent_configurations_exchange_configuration_1: concat!("SELECT id FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND source='configuration' AND operation_id=$2"),
                agent_configurations_exchange_configuration_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND configuration_id=$2 AND spki=$3)"),
                agent_configurations_exchange_configuration_3: concat!("INSERT INTO ", $access_schema, "certificate_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,created_at,expires_at,configuration_id,configuration_binding) VALUES($1::uuid,$2,$3,'configuration',$4,$5,$6,$7,$8,$9,$10,'available',statement_timestamp(),statement_timestamp()+make_interval(secs=>$11),$12,$13)"),
                agent_configurations_configuration_exchange_status_1: concat!("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>clock_timestamp() AS live FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND configuration_id=$2 AND operation_id=$3 AND source='configuration'"),
                agent_configurations_cancel_reservation_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "certificate_issuances WHERE tenant_id=$1::uuid AND grant_id=$2)"),
                agent_configurations_cancel_reservation_2: concat!("UPDATE ", $access_schema, "certificate_grants SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_bootstrap_challenge_1: concat!("UPDATE ", $access_schema, "agent_bootstraps SET state='signing',transaction_id=$3,csr_digest=$4,spki=$5,deadline=$6 WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_bootstrap_notify_1: concat!("UPDATE ", $access_schema, "agent_bootstraps SET state='issued',fingerprint=$3,certificate=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_native_grant_1: concat!("UPDATE ", $access_schema, "agent_bootstraps SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_row_1: concat!("SELECT installation_facts->>'device' FROM ", $access_schema, "agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_row_2: concat!("SELECT * FROM ", $access_schema, "agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                agent_bootstrap_require_delivery_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_bootstraps b WHERE b.tenant_id=$1::uuid AND b.id=$2 AND (EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE a.tenant_id=b.tenant_id AND a.operation=b.delivery AND a.phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE a.tenant_id=b.tenant_id AND a.operation=b.delivery AND a.phase='execute' AND a.state<>'pending')))"),
                agent_issuance_issue_1: concat!(r###"
SELECT * FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND grant_id=$2 FOR UPDATE
"###),
                agent_issuance_issue_2: concat!(r###"
INSERT INTO
"###, $access_schema, r###"certificate_issuances(tenant_id,
id,
grant_id,
operation_id,
request_digest,
csr,
spki,
identity,
profile,
not_before,
not_after,
authority_digest,
signing_issuer,
state)
VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'signing')
"###),
                agent_issuance_issue_3: concat!(r###"
UPDATE "###, $access_schema, r###"certificate_grants SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_issuance_record_unknown_1: concat!(r###"
UPDATE "###, $access_schema, r###"certificate_issuances SET state='unknown' WHERE tenant_id=$1::uuid AND id=$2 AND
state='signing'
"###),
                agent_issuance_save_certificate_1: concat!(r###"
SELECT * FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND id=$2 AND grant_id=$3 FOR
UPDATE
"###),
                agent_issuance_save_certificate_2: concat!(r###"
UPDATE "###, $access_schema, r###"certificate_issuances SET
state='issued',certificate_chain=$3,metadata=$4,fingerprint=$5 WHERE tenant_id=$1::uuid AND
id=$2
"###),
                agent_issuance_save_certificate_3: concat!(r###"
SELECT * FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_issuance_recover_issuance_1: concat!(r###"
SELECT * FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_current_user_bindings_on_1: concat!("SELECT u.device, u.revision, u.session_reference, u.confirmed_at, (SELECT decode(k.locator, 'hex') FROM ", $access_schema, "devices AS r INNER JOIN ", $access_schema, "credentials AS k ON (k.tenant_id, k.device) = (r.tenant_id, r.id) INNER JOIN ", $access_schema, "certificate_issuances AS i ON (i.tenant_id, i.credential) = (k.tenant_id, k.id) WHERE r.tenant_id = u.tenant_id AND r.id = u.device AND r.id = u.device AND r.channel = 'agent' AND r.purpose = 'primary' AND r.state = 'active' AND k.state = 'active' AND i.not_before <= EXTRACT(EPOCH FROM statement_timestamp()) AND i.not_after > EXTRACT(EPOCH FROM statement_timestamp())) AS fingerprint FROM ", $access_schema, "current_users AS u WHERE u.tenant_id = CAST($1 AS uuid) AND u.device = ANY($2)"),
                agent_current_user_change_current_user_1: concat!("SELECT digest,result,instance FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3"),
                agent_current_user_change_current_user_2: concat!("INSERT INTO ", $access_schema, "current_users (tenant_id, device, revision, session_reference, confirmed_at) VALUES (CAST($1 AS uuid), $2, $3, $4, $5) ON CONFLICT (tenant_id, device) DO UPDATE SET revision = excluded.revision, session_reference = excluded.session_reference, confirmed_at = excluded.confirmed_at"),
                agent_current_user_change_current_user_3: concat!("INSERT INTO ", $access_schema, "registration_operations(tenant_id,actor,instance,operation_id,digest,result,action,device,self_enrollment) VALUES($1::uuid,$2,$3,$4,$5,$6,'agent_current_user_change',$7,true)"),
                agent_queries_issuance_device_1: concat!("SELECT g.device FROM ", $access_schema, "certificate_issuances i JOIN ", $access_schema, "certificate_grants g ON(g.tenant_id,g.id)=(i.tenant_id,i.grant_id) WHERE i.tenant_id=$1::uuid AND i.id=$2"),
                agent_queries_request_details_1: concat!("SELECT device FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND id=$2"),
                agent_queries_registration_recovery_operation_1: concat!("SELECT id AS device FROM ", $access_schema, "devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND channel = 'agent'"),
                agent_queries_registration_recovery_operation_2: concat!("SELECT id,state,platform,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>statement_timestamp() AS live,actor,instance,device FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND source='recovery' AND operation_id=$2 AND device=$3"),
                agent_queries_issuance_recovery_operations_1: concat!("SELECT jsonb_build_object('actor',actor,'instance',instance,'operationId',operation_id) FROM ", $access_schema, "registration_operations WHERE tenant_id="),
                agent_queries_issuance_recovery_operation_1: concat!("SELECT * FROM ", $access_schema, "certificate_issuances WHERE tenant_id=$1::uuid AND id=$2"),
                agent_queries_issuance_recovery_operation_2: concat!("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>statement_timestamp() AS live FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND id=$2"),
                agent_queries_issuance_recovery_operation_3: concat!("SELECT result,digest,instance,agent_issuance_recovery FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3 AND agent_issuance_recovery=$4"),
                agent_settings_initialize_on_1: concat!("INSERT INTO ", $access_schema, "agent_enrollment_settings(tenant_id,revision,document) VALUES($1::uuid,1,$2)"),
                agent_settings_tenant_seed_sql_1: concat!("CREATE FUNCTION ", $access_schema, "seed_tenant_settings(t uuid) RETURNS void LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $seed$ INSERT INTO ", $access_schema, "agent_enrollment_settings(tenant_id,revision,document) VALUES(t,1,'", $default_agent_values, "'::jsonb); $seed$; REVOKE ALL ON FUNCTION ", $access_schema, "seed_tenant_settings(uuid) FROM PUBLIC;"),
                agent_settings_read_on_1: concat!("SELECT revision,document FROM ", $access_schema, "agent_enrollment_settings WHERE tenant_id=$1::uuid"),
                agent_settings_update_settings_1: concat!("SELECT tenant_id FROM ", $access_schema, "agent_enrollment_settings WHERE tenant_id=$1::uuid FOR UPDATE"),
                agent_settings_update_settings_2: concat!("UPDATE ", $access_schema, "agent_enrollment_settings SET revision=revision+1,document=$2 WHERE tenant_id=$1::uuid"),


                agent_activation_activate_3: concat!(r###"
SELECT grant_id FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_activation_activate_4: concat!(r###"
SELECT * FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE
"###),
                agent_activation_activate_5: concat!("SELECT r.state,k.state AS credential_state FROM ", $access_schema, "devices r JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND k.id=$3 AND r.channel IS NOT DISTINCT FROM $4 FOR UPDATE OF r,k"),
                agent_activation_activate_6: concat!(r###"
SELECT activation_result FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND
credential=$2
"###),
                agent_activation_activate_7: concat!(r###"
SELECT profile FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND credential=$2
"###),
                agent_activation_activate_8: concat!(r###"
UPDATE "###, $access_schema, r###"credentials SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2 AND
state='active'
"###),

                agent_activation_activate_10: concat!("INSERT INTO ", $access_schema, "devices(tenant_id,id,certificate_grant_id,epoch,channel,purpose,state) VALUES($1::uuid,$2,$3,$4,$5,$6,'active')"),
                agent_activation_activate_11: concat!("INSERT INTO ", $access_schema, "report_sources(tenant_id,device,source,epoch,enabled) VALUES($1::uuid,$2,$3,$4,true)"),
                agent_activation_activate_12: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,device,locator,channel,purpose,state) VALUES($1::uuid,$2,$3,$4,$5,$6,'active')"),
                agent_activation_activate_13: concat!(r###"
UPDATE "###, $access_schema, r###"certificate_issuances SET
activation_operation=$3,activation_digest=$4,activation_result=$5,credential=$6 WHERE
tenant_id=$1::uuid AND id=$2
"###),
                agent_activation_authenticate_1: concat!(r###"
SELECT not_after FROM "###, $access_schema, r###"certificate_issuances WHERE tenant_id=$1::uuid AND fingerprint=$2 AND
credential IS NOT NULL
"###),
                device_registration_user_assign_registration_user_1: concat!("INSERT INTO ", $access_schema, "registration_users(tenant_id,device,revision,instance,principal) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=EXCLUDED.revision,instance=EXCLUDED.instance,principal=EXCLUDED.principal"),
                device_registration_user_target_on_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2) OR EXISTS(SELECT 1 FROM ", $access_schema, "requests q JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND g.device=$2 AND q.issuance_operation IS NOT NULL AND q.state<>'cancelled') OR EXISTS(SELECT 1 FROM ", $access_schema, "certificate_grants WHERE tenant_id=$1::uuid AND device=$2 AND state IN('available','issued','active'))"),
                device_registration_user_read_on_1: concat!("SELECT revision,instance,principal FROM ", $access_schema, "registration_users WHERE tenant_id=$1::uuid AND device=$2"),
                device_registration_user_initialize_on_1: concat!("INSERT INTO ", $access_schema, "registration_users(tenant_id,device,revision,instance,principal) VALUES($1::uuid,$2,1,$3,$4) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=registration_users.revision+1,instance=EXCLUDED.instance,principal=EXCLUDED.principal WHERE registration_users.principal IS NULL"),
                device_registration_user_page_on_1: concat!("SELECT device,revision,instance,principal FROM ", $access_schema, "registration_users WHERE tenant_id=$1::uuid AND device=ANY($2)"),
                device_store_record_communication_in_1: concat!("UPDATE ", $access_schema, "devices SET last_communication_received_at=greatest(last_communication_received_at,clock_timestamp()) WHERE tenant_id=$1::uuid AND id=$2 AND channel=$3 AND purpose='primary' AND state='active'"),
                device_store_authorize_report_1: concat!("SELECT device::text AS id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3"),
                device_store_authorize_report_2: concat!("SELECT r.id AS device,r.channel,r.epoch::text,q.windows_profile FROM ", $access_schema, "devices r JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.channel=$3 AND r.purpose='primary' AND r.state='active' FOR SHARE OF r"),
                device_store_authorize_report_3: concat!("SELECT c.id::text AS id,s.epoch::text AS epoch FROM ", $access_schema, "credentials c JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.device)=(c.tenant_id,c.device) WHERE c.tenant_id=$1::uuid AND c.device=$2 AND c.channel=$3 AND c.locator=$4 AND c.state='active' AND s.source=$5 AND s.enabled FOR SHARE OF c,s"),
                device_store_current_scope_1: concat!("SELECT r.id::text AS id,s.epoch::text AS epoch FROM ", $access_schema, "devices r JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.device)=(r.tenant_id,r.id) JOIN ", $access_schema, "credentials c ON (c.tenant_id,c.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.channel=$3 AND r.state='active' AND c.state='active' AND s.source=$4 AND s.enabled"),
                device_store_retire_state_in_1: concat!("SELECT channel,state FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                device_store_retire_state_in_2: concat!("WITH closed AS (UPDATE ", $access_schema, "requests SET state='cancelled' WHERE tenant_id=$1::uuid AND device=$2 AND state<>'cancelled') UPDATE ", $access_schema, "devices SET state=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                device_store_retire_state_in_3: concat!("UPDATE ", $access_schema, "credentials SET state=$3 WHERE tenant_id=$1::uuid AND device=$2"),
                device_store_retire_state_in_4: concat!("UPDATE ", $access_schema, "report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2"),
                device_store_bind_authorized_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND request_id=$2::uuid)"),
                device_store_bind_authorized_in_2: concat!("SELECT source FROM ", $access_schema, "requests WHERE tenant_id=$1::uuid AND id=$2::uuid AND device=$3 AND authority_kind<>'parent_certificate' AND state='pending'"),

                device_store_bind_authorized_in_4: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3)"),


                device_store_bind_authorized_in_7: concat!("INSERT INTO ", $access_schema, "devices(tenant_id,id,channel,request_id,state,purpose,epoch) VALUES($1::uuid,$2,$3,$4::uuid,'active','primary',$5::uuid)"),
                device_store_bind_authorized_in_8: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,device,channel,locator,state,purpose) SELECT $1::uuid,$2::uuid,$3,$4,$5,'active','primary' FROM ", $access_schema, "requests WHERE tenant_id=$1::uuid AND id=$6 AND device=$3"),
                device_store_bind_authorized_in_9: concat!("INSERT INTO ", $access_schema, "report_sources(tenant_id,device,source,epoch,enabled) VALUES($1::uuid,$2,$3,$4::uuid,true)"),
                device_store_replace_mdm_credential_in_1: concat!("SELECT k.id FROM ", $access_schema, "credentials k JOIN ", $access_schema, "devices d ON(d.tenant_id,d.id)=(k.tenant_id,k.device) LEFT JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(k.tenant_id,k.protocol_request) WHERE k.tenant_id=$1::uuid AND k.device=$2 AND k.id=$3 AND k.channel='mdm' AND k.state='active' AND d.state='active' AND (k.protocol_request IS NULL OR q.state='bound') FOR UPDATE OF k"),
                device_store_replace_mdm_credential_in_2: concat!("UPDATE ", $access_schema, "credentials SET state='superseded' WHERE tenant_id=$1::uuid AND device=$2 AND id=$3 AND state='active'"),
                device_store_replace_mdm_credential_in_3: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,device,channel,locator,state,purpose,protocol_request) SELECT tenant_id,$2::uuid,device,channel,$4,'active',purpose,protocol_request FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND device=$3 AND id=$5 AND state='superseded'"),
                device_store_revalidate_source_1: concat!("SELECT id AS device FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2 AND channel=$3 AND state='active'"),
                device_store_revalidate_source_2: concat!("SELECT id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND device=$2 AND id=$3::uuid AND state='active'"),
                device_store_revalidate_source_3: concat!("SELECT epoch::text FROM ", $access_schema, "report_sources WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND enabled"),
                device_store_revoke_on_1: concat!("SELECT channel FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                device_store_revoke_on_2: concat!("SELECT state FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                device_store_active_source_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices r JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.state='active' AND s.source=$3 AND s.enabled)"),
                device_store_allocate_collection_in_1: concat!("SELECT s.epoch FROM ", $access_schema, "devices r JOIN ", $access_schema, "credentials c ON (c.tenant_id,c.device)=(r.tenant_id,r.id) JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.state='active' AND c.state='active' AND s.source=$3 AND s.enabled FOR UPDATE OF s"),
                device_store_allocate_collection_in_2: concat!("UPDATE ", $access_schema, "report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND next_sequence<9223372036854775807 RETURNING next_sequence-1"),
                device_store_source_current_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "report_sources WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND epoch=$4::uuid AND enabled)"),
                device_store_allocate_report_in_1: concat!("WITH locked AS MATERIALIZED (SELECT r.id FROM ", $access_schema, "devices r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.purpose='primary' AND r.state='active' AND s.source=$3 AND s.epoch=$4::uuid AND s.enabled AND s.next_sequence<9223372036854775807 AND r.next_command<=$6 FOR UPDATE OF r,s), ids AS (UPDATE ", $access_schema, "devices r SET next_command=next_command+$5 FROM locked WHERE r.tenant_id=$1::uuid AND r.id=locked.id RETURNING r.id,r.next_command-$5 AS first), seq AS (UPDATE ", $access_schema, "report_sources s SET next_sequence=next_sequence+1 FROM ids WHERE s.tenant_id=$1::uuid AND s.device=ids.id AND s.source=$3 RETURNING s.next_sequence-1 AS sequence) SELECT sequence,first FROM seq CROSS JOIN ids"),
                device_store_allocate_task_report_in_1: concat!("UPDATE ", $access_schema, "report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND enabled AND next_sequence<9223372036854775807 RETURNING epoch::text,next_sequence-1"),
                device_store_allocate_commands_in_1: concat!("WITH main AS (UPDATE ", $access_schema, "devices SET next_command=next_command+$4 WHERE tenant_id=$1::uuid AND id=$2 AND $3::uuid IS NULL AND state='active' AND next_command<=4294967296-$4 RETURNING next_command-$4 AS first), protocol AS (UPDATE ", $access_schema, "requests SET next_command=next_command+$4 WHERE tenant_id=$1::uuid AND device=$2 AND id=$3 AND authority_kind='parent_certificate' AND state='bound' AND next_command<=4294967296-$4 RETURNING next_command-$4 AS first) SELECT first FROM main UNION ALL SELECT first FROM protocol"),
                device_store_activate_renewed_mdm_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices r JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(r.tenant_id,r.id) LEFT JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(k.tenant_id,k.protocol_request) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.state='active' AND k.id=$3 AND k.state='active' AND k.purpose=$4 AND (k.protocol_request IS NULL OR q.state='bound'))"),
                device_store_revalidate_collection_source_1: concat!("SELECT epoch FROM ", $access_schema, "report_sources WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 AND enabled"),
                device_store_live_collection_streams_on_1: concat!("SELECT s.device,s.source,s.epoch FROM ", $access_schema, "devices r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND s.enabled AND s.source IN('agent.native','agent.script','agent.osquery') AND EXISTS(SELECT 1 FROM ", $access_schema, "credentials k JOIN ", $access_schema, "certificate_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE k.tenant_id=r.tenant_id AND k.device=r.id AND k.state='active' AND i.not_after>floor(extract(epoch FROM clock_timestamp()))::bigint) ORDER BY r.id,s.source LIMIT 65"),
                device_store_collection_stream_retired_on_1: concat!("SELECT NOT EXISTS(SELECT 1 FROM ", $access_schema, "devices r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND s.source=$3 AND s.epoch=$4 AND s.enabled)"),
                device_store_report_epoch_in_1: concat!("SELECT s.epoch FROM ", $access_schema, "report_sources s JOIN ", $access_schema, "devices r ON(r.tenant_id,r.id)=(s.tenant_id,s.device) WHERE s.tenant_id=$1::uuid AND s.device=$2 AND s.source=$3 AND s.enabled AND r.state='active'"),
                device_endpoints_current_in_1: concat!("SELECT r.id FROM ", $access_schema, "devices r WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.channel=$3 AND r.purpose='primary' AND r.state='active' AND EXISTS(SELECT FROM ", $access_schema, "credentials k WHERE(k.tenant_id,k.device)=(r.tenant_id,r.id) AND k.state='active')"),
                device_endpoints_current_page_in_1: concat!("SELECT r.id AS device,r.channel FROM ", $access_schema, "devices r WHERE r.tenant_id=$1::uuid AND r.id=ANY($2) AND r.purpose='primary' AND r.state='active' AND EXISTS(SELECT FROM ", $access_schema, "credentials k WHERE(k.tenant_id,k.device)=(r.tenant_id,r.id) AND k.state='active') ORDER BY r.id"),
                device_endpoints_page_in_1: concat!("SELECT id FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id COLLATE \"C\">$2 COLLATE \"C\" ORDER BY id COLLATE \"C\" LIMIT $3"),
                device_endpoints_page_at_1: concat!("WITH latest AS (\n SELECT DISTINCT ON(kind,identity) kind,identity,device,document FROM ", $access_schema, "asset_authority_history\n WHERE tenant_id=$1::uuid AND device=ANY($2) AND mdm.asset_visible($3::jsonb,revision) ORDER BY kind,identity,revision DESC\n) SELECT d.device,d.document->>'channel' AS channel FROM latest d\n WHERE d.kind='device' AND d.document->>'purpose'='primary' AND d.document->>'state'='active'\n AND EXISTS(SELECT FROM latest k WHERE k.kind='credential' AND k.device=d.device AND k.document->>'state'='active') ORDER BY d.device"),
                device_endpoints_candidate_page_in_1: concat!("SELECT r.id FROM ", $access_schema, "devices r WHERE r.tenant_id=$1::uuid AND r.channel=$2 AND r.purpose='primary' AND r.state='active' AND r.id COLLATE \"C\">$3 COLLATE \"C\" AND ($4::text[] IS NULL OR r.id=ANY($4)) ORDER BY r.id COLLATE \"C\" LIMIT $5"),
                device_endpoints_lifecycle_page_at_1: concat!("\n        WITH latest AS (\n            SELECT DISTINCT ON(kind,identity) kind,identity,device,document\n            FROM ", $access_schema, "asset_authority_history\n            WHERE tenant_id=$1::uuid AND device=ANY($2) AND mdm.asset_visible($3::jsonb,revision)\n            ORDER BY kind,identity,revision DESC\n        ), live AS (\n            SELECT r.device,CASE s.document->>'source'\n                WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos'\n                ELSE r.document->>'platform' END AS platform\n            FROM latest r JOIN latest s ON s.device=r.device AND s.kind='source'\n                JOIN latest k ON k.device=r.device AND k.kind='credential'\n                \n            WHERE r.kind='device' AND r.document->>'purpose'='primary'\n                AND r.document->>'state'='active' AND k.document->>'state'='active'\n                AND s.document->>'enabled'='true'\n        ) SELECT d AS device,count(l.device)>0 AS managed,\n            min(l.platform) AS platform,count(DISTINCT l.platform)>1 OR bool_or(l.device IS NOT NULL AND l.platform IS NULL) AS conflict\n        FROM unnest($2::text[]) d LEFT JOIN live l ON l.device=d GROUP BY d ORDER BY d COLLATE \"C\"\n    "),
                device_read_find_1: concat!("SELECT id FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                device_read_active_sources_1: concat!("SELECT r.id AS device,r.channel,s.source,s.epoch::text FROM ", $access_schema, "devices r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=ANY($2) AND r.state='active' AND s.enabled AND EXISTS(SELECT FROM ", $access_schema, "credentials c WHERE(c.tenant_id,c.device)=(r.tenant_id,r.id) AND c.state='active') ORDER BY r.id,s.source"),
                device_read_exists_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2)"),
                device_read_sources_at_1: concat!("SELECT * FROM ", $access_schema, "asset_sources_at($2,$3) WHERE nullif(current_setting('rss.tenant_id',true),'')=$1"),
                device_read_registered_1: concat!("SELECT EXISTS(SELECT FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2 AND state='active')"),
                device_read_active_channel_in_1: concat!("SELECT d.id FROM ", $access_schema, "devices d WHERE d.tenant_id=$1::uuid AND d.id=ANY($2) AND d.channel=$3 AND d.state='active' AND (($4='primary' AND d.purpose='primary') OR ($4='windows_declared' AND EXISTS(SELECT FROM ", $access_schema, "requests q WHERE(q.tenant_id,q.device)=(d.tenant_id,d.id) AND q.authority_kind='parent_certificate' AND q.state='bound' AND q.protocol_ready))) ORDER BY d.id"),
                device_read_active_sources_in_1: concat!("SELECT r.id FROM ", $access_schema, "devices r WHERE r.tenant_id=$1::uuid AND r.id=ANY($2) AND r.state='active' AND EXISTS(SELECT FROM ", $access_schema, "report_sources s WHERE(s.tenant_id,s.device)=(r.tenant_id,r.id) AND s.source=$3 AND s.enabled)"),

                device_read_enabled_source_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices r LEFT JOIN ", $access_schema, "requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) JOIN ", $access_schema, "credentials k ON (k.tenant_id,k.device)=(r.tenant_id,r.id) JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.device)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.state='active' AND k.state='active' AND (q.source=$3 OR (r.channel='agent' AND $3='agent.builtin')) AND s.source=$3 AND s.enabled)"),
                device_read_inactive_in_1: concat!("SELECT NOT EXISTS(SELECT FROM ", $access_schema, "devices r WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.state='active' AND EXISTS(SELECT FROM ", $access_schema, "credentials c WHERE(c.tenant_id,c.device)=(r.tenant_id,r.id) AND c.state='active'))"),
                device_read_timeline_device_in_1: concat!("SELECT id FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                device_read_timeline_enrollment_in_1: concat!("SELECT g.device FROM ", $access_schema, "requests r JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2"),

                device_read_live_at_1: concat!("\n                WITH latest AS (\n                    SELECT DISTINCT ON(kind,identity) kind,identity,device,document\n                    FROM ", $access_schema, "asset_authority_history\n                    WHERE tenant_id=$1::uuid AND device=ANY($2) AND mdm.asset_visible($3,revision)\n                      AND kind IN('device','credential','source')\n                    ORDER BY kind,identity,revision DESC\n                ), live AS (\n                    SELECT device FROM latest GROUP BY device\n                    HAVING bool_or(kind='device' AND document->>'state'='active')\n                       AND bool_or(kind='credential' AND document->>'state'='active')\n                       AND bool_or(kind='source' AND document->>'enabled'='true')\n                ) SELECT DISTINCT device FROM live\n            "),
                device_read_page_at_1: concat!("\n              WITH latest AS (\n                SELECT DISTINCT ON(identity COLLATE \"C\") identity,document\n                FROM ", $access_schema, "asset_authority_history\n                WHERE tenant_id=$1::uuid AND kind='device' AND mdm.asset_visible($2,revision)\n                  AND identity COLLATE \"C\">coalesce($3::text,'') COLLATE \"C\"\n                  AND ($4 OR identity=ANY($5))\n                ORDER BY identity COLLATE \"C\",revision DESC\n              ) SELECT identity FROM latest WHERE document IS NOT NULL\n                ORDER BY identity COLLATE \"C\" LIMIT $6\n            "),
                device_linked_request_in_1: concat!("SELECT q.windows_profile FROM ", $access_schema, "devices d JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(d.tenant_id,d.request_id) WHERE d.tenant_id=$1::uuid AND d.id=$2 AND q.source='mdm.windows' AND d.state='active'"),

                device_linked_request_in_3: concat!("INSERT INTO ", $access_schema, "requests(tenant_id,id,device,parent_credential,issuance_operation,windows_profile,state,expires_at,source,authority_kind) VALUES($1::uuid,$2,$3,$4,$5,$6,'pending',clock_timestamp()+interval '5 minutes','mdm.windows','parent_certificate')"),
                device_linked_bind_in_1: concat!("SELECT issuance_operation FROM ", $access_schema, "requests WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND parent_credential=$4 AND authority_kind='parent_certificate' AND state='pending' AND expires_at>clock_timestamp() FOR UPDATE"),

                device_linked_bind_in_3: concat!("WITH closed AS (UPDATE ", $access_schema, "requests SET state='cancelled' WHERE tenant_id=$1::uuid AND device=$2 AND id<>$3 AND authority_kind='parent_certificate' AND state<>'cancelled') UPDATE ", $access_schema, "credentials SET state='superseded' WHERE tenant_id=$1::uuid AND device=$2 AND purpose='windows_declared' AND protocol_request<>$3 AND state='active'"),

                device_linked_bind_in_5: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,device,locator,channel,state,purpose,protocol_request) VALUES($1::uuid,$2,$3,$4,'mdm','active','windows_declared',$5)"),
                device_linked_bind_in_6: concat!("UPDATE ", $access_schema, "requests SET state='bound',protocol_epoch=$3 WHERE tenant_id=$1::uuid AND id=$2 AND state='pending'"),
                device_linked_ready_in_1: concat!("UPDATE ", $access_schema, "requests SET protocol_ready=true WHERE tenant_id=$1::uuid AND device=$2 AND id=$3 AND authority_kind='parent_certificate' AND state='bound' AND NOT protocol_ready"),
                device_coordinates_authority_at_on_1: concat!("SELECT coalesce(max(revision),0) FROM ", $access_schema, "asset_authority_history WHERE tenant_id=$1::uuid AND device=$2 AND mdm.asset_visible($3,revision)"),


                device_directory_source_budget_1: concat!("WITH source_budget AS MATERIALIZED (SELECT count(*) AS rows FROM (SELECT tenant_id FROM ", $access_schema, "directory_inputs WHERE tenant_id="),
                device_directory_selection_1: concat!(", selected AS (SELECT d.id,d.status FROM ", $access_schema, "directory_metadata d WHERE (SELECT rows FROM source_budget)<="),
                device_directory_selection_2: concat!(") SELECT s.id,b.rows,e.summary FROM source_budget b LEFT JOIN selected s ON true LEFT JOIN ", $access_schema, "directory_endpoints e ON e.tenant_id=$1::uuid AND e.id=s.id"),
                device_directory_directory_statistics_1: concat!(" THEN (SELECT jsonb_build_object('statistics',jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE d.status='pending'),'active',count(*) FILTER(WHERE d.status='active'),'revoked',count(*) FILTER(WHERE d.status='revoked')),'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint) FROM ", $access_schema, "directory_metadata d WHERE d.tenant_id=$1::uuid"),
                device_directory_page_on_1: concat!("SELECT d.summary FROM unnest($2::text[]) WITH ORDINALITY p(id,n) JOIN ", $access_schema, "directory_endpoints d ON d.id=p.id WHERE d.tenant_id=$1::uuid ORDER BY p.n"),
                device_management_read_1: concat!("SELECT d.id AS device,k.purpose,coalesce(q.protocol_epoch,d.epoch) AS epoch,k.protocol_request,main.windows_profile,k.id AS credential FROM ", $access_schema, "devices d JOIN ", $access_schema, "requests main ON(main.tenant_id,main.id)=(d.tenant_id,d.request_id) JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(d.tenant_id,d.id) LEFT JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(k.tenant_id,k.protocol_request) WHERE d.tenant_id=$1::uuid AND d.channel=$2 AND k.purpose=$3 AND d.state='active' AND main.source=$4 AND k.channel=$2 AND k.state='active' AND k.locator=$5 AND (k.protocol_request IS NULL OR (q.state='bound' AND q.device=d.id))"),

                device_management_validate_2: concat!("SELECT k.state,r.state AS registration_state,i.not_after FROM ", $access_schema, "credentials k JOIN ", $access_schema, "devices r ON(r.tenant_id,r.id)=(k.tenant_id,k.device) JOIN ", $access_schema, "certificate_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE k.tenant_id=$1::uuid AND k.id=$2"),
                device_management_validate_primary: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices d JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(d.tenant_id,d.id) WHERE d.tenant_id=$1::uuid AND d.id=$2 AND d.purpose=$3 AND k.purpose=$3 AND d.epoch=$4 AND d.state='active' AND k.id=$5 AND k.state='active' AND k.protocol_request IS NULL)"),
                device_management_validate_3: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices d JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(d.tenant_id,d.id) LEFT JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(k.tenant_id,k.protocol_request) WHERE d.tenant_id=$1::uuid AND d.id=$2 AND k.purpose=$3 AND coalesce(q.protocol_epoch,d.epoch)=$4 AND d.state='active' AND k.id=$5 AND k.state='active' AND k.protocol_request IS NOT DISTINCT FROM $6 AND (k.protocol_request IS NULL OR (q.state='bound' AND q.device=d.id)))"),
                agent_configurations_directory_configuration_directory_1: concat!("WITH candidates AS (SELECT id,tenant_id,creator,quantity,document->'quantity' AS quantity_metadata,document->'targets' AS targets,floor(extract(epoch FROM created_at))::bigint AS created, floor(extract(epoch FROM expires_at))::bigint AS expiry,CASE WHEN state='revoked' THEN 'revoked' WHEN expires_at<=statement_timestamp() THEN 'expired' ELSE 'available' END AS effective_state FROM ", $access_schema, "agent_configurations WHERE tenant_id="),
                agent_configurations_directory_configuration_directory_2: concat!(") SELECT jsonb_build_object('configurationId',c.id,'state',c.effective_state,'createdAt',c.created,'expiresAt',c.expiry,'createdBy',c.creator,'targets',c.targets,'quantity',c.quantity_metadata,'reserved',u.reserved,'consumed',u.consumed,'remaining',c.quantity-u.reserved-u.consumed) FROM candidates c CROSS JOIN LATERAL (SELECT count(*) FILTER(WHERE NOT issued AND state='available' AND expires_at>statement_timestamp()) AS reserved,count(*) FILTER(WHERE issued) AS consumed FROM (SELECT g.state,g.expires_at,EXISTS(SELECT 1 FROM ", $access_schema, "certificate_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id)) AS issued FROM ", $access_schema, "certificate_grants g WHERE g.tenant_id=c.tenant_id AND g.configuration_id=c.id) grants) u"),
                enrollment_tasks_recovery_accept_action_dispatch_1: concat!("SELECT gateway_accepted FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE"),
                enrollment_tasks_recovery_accept_action_dispatch_2: concat!("UPDATE ", $mdm_registration_tasks_runs, " SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid"),
                enrollment_tasks_worker_pending_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_policy_recovery, " WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)"),
                enrollment_tasks_worker_pending_in_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " t WHERE tenant_id=$1::uuid AND id=$2 AND (state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed'))"),
                enrollment_tasks_retirement_retire_in_1: concat!("SELECT id, state AS state FROM ", $mdm_registration_tasks_runs, " AS a WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND id > $3 AND (state ->> 'execution' IN ('not_started', 'running', 'waiting_reboot', 'unknown') AND state ->> 'cancellation' = 'none') AND EXISTS (SELECT 1 FROM ", $access_schema, "devices AS r WHERE (r.tenant_id, r.id) = (a.tenant_id, a.device) AND (r.state <> 'active' OR (EXISTS (SELECT 1 FROM ", $access_schema, "devices AS d WHERE (d.tenant_id, d.id) = (r.tenant_id, r.id) AND d.retirement IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM mdm_devices.retirement_work AS w WHERE (w.tenant_id, w.execution) = (a.tenant_id, a.id))))) ORDER BY id LIMIT 64"),
                enrollment_tasks_retirement_retire_in_2: concat!("SELECT ", $mdm_registration_tasks_save_retired_run, "($1,$2,$3,$4)"),
                enrollment_tasks_retirement_progress_on_1: concat!("SELECT count(*) > 0, ((array_agg(t.id ORDER BY t.id) FILTER (WHERE t.state ->> 'execution' = 'unknown')))[1] FROM ", $mdm_registration_tasks_runs, " AS t WHERE t.tenant_id = CAST($1 AS uuid) AND t.device = ANY($2) AND t.state ->> 'execution' IN ('running', 'waiting_reboot', 'unknown')"),
                enrollment_tasks_wake_policy_in_1: concat!("INSERT INTO ", $mdm_registration_tasks_policy_recovery, "(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=", $mdm_registration_tasks_policy_recovery, ".input_revision+1"),
                enrollment_tasks_poll_offer_candidates_1: concat!("SELECT id, available_at FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state ->> 'execution' = 'not_started' AND state ->> 'cancellation' = 'none' AND gateway_accepted AND available_at <= $3 AND deadline > $3 AND (state -> 'delivery' ->> 'kind' = 'queued' OR CAST(state -> 'delivery' ->> 'leaseUntil' AS bigint) <= $3) AND (CAST($4 AS bigint) IS NULL OR (available_at, id) > ($4, CAST($5 AS uuid))) ORDER BY available_at, id LIMIT 128"),
                enrollment_tasks_poll_cancellations_1: concat!("SELECT id, state -> 'delivery' ->> 'attempt' AS attempt FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state ->> 'cancellation' = 'requested' AND (CAST($3 AS uuid) IS NULL OR id > $3) ORDER BY id LIMIT $4"),
                enrollment_tasks_admission_accept_for_device_1: concat!("SELECT t.id,t.created_at,t.deadline FROM ", $mdm_policy_triggers, " t WHERE t.tenant_id=$1::uuid AND t.version=$2 AND t.deadline>$4 AND $5 AND NOT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " r WHERE r.tenant_id=t.tenant_id AND r.policy_version=t.version AND r.device=$3 AND r.occurrence='explicit:'||t.id::text) ORDER BY t.created_at,t.id LIMIT 1"),
                enrollment_tasks_admission_accept_for_device_2: concat!("SELECT EXISTS (SELECT 1 FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2)"),
                enrollment_tasks_admission_queue_run_in_1: concat!("INSERT INTO ", $mdm_registration_tasks_runs, " (tenant_id, id, policy_version, device, occurrence, available_at, deadline, state, dispatch_fingerprint, created_at, source_objects, origin, invocation) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"),
                enrollment_tasks_admission_occurrence_available_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND policy_version=$2 AND device=$3 AND occurrence=$4)"),
                enrollment_tasks_policy_recovery_prepare_in_1: concat!("SELECT * FROM ", $mdm_registration_tasks_policy_recovery, " WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE"),
                enrollment_tasks_policy_recovery_advance_in_1: concat!("SELECT r.id FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33"),
                enrollment_tasks_policy_recovery_advance_in_2: concat!("UPDATE ", $mdm_registration_tasks_policy_recovery, " SET input_consumed=$3,input_window=$4,recovery_after=$5,runs_done=$6 WHERE tenant_id=$1::uuid AND policy=$2"),
                enrollment_tasks_agent_agent_admit_in_1: concat!("INSERT INTO ", $mdm_registration_tasks_agent_admission, " (tenant_id, device) VALUES (CAST($1 AS uuid), $2) ON CONFLICT DO NOTHING"),
                enrollment_tasks_agent_agent_admit_in_2: concat!("SELECT policy_after FROM ", $mdm_registration_tasks_agent_admission, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 FOR UPDATE"),
                enrollment_tasks_agent_agent_admit_in_3: concat!("SELECT id,current_version FROM ", $mdm_policy_policies, " WHERE tenant_id=$1::uuid AND state='enabled' AND definition->'action'->>'kind'='request_mdm_enrollment' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64"),
                enrollment_tasks_agent_agent_admit_in_4: concat!("UPDATE ", $mdm_registration_tasks_agent_admission, " SET policy_after = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                enrollment_tasks_storage_run_in_1: concat!("SELECT id FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                enrollment_tasks_storage_run_in_2: concat!("SELECT * FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                enrollment_tasks_storage_save_run_1: concat!("SELECT state FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                enrollment_tasks_storage_save_run_2: concat!("UPDATE ", $mdm_registration_tasks_runs, " SET state=$3,result=$4,invocation=$5 WHERE tenant_id=$1::uuid AND id=$2 AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4 OR invocation IS DISTINCT FROM $5)"),
                enrollment_tasks_storage_pending_in_1: concat!("SELECT EXISTS (SELECT 1 FROM ", $mdm_registration_tasks_runs, " AS r INNER JOIN ", $mdm_policy_versions, " AS v ON (v.tenant_id, v.id) = (r.tenant_id, r.policy_version) WHERE r.tenant_id = CAST($1 AS uuid) AND r.device = $2 AND (r.state ->> 'execution' = 'unknown' OR (r.state ->> 'execution' = 'running' AND r.deadline <= $6) OR (v.policy = $3 AND r.device = $5 AND r.state ->> 'cancellation' <> 'confirmed' AND (r.state ->> 'execution' = 'running' OR (r.state ->> 'execution' = 'not_started' AND r.deadline > $6))))), (SELECT max(created_at) FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND policy_version = $4 AND device = $5)"),
                enrollment_tasks_storage_active_count_on_1: concat!("SELECT count(*) FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$3"),
                enrollment_tasks_storage_owned_ids_on_1: concat!("SELECT id FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=ANY($2)"),
                enrollment_tasks_storage_replay_1: concat!("SELECT fingerprint,response FROM ", $mdm_registration_tasks_receipts, " WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3"),
                enrollment_tasks_diagnostic_receipt: concat!("SELECT response FROM ", $mdm_registration_tasks_receipts, " WHERE tenant_id = CAST($1 AS uuid) AND actor = $2 AND id = $3 AND device = $4 AND device = $5"),
                enrollment_tasks_storage_receipt_1: concat!("INSERT INTO ", $mdm_registration_tasks_receipts, " (tenant_id, actor, id, fingerprint, response, device) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6)"),
                enrollment_tasks_storage_association_on_1: concat!("SELECT device,NULL::uuid FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                enrollment_tasks_self_service_self_service_status_in_1: concat!("SELECT response FROM ", $mdm_registration_tasks_receipts, " WHERE tenant_id=$1::uuid AND actor=ANY($2) AND id=$3 ORDER BY array_position($2,actor) LIMIT 1"),
                enrollment_tasks_self_service_advance_waiting_in_1: concat!("UPDATE ", $mdm_registration_tasks_runs, " SET invocation=$3,source_objects=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                enrollment_tasks_queries_page_on_1: concat!(",'result',r.result) FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5"),
                enrollment_tasks_queries_detail_on_1: concat!("SELECT r.device FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3"),
                enrollment_tasks_queries_detail_on_2: concat!(",'result',r.result) FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3"),
                enrollment_tasks_queries_assignment_ids_on_1: concat!("SELECT r.id FROM ", $mdm_registration_tasks_runs, " AS r INNER JOIN ", $mdm_policy_versions, " AS v ON (v.tenant_id, v.id) = (r.tenant_id, r.policy_version) WHERE r.tenant_id = CAST($1 AS uuid) AND v.policy = $2 AND r.device = $3 AND $5 = 'agent' AND r.device = $4 ORDER BY r.id"),
                enrollment_tasks_queries_assignment_state_on_1: concat!("SELECT frozen FROM ", $mdm_policy_versions, " WHERE tenant_id=$1::uuid AND id=$2"),
                identity_install: identity_install!(),
                install: concat!(identity_install!(), inventory_install!()),
                identity_relations: identity_relations!(),
                relations: concat!(identity_relations!(), inventory_relations!()),
                agent_bootstrap: concat!(r###"BEGIN;
CREATE TABLE "###, $access_schema, r###"agent_bootstraps (
 tenant_id uuid NOT NULL,id uuid NOT NULL,installation uuid NOT NULL,installation_facts jsonb NOT NULL CHECK(octet_length(installation_facts::text)<=16384),delivery uuid NOT NULL,
 cleanup uuid,cleanup_complete boolean NOT NULL DEFAULT false,cleanup_retry_at bigint NOT NULL DEFAULT 0,source jsonb NOT NULL,release uuid NOT NULL,issuer text NOT NULL,provisioner text NOT NULL,
 download_origin text NOT NULL CHECK(octet_length(download_origin) BETWEEN 1 AND 2048),
 active boolean NOT NULL DEFAULT true,challenge bytea NOT NULL CHECK(octet_length(challenge)=32),deadline bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('prepared','signing','issued','consumed','revoked')),
 transaction_id text,csr_digest bytea,spki bytea,fingerprint bytea,certificate bytea,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,delivery),
 CHECK((csr_digest IS NULL)=(spki IS NULL)),
 CHECK(csr_digest IS NULL OR octet_length(csr_digest)=32),
 CHECK(spki IS NULL OR octet_length(spki)=32),
 CHECK(fingerprint IS NULL OR octet_length(fingerprint)=32)
);
"###, $index_80, " ON ", $access_schema, r###"agent_bootstraps(tenant_id,installation) WHERE active;
ALTER TABLE "###, $access_schema, r###"agent_bootstraps ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_bootstraps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_bootstraps USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_bootstraps TO ", $command_runtime, ",", $policy_runtime, r###";
GRANT UPDATE(active,cleanup,cleanup_complete,cleanup_retry_at) ON "###, $access_schema, "agent_bootstraps TO ", $command_runtime, ",", $policy_runtime, r###";
GRANT SELECT ON "###, $access_schema, "agent_bootstraps TO ", $access_role, r###";
GRANT UPDATE(state,deadline,transaction_id,csr_digest,spki,fingerprint,certificate) ON "###, $access_schema, "agent_bootstraps TO ", $access_role, r###";
GRANT SELECT ON "###, $access_schema, "certificate_grants TO ", $policy_runtime, r###";
COMMIT;
"###),
                agent_configurations: concat!("-- Registration settings and reusable configuration authority. Existing identities are unchanged.\nBEGIN;\nCREATE TABLE ", $access_schema, "agent_enrollment_settings (\n tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0),\n document jsonb NOT NULL CHECK(octet_length(document::text)<=4096)\n);\nCREATE TABLE ", $access_schema, "agent_configurations (\n tenant_id uuid NOT NULL, id uuid NOT NULL, operation_id uuid NOT NULL,\n creator text NOT NULL, instance text NOT NULL,\n secret_digest text NOT NULL CHECK(secret_digest ~ '^[0-9a-f]{64}$'),\n signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9_-]{86}$'),\n request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),\n document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),\n quantity bigint CHECK(quantity BETWEEN 1 AND 4294967295),\n state text NOT NULL CHECK(state IN('available','revoked')),\n created_at timestamptz NOT NULL DEFAULT clock_timestamp(),\n expires_at timestamptz NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '365 days'),\n PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation_id)\n);\n\nALTER TABLE ", $access_schema, "certificate_grants ADD FOREIGN KEY(tenant_id,configuration_id) REFERENCES ", $access_schema, "agent_configurations(tenant_id,id);\n\n", $index_81, " ON ", $access_schema, "certificate_grants(tenant_id,configuration_id);\nALTER TABLE ", $access_schema, "agent_enrollment_settings ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_enrollment_settings FORCE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_configurations ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_configurations FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_enrollment_settings USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nCREATE POLICY tenant ON ", $access_schema, "agent_configurations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT,INSERT ON ", $access_schema, "agent_enrollment_settings TO ", $access_role, ";\nGRANT SELECT ON ", $access_schema, "agent_enrollment_settings TO ", $command_runtime, ";\nGRANT UPDATE(revision,document) ON ", $access_schema, "agent_enrollment_settings TO ", $access_role, ";\nGRANT SELECT,INSERT ON ", $access_schema, "agent_configurations TO ", $access_role, ";\nGRANT UPDATE(state) ON ", $access_schema, "agent_configurations TO ", $access_role, ";\n-- Configuration signing has an independent lifetime from task-signing keys.\nCREATE TABLE ", $access_schema, "agent_configuration_keys (\n tenant_id uuid PRIMARY KEY, key_id text NOT NULL UNIQUE,\n public_key text NOT NULL CHECK(public_key ~ '^[A-Za-z0-9_-]{43}$'),\n private_key bytea NOT NULL CHECK(octet_length(private_key) BETWEEN 1 AND 4096)\n);\nCREATE TABLE ", $access_schema, "agent_connection_drafts (\n tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),\n document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),\n PRIMARY KEY(tenant_id,revision)\n);\nCREATE TABLE ", $access_schema, "agent_connection_versions (\n tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),\n document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),\n PRIMARY KEY(tenant_id,revision),\n FOREIGN KEY(tenant_id,revision) REFERENCES ", $access_schema, "agent_connection_drafts(tenant_id,revision)\n);\nCREATE TABLE ", $access_schema, "agent_connection_deployments (\n tenant_id uuid NOT NULL, origin text NOT NULL CHECK(octet_length(origin) BETWEEN 1 AND 2048),\n service_id uuid NOT NULL, host_id uuid NOT NULL,\n revision bigint NOT NULL CHECK(revision>0), configuration_revision bigint NOT NULL CHECK(configuration_revision>=0), observed_at bigint NOT NULL,\n PRIMARY KEY(tenant_id,origin)\n);\nCREATE TABLE ", $access_schema, "agent_connection_observations (\n    tenant_id uuid NOT NULL\n  , device text NOT NULL\n  , operation_id uuid NOT NULL\n  , revision bigint NOT NULL CHECK (revision > 0)\n  , document jsonb NOT NULL CHECK (octet_length(CAST(document AS text)) <= 4096)\n  , received_at bigint NOT NULL\n  , recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()\n  , PRIMARY KEY (tenant_id, device, operation_id)\n  , FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id)\n  , FOREIGN KEY (tenant_id, revision) REFERENCES ", $access_schema, "agent_connection_versions (tenant_id, revision)\n);\n", $index_82, "\n  ON ", $access_schema, "agent_connection_observations (tenant_id\n                                             , device\n                                             , revision DESC\n                                             , recorded_at DESC);\nALTER TABLE ", $access_schema, "agent_configuration_keys ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_configuration_keys FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_configuration_keys USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT,INSERT ON ", $access_schema, "agent_configuration_keys TO ", $access_role, ";\nGRANT SELECT(tenant_id,public_key) ON ", $access_schema, "agent_configuration_keys TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ";\nALTER TABLE ", $access_schema, "agent_connection_drafts ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_connection_drafts FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_connection_drafts USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT,INSERT ON ", $access_schema, "agent_connection_drafts TO ", $access_role, ";\nALTER TABLE ", $access_schema, "agent_connection_versions ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_connection_versions FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_connection_versions USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT,INSERT ON ", $access_schema, "agent_connection_versions TO ", $access_role, ";\nGRANT SELECT ON ", $access_schema, "agent_connection_versions TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ";\nALTER TABLE ", $access_schema, "agent_connection_deployments ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_connection_deployments FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_connection_deployments USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT ON ", $access_schema, "agent_connection_deployments TO ", $access_role, ";\nALTER TABLE ", $access_schema, "agent_connection_observations ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_connection_observations FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_connection_observations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT,INSERT ON ", $access_schema, "agent_connection_observations TO ", $access_role, ";\nCREATE TABLE ", $access_schema, "agent_connection_failures (\n    tenant_id uuid NOT NULL\n  , device text NOT NULL\n  , operation_id uuid NOT NULL\n  , revision bigint NOT NULL CHECK (revision > 0)\n  , document jsonb NOT NULL CHECK (octet_length(CAST(document AS text)) <= 4096)\n  , origin text NOT NULL CHECK (octet_length(origin) BETWEEN 1 AND 2048)\n  , received_at bigint NOT NULL\n  , recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()\n  , PRIMARY KEY (tenant_id, device, operation_id)\n  , FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id)\n  , FOREIGN KEY (tenant_id, revision) REFERENCES ", $access_schema, "agent_connection_versions (tenant_id, revision)\n);\n", $index_83, "\n  ON ", $access_schema, "agent_connection_failures (tenant_id\n                                         , device\n                                         , recorded_at DESC);\nALTER TABLE ", $access_schema, "agent_connection_failures ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $access_schema, "agent_connection_failures FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $access_schema, "agent_connection_failures USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);\nGRANT SELECT,INSERT ON ", $access_schema, "agent_connection_failures TO ", $access_role, ";\nCOMMIT;\n"),
                quotas: concat!(r###"-- Quota configuration is registration-owned.
BEGIN;

CREATE TABLE "###, $access_schema, r###"registration_quota_settings (
    tenant_id uuid NOT NULL,
    subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 256),
    revision bigint NOT NULL CHECK(revision>0),
    agent bigint CHECK(agent BETWEEN 0 AND 4294967295),
    windows_mdm bigint CHECK(windows_mdm BETWEEN 0 AND 4294967295),
    macos_mdm bigint CHECK(macos_mdm BETWEEN 0 AND 4294967295),
    PRIMARY KEY(tenant_id,subject),
    CHECK(subject<>'tenant' OR (agent IS NOT NULL AND windows_mdm IS NOT NULL AND macos_mdm IS NOT NULL))
);
ALTER TABLE "###, $access_schema, r###"registration_quota_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"registration_quota_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"registration_quota_settings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "registration_quota_settings TO ", $access_role, r###";
GRANT UPDATE(revision,agent,windows_mdm,macos_mdm) ON "###, $access_schema, "registration_quota_settings TO ", $access_role, r###";
COMMIT;
"###),
                admission: concat!(r###"-- Registration admission is independent of device management lifecycle.
BEGIN;
CREATE TABLE "###, $access_schema, r###"registration_admission (
 tenant_id uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN ('agent','windows_mdm','macos_mdm')),
 revision bigint NOT NULL CHECK(revision>0),
 paused boolean NOT NULL,
 PRIMARY KEY(tenant_id,channel)
);
ALTER TABLE "###, $access_schema, r###"registration_admission ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"registration_admission FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"registration_admission USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "registration_admission TO ", $access_role, r###";
GRANT UPDATE(revision,paused) ON "###, $access_schema, "registration_admission TO ", $access_role, r###";
GRANT SELECT ON "###, $access_schema, "registration_admission TO ", $command_runtime, r###";
COMMIT;
"###),
                directory: concat!("-- One device per accepted channel enrollment; pending requests retain their frozen IDs.\nBEGIN;\nCREATE VIEW ", $access_schema, "directory_inputs WITH(security_barrier=true) AS\nSELECT tenant_id,NULL::timestamptz AS expires_at FROM ", $access_schema, "devices WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid\nUNION ALL SELECT tenant_id,CASE WHEN state='pending' THEN expires_at END FROM ", $access_schema, "requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid;\nREVOKE ALL ON ", $access_schema, "directory_inputs FROM PUBLIC;\nGRANT SELECT ON ", $access_schema, "directory_inputs TO ", $access_role, ",", $identity_runtime, ";\nCREATE VIEW ", $access_schema, "directory_metadata WITH(security_barrier=true) AS\nSELECT coalesce(d.tenant_id,q.tenant_id) AS tenant_id,coalesce(d.id,q.device) AS id,\n coalesce(d.state,CASE WHEN q.state='pending' AND q.expires_at<=statement_timestamp() THEN 'expired' ELSE q.state END) AS status,\n coalesce(d.channel,CASE WHEN q.id IS NOT NULL THEN 'mdm' END) AS channel,\n CASE WHEN d.channel='agent' THEN 'agent.builtin' ELSE q.source END AS source,\n CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' ELSE g.platform END AS platform,\n d.last_communication_received_at,q.id AS enrollment_id,q.state AS enrollment_state,q.expires_at\nFROM ", $access_schema, "devices d FULL JOIN (SELECT * FROM ", $access_schema, "requests WHERE authority_kind<>'parent_certificate') q ON(q.tenant_id,q.id)=(d.tenant_id,d.request_id)\nLEFT JOIN ", $access_schema, "certificate_grants g ON(g.tenant_id,g.id)=(d.tenant_id,d.certificate_grant_id)\nWHERE coalesce(d.tenant_id,q.tenant_id)=nullif(current_setting('rss.tenant_id',true),'')::uuid;\nREVOKE ALL ON ", $access_schema, "directory_metadata FROM PUBLIC;\nGRANT SELECT ON ", $access_schema, "directory_metadata TO ", $access_role, ",", $identity_runtime, ";\nCREATE VIEW ", $access_schema, "directory_endpoints WITH(security_barrier=true) AS\nSELECT d.tenant_id,d.id,d.status,jsonb_build_object('id',d.id,'status',d.status,'channel',d.channel,'source',d.source,'platform',d.platform,\n 'lastCommunicationReceivedAt',floor(extract(epoch FROM d.last_communication_received_at))::bigint,\n 'enrollment',CASE WHEN d.enrollment_id IS NOT NULL THEN jsonb_build_object('enrollmentId',d.enrollment_id,'status',CASE WHEN d.enrollment_state='pending' AND d.expires_at<=statement_timestamp() THEN 'expired' ELSE d.enrollment_state END,'expiresAt',floor(extract(epoch FROM d.expires_at))::bigint) END) AS summary FROM ", $access_schema, "directory_metadata d;\nREVOKE ALL ON ", $access_schema, "directory_endpoints FROM PUBLIC;\nGRANT SELECT ON ", $access_schema, "directory_endpoints TO ", $access_role, ",", $identity_runtime, ",", $command_runtime, ";\nCREATE VIEW ", $access_schema, "directory_users WITH (security_barrier=true) AS\nSELECT coalesce(r.tenant_id,u.tenant_id) AS tenant_id,coalesce(r.device,u.device) AS device,\n CASE WHEN r.instance IS NOT NULL AND r.principal IS NOT NULL THEN\n  jsonb_build_object('tenantId',r.tenant_id,'instanceId',r.instance,'principalId',r.principal) END AS registration_user,\n coalesce(r.revision,0) AS registration_revision,u.session_reference,\n coalesce(u.revision,0) AS current_revision,u.confirmed_at,\n qualified.valid_until IS NOT NULL AS registration_valid,qualified.valid_until\nFROM ", $access_schema, "registration_users r FULL JOIN ", $access_schema, "current_users u USING(tenant_id,device)\nLEFT JOIN LATERAL (\n SELECT min(least(i.not_after,p.valid_until)) AS valid_until\n FROM ", $access_schema, "devices g JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.device)=(g.tenant_id,g.id)\n JOIN ", $access_schema, "certificate_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id)\n JOIN ", $pki_certificates, " p ON p.tenant_id=k.tenant_id AND p.purpose='agent' AND p.fingerprint=decode(k.locator,'hex')\n WHERE g.tenant_id=u.tenant_id AND g.id=u.device\n  AND g.channel='agent' AND g.purpose='primary' AND g.state='active' AND k.state='active'\n  AND i.not_before<=extract(epoch FROM statement_timestamp()) AND i.not_after>extract(epoch FROM statement_timestamp())\n) qualified ON true\nWHERE coalesce(r.tenant_id,u.tenant_id)=NULLIF(current_setting('rss.tenant_id',true),'')::uuid;\nREVOKE ALL ON ", $access_schema, "directory_users FROM PUBLIC;\nGRANT SELECT ON ", $access_schema, "directory_users TO ", $access_role, ",", $identity_runtime, ";\n\n", $index_85, " ON ", $access_schema, "grants(tenant_id,device,id);\n", $index_86, " ON ", $access_schema, "requests(tenant_id,expires_at) WHERE state='pending';\nCOMMIT;\nCREATE FUNCTION ", $access_schema, "asset_sources_at(p_devices text[],p_cut jsonb)\nRETURNS TABLE(device text,channel text,source text,epoch text)\nLANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$\n WITH latest AS (\n  SELECT DISTINCT ON(kind,identity) kind,identity,device,document FROM ", $access_schema, "asset_authority_history\n  WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND device=ANY(p_devices)\n   AND cardinality(p_devices)<=1000 AND (p_cut IS NULL OR ((p_cut->>'tenant')::uuid=nullif(current_setting('rss.tenant_id',true),'')::uuid AND mdm.asset_visible(p_cut,revision)))\n  ORDER BY kind,identity,revision DESC\n ) SELECT d.device,d.document->>'channel',s.document->>'source',s.document->>'epoch'\n FROM latest d JOIN latest s ON s.device=d.device AND s.kind='source'\n WHERE d.kind='device' AND d.document->>'state'='active' AND s.document->>'enabled'='true'\n AND EXISTS(SELECT FROM latest k WHERE k.kind='credential' AND k.device=d.device AND k.document->>'state'='active')\n ORDER BY d.device,s.identity LIMIT 2001\n$$;\nREVOKE ALL ON FUNCTION ", $access_schema, "asset_sources_at(text[],jsonb) FROM PUBLIC;\nGRANT EXECUTE ON FUNCTION ", $access_schema, "asset_sources_at(text[],jsonb) TO ", $access_role, ",", $identity_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ",", $command_runtime, ";\n"),
                enrollment_tasks: concat!("-- Fresh installation: Script owns its complete execution state.\nBEGIN;\n\n", $create_mdm_registration_tasks, ";\n\nCREATE TABLE ", $mdm_registration_tasks_runs, " (\n    tenant_id uuid NOT NULL\n  , id uuid NOT NULL\n  , policy_version uuid NOT NULL\n  , origin jsonb NOT NULL CHECK (origin IN ('\"system\"', '\"policy\"', '\"human\"', '\"ai\"'))\n  , source_objects jsonb NOT NULL\n  , device text NOT NULL\n  , occurrence text NOT NULL CHECK (octet_length(occurrence) BETWEEN 1 AND 256)\n  , created_at bigint NOT NULL CHECK (created_at >= 0)\n  , available_at bigint NOT NULL CHECK (available_at >= 0)\n  , deadline bigint NOT NULL CHECK (deadline > available_at)\n  , state jsonb NOT NULL CHECK (octet_length(CAST(state AS text)) <= 4096)\n  , gateway_accepted boolean NOT NULL DEFAULT FALSE\n  , dispatch_fingerprint bytea NOT NULL CHECK (octet_length(dispatch_fingerprint) = 32)\n  , dispatch_failure jsonb CHECK (dispatch_failure IS NULL\n                               OR octet_length(CAST(dispatch_failure AS text)) <= 8192)\n  , result jsonb CHECK (result IS NULL\n                     OR octet_length(CAST(result AS text)) <= 1114112)\n  , invocation jsonb CHECK (invocation IS NULL\n                         OR (jsonb_typeof(invocation) = 'object'\n                         AND octet_length(CAST(invocation AS text)) <= 131072))\n  , PRIMARY KEY (tenant_id, id)\n  , UNIQUE (tenant_id, policy_version, device, occurrence)\n);\n\nALTER TABLE ", $mdm_registration_tasks_runs, " ENABLE ROW LEVEL SECURITY;\n\nALTER TABLE ", $mdm_registration_tasks_runs, " FORCE ROW LEVEL SECURITY;\n\nCREATE POLICY tenant ON ", $mdm_registration_tasks_runs, "\n USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)\n WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\n\nCREATE TABLE ", $mdm_registration_tasks_receipts, " (\n    device text NOT NULL\n  , tenant_id uuid NOT NULL\n  , actor text NOT NULL\n  , id uuid NOT NULL\n  , fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32)\n  , response jsonb NOT NULL CHECK (octet_length(CAST(response AS text)) <= 6291456)\n  , PRIMARY KEY (tenant_id, actor, id)\n);\n\nALTER TABLE ", $mdm_registration_tasks_receipts, " ENABLE ROW LEVEL SECURITY;\n\nALTER TABLE ", $mdm_registration_tasks_receipts, " FORCE ROW LEVEL SECURITY;\n\nCREATE POLICY tenant ON ", $mdm_registration_tasks_receipts, "\n USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)\n WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\n\nCREATE TABLE ", $mdm_registration_tasks_agent_admission, " (\n    tenant_id uuid NOT NULL\n  , device text NOT NULL\n  , policy_after uuid\n  , PRIMARY KEY (tenant_id, device)\n);\n\nALTER TABLE ", $mdm_registration_tasks_agent_admission, " ENABLE ROW LEVEL SECURITY;\n\nALTER TABLE ", $mdm_registration_tasks_agent_admission, " FORCE ROW LEVEL SECURITY;\n\nCREATE POLICY tenant ON ", $mdm_registration_tasks_agent_admission, "\n USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)\n WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\n\nCREATE TABLE ", $mdm_registration_tasks_policy_recovery, " (\n    tenant_id uuid NOT NULL,\n    policy uuid NOT NULL,\n    input_revision bigint NOT NULL DEFAULT 1,\n    input_consumed bigint NOT NULL DEFAULT 0,\n    input_window bigint NOT NULL DEFAULT 0,\n    recovery_after uuid,\n    runs_done boolean NOT NULL DEFAULT false,\n    PRIMARY KEY(tenant_id,policy),\n    CHECK(input_revision>=input_consumed AND input_consumed>=0)\n);\n\nALTER TABLE ", $mdm_registration_tasks_policy_recovery, " ENABLE ROW LEVEL SECURITY;\n\nALTER TABLE ", $mdm_registration_tasks_policy_recovery, " FORCE ROW LEVEL SECURITY;\n\nCREATE POLICY tenant ON ", $mdm_registration_tasks_policy_recovery, "\n USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)\n WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\n\n", $index_87, "\n  ON ", $mdm_registration_tasks_runs, " (tenant_id\n                                , device\n                                , available_at\n                                , id)\n  WHERE state ->> 'execution' = 'not_started'\n    AND state ->> 'cancellation' = 'none';\n\n", $index_88, " ON ", $mdm_registration_tasks_runs, "(tenant_id,policy_version,available_at,id);\n\nCOMMIT;"),
                quota_usage: concat!("-- One read snapshot of active registrations and live reservations. Renewal/recovery\n-- retain the original registration; organization authority is exempt from personal quotas.\nWITH agent AS (\n SELECT g.device,g.id,g.expires_at,\n EXISTS(SELECT 1 FROM ", $access_schema, "devices r WHERE r.tenant_id=g.tenant_id AND r.certificate_grant_id=g.id AND r.state='active') AS active,\n g.state IN('available','consumed') AND g.expires_at>clock_timestamp() AND\n NOT EXISTS(SELECT 1 FROM ", $access_schema, "devices r WHERE r.tenant_id=g.tenant_id AND r.certificate_grant_id=g.id) AS reserved\n FROM ", $access_schema, "certificate_grants g\n WHERE g.tenant_id=$1::uuid AND g.instance=$2 AND g.actor=$3 AND g.source IN('download','browser')\n), native AS (\n SELECT g.device,q.id,q.source,q.expires_at,\n EXISTS(SELECT 1 FROM ", $access_schema, "devices r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.state='active' AND r.purpose='primary') AS active,\n q.state='pending' AND q.expires_at>clock_timestamp() AND\n NOT EXISTS(SELECT 1 FROM ", $access_schema, "devices r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.purpose='primary') AS reserved\n FROM ", $access_schema, "requests q JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)\n WHERE q.tenant_id=$1::uuid AND g.instance=$2 AND g.actor=$3 AND q.self_service\n), usage AS (\n SELECT 'agent' AS channel,device,id,expires_at,active,reserved FROM agent\n UNION ALL\n SELECT CASE source WHEN 'mdm.windows' THEN 'windows_mdm' ELSE 'macos_mdm' END,device,id,expires_at,active,reserved FROM native\n)\nSELECT channel,count(*) FILTER(WHERE active)::bigint AS active,count(*) FILTER(WHERE reserved)::bigint AS reserved FROM usage GROUP BY channel\n"),
                enrollment_retirement: concat!("-- Registration retirement participates on the initiating audit connection.\nBEGIN;\nSET LOCAL check_function_bodies = false;\nCREATE FUNCTION ", $mdm_registration_tasks_save_retired_run, "(p_device text,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean\n LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'\n AS $$\n WITH changed AS (\n UPDATE ", $mdm_registration_tasks_runs, " a SET state=p_state\n WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid\n AND a.device=p_device AND a.id=p_run AND a.state=p_previous\n AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')\n AND a.state->>'cancellation'='none'\n AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))\n AND EXISTS(SELECT 1 FROM ", $access_schema, "devices r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.device) AND (r.state<>'active' OR (r.retirement IS NOT NULL AND ", $native_retirement_clear, ")))\n RETURNING a.id\n ) SELECT EXISTS(SELECT 1 FROM changed);\n$$;\nREVOKE ALL ON FUNCTION ", $mdm_registration_tasks_save_retired_run, "(text,uuid,jsonb,jsonb) FROM PUBLIC;\nGRANT EXECUTE ON FUNCTION ", $mdm_registration_tasks_save_retired_run, "(text,uuid,jsonb,jsonb) TO ", $access_role, ",", $command_runtime, ";\nCOMMIT;\n"),
                task_relations: concat!("BEGIN;\nSET LOCAL check_function_bodies=false;\n\n\nALTER TABLE ", $mdm_registration_tasks_runs, " ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES ", $mdm_policy_versions, "(tenant_id,id);\n\n\nALTER TABLE ", $mdm_registration_tasks_runs, " ADD FOREIGN KEY(tenant_id,device) REFERENCES ", $access_schema, "devices(tenant_id,id);\n\n\n\n\n\nALTER TABLE ", $mdm_registration_tasks_agent_admission, " ADD FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id);\n\n\nALTER TABLE ", $mdm_registration_tasks_policy_recovery, " ADD FOREIGN KEY(tenant_id,policy) REFERENCES ", $mdm_policy_policies, "(tenant_id,id);\n\n\nGRANT USAGE ON ", $mdm_registration_tasks_schema, " TO ", $command_runtime, ",", $policy_runtime, ",", $access_role, ";\n\n\nGRANT SELECT,INSERT ON ", $mdm_registration_tasks_runs, " TO ", $command_runtime, ",", $policy_runtime, ";\n\n\nGRANT UPDATE(state,result,invocation,source_objects) ON ", $mdm_registration_tasks_runs, " TO ", $command_runtime, ",", $policy_runtime, ";\n\n\nGRANT UPDATE(gateway_accepted,dispatch_failure) ON ", $mdm_registration_tasks_runs, " TO ", $command_runtime, ";\n\n\nGRANT SELECT ON ", $mdm_registration_tasks_runs, " TO ", $access_role, ";\n\n\nGRANT UPDATE(policy_after) ON ", $mdm_registration_tasks_agent_admission, " TO ", $command_runtime, ";\n\n\nGRANT SELECT,INSERT ON ", $mdm_registration_tasks_policy_recovery, " TO ", $command_runtime, ",", $policy_runtime, ";\n\n\nGRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON ", $mdm_registration_tasks_policy_recovery, " TO ", $command_runtime, ";\n\n\nGRANT UPDATE(input_revision) ON ", $mdm_registration_tasks_policy_recovery, " TO ", $policy_runtime, ";\n\nGRANT SELECT,INSERT ON ", $mdm_registration_tasks_receipts, ",", $mdm_registration_tasks_agent_admission, " TO ", $command_runtime, ";\n\nGRANT SELECT,INSERT ON ", $mdm_registration_tasks_receipts, " TO ", $policy_runtime, ";\n\nGRANT SELECT ON ", $mdm_registration_tasks_agent_admission, " TO ", $policy_runtime, ";\nCOMMIT;"),
                member_authority: concat!("BEGIN;\nCREATE FUNCTION ", $access_schema, "channel_members_current(p_input jsonb,p_channel text) RETURNS jsonb\nLANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$\nDECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; selected jsonb;\nBEGIN\n IF p_channel NOT IN('agent','mdm') OR p_input->>'verified' IS DISTINCT FROM 'true' THEN RETURN NULL; END IF;\n IF jsonb_typeof(p_input->'members') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'invalid channel members' USING ERRCODE='23514'; END IF;\n IF EXISTS(SELECT FROM jsonb_array_elements(p_input->'members') m WHERE NOT EXISTS(\n  SELECT FROM ", $access_schema, "devices r WHERE r.tenant_id=tenant AND r.id=m->>'device'\n   AND r.channel=m->>'channel'\n   AND r.purpose='primary' AND r.state='active' AND EXISTS(\n    SELECT FROM ", $access_schema, "credentials k WHERE (k.tenant_id,k.device)=(r.tenant_id,r.id) AND k.state='active')\n )) THEN RETURN NULL; END IF;\n IF (SELECT count(*) FROM jsonb_array_elements(p_input->'members') m WHERE m->>'channel'=p_channel)>1 THEN\n  RAISE EXCEPTION 'ambiguous execution channel' USING ERRCODE='23514';\n END IF;\n SELECT m INTO selected FROM jsonb_array_elements(p_input->'members') m WHERE m->>'channel'=p_channel;\n RETURN selected;\nEND $$;\nREVOKE ALL ON FUNCTION ", $access_schema, "channel_members_current(jsonb,text) FROM PUBLIC;\nGRANT EXECUTE ON FUNCTION ", $access_schema, "channel_members_current(jsonb,text) TO ", $access_role, ",", $command_runtime, ",", $policy_runtime, ",", $scope_runtime, ",", $inventory_runtime, ",", $telemetry_runtime, ";\nCOMMIT;\n"),
                object_manifest: concat!("{\"tables\":[\"", $access_schema, "agent_bootstraps\",\"", $access_schema, "agent_configuration_keys\",\"", $access_schema, "agent_configurations\",\"", $access_schema, "agent_connection_deployments\",\"", $access_schema, "agent_connection_drafts\",\"", $access_schema, "agent_connection_failures\",\"", $access_schema, "agent_connection_observations\",\"", $access_schema, "agent_connection_versions\",\"", $access_schema, "agent_enrollment_settings\",\"", $access_schema, "certificate_grants\",\"", $access_schema, "certificate_issuances\",\"", $access_schema, "asset_authority_history\",\"", $access_schema, "credentials\",\"", $access_schema, "current_users\",\"", $access_schema, "devices\",\"", $access_schema, "grants\",\"", $access_schema, "registration_admission\",\"", $access_schema, "registration_operations\",\"", $access_schema, "registration_quota_settings\",\"", $access_schema, "registration_users\",\"", $access_schema, "report_sources\",\"", $access_schema, "requests\",\"", $mdm_registration_tasks_agent_admission, "\",\"", $mdm_registration_tasks_policy_recovery, "\",\"", $mdm_registration_tasks_receipts, "\",\"", $mdm_registration_tasks_runs, "\"],\"functions\":[\"", $access_schema, "asset_sources_at\",\"", $access_schema, "capture_asset_authority\",\"", $access_schema, "channel_members_current\",\"", $access_schema, "seed_tenant_settings\",\"", $mdm_registration_tasks_save_retired_run, "\"],\"views\":[\"", $access_schema, "directory_endpoints\",\"", $access_schema, "directory_inputs\",\"", $access_schema, "directory_metadata\",\"", $access_schema, "directory_users\"]}"),
                access_contract: concat!("{\"tables\":[{", $contract_table_89, ",\"read_write\":false,\"read_only\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_90, ",\"read_write\":true,\"updates\":[\"state\"],\"delete_policy\":null},{", $contract_table_91, ",\"read_write\":true,\"updates\":[\"retirement\",\"state\",\"next_command\",\"first_authenticated_at\",\"last_communication_received_at\"],\"delete_policy\":null},{", $contract_table_92, ",\"read_write\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_93, ",\"read_write\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_95, ",\"read_write\":true,\"updates\":[\"enabled\",\"next_sequence\"],\"delete_policy\":null},{", $contract_table_96, ",\"read_write\":true,\"updates\":[\"state\",\"protocol_epoch\",\"protocol_ready\",\"next_command\",\"password_digest\",\"password_version\",\"credential_ref\",\"expires_at\",\"account_version\",\"account_reference\",\"account_challenge\",\"organization_version\",\"organization_challenge\"],\"delete_policy\":null},{", $contract_table_97, ",\"read_write\":true,\"updates\":[\"actor\",\"instance\",\"state\"],\"delete_policy\":null,\"insert_policy\":\"current_user<>'", $command_runtime, "'::nameorsource='native'::text\"},{", $contract_table_98, ",\"read_write\":true,\"updates\":[\"state\",\"certificate_chain\",\"metadata\",\"fingerprint\",\"activation_operation\",\"activation_digest\",\"activation_result\",\"credential\"],\"delete_policy\":null},{", $contract_table_99, ",\"read_write\":true,\"updates\":[\"revision\",\"agent\",\"windows_mdm\",\"macos_mdm\"],\"delete_policy\":null},{", $contract_table_100, ",\"read_write\":true,\"updates\":[\"revision\",\"instance\",\"principal\"],\"delete_policy\":null},{", $contract_table_101, ",\"read_write\":true,\"updates\":[\"revision\",\"document\"],\"delete_policy\":null},{", $contract_table_102, ",\"read_write\":true,\"updates\":[\"state\"],\"delete_policy\":null},{", $contract_table_103, ",\"read_write\":true,\"updates\":[\"revision\",\"paused\"],\"delete_policy\":null},{", $contract_table_104, ",\"read_write\":false,\"read_only\":true,\"updates\":[\"state\",\"transaction_id\",\"csr_digest\",\"spki\",\"fingerprint\",\"certificate\",\"deadline\"],\"delete_policy\":null},{", $contract_table_105, ",\"read_write\":true,\"updates\":[\"revision\",\"session_reference\",\"confirmed_at\"],\"delete_policy\":null},{", $contract_table_106, ",\"read_write\":true,\"read_only\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_107, ",\"read_write\":true,\"read_only\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_108, ",\"read_write\":true,\"read_only\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_109, ",\"read_write\":false,\"read_only\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_110, ",\"read_write\":true,\"read_only\":true,\"updates\":[],\"delete_policy\":null},{", $contract_table_111, ",\"read_write\":true,\"read_only\":true,\"updates\":[],\"delete_policy\":null}", $access_contract_tables, "],\"functions\":[{\"name\":\"", $access_schema, "channel_members_current\",\"search_path\":\"search_path=pg_catalog\"},{\"name\":\"", $access_schema, "asset_sources_at\",\"search_path\":\"search_path=pg_catalog\"}", $access_contract_functions, "],\"external_relations\":[", $access_contract_external_relations, "],\"verified_schemas\":[]}"),
                enrollment_access_contract: concat!(r###"{"tables":[{"###, $contract_table_115, r###","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"###, $contract_table_116, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_117, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_118, r###","read_write":false,"updates":[],"delete_policy":null}"###, $enrollment_access_contract_tables, r###"],"functions":[{"name":""###, $mdm_registration_tasks_save_retired_run, r###"","search_path":"search_path=pg_catalog"}"###, $enrollment_access_contract_functions, r###"],"external_relations":[],"verified_schemas":[]}"###),
                current_members: concat!("SELECT ", $access_schema, "channel_members_current($1,$2)"),
                agent_default_values: concat!($default_agent_values),
                agent_issuance_save_certificate_4: concat!("SELECT binding FROM ", $pki_signing, " WHERE tenant_id=$1::uuid AND attempt=$2"),
                common_authority_admission: concat!("WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES\n('", $access_schema, "capture_asset_authority()','plpgsql','trigger',true,false,'v',ARRAY[]::text[],ARRAY['", $trigger_path, "']::text[],$1::text,ARRAY['", $owner, "']::text[]),\n('", $access_schema, "asset_sources_at(text[],jsonb)','sql','record',true,true,'s',ARRAY['p_devices','p_cut','device','channel','source','epoch']::text[],ARRAY['search_path=pg_catalog']::text[],$2::text,ARRAY['", $access_role, "','", $identity_runtime, "','", $inventory_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $telemetry_runtime, "','", $command_runtime, "','", $owner, "']::text[]),\n('", $access_schema, "channel_members_current(jsonb,text)','plpgsql','jsonb',true,false,'s',ARRAY['p_input','p_channel']::text[],ARRAY['search_path=pg_catalog']::text[],$3::text,ARRAY['", $access_role, "','", $command_runtime, "','", $policy_runtime, "','", $scope_runtime, "','", $inventory_runtime, "','", $telemetry_runtime, "','", $owner, "']::text[]),\n('", $access_schema, "seed_tenant_settings(uuid)','sql','void',false,false,'v',ARRAY['t']::text[],ARRAY['search_path=pg_catalog, pg_temp']::text[],$4::text,ARRAY['", $owner, "']::text[]),\n('", $mdm_registration_tasks_save_retired_run, "(text,uuid,jsonb,jsonb)','sql','boolean',true,false,'v',ARRAY['p_device','p_run','p_previous','p_state']::text[],ARRAY['search_path=pg_catalog']::text[],$5::text,ARRAY['", $access_role, "','", $command_runtime, "','", $owner, "']::text[])\n)\nSELECT e.signature FROM expected e\nLEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)\nLEFT JOIN pg_language l ON l.oid=p.prolang\nLEFT JOIN pg_roles r ON r.oid=p.proowner\nWHERE p.oid IS NULL OR l.lanname<>e.language OR p.prorettype<>to_regtype(e.result)\n OR p.prokind<>'f' OR p.prosecdef<>e.definer OR p.proretset<>e.returns_set\n OR p.proisstrict OR p.proparallel<>'u'\n OR p.provolatile::text<>e.volatility OR p.proleakproof OR p.prosrc<>e.body\n OR coalesce(p.proargnames,ARRAY[]::text[]) IS DISTINCT FROM e.names OR p.proconfig IS DISTINCT FROM e.config\n OR r.rolname<>'", $owner, "' OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole\n OR pg_has_role(current_user,r.oid,'MEMBER')\n OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a\n WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))\n OR EXISTS(SELECT FROM unnest(e.roles) role WHERE NOT has_function_privilege(role,p.oid,'EXECUTE'))\nORDER BY e.signature LIMIT 1\n"),
                authority_capture_header: concat!("CREATE FUNCTION ", $access_schema, "capture_asset_authority("),
                authority_sources_header: concat!("CREATE FUNCTION ", $access_schema, "asset_sources_at("),
                authority_members_header: concat!("CREATE FUNCTION ", $access_schema, "channel_members_current("),
                authority_seed_header: concat!("CREATE FUNCTION ", $access_schema, "seed_tenant_settings("),
                authority_retire_header: concat!("CREATE FUNCTION ", $mdm_registration_tasks_save_retired_run, "("),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_access.",
    "SCHEMA mdm_access",
    "'pg_catalog', 'mdm_access'",
    "mdm_access",
    "public.mdm_installation",
    "mdm_registration_tasks.agent_admission",
    "mdm_registration_tasks.policy_recovery",
    "mdm_registration_tasks.receipts",
    "mdm_registration_tasks.runs",
    "mdm_registration_tasks.save_retired_run",
    "SCHEMA mdm_registration_tasks",
    "mdm_policy.policies",
    "mdm_policy.triggers",
    "mdm_policy.versions",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_inventory_runtime",
    "mdm_scope_runtime",
    "mdm_policy_runtime",
    "mdm_telemetry_runtime",
    "mdm_software_driver",
    "mdm_identity_runtime",
    "CREATE SCHEMA IF NOT EXISTS mdm_registration_tasks",
    "CREATE SCHEMA IF NOT EXISTS mdm_access",
    "NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id))",
    "ADD CONSTRAINT operation_issuance_recovery",
    "ADD CONSTRAINT operation_issuance_result",
    "CREATE INDEX issuance_recovery_operations",
    "CREATE INDEX device_agent_requests",
    "CREATE INDEX agent_quota",
    "CREATE UNIQUE INDEX parent_certificate_enrollment",
    "ADD CONSTRAINT asset_authority_history_pkey",
    "ADD CONSTRAINT credentials_pkey",
    "ADD CONSTRAINT credentials_tenant_id_channel_locator_key",
    "ADD CONSTRAINT devices_pkey",
    "ADD CONSTRAINT enrollment_issuance_operation",
    "ADD CONSTRAINT grants_pkey",
    "ADD CONSTRAINT operations_pkey",
    "ADD CONSTRAINT registrations_tenant_id_id_channel_key",
    "ADD CONSTRAINT registrations_tenant_id_request_id_key",
    "ADD CONSTRAINT report_sources_pkey",
    "ADD CONSTRAINT requests_pkey",
    "ADD CONSTRAINT requests_tenant_id_grant_id_key",
    "CREATE INDEX asset_authority_by_device",
    "CREATE INDEX asset_authority_changes",
    "CREATE INDEX asset_authority_device_event",
    "CREATE UNIQUE INDEX one_active_credential",
    "ADD CONSTRAINT asset_authority_history_tenant_id_revision_fkey",
    "ADD CONSTRAINT credentials_tenant_id_registration_channel_fkey",
    "ADD CONSTRAINT registrations_tenant_id_request_id_fkey",
    "ADD CONSTRAINT report_sources_tenant_id_registration_fkey",
    "ADD CONSTRAINT requests_tenant_id_grant_id_fkey",
    "ADD CONSTRAINT request_parent_credential",
    "ADD CONSTRAINT agent_registration_grant",
    "ADD CONSTRAINT agent_recovery_predecessor",
    "ADD CONSTRAINT activated_credential",
    "CREATE UNIQUE INDEX agent_bootstrap_current",
    "CREATE INDEX agent_configuration_usage",
    "CREATE INDEX agent_connection_latest_observation",
    "CREATE INDEX agent_connection_latest_failure",
    "CREATE INDEX directory_grant_device",
    "CREATE INDEX directory_request_expiry",
    "CREATE INDEX enrollment_offer",
    "CREATE INDEX enrollment_history",
    r###""schema":"mdm_access","table":"asset_authority_history""###,
    r###""schema":"mdm_access","table":"credentials""###,
    r###""schema":"mdm_access","table":"devices""###,
    r###""schema":"mdm_access","table":"grants""###,
    r###""schema":"mdm_access","table":"registration_operations""###,
    r###""schema":"mdm_access","table":"report_sources""###,
    r###""schema":"mdm_access","table":"requests""###,
    r###""schema":"mdm_access","table":"certificate_grants""###,
    r###""schema":"mdm_access","table":"certificate_issuances""###,
    r###""schema":"mdm_access","table":"registration_quota_settings""###,
    r###""schema":"mdm_access","table":"registration_users""###,
    r###""schema":"mdm_access","table":"agent_enrollment_settings""###,
    r###""schema":"mdm_access","table":"agent_configurations""###,
    r###""schema":"mdm_access","table":"registration_admission""###,
    r###""schema":"mdm_access","table":"agent_bootstraps""###,
    r###""schema":"mdm_access","table":"current_users""###,
    r###""schema":"mdm_access","table":"agent_configuration_keys""###,
    r###""schema":"mdm_access","table":"agent_connection_drafts""###,
    r###""schema":"mdm_access","table":"agent_connection_versions""###,
    r###""schema":"mdm_access","table":"agent_connection_deployments""###,
    r###""schema":"mdm_access","table":"agent_connection_observations""###,
    r###""schema":"mdm_access","table":"agent_connection_failures""###,
    r###",{"schema":"mdm_windows","table":"operations","read_write":true,"updates":[],"delete_policy":null},{"schema":"mdm_windows","table":"entra_policy","read_write":true,"updates":["revision","document"],"delete_policy":null},{"schema":"mdm_access","table":"agent_native_enrollments","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_access","table":"command_authorities","read_write":false,"read_only":true,"updates":[],"delete_policy":null}"###,
    "",
    r###""mdm_access.directory_endpoints","mdm_access.directory_users","mdm_access.directory_metadata","mdm_access.directory_inputs""###,
    r###""schema":"mdm_registration_tasks","table":"runs""###,
    r###""schema":"mdm_registration_tasks","table":"receipts""###,
    r###""schema":"mdm_registration_tasks","table":"agent_admission""###,
    r###""schema":"mdm_registration_tasks","table":"policy_recovery""###,
    r###",{"schema":"mdm_registration_tasks","table":"operations","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"schema":"mdm_registration_tasks","table":"device_recovery","read_write":false,"updates":[],"delete_policy":null}"###,
    r###",{"name":"mdm_registration_tasks.retirement_commands","search_path":"search_path=pg_catalog"},{"name":"mdm_registration_tasks.save_retired_command","search_path":"search_path=pg_catalog"},{"name":"mdm_registration_tasks.installation_status","search_path":"search_path=pg_catalog"},{"name":"mdm_registration_tasks.windows_wake_candidates","search_path":"search_path=pg_catalog"},{"name":"mdm_registration_tasks.windows_pending_operations","search_path":"search_path=pg_catalog"},{"name":"mdm_registration_tasks.recovery_key","search_path":"search_path=pg_catalog","security_definer":false}"###,
    r###"{"grantSeconds":86400,"configurationDefaultSeconds":86400,"platforms":["windows","macos"]}"###,
    "mdm_pki.current_certificates",
    "mdm_pki.signing",
    "search_path=pg_catalog, mdm_access"
);
define_storage!(
    da,
    "rss_da.",
    "SCHEMA rss_da",
    "'pg_catalog', 'rss_da'",
    "da_access",
    "rss_da.installation_binding",
    "rss_da.enrollment_agent_admission",
    "rss_da.enrollment_policy_recovery",
    "rss_da.enrollment_receipts",
    "rss_da.enrollment_runs",
    "rss_da.enrollment_save_retired_run",
    "SCHEMA rss_da",
    "rss_da.policies",
    "rss_da.policy_triggers",
    "rss_da.policy_versions",
    "da_owner",
    "da_command_runtime",
    "da_inventory_runtime",
    "da_scope_runtime",
    "da_policy_runtime",
    "da_telemetry_runtime",
    "da_software_driver",
    "da_identity_runtime",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "true",
    "ADD CONSTRAINT registration_operation_issuance_recovery",
    "ADD CONSTRAINT registration_operation_issuance_result",
    "CREATE INDEX registration_issuance_recovery_operations",
    "CREATE INDEX registration_device_agent_requests",
    "CREATE INDEX registration_agent_quota",
    "CREATE UNIQUE INDEX registration_parent_certificate_enrollment",
    "ADD CONSTRAINT registration_asset_authority_history_pkey",
    "ADD CONSTRAINT registration_credentials_pkey",
    "ADD CONSTRAINT registration_credentials_tenant_id_channel_locator_key",
    "ADD CONSTRAINT registration_devices_pkey",
    "ADD CONSTRAINT registration_enrollment_issuance_operation",
    "ADD CONSTRAINT registration_grants_pkey",
    "ADD CONSTRAINT registration_operations_pkey",
    "ADD CONSTRAINT registration_registrations_tenant_id_id_channel_key",
    "ADD CONSTRAINT registration_registrations_tenant_id_request_id_key",
    "ADD CONSTRAINT registration_report_sources_pkey",
    "ADD CONSTRAINT registration_requests_pkey",
    "ADD CONSTRAINT registration_requests_tenant_id_grant_id_key",
    "CREATE INDEX registration_asset_authority_by_device",
    "CREATE INDEX registration_asset_authority_changes",
    "CREATE INDEX registration_asset_authority_device_event",
    "CREATE UNIQUE INDEX registration_one_active_credential",
    "ADD CONSTRAINT registration_asset_authority_history_tenant_id_revision_fkey",
    "ADD CONSTRAINT registration_credentials_tenant_id_registration_channel_fkey",
    "ADD CONSTRAINT registration_registrations_tenant_id_request_id_fkey",
    "ADD CONSTRAINT registration_report_sources_tenant_id_registration_fkey",
    "ADD CONSTRAINT registration_requests_tenant_id_grant_id_fkey",
    "ADD CONSTRAINT registration_request_parent_credential",
    "ADD CONSTRAINT registration_agent_registration_grant",
    "ADD CONSTRAINT registration_agent_recovery_predecessor",
    "ADD CONSTRAINT registration_activated_credential",
    "CREATE UNIQUE INDEX registration_agent_bootstrap_current",
    "CREATE INDEX registration_agent_configuration_usage",
    "CREATE INDEX registration_agent_connection_latest_observation",
    "CREATE INDEX registration_agent_connection_latest_failure",
    "CREATE INDEX registration_directory_grant_device",
    "CREATE INDEX registration_directory_request_expiry",
    "CREATE INDEX registration_enrollment_offer",
    "CREATE INDEX registration_enrollment_history",
    r###""schema":"rss_da","table":"asset_authority_history""###,
    r###""schema":"rss_da","table":"credentials""###,
    r###""schema":"rss_da","table":"devices""###,
    r###""schema":"rss_da","table":"grants""###,
    r###""schema":"rss_da","table":"registration_operations""###,
    r###""schema":"rss_da","table":"report_sources""###,
    r###""schema":"rss_da","table":"requests""###,
    r###""schema":"rss_da","table":"certificate_grants""###,
    r###""schema":"rss_da","table":"certificate_issuances""###,
    r###""schema":"rss_da","table":"registration_quota_settings""###,
    r###""schema":"rss_da","table":"registration_users""###,
    r###""schema":"rss_da","table":"agent_enrollment_settings""###,
    r###""schema":"rss_da","table":"agent_configurations""###,
    r###""schema":"rss_da","table":"registration_admission""###,
    r###""schema":"rss_da","table":"agent_bootstraps""###,
    r###""schema":"rss_da","table":"current_users""###,
    r###""schema":"rss_da","table":"agent_configuration_keys""###,
    r###""schema":"rss_da","table":"agent_connection_drafts""###,
    r###""schema":"rss_da","table":"agent_connection_versions""###,
    r###""schema":"rss_da","table":"agent_connection_deployments""###,
    r###""schema":"rss_da","table":"agent_connection_observations""###,
    r###""schema":"rss_da","table":"agent_connection_failures""###,
    "",
    "",
    r###""rss_da.directory_endpoints","rss_da.directory_users","rss_da.directory_metadata","rss_da.directory_inputs""###,
    r###""schema":"rss_da","table":"enrollment_runs""###,
    r###""schema":"rss_da","table":"enrollment_receipts""###,
    r###""schema":"rss_da","table":"enrollment_agent_admission""###,
    r###""schema":"rss_da","table":"enrollment_policy_recovery""###,
    "",
    "",
    r###"{"grantSeconds":86400,"configurationDefaultSeconds":86400,"platforms":["windows","macos"]}"###,
    "rss_da.pki_current_certificates",
    "rss_da.pki_signing",
    "search_path=pg_catalog, rss_da"
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
