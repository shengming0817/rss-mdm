//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub device_authenticate_agent_in_1: &'static str,
    pub quotas_configuration_on_1: &'static str,
    pub admission_read_in_1: &'static str,
    pub admission_require_request_in_1: &'static str,
    pub admission_change_1: &'static str,
    pub admission_require_windows_in_1: &'static str,
    pub agent_grant_row_1: &'static str,
    pub lifecycle_retire_1: &'static str,
    pub lifecycle_retire_2: &'static str,
    pub lifecycle_retire_3: &'static str,
    pub lifecycle_work_allowed_on_1: &'static str,
    pub lifecycle_begin_retirement_in_1: &'static str,
    pub lifecycle_authorize_reenrollment_in_1: &'static str,
    pub lifecycle_authorize_reenrollment_in_2: &'static str,
    pub lifecycle_authorize_reenrollment_in_3: &'static str,
    pub lifecycle_authorize_reenrollment_in_4: &'static str,
    pub lifecycle_authorize_reenrollment_in_5: &'static str,
    pub operations_read_1: &'static str,
    pub operations_save_result_1: &'static str,
    pub enrollment_agent_policy_create_in_1: &'static str,
    pub enrollment_agent_policy_create_in_2: &'static str,
    pub enrollment_agent_policy_create_in_3: &'static str,
    pub enrollment_agent_policy_create_in_4: &'static str,
    pub enrollment_agent_policy_current_source_in_1: &'static str,
    pub enrollment_store_request_1: &'static str,
    pub enrollment_store_create_enrollment_on_1: &'static str,
    pub enrollment_store_create_enrollment_on_2: &'static str,
    pub enrollment_store_create_enrollment_on_3: &'static str,
    pub enrollment_store_change_enrollment_on_1: &'static str,
    pub enrollment_store_change_enrollment_on_2: &'static str,
    pub enrollment_store_active_registration_1: &'static str,
    pub enrollment_store_mark_bound_in_1: &'static str,
    pub enrollment_read_enrollment_status_1: &'static str,
    pub enrollment_read_record_authenticated_in_1: &'static str,
    pub enrollment_registrations_list_1: &'static str,
    pub quotas_management_change_1: &'static str,
    pub agent_native_source_1: &'static str,
    pub agent_native_native_grant_row_1: &'static str,
    pub agent_native_create_in_1: &'static str,
    pub agent_native_create_in_2: &'static str,
    pub agent_native_source_2: &'static str,
    pub agent_grants_request_1: &'static str,
    pub agent_grants_request_2: &'static str,
    pub agent_grants_request_3: &'static str,
    pub agent_grants_authorize_target_1: &'static str,
    pub agent_grants_authorize_target_2: &'static str,
    pub agent_grants_revoke_1: &'static str,
    pub agent_grants_renewal_status_1: &'static str,
    pub agent_grants_authorize_target_3: &'static str,
    pub agent_grants_revoke_2: &'static str,
    pub agent_grants_recovery_1: &'static str,
    pub agent_grants_recovery_2: &'static str,
    pub agent_grants_recovery_3: &'static str,
    pub agent_grants_progress_1: &'static str,
    pub agent_grants_renew_1: &'static str,
    pub agent_grants_renew_2: &'static str,
    pub agent_grants_renew_3: &'static str,
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
    pub agent_activation_activate_1: &'static str,
    pub agent_activation_activate_2: &'static str,
    pub agent_activation_activate_3: &'static str,
    pub agent_activation_activate_4: &'static str,
    pub agent_activation_activate_5: &'static str,
    pub agent_activation_activate_6: &'static str,
    pub agent_activation_activate_7: &'static str,
    pub agent_activation_activate_8: &'static str,
    pub agent_activation_activate_9: &'static str,
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
    pub device_store_bind_authorized_in_3: &'static str,
    pub device_store_bind_authorized_in_4: &'static str,
    pub device_store_bind_authorized_in_5: &'static str,
    pub device_store_bind_authorized_in_6: &'static str,
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
    pub device_read_lock_active_source_in_1: &'static str,
    pub device_read_enabled_source_in_1: &'static str,
    pub device_read_stale_registration_in_1: &'static str,
    pub device_read_timeline_device_in_1: &'static str,
    pub device_read_timeline_enrollment_in_1: &'static str,
    pub device_read_management_root_in_1: &'static str,
    pub device_read_live_at_1: &'static str,
    pub device_read_page_at_1: &'static str,
    pub device_linked_request_in_1: &'static str,
    pub device_linked_request_in_2: &'static str,
    pub device_linked_request_in_3: &'static str,
    pub device_linked_bind_in_1: &'static str,
    pub device_linked_bind_in_2: &'static str,
    pub device_linked_bind_in_3: &'static str,
    pub device_linked_bind_in_4: &'static str,
    pub device_linked_bind_in_5: &'static str,
    pub device_linked_bind_in_6: &'static str,
    pub device_linked_ready_in_1: &'static str,
    pub device_coordinates_authority_at_on_1: &'static str,
    pub device_directory_column_1: &'static str,
    pub device_directory_column_2: &'static str,
    pub device_directory_source_budget_1: &'static str,
    pub device_directory_selection_1: &'static str,
    pub device_directory_selection_2: &'static str,
    pub device_directory_directory_statistics_1: &'static str,
    pub device_directory_page_on_1: &'static str,
    pub device_management_read_1: &'static str,
    pub device_management_validate_1: &'static str,
    pub device_management_validate_2: &'static str,
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
    ($module:ident, $access_schema:literal, $access_schema_decl:literal, $access_path:literal, $access_role:literal, $installation:literal, $mdm_registration_tasks_agent_admission:literal, $mdm_registration_tasks_device_recovery:literal, $mdm_registration_tasks_installation_status:literal, $mdm_registration_tasks_operations:literal, $mdm_registration_tasks_policy_recovery:literal, $mdm_registration_tasks_receipts:literal, $mdm_registration_tasks_recovery_key:literal, $mdm_registration_tasks_requests:literal, $mdm_registration_tasks_retirement_commands:literal, $mdm_registration_tasks_runs:literal, $mdm_registration_tasks_save_retired_command:literal, $mdm_registration_tasks_save_retired_run:literal, $mdm_registration_tasks_windows_pending_operations:literal, $mdm_registration_tasks_windows_wake_candidates:literal, $mdm_registration_tasks_schema:literal, $mdm_policy_policies:literal, $mdm_policy_triggers:literal, $mdm_policy_versions:literal, $mdm_policy_schema:literal, $owner:literal, $command_runtime:literal, $inventory_runtime:literal, $scope_runtime:literal, $policy_runtime:literal, $resource_runtime:literal, $software_runtime:literal, $content_runtime:literal, $telemetry_runtime:literal, $software_driver:literal, $identity_runtime:literal, $create_mdm_registration_tasks:literal, $create_access:literal, $native_retirement_clear:literal, $index_38:literal, $index_39:literal, $index_40:literal, $index_41:literal, $index_42:literal, $index_43:literal, $index_44:literal, $index_45:literal, $index_46:literal, $index_47:literal, $index_48:literal, $index_49:literal, $index_50:literal, $index_51:literal, $index_52:literal, $index_53:literal, $index_54:literal, $index_55:literal, $index_56:literal, $index_57:literal, $index_58:literal, $index_59:literal, $index_60:literal, $index_61:literal, $index_62:literal, $index_63:literal, $index_64:literal, $index_65:literal, $index_66:literal, $index_67:literal, $index_68:literal, $index_69:literal, $index_70:literal, $index_71:literal, $index_72:literal, $index_73:literal, $index_74:literal, $index_75:literal, $index_76:literal, $index_77:literal, $index_78:literal, $index_79:literal, $index_80:literal, $index_81:literal, $index_82:literal, $index_83:literal, $index_84:literal, $index_85:literal, $index_86:literal, $index_87:literal, $index_88:literal, $contract_table_89:literal, $contract_table_90:literal, $contract_table_91:literal, $contract_table_92:literal, $contract_table_93:literal, $contract_table_94:literal, $contract_table_95:literal, $contract_table_96:literal, $contract_table_97:literal, $contract_table_98:literal, $contract_table_99:literal, $contract_table_100:literal, $contract_table_101:literal, $contract_table_102:literal, $contract_table_103:literal, $contract_table_104:literal, $contract_table_105:literal, $contract_table_106:literal, $contract_table_107:literal, $contract_table_108:literal, $contract_table_109:literal, $contract_table_110:literal, $contract_table_111:literal, $access_contract_tables:literal, $access_contract_functions:literal, $access_contract_external_relations:literal, $contract_table_115:literal, $contract_table_116:literal, $contract_table_117:literal, $contract_table_118:literal, $enrollment_access_contract_tables:literal, $enrollment_access_contract_functions:literal, $default_agent_values:literal, $pki_certificates:literal, $pki_signing:literal, $trigger_path:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                device_authenticate_agent_in_1: concat!("SELECT r.id,r.device,r.generation,r.epoch,r.state,k.id AS credential,k.state AS credential_state,i.identity FROM ", $access_schema, "agent_issuances i JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.id)=(i.tenant_id,i.credential) JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.id)=(k.tenant_id,k.registration) WHERE i.tenant_id=$1::uuid AND i.fingerprint=$2 AND r.channel='agent'"),
                quotas_configuration_on_1: concat!("SELECT revision,agent,windows_mdm,macos_mdm FROM ", $access_schema, "registration_quota_settings WHERE tenant_id=$1::uuid AND subject=$2"),
                admission_read_in_1: concat!("SELECT revision,paused FROM ", $access_schema, "registration_admission WHERE tenant_id=$1::uuid AND channel=$2"),
                admission_require_request_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND q.id=$2 AND r.state='active' AND (r.first_authenticated_at IS NOT NULL OR (q.source='mdm.apple' AND q.state='bound')))"),
                admission_change_1: concat!("INSERT INTO ", $access_schema, "registration_admission(tenant_id,channel,revision,paused) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,channel) DO UPDATE SET revision=EXCLUDED.revision,paused=EXCLUDED.paused"),
                admission_require_windows_in_1: concat!("SELECT first_authenticated_at IS NOT NULL FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active'"),
                agent_grant_row_1: concat!("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                lifecycle_retire_1: concat!("SELECT device FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2"),
                lifecycle_retire_2: concat!("SELECT id FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                lifecycle_retire_3: concat!("SELECT id FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND parent_id=$2 AND state='active' ORDER BY id FOR UPDATE"),
                lifecycle_work_allowed_on_1: concat!("SELECT retirement FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                lifecycle_begin_retirement_in_1: concat!("UPDATE ", $access_schema, "devices SET retirement=$3 WHERE tenant_id=$1::uuid AND id=$2 AND (retirement IS NULL OR retirement=$3)"),
                lifecycle_authorize_reenrollment_in_1: concat!("SELECT retirement FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                lifecycle_authorize_reenrollment_in_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices d JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.device)=(d.tenant_id,d.id) WHERE d.tenant_id=$1::uuid AND d.retirement=$2 AND r.state='active')"),
                lifecycle_authorize_reenrollment_in_3: concat!("UPDATE ", $access_schema, "requests r SET state='cancelled' FROM ", $access_schema, "grants g WHERE(r.tenant_id,r.grant_id)=(g.tenant_id,g.id) AND g.tenant_id=$1::uuid AND g.device=$2 AND r.state='pending'"),
                lifecycle_authorize_reenrollment_in_4: concat!("UPDATE ", $access_schema, "agent_grants SET state='revoked' WHERE tenant_id=$1::uuid AND device=$2 AND state<>'revoked'"),
                lifecycle_authorize_reenrollment_in_5: concat!("UPDATE ", $access_schema, "devices SET retirement=NULL WHERE tenant_id=$1::uuid AND id=$2"),
                operations_read_1: concat!("SELECT digest,result,instance FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid"),
                operations_save_result_1: concat!("INSERT INTO ", $access_schema, "registration_operations(tenant_id,actor,operation_id,digest,result,instance,agent_issuance_recovery) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7)"),
                enrollment_agent_policy_create_in_1: concat!("SELECT l.*,g.device,r.state,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.source FROM ", $access_schema, "agent_native_enrollments l JOIN ", $access_schema, "requests r ON(r.tenant_id,r.id)=(l.tenant_id,l.request) JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE l.tenant_id=$1::uuid AND l.task=$2"),
                enrollment_agent_policy_create_in_2: concat!("INSERT INTO ", $access_schema, "grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,'enrollment','consumed',clock_timestamp(),to_timestamp($6))"),
                enrollment_agent_policy_create_in_3: concat!("INSERT INTO ", $access_schema, "requests(tenant_id,id,grant_id,state,source,expected_generation,password_digest,password_version,expires_at,issuance_operation,windows_profile,self_service,authority_kind) VALUES($1::uuid,$2,$3,'pending',$4,0,$5,1,to_timestamp($6),$7,$8,false,'agent_policy')"),
                enrollment_agent_policy_create_in_4: concat!("INSERT INTO ", $access_schema, "agent_native_enrollments VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)"),
                enrollment_agent_policy_current_source_in_1: concat!("SELECT decode(k.locator,'hex') FROM ", $access_schema, "agent_native_enrollments l JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.id,r.generation)=(l.tenant_id,l.source_registration,l.source_generation) JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE l.tenant_id=$1::uuid AND l.request=$2 AND r.state='active' AND r.channel='agent' AND k.state='active' AND k.channel='agent'"),
                enrollment_store_request_1: concat!("SELECT r.id::text,CASE r.authority_kind WHEN 'apple_account' THEN r.account_version WHEN 'apple_ade' THEN r.organization_version WHEN 'windows_entra' THEN r.organization_version ELSE r.password_version END AS native_version,r.authority_kind,r.account_version,r.account_reference,r.account_challenge,r.organization_version,r.organization_challenge,r.self_service,r.state,r.source,r.windows_profile,r.password_digest,r.password_version,r.expected_generation,r.credential_ref::text,r.issuance_operation::text,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.expires_at::text AS deadline,r.expires_at>clock_timestamp() AS live,g.actor,g.instance,g.device FROM ", $access_schema, "requests r JOIN ", $access_schema, "grants g ON (g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.issuance_operation IS NOT NULL AND r.authority_kind IN ('password','apple_account','apple_ade','windows_entra','agent_policy') FOR UPDATE OF r"),
                enrollment_store_create_enrollment_on_1: concat!("SELECT coalesce(max(generation),0) FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3 AND purpose='primary'"),
                enrollment_store_create_enrollment_on_2: concat!("INSERT INTO ", $access_schema, "grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2::uuid,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t"),
                enrollment_store_create_enrollment_on_3: concat!("INSERT INTO ", $access_schema, "requests(tenant_id,id,grant_id,state,source,expected_generation,password_digest,password_version,credential_ref,expires_at,issuance_operation,windows_profile,self_service) VALUES($1::uuid,$2::uuid,$3::uuid,'pending',$4,$5,$6,1,$7::uuid,clock_timestamp()+interval '300 seconds',$8::uuid,$9,$10) RETURNING floor(extract(epoch FROM expires_at))::bigint"),
                enrollment_store_change_enrollment_on_1: concat!("UPDATE ", $access_schema, "requests SET password_digest=$3,password_version=password_version+1,credential_ref=$4::uuid,expires_at=clock_timestamp()+interval '300 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid RETURNING floor(extract(epoch FROM expires_at))::bigint"),
                enrollment_store_change_enrollment_on_2: concat!("UPDATE ", $access_schema, "requests SET state='cancelled' WHERE tenant_id=$1::uuid AND id=$2::uuid"),
                enrollment_store_active_registration_1: concat!("SELECT r.id::text FROM ", $access_schema, "registrations r JOIN ", $access_schema, "credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.request_id=$2::uuid AND r.state='active' AND c.state='active' FOR SHARE OF r,c"),
                enrollment_store_mark_bound_in_1: concat!("UPDATE ", $access_schema, "requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND password_version=$3 AND expires_at>clock_timestamp() AND self_service=$4"),
                enrollment_read_enrollment_status_1: concat!("SELECT q.state,q.source,q.authority_kind,CASE q.authority_kind WHEN 'apple_account' THEN q.account_version WHEN 'apple_ade' THEN q.organization_version WHEN 'windows_entra' THEN q.organization_version ELSE q.password_version END AS authorization_version,q.windows_profile,q.credential_ref,floor(extract(epoch FROM q.expires_at))::bigint AS expires_at,floor(extract(epoch FROM statement_timestamp()))::bigint AS now,r.id AS registration,r.generation,r.state AS registration_state,floor(extract(epoch FROM r.first_authenticated_at))::bigint AS first_authenticated_at,EXISTS(SELECT 1 FROM ", $access_schema, "report_sources s WHERE s.tenant_id=r.tenant_id AND s.registration=r.id AND s.source=q.source AND s.enabled) AS source_enabled FROM ", $access_schema, "requests q JOIN ", $access_schema, "grants g ON (g.tenant_id,g.id)=(q.tenant_id,q.grant_id) LEFT JOIN ", $access_schema, "registrations r ON (r.tenant_id,r.request_id)=(q.tenant_id,q.id) WHERE q.tenant_id=$1::uuid AND q.id=$2 AND g.device=$3 AND q.issuance_operation IS NOT NULL AND (NOT $4 OR (q.self_service AND g.instance=$5 AND g.actor=$6))"),
                enrollment_read_record_authenticated_in_1: concat!("UPDATE ", $access_schema, "registrations SET first_authenticated_at=clock_timestamp() WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active' AND first_authenticated_at IS NULL"),
                enrollment_registrations_list_1: concat!("SELECT jsonb_build_object('registrationId',r.id,'userContextId',CASE WHEN q.windows_profile='Full' THEN r.id END,'enrollmentId',r.request_id,'agentGrantId',r.agent_grant_id,'source',coalesce(q.source,'agent.builtin'),'generation',r.generation,'status',r.state) FROM ", $access_schema, "registrations r LEFT JOIN ", $access_schema, "requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id="),
                quotas_management_change_1: concat!("INSERT INTO ", $access_schema, "registration_quota_settings(tenant_id,subject,revision,agent,windows_mdm,macos_mdm) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,subject) DO UPDATE SET revision=EXCLUDED.revision,agent=EXCLUDED.agent,windows_mdm=EXCLUDED.windows_mdm,macos_mdm=EXCLUDED.macos_mdm"),
                agent_native_source_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 AND installation=$3 AND active AND state<>'revoked' AND (state='consumed' OR deadline>extract(epoch FROM clock_timestamp())) AND source->>'registration'=$4 AND source->>'credential'=$5 AND source->>'generation'=$6)"),
                agent_native_native_grant_row_1: concat!("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND id=$2 AND source='native'"),
                agent_native_create_in_1: concat!(r###"
SELECT id FROM "###, $access_schema, r###"agent_grants WHERE tenant_id=$1::uuid AND source='native' AND
native_authority->>'installation'= $2
"###),
                agent_native_create_in_2: concat!(r###"
INSERT INTO
"###, $access_schema, r###"agent_grants(tenant_id,
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
                agent_native_source_2: concat!(r###"
SELECT locator FROM "###, $access_schema, r###"credentials WHERE tenant_id=$1::uuid AND id=$2 AND
registration=$3 AND channel='mdm' AND state='active'
"###),
                agent_grants_request_1: concat!("SELECT id FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND source='browser' AND operation_id=$2"),
                agent_grants_request_2: concat!("SELECT count(*) FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND state='pending' AND expires_at>clock_timestamp()"),
                agent_grants_request_3: concat!("INSERT INTO ", $access_schema, "agent_grants(tenant_id,id,operation_id,source,device,platform,secret_digest,request_digest,spki,state,created_at,expires_at) VALUES($1::uuid,$2,$3,'browser',$4,$5,$6,$7,$8,'pending',statement_timestamp(),statement_timestamp()+make_interval(secs=>$9))"),
                agent_grants_authorize_target_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2) AND NOT EXISTS(SELECT 1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active')"),
                agent_grants_authorize_target_2: concat!("UPDATE ", $access_schema, "agent_grants SET device=$3 WHERE tenant_id=$1::uuid AND id=$2 AND state='pending'"),
                agent_grants_revoke_1: concat!("SELECT id FROM ", $access_schema, "agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2"),
                agent_grants_renewal_status_1: concat!("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND source='renewal' AND operation_id=$2"),
                agent_grants_authorize_target_3: concat!(r###"
UPDATE "###, $access_schema, r###"agent_grants SET actor=$3,instance=$4,state='available' WHERE
tenant_id=$1::uuid AND id=$2
"###),
                agent_grants_revoke_2: concat!(r###"
UPDATE "###, $access_schema, r###"agent_grants SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_grants_recovery_1: concat!(r###"
SELECT r.device,r.state,k.id FROM "###, $access_schema, "registrations r JOIN ", $access_schema, r###"credentials k
ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND
r.channel='agent' AND k.state='active' FOR UPDATE OF r,k
"###),
                agent_grants_recovery_2: concat!(r###"
SELECT id FROM "###, $access_schema, r###"agent_grants WHERE tenant_id=$1::uuid AND source='recovery' AND
operation_id=$2
"###),
                agent_grants_recovery_3: concat!(r###"
INSERT INTO
"###, $access_schema, r###"agent_grants(tenant_id,
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
target_registration,
predecessor)
VALUES($1::uuid,
$2,
$3,
'recovery',
$4,
$5,
$6,
$7,
$8,
$9,
$10,
'available',
statement_timestamp(),
statement_timestamp()+make_interval(secs=>$11),
$12,
$13)
"###),
                agent_grants_progress_1: concat!(r###"
SELECT id,state,activation_result FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND
grant_id=$2
"###),
                agent_grants_renew_1: concat!(r###"
SELECT g.actor,g.instance,g.platform FROM "###, $access_schema, r###"registrations r JOIN
"###, $access_schema, r###"agent_grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.agent_grant_id) WHERE
r.tenant_id=$1::uuid AND r.id=$2
"###),
                agent_grants_renew_2: concat!(r###"
SELECT id FROM "###, $access_schema, r###"agent_grants WHERE tenant_id=$1::uuid AND source='renewal' AND
operation_id=$2
"###),
                agent_grants_renew_3: concat!(r###"
INSERT INTO
"###, $access_schema, r###"agent_grants(tenant_id,
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
target_registration,
predecessor)
VALUES($1::uuid,
$2,
$3,
'renewal',
$4,
$5,
$6,
$7,
$8,
$9,
$10,
'available',
statement_timestamp(),
statement_timestamp()+make_interval(secs=>$11),
$12,
$13)
"###),
                agent_connections_retirement_blockers_on_1: concat!("SELECT count(*) FROM ", $access_schema, "agent_configurations f WHERE f.tenant_id=$1::uuid AND NOT ((f.document#>'{connections,configuration,origins}') ?| $2::text[]) AND ((f.state='available' AND f.expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM ", $access_schema, "agent_grants g WHERE g.tenant_id=f.tenant_id AND g.configuration_id=f.id AND g.state IN('available','consumed') AND g.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id)))"),
                agent_connections_retirement_blockers_on_2: concat!("SELECT count(*) FROM ", $access_schema, "agent_bootstraps b WHERE b.tenant_id=$1::uuid AND b.active AND NOT b.cleanup_complete AND b.state<>'revoked' AND b.deadline>floor(extract(epoch FROM clock_timestamp()))::bigint AND NOT(b.download_origin=ANY($2::text[])) AND NOT EXISTS(SELECT 1 FROM ", $access_schema, "agent_grants g JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.agent_grant_id)=(g.tenant_id,g.id) WHERE g.tenant_id=b.tenant_id AND g.native_authority->>'installation'=b.installation::text AND r.state='active')"),
                agent_connections_signer_on_1: concat!("SELECT key_id,public_key,private_key FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid"),
                agent_connections_ensure_signer_on_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid)"),
                agent_connections_ensure_signer_on_2: concat!("INSERT INTO ", $access_schema, "agent_configuration_keys(tenant_id,key_id,public_key,private_key) VALUES($1::uuid,$2,$3,$4)"),
                agent_connections_service_id_on_1: concat!("SELECT instance_id FROM ", $installation),
                agent_connections_draft_on_1: concat!("SELECT document FROM ", $access_schema, "agent_connection_drafts WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision=$2) ORDER BY revision DESC LIMIT 1"),
                agent_connections_published_on_1: concat!("SELECT document,k.public_key FROM ", $access_schema, "agent_connection_versions v JOIN ", $access_schema, "agent_configuration_keys k USING(tenant_id) WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision=$2) ORDER BY revision DESC LIMIT 1"),
                agent_connections_record_deployment_on_1: concat!("SELECT coalesce(max(revision),0) FROM ", $access_schema, "agent_connection_drafts WHERE tenant_id=$1"),
                agent_connections_record_deployment_on_2: concat!("INSERT INTO ", $access_schema, "agent_connection_deployments(tenant_id,origin,service_id,host_id,revision,configuration_revision,observed_at) VALUES($1,$2,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(tenant_id,origin) DO UPDATE SET service_id=excluded.service_id,host_id=excluded.host_id,revision=excluded.revision,configuration_revision=excluded.configuration_revision,observed_at=excluded.observed_at"),
                agent_connections_connection_state_1: concat!("SELECT origin,host_id,revision,configuration_revision,observed_at FROM ", $access_schema, "agent_connection_deployments WHERE tenant_id=$1::uuid AND service_id=$2 ORDER BY origin"),
                agent_connections_connection_state_2: concat!("SELECT count(*),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM ", $access_schema, "agent_connection_observations o WHERE o.tenant_id=r.tenant_id AND o.registration=r.id AND o.generation=r.generation AND o.revision=$2)) FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active'"),
                agent_connections_connection_state_3: concat!("SELECT key_id,public_key FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid"),
                agent_connections_save_connections_1: concat!("INSERT INTO ", $access_schema, "agent_connection_drafts(tenant_id,revision,document) VALUES($1::uuid,$2,$3)"),
                agent_connections_publish_connections_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND NOT EXISTS(SELECT 1 FROM ", $access_schema, "agent_connection_observations o WHERE o.tenant_id=r.tenant_id AND o.registration=r.id AND o.generation=r.generation AND o.operation_id=(SELECT n.operation_id FROM ", $access_schema, "agent_connection_observations n WHERE n.tenant_id=r.tenant_id AND n.registration=r.id AND n.generation=r.generation ORDER BY n.revision DESC,n.recorded_at DESC LIMIT 1) AND o.document->>'origin'=ANY($2::text[])))"),
                agent_connections_publish_connections_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_connection_deployments WHERE tenant_id=$1::uuid AND origin=$2 AND service_id=$3 AND configuration_revision=$4 AND observed_at>=floor(extract(epoch FROM clock_timestamp()))::bigint-300)"),
                agent_connections_publish_connections_3: concat!("INSERT INTO ", $access_schema, "agent_connection_versions(tenant_id,revision,document) VALUES($1::uuid,$2,$3)"),
                agent_connections_connection_operation_1: concat!("SELECT result FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND instance=$3 AND operation_id=$4"),
                agent_connections_acknowledge_connections_1: concat!("SELECT document FROM ", $access_schema, "agent_connection_observations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND operation_id=$4"),
                agent_connections_acknowledge_connections_2: concat!("SELECT max(revision) FROM ", $access_schema, "agent_connection_observations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3"),
                agent_connections_acknowledge_connections_3: concat!("INSERT INTO ", $access_schema, "agent_connection_observations(tenant_id,registration,generation,operation_id,revision,document,received_at) VALUES($1::uuid,$2,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint)"),
                agent_connections_report_connection_failure_1: concat!("SELECT document FROM ", $access_schema, "agent_connection_failures WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND operation_id=$4"),
                agent_connections_report_connection_failure_2: concat!("INSERT INTO ", $access_schema, "agent_connection_failures(tenant_id,registration,generation,operation_id,revision,document,origin,received_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint)"),
                agent_connections_unconfirmed_connection_devices_1: concat!("SELECT r.id,r.device,r.generation,a.revision,a.document->>'origin' AS origin,a.received_at FROM ", $access_schema, "registrations r LEFT JOIN LATERAL(SELECT revision,document,received_at FROM ", $access_schema, "agent_connection_observations WHERE tenant_id=r.tenant_id AND registration=r.id AND generation=r.generation ORDER BY revision DESC,recorded_at DESC LIMIT 1) a ON true WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND ($2::uuid IS NULL OR r.id>$2) AND (a.revision IS NULL OR a.revision<>$3) ORDER BY r.id LIMIT 101"),
                agent_connections_connection_observation_1: concat!("SELECT (SELECT max(revision) FROM ", $access_schema, "agent_connection_versions WHERE tenant_id=r.tenant_id) AS target_revision,r.id AS registration,r.generation,a.document,a.received_at,f.document AS failure_document,f.origin AS failure_origin,f.received_at AS failure_received_at FROM ", $access_schema, "registrations r LEFT JOIN LATERAL(SELECT revision,document,received_at,recorded_at FROM ", $access_schema, "agent_connection_observations WHERE tenant_id=r.tenant_id AND registration=r.id AND generation=r.generation ORDER BY revision DESC,recorded_at DESC LIMIT 1) a ON true LEFT JOIN LATERAL(SELECT document,origin,received_at FROM ", $access_schema, "agent_connection_failures WHERE tenant_id=r.tenant_id AND registration=r.id AND generation=r.generation AND (revision>coalesce(a.revision,0) OR (revision=a.revision AND recorded_at>a.recorded_at)) ORDER BY revision DESC,recorded_at DESC LIMIT 1) f ON true WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active'"),
                agent_connections_rewrap_1: concat!("SELECT key_id,private_key FROM ", $access_schema, "agent_configuration_keys WHERE tenant_id=$1::uuid AND substring(private_key FROM 1 FOR $2)<>$3 FOR UPDATE"),
                agent_connections_rewrap_2: concat!("UPDATE ", $access_schema, "agent_configuration_keys SET private_key=$3 WHERE tenant_id=$1::uuid AND key_id=$2"),
                agent_configurations_row_1: concat!("SELECT * FROM ", $access_schema, "agent_configurations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                agent_configurations_usage_1: concat!("SELECT count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM ", $access_schema, "agent_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id)) AND g.state='available' AND g.expires_at>clock_timestamp()),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM ", $access_schema, "agent_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id))) FROM ", $access_schema, "agent_grants g WHERE g.tenant_id=$1::uuid AND g.configuration_id=$2"),
                agent_configurations_lock_for_grant_1: concat!("SELECT configuration_id FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND id=$2"),
                agent_configurations_create_configuration_1: concat!("SELECT id FROM ", $access_schema, "agent_configurations WHERE tenant_id=$1::uuid AND operation_id=$2"),
                agent_configurations_create_configuration_2: concat!("INSERT INTO ", $access_schema, "agent_configurations(tenant_id,id,operation_id,creator,instance,secret_digest,request_digest,signature,document,quantity,state,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',to_timestamp($11))"),
                agent_configurations_configuration_operation_1: concat!("SELECT id FROM ", $access_schema, "agent_configurations WHERE tenant_id=$1::uuid AND operation_id=$2 AND creator=$3 AND instance=$4"),
                agent_configurations_revoke_configuration_1: concat!("UPDATE ", $access_schema, "agent_configurations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2"),
                agent_configurations_exchange_configuration_1: concat!("SELECT id FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND source='configuration' AND operation_id=$2"),
                agent_configurations_exchange_configuration_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND configuration_id=$2 AND spki=$3)"),
                agent_configurations_exchange_configuration_3: concat!("INSERT INTO ", $access_schema, "agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,created_at,expires_at,configuration_id,configuration_binding) VALUES($1::uuid,$2,$3,'configuration',$4,$5,$6,$7,$8,$9,$10,'available',statement_timestamp(),statement_timestamp()+make_interval(secs=>$11),$12,$13)"),
                agent_configurations_configuration_exchange_status_1: concat!("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>clock_timestamp() AS live FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND configuration_id=$2 AND operation_id=$3 AND source='configuration'"),
                agent_configurations_cancel_reservation_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2)"),
                agent_configurations_cancel_reservation_2: concat!("UPDATE ", $access_schema, "agent_grants SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_bootstrap_challenge_1: concat!("UPDATE ", $access_schema, "agent_bootstraps SET state='signing',transaction_id=$3,csr_digest=$4,spki=$5,deadline=$6 WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_bootstrap_notify_1: concat!("UPDATE ", $access_schema, "agent_bootstraps SET state='issued',fingerprint=$3,certificate=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_native_grant_1: concat!("UPDATE ", $access_schema, "agent_bootstraps SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_row_1: concat!("SELECT installation_facts->>'device' FROM ", $access_schema, "agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2"),
                agent_bootstrap_row_2: concat!("SELECT * FROM ", $access_schema, "agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                agent_bootstrap_require_delivery_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "agent_bootstraps b WHERE b.tenant_id=$1::uuid AND b.id=$2 AND (EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE a.tenant_id=b.tenant_id AND a.operation=b.delivery AND a.phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE a.tenant_id=b.tenant_id AND a.operation=b.delivery AND a.phase='execute' AND a.state<>'pending')))"),
                agent_issuance_issue_1: concat!(r###"
SELECT * FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2 FOR UPDATE
"###),
                agent_issuance_issue_2: concat!(r###"
INSERT INTO
"###, $access_schema, r###"agent_issuances(tenant_id,
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
UPDATE "###, $access_schema, r###"agent_grants SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_issuance_record_unknown_1: concat!(r###"
UPDATE "###, $access_schema, r###"agent_issuances SET state='unknown' WHERE tenant_id=$1::uuid AND id=$2 AND
state='signing'
"###),
                agent_issuance_save_certificate_1: concat!(r###"
SELECT * FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND id=$2 AND grant_id=$3 FOR
UPDATE
"###),
                agent_issuance_save_certificate_2: concat!(r###"
UPDATE "###, $access_schema, r###"agent_issuances SET
state='issued',certificate_chain=$3,metadata=$4,fingerprint=$5 WHERE tenant_id=$1::uuid AND
id=$2
"###),
                agent_issuance_save_certificate_3: concat!(r###"
SELECT * FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_issuance_recover_issuance_1: concat!(r###"
SELECT * FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_current_user_bindings_on_1: concat!("SELECT u.device,u.revision,u.session_reference,u.confirmed_at,(SELECT decode(k.locator,'hex') FROM ", $access_schema, "registrations r JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) JOIN ", $access_schema, "agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE r.tenant_id=u.tenant_id AND r.id=u.registration AND r.device=u.device AND r.generation=u.generation AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND k.state='active' AND i.not_before<=extract(epoch FROM statement_timestamp()) AND i.not_after>extract(epoch FROM statement_timestamp())) AS fingerprint FROM ", $access_schema, "current_users u WHERE u.tenant_id=$1::uuid AND u.device=ANY($2)"),
                agent_current_user_change_current_user_1: concat!("SELECT digest,result,instance FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3"),
                agent_current_user_change_current_user_2: concat!("INSERT INTO ", $access_schema, "current_users(tenant_id,device,revision,registration,generation,session_reference,confirmed_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=EXCLUDED.revision,registration=EXCLUDED.registration,generation=EXCLUDED.generation,session_reference=EXCLUDED.session_reference,confirmed_at=EXCLUDED.confirmed_at"),
                agent_current_user_change_current_user_3: concat!("INSERT INTO ", $access_schema, "registration_operations(tenant_id,actor,instance,operation_id,digest,result) VALUES($1::uuid,$2,$3,$4,$5,$6)"),
                agent_queries_issuance_device_1: concat!("SELECT g.device FROM ", $access_schema, "agent_issuances i JOIN ", $access_schema, "agent_grants g ON(g.tenant_id,g.id)=(i.tenant_id,i.grant_id) WHERE i.tenant_id=$1::uuid AND i.id=$2"),
                agent_queries_request_details_1: concat!("SELECT device FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND id=$2"),
                agent_queries_registration_recovery_operation_1: concat!("SELECT device FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2 AND channel='agent'"),
                agent_queries_registration_recovery_operation_2: concat!("SELECT id,state,platform,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>statement_timestamp() AS live,actor,instance,target_registration FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND source='recovery' AND operation_id=$2 AND target_registration=$3"),
                agent_queries_issuance_recovery_operations_1: concat!("SELECT jsonb_build_object('actor',actor,'instance',instance,'operationId',operation_id) FROM ", $access_schema, "registration_operations WHERE tenant_id="),
                agent_queries_issuance_recovery_operation_1: concat!("SELECT * FROM ", $access_schema, "agent_issuances WHERE tenant_id=$1::uuid AND id=$2"),
                agent_queries_issuance_recovery_operation_2: concat!("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>statement_timestamp() AS live FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND id=$2"),
                agent_queries_issuance_recovery_operation_3: concat!("SELECT result,digest,instance,agent_issuance_recovery FROM ", $access_schema, "registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3 AND agent_issuance_recovery=$4"),
                agent_settings_initialize_on_1: concat!("INSERT INTO ", $access_schema, "agent_enrollment_settings(tenant_id,revision,document) VALUES($1::uuid,1,$2)"),
                agent_settings_tenant_seed_sql_1: concat!("CREATE FUNCTION ", $access_schema, "seed_tenant_settings(t uuid) RETURNS void LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $seed$ INSERT INTO ", $access_schema, "agent_enrollment_settings(tenant_id,revision,document) VALUES(t,1,'", $default_agent_values, "'::jsonb); $seed$; REVOKE ALL ON FUNCTION ", $access_schema, "seed_tenant_settings(uuid) FROM PUBLIC;"),
                agent_settings_read_on_1: concat!("SELECT revision,document FROM ", $access_schema, "agent_enrollment_settings WHERE tenant_id=$1::uuid"),
                agent_settings_update_settings_1: concat!("SELECT tenant_id FROM ", $access_schema, "agent_enrollment_settings WHERE tenant_id=$1::uuid FOR UPDATE"),
                agent_settings_update_settings_2: concat!("UPDATE ", $access_schema, "agent_enrollment_settings SET revision=revision+1,document=$2 WHERE tenant_id=$1::uuid"),
                agent_activation_activate_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='agent' AND state='active')"),
                agent_activation_activate_2: concat!("SELECT coalesce(max(generation),0)+1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='agent'"),
                agent_activation_activate_3: concat!(r###"
SELECT grant_id FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND id=$2
"###),
                agent_activation_activate_4: concat!(r###"
SELECT * FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE
"###),
                agent_activation_activate_5: concat!(r###"
SELECT r.generation,r.epoch,k.state AS credential_state,r.state FROM "###, $access_schema, r###"registrations r
JOIN "###, $access_schema, r###"credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE
r.tenant_id=$1::uuid AND r.id=$2 AND r.device=$3 AND r.channel='agent' AND k.id=$4 FOR UPDATE OF
r,k
"###),
                agent_activation_activate_6: concat!(r###"
SELECT activation_result FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND
credential=$2
"###),
                agent_activation_activate_7: concat!(r###"
SELECT profile FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND credential=$2
"###),
                agent_activation_activate_8: concat!(r###"
UPDATE "###, $access_schema, r###"credentials SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2 AND
state='active'
"###),
                agent_activation_activate_9: concat!(r###"
INSERT INTO "###, $access_schema, r###"devices(tenant_id,id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING
"###),
                agent_activation_activate_10: concat!(r###"
INSERT INTO
"###, $access_schema, r###"registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch)
VALUES($1::uuid,$2,$3,'agent',$6,$4,'active','primary',$5)
"###),
                agent_activation_activate_11: concat!(r###"
INSERT INTO "###, $access_schema, r###"report_sources(tenant_id,registration,source,epoch,enabled)
VALUES($1::uuid,$2,$3,$4,true)
"###),
                agent_activation_activate_12: concat!(r###"
INSERT INTO "###, $access_schema, r###"credentials(tenant_id,id,registration,channel,locator,state)
VALUES($1::uuid,$2,$3,'agent',$4,'active')
"###),
                agent_activation_activate_13: concat!(r###"
UPDATE "###, $access_schema, r###"agent_issuances SET
activation_operation=$3,activation_digest=$4,activation_result=$5,credential=$6 WHERE
tenant_id=$1::uuid AND id=$2
"###),
                agent_activation_authenticate_1: concat!(r###"
SELECT not_after FROM "###, $access_schema, r###"agent_issuances WHERE tenant_id=$1::uuid AND fingerprint=$2 AND
credential IS NOT NULL
"###),
                device_registration_user_assign_registration_user_1: concat!("INSERT INTO ", $access_schema, "registration_users(tenant_id,device,revision,instance,principal) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=EXCLUDED.revision,instance=EXCLUDED.instance,principal=EXCLUDED.principal"),
                device_registration_user_target_on_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2) OR EXISTS(SELECT 1 FROM ", $access_schema, "requests q JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND g.device=$2 AND q.issuance_operation IS NOT NULL AND q.state<>'cancelled') OR EXISTS(SELECT 1 FROM ", $access_schema, "agent_grants WHERE tenant_id=$1::uuid AND device=$2 AND state IN('available','issued','active'))"),
                device_registration_user_read_on_1: concat!("SELECT revision,instance,principal FROM ", $access_schema, "registration_users WHERE tenant_id=$1::uuid AND device=$2"),
                device_registration_user_initialize_on_1: concat!("INSERT INTO ", $access_schema, "registration_users(tenant_id,device,revision,instance,principal) VALUES($1::uuid,$2,1,$3,$4) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=registration_users.revision+1,instance=EXCLUDED.instance,principal=EXCLUDED.principal WHERE registration_users.principal IS NULL"),
                device_registration_user_page_on_1: concat!("SELECT device,revision,instance,principal FROM ", $access_schema, "registration_users WHERE tenant_id=$1::uuid AND device=ANY($2)"),
                device_store_record_communication_in_1: concat!("UPDATE ", $access_schema, "registrations SET last_communication_received_at=greatest(last_communication_received_at,clock_timestamp()) WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND device=$4 AND channel=$5 AND purpose='primary' AND state='active'"),
                device_store_authorize_report_1: concat!("SELECT registration::text AS id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3"),
                device_store_authorize_report_2: concat!("SELECT r.device,r.generation,r.channel,r.epoch::text,q.windows_profile FROM ", $access_schema, "registrations r JOIN ", $access_schema, "requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.channel=$3 AND r.purpose='primary' AND r.state='active' FOR SHARE OF r"),
                device_store_authorize_report_3: concat!("SELECT c.id::text AS id,s.epoch::text AS epoch FROM ", $access_schema, "credentials c JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.registration)=(c.tenant_id,c.registration) WHERE c.tenant_id=$1::uuid AND c.registration=$2::uuid AND c.channel=$3 AND c.locator=$4 AND c.state='active' AND s.source=$5 AND s.enabled FOR SHARE OF c,s"),
                device_store_current_scope_1: concat!("SELECT r.id::text AS id,s.epoch::text AS epoch FROM ", $access_schema, "registrations r JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN ", $access_schema, "credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.state='active' AND c.state='active' AND s.source=$4 AND s.enabled"),
                device_store_retire_state_in_1: concat!("SELECT device,generation,channel,state FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                device_store_retire_state_in_2: concat!("UPDATE ", $access_schema, "registrations SET state=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid"),
                device_store_retire_state_in_3: concat!("UPDATE ", $access_schema, "credentials SET state=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid"),
                device_store_retire_state_in_4: concat!("UPDATE ", $access_schema, "report_sources SET enabled=false WHERE tenant_id=$1::uuid AND registration=$2::uuid"),
                device_store_bind_authorized_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid)"),
                device_store_bind_authorized_in_2: concat!("SELECT source FROM ", $access_schema, "requests WHERE tenant_id=$1::uuid AND id=$2::uuid"),
                device_store_bind_authorized_in_3: concat!("SELECT coalesce(max(generation),0) FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3 AND purpose='primary'"),
                device_store_bind_authorized_in_4: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3)"),
                device_store_bind_authorized_in_5: concat!("SELECT id::text AS id FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3 AND purpose='primary' AND state='active' FOR UPDATE"),
                device_store_bind_authorized_in_6: concat!("INSERT INTO ", $access_schema, "devices(tenant_id,id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING"),
                device_store_bind_authorized_in_7: concat!("INSERT INTO ", $access_schema, "registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,'active','primary',$7::uuid)"),
                device_store_bind_authorized_in_8: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,'active')"),
                device_store_bind_authorized_in_9: concat!("INSERT INTO ", $access_schema, "report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2::uuid,$3,$4::uuid,true)"),
                device_store_replace_mdm_credential_in_1: concat!("SELECT id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active' FOR UPDATE"),
                device_store_replace_mdm_credential_in_2: concat!("UPDATE ", $access_schema, "credentials SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active'"),
                device_store_replace_mdm_credential_in_3: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2::uuid,$3::uuid,'mdm',$4,'active')"),
                device_store_revalidate_source_1: concat!("SELECT device,generation FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND channel=$3 AND state='active'"),
                device_store_revalidate_source_2: concat!("SELECT id FROM ", $access_schema, "credentials WHERE tenant_id=$1::uuid AND registration=$2::uuid AND id=$3::uuid AND state='active'"),
                device_store_revalidate_source_3: concat!("SELECT epoch::text FROM ", $access_schema, "report_sources WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND enabled"),
                device_store_revoke_on_1: concat!("SELECT channel FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND device=$3"),
                device_store_revoke_on_2: concat!("SELECT state FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE"),
                device_store_active_source_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.state='active' AND s.source=$3 AND s.enabled)"),
                device_store_allocate_collection_in_1: concat!("SELECT r.id,r.generation,s.epoch FROM ", $access_schema, "registrations r JOIN ", $access_schema, "credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.state='active' AND c.state='active' AND s.source=$3 AND s.enabled FOR UPDATE OF s"),
                device_store_allocate_collection_in_2: concat!("UPDATE ", $access_schema, "report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND next_sequence<9223372036854775807 RETURNING next_sequence-1"),
                device_store_source_current_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "report_sources WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND epoch=$4::uuid AND enabled)"),
                device_store_allocate_report_in_1: concat!("WITH locked AS MATERIALIZED (SELECT r.id FROM ", $access_schema, "registrations r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.purpose='primary' AND r.state='active' AND s.source=$3 AND s.epoch=$4::uuid AND s.enabled AND s.next_sequence<9223372036854775807 AND r.next_command<=$6 FOR UPDATE OF r,s), ids AS (UPDATE ", $access_schema, "registrations r SET next_command=next_command+$5 FROM locked WHERE r.tenant_id=$1::uuid AND r.id=locked.id RETURNING r.id,r.next_command-$5 AS first), seq AS (UPDATE ", $access_schema, "report_sources s SET next_sequence=next_sequence+1 FROM ids WHERE s.tenant_id=$1::uuid AND s.registration=ids.id AND s.source=$3 RETURNING s.next_sequence-1 AS sequence) SELECT sequence,first FROM seq CROSS JOIN ids"),
                device_store_allocate_task_report_in_1: concat!("UPDATE ", $access_schema, "report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND enabled AND next_sequence<9223372036854775807 RETURNING epoch::text,next_sequence-1"),
                device_store_allocate_commands_in_1: concat!("UPDATE ", $access_schema, "registrations SET next_command=next_command+$5 WHERE tenant_id=$1::uuid AND id=$2 AND purpose=$3 AND generation=$4 AND state='active' AND next_command<=4294967296-$5 RETURNING next_command-$5"),
                device_store_activate_renewed_mdm_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.device=$3 AND r.generation=$4 AND r.state='active' AND k.id=$5 AND k.state='active' AND r.purpose=$6 AND (r.parent_id IS NULL OR EXISTS(SELECT 1 FROM ", $access_schema, "registrations p WHERE p.tenant_id=r.tenant_id AND p.id=r.parent_id AND p.generation=r.parent_generation AND p.state='active' AND p.purpose='primary')))"),
                device_store_revalidate_collection_source_1: concat!("SELECT epoch FROM ", $access_schema, "report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source=$3 AND enabled"),
                device_store_live_collection_streams_on_1: concat!("SELECT r.id,s.source,s.epoch FROM ", $access_schema, "registrations r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND s.enabled AND s.source IN('agent.native','agent.script','agent.osquery') AND EXISTS(SELECT 1 FROM ", $access_schema, "credentials k JOIN ", $access_schema, "agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE k.tenant_id=r.tenant_id AND k.registration=r.id AND k.state='active' AND i.not_after>floor(extract(epoch FROM clock_timestamp()))::bigint) ORDER BY r.id,s.source LIMIT 65"),
                device_store_collection_stream_retired_on_1: concat!("SELECT NOT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r JOIN ", $access_schema, "report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.id=$3 AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND s.source=$4 AND s.epoch=$5 AND s.enabled)"),
                device_store_report_epoch_in_1: concat!("SELECT s.epoch FROM ", $access_schema, "report_sources s JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.id)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.registration=$2 AND s.source=$3 AND s.enabled AND r.state='active'"),
                device_endpoints_current_in_1: concat!("SELECT r.id,r.generation FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.purpose='primary' AND r.state='active' AND EXISTS(SELECT 1 FROM ", $access_schema, "credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')"),
                device_endpoints_current_page_in_1: concat!("SELECT r.device,r.channel,r.id,r.generation FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.device=ANY($2) AND r.purpose='primary' AND r.state='active' AND EXISTS(SELECT FROM ", $access_schema, "credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active') ORDER BY r.device,r.channel"),
                device_endpoints_page_in_1: concat!("SELECT id FROM ", $access_schema, r###"devices WHERE tenant_id=$1::uuid AND id COLLATE "C">$2 COLLATE "C" ORDER BY id COLLATE "C" LIMIT $3"###),
                device_endpoints_page_at_1: concat!(r###"WITH latest AS (
        SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document FROM "###, $access_schema, r###"asset_authority_history
        WHERE tenant_id=$1::uuid AND device=ANY($2) AND mdm.asset_visible($3::jsonb,revision)
        ORDER BY kind,identity,revision DESC
    ) SELECT r.device,r.document->>'channel' AS channel,r.identity::uuid AS id,(r.document->>'generation')::bigint AS generation
    FROM latest r WHERE r.kind='registration' AND r.document->>'purpose'='primary' AND r.document->>'state'='active'
        AND EXISTS(SELECT FROM latest k WHERE k.kind='credential' AND k.registration=r.registration AND k.document->>'state'='active')
    ORDER BY r.device,channel"###),
                device_endpoints_candidate_page_in_1: concat!("SELECT r.device FROM ", $access_schema, r###"registrations r WHERE r.tenant_id=$1::uuid AND r.channel=$2 AND r.purpose='primary' AND r.state='active' AND r.device COLLATE "C">$3 COLLATE "C" AND ($4::text[] IS NULL OR r.device=ANY($4)) ORDER BY r.device COLLATE "C" LIMIT $5"###),
                device_endpoints_lifecycle_page_at_1: concat!(r###"
        WITH latest AS (
            SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
            FROM "###, $access_schema, r###"asset_authority_history
            WHERE tenant_id=$1::uuid AND device=ANY($2) AND mdm.asset_visible($3::jsonb,revision)
            ORDER BY kind,identity,revision DESC
        ), live AS (
            SELECT r.device,CASE s.document->>'source'
                WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos'
                ELSE r.document->>'platform' END AS platform
            FROM latest r JOIN latest s ON s.registration=r.registration AND s.kind='source'
                JOIN latest k ON k.registration=r.registration AND k.kind='credential'
                JOIN latest d ON d.device=r.device AND d.kind='device' AND d.document IS NOT NULL
            WHERE r.kind='registration' AND r.document->>'purpose'='primary'
                AND r.document->>'state'='active' AND k.document->>'state'='active'
                AND s.document->>'enabled'='true'
        ) SELECT d AS device,count(l.device)>0 AS managed,
            min(l.platform) AS platform,count(DISTINCT l.platform)>1 OR bool_or(l.device IS NOT NULL AND l.platform IS NULL) AS conflict
        FROM unnest($2::text[]) d LEFT JOIN live l ON l.device=d GROUP BY d ORDER BY d COLLATE "C"
    "###),
                device_read_find_1: concat!("SELECT id FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2"),
                device_read_active_sources_1: concat!("SELECT r.device,r.id::text AS registration,r.generation,r.channel,s.source,s.epoch::text FROM ", $access_schema, "registrations r JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN ", $access_schema, "credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=ANY($2) AND r.state='active' AND s.enabled AND c.state='active' ORDER BY r.device,s.source"),
                device_read_exists_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "devices WHERE tenant_id=$1::uuid AND id=$2)"),
                device_read_sources_at_1: concat!("SELECT * FROM ", $access_schema, "asset_sources_at($2,$3) WHERE nullif(current_setting('rss.tenant_id',true),'')=$1"),
                device_read_registered_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active')"),
                device_read_active_channel_in_1: concat!("SELECT device,id,generation FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=ANY($2) AND channel=$3 AND purpose=$4 AND state='active' AND (purpose='primary' OR ready) AND (parent_id IS NULL OR EXISTS(SELECT 1 FROM ", $access_schema, "registrations p WHERE p.tenant_id=registrations.tenant_id AND p.id=registrations.parent_id AND p.generation=registrations.parent_generation AND p.state='active')) ORDER BY device,id"),
                device_read_active_sources_in_1: concat!("SELECT r.id,r.device,r.generation FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.id=ANY($2) AND r.state='active' AND EXISTS(SELECT 1 FROM ", $access_schema, "report_sources s WHERE (s.tenant_id,s.registration)=(r.tenant_id,r.id) AND s.source=$3 AND s.enabled)"),
                device_read_lock_active_source_in_1: concat!("SELECT r.device,r.generation FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.state='active' AND EXISTS(SELECT 1 FROM ", $access_schema, "report_sources s WHERE (s.tenant_id,s.registration)=(r.tenant_id,r.id) AND s.source=$3 AND s.enabled) FOR UPDATE OF r"),
                device_read_enabled_source_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r LEFT JOIN ", $access_schema, "requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) JOIN ", $access_schema, "credentials k ON (k.tenant_id,k.registration)=(r.tenant_id,r.id) JOIN ", $access_schema, "report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.state='active' AND k.state='active' AND (q.source=$3 OR (r.channel='agent' AND $3='agent.builtin')) AND s.source=$3 AND s.enabled)"),
                device_read_stale_registration_in_1: concat!("SELECT NOT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.device=$3 AND r.generation=$4 AND r.state='active' AND EXISTS(SELECT 1 FROM ", $access_schema, "credentials c WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND c.state='active'))"),
                device_read_timeline_device_in_1: concat!("SELECT device FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2"),
                device_read_timeline_enrollment_in_1: concat!("SELECT g.device FROM ", $access_schema, "requests r JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2"),
                device_read_management_root_in_1: concat!("SELECT coalesce(parent_id,id),coalesce(parent_generation,generation) FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active'"),
                device_read_live_at_1: concat!(r###"
                WITH latest AS (
                    SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
                    FROM "###, $access_schema, r###"asset_authority_history
                    WHERE tenant_id=$1::uuid AND device=ANY($2) AND mdm.asset_visible($3,revision)
                      AND kind IN('registration','credential','source')
                    ORDER BY kind,identity,revision DESC
                ), live AS (
                    SELECT device,registration FROM latest GROUP BY device,registration
                    HAVING bool_or(kind='registration' AND document->>'state'='active')
                       AND bool_or(kind='credential' AND document->>'state'='active')
                       AND bool_or(kind='source' AND document->>'enabled'='true')
                ) SELECT DISTINCT device FROM live
            "###),
                device_read_page_at_1: concat!(r###"
              WITH latest AS (
                SELECT DISTINCT ON(identity COLLATE "C") identity,document
                FROM "###, $access_schema, r###"asset_authority_history
                WHERE tenant_id=$1::uuid AND kind='device' AND mdm.asset_visible($2,revision)
                  AND identity COLLATE "C">coalesce($3::text,'') COLLATE "C"
                  AND ($4 OR identity=ANY($5))
                ORDER BY identity COLLATE "C",revision DESC
              ) SELECT identity FROM latest WHERE document IS NOT NULL
                ORDER BY identity COLLATE "C" LIMIT $6
            "###),
                device_linked_request_in_1: concat!("SELECT windows_profile FROM ", $access_schema, "requests q JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.request_id)=(q.tenant_id,q.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND q.source='mdm.windows'"),
                device_linked_request_in_2: concat!("SELECT coalesce(max(generation),0) FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='windows_declared'"),
                device_linked_request_in_3: concat!("INSERT INTO ", $access_schema, "requests(tenant_id,id,authority_kind,parent_id,parent_generation,parent_credential,state,expected_generation,expires_at,issuance_operation,source,windows_profile) VALUES($1::uuid,$2,'parent_certificate',$3,$4,$5,'pending',$6,clock_timestamp()+interval '5 minutes',$7,'mdm.windows',$8)"),
                device_linked_bind_in_1: concat!("SELECT expected_generation,issuance_operation FROM ", $access_schema, "requests WHERE tenant_id=$1::uuid AND id=$2 AND authority_kind='parent_certificate' AND parent_id=$3 AND parent_generation=$4 AND parent_credential=$5 AND state='pending' AND expires_at>clock_timestamp() FOR UPDATE"),
                device_linked_bind_in_2: concat!("SELECT coalesce(max(generation),0) FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='windows_declared'"),
                device_linked_bind_in_3: concat!("SELECT id FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='windows_declared' AND state='active' FOR UPDATE"),
                device_linked_bind_in_4: concat!("INSERT INTO ", $access_schema, "registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch,parent_id,parent_generation) VALUES($1::uuid,$2,$3,'mdm',$4,$5,'active','windows_declared',$6,$7,$8)"),
                device_linked_bind_in_5: concat!("INSERT INTO ", $access_schema, "credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2,$3,'mdm',$4,'active')"),
                device_linked_bind_in_6: concat!("UPDATE ", $access_schema, "requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2"),
                device_linked_ready_in_1: concat!("UPDATE ", $access_schema, "registrations SET ready=true WHERE tenant_id=$1::uuid AND id=$2 AND purpose='windows_declared' AND NOT ready"),
                device_coordinates_authority_at_on_1: concat!("SELECT coalesce(max(revision),0) FROM ", $access_schema, "asset_authority_history WHERE tenant_id=$1::uuid AND device=$2 AND mdm.asset_visible($3,revision)"),
                device_directory_column_1: concat!("ARRAY(SELECT r.channel FROM ", $access_schema, "registrations r WHERE r.tenant_id=d.tenant_id AND r.device=d.id UNION SELECT CASE WHEN q.source LIKE 'mdm.%' THEN 'mdm' ELSE 'agent' END FROM ", $access_schema, "requests q JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE g.tenant_id=d.tenant_id AND g.device=d.id)"),
                device_directory_column_2: concat!("ARRAY(SELECT 'agent.builtin' FROM ", $access_schema, "registrations r WHERE r.tenant_id=d.tenant_id AND r.device=d.id AND r.channel='agent' UNION SELECT q.source FROM ", $access_schema, "requests q JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE g.tenant_id=d.tenant_id AND g.device=d.id)"),
                device_directory_source_budget_1: concat!("WITH source_budget AS MATERIALIZED (SELECT count(*) AS rows FROM (SELECT tenant_id FROM ", $access_schema, "directory_inputs WHERE tenant_id="),
                device_directory_selection_1: concat!(", selected AS (SELECT d.id,d.status FROM ", $access_schema, "directory_metadata d WHERE (SELECT rows FROM source_budget)<="),
                device_directory_selection_2: concat!(") SELECT s.id,b.rows,e.summary FROM source_budget b LEFT JOIN selected s ON true LEFT JOIN ", $access_schema, "directory_endpoints e ON e.tenant_id=$1::uuid AND e.id=s.id"),
                device_directory_directory_statistics_1: concat!(" THEN (SELECT jsonb_build_object('statistics',jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE d.status='pending'),'active',count(*) FILTER(WHERE d.status='active'),'revoked',count(*) FILTER(WHERE d.status='revoked')),'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint) FROM ", $access_schema, "directory_metadata d WHERE d.tenant_id=$1::uuid"),
                device_directory_page_on_1: concat!("SELECT d.summary FROM unnest($2::text[]) WITH ORDINALITY p(id,n) JOIN ", $access_schema, "directory_endpoints d ON d.id=p.id WHERE d.tenant_id=$1::uuid ORDER BY p.n"),
                device_management_read_1: concat!("SELECT r.id,r.device,r.generation,r.purpose,r.epoch,r.parent_id,r.parent_generation,q.windows_profile,k.id AS credential FROM ", $access_schema, "registrations r JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.channel=$2 AND r.purpose=$3 AND r.state='active' AND q.source=$4 AND k.channel=$2 AND k.state='active' AND k.locator=$5"),
                device_management_validate_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r JOIN ", $access_schema, "requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.generation=$3 AND r.device=$4 AND r.purpose='primary' AND r.state='active' AND q.source='mdm.windows' AND EXISTS(SELECT 1 FROM ", $access_schema, "credentials k WHERE k.tenant_id=r.tenant_id AND k.registration=r.id AND k.state='active'))"),
                device_management_validate_2: concat!("SELECT k.state,r.state AS registration_state,i.not_after FROM ", $access_schema, "credentials k JOIN ", $access_schema, "registrations r ON(r.tenant_id,r.id)=(k.tenant_id,k.registration) JOIN ", $access_schema, "agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE k.tenant_id=$1::uuid AND k.id=$2"),
                device_management_validate_3: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations r JOIN ", $access_schema, "credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.generation=$3 AND r.device=$4 AND r.purpose=$5 AND r.epoch=$6 AND r.state='active' AND k.id=$7 AND k.state='active' AND r.parent_id IS NOT DISTINCT FROM $8 AND r.parent_generation IS NOT DISTINCT FROM $9)"),
                agent_configurations_directory_configuration_directory_1: concat!("WITH candidates AS (SELECT id,tenant_id,creator,quantity,document->'quantity' AS quantity_metadata,document->'targets' AS targets,floor(extract(epoch FROM created_at))::bigint AS created, floor(extract(epoch FROM expires_at))::bigint AS expiry,CASE WHEN state='revoked' THEN 'revoked' WHEN expires_at<=statement_timestamp() THEN 'expired' ELSE 'available' END AS effective_state FROM ", $access_schema, "agent_configurations WHERE tenant_id="),
                agent_configurations_directory_configuration_directory_2: concat!(") SELECT jsonb_build_object('configurationId',c.id,'state',c.effective_state,'createdAt',c.created,'expiresAt',c.expiry,'createdBy',c.creator,'targets',c.targets,'quantity',c.quantity_metadata,'reserved',u.reserved,'consumed',u.consumed,'remaining',c.quantity-u.reserved-u.consumed) FROM candidates c CROSS JOIN LATERAL (SELECT count(*) FILTER(WHERE NOT issued AND state='available' AND expires_at>statement_timestamp()) AS reserved,count(*) FILTER(WHERE issued) AS consumed FROM (SELECT g.state,g.expires_at,EXISTS(SELECT 1 FROM ", $access_schema, "agent_issuances i WHERE (i.tenant_id,i.grant_id)=(g.tenant_id,g.id)) AS issued FROM ", $access_schema, "agent_grants g WHERE g.tenant_id=c.tenant_id AND g.configuration_id=c.id) grants) u"),
                enrollment_tasks_recovery_accept_action_dispatch_1: concat!("SELECT gateway_accepted FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE"),
                enrollment_tasks_recovery_accept_action_dispatch_2: concat!("UPDATE ", $mdm_registration_tasks_runs, " SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid"),
                enrollment_tasks_worker_pending_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_policy_recovery, " WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)"),
                enrollment_tasks_worker_pending_in_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " t WHERE tenant_id=$1::uuid AND id=$2 AND (state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed'))"),
                enrollment_tasks_retirement_retire_in_1: concat!("SELECT id,state AS state FROM ", $mdm_registration_tasks_runs, " a WHERE tenant_id=$1::uuid AND registration=$2 AND id>$3 AND ((state->>'execution' IN ('not_started','running','waiting_reboot','unknown') AND state->>'cancellation'='none')) AND EXISTS(SELECT 1 FROM ", $access_schema, "registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM ", $access_schema, "devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND ", $native_retirement_clear, "))) ORDER BY id LIMIT 64"),
                enrollment_tasks_retirement_retire_in_2: concat!("SELECT ", $mdm_registration_tasks_save_retired_run, "($1,$2,$3,$4)"),
                enrollment_tasks_retirement_progress_on_1: concat!("SELECT count(*)>0,(array_agg(t.id ORDER BY t.id) FILTER(WHERE t.state->>'execution'='unknown'))[1] FROM ", $mdm_registration_tasks_runs, " t WHERE t.tenant_id=$1::uuid AND t.registration=ANY($2) AND (t.state->>'execution' IN('running','waiting_reboot','unknown'))"),
                enrollment_tasks_wake_policy_in_1: concat!("INSERT INTO ", $mdm_registration_tasks_policy_recovery, "(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=", $mdm_registration_tasks_policy_recovery, ".input_revision+1"),
                enrollment_tasks_poll_offer_candidates_1: concat!("SELECT id,available_at FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'execution'='not_started' AND state->>'cancellation'='none' AND gateway_accepted AND available_at<=$3 AND deadline>$3 AND (state->'delivery'->>'kind'='queued' OR (state->'delivery'->>'leaseUntil')::bigint<=$3) AND ($4::bigint IS NULL OR (available_at,id)>($4,$5::uuid)) ORDER BY available_at,id LIMIT 128"),
                enrollment_tasks_poll_cancellations_1: concat!("SELECT id,state->'delivery'->>'attempt' AS attempt FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'cancellation'='requested' AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4"),
                enrollment_tasks_admission_accept_for_device_1: concat!("SELECT t.id,t.created_at,t.deadline FROM ", $mdm_policy_triggers, " t WHERE t.tenant_id=$1::uuid AND t.version=$2 AND t.deadline>$4 AND $5 AND NOT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " r WHERE r.tenant_id=t.tenant_id AND r.policy_version=t.version AND r.device=$3 AND r.occurrence='explicit:'||t.id::text) ORDER BY t.created_at,t.id LIMIT 1"),
                enrollment_tasks_admission_accept_for_device_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND registration=$2)"),
                enrollment_tasks_admission_queue_run_in_1: concat!("INSERT INTO ", $mdm_registration_tasks_runs, "(tenant_id,id,policy_version,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at,source_objects,origin,invocation) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)"),
                enrollment_tasks_admission_occurrence_available_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND policy_version=$2 AND device=$3 AND occurrence=$4)"),
                enrollment_tasks_policy_recovery_prepare_in_1: concat!("SELECT * FROM ", $mdm_registration_tasks_policy_recovery, " WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE"),
                enrollment_tasks_policy_recovery_advance_in_1: concat!("SELECT r.id FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33"),
                enrollment_tasks_policy_recovery_advance_in_2: concat!("UPDATE ", $mdm_registration_tasks_policy_recovery, " SET input_consumed=$3,input_window=$4,recovery_after=$5,runs_done=$6 WHERE tenant_id=$1::uuid AND policy=$2"),
                enrollment_tasks_agent_agent_admit_in_1: concat!("INSERT INTO ", $mdm_registration_tasks_agent_admission, "(tenant_id,registration) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING"),
                enrollment_tasks_agent_agent_admit_in_2: concat!("SELECT policy_after FROM ", $mdm_registration_tasks_agent_admission, " WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE"),
                enrollment_tasks_agent_agent_admit_in_3: concat!("SELECT id,current_version FROM ", $mdm_policy_policies, " WHERE tenant_id=$1::uuid AND state='enabled' AND definition->'action'->>'kind'='request_mdm_enrollment' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64"),
                enrollment_tasks_agent_agent_admit_in_4: concat!("UPDATE ", $mdm_registration_tasks_agent_admission, " SET policy_after=$3 WHERE tenant_id=$1::uuid AND registration=$2"),
                enrollment_tasks_storage_run_in_1: concat!("SELECT id FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                enrollment_tasks_storage_run_in_2: concat!("SELECT * FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                enrollment_tasks_storage_save_run_1: concat!("SELECT state FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                enrollment_tasks_storage_save_run_2: concat!("UPDATE ", $mdm_registration_tasks_runs, " SET state=$3,result=$4,invocation=$5 WHERE tenant_id=$1::uuid AND id=$2 AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4 OR invocation IS DISTINCT FROM $5)"),
                enrollment_tasks_storage_pending_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND (((r.state->>'execution'='unknown' OR (r.state->>'execution'='running' AND r.deadline<=$6))) OR (v.policy=$3 AND r.registration=$5 AND r.state->>'cancellation'<>'confirmed' AND (r.state->>'execution'='running' OR (r.state->>'execution'='not_started' AND r.deadline>$6))))), (SELECT max(created_at) FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND device=$2 AND policy_version=$4 AND registration=$5)"),
                enrollment_tasks_storage_active_count_on_1: concat!("SELECT count(*) FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$3"),
                enrollment_tasks_storage_owned_ids_on_1: concat!("SELECT id FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=ANY($2)"),
                enrollment_tasks_storage_replay_1: concat!("SELECT fingerprint,response FROM ", $mdm_registration_tasks_receipts, " WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3"),
                enrollment_tasks_storage_receipt_1: concat!("INSERT INTO ", $mdm_registration_tasks_receipts, "(tenant_id,actor,id,fingerprint,response) VALUES($1::uuid,$2,$3,$4,$5)"),
                enrollment_tasks_storage_association_on_1: concat!("SELECT device,NULL::uuid FROM ", $mdm_registration_tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                enrollment_tasks_self_service_self_service_status_in_1: concat!("SELECT response FROM ", $mdm_registration_tasks_receipts, " WHERE tenant_id=$1::uuid AND actor=ANY($2) AND id=$3 ORDER BY array_position($2,actor) LIMIT 1"),
                enrollment_tasks_self_service_advance_waiting_in_1: concat!("UPDATE ", $mdm_registration_tasks_runs, " SET invocation=$3,source_objects=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                enrollment_tasks_queries_page_on_1: concat!(",'result',r.result) FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5"),
                enrollment_tasks_queries_detail_on_1: concat!("SELECT r.device FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3"),
                enrollment_tasks_queries_detail_on_2: concat!(",'result',r.result) FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3"),
                enrollment_tasks_queries_assignment_ids_on_1: concat!("SELECT r.id FROM ", $mdm_registration_tasks_runs, " r JOIN ", $mdm_policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND $6='agent' AND r.registration=$4 AND r.generation=$5 ORDER BY r.id"),
                enrollment_tasks_queries_assignment_state_on_1: concat!("SELECT frozen FROM ", $mdm_policy_versions, " WHERE tenant_id=$1::uuid AND id=$2"),
                install: concat!(r###"-- Fresh installation: registration-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

"###, $create_access, r###";

CREATE FUNCTION "###, $access_schema, r###"capture_asset_authority() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO "###, $access_path, r###"
    AS $$
DECLARE r jsonb; d jsonb; previous jsonb; k text; i text; dev text; reg uuid; v bigint; t uuid; platform text;
BEGIN
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 IF TG_OP='UPDATE' THEN previous=to_jsonb(OLD); END IF;
 t=(r->>'tenant_id')::uuid;
 IF TG_TABLE_NAME='registrations' AND r->>'channel'='agent' THEN
  SELECT g.platform INTO platform FROM "###, $access_schema, r###"agent_grants g WHERE g.tenant_id=t AND g.id=(r->>'agent_grant_id')::uuid;
 END IF;
 CASE TG_TABLE_NAME
 WHEN 'devices' THEN
  k='device'; i=r->>'id'; dev=i; d=jsonb_build_object('id',i);
  -- Admission intent does not replace the endpoint identity or invalidate
  -- other devices in the same sealed Policy batch.
  IF previous IS NOT NULL AND d=jsonb_build_object('id',previous->>'id') THEN RETURN NULL; END IF;
 WHEN 'registrations' THEN
  k='registration'; i=r->>'id'; reg=i::uuid; dev=r->>'device';
  d=jsonb_build_object('id',i,'device',dev,'channel',r->>'channel','purpose',r->>'purpose','generation',r->'generation','state',r->>'state','platform',platform);
  IF previous IS NOT NULL AND d=jsonb_build_object('id',previous->>'id','device',previous->>'device','channel',previous->>'channel','purpose',previous->>'purpose','generation',previous->'generation','state',previous->>'state','platform',platform) THEN RETURN NULL; END IF;
 WHEN 'report_sources' THEN
  IF NOT EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations WHERE tenant_id=t AND id=(r->>'registration')::uuid AND purpose='primary') THEN RAISE EXCEPTION 'report source requires primary registration'; END IF;
  k='source'; reg=(r->>'registration')::uuid;
  i=jsonb_build_array(r->>'registration',r->>'source')::text;
  d=jsonb_build_object('registration',reg,'source',r->>'source','epoch',r->>'epoch','enabled',r->'enabled');
  -- Collection sequence/command allocation is not an asset change.
  IF previous IS NOT NULL AND d=jsonb_build_object('registration',(previous->>'registration')::uuid,'source',previous->>'source','epoch',previous->>'epoch','enabled',previous->'enabled') THEN RETURN NULL; END IF;
 WHEN 'credentials' THEN
  k='credential'; i=r->>'id'; reg=(r->>'registration')::uuid;
  -- Credential locators and secrets never enter asset history.
  d=jsonb_build_object('id',i,'registration',reg,'channel',r->>'channel','state',r->>'state');
 ELSE RAISE EXCEPTION 'unexpected asset authority';
 END CASE;
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF dev IS NULL THEN SELECT device INTO dev FROM "###, $access_schema, r###"registrations WHERE tenant_id=t AND id=reg; END IF;
 v=mdm.record_asset_change(t,k,jsonb_build_object('device',dev,'registration',reg,'identity',i),ARRAY[]::text[]);
 IF TG_OP='DELETE' THEN d=NULL; END IF;
 INSERT INTO "###, $access_schema, r###"asset_authority_history VALUES(t,k,i,dev,reg,v,d);
 RETURN NULL;
END $$;

CREATE TABLE "###, $access_schema, r###"asset_authority_history (
    tenant_id uuid NOT NULL,
    kind text NOT NULL,
    identity text NOT NULL,
    device text,
    registration uuid,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT asset_authority_history_document_check CHECK (((document IS NULL) OR (octet_length((document)::text) <= 16384))),
    CONSTRAINT asset_authority_history_identity_check CHECK (((octet_length(identity) >= 1) AND (octet_length(identity) <= 1024))),
    CONSTRAINT asset_authority_history_kind_check CHECK ((kind = ANY (ARRAY['device'::text, 'registration'::text, 'source'::text, 'credential'::text])))
);

ALTER TABLE ONLY "###, $access_schema, r###"asset_authority_history FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"credentials (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    registration uuid NOT NULL,
    channel text NOT NULL,
    locator text NOT NULL,
    state text NOT NULL,
    CONSTRAINT credentials_channel_check CHECK ((channel = ANY (ARRAY['agent'::text, 'mdm'::text]))),
    CONSTRAINT credentials_locator_check CHECK ((locator ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT credentials_state_check CHECK ((state = ANY (ARRAY['active'::text, 'superseded'::text, 'revoked'::text])))
);

ALTER TABLE ONLY "###, $access_schema, r###"credentials FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"devices (
    tenant_id uuid NOT NULL,
    id text NOT NULL,
    retirement uuid,
    CONSTRAINT devices_id_check CHECK ((((octet_length(id) >= 1) AND (octet_length(id) <= 256)) AND (id !~ '[[:cntrl:]]'::text)))
);

ALTER TABLE ONLY "###, $access_schema, r###"devices FORCE ROW LEVEL SECURITY;

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
    CONSTRAINT operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT operations_result_check CHECK ((octet_length(result) <= 65536))
);

ALTER TABLE ONLY "###, $access_schema, r###"registration_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"agent_grants (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 operation_id uuid NOT NULL,
 source text NOT NULL,
 actor text,
 instance text,
 device text NOT NULL CHECK(octet_length(device) BETWEEN 1 AND 256 AND device !~ '[[:cntrl:]]'),
 platform text NOT NULL CHECK(platform IN('windows','macos')),
 secret_digest text NOT NULL CHECK(secret_digest ~ '^[0-9a-f]{64}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 spki text CHECK(spki ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN('pending','available','consumed','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 target_registration uuid,
 predecessor uuid,
 native_authority jsonb CHECK(octet_length(native_authority::text)<=65536),
 CONSTRAINT native_origin CHECK((source='native')=(native_authority IS NOT NULL)),
 CONSTRAINT agent_grant_window CHECK(expires_at>created_at AND expires_at<=created_at+interval '7 days'),
 CONSTRAINT agent_grant_subject CHECK((state IN('pending','revoked') AND source='browser' AND actor IS NULL AND instance IS NULL AND spki IS NOT NULL) OR (state<>'pending' AND actor IS NOT NULL AND instance IS NOT NULL)),
 CONSTRAINT agent_grant_target CHECK((source IN('recovery','renewal'))=(target_registration IS NOT NULL AND predecessor IS NOT NULL)),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,source,operation_id),
 configuration_id uuid,
 configuration_binding jsonb CHECK(octet_length(configuration_binding::text)<=32768),
 CONSTRAINT configuration_authority
 CHECK((source='configuration' AND configuration_id IS NOT NULL AND configuration_binding IS NOT NULL AND spki IS NOT NULL) OR (source<>'configuration' AND configuration_id IS NULL AND configuration_binding IS NULL)),
 CONSTRAINT agent_grants_source_check CHECK(source IN('download','browser','native','recovery','renewal','configuration')),
 CONSTRAINT configuration_device_key UNIQUE(tenant_id,configuration_id,spki)

);
CREATE TABLE "###, $access_schema, r###"agent_issuances (
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
 FOREIGN KEY(tenant_id,grant_id) REFERENCES "###, $access_schema, r###"agent_grants(tenant_id,id),
 signing_issuer text CHECK(signing_issuer ~ '^[0-9a-f]{64}$')

);
ALTER TABLE "###, $access_schema, r###"registration_operations ADD COLUMN agent_issuance_recovery uuid;
ALTER TABLE "###, $access_schema, "registration_operations ", $index_38, " FOREIGN KEY(tenant_id,agent_issuance_recovery) REFERENCES ", $access_schema, r###"agent_issuances(tenant_id,id);
ALTER TABLE "###, $access_schema, "registration_operations ", $index_39, r###" CHECK(agent_issuance_recovery IS NULL OR result=to_json(agent_issuance_recovery)::text);
"###, $index_40, " ON ", $access_schema, r###"registration_operations(tenant_id,agent_issuance_recovery,actor,operation_id) WHERE agent_issuance_recovery IS NOT NULL;
"###, $index_41, " ON ", $access_schema, r###"agent_grants(tenant_id,device,id);
"###, $index_42, " ON ", $access_schema, r###"agent_grants(tenant_id,target_registration,id) WHERE target_registration IS NOT NULL;
ALTER TABLE "###, $access_schema, r###"agent_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_issuances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_grants USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY insert_only ON "###, $access_schema, "agent_grants AS RESTRICTIVE FOR INSERT WITH CHECK(current_user <> '", $command_runtime, r###"' OR source='native');
CREATE POLICY tenant ON "###, $access_schema, r###"agent_issuances USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
"###, $index_43, " ON ", $access_schema, r###"agent_grants(tenant_id,actor,instance,expires_at);
CREATE TABLE "###, $access_schema, r###"registrations (
 purpose text NOT NULL CHECK(purpose IN('primary','windows_declared')),
 epoch uuid NOT NULL,
 next_command bigint DEFAULT 1024 NOT NULL CHECK(next_command BETWEEN 1024 AND 4294967296),
 parent_id uuid,
 parent_generation bigint,
 ready boolean NOT NULL DEFAULT false,
 CONSTRAINT linked_shape CHECK((purpose='primary' AND parent_id IS NULL AND parent_generation IS NULL) OR (purpose='windows_declared' AND channel='mdm' AND parent_id IS NOT NULL AND parent_generation IS NOT NULL AND parent_generation>0)),
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 device text NOT NULL,
 channel text NOT NULL,
 generation bigint NOT NULL,
 request_id uuid,
 agent_grant_id uuid,
 CONSTRAINT registration_origin CHECK((channel='mdm' AND request_id IS NOT NULL AND agent_grant_id IS NULL) OR (channel='agent' AND request_id IS NULL AND agent_grant_id IS NOT NULL)),
 state text NOT NULL,
 CONSTRAINT registrations_channel_check CHECK ((channel = ANY (ARRAY['agent'::text, 'mdm'::text]))),
 CONSTRAINT registrations_generation_check CHECK ((generation > 0)),
 CONSTRAINT registrations_state_check CHECK ((state = ANY (ARRAY['active'::text, 'superseded'::text, 'revoked'::text]))),
 first_authenticated_at timestamptz,
 last_communication_received_at timestamptz

);

ALTER TABLE ONLY "###, $access_schema, r###"registrations FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###"report_sources (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
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
 parent_id uuid,
 parent_generation bigint,
 parent_credential uuid,
 state text DEFAULT 'cancelled'::text NOT NULL,
 expected_generation bigint,
 password_digest text,
 password_version bigint DEFAULT 0 NOT NULL,
 credential_ref uuid,
 expires_at timestamp with time zone,
 issuance_operation uuid,
 source text NOT NULL,
 windows_profile text,
 CONSTRAINT requests_windows_profile_check CHECK ((source='mdm.windows' AND windows_profile IS NOT NULL AND windows_profile IN ('Full','Device')) OR (source<>'mdm.windows' AND windows_profile IS NULL)),
 CONSTRAINT requests_expected_generation_check CHECK ((expected_generation >= 0)),
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
 state='cancelled' OR (expected_generation IS NOT NULL AND expires_at IS NOT NULL AND issuance_operation IS NOT NULL AND (
 (authority_kind='password' AND grant_id IS NOT NULL AND parent_id IS NULL AND password_digest IS NOT NULL AND password_version>0 AND credential_ref IS NOT NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='parent_certificate' AND grant_id IS NULL AND source='mdm.windows' AND parent_id IS NOT NULL AND parent_generation IS NOT NULL AND parent_generation>0 AND parent_credential IS NOT NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='apple_account' AND grant_id IS NOT NULL AND source='mdm.apple' AND self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version>0 AND account_reference IS NOT NULL AND account_challenge IS NOT NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='apple_ade' AND grant_id IS NOT NULL AND source='mdm.apple' AND NOT self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version>0 AND organization_challenge IS NOT NULL) OR
 (authority_kind='windows_entra' AND grant_id IS NOT NULL AND source='mdm.windows' AND NOT self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version>0 AND organization_challenge IS NULL) OR
 (authority_kind='agent_policy' AND grant_id IS NOT NULL AND NOT self_service AND parent_id IS NULL AND password_digest IS NOT NULL AND password_version=1 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL)
 )))

);

"###, $index_44, " ON ", $access_schema, r###"requests(tenant_id,issuance_operation) WHERE authority_kind='parent_certificate';

ALTER TABLE ONLY "###, $access_schema, r###"requests FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY "###, $access_schema, r###"asset_authority_history
    "###, $index_45, r###" PRIMARY KEY (tenant_id, kind, identity, revision);

ALTER TABLE ONLY "###, $access_schema, r###"credentials
    "###, $index_46, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"credentials
    "###, $index_47, r###" UNIQUE (tenant_id, channel, locator);

ALTER TABLE ONLY "###, $access_schema, r###"devices
    "###, $index_48, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_49, r###" UNIQUE (tenant_id, issuance_operation);

ALTER TABLE ONLY "###, $access_schema, r###"grants
    "###, $index_50, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"registration_operations
    "###, $index_51, r###" PRIMARY KEY (tenant_id, actor, operation_id);

ALTER TABLE ONLY "###, $access_schema, "registrations ", $index_52, r###" UNIQUE(tenant_id,id,generation);

ALTER TABLE ONLY "###, $access_schema, r###"registrations
    "###, $index_53, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"registrations
    "###, $index_54, r###" UNIQUE (tenant_id, device, channel, purpose, generation);

ALTER TABLE ONLY "###, $access_schema, r###"registrations
    "###, $index_55, r###" UNIQUE (tenant_id, id, channel);

ALTER TABLE ONLY "###, $access_schema, r###"registrations
    "###, $index_56, r###" UNIQUE (tenant_id, request_id);

ALTER TABLE ONLY "###, $access_schema, r###"report_sources
    "###, $index_57, r###" PRIMARY KEY (tenant_id, registration, source);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_58, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_59, r###" UNIQUE (tenant_id, grant_id);

"###, $index_60, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, device, kind, identity, revision);

"###, $index_61, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, registration, kind, identity, revision);

"###, $index_62, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, revision, device);

"###, $index_63, " ON ", $access_schema, r###"asset_authority_history USING btree (tenant_id, device, revision DESC);

"###, $index_64, " ON ", $access_schema, r###"credentials USING btree (tenant_id, registration) WHERE (state = 'active'::text);

"###, $index_65, " ON ", $access_schema, r###"registrations USING btree (tenant_id, device, channel, purpose) WHERE (state = 'active'::text);

"###, $index_66, " ON ", $access_schema, r###"registrations USING btree (tenant_id, device, id);

ALTER TABLE "###, $access_schema, r###"asset_authority_history ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"credentials ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"grants ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"registration_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"registrations ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"report_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###"requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $access_schema, r###"asset_authority_history USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"credentials USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"grants USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"registration_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###"registrations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

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
    registration uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    session_reference jsonb,
    confirmed_at bigint NOT NULL,
    PRIMARY KEY(tenant_id,device)
);
ALTER TABLE "###, $access_schema, r###"current_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"current_users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"current_users USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "current_users TO ", $access_role, r###";
GRANT UPDATE(revision,registration,generation,session_reference,confirmed_at) ON "###, $access_schema, "current_users TO ", $access_role, r###";
COMMIT;
"###),
                relations: concat!(r###"-- Fresh installation: registration-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "credentials FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "devices FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "registrations FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON "###, $access_schema, "report_sources FOR EACH ROW EXECUTE FUNCTION ", $access_schema, r###"capture_asset_authority();

ALTER TABLE ONLY "###, $access_schema, r###"asset_authority_history
    "###, $index_67, r###" FOREIGN KEY (tenant_id, revision) REFERENCES mdm.asset_changes(tenant_id, revision);

ALTER TABLE ONLY "###, $access_schema, r###"credentials
    "###, $index_68, " FOREIGN KEY (tenant_id, registration, channel) REFERENCES ", $access_schema, r###"registrations(tenant_id, id, channel);

ALTER TABLE ONLY "###, $access_schema, r###"registrations
    "###, $index_69, " FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, r###"devices(tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"registrations
    "###, $index_70, " FOREIGN KEY (tenant_id, request_id) REFERENCES ", $access_schema, r###"requests(tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"report_sources
    "###, $index_71, " FOREIGN KEY (tenant_id, registration) REFERENCES ", $access_schema, r###"registrations(tenant_id, id);

ALTER TABLE ONLY "###, $access_schema, r###"requests
    "###, $index_72, " FOREIGN KEY (tenant_id, grant_id) REFERENCES ", $access_schema, r###"grants(tenant_id, id);

GRANT USAGE ON "###, $access_schema_decl, " TO ", $access_role, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $software_driver, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT USAGE ON "###, $access_schema_decl, " TO ", $command_runtime, r###";

REVOKE ALL ON FUNCTION "###, $access_schema, r###"capture_asset_authority() FROM PUBLIC;

GRANT SELECT ON TABLE "###, $access_schema, "asset_authority_history TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ",", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "credentials TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "credentials TO ", $command_runtime, r###";

GRANT SELECT(tenant_id,id) ON TABLE "###, $access_schema, "credentials TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";

GRANT SELECT(registration) ON TABLE "###, $access_schema, "credentials TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";

GRANT UPDATE(state) ON TABLE "###, $access_schema, "credentials TO ", $access_role, r###";
GRANT SELECT(state) ON TABLE "###, $access_schema, "credentials TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "devices TO ", $access_role, r###";
GRANT UPDATE(retirement) ON "###, $access_schema, "devices TO ", $access_role, ",", $policy_runtime, ",", $command_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "devices TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "devices TO ", $command_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "grants TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "registration_operations TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "registrations TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "registrations TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "registrations TO ", $command_runtime, r###";

GRANT UPDATE(ready) ON TABLE "###, $access_schema, "registrations TO ", $access_role, r###";
GRANT UPDATE(ready) ON TABLE "###, $access_schema, "registrations TO ", $command_runtime, r###";
GRANT UPDATE(state) ON TABLE "###, $access_schema, "registrations TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "report_sources TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "report_sources TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, "report_sources TO ", $command_runtime, r###";

GRANT UPDATE(enabled) ON TABLE "###, $access_schema, "report_sources TO ", $access_role, r###";

GRANT UPDATE(next_command) ON TABLE "###, $access_schema, "registrations TO ", $access_role, r###";
GRANT UPDATE(next_command) ON TABLE "###, $access_schema, "registrations TO ", $command_runtime, r###";

GRANT UPDATE(next_sequence) ON TABLE "###, $access_schema, "report_sources TO ", $access_role, r###";
GRANT UPDATE(next_sequence) ON TABLE "###, $access_schema, "report_sources TO ", $command_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, "requests TO ", $command_runtime, r###";
-- Policy native acceptance reads source/profile evidence, never enrollment secrets.
GRANT SELECT(tenant_id,id,source,windows_profile) ON "###, $access_schema, "requests TO ", $policy_runtime, r###";

GRANT UPDATE(state) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(password_digest) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(password_version) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(credential_ref) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";

GRANT UPDATE(expires_at) ON TABLE "###, $access_schema, "requests TO ", $access_role, r###";
ALTER TABLE "###, $access_schema, "registrations ", $index_73, " FOREIGN KEY(tenant_id,parent_id,parent_generation) REFERENCES ", $access_schema, r###"registrations(tenant_id,id,generation);
ALTER TABLE "###, $access_schema, "requests ", $index_74, " FOREIGN KEY(tenant_id,parent_id,parent_generation) REFERENCES ", $access_schema, r###"registrations(tenant_id,id,generation);
ALTER TABLE "###, $access_schema, "requests ", $index_75, " FOREIGN KEY(tenant_id,parent_credential) REFERENCES ", $access_schema, r###"credentials(tenant_id,id);
ALTER TABLE "###, $access_schema, "registrations ", $index_76, " FOREIGN KEY(tenant_id,agent_grant_id) REFERENCES ", $access_schema, r###"agent_grants(tenant_id,id);
ALTER TABLE "###, $access_schema, "agent_grants ", $index_77, " FOREIGN KEY(tenant_id,target_registration) REFERENCES ", $access_schema, r###"registrations(tenant_id,id);
ALTER TABLE "###, $access_schema, "agent_grants ", $index_78, " FOREIGN KEY(tenant_id,predecessor) REFERENCES ", $access_schema, r###"credentials(tenant_id,id);
ALTER TABLE "###, $access_schema, "agent_issuances ", $index_79, " FOREIGN KEY(tenant_id,credential) REFERENCES ", $access_schema, r###"credentials(tenant_id,id);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_grants,", $access_schema, "agent_issuances TO ", $access_role, r###";
GRANT UPDATE(actor,instance,state,device) ON "###, $access_schema, "agent_grants TO ", $access_role, r###";
GRANT UPDATE(state,certificate_chain,metadata,fingerprint,activation_operation,activation_digest,activation_result,credential) ON "###, $access_schema, "agent_issuances TO ", $access_role, r###";
GRANT SELECT,INSERT ON "###, $access_schema, "agent_grants TO ", $command_runtime, r###";
GRANT SELECT(tenant_id,credential,not_after) ON "###, $access_schema, "agent_issuances TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT UPDATE(last_communication_received_at) ON "###, $access_schema, "registrations TO ", $access_role, ", ", $command_runtime, r###";
GRANT UPDATE(first_authenticated_at) ON "###, $access_schema, "registrations TO ", $access_role, ", ", $command_runtime, r###";
GRANT UPDATE(account_version,account_reference,account_challenge) ON "###, $access_schema, "requests TO ", $access_role, r###";
GRANT UPDATE(organization_version,organization_challenge) ON "###, $access_schema, "requests TO ", $access_role, r###";
-- Device invokes Registration retirement on the shared audited command transaction.
GRANT UPDATE(state) ON "###, $access_schema, "registrations,", $access_schema, "credentials TO ", $command_runtime, r###";
GRANT UPDATE(enabled) ON "###, $access_schema, "report_sources TO ", $command_runtime, r###";
COMMIT;
"###),
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
GRANT SELECT ON "###, $access_schema, "agent_grants TO ", $policy_runtime, r###";
COMMIT;
"###),
                agent_configurations: concat!(r###"-- Registration settings and reusable configuration authority. Existing identities are unchanged.
BEGIN;
CREATE TABLE "###, $access_schema, r###"agent_enrollment_settings (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096)
);
CREATE TABLE "###, $access_schema, r###"agent_configurations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, operation_id uuid NOT NULL,
 creator text NOT NULL, instance text NOT NULL,
 secret_digest text NOT NULL CHECK(secret_digest ~ '^[0-9a-f]{64}$'),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9_-]{86}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 quantity bigint CHECK(quantity BETWEEN 1 AND 4294967295),
 state text NOT NULL CHECK(state IN('available','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '365 days'),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation_id)
);

ALTER TABLE "###, $access_schema, "agent_grants ADD FOREIGN KEY(tenant_id,configuration_id) REFERENCES ", $access_schema, r###"agent_configurations(tenant_id,id);

"###, $index_81, " ON ", $access_schema, r###"agent_grants(tenant_id,configuration_id);
ALTER TABLE "###, $access_schema, r###"agent_enrollment_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_enrollment_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_enrollment_settings USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON "###, $access_schema, r###"agent_configurations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_enrollment_settings TO ", $access_role, r###";
GRANT SELECT ON "###, $access_schema, "agent_enrollment_settings TO ", $command_runtime, r###";
GRANT UPDATE(revision,document) ON "###, $access_schema, "agent_enrollment_settings TO ", $access_role, r###";
GRANT SELECT,INSERT ON "###, $access_schema, "agent_configurations TO ", $access_role, r###";
GRANT UPDATE(state) ON "###, $access_schema, "agent_configurations TO ", $access_role, r###";
-- Configuration signing has an independent lifetime from task-signing keys.
CREATE TABLE "###, $access_schema, r###"agent_configuration_keys (
 tenant_id uuid PRIMARY KEY, key_id text NOT NULL UNIQUE,
 public_key text NOT NULL CHECK(public_key ~ '^[A-Za-z0-9_-]{43}$'),
 private_key bytea NOT NULL CHECK(octet_length(private_key) BETWEEN 1 AND 4096)
);
CREATE TABLE "###, $access_schema, r###"agent_connection_drafts (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 PRIMARY KEY(tenant_id,revision)
);
CREATE TABLE "###, $access_schema, r###"agent_connection_versions (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 PRIMARY KEY(tenant_id,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES "###, $access_schema, r###"agent_connection_drafts(tenant_id,revision)
);
CREATE TABLE "###, $access_schema, r###"agent_connection_deployments (
 tenant_id uuid NOT NULL, origin text NOT NULL CHECK(octet_length(origin) BETWEEN 1 AND 2048),
 service_id uuid NOT NULL, host_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), configuration_revision bigint NOT NULL CHECK(configuration_revision>=0), observed_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,origin)
);
CREATE TABLE "###, $access_schema, r###"agent_connection_observations (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 operation_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096), received_at bigint NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,registration,generation,operation_id),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES "###, $access_schema, r###"registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,revision) REFERENCES "###, $access_schema, r###"agent_connection_versions(tenant_id,revision)
);
"###, $index_82, " ON ", $access_schema, r###"agent_connection_observations(tenant_id,registration,generation,revision DESC,recorded_at DESC);
ALTER TABLE "###, $access_schema, r###"agent_configuration_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_configuration_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_configuration_keys USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_configuration_keys TO ", $access_role, r###";
GRANT SELECT(tenant_id,public_key) ON "###, $access_schema, "agent_configuration_keys TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
ALTER TABLE "###, $access_schema, r###"agent_connection_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_connection_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_connection_drafts USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_connection_drafts TO ", $access_role, r###";
ALTER TABLE "###, $access_schema, r###"agent_connection_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_connection_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_connection_versions USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_connection_versions TO ", $access_role, r###";
GRANT SELECT ON "###, $access_schema, "agent_connection_versions TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
ALTER TABLE "###, $access_schema, r###"agent_connection_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_connection_deployments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_connection_deployments USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON "###, $access_schema, "agent_connection_deployments TO ", $access_role, r###";
ALTER TABLE "###, $access_schema, r###"agent_connection_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_connection_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_connection_observations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_connection_observations TO ", $access_role, r###";
CREATE TABLE "###, $access_schema, r###"agent_connection_failures (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 operation_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),
 origin text NOT NULL CHECK(octet_length(origin) BETWEEN 1 AND 2048),
 received_at bigint NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,registration,generation,operation_id),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES "###, $access_schema, r###"registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,revision) REFERENCES "###, $access_schema, r###"agent_connection_versions(tenant_id,revision)
);
"###, $index_83, " ON ", $access_schema, r###"agent_connection_failures(tenant_id,registration,generation,recorded_at DESC);
ALTER TABLE "###, $access_schema, r###"agent_connection_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"agent_connection_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"agent_connection_failures USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $access_schema, "agent_connection_failures TO ", $access_role, r###";
COMMIT;
"###),
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
                directory: concat!(r###"-- Fixed registration directory relation; caller authorization precedes paging.
BEGIN;
-- Raw narrow source rows, before deduplication or value decoding. UNION ALL
-- allows the caller's overflow probe to stop at its explicit source-row budget.
CREATE VIEW "###, $access_schema, r###"directory_inputs WITH (security_barrier=true) AS
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"devices WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,CASE WHEN state='pending' THEN expires_at END AS expires_at FROM "###, $access_schema, r###"requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"grants WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"registrations WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"credentials WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"agent_grants WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"registration_users WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM "###, $access_schema, r###"report_sources WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON "###, $access_schema, r###"directory_inputs FROM PUBLIC;
GRANT SELECT ON "###, $access_schema, "directory_inputs TO ", $access_role, ",", $identity_runtime, r###";
CREATE VIEW "###, $access_schema, r###"directory_metadata WITH (security_barrier=true) AS

WITH targets AS (
 SELECT id FROM "###, $access_schema, r###"devices WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 UNION SELECT g.device FROM "###, $access_schema, "requests q JOIN ", $access_schema, r###"grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
 WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND q.issuance_operation IS NOT NULL
), visible AS (
 SELECT id FROM targets
), heads AS (
 SELECT d.id,
 CASE WHEN EXISTS(SELECT 1 FROM "###, $access_schema, "registrations r JOIN ", $access_schema, r###"credentials c ON(c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.state='active' AND c.state='active') THEN 'active'
 WHEN EXISTS(SELECT 1 FROM "###, $access_schema, "requests q JOIN ", $access_schema, "grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.device=d.id AND q.state='pending' AND q.expires_at>statement_timestamp() AND NOT EXISTS(SELECT 1 FROM ", $access_schema, r###"registrations r WHERE (r.tenant_id,r.request_id)=(q.tenant_id,q.id))) THEN 'pending'
 WHEN EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.state='revoked') THEN 'revoked'
 WHEN EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.state='superseded') THEN 'superseded'
 WHEN EXISTS(SELECT 1 FROM "###, $access_schema, r###"devices r WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.id=d.id) THEN 'registered'
 WHEN EXISTS(SELECT 1 FROM "###, $access_schema, "requests q JOIN ", $access_schema, r###"grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.device=d.id AND q.state='cancelled') THEN 'cancelled'
 ELSE 'expired' END AS status
 FROM visible d
)
SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant_id,id,status FROM heads;
REVOKE ALL ON "###, $access_schema, r###"directory_metadata FROM PUBLIC;
GRANT SELECT ON "###, $access_schema, "directory_metadata TO ", $access_role, ",", $identity_runtime, r###";
CREATE VIEW "###, $access_schema, r###"directory_channels WITH (security_barrier=true) AS
SELECT DISTINCT ON(r.tenant_id,r.device,r.channel) r.tenant_id,r.device,r.channel,r.id,r.generation,r.state,r.last_communication_received_at,q.windows_profile,coalesce(q.source,'agent.builtin') AS source,
 CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' ELSE g.platform END AS platform
FROM "###, $access_schema, "registrations r LEFT JOIN ", $access_schema, r###"requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id)
LEFT JOIN "###, $access_schema, r###"agent_grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.agent_grant_id)
WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.purpose='primary'
ORDER BY r.tenant_id,r.device,r.channel,r.generation DESC;
CREATE VIEW "###, $access_schema, r###"directory_enrollments WITH (security_barrier=true) AS
SELECT DISTINCT ON(q.tenant_id,g.device,q.source) q.tenant_id,g.device,q.source,q.id,q.state,q.expires_at,
 CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' END AS platform
FROM "###, $access_schema, "requests q JOIN ", $access_schema, r###"grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND q.issuance_operation IS NOT NULL
ORDER BY q.tenant_id,g.device,q.source,q.expires_at DESC,q.id DESC;
REVOKE ALL ON "###, $access_schema, "directory_channels,", $access_schema, r###"directory_enrollments FROM PUBLIC;
GRANT SELECT ON "###, $access_schema, "directory_channels,", $access_schema, "directory_enrollments TO ", $access_role, ",", $identity_runtime, r###";
CREATE VIEW "###, $access_schema, r###"directory_endpoints WITH (security_barrier=true) AS
SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant_id,d.id,d.status,jsonb_build_object('id',d.id,'status',d.status,
 'primaryMdmRegistration',(SELECT jsonb_build_object('registrationId',r.id,'generation',r.generation,'source',q.source) FROM "###, $access_schema, "registrations r JOIN ", $access_schema, r###"requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.channel='mdm' AND r.purpose='primary' AND r.state='active'),
 'channels',coalesce((SELECT jsonb_agg(jsonb_build_object('registrationId',r.id,'channel',r.channel,'generation',r.generation,'status',r.state,'source',r.source,'platform',r.platform,'lastCommunicationReceivedAt',floor(extract(epoch FROM r.last_communication_received_at))::bigint,
 'children',coalesce((SELECT jsonb_agg(jsonb_build_object('registrationId',child.id,'purpose',child.purpose,'generation',child.generation,'status',child.state,'ready',child.ready,'parentRegistrationId',child.parent_id,'parentGeneration',child.parent_generation) ORDER BY child.purpose) FROM
 (SELECT DISTINCT ON(c.purpose) c.id,c.purpose,c.generation,c.state,c.ready,c.parent_id,c.parent_generation FROM "###, $access_schema, r###"registrations c WHERE c.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND c.device=d.id AND c.parent_id=r.id AND c.parent_generation=r.generation ORDER BY c.purpose,c.generation DESC) child),'[]'::jsonb),
 'userContext',CASE WHEN r.windows_profile='Full' THEN jsonb_build_object('id',r.id,'parentRegistrationId',r.id,'parentGeneration',r.generation,'registrationStatus',r.state) END) ORDER BY r.channel) FROM
 "###, $access_schema, r###"directory_channels r WHERE r.tenant_id=d.tenant_id AND r.device=d.id),'[]'::jsonb),
 'enrollments',coalesce((SELECT jsonb_agg(jsonb_build_object('enrollmentId',q.id,'source',q.source,'platform',CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' END,'status',CASE WHEN q.state='pending' AND q.expires_at<=statement_timestamp() THEN 'expired' ELSE q.state END,'expiresAt',floor(extract(epoch FROM q.expires_at))::bigint) ORDER BY q.source) FROM
 "###, $access_schema, "directory_enrollments q WHERE q.tenant_id=d.tenant_id AND q.device=d.id),'[]'::jsonb)) AS summary FROM ", $access_schema, r###"directory_metadata d;
REVOKE ALL ON "###, $access_schema, r###"directory_endpoints FROM PUBLIC;
GRANT SELECT ON "###, $access_schema, "directory_endpoints TO ", $access_role, ",", $identity_runtime, ",", $command_runtime, r###";

CREATE VIEW "###, $access_schema, r###"directory_users WITH (security_barrier=true) AS
SELECT coalesce(r.tenant_id,u.tenant_id) AS tenant_id,coalesce(r.device,u.device) AS device,
 CASE WHEN r.instance IS NOT NULL AND r.principal IS NOT NULL THEN
  jsonb_build_object('tenantId',r.tenant_id,'instanceId',r.instance,'principalId',r.principal) END AS registration_user,
 coalesce(r.revision,0) AS registration_revision,u.session_reference,
 coalesce(u.revision,0) AS current_revision,u.confirmed_at,
 qualified.valid_until IS NOT NULL AS registration_valid,qualified.valid_until
FROM "###, $access_schema, "registration_users r FULL JOIN ", $access_schema, r###"current_users u USING(tenant_id,device)
LEFT JOIN LATERAL (
 SELECT min(least(i.not_after,p.valid_until)) AS valid_until
 FROM "###, $access_schema, "registrations g JOIN ", $access_schema, r###"credentials k ON(k.tenant_id,k.registration)=(g.tenant_id,g.id)
 JOIN "###, $access_schema, r###"agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id)
 JOIN "###, $pki_certificates, r###" p ON p.tenant_id=k.tenant_id AND p.purpose='agent' AND p.fingerprint=decode(k.locator,'hex')
 WHERE g.tenant_id=u.tenant_id AND g.id=u.registration AND g.device=u.device AND g.generation=u.generation
  AND g.channel='agent' AND g.purpose='primary' AND g.state='active' AND k.state='active'
  AND i.not_before<=extract(epoch FROM statement_timestamp()) AND i.not_after>extract(epoch FROM statement_timestamp())
) qualified ON true
WHERE coalesce(r.tenant_id,u.tenant_id)=NULLIF(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON "###, $access_schema, r###"directory_users FROM PUBLIC;
GRANT SELECT ON "###, $access_schema, "directory_users TO ", $access_role, ",", $identity_runtime, r###";
"###, $index_84, " ON ", $access_schema, r###"registrations(tenant_id,device,channel,purpose,generation DESC);
"###, $index_85, " ON ", $access_schema, r###"grants(tenant_id,device,id);
"###, $index_86, " ON ", $access_schema, r###"requests(tenant_id,expires_at) WHERE state='pending';


COMMIT;

-- Same source qualification for composed and standalone Inventory snapshots.
CREATE FUNCTION "###, $access_schema, r###"asset_sources_at(p_devices text[], p_cut jsonb)
RETURNS TABLE(device text, registration text, generation text, channel text, source text, epoch text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$

              WITH latest AS (
                SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
                FROM "###, $access_schema, r###"asset_authority_history
                WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND device=ANY(p_devices) AND (p_cut IS NULL OR mdm.asset_visible(p_cut,revision))
                  AND kind IN('registration','credential','source') AND cardinality(p_devices)<=1000 AND (p_cut IS NULL OR (p_cut->>'tenant')::uuid=nullif(current_setting('rss.tenant_id',true),'')::uuid)
                ORDER BY kind,identity,revision DESC
              ) SELECT r.device,r.identity AS registration,r.document->>'generation' AS generation,
                  r.document->>'channel' AS channel,s.document->>'source' AS source,s.document->>'epoch' AS epoch
                FROM latest r JOIN latest s ON s.registration=r.registration AND s.kind='source'
                JOIN latest c ON c.registration=r.registration AND c.kind='credential'
                WHERE r.kind='registration' AND r.document->>'state'='active'
                  AND c.document->>'state'='active' AND s.document->>'enabled'='true'
                ORDER BY r.device,s.identity LIMIT 2001

$$;
REVOKE ALL ON FUNCTION "###, $access_schema, r###"asset_sources_at(text[],jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "###, $access_schema, "asset_sources_at(text[],jsonb) TO ", $access_role, ",", $identity_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ",", $command_runtime, r###";
"###),
                enrollment_tasks: concat!(r###"-- Fresh installation: Script owns its complete execution state.
BEGIN;

"###, $create_mdm_registration_tasks, r###";

CREATE TABLE "###, $mdm_registration_tasks_runs, r###" (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_version uuid NOT NULL,
    origin jsonb NOT NULL CHECK(origin IN ('"system"','"policy"','"human"','"ai"')),
    source_objects jsonb NOT NULL,
    device text NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    occurrence text NOT NULL CHECK(octet_length(occurrence) BETWEEN 1 AND 256),
    created_at bigint NOT NULL CHECK(created_at>=0),
    available_at bigint NOT NULL CHECK(available_at>=0),
    deadline bigint NOT NULL CHECK(deadline>available_at),
    state jsonb NOT NULL CHECK(octet_length(state::text)<=4096),
    gateway_accepted boolean NOT NULL DEFAULT false,
    dispatch_fingerprint bytea NOT NULL CHECK(octet_length(dispatch_fingerprint)=32),
    dispatch_failure jsonb CHECK(dispatch_failure IS NULL OR octet_length(dispatch_failure::text)<=8192),
    result jsonb CHECK(result IS NULL OR octet_length(result::text)<=1114112),
    invocation jsonb CHECK(invocation IS NULL OR (jsonb_typeof(invocation)='object' AND octet_length(invocation::text)<=131072)),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,policy_version,device,occurrence)
);

ALTER TABLE "###, $mdm_registration_tasks_runs, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $mdm_registration_tasks_runs, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $mdm_registration_tasks_runs, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE "###, $mdm_registration_tasks_receipts, r###" (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
    response jsonb NOT NULL CHECK(octet_length(response::text)<=6291456),
    PRIMARY KEY(tenant_id,actor,id)
);

ALTER TABLE "###, $mdm_registration_tasks_receipts, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $mdm_registration_tasks_receipts, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $mdm_registration_tasks_receipts, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE "###, $mdm_registration_tasks_agent_admission, r###" (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    policy_after uuid,
    PRIMARY KEY(tenant_id,registration)
);

ALTER TABLE "###, $mdm_registration_tasks_agent_admission, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $mdm_registration_tasks_agent_admission, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $mdm_registration_tasks_agent_admission, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE "###, $mdm_registration_tasks_policy_recovery, r###" (
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    input_revision bigint NOT NULL DEFAULT 1,
    input_consumed bigint NOT NULL DEFAULT 0,
    input_window bigint NOT NULL DEFAULT 0,
    recovery_after uuid,
    runs_done boolean NOT NULL DEFAULT false,
    PRIMARY KEY(tenant_id,policy),
    CHECK(input_revision>=input_consumed AND input_consumed>=0)
);

ALTER TABLE "###, $mdm_registration_tasks_policy_recovery, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $mdm_registration_tasks_policy_recovery, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $mdm_registration_tasks_policy_recovery, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

"###, $index_87, " ON ", $mdm_registration_tasks_runs, r###"(tenant_id,registration,available_at,id)
 WHERE state->>'execution'='not_started' AND state->>'cancellation'='none';

"###, $index_88, " ON ", $mdm_registration_tasks_runs, r###"(tenant_id,policy_version,available_at,id);

COMMIT;"###),
                quota_usage: concat!(r###"-- One read snapshot of active registrations and live reservations. Renewal/recovery
-- retain the original registration; organization authority is exempt from personal quotas.
WITH agent AS (
 SELECT g.device,g.id,g.expires_at,
 EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id AND r.state='active') AS active,
 g.state IN('available','consumed') AND g.expires_at>clock_timestamp() AND
 NOT EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id) AS reserved
 FROM "###, $access_schema, r###"agent_grants g
 WHERE g.tenant_id=$1::uuid AND g.instance=$2 AND g.actor=$3 AND g.source IN('download','browser')
), native AS (
 SELECT g.device,q.id,q.source,q.expires_at,
 EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.state='active' AND r.purpose='primary') AS active,
 q.state='pending' AND q.expires_at>clock_timestamp() AND
 NOT EXISTS(SELECT 1 FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.purpose='primary') AS reserved
 FROM "###, $access_schema, "requests q JOIN ", $access_schema, r###"grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
 WHERE q.tenant_id=$1::uuid AND g.instance=$2 AND g.actor=$3 AND q.self_service
), usage AS (
 SELECT 'agent' AS channel,device,id,expires_at,active,reserved FROM agent
 UNION ALL
 SELECT CASE source WHEN 'mdm.windows' THEN 'windows_mdm' ELSE 'macos_mdm' END,device,id,expires_at,active,reserved FROM native
)
SELECT channel,count(*) FILTER(WHERE active)::bigint AS active,count(*) FILTER(WHERE reserved)::bigint AS reserved FROM usage GROUP BY channel
"###),
                enrollment_retirement: concat!(r###"-- Registration retirement participates on the initiating audit connection.
BEGIN;
SET LOCAL check_function_bodies = false;
CREATE FUNCTION "###, $mdm_registration_tasks_save_retired_run, r###"(p_registration uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE "###, $mdm_registration_tasks_runs, r###" a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.registration=p_registration AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT 1 FROM "###, $access_schema, "registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM ", $access_schema, "devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND ", $native_retirement_clear, r###")))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION "###, $mdm_registration_tasks_save_retired_run, r###"(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "###, $mdm_registration_tasks_save_retired_run, "(uuid,uuid,jsonb,jsonb) TO ", $access_role, ",", $command_runtime, r###";
COMMIT;
"###),
                task_relations: concat!(r###"BEGIN;
SET LOCAL check_function_bodies=false;


ALTER TABLE "###, $mdm_registration_tasks_runs, " ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES ", $mdm_policy_versions, r###"(tenant_id,id);


ALTER TABLE "###, $mdm_registration_tasks_runs, " ADD FOREIGN KEY(tenant_id,device) REFERENCES ", $access_schema, r###"devices(tenant_id,id);


ALTER TABLE "###, $mdm_registration_tasks_runs, " ADD FOREIGN KEY(tenant_id,registration) REFERENCES ", $access_schema, r###"registrations(tenant_id,id);


ALTER TABLE "###, $mdm_registration_tasks_agent_admission, " ADD FOREIGN KEY(tenant_id,registration) REFERENCES ", $access_schema, r###"registrations(tenant_id,id);


ALTER TABLE "###, $mdm_registration_tasks_policy_recovery, " ADD FOREIGN KEY(tenant_id,policy) REFERENCES ", $mdm_policy_policies, r###"(tenant_id,id);


GRANT USAGE ON "###, $mdm_registration_tasks_schema, " TO ", $command_runtime, ",", $policy_runtime, ",", $access_role, r###";


GRANT SELECT,INSERT ON "###, $mdm_registration_tasks_runs, " TO ", $command_runtime, ",", $policy_runtime, r###";


GRANT UPDATE(state,result,invocation,source_objects) ON "###, $mdm_registration_tasks_runs, " TO ", $command_runtime, ",", $policy_runtime, r###";


GRANT UPDATE(gateway_accepted,dispatch_failure) ON "###, $mdm_registration_tasks_runs, " TO ", $command_runtime, r###";


GRANT SELECT ON "###, $mdm_registration_tasks_runs, " TO ", $access_role, r###";


GRANT UPDATE(policy_after) ON "###, $mdm_registration_tasks_agent_admission, " TO ", $command_runtime, r###";


GRANT SELECT,INSERT ON "###, $mdm_registration_tasks_policy_recovery, " TO ", $command_runtime, ",", $policy_runtime, r###";


GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON "###, $mdm_registration_tasks_policy_recovery, " TO ", $command_runtime, r###";


GRANT UPDATE(input_revision) ON "###, $mdm_registration_tasks_policy_recovery, " TO ", $policy_runtime, r###";

GRANT SELECT,INSERT ON "###, $mdm_registration_tasks_receipts, ",", $mdm_registration_tasks_agent_admission, " TO ", $command_runtime, r###";

GRANT SELECT,INSERT ON "###, $mdm_registration_tasks_receipts, " TO ", $policy_runtime, r###";

GRANT SELECT ON "###, $mdm_registration_tasks_agent_admission, " TO ", $policy_runtime, r###";
COMMIT;"###),
                member_authority: concat!(r###"BEGIN;
CREATE FUNCTION "###, $access_schema, r###"channel_members_current(p_input jsonb,p_channel text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; selected jsonb;
BEGIN
 IF p_channel NOT IN('agent','mdm') OR p_input->>'verified' IS DISTINCT FROM 'true' THEN RETURN NULL; END IF;
 IF jsonb_typeof(p_input->'members') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'invalid channel members' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT FROM jsonb_array_elements(p_input->'members') m WHERE NOT EXISTS(
  SELECT FROM "###, $access_schema, r###"registrations r WHERE r.tenant_id=tenant AND r.device=m->>'device'
   AND r.channel=m->>'channel' AND r.id::text=m->>'registrationId' AND r.generation=(m->>'generation')::bigint
   AND r.purpose='primary' AND r.state='active' AND EXISTS(
    SELECT FROM "###, $access_schema, r###"credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')
 )) THEN RETURN NULL; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(p_input->'members') m WHERE m->>'channel'=p_channel)>1 THEN
  RAISE EXCEPTION 'ambiguous execution channel' USING ERRCODE='23514';
 END IF;
 SELECT m INTO selected FROM jsonb_array_elements(p_input->'members') m WHERE m->>'channel'=p_channel;
 RETURN selected;
END $$;
REVOKE ALL ON FUNCTION "###, $access_schema, r###"channel_members_current(jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "###, $access_schema, "channel_members_current(jsonb,text) TO ", $access_role, ",", $command_runtime, ",", $policy_runtime, ",", $scope_runtime, ",", $inventory_runtime, ",", $telemetry_runtime, r###";
COMMIT;
"###),
                object_manifest: concat!(r###"{"tables":[""###, $access_schema, r###"agent_bootstraps",""###, $access_schema, r###"agent_configuration_keys",""###, $access_schema, r###"agent_configurations",""###, $access_schema, r###"agent_connection_deployments",""###, $access_schema, r###"agent_connection_drafts",""###, $access_schema, r###"agent_connection_failures",""###, $access_schema, r###"agent_connection_observations",""###, $access_schema, r###"agent_connection_versions",""###, $access_schema, r###"agent_enrollment_settings",""###, $access_schema, r###"agent_grants",""###, $access_schema, r###"agent_issuances",""###, $access_schema, r###"asset_authority_history",""###, $access_schema, r###"credentials",""###, $access_schema, r###"current_users",""###, $access_schema, r###"devices",""###, $access_schema, r###"grants",""###, $access_schema, r###"registration_admission",""###, $access_schema, r###"registration_operations",""###, $access_schema, r###"registration_quota_settings",""###, $access_schema, r###"registration_users",""###, $access_schema, r###"registrations",""###, $access_schema, r###"report_sources",""###, $access_schema, r###"requests",""###, $mdm_registration_tasks_agent_admission, r###"",""###, $mdm_registration_tasks_policy_recovery, r###"",""###, $mdm_registration_tasks_receipts, r###"",""###, $mdm_registration_tasks_runs, r###""],"functions":[""###, $access_schema, r###"asset_sources_at",""###, $access_schema, r###"capture_asset_authority",""###, $access_schema, r###"channel_members_current",""###, $access_schema, r###"seed_tenant_settings",""###, $mdm_registration_tasks_save_retired_run, r###""],"views":[""###, $access_schema, r###"directory_channels",""###, $access_schema, r###"directory_endpoints",""###, $access_schema, r###"directory_enrollments",""###, $access_schema, r###"directory_inputs",""###, $access_schema, r###"directory_metadata",""###, $access_schema, r###"directory_users"]}"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_table_89, r###","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_90, r###","read_write":true,"updates":["state"],"delete_policy":null},{"###, $contract_table_91, r###","read_write":true,"updates":["retirement"],"delete_policy":null},{"###, $contract_table_92, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_93, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_94, r###","read_write":true,"updates":["state","next_command","ready","first_authenticated_at","last_communication_received_at"],"delete_policy":null},{"###, $contract_table_95, r###","read_write":true,"updates":["enabled","next_sequence"],"delete_policy":null},{"###, $contract_table_96, r###","read_write":true,"updates":["state","password_digest","password_version","credential_ref","expires_at","account_version","account_reference","account_challenge","organization_version","organization_challenge"],"delete_policy":null},{"###, $contract_table_97, r###","read_write":true,"updates":["actor","instance","state","device"],"delete_policy":null,"insert_policy":"current_user<>'"###, $command_runtime, r###"'::nameorsource='native'::text"},{"###, $contract_table_98, r###","read_write":true,"updates":["state","certificate_chain","metadata","fingerprint","activation_operation","activation_digest","activation_result","credential"],"delete_policy":null},{"###, $contract_table_99, r###","read_write":true,"updates":["revision","agent","windows_mdm","macos_mdm"],"delete_policy":null},{"###, $contract_table_100, r###","read_write":true,"updates":["revision","instance","principal"],"delete_policy":null},{"###, $contract_table_101, r###","read_write":true,"updates":["revision","document"],"delete_policy":null},{"###, $contract_table_102, r###","read_write":true,"updates":["state"],"delete_policy":null},{"###, $contract_table_103, r###","read_write":true,"updates":["revision","paused"],"delete_policy":null},{"###, $contract_table_104, r###","read_write":false,"read_only":true,"updates":["state","transaction_id","csr_digest","spki","fingerprint","certificate","deadline"],"delete_policy":null},{"###, $contract_table_105, r###","read_write":true,"updates":["revision","registration","generation","session_reference","confirmed_at"],"delete_policy":null},{"###, $contract_table_106, r###","read_write":true,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_107, r###","read_write":true,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_108, r###","read_write":true,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_109, r###","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_110, r###","read_write":true,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_111, r###","read_write":true,"read_only":true,"updates":[],"delete_policy":null}"###, $access_contract_tables, r###"],"functions":[{"name":""###, $access_schema, r###"channel_members_current","search_path":"search_path=pg_catalog"},{"name":""###, $access_schema, r###"asset_sources_at","search_path":"search_path=pg_catalog"}"###, $access_contract_functions, r###"],"external_relations":["###, $access_contract_external_relations, r###"],"verified_schemas":[]}"###),
                enrollment_access_contract: concat!(r###"{"tables":[{"###, $contract_table_115, r###","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"###, $contract_table_116, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_117, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_118, r###","read_write":false,"updates":[],"delete_policy":null}"###, $enrollment_access_contract_tables, r###"],"functions":[{"name":""###, $mdm_registration_tasks_save_retired_run, r###"","search_path":"search_path=pg_catalog"}"###, $enrollment_access_contract_functions, r###"],"external_relations":[],"verified_schemas":[]}"###),
                current_members: concat!("SELECT ", $access_schema, "channel_members_current($1,$2)"),
                agent_default_values: concat!($default_agent_values),
                agent_issuance_save_certificate_4: concat!("SELECT binding FROM ", $pki_signing, " WHERE tenant_id=$1::uuid AND attempt=$2"),
                common_authority_admission: concat!(r###"WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
('"###, $access_schema, "capture_asset_authority()','plpgsql','trigger',true,false,'v',ARRAY[]::text[],ARRAY['", $trigger_path, "']::text[],$1::text,ARRAY['", $owner, r###"']::text[]),
('"###, $access_schema, "asset_sources_at(text[],jsonb)','sql','record',true,true,'s',ARRAY['p_devices','p_cut','device','registration','generation','channel','source','epoch']::text[],ARRAY['search_path=pg_catalog']::text[],$2::text,ARRAY['", $access_role, "','", $identity_runtime, "','", $inventory_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $telemetry_runtime, "','", $command_runtime, "','", $owner, r###"']::text[]),
('"###, $access_schema, "channel_members_current(jsonb,text)','plpgsql','jsonb',true,false,'s',ARRAY['p_input','p_channel']::text[],ARRAY['search_path=pg_catalog']::text[],$3::text,ARRAY['", $access_role, "','", $command_runtime, "','", $policy_runtime, "','", $scope_runtime, "','", $inventory_runtime, "','", $telemetry_runtime, "','", $owner, r###"']::text[]),
('"###, $access_schema, "seed_tenant_settings(uuid)','sql','void',false,false,'v',ARRAY['t']::text[],ARRAY['search_path=pg_catalog, pg_temp']::text[],$4::text,ARRAY['", $owner, r###"']::text[]),
('"###, $mdm_registration_tasks_save_retired_run, "(uuid,uuid,jsonb,jsonb)','sql','boolean',true,false,'v',ARRAY['p_registration','p_run','p_previous','p_state']::text[],ARRAY['search_path=pg_catalog']::text[],$5::text,ARRAY['", $access_role, "','", $command_runtime, "','", $owner, r###"']::text[])
)
SELECT e.signature FROM expected e
LEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)
LEFT JOIN pg_language l ON l.oid=p.prolang
LEFT JOIN pg_roles r ON r.oid=p.proowner
WHERE p.oid IS NULL OR l.lanname<>e.language OR p.prorettype<>to_regtype(e.result)
 OR p.prokind<>'f' OR p.prosecdef<>e.definer OR p.proretset<>e.returns_set
 OR p.proisstrict OR p.proparallel<>'u'
 OR p.provolatile::text<>e.volatility OR p.proleakproof OR p.prosrc<>e.body
 OR coalesce(p.proargnames,ARRAY[]::text[]) IS DISTINCT FROM e.names OR p.proconfig IS DISTINCT FROM e.config
 OR r.rolname<>'"###, $owner, r###"' OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
 OR pg_has_role(current_user,r.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))
 OR EXISTS(SELECT FROM unnest(e.roles) role WHERE NOT has_function_privilege(role,p.oid,'EXECUTE'))
ORDER BY e.signature LIMIT 1
"###),
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
    "mdm_registration_tasks.device_recovery",
    "mdm_registration_tasks.installation_status",
    "mdm_registration_tasks.operations",
    "mdm_registration_tasks.policy_recovery",
    "mdm_registration_tasks.receipts",
    "mdm_registration_tasks.recovery_key",
    "mdm_registration_tasks.requests",
    "mdm_registration_tasks.retirement_commands",
    "mdm_registration_tasks.runs",
    "mdm_registration_tasks.save_retired_command",
    "mdm_registration_tasks.save_retired_run",
    "mdm_registration_tasks.windows_pending_operations",
    "mdm_registration_tasks.windows_wake_candidates",
    "SCHEMA mdm_registration_tasks",
    "mdm_policy.policies",
    "mdm_policy.triggers",
    "mdm_policy.versions",
    "SCHEMA mdm_policy",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_inventory_runtime",
    "mdm_scope_runtime",
    "mdm_policy_runtime",
    "mdm_resource_runtime",
    "mdm_software_runtime",
    "mdm_content_runtime",
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
    "CREATE INDEX registration_agent_recoveries",
    "CREATE INDEX agent_quota",
    "CREATE UNIQUE INDEX parent_certificate_enrollment",
    "ADD CONSTRAINT asset_authority_history_pkey",
    "ADD CONSTRAINT credentials_pkey",
    "ADD CONSTRAINT credentials_tenant_id_channel_locator_key",
    "ADD CONSTRAINT devices_pkey",
    "ADD CONSTRAINT enrollment_issuance_operation",
    "ADD CONSTRAINT grants_pkey",
    "ADD CONSTRAINT operations_pkey",
    "ADD CONSTRAINT registration_generation_identity",
    "ADD CONSTRAINT registrations_pkey",
    "ADD CONSTRAINT registrations_tenant_id_device_channel_generation_key",
    "ADD CONSTRAINT registrations_tenant_id_id_channel_key",
    "ADD CONSTRAINT registrations_tenant_id_request_id_key",
    "ADD CONSTRAINT report_sources_pkey",
    "ADD CONSTRAINT requests_pkey",
    "ADD CONSTRAINT requests_tenant_id_grant_id_key",
    "CREATE INDEX asset_authority_by_device",
    "CREATE INDEX asset_authority_by_registration",
    "CREATE INDEX asset_authority_changes",
    "CREATE INDEX asset_authority_device_event",
    "CREATE UNIQUE INDEX one_active_credential",
    "CREATE UNIQUE INDEX one_active_registration",
    "CREATE INDEX registration_control_page",
    "ADD CONSTRAINT asset_authority_history_tenant_id_revision_fkey",
    "ADD CONSTRAINT credentials_tenant_id_registration_channel_fkey",
    "ADD CONSTRAINT registrations_tenant_id_device_fkey",
    "ADD CONSTRAINT registrations_tenant_id_request_id_fkey",
    "ADD CONSTRAINT report_sources_tenant_id_registration_fkey",
    "ADD CONSTRAINT requests_tenant_id_grant_id_fkey",
    "ADD CONSTRAINT registration_parent",
    "ADD CONSTRAINT request_parent",
    "ADD CONSTRAINT request_parent_credential",
    "ADD CONSTRAINT agent_registration_grant",
    "ADD CONSTRAINT agent_recovery_registration",
    "ADD CONSTRAINT agent_recovery_predecessor",
    "ADD CONSTRAINT activated_credential",
    "CREATE UNIQUE INDEX agent_bootstrap_current",
    "CREATE INDEX agent_configuration_usage",
    "CREATE INDEX agent_connection_latest_observation",
    "CREATE INDEX agent_connection_latest_failure",
    "CREATE INDEX directory_registration_channel",
    "CREATE INDEX directory_grant_device",
    "CREATE INDEX directory_request_expiry",
    "CREATE INDEX enrollment_offer",
    "CREATE INDEX enrollment_history",
    r###""schema":"mdm_access","table":"asset_authority_history""###,
    r###""schema":"mdm_access","table":"credentials""###,
    r###""schema":"mdm_access","table":"devices""###,
    r###""schema":"mdm_access","table":"grants""###,
    r###""schema":"mdm_access","table":"registration_operations""###,
    r###""schema":"mdm_access","table":"registrations""###,
    r###""schema":"mdm_access","table":"report_sources""###,
    r###""schema":"mdm_access","table":"requests""###,
    r###""schema":"mdm_access","table":"agent_grants""###,
    r###""schema":"mdm_access","table":"agent_issuances""###,
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
    r###",{"schema":"mdm_windows","table":"operations","read_write":true,"updates":[],"delete_policy":null},{"schema":"mdm_windows","table":"entra_policy","read_write":true,"updates":["revision","document"],"delete_policy":null},{"schema":"mdm_access","table":"agent_native_enrollments","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_access","table":"device_access_bindings","read_write":true,"updates":["instance","principal","generation","revision","state","account","document"],"delete_policy":null},{"schema":"mdm_access","table":"device_access_ceremonies","read_write":true,"updates":["consumed"],"delete_policy":"expires_at<clock_timestampandconsumedisnull"},{"schema":"mdm_access","table":"device_access_results","read_write":true,"updates":[],"delete_policy":null},{"schema":"mdm_access","table":"device_access_subject_denials","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_access","table":"device_access_lifecycles","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_enterprise","table":"relying_parties","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_enterprise","table":"subjects","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_enterprise","table":"subject_versions","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_enterprise","table":"subject_owners","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_enterprise","table":"windows_sources","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_enterprise","table":"brokers","read_write":true,"updates":["document","sealed","expires_at","phase"],"delete_policy":null},{"schema":"mdm_access","table":"command_authorities","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"schema":"mdm_access_tasks","table":"runs","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"schema":"mdm_access_tasks","table":"policy_recovery","read_write":false,"updates":[],"delete_policy":null}"###,
    r###",{"name":"mdm_access.access_binding_ready","search_path":"search_path=pg_catalog"},{"name":"mdm_access_tasks.save_retired_run","search_path":"search_path=pg_catalog"},{"name":"mdm_access.access_policy","search_path":"search_path=pg_catalog"},{"name":"mdm_access.active_access_binding","search_path":"search_path=pg_catalog"}"###,
    r###""mdm_access.directory_endpoints","mdm_access.directory_users","mdm_access.directory_metadata","mdm_access.directory_channels","mdm_access.directory_enrollments","mdm_access.directory_inputs""###,
    r###""schema":"mdm_registration_tasks","table":"runs""###,
    r###""schema":"mdm_registration_tasks","table":"receipts""###,
    r###""schema":"mdm_registration_tasks","table":"agent_admission""###,
    r###""schema":"mdm_registration_tasks","table":"policy_recovery""###,
    r###",{"schema":"mdm_registration_tasks","table":"operations","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"schema":"mdm_registration_tasks","table":"requests","read_write":false,"updates":[],"delete_policy":null},{"schema":"mdm_registration_tasks","table":"device_recovery","read_write":false,"updates":[],"delete_policy":null}"###,
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
    "rss_da.enrollment_device_recovery",
    "rss_da.enrollment_installation_status",
    "rss_da.enrollment_operations",
    "rss_da.enrollment_policy_recovery",
    "rss_da.enrollment_receipts",
    "rss_da.enrollment_recovery_key",
    "rss_da.enrollment_requests",
    "rss_da.enrollment_retirement_commands",
    "rss_da.enrollment_runs",
    "rss_da.enrollment_save_retired_command",
    "rss_da.enrollment_save_retired_run",
    "rss_da.enrollment_windows_pending_operations",
    "rss_da.enrollment_windows_wake_candidates",
    "SCHEMA rss_da",
    "rss_da.policies",
    "rss_da.policy_triggers",
    "rss_da.policy_versions",
    "SCHEMA rss_da",
    "da_owner",
    "da_command_runtime",
    "da_inventory_runtime",
    "da_scope_runtime",
    "da_policy_runtime",
    "da_resource_runtime",
    "da_software_runtime",
    "da_content_runtime",
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
    "CREATE INDEX registration_registration_agent_recoveries",
    "CREATE INDEX registration_agent_quota",
    "CREATE UNIQUE INDEX registration_parent_certificate_enrollment",
    "ADD CONSTRAINT registration_asset_authority_history_pkey",
    "ADD CONSTRAINT registration_credentials_pkey",
    "ADD CONSTRAINT registration_credentials_tenant_id_channel_locator_key",
    "ADD CONSTRAINT registration_devices_pkey",
    "ADD CONSTRAINT registration_enrollment_issuance_operation",
    "ADD CONSTRAINT registration_grants_pkey",
    "ADD CONSTRAINT registration_operations_pkey",
    "ADD CONSTRAINT registration_registration_generation_identity",
    "ADD CONSTRAINT registration_registrations_pkey",
    "ADD CONSTRAINT registration_registrations_tenant_id_device_channel_generation_key",
    "ADD CONSTRAINT registration_registrations_tenant_id_id_channel_key",
    "ADD CONSTRAINT registration_registrations_tenant_id_request_id_key",
    "ADD CONSTRAINT registration_report_sources_pkey",
    "ADD CONSTRAINT registration_requests_pkey",
    "ADD CONSTRAINT registration_requests_tenant_id_grant_id_key",
    "CREATE INDEX registration_asset_authority_by_device",
    "CREATE INDEX registration_asset_authority_by_registration",
    "CREATE INDEX registration_asset_authority_changes",
    "CREATE INDEX registration_asset_authority_device_event",
    "CREATE UNIQUE INDEX registration_one_active_credential",
    "CREATE UNIQUE INDEX registration_one_active_registration",
    "CREATE INDEX registration_registration_control_page",
    "ADD CONSTRAINT registration_asset_authority_history_tenant_id_revision_fkey",
    "ADD CONSTRAINT registration_credentials_tenant_id_registration_channel_fkey",
    "ADD CONSTRAINT registration_registrations_tenant_id_device_fkey",
    "ADD CONSTRAINT registration_registrations_tenant_id_request_id_fkey",
    "ADD CONSTRAINT registration_report_sources_tenant_id_registration_fkey",
    "ADD CONSTRAINT registration_requests_tenant_id_grant_id_fkey",
    "ADD CONSTRAINT registration_registration_parent",
    "ADD CONSTRAINT registration_request_parent",
    "ADD CONSTRAINT registration_request_parent_credential",
    "ADD CONSTRAINT registration_agent_registration_grant",
    "ADD CONSTRAINT registration_agent_recovery_registration",
    "ADD CONSTRAINT registration_agent_recovery_predecessor",
    "ADD CONSTRAINT registration_activated_credential",
    "CREATE UNIQUE INDEX registration_agent_bootstrap_current",
    "CREATE INDEX registration_agent_configuration_usage",
    "CREATE INDEX registration_agent_connection_latest_observation",
    "CREATE INDEX registration_agent_connection_latest_failure",
    "CREATE INDEX registration_directory_registration_channel",
    "CREATE INDEX registration_directory_grant_device",
    "CREATE INDEX registration_directory_request_expiry",
    "CREATE INDEX registration_enrollment_offer",
    "CREATE INDEX registration_enrollment_history",
    r###""schema":"rss_da","table":"asset_authority_history""###,
    r###""schema":"rss_da","table":"credentials""###,
    r###""schema":"rss_da","table":"devices""###,
    r###""schema":"rss_da","table":"grants""###,
    r###""schema":"rss_da","table":"registration_operations""###,
    r###""schema":"rss_da","table":"registrations""###,
    r###""schema":"rss_da","table":"report_sources""###,
    r###""schema":"rss_da","table":"requests""###,
    r###""schema":"rss_da","table":"agent_grants""###,
    r###""schema":"rss_da","table":"agent_issuances""###,
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
    r###""rss_da.directory_endpoints","rss_da.directory_users","rss_da.directory_metadata","rss_da.directory_channels","rss_da.directory_enrollments","rss_da.directory_inputs""###,
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
