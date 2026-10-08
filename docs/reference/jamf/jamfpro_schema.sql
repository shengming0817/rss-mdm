-- MySQL dump 10.13  Distrib 8.4.8, for Linux (x86_64)
--
-- Host: localhost    Database: jamf0
-- ------------------------------------------------------
-- Server version	8.4.8-0ubuntu0.25.10.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `BATCH_JOB_EXECUTION`
--

DROP TABLE IF EXISTS `BATCH_JOB_EXECUTION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_JOB_EXECUTION` (
  `job_execution_id` bigint NOT NULL DEFAULT '-1',
  `version` bigint DEFAULT NULL,
  `job_instance_id` bigint NOT NULL DEFAULT '-1',
  `create_time` datetime(6) NOT NULL DEFAULT '1970-01-01 00:00:00.000000',
  `start_time` datetime(6) DEFAULT NULL,
  `end_time` datetime(6) DEFAULT NULL,
  `status` varchar(10) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `exit_code` varchar(2500) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `exit_message` varchar(2500) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_updated` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`job_execution_id`),
  KEY `job_inst_exec_fk` (`job_instance_id`),
  CONSTRAINT `job_inst_exec_fk` FOREIGN KEY (`job_instance_id`) REFERENCES `BATCH_JOB_INSTANCE` (`job_instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_JOB_EXECUTION_CONTEXT`
--

DROP TABLE IF EXISTS `BATCH_JOB_EXECUTION_CONTEXT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_JOB_EXECUTION_CONTEXT` (
  `job_execution_id` bigint NOT NULL DEFAULT '-1',
  `short_context` varchar(2500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serialized_context` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`job_execution_id`),
  CONSTRAINT `job_exec_ctx_fk` FOREIGN KEY (`job_execution_id`) REFERENCES `BATCH_JOB_EXECUTION` (`job_execution_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_JOB_EXECUTION_PARAMS`
--

DROP TABLE IF EXISTS `BATCH_JOB_EXECUTION_PARAMS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_JOB_EXECUTION_PARAMS` (
  `job_execution_id` bigint NOT NULL DEFAULT '-1',
  `parameter_name` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_type` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_value` varchar(2500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `identifying` char(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `job_exec_params_fk` (`job_execution_id`),
  CONSTRAINT `job_exec_params_fk` FOREIGN KEY (`job_execution_id`) REFERENCES `BATCH_JOB_EXECUTION` (`job_execution_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_JOB_EXECUTION_SEQ`
--

DROP TABLE IF EXISTS `BATCH_JOB_EXECUTION_SEQ`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_JOB_EXECUTION_SEQ` (
  `id` bigint NOT NULL DEFAULT '-1',
  `unique_key` char(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  UNIQUE KEY `unique_key_un` (`unique_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_JOB_INSTANCE`
--

DROP TABLE IF EXISTS `BATCH_JOB_INSTANCE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_JOB_INSTANCE` (
  `job_instance_id` bigint NOT NULL DEFAULT '-1',
  `version` bigint DEFAULT NULL,
  `job_name` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_key` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`job_instance_id`),
  KEY `job_inst_un` (`job_name`,`job_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_JOB_SEQ`
--

DROP TABLE IF EXISTS `BATCH_JOB_SEQ`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_JOB_SEQ` (
  `id` bigint NOT NULL DEFAULT '-1',
  `unique_key` char(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  UNIQUE KEY `unique_key_un` (`unique_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_STEP_EXECUTION`
--

DROP TABLE IF EXISTS `BATCH_STEP_EXECUTION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_STEP_EXECUTION` (
  `step_execution_id` bigint NOT NULL DEFAULT '-1',
  `version` bigint NOT NULL DEFAULT '-1',
  `step_name` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_execution_id` bigint NOT NULL DEFAULT '-1',
  `start_time` datetime(6) DEFAULT NULL,
  `end_time` datetime(6) DEFAULT NULL,
  `status` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `commit_count` bigint NOT NULL DEFAULT '-1',
  `read_count` bigint NOT NULL DEFAULT '-1',
  `filter_count` bigint NOT NULL DEFAULT '-1',
  `write_count` bigint NOT NULL DEFAULT '-1',
  `read_skip_count` bigint NOT NULL DEFAULT '-1',
  `write_skip_count` bigint NOT NULL DEFAULT '-1',
  `process_skip_count` bigint NOT NULL DEFAULT '-1',
  `rollback_count` bigint NOT NULL DEFAULT '-1',
  `exit_code` varchar(2500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exit_message` varchar(2500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_updated` datetime(6) DEFAULT NULL,
  `create_time` datetime(6) NOT NULL DEFAULT '1970-01-01 00:00:00.000000',
  PRIMARY KEY (`step_execution_id`),
  KEY `job_exec_step_fk` (`job_execution_id`),
  CONSTRAINT `job_exec_step_fk` FOREIGN KEY (`job_execution_id`) REFERENCES `BATCH_JOB_EXECUTION` (`job_execution_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_STEP_EXECUTION_CONTEXT`
--

DROP TABLE IF EXISTS `BATCH_STEP_EXECUTION_CONTEXT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_STEP_EXECUTION_CONTEXT` (
  `step_execution_id` bigint NOT NULL DEFAULT '-1',
  `short_context` varchar(2500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serialized_context` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`step_execution_id`),
  CONSTRAINT `step_exec_ctx_fk` FOREIGN KEY (`step_execution_id`) REFERENCES `BATCH_STEP_EXECUTION` (`step_execution_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BATCH_STEP_EXECUTION_SEQ`
--

DROP TABLE IF EXISTS `BATCH_STEP_EXECUTION_SEQ`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `BATCH_STEP_EXECUTION_SEQ` (
  `id` bigint NOT NULL DEFAULT '-1',
  `unique_key` char(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  UNIQUE KEY `unique_key_un` (`unique_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `access_management_setting`
--

DROP TABLE IF EXISTS `access_management_setting`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `access_management_setting` (
  `device_enrollment_server_uuid` varchar(256) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`device_enrollment_server_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `account_driven_enrollment_service_discovery_setting`
--

DROP TABLE IF EXISTS `account_driven_enrollment_service_discovery_setting`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `account_driven_enrollment_service_discovery_setting` (
  `account_driven_enrollment_service_discovery_setting_id` int NOT NULL AUTO_INCREMENT,
  `device_enrollment_account_details_server_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Maps to AxM server UUID',
  `account_driven_enrollment_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`account_driven_enrollment_service_discovery_setting_id`),
  UNIQUE KEY `server_uuid_unique` (`device_enrollment_account_details_server_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `account_driven_user_enrollment_session_token_settings`
--

DROP TABLE IF EXISTS `account_driven_user_enrollment_session_token_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `account_driven_user_enrollment_session_token_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `expiration_interval_seconds` int NOT NULL DEFAULT '-1',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `account_invitations`
--

DROP TABLE IF EXISTS `account_invitations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `account_invitations` (
  `account_invitation_id` int NOT NULL AUTO_INCREMENT,
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `use_count` int NOT NULL DEFAULT '0',
  `expiration_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`account_invitation_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `activation_code`
--

DROP TABLE IF EXISTS `activation_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `activation_code` (
  `activation_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `institution_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cal_token` text COLLATE utf8mb3_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adcs_cert_payload_settings`
--

DROP TABLE IF EXISTS `adcs_cert_payload_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adcs_cert_payload_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `adcs_id` int NOT NULL DEFAULT '-1',
  `adcs_cert_subject` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `adcs_template_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `key_size` int NOT NULL DEFAULT '2048',
  PRIMARY KEY (`id`),
  KEY `payload_identifier` (`payload_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adcs_cert_subject_alt_names`
--

DROP TABLE IF EXISTS `adcs_cert_subject_alt_names`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adcs_cert_subject_alt_names` (
  `id` int NOT NULL AUTO_INCREMENT,
  `cert_payload_settings_id` int NOT NULL DEFAULT '-1',
  `subject_alt_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `subject_alt_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `fk_cert_payload_id` (`cert_payload_settings_id`),
  CONSTRAINT `fk_cert_payload_id` FOREIGN KEY (`cert_payload_settings_id`) REFERENCES `adcs_cert_payload_settings` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adcs_certificate_requests`
--

DROP TABLE IF EXISTS `adcs_certificate_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adcs_certificate_requests` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `pkiId` int NOT NULL DEFAULT '-1',
  `encrypted_private_key` mediumblob,
  `password` text COLLATE utf8mb3_unicode_ci,
  `public_key` mediumblob,
  `adcs_request_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `device_udid` (`device_udid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adcs_job`
--

DROP TABLE IF EXISTS `adcs_job`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adcs_job` (
  `id` int NOT NULL AUTO_INCREMENT,
  `adcs_settings_id` int NOT NULL DEFAULT '-1',
  `status` tinyint(1) NOT NULL DEFAULT '-1',
  `job_type` tinyint(1) NOT NULL DEFAULT '-1',
  `adcs_fqdn` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ca_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `created_timestamp` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `completed_timestamp` datetime DEFAULT NULL,
  `processing_timestamp` datetime DEFAULT NULL,
  `retry_count` int NOT NULL DEFAULT '-1',
  `template` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `pkcs10` blob,
  `x509_certificate` mediumblob,
  `certificate_serial_number` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `certificate_authority_issued_certificate_id` int DEFAULT NULL,
  `resolved` tinyint(1) NOT NULL DEFAULT '0',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `transaction_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `adcs_settings_id` (`adcs_settings_id`),
  KEY `status` (`status`),
  KEY `created_timestamp` (`created_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adcs_scep_payload_settings`
--

DROP TABLE IF EXISTS `adcs_scep_payload_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adcs_scep_payload_settings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `adcs_settings_id` int NOT NULL DEFAULT '-1',
  `created_timestamp` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `expiration_timestamp` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `challenge_password` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `is_challenge_redeemed` tinyint(1) NOT NULL DEFAULT '0',
  `template` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_type` int NOT NULL DEFAULT '-1',
  `device_payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adcs_settings`
--

DROP TABLE IF EXISTS `adcs_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adcs_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `api_integrations_integration_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `adcs_fqdn` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `adcs_ca_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cat_url` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `cat_server_cert` mediumblob COMMENT 'Server certificate used for SSL trust to AD CS Translation Service',
  `cat_server_cert_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `cat_client_cert` mediumblob,
  `cat_client_cert_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `cat_client_cert_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `is_revocation_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `is_outbound` tinyint(1) NOT NULL DEFAULT '0',
  `connector_last_check_in_timestamp` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `adobe_payloads`
--

DROP TABLE IF EXISTS `adobe_payloads`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adobe_payloads` (
  `package_id` int NOT NULL DEFAULT '0',
  `adobe_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `short_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `long_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `idx_adobe_pid_sn` (`package_id`,`short_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `advanced_searches`
--

DROP TABLE IF EXISTS `advanced_searches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `advanced_searches` (
  `batch_size` int NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `airplay_permission_mappings`
--

DROP TABLE IF EXISTS `airplay_permission_mappings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `airplay_permission_mappings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `apple_tv_id` int NOT NULL DEFAULT '-1',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `automate_tv_remote_app` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `mobile_device_id_apple_tv_id_auto` (`mobile_device_id`,`apple_tv_id`,`automate_tv_remote_app`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `airplay_permissions`
--

DROP TABLE IF EXISTS `airplay_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `airplay_permissions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_field` int NOT NULL DEFAULT '0',
  `restrict_destinations` tinyint(1) NOT NULL DEFAULT '0',
  `automate_passwords` tinyint(1) NOT NULL DEFAULT '0',
  `automate_tv_remote_connection` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `api_integration_linked_apps`
--

DROP TABLE IF EXISTS `api_integration_linked_apps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `api_integration_linked_apps` (
  `id` int NOT NULL AUTO_INCREMENT,
  `api_integration_id` int NOT NULL DEFAULT '-1',
  `linked_app_id` int NOT NULL DEFAULT '-1',
  `linked_app_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `claims` json NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `api_integration_for_app` (`linked_app_id`,`linked_app_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `api_integrations`
--

DROP TABLE IF EXISTS `api_integrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `api_integrations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `integration_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `authorization_scopes` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '-1',
  `access_token_lifetime_seconds` int NOT NULL DEFAULT '0',
  `app_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'NONE' COMMENT 'application type that equates to an enum with values like NONE, CLIENT or LINKED_APP',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `api_roles`
--

DROP TABLE IF EXISTS `api_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `api_roles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `privileges` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `apns_push_enable_requests`
--

DROP TABLE IF EXISTS `apns_push_enable_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `apns_push_enable_requests` (
  `id` int NOT NULL AUTO_INCREMENT,
  `requested_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `status` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'QUEUED',
  `processed_time` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`,`requested_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_config_reinstall_codes`
--

DROP TABLE IF EXISTS `app_config_reinstall_codes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_config_reinstall_codes` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `issued_at` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `mobile_device_app_id` (`mobile_device_app_id`),
  KEY `device_device_app_composite_key` (`mobile_device_id`,`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers`
--

DROP TABLE IF EXISTS `app_installers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `app_title_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `target_smart_computer_group_id` int NOT NULL DEFAULT '-1',
  `deployment_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '-1',
  `install_predefined_config_profiles` tinyint(1) NOT NULL DEFAULT '0',
  `title_available_in_ais` tinyint(1) NOT NULL DEFAULT '1',
  `trigger_admin_notifications` tinyint(1) NOT NULL DEFAULT '0',
  `smart_group_out_of_sync_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `app_title_id` (`app_title_id`),
  KEY `target_smart_computer_group_id` (`target_smart_computer_group_id`),
  KEY `deployment_type` (`deployment_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_admin_web_notifications`
--

DROP TABLE IF EXISTS `app_installers_admin_web_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_admin_web_notifications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `notification_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `notification_params` json NOT NULL,
  `object_id` int NOT NULL DEFAULT '-1',
  `created_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_computer_config_profiles`
--

DROP TABLE IF EXISTS `app_installers_computer_config_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_computer_config_profiles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `deployment_id` int NOT NULL DEFAULT '-1',
  `device_id` int NOT NULL DEFAULT '-1',
  `config_profile_id` int NOT NULL DEFAULT '-1',
  `is_installed` tinyint(1) NOT NULL DEFAULT '0',
  `reinstall_epoch` bigint NOT NULL DEFAULT '0',
  `removal_epoch` bigint NOT NULL DEFAULT '0',
  `removal_retry_attempts` tinyint(1) NOT NULL DEFAULT '0',
  `config_profile_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `deployment_id` (`deployment_id`),
  KEY `device_id` (`device_id`),
  KEY `reinstall_epoch` (`reinstall_epoch`),
  KEY `removal_epoch` (`removal_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_deployment_computers`
--

DROP TABLE IF EXISTS `app_installers_deployment_computers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_deployment_computers` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `deployment_id` int NOT NULL DEFAULT '-1',
  `device_id` int NOT NULL DEFAULT '-1',
  `deployment_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `deployment_id` (`deployment_id`),
  KEY `device_id_deployment_id` (`device_id`,`deployment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_deployment_status`
--

DROP TABLE IF EXISTS `app_installers_deployment_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_deployment_status` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `app_title_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `short_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `version_recalc_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `process_started_epoch` bigint NOT NULL DEFAULT '0',
  `mdm_command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `installation_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_compatibility_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `installation_status_updated_epoch` bigint NOT NULL DEFAULT '0',
  `command_sent_counters` int NOT NULL DEFAULT '0',
  `command_errors_counter` int NOT NULL DEFAULT '0',
  `recalculation_gave_up_epoch` bigint NOT NULL DEFAULT '0',
  `deployment_id` int NOT NULL DEFAULT '-1',
  `initial_deployment_completed` tinyint(1) NOT NULL DEFAULT '0',
  `subscribed` tinyint(1) NOT NULL DEFAULT '0',
  `subscription_reinstall_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `app_title_id_device_id_unique` (`app_title_id`,`device_id`),
  KEY `deployment_id` (`deployment_id`),
  KEY `version_recalc_status_and_started_epoch` (`version_recalc_status`,`process_started_epoch`),
  KEY `device_id_and_installation_status` (`device_id`,`installation_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_global_settings_deployment_process_controls`
--

DROP TABLE IF EXISTS `app_installers_global_settings_deployment_process_controls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_global_settings_deployment_process_controls` (
  `id` int NOT NULL DEFAULT '0',
  `commands_batch_size` int DEFAULT NULL,
  `batch_frequency_in_minutes` int DEFAULT NULL,
  `days_of_week` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `from_time_of_day` varchar(50) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `to_time_of_day` varchar(50) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_global_settings_end_user_experience`
--

DROP TABLE IF EXISTS `app_installers_global_settings_end_user_experience`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_global_settings_end_user_experience` (
  `id` int NOT NULL DEFAULT '0',
  `notification_message` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `deadline_message` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `notification_interval_hours` bigint DEFAULT NULL,
  `deadline_hours` bigint DEFAULT NULL,
  `quit_delay_minutes` bigint DEFAULT NULL,
  `complete_message` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `relaunch` tinyint(1) DEFAULT NULL,
  `suppress` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_notification_settings`
--

DROP TABLE IF EXISTS `app_installers_notification_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_notification_settings` (
  `deployment_id` int NOT NULL DEFAULT '-1',
  `notification_message` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `deadline_message` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `notification_interval_hours` bigint DEFAULT NULL,
  `deadline_hours` bigint DEFAULT NULL,
  `quit_delay_minutes` bigint DEFAULT NULL,
  `complete_message` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `relaunch` tinyint(1) DEFAULT NULL,
  `suppress` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`deployment_id`),
  CONSTRAINT `fk_deployment_id` FOREIGN KEY (`deployment_id`) REFERENCES `app_installers` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_self_service_categories`
--

DROP TABLE IF EXISTS `app_installers_self_service_categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_self_service_categories` (
  `deployment_id` int NOT NULL DEFAULT '-1',
  `category_id` int NOT NULL DEFAULT '-1',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`deployment_id`,`category_id`),
  KEY `deployment_id` (`deployment_id`),
  CONSTRAINT `fk_app_installer_self_service_categories_deployment_id` FOREIGN KEY (`deployment_id`) REFERENCES `app_installers` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_self_service_settings`
--

DROP TABLE IF EXISTS `app_installers_self_service_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_self_service_settings` (
  `deployment_id` int NOT NULL DEFAULT '-1',
  `description` varchar(4000) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `force_view_description` tinyint(1) NOT NULL DEFAULT '0',
  `include_in_featured_category` tinyint(1) NOT NULL DEFAULT '0',
  `include_in_compliance_category` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`deployment_id`),
  CONSTRAINT `fk_app_installer_self_service_deployment_id` FOREIGN KEY (`deployment_id`) REFERENCES `app_installers` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_title_config_profiles`
--

DROP TABLE IF EXISTS `app_installers_title_config_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_title_config_profiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `config_profile_id` int NOT NULL DEFAULT '-1',
  `profile_payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `app_title_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `config_profiles_definition_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `minimum_os_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_update_time` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `config_profile_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deployment_id` int DEFAULT NULL,
  `removal_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `config_profile_id` (`config_profile_id`),
  KEY `app_title_id` (`app_title_id`),
  KEY `deployment_id` (`deployment_id`),
  KEY `removal_epoch` (`removal_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_titles`
--

DROP TABLE IF EXISTS `app_installers_titles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_titles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_title_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `publisher` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `icon_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `latest_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ais_profiles_update_attempt_epoch` bigint NOT NULL DEFAULT '0',
  `available_in_ais` tinyint(1) NOT NULL DEFAULT '1',
  `installation_path_shared` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `app_title_id_unique` (`app_title_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_installers_versions`
--

DROP TABLE IF EXISTS `app_installers_versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_installers_versions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_title_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `short_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `architecture` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version_order` bigint DEFAULT NULL,
  `minimum_os_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `notification_available` tinyint(1) NOT NULL DEFAULT '0',
  `removed` tinyint(1) NOT NULL DEFAULT '0',
  `last_updated_epoch` bigint NOT NULL DEFAULT '-1',
  `config_profiles_definition_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `media_source_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'JAMF_SERVER',
  PRIMARY KEY (`id`),
  KEY `app_title_id` (`app_title_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_push_notification_queue`
--

DROP TABLE IF EXISTS `app_push_notification_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_push_notification_queue` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `push_content` mediumblob,
  `retry_count` int NOT NULL DEFAULT '0',
  `next_retry_epoch` bigint NOT NULL DEFAULT '0',
  `created_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `app_token` (`app_token`),
  KEY `next_retry_epoch` (`next_retry_epoch`),
  KEY `created_epoch` (`created_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_request_approvers`
--

DROP TABLE IF EXISTS `app_request_approvers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_request_approvers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_request_form_fields`
--

DROP TABLE IF EXISTS `app_request_form_fields`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_request_form_fields` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `priority` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_request_settings`
--

DROP TABLE IF EXISTS `app_request_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_request_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `app_store_locale` varchar(2) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `requester_user_group_id` int DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `app_updater_settings`
--

DROP TABLE IF EXISTS `app_updater_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_updater_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keep_all_apps_desc_icon_up_to_date` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_sync_time` int NOT NULL DEFAULT '0' COMMENT 'This is the time in seconds after midnight that app version, description, and icon get synced with iTunes App Store.',
  `itunes_default_region` varchar(2) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'US',
  `auto_update_automatically_installed_apps` tinyint(1) NOT NULL DEFAULT '0',
  `auto_update_self_service_installed_apps` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `apple_school_manager_active_syncs`
--

DROP TABLE IF EXISTS `apple_school_manager_active_syncs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `apple_school_manager_active_syncs` (
  `sync_id` int NOT NULL AUTO_INCREMENT,
  `instance_id` int NOT NULL DEFAULT '-1',
  `sync_type` int NOT NULL DEFAULT '-1',
  `sync_status` int NOT NULL DEFAULT '-1',
  `sync_date_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`sync_id`),
  KEY `instance_id` (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `apple_school_manager_instance`
--

DROP TABLE IF EXISTS `apple_school_manager_instance`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `apple_school_manager_instance` (
  `instance_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_enrollment_program_instance_id` int NOT NULL DEFAULT '-1',
  `interval_type` int NOT NULL DEFAULT '-1',
  `interval_offset` int NOT NULL DEFAULT '-1',
  `interval_time` int NOT NULL DEFAULT '-1',
  `interval_time_zone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `class_name_format` text COLLATE utf8mb3_unicode_ci,
  `class_description_format` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `apple_school_manager_matcher`
--

DROP TABLE IF EXISTS `apple_school_manager_matcher`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `apple_school_manager_matcher` (
  `matcher_id` int NOT NULL AUTO_INCREMENT,
  `instance_id` int NOT NULL DEFAULT '-1',
  `matcher_operation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `matcher_roster_column` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `matcher_user_column` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `matcher_user_extension_attribute_id` int NOT NULL DEFAULT '-1',
  `matcher_roster_right` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`matcher_id`),
  KEY `instance_id` (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `apple_school_manager_sync_change_requests`
--

DROP TABLE IF EXISTS `apple_school_manager_sync_change_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `apple_school_manager_sync_change_requests` (
  `sync_id` int NOT NULL AUTO_INCREMENT,
  `instance_id` int NOT NULL DEFAULT '-1',
  `sync_type` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`sync_id`),
  KEY `instance_id` (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `apple_school_manager_sync_records`
--

DROP TABLE IF EXISTS `apple_school_manager_sync_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `apple_school_manager_sync_records` (
  `sync_id` int NOT NULL AUTO_INCREMENT,
  `instance_id` int NOT NULL DEFAULT '-1',
  `sync_time` bigint NOT NULL DEFAULT '-1',
  `status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`sync_id`),
  KEY `instance_id` (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_certificates`
--

DROP TABLE IF EXISTS `application_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_certificates` (
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `certificate_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Enum string representations from CertificateType, i.e. IOS_SELF_SERVICE',
  `certificate_data` mediumblob,
  KEY `mobile_device_id_cert_type` (`mobile_device_id`,`certificate_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_details`
--

DROP TABLE IF EXISTS `application_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_details` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cf_bundle_short_version_string` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cf_bundle_version` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `path` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_id` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `external_version_identifier` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `application_key` (`name`,`version`,`path`(255),`bundle_id`,`external_version_identifier`,`cf_bundle_short_version_string`,`cf_bundle_version`),
  KEY `name` (`name`),
  KEY `version` (`version`),
  KEY `cf_bundle_short_version_string` (`cf_bundle_short_version_string`),
  KEY `cf_bundle_version` (`cf_bundle_version`),
  KEY `bundle_id` (`bundle_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_history`
--

DROP TABLE IF EXISTS `application_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `application_details_id` int NOT NULL DEFAULT '-1',
  `application_history_type_cd` varchar(4) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `application_history_key` (`report_id`,`application_details_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_history_type`
--

DROP TABLE IF EXISTS `application_history_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_history_type` (
  `cd` varchar(4) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`cd`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_push_tokens`
--

DROP TABLE IF EXISTS `application_push_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_push_tokens` (
  `application_push_token_id` int NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL DEFAULT '-1' COMMENT 'ID of the target. If it is a mobile device, the mobile_device_id, etc.',
  `target_object_id` int NOT NULL DEFAULT '-1' COMMENT 'Int value from ObjectConstants (i.e., ObjectConstants.TYPE_MOBILE_DEVICE = 21)',
  `application` tinyint(1) NOT NULL DEFAULT '-1' COMMENT 'Enum integer values from PushCapableApplications, i.e. IOS_SELF_SERVICE_APPSTORE=-1',
  `push_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Actual token used for APNS communication with the target',
  PRIMARY KEY (`application_push_token_id`),
  KEY `target_key_index` (`target_id`,`target_object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_updates`
--

DROP TABLE IF EXISTS `application_updates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_updates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_object_id` int NOT NULL DEFAULT '-1',
  `app_bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `app_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_time` bigint NOT NULL DEFAULT '-1',
  `retry_count` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `app_update_for_device` (`device_object_id`,`device_id`,`app_bundle_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `application_usage_logs`
--

DROP TABLE IF EXISTS `application_usage_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `application_usage_logs` (
  `application_usage_log_id` bigint NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `application_details_id` int NOT NULL DEFAULT '-1',
  `usage_date_epoch` bigint NOT NULL DEFAULT '0',
  `minutes_open` int NOT NULL DEFAULT '0',
  `minutes_foreground` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`application_usage_log_id`),
  KEY `usage_date_epoch` (`usage_date_epoch`),
  KEY `aul_compid_epochdate` (`computer_id`,`usage_date_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `applications`
--

DROP TABLE IF EXISTS `applications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `applications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '0',
  `application_details_id` int NOT NULL DEFAULT '-1',
  `size` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mac_app_store` tinyint(1) NOT NULL DEFAULT '0',
  `has_update_available` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`report_id`,`id`),
  UNIQUE KEY `report_id_detail_id` (`report_id`,`application_details_id`),
  KEY `id` (`id`),
  KEY `application_details_id` (`application_details_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `assign_remove_profile_response_sync_state`
--

DROP TABLE IF EXISTS `assign_remove_profile_response_sync_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `assign_remove_profile_response_sync_state` (
  `id` int NOT NULL AUTO_INCREMENT,
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sync_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `failure_count` int NOT NULL DEFAULT '-1',
  `timestamp` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `serial_number_unique_key` (`serial_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attachment_assignments`
--

DROP TABLE IF EXISTS `attachment_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `attachment_assignments` (
  `attachment_id` int NOT NULL DEFAULT '-1',
  `object_type` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_id` int NOT NULL DEFAULT '-1',
  KEY `object_id` (`object_id`),
  KEY `assignments_id` (`attachment_id`,`object_type`,`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attachments`
--

DROP TABLE IF EXISTS `attachments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `attachments` (
  `attachment_id` int NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `contents` longblob,
  `file_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_size` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`attachment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auto_management_command_state`
--

DROP TABLE IF EXISTS `auto_management_command_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auto_management_command_state` (
  `id` int NOT NULL AUTO_INCREMENT,
  `auto_management_setting_type` int NOT NULL DEFAULT '-1',
  `auto_management_setting_id` int NOT NULL DEFAULT '-1',
  `device_id` int NOT NULL DEFAULT '-1',
  `date_sent_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `auto_management_command_state_id` (`auto_management_setting_type`,`auto_management_setting_id`,`device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `available_software_updates`
--

DROP TABLE IF EXISTS `available_software_updates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `available_software_updates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `recommended` tinyint(1) NOT NULL DEFAULT '0',
  `restart_required` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `azure_configurations`
--

DROP TABLE IF EXISTS `azure_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `azure_configurations` (
  `id` int NOT NULL DEFAULT '-1',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `scim_username_change_support_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `scim_group_name_change_support_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `migrated` tinyint(1) NOT NULL DEFAULT '0',
  `type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'PUBLIC',
  `tenant_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_timestamp` bigint NOT NULL DEFAULT '0',
  `user_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `real_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `department` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `building` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `group_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'id',
  `group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `read_timeout` int NOT NULL DEFAULT '-1',
  `connection_timeout` int NOT NULL DEFAULT '5',
  `transitive_sso_membership_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `transitive_sso_membership_user_field` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'userPrincipalName',
  `transitive_directory_membership_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `membership_calculation_optimization_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `client_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `client_secret_encrypted` text COLLATE utf8mb3_unicode_ci,
  `credentials_name_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `azure_integration_state`
--

DROP TABLE IF EXISTS `azure_integration_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `azure_integration_state` (
  `action_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_id_hash` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'PUBLIC',
  PRIMARY KEY (`action_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `azure_migration_report_files`
--

DROP TABLE IF EXISTS `azure_migration_report_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `azure_migration_report_files` (
  `migration_report_process_id` int NOT NULL DEFAULT '-1',
  `report_file` longblob,
  PRIMARY KEY (`migration_report_process_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `azure_migration_report_processes`
--

DROP TABLE IF EXISTS `azure_migration_report_processes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `azure_migration_report_processes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `source_ldap_id` int NOT NULL DEFAULT '-1',
  `target_azure_id` int NOT NULL DEFAULT '-1',
  `report_started_epoch` bigint NOT NULL DEFAULT '0',
  `report_finished_epoch` bigint NOT NULL DEFAULT '0',
  `report_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_user_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_real_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_department` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_building` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mapping_group_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'id',
  `mapping_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `buildings`
--

DROP TABLE IF EXISTS `buildings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `buildings` (
  `building_id` int NOT NULL AUTO_INCREMENT,
  `building_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `street_address_1` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `street_address_2` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `city` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `state_province` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `zip_postal_code` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `country` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`building_id`),
  KEY `buildings_idx1` (`building_name`,`building_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cached_packages`
--

DROP TABLE IF EXISTS `cached_packages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cached_packages` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `package_file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `categories`
--

DROP TABLE IF EXISTS `categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `categories` (
  `category_id` int NOT NULL AUTO_INCREMENT,
  `category_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_priority` int NOT NULL DEFAULT '5',
  PRIMARY KEY (`category_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `category_objects`
--

DROP TABLE IF EXISTS `category_objects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `category_objects` (
  `category_id` int NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `featured` int NOT NULL DEFAULT '0',
  `primary_category` int NOT NULL DEFAULT '0',
  KEY `object_id` (`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ccm_settings`
--

DROP TABLE IF EXISTS `ccm_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ccm_settings` (
  `ccm_id` int NOT NULL DEFAULT '1',
  `jcds2_api_domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `jcds2_download_token` varchar(2048) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `jcds2_download_expires` bigint NOT NULL DEFAULT '0',
  `endpoint_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_authority_audit_log`
--

DROP TABLE IF EXISTS `certificate_authority_audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_authority_audit_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `before_action_ca_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `after_action_ca_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `change_event_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `log_message` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `event_time_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_authority_issued`
--

DROP TABLE IF EXISTS `certificate_authority_issued`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_authority_issued` (
  `certificate_id` int NOT NULL AUTO_INCREMENT,
  `subject_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `issued_date_epoch` bigint NOT NULL DEFAULT '0',
  `is_revoked` tinyint(1) NOT NULL DEFAULT '0',
  `revoked_date_epoch` bigint NOT NULL DEFAULT '0',
  `not_after_date_epoch` bigint NOT NULL DEFAULT '-1',
  `common_ca_settings_id` int NOT NULL DEFAULT '-1',
  `serial_number` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `pending_revoke` tinyint(1) NOT NULL DEFAULT '0',
  `resolved` tinyint(1) NOT NULL DEFAULT '1',
  `revoke_failure_count` tinyint(1) NOT NULL DEFAULT '0',
  `sha1_fingerprint` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`certificate_id`),
  UNIQUE KEY `ca_serial_number_object` (`serial_number`,`issued_date_epoch`,`not_after_date_epoch`),
  KEY `is_revoked` (`is_revoked`),
  KEY `pending_revoke` (`pending_revoke`),
  KEY `resolved` (`resolved`),
  KEY `revoke_failure_count` (`revoke_failure_count`),
  KEY `idx_serial_resolved` (`serial_number`,`resolved`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_authority_revocation_list`
--

DROP TABLE IF EXISTS `certificate_authority_revocation_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_authority_revocation_list` (
  `id` int NOT NULL AUTO_INCREMENT,
  `crl_number` bigint NOT NULL DEFAULT '1',
  `crl_blob` mediumblob,
  `issued_date_epoch` bigint NOT NULL DEFAULT '0',
  `next_update_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_authority_settings`
--

DROP TABLE IF EXISTS `certificate_authority_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_authority_settings` (
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `subject_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'CN=JAMF Software Server CA',
  `keysize` int NOT NULL DEFAULT '2048',
  `keystore_blob` mediumblob,
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `certificate_authority_expiration` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_authority_settings_backup`
--

DROP TABLE IF EXISTS `certificate_authority_settings_backup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_authority_settings_backup` (
  `id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `subject_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keysize` int NOT NULL DEFAULT '2048',
  `keystore_blob` mediumblob,
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `certificate_authority_expiration` bigint NOT NULL DEFAULT '-1',
  `backup_date` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_certificate_detail`
--

DROP TABLE IF EXISTS `certificate_management_certificate_detail`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_certificate_detail` (
  `id` int NOT NULL AUTO_INCREMENT,
  `certificate_id` int NOT NULL DEFAULT '-1',
  `keystore_blob` longblob,
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `fk_certificate_detail_certificate_id` (`certificate_id`),
  CONSTRAINT `fk_certificate_detail_certificate_id` FOREIGN KEY (`certificate_id`) REFERENCES `certificate_management_metadata` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_metadata`
--

DROP TABLE IF EXISTS `certificate_management_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_metadata` (
  `id` int NOT NULL AUTO_INCREMENT,
  `uuid` binary(16) NOT NULL DEFAULT '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
  `issuer_id` int DEFAULT NULL,
  `serial_number` varchar(100) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `subject_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `key_curve` varchar(50) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `not_before_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `not_after_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_uuid` (`uuid`),
  KEY `fk_issuer_id` (`issuer_id`),
  CONSTRAINT `fk_issuer_id` FOREIGN KEY (`issuer_id`) REFERENCES `certificate_management_metadata` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_request_queue`
--

DROP TABLE IF EXISTS `certificate_management_request_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_request_queue` (
  `id` int NOT NULL AUTO_INCREMENT,
  `issued_certificate_id` int DEFAULT NULL,
  `issuer_certificate_uuid` binary(16) DEFAULT NULL,
  `subject_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `public_key` longblob,
  `signature_algorithm` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `not_before_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `not_after_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `certificate_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serial_number` varchar(100) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `request_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `process_date_time` datetime DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`id`),
  KEY `fk_issued_certificate_id` (`issued_certificate_id`),
  CONSTRAINT `fk_issued_certificate_id` FOREIGN KEY (`issued_certificate_id`) REFERENCES `certificate_management_metadata` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_request_queue_extensions`
--

DROP TABLE IF EXISTS `certificate_management_request_queue_extensions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_request_queue_extensions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `certificate_request_id` int NOT NULL DEFAULT '-1',
  `object_identifier` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_critical` tinyint(1) NOT NULL DEFAULT '-1',
  `class_serialized` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value_blob` longblob,
  PRIMARY KEY (`id`),
  KEY `fk_certificate_request_id` (`certificate_request_id`),
  CONSTRAINT `fk_certificate_request_id` FOREIGN KEY (`certificate_request_id`) REFERENCES `certificate_management_request_queue` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_revocation_list`
--

DROP TABLE IF EXISTS `certificate_management_revocation_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_revocation_list` (
  `id` int NOT NULL AUTO_INCREMENT,
  `crl_blob` longblob,
  `created_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `expiration_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_revoked_certificates`
--

DROP TABLE IF EXISTS `certificate_management_revoked_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_revoked_certificates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `certificate_id` int NOT NULL DEFAULT '-1',
  `serial_number` varchar(100) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `revocation_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `not_after_date_time` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `revocation_reason_id` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_uuid` (`certificate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_management_settings`
--

DROP TABLE IF EXISTS `certificate_management_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_management_settings` (
  `id` tinyint(1) NOT NULL DEFAULT '-1',
  `implementation_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_renewal_signing_cert_reissue_log`
--

DROP TABLE IF EXISTS `certificate_renewal_signing_cert_reissue_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_renewal_signing_cert_reissue_log` (
  `signing_certificate_id` int NOT NULL DEFAULT '0',
  `signing_cert_type_id` int NOT NULL DEFAULT '0',
  `replaced_on_epoch` bigint NOT NULL DEFAULT '0',
  `replacement_complete` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_request_details`
--

DROP TABLE IF EXISTS `certificate_request_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_request_details` (
  `id` int NOT NULL AUTO_INCREMENT,
  `type_id` tinyint(1) NOT NULL DEFAULT '-1',
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_mandatory` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_template_common_name_restrictions`
--

DROP TABLE IF EXISTS `certificate_template_common_name_restrictions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_template_common_name_restrictions` (
  `certificate_template_type` int NOT NULL DEFAULT '-1',
  `restriction` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_template_san_restrictions`
--

DROP TABLE IF EXISTS `certificate_template_san_restrictions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_template_san_restrictions` (
  `certificate_template_type` int NOT NULL DEFAULT '-1',
  `restriction` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_to_mobile_device_configuration_profile`
--

DROP TABLE IF EXISTS `certificate_to_mobile_device_configuration_profile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_to_mobile_device_configuration_profile` (
  `id` int NOT NULL AUTO_INCREMENT,
  `certificate_id` int NOT NULL DEFAULT '-1',
  `profile_id` int NOT NULL DEFAULT '-1',
  `certificate_payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `deleted_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `certificate_id_profile_id` (`certificate_id`,`profile_id`),
  KEY `certificate_payload_uuid` (`certificate_payload_uuid`),
  KEY `mdm_uuid` (`mdm_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificate_to_os_x_configuration_profile`
--

DROP TABLE IF EXISTS `certificate_to_os_x_configuration_profile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificate_to_os_x_configuration_profile` (
  `id` int NOT NULL AUTO_INCREMENT,
  `certificate_id` int NOT NULL DEFAULT '-1',
  `profile_id` int NOT NULL DEFAULT '-1',
  `certificate_payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `deleted_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `certificate_id_profile_id` (`certificate_id`,`profile_id`),
  KEY `certificate_payload_uuid` (`certificate_payload_uuid`),
  KEY `mdm_uuid` (`mdm_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `change_management`
--

DROP TABLE IF EXISTS `change_management`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `change_management` (
  `enable_file_cm` tinyint(1) NOT NULL DEFAULT '0',
  `cm_file` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '/private/var/log/',
  `cm_file_size` int NOT NULL DEFAULT '10',
  `cm_file_format` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enable_syslog_cm` tinyint(1) NOT NULL DEFAULT '0',
  `syslog_facility_name` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'JAMF',
  `syslog_host_name` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'localhost',
  `syslog_port` int NOT NULL DEFAULT '514',
  `syslog_format` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `syslog_is_secure` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_beacon_id_available`
--

DROP TABLE IF EXISTS `classroom_beacon_id_available`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_beacon_id_available` (
  `beacon_id` int NOT NULL DEFAULT '-1',
  `available` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`beacon_id`),
  KEY `classroom_available_beacon_id` (`available`,`beacon_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_edu_profile_composite_hash`
--

DROP TABLE IF EXISTS `classroom_edu_profile_composite_hash`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_edu_profile_composite_hash` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_object_id` int NOT NULL DEFAULT '-1',
  `edu_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_calculated_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_id_device_object_id` (`device_id`,`device_object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_instructor_jss_user`
--

DROP TABLE IF EXISTS `classroom_instructor_jss_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_instructor_jss_user` (
  `classroom_id` int NOT NULL DEFAULT '-1',
  `user_object_id` int NOT NULL DEFAULT '-1',
  KEY `ciju_uoid_cid` (`user_object_id`,`classroom_id`),
  KEY `ciju_cid_uoid` (`classroom_id`,`user_object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_instructor_user_group`
--

DROP TABLE IF EXISTS `classroom_instructor_user_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_instructor_user_group` (
  `classroom_id` int NOT NULL DEFAULT '-1',
  `group_id` int NOT NULL DEFAULT '-1',
  KEY `csug_gid_cid` (`group_id`,`classroom_id`),
  KEY `ciug_cid_gid` (`classroom_id`,`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_mobile_device_group`
--

DROP TABLE IF EXISTS `classroom_mobile_device_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_mobile_device_group` (
  `classroom_id` int NOT NULL DEFAULT '-1',
  `mobile_device_group_id` int NOT NULL DEFAULT '-1',
  KEY `cmdg_mdgid_cid` (`mobile_device_group_id`,`classroom_id`),
  KEY `cmdg_cid_mdgid` (`classroom_id`,`mobile_device_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_student_jss_user`
--

DROP TABLE IF EXISTS `classroom_student_jss_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_student_jss_user` (
  `classroom_id` int NOT NULL DEFAULT '-1',
  `user_object_id` int NOT NULL DEFAULT '-1',
  KEY `csju_uoid_cid` (`user_object_id`,`classroom_id`),
  KEY `csju_cid_uoid` (`classroom_id`,`user_object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classroom_student_user_group`
--

DROP TABLE IF EXISTS `classroom_student_user_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classroom_student_user_group` (
  `classroom_id` int NOT NULL DEFAULT '-1',
  `group_id` int NOT NULL DEFAULT '-1',
  KEY `csug_gid_cid` (`group_id`,`classroom_id`),
  KEY `csug_cid_gid` (`classroom_id`,`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `classrooms`
--

DROP TABLE IF EXISTS `classrooms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `classrooms` (
  `classroom_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_group_id` int NOT NULL DEFAULT '-1',
  `setting` longblob,
  `roster_class_id` int NOT NULL DEFAULT '-1',
  `beacon_id` int DEFAULT NULL,
  KEY `classroom_id` (`classroom_id`),
  KEY `roster_class_id` (`roster_class_id`),
  KEY `beacon_id` (`beacon_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `client_check_in`
--

DROP TABLE IF EXISTS `client_check_in`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_check_in` (
  `check_in_frequency` tinyint(1) NOT NULL DEFAULT '15',
  `create_startup_script` tinyint(1) NOT NULL DEFAULT '0',
  `startup_log` tinyint(1) NOT NULL DEFAULT '0',
  `startup_policies` tinyint(1) NOT NULL DEFAULT '0',
  `startup_ssh` tinyint(1) NOT NULL DEFAULT '0',
  `create_hooks` tinyint(1) NOT NULL DEFAULT '0',
  `hook_log` tinyint(1) NOT NULL DEFAULT '0',
  `hook_policies` tinyint(1) NOT NULL DEFAULT '0',
  `hook_display_status` tinyint(1) NOT NULL DEFAULT '0',
  `flush_management_history_on_remanage` tinyint(1) NOT NULL DEFAULT '0',
  `flush_location_information_on_remanage` tinyint(1) NOT NULL DEFAULT '1',
  `enable_local_configuration_profiles` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `client_security`
--

DROP TABLE IF EXISTS `client_security`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_security` (
  `enable_certificate_based_authentication` tinyint(1) NOT NULL DEFAULT '1',
  `enable_push_notifications` tinyint(1) NOT NULL DEFAULT '0',
  `max_clock_skew` int NOT NULL DEFAULT '-1',
  `verify_message_signatures` tinyint(1) NOT NULL DEFAULT '1',
  `require_certificate_communication` tinyint(1) NOT NULL DEFAULT '0',
  `package_validation_level` tinyint(1) NOT NULL DEFAULT '1',
  `enable_auto_privacy_preferences_install` tinyint(1) NOT NULL DEFAULT '1',
  `enable_auto_notifications_profile_install` tinyint(1) NOT NULL DEFAULT '1',
  `enable_auto_jamf_connect_pppc_install` tinyint(1) NOT NULL DEFAULT '0',
  `enable_auto_jamf_protect_pppc_install` tinyint(1) NOT NULL DEFAULT '0',
  `enable_auto_jamf_connect_notifications_profile_install` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_distribution_point`
--

DROP TABLE IF EXISTS `cloud_distribution_point`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_distribution_point` (
  `cloud_vendor` tinyint(1) NOT NULL DEFAULT '0',
  `master` tinyint(1) NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `directory` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cdn_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `upload_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `download_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cloud_distribution_point_inventory_id` int NOT NULL DEFAULT '-1',
  `last_inventory_epoch` bigint NOT NULL DEFAULT '0',
  `replication_type` int NOT NULL DEFAULT '0',
  `secondary_auth_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `secondary_auth_status_code` int NOT NULL DEFAULT '200',
  `secondary_auth_ttl` bigint NOT NULL DEFAULT '0',
  `amazon_sign_urls` tinyint(1) NOT NULL DEFAULT '0',
  `amazon_key_pair_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `amazon_expiration` bigint NOT NULL DEFAULT '0',
  `amazon_private_key_encrypted` mediumblob
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_distribution_point_inventory_files`
--

DROP TABLE IF EXISTS `cloud_distribution_point_inventory_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_distribution_point_inventory_files` (
  `cloud_distribution_point_inventory_file_id` bigint NOT NULL AUTO_INCREMENT,
  `cloud_distribution_point_inventory_id` int NOT NULL DEFAULT '-1',
  `type` int NOT NULL DEFAULT '-1',
  `file_object_id` int NOT NULL DEFAULT '-1',
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hash_type` tinyint(1) NOT NULL DEFAULT '-1',
  `hash_value` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Stores the hex representation of the hash value',
  `md5_hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Stores the hex representation of the MD5 hash',
  `last_modified_epoch` bigint NOT NULL DEFAULT '0',
  `size` bigint NOT NULL DEFAULT '0',
  `status` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'READY',
  `sha256` char(64) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sha3_512` char(128) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`cloud_distribution_point_inventory_file_id`),
  KEY `type` (`type`),
  KEY `file_object_id` (`file_object_id`),
  KEY `file_name` (`file_name`),
  KEY `hash_value` (`hash_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_distribution_point_upload`
--

DROP TABLE IF EXISTS `cloud_distribution_point_upload`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_distribution_point_upload` (
  `cloud_distribution_point_upload_id` int NOT NULL AUTO_INCREMENT,
  `cloud_distribution_point_id` int NOT NULL DEFAULT '-1',
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `started_epoch` bigint NOT NULL DEFAULT '0',
  `last_updated_epoch` bigint NOT NULL DEFAULT '0',
  `progress` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`cloud_distribution_point_upload_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_idp_configurations`
--

DROP TABLE IF EXISTS `cloud_idp_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_idp_configurations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `provider_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `display_name_unique` (`display_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_idp_ldap_configurations`
--

DROP TABLE IF EXISTS `cloud_idp_ldap_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_idp_ldap_configurations` (
  `id` int NOT NULL DEFAULT '-1',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `server_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_port` int NOT NULL DEFAULT '-1',
  `keystore_id` int NOT NULL DEFAULT '-1',
  `connection_timeout` int NOT NULL DEFAULT '-1',
  `search_timeout` int NOT NULL DEFAULT '-1',
  `use_wildcards` tinyint(1) NOT NULL DEFAULT '0',
  `domain_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_timestamp` bigint NOT NULL DEFAULT '0',
  `connection_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `membership_calculation_optimization_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_ldap_group_mappings`
--

DROP TABLE IF EXISTS `cloud_ldap_group_mappings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_ldap_group_mappings` (
  `configuration_id` int NOT NULL DEFAULT '-1',
  `group_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `group_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_class_limitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_classes` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_scope` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`configuration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_ldap_membership_mappings`
--

DROP TABLE IF EXISTS `cloud_ldap_membership_mappings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_ldap_membership_mappings` (
  `configuration_id` int NOT NULL DEFAULT '-1',
  `group_membership_mapping` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`configuration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cloud_ldap_user_mappings`
--

DROP TABLE IF EXISTS `cloud_ldap_user_mappings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cloud_ldap_user_mappings` (
  `configuration_id` int NOT NULL DEFAULT '-1',
  `user_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `real_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `department` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `building` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_class_limitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `additional_search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_classes` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_scope` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`configuration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `common_certificate_authority_settings`
--

DROP TABLE IF EXISTS `common_certificate_authority_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `common_certificate_authority_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '255',
  `type_id` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `complex_payload_sub_payloads`
--

DROP TABLE IF EXISTS `complex_payload_sub_payloads`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `complex_payload_sub_payloads` (
  `id` int NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `complex_payload_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_content_caching_cache_details`
--

DROP TABLE IF EXISTS `computer_content_caching_cache_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_content_caching_cache_details` (
  `computer_content_caching_cache_details_id` int NOT NULL AUTO_INCREMENT,
  `computer_content_caching_information_id` int NOT NULL DEFAULT '-1',
  `category_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `disk_space_used` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_content_caching_cache_details_id`),
  KEY `computer_content_caching_information_id` (`computer_content_caching_information_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_content_caching_information`
--

DROP TABLE IF EXISTS `computer_content_caching_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_content_caching_information` (
  `computer_content_caching_information_id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `activated` tinyint(1) NOT NULL DEFAULT '-1',
  `active` tinyint(1) NOT NULL DEFAULT '-1',
  `actual_cache_used` bigint NOT NULL DEFAULT '0',
  `cache_free` bigint NOT NULL DEFAULT '0',
  `cache_limit` bigint NOT NULL DEFAULT '0',
  `cache_status` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cache_used` bigint NOT NULL DEFAULT '0',
  `data_migration_completed` tinyint(1) NOT NULL DEFAULT '-1',
  `data_migration_progress` double(18,8) NOT NULL DEFAULT '0.00000000',
  `max_cache_pressure_last_1_hour` double(18,8) NOT NULL DEFAULT '0.00000000',
  `personal_cache_free` bigint NOT NULL DEFAULT '0',
  `personal_cache_limit` bigint NOT NULL DEFAULT '0',
  `personal_cache_used` bigint NOT NULL DEFAULT '0',
  `port` bigint NOT NULL DEFAULT '0',
  `public_address` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `registration_error` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `registration_response_code` bigint NOT NULL DEFAULT '0',
  `registration_started` bigint DEFAULT NULL,
  `registration_status` bigint NOT NULL DEFAULT '0',
  `restricted_media` tinyint(1) NOT NULL DEFAULT '-1',
  `server_guid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `startup_status` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `tetherator_status` bigint NOT NULL DEFAULT '0',
  `total_bytes_are_since` bigint DEFAULT NULL,
  `total_bytes_dropped` bigint NOT NULL DEFAULT '0',
  `total_bytes_imported` bigint NOT NULL DEFAULT '0',
  `total_bytes_returned_to_children` bigint NOT NULL DEFAULT '0',
  `total_bytes_returned_to_clients` bigint NOT NULL DEFAULT '0',
  `total_bytes_returned_to_peers` bigint NOT NULL DEFAULT '0',
  `total_bytes_stored_from_origin` bigint NOT NULL DEFAULT '0',
  `total_bytes_stored_from_parents` bigint NOT NULL DEFAULT '0',
  `total_bytes_stored_from_peers` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_content_caching_information_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_dep_prestage_device_assignments`
--

DROP TABLE IF EXISTS `computer_dep_prestage_device_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_dep_prestage_device_assignments` (
  `computer_dep_prestage_device_assignment_id` int NOT NULL AUTO_INCREMENT,
  `computer_dep_prestage_id` int NOT NULL DEFAULT '-1',
  `device_enrollment_program_device_serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `created_by` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_dep_prestage_device_assignment_id`),
  UNIQUE KEY `device_enrollment_program_device_serial_number_unique` (`device_enrollment_program_device_serial_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_dep_prestage_locations`
--

DROP TABLE IF EXISTS `computer_dep_prestage_locations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_dep_prestage_locations` (
  `computer_dep_prestage_location_id` int NOT NULL AUTO_INCREMENT,
  `computer_dep_prestage_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `building_id` int NOT NULL DEFAULT '-1',
  `department_id` int NOT NULL DEFAULT '-1',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_dep_prestage_location_id`),
  KEY `computer_dep_prestage_id` (`computer_dep_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_dep_prestage_purchasing`
--

DROP TABLE IF EXISTS `computer_dep_prestage_purchasing`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_dep_prestage_purchasing` (
  `computer_dep_prestage_purchasing_id` int NOT NULL AUTO_INCREMENT,
  `computer_dep_prestage_id` int NOT NULL DEFAULT '-1',
  `is_leased` tinyint(1) NOT NULL DEFAULT '0',
  `is_purchased` tinyint(1) NOT NULL DEFAULT '0',
  `applecare_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `po_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `vendor` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_price` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `life_expectancy` int NOT NULL DEFAULT '-1',
  `purchasing_account` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lease_date_epoch` bigint NOT NULL DEFAULT '0',
  `po_date_epoch` bigint NOT NULL DEFAULT '0',
  `warranty_date_epoch` bigint NOT NULL DEFAULT '0',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_dep_prestage_purchasing_id`),
  KEY `computer_dep_prestage_id` (`computer_dep_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_dep_prestage_skip_step_associations`
--

DROP TABLE IF EXISTS `computer_dep_prestage_skip_step_associations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_dep_prestage_skip_step_associations` (
  `computer_dep_prestage_skip_step_association_id` int NOT NULL AUTO_INCREMENT,
  `computer_dep_prestage_id` int NOT NULL DEFAULT '-1',
  `computer_dep_prestage_skip_step` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`computer_dep_prestage_skip_step_association_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_dep_prestages`
--

DROP TABLE IF EXISTS `computer_dep_prestages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_dep_prestages` (
  `computer_dep_prestage_id` int NOT NULL AUTO_INCREMENT,
  `device_enrollment_program_instance_id` int NOT NULL DEFAULT '-1',
  `profile_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_mandatory` tinyint(1) NOT NULL DEFAULT '0',
  `is_mdm_removable` tinyint(1) NOT NULL DEFAULT '0',
  `support_phone_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `support_email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_magic` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `department` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `require_authentication` tinyint(1) NOT NULL DEFAULT '0',
  `authentication_prompt` longtext COLLATE utf8mb3_unicode_ci,
  `anchor_certs` longblob,
  `enrollment_site_id` int NOT NULL DEFAULT '-1',
  `keep_existing_site_membership` tinyint(1) NOT NULL DEFAULT '0',
  `keep_existing_location_information` tinyint(1) NOT NULL DEFAULT '0',
  `default_prestage` tinyint(1) NOT NULL DEFAULT '0',
  `version_lock` bigint NOT NULL DEFAULT '0',
  `install_profiles_during_setup` tinyint(1) NOT NULL DEFAULT '0',
  `custom_package_distribution_point` int NOT NULL DEFAULT '-1',
  `enrollment_customization_id` int NOT NULL DEFAULT '0',
  `language` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `region` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `auto_advance_setup` tinyint(1) NOT NULL DEFAULT '0',
  `prevent_activation_lock` tinyint(1) NOT NULL DEFAULT '0',
  `enable_device_based_activation_lock` tinyint(1) NOT NULL DEFAULT '0',
  `enable_recovery_lock` tinyint(1) NOT NULL DEFAULT '0',
  `recovery_lock_password_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `recovery_lock_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `rotate_recovery_lock_password` tinyint(1) NOT NULL DEFAULT '0',
  `minimum_os_message` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_os_target_version` int NOT NULL DEFAULT '0',
  `minimum_os_specific_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `psso_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `platform_sso_app_bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `profile_url` varchar(2048) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `manifest_url` varchar(2048) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `auth_url` varchar(2048) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `psso_config_profile_id` int DEFAULT '-1',
  PRIMARY KEY (`computer_dep_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_group_memberships`
--

DROP TABLE IF EXISTS `computer_group_memberships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_group_memberships` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `computer_group_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `group_id_computer_id` (`computer_group_id`,`computer_id`),
  KEY `computer_id_group_id` (`computer_id`,`computer_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_groups`
--

DROP TABLE IF EXISTS `computer_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_groups` (
  `computer_group_id` int NOT NULL AUTO_INCREMENT,
  `computer_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_description` longtext COLLATE utf8mb3_unicode_ci,
  `is_smart_group` tinyint(1) NOT NULL DEFAULT '0',
  `requires_live_lookup` tinyint(1) NOT NULL DEFAULT '0',
  `notify_on_change` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_group_id`),
  KEY `is_smart_group` (`is_smart_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_installed_certificates`
--

DROP TABLE IF EXISTS `computer_installed_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_installed_certificates` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `common_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `issuer` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_data` mediumblob,
  `cert_blob_lookup_hash` binary(16) GENERATED ALWAYS AS (unhex(md5(cast(`certificate_data` as char charset binary)))) VIRTUAL,
  `is_identity` tinyint(1) NOT NULL DEFAULT '0',
  `expiration_date_epoch` bigint NOT NULL DEFAULT '0',
  `certificate_id` int NOT NULL DEFAULT '-1',
  KEY `computer_id` (`computer_id`),
  KEY `certificate_id` (`certificate_id`),
  KEY `cert_blob_lookup_hash` (`cert_blob_lookup_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_inventory_collection_custom_paths`
--

DROP TABLE IF EXISTS `computer_inventory_collection_custom_paths`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_inventory_collection_custom_paths` (
  `id` int NOT NULL AUTO_INCREMENT,
  `scope` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `path` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `platform` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `path` (`path`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_inventory_collection_preferences`
--

DROP TABLE IF EXISTS `computer_inventory_collection_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_inventory_collection_preferences` (
  `id` int NOT NULL AUTO_INCREMENT,
  `monitor_usage` tinyint(1) NOT NULL DEFAULT '0',
  `include_fonts` tinyint(1) NOT NULL DEFAULT '0',
  `include_plugins` tinyint(1) NOT NULL DEFAULT '0',
  `include_swu` tinyint(1) NOT NULL DEFAULT '0',
  `include_swid` tinyint(1) NOT NULL DEFAULT '1',
  `calculate_sizes` tinyint(1) NOT NULL DEFAULT '0',
  `include_packages` tinyint(1) NOT NULL DEFAULT '1',
  `include_accounts` tinyint(1) NOT NULL DEFAULT '1',
  `include_hidden_accounts` tinyint(1) NOT NULL DEFAULT '0',
  `include_printers` tinyint(1) NOT NULL DEFAULT '1',
  `include_services` tinyint(1) NOT NULL DEFAULT '1',
  `collect_synced_mobile_device_info` tinyint(1) NOT NULL DEFAULT '0',
  `update_ldap_info_on_computer_inventory_submissions` tinyint(1) NOT NULL DEFAULT '0',
  `monitor_beacons` tinyint(1) NOT NULL DEFAULT '0',
  `use_unix_user_paths` tinyint(1) NOT NULL DEFAULT '1',
  `allow_changing_user_and_location` tinyint(1) NOT NULL DEFAULT '1',
  `collect_unmanaged_certificates` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_mdm_applications`
--

DROP TABLE IF EXISTS `computer_mdm_applications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_mdm_applications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `application_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `application_version` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `application_short_version` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `application_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_size` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `external_version_identifier` bigint NOT NULL DEFAULT '0',
  `has_update_available` tinyint(1) NOT NULL DEFAULT '0',
  `installing` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `computer_id` (`computer_id`),
  KEY `application_identifier` (`application_identifier`),
  KEY `application_name` (`application_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_prestage_account_settings`
--

DROP TABLE IF EXISTS `computer_prestage_account_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_prestage_account_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `computer_prestage_id` int NOT NULL DEFAULT '-1',
  `admin_account_enabled` tinyint(1) NOT NULL DEFAULT '-1',
  `admin_account_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `admin_account_password_hash` mediumblob,
  `admin_account_hidden` tinyint(1) NOT NULL DEFAULT '-1',
  `admin_account_managed` tinyint(1) NOT NULL DEFAULT '0',
  `user_account_type` tinyint(1) NOT NULL DEFAULT '-1',
  `configured` tinyint(1) NOT NULL DEFAULT '-1',
  `prefill_feature_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `prefill_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `prefill_account_full_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `prefill_account_user_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `prefill_prevent_modification` tinyint(1) NOT NULL DEFAULT '0',
  `prefill_dont_auto_populate_from_ldap` tinyint(1) NOT NULL DEFAULT '0',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `computer_prestage_id` (`computer_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_prestage_configuration_profiles`
--

DROP TABLE IF EXISTS `computer_prestage_configuration_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_prestage_configuration_profiles` (
  `computer_dep_prestage_id` int NOT NULL DEFAULT '-1',
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  `payload_type` tinyint(1) NOT NULL DEFAULT '-1',
  KEY `computer_prestage_configuration_profile` (`computer_dep_prestage_id`,`configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_prestage_custom_packages`
--

DROP TABLE IF EXISTS `computer_prestage_custom_packages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_prestage_custom_packages` (
  `computer_prestage_custom_package_id` int NOT NULL AUTO_INCREMENT,
  `prestage_id` int NOT NULL DEFAULT '-1',
  `package_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`computer_prestage_custom_package_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_prestage_installed_configuration_profiles`
--

DROP TABLE IF EXISTS `computer_prestage_installed_configuration_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_prestage_installed_configuration_profiles` (
  `computer_prestage_installed_configuration_profile_id` int NOT NULL AUTO_INCREMENT,
  `computer_dep_prestage_id` int NOT NULL DEFAULT '-1',
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`computer_prestage_installed_configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_previous_certificates`
--

DROP TABLE IF EXISTS `computer_previous_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_previous_certificates` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `device_certificate` mediumblob,
  `date_created_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_security_info`
--

DROP TABLE IF EXISTS `computer_security_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_security_info` (
  `computer_security_info_id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `secure_boot_level` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `external_boot_level` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bootstrap_token` mediumblob,
  `bootstrap_token_allowed_sent_to_device` int NOT NULL DEFAULT '0',
  `bootstrap_token_allowed` int DEFAULT NULL,
  PRIMARY KEY (`computer_security_info_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_user_inventory_values`
--

DROP TABLE IF EXISTS `computer_user_inventory_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_user_inventory_values` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `password_require_alphanumeric` tinyint(1) DEFAULT NULL,
  `password_min_length` int DEFAULT NULL,
  `password_min_complex_characters` int DEFAULT NULL,
  `password_max_age_days` int DEFAULT NULL,
  `password_history_depth` int DEFAULT NULL,
  `password_max_failed_attempts` int DEFAULT NULL,
  `screen_saver_idle_time` int DEFAULT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  KEY `computer_id` (`computer_id`),
  KEY `computer_user_id` (`computer_id`,`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_user_pushtokens`
--

DROP TABLE IF EXISTS `computer_user_pushtokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_user_pushtokens` (
  `computer_user_pushtoken_id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `user_id` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_short_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `type` tinyint(1) NOT NULL DEFAULT '1',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `is_logged_in` tinyint(1) NOT NULL DEFAULT '1',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`computer_user_pushtoken_id`),
  KEY `computer_id` (`computer_id`),
  KEY `user_short_name` (`user_short_name`),
  KEY `management_id` (`management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computer_users`
--

DROP TABLE IF EXISTS `computer_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computer_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `last_logged_in_username_binary` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_logged_in_username_binary_timestamp` bigint DEFAULT NULL,
  `last_logged_in_username_self_service` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_logged_in_username_self_service_timestamp` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `computer_id_unique` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computers`
--

DROP TABLE IF EXISTS `computers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computers` (
  `computer_id` int NOT NULL AUTO_INCREMENT,
  `platform` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_certificate` mediumblob,
  `mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `network_adapter_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `alt_mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `alt_network_adapter_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_name` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `asset_tag` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_ip` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `last_reported_ipv4` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `last_reported_ipv6` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `bar_code_1` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bar_code_2` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `default_distribution_point_id` int NOT NULL DEFAULT '0',
  `default_software_update_server_id` int NOT NULL DEFAULT '-1',
  `default_distribution_server_id` int NOT NULL DEFAULT '-1',
  `jamf_version` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'n/a',
  `initial_entry_date_epoch` bigint NOT NULL DEFAULT '0',
  `mdm_access_rights` int NOT NULL DEFAULT '2047',
  `user_removed_mdm_profile` tinyint(1) NOT NULL DEFAULT '0',
  `device_push_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_vault_2_eligibility_message` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_cert_dirty` tinyint(1) NOT NULL DEFAULT '0',
  `requires_token_update` tinyint(1) NOT NULL DEFAULT '0',
  `logged_in_user` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `delay_user_mdm` tinyint(1) NOT NULL DEFAULT '0',
  `ble_capable` tinyint(1) NOT NULL DEFAULT '0',
  `sip_status` tinyint(1) NOT NULL DEFAULT '0',
  `gatekeeper_status` tinyint(1) NOT NULL DEFAULT '0',
  `xprotect_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `auto_login_user` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_store_account_is_active` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_store_account_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `awaiting_quick_add` tinyint(1) NOT NULL DEFAULT '0',
  `supports_ios_app_installs` tinyint(1) NOT NULL DEFAULT '0',
  `is_apple_silicon` tinyint(1) NOT NULL DEFAULT '0',
  `software_update_device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_recovery_lock_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `firewall_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `enrollment_type` int NOT NULL DEFAULT '0',
  `provisioning_udid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `file_vault_2_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`computer_id`),
  KEY `udid` (`udid`),
  KEY `management_id` (`management_id`),
  KEY `mac_address` (`mac_address`),
  KEY `alt_mac_address` (`alt_mac_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `computers_denormalized`
--

DROP TABLE IF EXISTS `computers_denormalized`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `computers_denormalized` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `computer_name` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_report_id` int NOT NULL DEFAULT '-1',
  `asset_tag` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `platform` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bar_code_1` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bar_code_2` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_contact_time_epoch` bigint NOT NULL DEFAULT '0',
  `last_report_date_epoch` bigint NOT NULL DEFAULT '0',
  `last_cloud_backup_date_epoch` bigint NOT NULL DEFAULT '0',
  `last_enrolled_date_epoch` bigint NOT NULL DEFAULT '0',
  `is_managed` tinyint(1) NOT NULL DEFAULT '0',
  `jamf_binary_version` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'n/a',
  `last_ip` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `last_reported_ipv4` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `last_reported_ipv6` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `last_location_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `department_id` int NOT NULL DEFAULT '-1',
  `building_id` int NOT NULL DEFAULT '-1',
  `department_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `building_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `make` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Apple',
  `model` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model_identifier` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `network_adapter_type` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `alt_mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `alt_network_adapter_type` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `nic_speed` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `optical_drive` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `boot_rom` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bus_speed_mhz` bigint NOT NULL DEFAULT '-1',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `processor_speed_mhz` bigint NOT NULL DEFAULT '-1',
  `processor_count` int NOT NULL DEFAULT '-1',
  `core_count` int NOT NULL DEFAULT '-1',
  `processor_type` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `processor_architecture` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `total_ram_mb` bigint NOT NULL DEFAULT '-1',
  `open_ram_slots` int NOT NULL DEFAULT '-1',
  `smc_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `battery_capacity` int NOT NULL DEFAULT '0',
  `battery_health` int NOT NULL DEFAULT '3',
  `file_vault_1_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'This is FV1 and FV2 user status',
  `file_vault_1_status_percent` int NOT NULL DEFAULT '-1' COMMENT 'This is FV1 and FV2 user status',
  `file_vault_2_status` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_vault_2_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `file_vault_2_recovery_key_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_vault_2_recovery_key_valid` tinyint(1) NOT NULL DEFAULT '3' COMMENT 'Maps to file_vault_2_computer_key.individual_key_verified',
  `file_vault_2_institutional_key_present` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'Maps to file_vault_2_computer_key.institutional_key_present',
  `file_vault_2_eligibility_message` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Maps to computers.file_vault_2_eligibility_message',
  `disk_encryption_configuration` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hard_drive_size_mb` bigint NOT NULL DEFAULT '-1',
  `smart_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lvm_managed_boot_partition` tinyint(1) NOT NULL DEFAULT '0',
  `boot_drive_percent_full` int NOT NULL DEFAULT '-1',
  `boot_drive_available_mb` bigint NOT NULL DEFAULT '-1',
  `operating_system_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_build` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_supplemental_build_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_supplemental_version_extra` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_comparable` int NOT NULL DEFAULT '0',
  `service_pack` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `master_password_set` tinyint(1) NOT NULL DEFAULT '0',
  `active_directory_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'N/A',
  `number_of_available_updates` tinyint(1) NOT NULL DEFAULT '0',
  `applecare_id` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `po_number` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `vendor` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `leased` tinyint(1) NOT NULL DEFAULT '0',
  `purchased` tinyint(1) NOT NULL DEFAULT '0',
  `lease_date_epoch` bigint NOT NULL DEFAULT '0',
  `po_date_epoch` bigint NOT NULL DEFAULT '0',
  `warranty_date_epoch` bigint NOT NULL DEFAULT '0',
  `purchase_price` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `life_expectancy` int NOT NULL DEFAULT '0',
  `purchasing_account` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ble_capable` tinyint(1) NOT NULL DEFAULT '0',
  `sip_status` tinyint(1) NOT NULL DEFAULT '0',
  `gatekeeper_status` tinyint(1) NOT NULL DEFAULT '0',
  `xprotect_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `auto_login_user` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_capability` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_store_account_is_active` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_store_account_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_certificate_expiration` bigint NOT NULL DEFAULT '-1',
  `mdm_certificate_expiration` bigint NOT NULL DEFAULT '-1',
  `enrolled_via_automated_device_enrollment` tinyint(1) NOT NULL DEFAULT '0',
  `user_approved_mdm` tinyint(1) NOT NULL DEFAULT '0',
  `remote_desktop_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `activation_lock_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `is_supervised` tinyint(1) NOT NULL DEFAULT '0',
  `is_activation_lock_manageable` tinyint(1) NOT NULL DEFAULT '0',
  `secure_boot_level` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `external_boot_level` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `jmf_settings_version` int NOT NULL DEFAULT '0',
  `supports_ios_app_installs` tinyint(1) NOT NULL DEFAULT '0',
  `is_recovery_lock_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `is_apple_silicon` tinyint(1) NOT NULL DEFAULT '0',
  `software_update_device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `firewall_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `declarative_device_management_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `enrollment_type` int NOT NULL DEFAULT '0',
  `provisioning_udid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `attestation_attempt_date_epoch` bigint DEFAULT NULL,
  `last_successful_attestation_date_epoch` bigint DEFAULT NULL,
  `managed_device_attestation_status_value` tinyint(1) NOT NULL DEFAULT '1',
  KEY `computer_id` (`computer_id`),
  KEY `computer_name` (`computer_name`),
  KEY `udid` (`udid`),
  KEY `management_id` (`management_id`),
  KEY `last_report_id` (`last_report_id`),
  KEY `asset_tag` (`asset_tag`),
  KEY `bar_code_1` (`bar_code_1`),
  KEY `bar_code_2` (`bar_code_2`),
  KEY `last_location_id` (`last_location_id`),
  KEY `username` (`username`),
  KEY `realname` (`realname`),
  KEY `email` (`email`),
  KEY `department_name` (`department_name`),
  KEY `building_name` (`building_name`),
  KEY `room` (`room`),
  KEY `position` (`position`),
  KEY `mac_address` (`mac_address`),
  KEY `alt_mac_address` (`alt_mac_address`),
  KEY `serial_number` (`serial_number`),
  KEY `cd_last_report_id_is_managed_computer_id` (`last_report_id`,`is_managed`,`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `conditional_access`
--

DROP TABLE IF EXISTS `conditional_access`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `conditional_access` (
  `conditional_access_id` int NOT NULL DEFAULT '-1',
  `client_secret` text COLLATE utf8mb3_unicode_ci,
  `tenant_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `tenant_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_app_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sovereign_domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `connection_type` tinyint(1) NOT NULL DEFAULT '0',
  `cloud_connector_registration_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cloud_connector_connection_state` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `authority_base_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `native_client_app_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `resource_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `resource_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ms_graph_resource_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `debug_domain` tinyint(1) NOT NULL DEFAULT '0',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `enabled_before` tinyint(1) NOT NULL DEFAULT '0',
  `device_registration_strategy` tinyint(1) NOT NULL DEFAULT '0',
  `custom_registration_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_deactivation_threshold` tinyint(1) NOT NULL DEFAULT '120',
  `registrant_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`conditional_access_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `conditional_access_devices`
--

DROP TABLE IF EXISTS `conditional_access_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `conditional_access_devices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_type` tinyint(1) NOT NULL DEFAULT '-1',
  `integration_type` tinyint(1) NOT NULL DEFAULT '-1',
  `compliance_state` tinyint(1) NOT NULL DEFAULT '-1',
  `compliance_changed` tinyint(1) NOT NULL DEFAULT '0',
  `details` json NOT NULL,
  `origin` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `compliance_changed_epoch` bigint NOT NULL DEFAULT '0',
  `compliance_sync_epoch` bigint NOT NULL DEFAULT '-1',
  `removal_epoch` bigint NOT NULL DEFAULT '-1',
  `tenant_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `applicable` tinyint(1) NOT NULL DEFAULT '0',
  `applicable_changed_epoch` bigint NOT NULL DEFAULT '-1',
  `failure_count` int NOT NULL DEFAULT '0',
  `shared_device_token_creation_timestamp` varchar(255) COLLATE utf8mb3_unicode_ci GENERATED ALWAYS AS (json_unquote(json_extract(`details`,_utf8mb4'$.sharedDeviceTokenCreationTimestamp'))) VIRTUAL,
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  KEY `integration_type` (`integration_type`),
  KEY `origin` (`origin`),
  KEY `shared_device_token_creation_timestamp` (`shared_device_token_creation_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `conditional_access_integrations`
--

DROP TABLE IF EXISTS `conditional_access_integrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `conditional_access_integrations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `integration_type` int NOT NULL DEFAULT '-1',
  `integration_state` int NOT NULL DEFAULT '1',
  `tenant_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `settings` json NOT NULL,
  `device_deactivation_threshold` bigint NOT NULL DEFAULT '10368000',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `config_profile_payloads`
--

DROP TABLE IF EXISTS `config_profile_payloads`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `config_profile_payloads` (
  `id` int NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `content` json NOT NULL,
  `config_profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `payload_type` (`payload_type`),
  KEY `config_profile_uuid` (`config_profile_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `config_profiles`
--

DROP TABLE IF EXISTS `config_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `config_profiles` (
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `os_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`uuid`),
  KEY `os_type` (`os_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `config_profiles_audit_data`
--

DROP TABLE IF EXISTS `config_profiles_audit_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `config_profiles_audit_data` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `config_profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `creation_date` datetime DEFAULT '1970-01-01 00:00:00',
  `created_version` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'n/a' COMMENT 'Jamf Pro version used to create the config profile',
  `updated_version` varchar(100) COLLATE utf8mb3_unicode_ci DEFAULT 'n/a' COMMENT 'Jamf Pro version used to edit the config profile',
  PRIMARY KEY (`id`),
  UNIQUE KEY `config_profile_uuid_unique` (`config_profile_uuid`),
  CONSTRAINT `fk_configuration_profiles` FOREIGN KEY (`config_profile_uuid`) REFERENCES `config_profiles` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `config_profiles_history`
--

DROP TABLE IF EXISTS `config_profiles_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `config_profiles_history` (
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payloads` json NOT NULL,
  `os_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `configurator_enrollment`
--

DROP TABLE IF EXISTS `configurator_enrollment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `configurator_enrollment` (
  `allow_url_enrollment` tinyint(1) NOT NULL DEFAULT '0',
  `allow_invitation_enrollment` tinyint(1) NOT NULL DEFAULT '0',
  `require_authentication` tinyint(1) NOT NULL DEFAULT '0',
  `authentication_prompt` longtext COLLATE utf8mb3_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_alerts`
--

DROP TABLE IF EXISTS `content_caching_alerts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_alerts` (
  `content_caching_alert_id` int NOT NULL AUTO_INCREMENT,
  `content_caching_info_id` int NOT NULL DEFAULT '-1',
  `cache_limit` bigint DEFAULT NULL,
  `class_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `path_preventing_access` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `post_date` bigint NOT NULL DEFAULT '-1',
  `reserved_volume_space` bigint DEFAULT NULL,
  `resource` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`content_caching_alert_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_information_data_migration_error`
--

DROP TABLE IF EXISTS `content_caching_information_data_migration_error`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_information_data_migration_error` (
  `content_caching_information_data_migration_error_id` int NOT NULL AUTO_INCREMENT,
  `computer_content_caching_information_id` int NOT NULL DEFAULT '-1',
  `code` bigint NOT NULL DEFAULT '0',
  `domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_info` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`content_caching_information_data_migration_error_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_parent`
--

DROP TABLE IF EXISTS `content_caching_parent`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_parent` (
  `content_caching_parent_id` int NOT NULL AUTO_INCREMENT,
  `content_caching_info_id` int NOT NULL DEFAULT '-1',
  `address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `content_caching_parent_alert_id` int DEFAULT NULL,
  `content_caching_parent_details_id` int NOT NULL DEFAULT '-1',
  `guid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `healthy` tinyint(1) NOT NULL DEFAULT '0',
  `port` int NOT NULL DEFAULT '-1',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`content_caching_parent_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_parent_alert`
--

DROP TABLE IF EXISTS `content_caching_parent_alert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_parent_alert` (
  `content_caching_parent_alert_id` int NOT NULL AUTO_INCREMENT,
  `content_caching_parent_id` int NOT NULL DEFAULT '-1',
  `class_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `post_date` bigint NOT NULL DEFAULT '-1',
  `addresses` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`content_caching_parent_alert_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_parent_capabilities`
--

DROP TABLE IF EXISTS `content_caching_parent_capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_parent_capabilities` (
  `content_caching_parent_capabilities_id` int NOT NULL AUTO_INCREMENT,
  `content_caching_parent_details_id` int NOT NULL DEFAULT '-1',
  `imports` tinyint(1) NOT NULL DEFAULT '0',
  `namespaces` tinyint(1) NOT NULL DEFAULT '0',
  `personal_content` tinyint(1) NOT NULL DEFAULT '0',
  `query_parameters` tinyint(1) NOT NULL DEFAULT '0',
  `shared_content` tinyint(1) NOT NULL DEFAULT '0',
  `prioritization` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`content_caching_parent_capabilities_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_parent_details`
--

DROP TABLE IF EXISTS `content_caching_parent_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_parent_details` (
  `content_caching_parent_details_id` int NOT NULL AUTO_INCREMENT,
  `content_caching_parent_id` int NOT NULL DEFAULT '-1',
  `ac_power` tinyint(1) NOT NULL DEFAULT '0',
  `cache_size` bigint NOT NULL DEFAULT '-1',
  `content_caching_capabilities_id` int NOT NULL DEFAULT '-1',
  `is_portable` tinyint(1) NOT NULL DEFAULT '0',
  `content_caching_local_network_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`content_caching_parent_details_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_caching_parent_local_network`
--

DROP TABLE IF EXISTS `content_caching_parent_local_network`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `content_caching_parent_local_network` (
  `content_caching_parent_local_network_id` int NOT NULL AUTO_INCREMENT,
  `content_caching_parent_details_id` int NOT NULL DEFAULT '-1',
  `speed` bigint NOT NULL DEFAULT '-1',
  `wired` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`content_caching_parent_local_network_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `csa_enablement`
--

DROP TABLE IF EXISTS `csa_enablement`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `csa_enablement` (
  `auth_code` varchar(8190) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_consumed_millis` bigint NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `csa_tokens`
--

DROP TABLE IF EXISTS `csa_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `csa_tokens` (
  `access_token` text COLLATE utf8mb3_unicode_ci NOT NULL,
  `refresh_token` text COLLATE utf8mb3_unicode_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `custom_disclaimer`
--

DROP TABLE IF EXISTS `custom_disclaimer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `custom_disclaimer` (
  `id` bigint NOT NULL DEFAULT '0',
  `include_disclaimer` tinyint(1) NOT NULL DEFAULT '0',
  `heading_text` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `main_text` varchar(2500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `action_text` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `custom_reports`
--

DROP TABLE IF EXISTS `custom_reports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `custom_reports` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `page_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `detailed` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `custom_settings_schema_source`
--

DROP TABLE IF EXISTS `custom_settings_schema_source`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `custom_settings_schema_source` (
  `bucket_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`bucket_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `database_schema_overrides`
--

DROP TABLE IF EXISTS `database_schema_overrides`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `database_schema_overrides` (
  `table_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `column_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `column_type` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `column_size` int NOT NULL DEFAULT '1',
  `default_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `extra_column` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `allow_null` tinyint(1) NOT NULL DEFAULT '0',
  `key_column` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `composite_key_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `comment_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `db_change_actions`
--

DROP TABLE IF EXISTS `db_change_actions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `db_change_actions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `processed_action` varchar(511) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'n/a',
  `status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'PENDING',
  `run_count` int NOT NULL DEFAULT '0',
  `last_run_date` datetime DEFAULT NULL,
  `first_run_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `version` (`version`)
) ENGINE=InnoDB AUTO_INCREMENT=83 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `db_schema_information`
--

DROP TABLE IF EXISTS `db_schema_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `db_schema_information` (
  `db_schema_information_id` int NOT NULL AUTO_INCREMENT,
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version_change_date_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`db_schema_information_id`),
  KEY `version` (`version`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_attribute`
--

DROP TABLE IF EXISTS `declarative_management_attribute`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_attribute` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `attribute_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `attribute_value` longtext COLLATE utf8mb3_unicode_ci,
  `last_update_epoch` bigint NOT NULL DEFAULT '0',
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_management_id_attribute_key` (`client_management_id`,`attribute_key`),
  KEY `client_management_id` (`client_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_declaration`
--

DROP TABLE IF EXISTS `declarative_management_declaration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_declaration` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `declaration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `declaration_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `declaration_json` json NOT NULL,
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `declaration_uuid_unique_key` (`declaration_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_dss_declaration`
--

DROP TABLE IF EXISTS `declarative_management_dss_declaration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_dss_declaration` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `declaration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `declaration_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_identifier_association`
--

DROP TABLE IF EXISTS `declarative_management_identifier_association`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_identifier_association` (
  `id` int NOT NULL AUTO_INCREMENT,
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `declaration_identifier` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `client_management_id` (`client_management_id`),
  KEY `declaration_identifier` (`declaration_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_organization_information`
--

DROP TABLE IF EXISTS `declarative_management_organization_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_organization_information` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_settings`
--

DROP TABLE IF EXISTS `declarative_management_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_settings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `dss_migrated` tinyint(1) NOT NULL DEFAULT '0',
  `csa_subject` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_status_subscription_association`
--

DROP TABLE IF EXISTS `declarative_management_status_subscription_association`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_status_subscription_association` (
  `id` int NOT NULL AUTO_INCREMENT,
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status_subscription_declaration_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `activation_declaration_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_management_id_unique` (`client_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `declarative_management_token`
--

DROP TABLE IF EXISTS `declarative_management_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `declarative_management_token` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `issued_time` bigint NOT NULL DEFAULT '0',
  `declaration_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `declaration_type` (`declaration_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `defined_foreign_keys`
--

DROP TABLE IF EXISTS `defined_foreign_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `defined_foreign_keys` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `column_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `constraint_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `referenced_table_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `referenced_column_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `table_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `table_name` (`table_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dep_devices_awaiting_conf_queue`
--

DROP TABLE IF EXISTS `dep_devices_awaiting_conf_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dep_devices_awaiting_conf_queue` (
  `id` int NOT NULL AUTO_INCREMENT,
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `prestage_commands_queued` tinyint(1) NOT NULL DEFAULT '0',
  `platform_sso_app_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `platform_sso_install_app_command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `platform_sso_app_list_retry_count` int NOT NULL DEFAULT '0',
  `platform_sso_app_installed` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_object_type_object_id` (`object_type`,`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dep_quick_add_packages`
--

DROP TABLE IF EXISTS `dep_quick_add_packages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dep_quick_add_packages` (
  `device_id` int NOT NULL DEFAULT '-1',
  `creation_date_epoch` bigint NOT NULL DEFAULT '0',
  `package_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `package_contents` longblob,
  `md5` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `size_bytes` int NOT NULL DEFAULT '-1',
  KEY `package_uuid` (`package_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `departments`
--

DROP TABLE IF EXISTS `departments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `departments` (
  `department_id` int NOT NULL AUTO_INCREMENT,
  `department_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`department_id`),
  KEY `departments_idx1` (`department_name`,`department_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `developer_certificate_identity`
--

DROP TABLE IF EXISTS `developer_certificate_identity`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `developer_certificate_identity` (
  `developer_certificate_identity_id` int NOT NULL AUTO_INCREMENT,
  `identity` mediumblob COMMENT 'developer certificate identity keystore',
  `keystore_password` text COLLATE utf8mb3_unicode_ci COMMENT 'password for the keystore',
  `certificate_filename` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`developer_certificate_identity_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_aad_information`
--

DROP TABLE IF EXISTS `device_aad_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_aad_information` (
  `device_aad_information_id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_aad_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `user_aad_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `tenant_aad_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `local_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `inventory_sent_epoch` bigint NOT NULL DEFAULT '0',
  `last_sent_to_ms_epoch` bigint NOT NULL DEFAULT '0',
  `last_sent_message_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_message_hash` int NOT NULL DEFAULT '0',
  `last_sent_inventory_json_array` text COLLATE utf8mb3_unicode_ci,
  `device_state` int NOT NULL DEFAULT '1',
  `is_deprecated` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`device_aad_information_id`),
  KEY `device_id` (`device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_activation_lock`
--

DROP TABLE IF EXISTS `device_activation_lock`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_activation_lock` (
  `mdm_activation_lock_id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `bypass_code_encrypted` text COLLATE utf8mb3_unicode_ci,
  `device_based_bypass_code_encrypted` text COLLATE utf8mb3_unicode_ci,
  `date_entered_epoch` bigint NOT NULL DEFAULT '0',
  `lock_cleared` tinyint(1) NOT NULL DEFAULT '0',
  `bypass_code_collected` tinyint(1) NOT NULL DEFAULT '0',
  `device_type` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`mdm_activation_lock_id`),
  KEY `device_id` (`device_id`),
  KEY `date_entered_epoch` (`date_entered_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_classroom_associations`
--

DROP TABLE IF EXISTS `device_classroom_associations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_classroom_associations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `classroom_id` int NOT NULL DEFAULT '-1',
  `device_object_id` int NOT NULL DEFAULT '-1',
  `device_role` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_id_classroom_object` (`device_id`,`device_object_id`,`classroom_id`,`device_role`),
  KEY `classroom_id_device_object` (`classroom_id`,`device_object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_common_detail`
--

DROP TABLE IF EXISTS `device_common_detail`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_common_detail` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `renew_mdm_profile_start_date_epoch` bigint DEFAULT NULL,
  `mdm_profile_needs_renewal_ca_renewed` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'This indicates that the MDM profile for a given device needs to be renewed due to the CA that issued its device identity certificate being renewed.',
  `mdm_profile_needs_renewal_device_identity_cert_expiring` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'This indicates that the MDM profile for a given device needs to be renewed due to device identity certificate expiring.',
  `mdm_checkin_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_server_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `management_id_unique` (`device_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_communication_settings`
--

DROP TABLE IF EXISTS `device_communication_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_communication_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `auto_renew_mobile_device_mdm_profile_when_ca_renewed` tinyint(1) NOT NULL DEFAULT '1' COMMENT 'This indicates that a mobile device will automatically renewal its mdm profile upon check-in if the root CA has been renewed.',
  `auto_renew_mobile_device_mdm_profile_when_dic_expiring` tinyint(1) NOT NULL DEFAULT '1' COMMENT 'This indicates that a mobile device will automatically renewal its mdm profile upon check-in if the device identity certificate is expiring.',
  `auto_renew_computer_mdm_profile_when_ca_renewed` tinyint(1) NOT NULL DEFAULT '1' COMMENT 'This indicates that a computer will automatically renewal its mdm profile upon check-in if the root CA has been renewed.',
  `auto_renew_computer_mdm_profile_when_dic_expiring` tinyint(1) NOT NULL DEFAULT '1' COMMENT 'This indicates that a computer will automatically renewal its mdm profile upon check-in if the device identity certificate is expiring.',
  `mdm_profile_mobile_device_expiration_limit_in_days` int NOT NULL DEFAULT '-1' COMMENT 'The number of days until the device identity certificate expires at which point the mobile device will be marked as needing to be renewed.',
  `mdm_profile_computer_expiration_limit_in_days` int NOT NULL DEFAULT '-1' COMMENT 'The number of days until the device identity certificate expires at which point the computer will be marked as needing to be renewed.',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_created_event`
--

DROP TABLE IF EXISTS `device_created_event`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_created_event` (
  `device_created_event_id` int NOT NULL AUTO_INCREMENT,
  `device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`device_created_event_id`),
  KEY `device_management_id` (`device_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_enrollment_account_details`
--

DROP TABLE IF EXISTS `device_enrollment_account_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_enrollment_account_details` (
  `device_enrollment_account_details_id` int NOT NULL AUTO_INCREMENT,
  `server_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `admin_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_id_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`device_enrollment_account_details_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_enrollment_instance_sync_state`
--

DROP TABLE IF EXISTS `device_enrollment_instance_sync_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_enrollment_instance_sync_state` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_enrollment_program_instance_id` int NOT NULL DEFAULT '-1',
  `status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `device_enrollment_program_instance_id` (`device_enrollment_program_instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_enrollment_program_devices`
--

DROP TABLE IF EXISTS `device_enrollment_program_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_enrollment_program_devices` (
  `device_enrollment_program_device_id` int NOT NULL AUTO_INCREMENT,
  `device_enrollment_program_instance_id` int NOT NULL DEFAULT '-1',
  `device_type` int NOT NULL DEFAULT '-1',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `color` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `asset_tag` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_assign_time_epoch` bigint NOT NULL DEFAULT '0',
  `profile_push_time_epoch` bigint NOT NULL DEFAULT '0',
  `device_assigned_date_epoch` bigint NOT NULL DEFAULT '0',
  `needs_assignment` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`device_enrollment_program_device_id`),
  KEY `device_type` (`device_type`),
  KEY `serial_number` (`serial_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_enrollment_program_instances`
--

DROP TABLE IF EXISTS `device_enrollment_program_instances`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_enrollment_program_instances` (
  `device_enrollment_program_instance_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'JSS-side value. The only user-editable field of this object.ts',
  `uploaded_token_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `consumer_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `consumer_secret_encrypted` text COLLATE utf8mb3_unicode_ci,
  `access_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `access_secret_encrypted` text COLLATE utf8mb3_unicode_ci,
  `access_token_expiry_date_epoch` bigint NOT NULL DEFAULT '0',
  `supervision_identity_id` int DEFAULT NULL,
  `account_details_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`device_enrollment_program_instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_enrollment_update_cursors`
--

DROP TABLE IF EXISTS `device_enrollment_update_cursors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_enrollment_update_cursors` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_enrollment_instance_id` int NOT NULL DEFAULT '-1',
  `per_request_limit` int NOT NULL DEFAULT '1000',
  `request_cursor` varchar(1001) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `request_cursor_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `device_enrollment_instance_id` (`device_enrollment_instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_name_pattern`
--

DROP TABLE IF EXISTS `device_name_pattern`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_name_pattern` (
  `device_name_pattern_id` int NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `delimiter_value` tinyint(1) NOT NULL DEFAULT '0',
  `criteria` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `device_name_pattern_id` (`device_name_pattern_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digicert_attribute_mapping`
--

DROP TABLE IF EXISTS `digicert_attribute_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digicert_attribute_mapping` (
  `attribute_mapping_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_mandatory` tinyint(1) NOT NULL DEFAULT '-1',
  `is_multiple` tinyint(1) NOT NULL DEFAULT '0',
  `is_fixed` tinyint(1) NOT NULL DEFAULT '0',
  `category` tinyint(1) NOT NULL DEFAULT '0',
  `digicert_cert_payload_settings_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`attribute_mapping_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digicert_cert_payload_settings`
--

DROP TABLE IF EXISTS `digicert_cert_payload_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digicert_cert_payload_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `seat_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_type` tinyint(1) NOT NULL DEFAULT '-1',
  `digicert_settings_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digicert_challenge_info`
--

DROP TABLE IF EXISTS `digicert_challenge_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digicert_challenge_info` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mdm_command_id` int NOT NULL DEFAULT '-1',
  `payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `pki_id` int NOT NULL DEFAULT '-1',
  `oid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `seat_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `passcode_encrypted` text COLLATE utf8mb3_unicode_ci,
  `status` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status_epoch` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `mdm_command_id` (`mdm_command_id`),
  KEY `dci_status_status_epoch_idx` (`status`,`status_epoch`),
  KEY `dci_payload_device_idx` (`payload_uuid`,`device_udid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digicert_scep_challenge_configuration`
--

DROP TABLE IF EXISTS `digicert_scep_challenge_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digicert_scep_challenge_configuration` (
  `id` int NOT NULL AUTO_INCREMENT,
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  `configuration_profile_type` int NOT NULL DEFAULT '-1',
  `symantec_pki_id` int NOT NULL DEFAULT '-1',
  `profile_oid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `seat_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `payload_identifier_unique` (`payload_identifier`),
  KEY `configuration_profile_id` (`configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digicert_settings`
--

DROP TABLE IF EXISTS `digicert_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digicert_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `ca_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_revocation_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `fqdn` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_cert` mediumblob,
  `client_cert_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `client_cert_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digicert_tlm_scep_challenge_configuration`
--

DROP TABLE IF EXISTS `digicert_tlm_scep_challenge_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digicert_tlm_scep_challenge_configuration` (
  `id` int NOT NULL AUTO_INCREMENT,
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  `configuration_profile_type` int NOT NULL DEFAULT '-1',
  `digicert_settings_id` int NOT NULL DEFAULT '-1',
  `profile_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `business_unit_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `seat_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `create_seat_type` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `payload_identifier_unique` (`payload_identifier`),
  KEY `configuration_profile_id` (`configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `directory_bindings`
--

DROP TABLE IF EXISTS `directory_bindings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `directory_bindings` (
  `directory_binding_id` int NOT NULL AUTO_INCREMENT,
  `directory_binding_type` int NOT NULL DEFAULT '1',
  `priority` int NOT NULL DEFAULT '0',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `forest` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password` text COLLATE utf8mb3_unicode_ci,
  `computer_ou` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cache_last_user` tinyint(1) NOT NULL DEFAULT '0',
  `require_confirmation` tinyint(1) NOT NULL DEFAULT '0',
  `local_home` tinyint(1) NOT NULL DEFAULT '1',
  `use_unc_path` tinyint(1) NOT NULL DEFAULT '1',
  `mount_style` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `default_shell` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '/bin/bash',
  `uid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_gid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `gid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `multiple_domains` tinyint(1) NOT NULL DEFAULT '1',
  `preferred_domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `admin_groups` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `perform_secure_bind` tinyint(1) NOT NULL DEFAULT '0',
  `use_for_authentication` tinyint(1) NOT NULL DEFAULT '0',
  `use_for_contacts` tinyint(1) NOT NULL DEFAULT '0',
  `encrypt_using_ssl` tinyint(1) NOT NULL DEFAULT '0',
  `mount_network_home` tinyint(1) NOT NULL DEFAULT '0',
  `place_home_folders` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home_directory` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cached_credentials` tinyint(1) NOT NULL DEFAULT '0',
  `add_user_to_local` tinyint(1) NOT NULL DEFAULT '0',
  `users_ou` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `groups_ou` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `printers_ou` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `shared_folders_ou` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `workstation_mode` tinyint(1) NOT NULL DEFAULT '0',
  `overwrite_existing` tinyint(1) NOT NULL DEFAULT '0',
  `update_pam` tinyint(1) NOT NULL DEFAULT '0',
  `zone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `preferred_domain_server` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`directory_binding_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `directory_group_user_membership`
--

DROP TABLE IF EXISTS `directory_group_user_membership`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `directory_group_user_membership` (
  `directory_group_id` bigint NOT NULL DEFAULT '-1',
  `directory_user_id` bigint NOT NULL DEFAULT '-1',
  `last_modified` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  UNIQUE KEY `unique_group_user` (`directory_group_id`,`directory_user_id`),
  KEY `fk_m2m_users` (`directory_user_id`),
  CONSTRAINT `fk_m2m_groups` FOREIGN KEY (`directory_group_id`) REFERENCES `directory_groups` (`directory_group_id`),
  CONSTRAINT `fk_m2m_users` FOREIGN KEY (`directory_user_id`) REFERENCES `directory_users` (`directory_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `directory_groups`
--

DROP TABLE IF EXISTS `directory_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `directory_groups` (
  `directory_group_id` bigint NOT NULL AUTO_INCREMENT,
  `directory_service_id` int NOT NULL DEFAULT '-1' COMMENT 'FK to ldap_servers to cloud_idp_configurations',
  `directory_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `directory_group_remote_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_modified` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`directory_group_id`),
  UNIQUE KEY `unique_group_name_per_service` (`directory_group_name`,`directory_service_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `directory_users`
--

DROP TABLE IF EXISTS `directory_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `directory_users` (
  `directory_user_id` bigint NOT NULL AUTO_INCREMENT,
  `directory_service_id` int NOT NULL DEFAULT '-1' COMMENT 'FK to ldap_servers to cloud_idp_configurations',
  `directory_user_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `directory_user_remote_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_modified` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`directory_user_id`),
  UNIQUE KEY `unique_user_name_per_service` (`directory_user_name`,`directory_service_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `distribution_points`
--

DROP TABLE IF EXISTS `distribution_points`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `distribution_points` (
  `distribution_point_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_address` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `share_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `file_sharing_connection_type` varchar(8) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `workgroup` varchar(30) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `file_sharing_read_only_username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `file_sharing_read_only_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `file_sharing_read_write_username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `file_sharing_read_write_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `file_sharing_port` int DEFAULT NULL,
  `master` tinyint(1) NOT NULL DEFAULT '0',
  `backup_distribution_point_id` int NOT NULL DEFAULT '-1',
  `enable_load_balancing` tinyint(1) NOT NULL DEFAULT '0',
  `ssh_username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `ssh_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `http_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `http_port` int DEFAULT NULL,
  `http_context` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `http_authentication_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'none',
  `http_username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `http_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `local_path_to_share` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`distribution_point_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `distribution_technology_settings`
--

DROP TABLE IF EXISTS `distribution_technology_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `distribution_technology_settings` (
  `script_migration_complete` tinyint(1) NOT NULL DEFAULT '0',
  `client_http_max_retry` int NOT NULL DEFAULT '300000'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dock_items`
--

DROP TABLE IF EXISTS `dock_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dock_items` (
  `dock_item_id` int NOT NULL AUTO_INCREMENT,
  `type` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `path` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `contents` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`dock_item_id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `edu_profile_deployment_hash`
--

DROP TABLE IF EXISTS `edu_profile_deployment_hash`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `edu_profile_deployment_hash` (
  `id` int NOT NULL AUTO_INCREMENT,
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hash` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`),
  UNIQUE KEY `command_uuid_idx` (`command_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `education_feature_settings`
--

DROP TABLE IF EXISTS `education_feature_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `education_feature_settings` (
  `setting_id` int NOT NULL DEFAULT '-1',
  `enable_education_profile` tinyint(1) NOT NULL DEFAULT '0',
  `enable_asm` tinyint(1) NOT NULL DEFAULT '0',
  `education_org_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enable_photos_server` tinyint(1) NOT NULL DEFAULT '0',
  `photos_server_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `student_photo_server_trust_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`setting_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `education_profile_event`
--

DROP TABLE IF EXISTS `education_profile_event`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `education_profile_event` (
  `education_profile_event_id` int NOT NULL AUTO_INCREMENT,
  `event_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`education_profile_event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `encryption_key`
--

DROP TABLE IF EXISTS `encryption_key`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `encryption_key` (
  `id` int NOT NULL DEFAULT '0',
  `encryption_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `key_encryption_key_name` varchar(1000) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `key_encryption_key_version` bigint DEFAULT NULL,
  `encryption_type` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `encryption_migration_process`
--

DROP TABLE IF EXISTS `encryption_migration_process`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `encryption_migration_process` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `table_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `encryption_used` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `encryption_salt`
--

DROP TABLE IF EXISTS `encryption_salt`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `encryption_salt` (
  `id` int NOT NULL AUTO_INCREMENT,
  `salt` varchar(64) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `encryption_settings`
--

DROP TABLE IF EXISTS `encryption_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `encryption_settings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `encryption_target` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `encryption_complete` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_access_groups`
--

DROP TABLE IF EXISTS `enrollment_access_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_access_groups` (
  `id` int NOT NULL AUTO_INCREMENT,
  `group_type` tinyint(1) NOT NULL DEFAULT '-1',
  `group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `group_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ldap_server_id` int NOT NULL DEFAULT '-1',
  `enable_enterprise_enrollment` tinyint(1) NOT NULL DEFAULT '-1',
  `enable_byo_enrollment` tinyint(1) NOT NULL DEFAULT '-1',
  `enable_account_driven_enrollment` tinyint(1) NOT NULL DEFAULT '0',
  `require_eula` tinyint(1) NOT NULL DEFAULT '-1',
  `site_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_associations`
--

DROP TABLE IF EXISTS `enrollment_associations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_associations` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `enrollment_object_type` int NOT NULL DEFAULT '-1',
  `enrollment_object_id` int NOT NULL DEFAULT '-1',
  `enrollment_date_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `object_id` (`object_id`),
  KEY `object_type_object_id` (`object_type`,`object_id`),
  KEY `enrollment_object_type_and_id` (`enrollment_object_type`,`enrollment_object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization`
--

DROP TABLE IF EXISTS `enrollment_customization`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_branding_image`
--

DROP TABLE IF EXISTS `enrollment_customization_branding_image`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_branding_image` (
  `id` int NOT NULL AUTO_INCREMENT,
  `image_data` longblob,
  `image_content_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_branding_settings`
--

DROP TABLE IF EXISTS `enrollment_customization_branding_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_branding_settings` (
  `enrollment_customization_id` int NOT NULL DEFAULT '-1',
  `text_color` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `button_color` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `button_text_color` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `background_color` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `icon_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`enrollment_customization_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_ldap_group_access`
--

DROP TABLE IF EXISTS `enrollment_customization_ldap_group_access`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_ldap_group_access` (
  `id` int NOT NULL AUTO_INCREMENT,
  `enrollment_customization_panel_id` int NOT NULL DEFAULT '-1',
  `ldap_server_id` int NOT NULL DEFAULT '-1',
  `group_name` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `enrollment_customization_panel_id` (`enrollment_customization_panel_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_panel`
--

DROP TABLE IF EXISTS `enrollment_customization_panel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_panel` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` text COLLATE utf8mb3_unicode_ci,
  `enrollment_customization_id` int NOT NULL DEFAULT '-1',
  `rank_order` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `enrollment_customization_id` (`enrollment_customization_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_panel_ldap_auth`
--

DROP TABLE IF EXISTS `enrollment_customization_panel_ldap_auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_panel_ldap_auth` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username_label` text COLLATE utf8mb3_unicode_ci,
  `password_label` text COLLATE utf8mb3_unicode_ci,
  `title` text COLLATE utf8mb3_unicode_ci NOT NULL,
  `continue_button_text` text COLLATE utf8mb3_unicode_ci,
  `back_button_text` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_panel_sso_auth`
--

DROP TABLE IF EXISTS `enrollment_customization_panel_sso_auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_panel_sso_auth` (
  `id` int NOT NULL AUTO_INCREMENT,
  `use_jamf_connect` tinyint(1) NOT NULL DEFAULT '-1',
  `isGroupEnrollmentAccessEnabled` tinyint(1) NOT NULL DEFAULT '-1',
  `groupEnrollmentAccessName` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `long_name_attribute` text COLLATE utf8mb3_unicode_ci,
  `short_name_attribute` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_customization_panel_text`
--

DROP TABLE IF EXISTS `enrollment_customization_panel_text`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_customization_panel_text` (
  `id` int NOT NULL AUTO_INCREMENT,
  `body` text COLLATE utf8mb3_unicode_ci,
  `subtext` text COLLATE utf8mb3_unicode_ci,
  `title` text COLLATE utf8mb3_unicode_ci NOT NULL,
  `back_button_text` text COLLATE utf8mb3_unicode_ci,
  `continue_button_text` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_invitation_management_account`
--

DROP TABLE IF EXISTS `enrollment_invitation_management_account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_invitation_management_account` (
  `id` int NOT NULL AUTO_INCREMENT,
  `enrollment_invitation_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `create_account_if_does_not_exist` tinyint(1) NOT NULL DEFAULT '0',
  `hide_account` tinyint(1) NOT NULL DEFAULT '0',
  `lock_down_ssh` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `enrollment_invitation_id` (`enrollment_invitation_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_invitation_supported_device_types`
--

DROP TABLE IF EXISTS `enrollment_invitation_supported_device_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_invitation_supported_device_types` (
  `device_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `invitation_id` int NOT NULL DEFAULT '-1',
  UNIQUE KEY `invitation_device_type` (`invitation_id`,`device_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_invitation_usage`
--

DROP TABLE IF EXISTS `enrollment_invitation_usage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_invitation_usage` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int DEFAULT '-1',
  `device_type` varchar(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `enrollment_invitation_id` int NOT NULL DEFAULT '-1',
  `device_udid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `requires_binary` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_udid_enrollment_invitation_id_key` (`device_udid`,`enrollment_invitation_id`),
  KEY `enrollment_invitation_id` (`enrollment_invitation_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_invitations`
--

DROP TABLE IF EXISTS `enrollment_invitations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_invitations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `invitation_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `invitation_string` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `require_login` tinyint(1) NOT NULL DEFAULT '1',
  `allow_multiple_uses` tinyint(1) NOT NULL DEFAULT '0',
  `enroll_into_site_id` int NOT NULL DEFAULT '-1',
  `keep_existing_site_membership` tinyint(1) NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `logged_in_user` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `expiration_date_epoch` bigint NOT NULL DEFAULT '0',
  `sent_to` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sent_from` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `reply_to` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `subject` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `message` longtext COLLATE utf8mb3_unicode_ci,
  `date_sent_epoch` bigint DEFAULT '0',
  `invitation_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_status_update_epoch` bigint NOT NULL DEFAULT '0',
  `use_count` int NOT NULL DEFAULT '0',
  `is_personal` tinyint(1) NOT NULL DEFAULT '0',
  `managed_apple_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `invitation_string` (`invitation_string`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_process_localized_strings`
--

DROP TABLE IF EXISTS `enrollment_process_localized_strings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_process_localized_strings` (
  `language_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `title` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `login_description` longtext COLLATE utf8mb3_unicode_ci,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `login_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `logout_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_class_description` longtext COLLATE utf8mb3_unicode_ci,
  `device_class_byo` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_class_enterprise` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_class_byo_description` longtext COLLATE utf8mb3_unicode_ci,
  `device_class_enterprise_description` longtext COLLATE utf8mb3_unicode_ci,
  `device_class_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `byo_eula` longtext COLLATE utf8mb3_unicode_ci,
  `enterprise_eula` longtext COLLATE utf8mb3_unicode_ci,
  `eula_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `site_description` longtext COLLATE utf8mb3_unicode_ci,
  `certificate_text` longtext COLLATE utf8mb3_unicode_ci,
  `certificate_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_profile_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_profile_description` longtext COLLATE utf8mb3_unicode_ci,
  `user_enrollment_text` longtext COLLATE utf8mb3_unicode_ci,
  `user_enrollment_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_enrollment_profile_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_enrollment_profile_description` longtext COLLATE utf8mb3_unicode_ci,
  `enterprise_text` longtext COLLATE utf8mb3_unicode_ci,
  `enterprise_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enterprise_profile_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enterprise_profile_description` longtext COLLATE utf8mb3_unicode_ci,
  `enterprise_pending` longtext COLLATE utf8mb3_unicode_ci,
  `quick_add_text` longtext COLLATE utf8mb3_unicode_ci,
  `quick_add_button` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `quick_add_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `quick_add_pending` longtext COLLATE utf8mb3_unicode_ci,
  `complete_message` longtext COLLATE utf8mb3_unicode_ci,
  `failed_message` longtext COLLATE utf8mb3_unicode_ci,
  `try_again_button` longtext COLLATE utf8mb3_unicode_ci,
  `check_now_button` longtext COLLATE utf8mb3_unicode_ci,
  `check_enrollment_message` longtext COLLATE utf8mb3_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_profile_enrollment_history`
--

DROP TABLE IF EXISTS `enrollment_profile_enrollment_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_profile_enrollment_history` (
  `enrollment_profile_id` int NOT NULL DEFAULT '-1',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `enrolled_date_epoch` bigint NOT NULL DEFAULT '0',
  KEY `enrollment_profile_id` (`enrollment_profile_id`),
  KEY `mobile_device_id` (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_profiles`
--

DROP TABLE IF EXISTS `enrollment_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_profiles` (
  `enrollment_profile_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `phone` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `department_id` int NOT NULL DEFAULT '-1',
  `building_id` int NOT NULL DEFAULT '-1',
  `room` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enroll_into_site_id` int NOT NULL DEFAULT '-1',
  `keep_existing_site_membership` tinyint(1) NOT NULL DEFAULT '0',
  `checkout_when_removed` tinyint(1) NOT NULL DEFAULT '0',
  `use_ipcu` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`enrollment_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enrollment_settings`
--

DROP TABLE IF EXISTS `enrollment_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `enrollment_settings` (
  `id` tinyint(1) NOT NULL DEFAULT '-1',
  `restrict_reenrollment` tinyint(1) NOT NULL DEFAULT '0',
  `single_profile` tinyint(1) NOT NULL DEFAULT '0',
  `computer_enterprise_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `management_account_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `create_account` tinyint(1) NOT NULL DEFAULT '0',
  `configure_ssh` tinyint(1) NOT NULL DEFAULT '0',
  `hide_account` tinyint(1) NOT NULL DEFAULT '0',
  `launch_self_service` tinyint(1) NOT NULL DEFAULT '0',
  `start_ssh` tinyint(1) NOT NULL DEFAULT '0',
  `developer_certificate_identity_id` int NOT NULL DEFAULT '-1',
  `login_image` mediumblob COMMENT 'a custom image for the osx enrollment login page',
  `login_image_filename` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'The original filename for the uploaded image',
  `ios_enterprise_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `ios_byo_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `package_signing_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `mdm_signing_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `mdm_signing_cert_id` int NOT NULL DEFAULT '-1',
  `account_driven_user_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `account_driven_device_ios_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `account_driven_device_macos_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `account_driven_user_visionos_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `account_driven_device_visionos_enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `maid_user_enrollment_username_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `entrust_scep_challenge_configuration`
--

DROP TABLE IF EXISTS `entrust_scep_challenge_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `entrust_scep_challenge_configuration` (
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `scep_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `digital_id_configuration` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `entrust_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `api_server_certificate` mediumblob COMMENT 'Server certificate used for SSL trust to Entrust API endpoint',
  `rdn_variables` text COLLATE utf8mb3_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `eula_acceptance_logs`
--

DROP TABLE IF EXISTS `eula_acceptance_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `eula_acceptance_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `eula_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `jss_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp_epoch` bigint NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ip_address` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `accepted` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_logs`
--

DROP TABLE IF EXISTS `event_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `event_type` varchar(25) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `event_status` varchar(25) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `event_timestamp_utc` bigint NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `object_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_type` int NOT NULL DEFAULT '-1',
  `device_id` int NOT NULL DEFAULT '-1',
  `device_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_serial` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `site_id` int NOT NULL DEFAULT '-1',
  `device_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `site_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `status_details` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `site_id` (`site_id`),
  KEY `object_type_object_id_idx` (`object_type`,`object_id`),
  KEY `event_timestamp_utc_device_serial_idx` (`event_timestamp_utc`,`device_serial`),
  KEY `device_id_device_type_object_id_object_type_idx` (`device_id`,`device_type`,`object_id`,`object_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_tracking`
--

DROP TABLE IF EXISTS `event_tracking`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_tracking` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `event_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `event_key` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `occurred_at` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `created_by` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `metadata` json DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_event` (`event_type`,`event_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `extension_attribute_popup_choices`
--

DROP TABLE IF EXISTS `extension_attribute_popup_choices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `extension_attribute_popup_choices` (
  `extension_attribute_id` int NOT NULL DEFAULT '-1',
  `choice` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `extension_attribute_values`
--

DROP TABLE IF EXISTS `extension_attribute_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `extension_attribute_values` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `extension_attribute_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `value_on_client` longtext COLLATE utf8mb3_unicode_ci,
  `date_value_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `computer_id_extension_attribute_id` (`computer_id`,`extension_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `extension_attributes`
--

DROP TABLE IF EXISTS `extension_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `extension_attributes` (
  `extension_attribute_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `data_type` tinyint(1) NOT NULL DEFAULT '0',
  `type` tinyint(1) NOT NULL DEFAULT '0',
  `display_in_section` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `platform` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'osx',
  `script_contents_mac` longtext COLLATE utf8mb3_unicode_ci,
  `script_contents_windows` longtext COLLATE utf8mb3_unicode_ci,
  `script_type_windows` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checked` tinyint(1) NOT NULL DEFAULT '0',
  `ldap_attribute_mapping` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `patch_extension_attribute_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ldap_extension_attribute_allowed` tinyint(1) NOT NULL DEFAULT '0',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`extension_attribute_id`),
  KEY `display_name` (`display_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `extension_attributes_templates`
--

DROP TABLE IF EXISTS `extension_attributes_templates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `extension_attributes_templates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=224 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_certificate_authority_settings`
--

DROP TABLE IF EXISTS `external_certificate_authority_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `external_certificate_authority_settings` (
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `external_certificate_authority_id` int NOT NULL AUTO_INCREMENT,
  `scep_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_subject` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_alternative_subject_name_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'None',
  `scep_challenge_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_challenge_encrypted` text COLLATE utf8mb3_unicode_ci,
  `scep_key_size` int NOT NULL DEFAULT '1024',
  `scep_use_as_digital_signature` tinyint(1) NOT NULL DEFAULT '0',
  `scep_use_for_encipherment` tinyint(1) NOT NULL DEFAULT '0',
  `scep_fingerprint` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enrollment_scep` tinyint(1) NOT NULL DEFAULT '0',
  `legacy_mode` tinyint(1) NOT NULL DEFAULT '1',
  `enrollment_scep_proxy` tinyint(1) NOT NULL DEFAULT '0',
  `config_scep_proxy` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`external_certificate_authority_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_communication_settings`
--

DROP TABLE IF EXISTS `external_communication_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `external_communication_settings` (
  `external_communication_settings_id` int NOT NULL AUTO_INCREMENT,
  `proxy_type` int NOT NULL DEFAULT '-1',
  `http_proxy_host` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `http_proxy_port` int NOT NULL DEFAULT '-1',
  `http_proxy_auth_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `http_proxy_auth_password` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`external_communication_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `feature_metric`
--

DROP TABLE IF EXISTS `feature_metric`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `feature_metric` (
  `id` int NOT NULL AUTO_INCREMENT,
  `feature_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `metric_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `num_hits` int NOT NULL DEFAULT '0',
  `avg_time` int DEFAULT NULL,
  `last_modified_epoch` bigint NOT NULL DEFAULT '0',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `feature_metric_unique` (`feature_name`,`metric_name`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `file_extension_white_list`
--

DROP TABLE IF EXISTS `file_extension_white_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `file_extension_white_list` (
  `id` int NOT NULL AUTO_INCREMENT,
  `extension` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=146 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `file_vault_2`
--

DROP TABLE IF EXISTS `file_vault_2`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `file_vault_2` (
  `file_vault_2_id` int NOT NULL AUTO_INCREMENT,
  `key_type` int NOT NULL DEFAULT '10' COMMENT '0 indicates this instance of fv2 is set up with individual keys, 1 indicates institutional and 2 indicates hybrid.',
  `file_vault_2_certificate_id` int DEFAULT NULL COMMENT 'A link to the file_vault_2_certificate associated with this filevault 2 instance. Empty indicates an individual key type.',
  `management_account_enabled` tinyint(1) NOT NULL DEFAULT '1' COMMENT 'true if this fv2 instance will use the management account to encrypt the drive',
  `defer` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'true if process should defer user additions until logout',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'user friendly name to display',
  PRIMARY KEY (`file_vault_2_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `file_vault_2_certificate`
--

DROP TABLE IF EXISTS `file_vault_2_certificate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `file_vault_2_certificate` (
  `file_vault_2_certificate_id` int NOT NULL AUTO_INCREMENT,
  `contents` mediumblob COMMENT 'The DER encoded cert or p12 that is associated with unlocking a computer',
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci COMMENT 'The password associated with the contents field if content_type is pkcs12',
  `certificate_content_type` tinyint NOT NULL DEFAULT '-1' COMMENT 'This specifies if the content field is a cert or p12',
  PRIMARY KEY (`file_vault_2_certificate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `file_vault_2_computer_key`
--

DROP TABLE IF EXISTS `file_vault_2_computer_key`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `file_vault_2_computer_key` (
  `id` int NOT NULL AUTO_INCREMENT,
  `file_vault_2_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `file_vault_2_certificate_id` int NOT NULL DEFAULT '-1',
  `individual_key_encrypted` text COLLATE utf8mb3_unicode_ci COMMENT 'The individual key associated with this computer. May be encrypted if collected via SecurityInfo. This will be empty if the fv2 instance is institution.',
  `individual_key_device_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Device Key collected from SecurityInfo in 10.13 and later',
  `disk` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Including this as a possible placeholder for the future UUID of the encrypted disk',
  `individual_key_verified` tinyint(1) NOT NULL DEFAULT '3' COMMENT 'If key matches and is valid for computer.',
  `institutional_key_present` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'If computer has an institutinal key for encryption',
  `key_deleted` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'This indicates the key should be considered deleted but the row is kept for historical purposes',
  PRIMARY KEY (`id`),
  KEY `file_vault_2_id` (`file_vault_2_id`),
  KEY `computer_id` (`computer_id`),
  KEY `file_vault_2_certificate_id` (`file_vault_2_certificate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `file_vault_2_users`
--

DROP TABLE IF EXISTS `file_vault_2_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `file_vault_2_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  PRIMARY KEY (`id`),
  KEY `computer_id` (`computer_id`),
  KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `font_details`
--

DROP TABLE IF EXISTS `font_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `font_details` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `path` varchar(2000) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `font_history`
--

DROP TABLE IF EXISTS `font_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `font_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '0',
  `computer_id` int NOT NULL DEFAULT '-1',
  `font_details_id` int NOT NULL DEFAULT '-1',
  `font_history_type` varchar(4) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `font_history_key` (`report_id`,`font_details_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `fonts`
--

DROP TABLE IF EXISTS `fonts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `fonts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '0',
  `computer_id` int NOT NULL DEFAULT '-1',
  `font_details_id` int NOT NULL DEFAULT '-1',
  `timestamp_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`report_id`,`id`),
  KEY `id` (`id`),
  KEY `report_id` (`report_id`),
  KEY `font_details_id` (`font_details_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `google_mail_authentication`
--

DROP TABLE IF EXISTS `google_mail_authentication`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `google_mail_authentication` (
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `access_token_encrypted` text COLLATE utf8mb3_unicode_ci,
  `refresh_token_encrypted` text COLLATE utf8mb3_unicode_ci,
  `status` int NOT NULL DEFAULT '-1',
  `expiration_date` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`email_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `google_mail_authentication_temp`
--

DROP TABLE IF EXISTS `google_mail_authentication_temp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `google_mail_authentication_temp` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `access_token_encrypted` text COLLATE utf8mb3_unicode_ci,
  `refresh_token_encrypted` text COLLATE utf8mb3_unicode_ci,
  `status` int NOT NULL DEFAULT '-1',
  `expiration_date` bigint NOT NULL DEFAULT '0',
  `google_oauth_state_encrypted` text COLLATE utf8mb3_unicode_ci,
  `google_oauth_state_encrypted_lookup_hash` varchar(256) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `google_oauth_state_encrypted_lookup_hash` (`google_oauth_state_encrypted_lookup_hash`),
  KEY `email_address_oauth_state` (`email_address`,`google_oauth_state_encrypted_lookup_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `group_recalculation_times`
--

DROP TABLE IF EXISTS `group_recalculation_times`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `group_recalculation_times` (
  `seconds_after_midnight` int NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `gsx_connection`
--

DROP TABLE IF EXISTS `gsx_connection`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `gsx_connection` (
  `gsx_connection_id` int NOT NULL DEFAULT '0',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `account_no` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `shipto_no` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uri` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `token` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`gsx_connection_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hard_drive_partitions`
--

DROP TABLE IF EXISTS `hard_drive_partitions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hard_drive_partitions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '0',
  `disk` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `partition_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `partition_type` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `size_mb` bigint NOT NULL DEFAULT '-1',
  `available_mb` bigint NOT NULL DEFAULT '-1',
  `used` int NOT NULL DEFAULT '-1',
  `filevault_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `filevault_percent` int NOT NULL DEFAULT '-1',
  `filevault_2_state` int NOT NULL DEFAULT '0',
  `lvg_UUID` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lv_UUID` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `pv_UUID` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lvf_UUID` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lvm_managed` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `hdp_report_id_disk` (`report_id`,`disk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hard_drives`
--

DROP TABLE IF EXISTS `hard_drives`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hard_drives` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '0',
  `disk` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model` varchar(80) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serial` varchar(80) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `size_mb` bigint NOT NULL DEFAULT '-1',
  `smart_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `report_id` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hardware_reports`
--

DROP TABLE IF EXISTS `hardware_reports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hardware_reports` (
  `report_id` int NOT NULL DEFAULT '0',
  `model_identifier` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `processor_speed_mhz` bigint NOT NULL DEFAULT '-1',
  `processor_count` int NOT NULL DEFAULT '-1',
  `core_count` int NOT NULL DEFAULT '-1',
  `bus_speed_mhz` bigint NOT NULL DEFAULT '-1',
  `cache_size_kb` bigint NOT NULL DEFAULT '-1',
  `nic_speed` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `optical_drive` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `total_ram_mb` bigint NOT NULL DEFAULT '-1',
  `open_ram_slots` int NOT NULL DEFAULT '-1',
  `make` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Apple',
  `processor_type` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `processor_architecture` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `smc_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `battery_capacity` int NOT NULL DEFAULT '0',
  `battery_health` int NOT NULL DEFAULT '3',
  KEY `report_id` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hcl_command_status`
--

DROP TABLE IF EXISTS `hcl_command_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hcl_command_status` (
  `id` int NOT NULL AUTO_INCREMENT,
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hcl_id` int NOT NULL DEFAULT '-1',
  `hcl_rule_id` int NOT NULL DEFAULT '-1',
  `hcl_threshold_epoch` bigint NOT NULL DEFAULT '-1',
  `command` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `correlation_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_command_uuid` (`command_uuid`),
  KEY `hcl_rule_id` (`hcl_rule_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hcl_settings`
--

DROP TABLE IF EXISTS `hcl_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hcl_settings` (
  `hcl_id` int NOT NULL AUTO_INCREMENT,
  `jsam_id` int NOT NULL DEFAULT '-1',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `port` int NOT NULL DEFAULT '-1',
  `version` int NOT NULL DEFAULT '-1',
  `single_ips` text COLLATE utf8mb3_unicode_ci,
  `range_ips` text COLLATE utf8mb3_unicode_ci,
  `hcl_status` text COLLATE utf8mb3_unicode_ci,
  `bundle_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`hcl_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hcl_settings_rule`
--

DROP TABLE IF EXISTS `hcl_settings_rule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hcl_settings_rule` (
  `hcl_rule_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hcl_id` int NOT NULL DEFAULT '-1',
  `mdm_capable_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hcl_command_template` text COLLATE utf8mb3_unicode_ci,
  `adt_message` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `adt_message_field` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_inventory_field` int NOT NULL DEFAULT '-1',
  `device_inventory_field_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `notification_enable` tinyint(1) NOT NULL DEFAULT '0',
  `notify_on_unsupported_device` tinyint(1) NOT NULL DEFAULT '0',
  `notification_threshold` int NOT NULL DEFAULT '15',
  `notification_emails` text COLLATE utf8mb3_unicode_ci,
  `enable_test_mode` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`hcl_rule_id`),
  KEY `hcl_id` (`hcl_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hibernate_sequences`
--

DROP TABLE IF EXISTS `hibernate_sequences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hibernate_sequences` (
  `sequence_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `next_value` int NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hidden_files`
--

DROP TABLE IF EXISTS `hidden_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hidden_files` (
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `file_type` (`file_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibeacon_device_proximities`
--

DROP TABLE IF EXISTS `ibeacon_device_proximities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibeacon_device_proximities` (
  `ibeacon_id` int NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `proximity` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp_epoch` bigint NOT NULL DEFAULT '-1',
  KEY `object_id` (`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibeacons`
--

DROP TABLE IF EXISTS `ibeacons`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibeacons` (
  `ibeacon_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `major_value` int NOT NULL DEFAULT '-1',
  `minor_value` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`ibeacon_id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibook_deployment`
--

DROP TABLE IF EXISTS `ibook_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibook_deployment` (
  `ibook_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `ibook_id` (`ibook_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibook_deployment_queue`
--

DROP TABLE IF EXISTS `ibook_deployment_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibook_deployment_queue` (
  `device_id` int NOT NULL DEFAULT '-1',
  `ibook_id` int NOT NULL DEFAULT '-1',
  `date_deployed_epoch` bigint NOT NULL DEFAULT '0',
  `current_state` tinyint(1) NOT NULL DEFAULT '-1',
  `last_update_epoch` bigint NOT NULL DEFAULT '0',
  `current_delay` int NOT NULL DEFAULT '0' COMMENT 'How long the previous install attempt was delayed in seconds',
  KEY `ibook_id` (`ibook_id`),
  KEY `device_id_ibook_id` (`device_id`,`ibook_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibook_volume_purchase_codes`
--

DROP TABLE IF EXISTS `ibook_volume_purchase_codes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibook_volume_purchase_codes` (
  `ibook_id` int NOT NULL DEFAULT '-1',
  `code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_redeemed_epoch` bigint NOT NULL DEFAULT '0',
  `redeemed` tinyint(1) NOT NULL DEFAULT '0',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  KEY `ibook_id` (`ibook_id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  KEY `computer_id` (`computer_id`),
  KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibooks`
--

DROP TABLE IF EXISTS `ibooks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibooks` (
  `ibook_id` int NOT NULL AUTO_INCREMENT,
  `ibook_name` text COLLATE utf8mb3_unicode_ci,
  `publisher` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_service_display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_service_description` longtext COLLATE utf8mb3_unicode_ci,
  `is_free` tinyint(1) NOT NULL DEFAULT '1',
  `icon_attachment_id` int NOT NULL DEFAULT '-1',
  `itunes_store_url` varchar(2083) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hash_type` tinyint(1) NOT NULL DEFAULT '-1',
  `hash_value` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Stores the hex representation of the hash value',
  `filename` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` int NOT NULL DEFAULT '0',
  `itunes_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchase_method` int NOT NULL DEFAULT '0',
  `install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Install',
  `force_users_to_view_description` tinyint(1) NOT NULL DEFAULT '0',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `author` text COLLATE utf8mb3_unicode_ci,
  `kind` int NOT NULL DEFAULT '-1',
  `installed_automatically` int NOT NULL DEFAULT '0',
  `deploy_as_managed_ebook` int NOT NULL DEFAULT '0',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `vpp_admin_account_id` int NOT NULL DEFAULT '-1',
  `assign_vpp_device_based_licenses` tinyint(1) NOT NULL DEFAULT '0',
  `compliance` tinyint(1) NOT NULL DEFAULT '0',
  `ios_compliance` tinyint(1) NOT NULL DEFAULT '0',
  `available_in_appstore` tinyint(1) NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `md5` char(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sha256` char(64) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sha3_512` char(128) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`ibook_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ibooks_installed`
--

DROP TABLE IF EXISTS `ibooks_installed`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ibooks_installed` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `title` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_id` bigint NOT NULL DEFAULT '-1',
  `management_status` tinyint(1) NOT NULL DEFAULT '-1',
  `persistent_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `author` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `kind` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `report_id_and_hash` (`report_id`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `icons`
--

DROP TABLE IF EXISTS `icons`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `icons` (
  `icon_id` int NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `contents_original` longblob,
  `contents_300` longblob,
  `contents_512` longblob,
  PRIMARY KEY (`icon_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `icons_details`
--

DROP TABLE IF EXISTS `icons_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `icons_details` (
  `ics_icon_id` int NOT NULL AUTO_INCREMENT,
  `icon_id` int NOT NULL DEFAULT '-1',
  `ics_customer_icon_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `ics_icon_hash` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `ics_icon_migration_complete` tinyint(1) NOT NULL DEFAULT '0',
  `ics_icon_migration_try_count` int NOT NULL DEFAULT '0',
  `ics_icon_migration_error` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `jss_icon_hash` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `icon_base_download_url` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`ics_icon_id`),
  KEY `icon_id` (`icon_id`),
  KEY `ics_icon_hash` (`ics_icon_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_certificates`
--

DROP TABLE IF EXISTS `identity_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_certificates` (
  `certificate_id` int NOT NULL AUTO_INCREMENT,
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_data` mediumblob,
  `certificate_expiration` bigint NOT NULL DEFAULT '-1',
  `common_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `extension` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`certificate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `images`
--

DROP TABLE IF EXISTS `images`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `images` (
  `id` int NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `image_data` longblob,
  `image_content_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `impact_alert_notification_settings`
--

DROP TABLE IF EXISTS `impact_alert_notification_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `impact_alert_notification_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `scopeable_objects_alert_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `scopeable_objects_confirmation_code_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `deployable_objects_alert_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `deployable_objects_confirmation_code_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `confirmation_code` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `installed_printers`
--

DROP TABLE IF EXISTS `installed_printers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `installed_printers` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `printer_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uri` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `location` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `intune_device_compliance_aad_information`
--

DROP TABLE IF EXISTS `intune_device_compliance_aad_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `intune_device_compliance_aad_information` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_aad_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `user_aad_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `aad_state` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `tenant_aad_id` varchar(36) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `device_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `inventory_hash` int NOT NULL DEFAULT '-1',
  `inventory_changed` tinyint(1) NOT NULL DEFAULT '0',
  `is_compliant` tinyint(1) NOT NULL DEFAULT '0',
  `compliance_changed` tinyint(1) NOT NULL DEFAULT '0',
  `last_compliance_message_epoch` bigint NOT NULL DEFAULT '0',
  `last_message_epoch` bigint NOT NULL DEFAULT '0',
  `last_message_guid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  KEY `user_aad_id` (`user_aad_id`),
  KEY `device_type` (`device_type`),
  KEY `last_message_guid` (`last_message_guid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `intune_device_compliance_connections`
--

DROP TABLE IF EXISTS `intune_device_compliance_connections`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `intune_device_compliance_connections` (
  `id` int NOT NULL AUTO_INCREMENT,
  `registration_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `tenant_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `connection_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sovereign_cloud` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_compliance_group_id` int NOT NULL DEFAULT '-1',
  `mobile_device_registration_scope_group_id` int NOT NULL DEFAULT '-1',
  `device_remediation_action_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `custom_device_remediation_url` varchar(2048) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_enrollment_action_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `custom_device_enrollment_url` varchar(2048) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `native_client_app_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `established_before` tinyint(1) NOT NULL DEFAULT '0',
  `registrant_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `intune_device_compliance_removed_device_inventory`
--

DROP TABLE IF EXISTS `intune_device_compliance_removed_device_inventory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `intune_device_compliance_removed_device_inventory` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_class` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `eas_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_check_in_time_epoch` bigint NOT NULL DEFAULT '0',
  `device_removal_time_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  KEY `device_type` (`device_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `invalidated_tokens`
--

DROP TABLE IF EXISTS `invalidated_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `invalidated_tokens` (
  `token_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `expiration` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`token_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inventory_preload_extension_attributes`
--

DROP TABLE IF EXISTS `inventory_preload_extension_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inventory_preload_extension_attributes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `record_id` int NOT NULL DEFAULT '-1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inventory_preload_records`
--

DROP TABLE IF EXISTS `inventory_preload_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inventory_preload_records` (
  `id` int NOT NULL AUTO_INCREMENT,
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_type` tinyint(1) NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `full_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `phone_number` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `department` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `building` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `po_number` varchar(60) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `po_date` varchar(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `warranty_expiration` varchar(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `apple_care_id` varchar(60) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `purchase_price` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `life_expectancy` varchar(11) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `purchasing_account` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `lease_expiration` varchar(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `bar_code_1` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `bar_code_2` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `asset_tag` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `vendor` varchar(60) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `serial_number_unique` (`serial_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ios_configuration_profile_attributes`
--

DROP TABLE IF EXISTS `ios_configuration_profile_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ios_configuration_profile_attributes` (
  `ios_configuration_profile_attribute_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_configuration_profile_id` int NOT NULL DEFAULT '-1',
  `attribute_type` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`ios_configuration_profile_attribute_id`),
  KEY `mobile_device_configuration_profile_id` (`mobile_device_configuration_profile_id`),
  KEY `attribute_type` (`attribute_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `issued_certificates`
--

DROP TABLE IF EXISTS `issued_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `issued_certificates` (
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `subject_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_status` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_id` int NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `itunes_metadata`
--

DROP TABLE IF EXISTS `itunes_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `itunes_metadata` (
  `id` int NOT NULL AUTO_INCREMENT,
  `adam_id` bigint NOT NULL DEFAULT '-1',
  `minimum_os_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp` bigint NOT NULL DEFAULT '0',
  `is_32_bit_only` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `adam_id_unique` (`adam_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `itunes_metadata_device_families`
--

DROP TABLE IF EXISTS `itunes_metadata_device_families`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `itunes_metadata_device_families` (
  `id` int NOT NULL AUTO_INCREMENT,
  `itunes_metadata_id` int NOT NULL DEFAULT '-1',
  `device_family` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `itunes_metadata_id` (`itunes_metadata_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jamf_banner_notifications`
--

DROP TABLE IF EXISTS `jamf_banner_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jamf_banner_notifications` (
  `application` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`application`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jamf_connect_idp_user_info`
--

DROP TABLE IF EXISTS `jamf_connect_idp_user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jamf_connect_idp_user_info` (
  `id` int NOT NULL AUTO_INCREMENT,
  `shortname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `longname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `device_serial` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jamf_package_active_reenrollments`
--

DROP TABLE IF EXISTS `jamf_package_active_reenrollments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jamf_package_active_reenrollments` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `date_created_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jamf_package_install_commands`
--

DROP TABLE IF EXISTS `jamf_package_install_commands`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jamf_package_install_commands` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_id` int NOT NULL DEFAULT '-1',
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `date_created_epoch` bigint NOT NULL DEFAULT '0',
  `date_updated_epoch` bigint NOT NULL DEFAULT '0',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `application` varchar(31) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `device_management_id` (`device_management_id`),
  KEY `date_updated_epoch` (`date_updated_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jamf_package_notifications`
--

DROP TABLE IF EXISTS `jamf_package_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jamf_package_notifications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `application_name` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `latest_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `published_date_epoch` bigint NOT NULL DEFAULT '0',
  `is_major_update` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jmf_settings_mdm_deploy`
--

DROP TABLE IF EXISTS `jmf_settings_mdm_deploy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jmf_settings_mdm_deploy` (
  `id` int NOT NULL AUTO_INCREMENT,
  `custom_trigger` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checkin_interval` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `jmf_unique_command_uuid` (`command_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jsam_invitations`
--

DROP TABLE IF EXISTS `jsam_invitations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jsam_invitations` (
  `jsam_invitation_id` int NOT NULL AUTO_INCREMENT,
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `use_count` int NOT NULL DEFAULT '0',
  `expiration_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`jsam_invitation_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jsams`
--

DROP TABLE IF EXISTS `jsams`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jsams` (
  `jsam_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hostname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `identity_certificate` mediumblob,
  `operating_system` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checkin_interval_seconds` int NOT NULL DEFAULT '30',
  `os_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_reported_ip` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_checkin_epoch` bigint NOT NULL DEFAULT '-1',
  `jsam_status` int NOT NULL DEFAULT '0',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`jsam_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `json_web_token_configs`
--

DROP TABLE IF EXISTS `json_web_token_configs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `json_web_token_configs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `encryption_key` mediumblob,
  `token_expiry` tinyint(1) NOT NULL DEFAULT '5',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `disabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_access_logs`
--

DROP TABLE IF EXISTS `jss_access_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_access_logs` (
  `jss_access_log_id` int NOT NULL AUTO_INCREMENT,
  `timestamp_epoch` bigint NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ip_address` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `entry_point` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`jss_access_log_id`),
  KEY `timestamp_epoch` (`timestamp_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_audit`
--

DROP TABLE IF EXISTS `jss_audit`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_audit` (
  `jss_audit_id` int NOT NULL AUTO_INCREMENT,
  `primary_object_type` int NOT NULL DEFAULT '-1',
  `primary_object_id` int NOT NULL DEFAULT '-1',
  `child_object_type` int NOT NULL DEFAULT '-1',
  `child_object_id` int NOT NULL DEFAULT '-1',
  `audit_who` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Who performed this auditable action, usually username',
  `audit_when` bigint NOT NULL DEFAULT '0' COMMENT 'When the auditable action was performed, millis since epoch',
  `audit_what` mediumblob COMMENT 'Usually and initially a chunk of xml representing fields marked for audit',
  `audit_what_class_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Usually the simple class name of the primary object',
  `audit_where` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'A string that describes where in the app this auditable action was performed',
  PRIMARY KEY (`jss_audit_id`),
  KEY `primary_object_type` (`primary_object_type`),
  KEY `primary_object_id` (`primary_object_id`),
  KEY `child_object_type` (`child_object_type`),
  KEY `child_object_id` (`child_object_id`),
  KEY `audit_who` (`audit_who`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_cache_configurations`
--

DROP TABLE IF EXISTS `jss_cache_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_cache_configurations` (
  `id` int NOT NULL DEFAULT '0',
  `cache_type` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `time_to_live_seconds` int NOT NULL DEFAULT '-1',
  `directory_time_to_live_seconds` int DEFAULT NULL,
  `time_to_idle_seconds` int DEFAULT NULL,
  `ehcache_max_bytes_local_heap` varchar(50) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `cache_unique_id` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `elasticache` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_cluster_nodes`
--

DROP TABLE IF EXISTS `jss_cluster_nodes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_cluster_nodes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `address` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_master` tinyint(1) NOT NULL DEFAULT '0',
  `last_check_in_epoch` bigint NOT NULL DEFAULT '0',
  `jss_cluster_settings_id` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_cluster_settings`
--

DROP TABLE IF EXISTS `jss_cluster_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_cluster_settings` (
  `id` int NOT NULL DEFAULT '0',
  `clustered` tinyint(1) NOT NULL DEFAULT '0',
  `cluster_monitor_frequency` int NOT NULL DEFAULT '60',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_cluster_updates`
--

DROP TABLE IF EXISTS `jss_cluster_updates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_cluster_updates` (
  `class_id` int NOT NULL DEFAULT '-1',
  `last_update_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`class_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_custom_settings`
--

DROP TABLE IF EXISTS `jss_custom_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_custom_settings` (
  `settings_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` text COLLATE utf8mb3_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_memcached_endpoints`
--

DROP TABLE IF EXISTS `jss_memcached_endpoints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_memcached_endpoints` (
  `id` int NOT NULL AUTO_INCREMENT,
  `host_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `port` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `jss_cache_configuration_id` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_server_url`
--

DROP TABLE IF EXISTS `jss_server_url`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_server_url` (
  `jss_server_url_id` int NOT NULL DEFAULT '0',
  `https` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `http` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'This field is deprecated and is no longer being used.',
  PRIMARY KEY (`jss_server_url_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_settings`
--

DROP TABLE IF EXISTS `jss_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_settings` (
  `flush_log_time` int NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jss_webhook_settings`
--

DROP TABLE IF EXISTS `jss_webhook_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jss_webhook_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `webhook_content_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `url` text COLLATE utf8mb3_unicode_ci NOT NULL,
  `event_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `connection_timeout` int NOT NULL DEFAULT '5',
  `read_timeout` int NOT NULL DEFAULT '2',
  `authentication_type` varchar(50) COLLATE utf8mb3_unicode_ci DEFAULT 'NONE',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `encrypted_password` text COLLATE utf8mb3_unicode_ci,
  `header` longblob,
  `associated_smart_group_id` int NOT NULL DEFAULT '-1',
  `enable_display_fields_for_group_object` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `key_pairs`
--

DROP TABLE IF EXISTS `key_pairs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `key_pairs` (
  `key_pair_id` int NOT NULL AUTO_INCREMENT,
  `key_pair_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `private_key` mediumblob,
  `public_key` mediumblob,
  `password` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`key_pair_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `keystores`
--

DROP TABLE IF EXISTS `keystores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `keystores` (
  `keystore_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password` text COLLATE utf8mb3_unicode_ci,
  `keystore` mediumblob,
  PRIMARY KEY (`keystore_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `laps_password_audits`
--

DROP TABLE IF EXISTS `laps_password_audits`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `laps_password_audits` (
  `audit_id` int NOT NULL AUTO_INCREMENT,
  `local_admin_password_id` int NOT NULL DEFAULT '-1',
  `viewed_by` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_seen` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`audit_id`),
  KEY `local_admin_password_id` (`local_admin_password_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `laps_password_entries`
--

DROP TABLE IF EXISTS `laps_password_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `laps_password_entries` (
  `id` int NOT NULL AUTO_INCREMENT,
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `rotation_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `local_admin_password` text COLLATE utf8mb3_unicode_ci,
  `date_last_seen` bigint DEFAULT NULL,
  `is_valid` tinyint(1) NOT NULL DEFAULT '0',
  `expiration_time` bigint DEFAULT NULL,
  `created_date` bigint NOT NULL DEFAULT '-1',
  `laps_user_id` int NOT NULL DEFAULT '-1',
  `modified_date` bigint NOT NULL DEFAULT '-1',
  `rotation_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `client_management_id` (`client_management_id`),
  KEY `client_management_id_laps_user_id` (`client_management_id`,`laps_user_id`),
  KEY `is_valid_created_date_idx` (`is_valid`,`created_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `laps_settings`
--

DROP TABLE IF EXISTS `laps_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `laps_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `auto_deploy_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `command_delay_seconds` bigint NOT NULL DEFAULT '3600',
  `auto_rotate_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `auto_rotate_expiration_seconds` bigint NOT NULL DEFAULT '7776000',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `laps_user`
--

DROP TABLE IF EXISTS `laps_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `laps_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `guid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'MDM',
  PRIMARY KEY (`id`),
  KEY `management_id` (`management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `latest_jamf_packages`
--

DROP TABLE IF EXISTS `latest_jamf_packages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `latest_jamf_packages` (
  `application_name` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `latest_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`application_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ldap_servers`
--

DROP TABLE IF EXISTS `ldap_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ldap_servers` (
  `ldap_server_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'cust',
  `connection_is_used_for` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hostname` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_port` int NOT NULL DEFAULT '0',
  `open_close_timeout` int NOT NULL DEFAULT '15',
  `connection_timeout` int NOT NULL DEFAULT '60',
  `is_secure` tinyint(1) NOT NULL DEFAULT '0',
  `max_page_size` int NOT NULL DEFAULT '500',
  `referrals` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `allow_wildcard_searches` tinyint(1) NOT NULL DEFAULT '1',
  `enable_connection_pooling` tinyint(1) NOT NULL DEFAULT '1',
  `authentication_type` varchar(12) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `distinguished_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `lps_connection_settings_id` int NOT NULL DEFAULT '-1',
  `user_object_map_to_all_class_values` tinyint(1) NOT NULL DEFAULT '1',
  `user_object_class_values` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_all_subtrees` tinyint(1) NOT NULL DEFAULT '1',
  `user_object_map_id_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_username_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_uuid_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_uuid_bindable` tinyint(1) NOT NULL DEFAULT '0',
  `user_object_map_email_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_append_to_email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_real_name_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_department_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_position_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_phone_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_room_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_object_map_building_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_object_map_to_all_class_values` tinyint(1) NOT NULL DEFAULT '1',
  `user_group_object_class_values` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_object_search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_object_all_subtrees` tinyint(1) NOT NULL DEFAULT '1',
  `user_group_object_map_id_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_object_map_group_name_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_object_map_uuid_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_object_uuid_bindable` tinyint(1) NOT NULL DEFAULT '0',
  `user_group_lookup_object_map_to_all_class_values` tinyint(1) NOT NULL DEFAULT '1',
  `user_group_lookup_object_search_base` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_lookup_object_class_values` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_lookup_object_all_subtrees` tinyint(1) NOT NULL DEFAULT '1',
  `user_group_lookup_object_map_group_id_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_lookup_object_map_username_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_membership_stored_in` tinyint(1) NOT NULL DEFAULT '-1',
  `user_group_membership_map_group_to_field_in_user` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_membership_map_group_to_field_in_user_use_dn` tinyint(1) NOT NULL DEFAULT '0',
  `user_group_membership_map_group_to_field_in_user_rcrsv_lkups` tinyint(1) NOT NULL DEFAULT '0',
  `user_group_membership_map_group_to_field_in_user_ad_gr_memb_en` tinyint(1) NOT NULL DEFAULT '0',
  `user_group_membership_append_to_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_membership_map_user_to_field_in_group` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_membership_map_user_to_field_in_group_use_dn` tinyint(1) NOT NULL DEFAULT '0',
  `user_group_membership_use_ldap_compare` tinyint(1) NOT NULL DEFAULT '1',
  `user_group_membership_scoping_optimization_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `computer_object_map_to_all_class_values` tinyint(1) NOT NULL DEFAULT '1',
  `computer_object_search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_object_all_subtrees` tinyint(1) NOT NULL DEFAULT '1',
  `computer_object_class_values` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_object_map_computer_name_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_object_map_mac_address_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_object_map_to_all_class_values` tinyint(1) NOT NULL DEFAULT '1',
  `computer_group_object_class_values` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_object_search_base` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_object_all_subtrees` tinyint(1) NOT NULL DEFAULT '1',
  `computer_group_object_map_name_to` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_membership_stored_in` tinyint(1) NOT NULL DEFAULT '0',
  `computer_group_membership_map_group_to_field_in_computer` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_membership_map_group_to_field_in_computer_use_dn` tinyint(1) NOT NULL DEFAULT '0',
  `computer_group_membership_map_computer_to_field_in_group` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_group_membership_map_computer_to_field_in_group_use_dn` tinyint(1) NOT NULL DEFAULT '0',
  `is_mapping_in_return_attr` tinyint(1) NOT NULL DEFAULT '0',
  `is_insecure` tinyint(1) NOT NULL DEFAULT '0',
  `is_verified` tinyint(1) NOT NULL DEFAULT '0',
  `is_lps_verified` tinyint(1) NOT NULL DEFAULT '0',
  `is_strict_ssl` tinyint(1) NOT NULL DEFAULT '0',
  `is_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `migrated_to_id` int NOT NULL DEFAULT '0',
  `mutual_ssl_keystore_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`ldap_server_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `licensed_software`
--

DROP TABLE IF EXISTS `licensed_software`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `licensed_software` (
  `licensed_software_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `send_notification` tinyint(1) NOT NULL DEFAULT '0',
  `remove_titles` tinyint(1) NOT NULL DEFAULT '0',
  `exclude_mac_app_store_apps` tinyint(1) NOT NULL DEFAULT '0',
  `publisher` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `platform` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `notes` longtext COLLATE utf8mb3_unicode_ci,
  `identification_method` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`licensed_software_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `licensed_software_activation_status`
--

DROP TABLE IF EXISTS `licensed_software_activation_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `licensed_software_activation_status` (
  `licensed_software_activation_status_id` int NOT NULL AUTO_INCREMENT,
  `licensed_software_id` int NOT NULL DEFAULT '-1',
  `activation_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`licensed_software_activation_status_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `licensed_software_definitions`
--

DROP TABLE IF EXISTS `licensed_software_definitions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `licensed_software_definitions` (
  `licensed_software_id` int NOT NULL DEFAULT '-1',
  `object_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_version` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_version_compare_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'like'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `licensed_software_swid_definition`
--

DROP TABLE IF EXISTS `licensed_software_swid_definition`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `licensed_software_swid_definition` (
  `licensed_software_swid_definition_id` int NOT NULL AUTO_INCREMENT,
  `licensed_software_id` int NOT NULL DEFAULT '-1',
  `software_id_unique_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_creator_regid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`licensed_software_swid_definition_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `licensed_software_usage`
--

DROP TABLE IF EXISTS `licensed_software_usage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `licensed_software_usage` (
  `licensed_software_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  KEY `licensed_software_id` (`licensed_software_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `licensed_software_usage_counts`
--

DROP TABLE IF EXISTS `licensed_software_usage_counts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `licensed_software_usage_counts` (
  `licensed_software_id` int NOT NULL DEFAULT '-1',
  `usage_count` int NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `limited_access_mode_settings`
--

DROP TABLE IF EXISTS `limited_access_mode_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `limited_access_mode_settings` (
  `address` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `access_mode` int NOT NULL DEFAULT '0',
  KEY `address` (`address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `linked_app_profiles`
--

DROP TABLE IF EXISTS `linked_app_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `linked_app_profiles` (
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_id` int NOT NULL DEFAULT '-1',
  `linked_app` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `auto_deployment_type` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`uuid`),
  KEY `profile_id` (`profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `linked_connect_profiles`
--

DROP TABLE IF EXISTS `linked_connect_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `linked_connect_profiles` (
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `linked_protect_plan_profiles`
--

DROP TABLE IF EXISTS `linked_protect_plan_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `linked_protect_plan_profiles` (
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `plan_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `plan_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `plan_description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_version` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `location_history`
--

DROP TABLE IF EXISTS `location_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `location_history` (
  `location_id` int NOT NULL DEFAULT '0',
  `computer_id` int NOT NULL DEFAULT '0',
  `peripheral_id` int NOT NULL DEFAULT '0',
  `mobile_device_id` int NOT NULL DEFAULT '0',
  `date_assigned_epoch` bigint NOT NULL DEFAULT '0',
  KEY `location_id` (`location_id`),
  KEY `computer_id` (`computer_id`),
  KEY `peripheral_id` (`peripheral_id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  KEY `date_assigned_epoch` (`date_assigned_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `locations`
--

DROP TABLE IF EXISTS `locations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `locations` (
  `location_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `building_id` int NOT NULL DEFAULT '-1' COMMENT '[PII]',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `department_id` int NOT NULL DEFAULT '-1' COMMENT '[PII]',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `ldap_server_id` int NOT NULL DEFAULT '-1',
  `ldap_uid` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `unique_creator` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `log_actions`
--

DROP TABLE IF EXISTS `log_actions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `log_actions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `log_id` bigint NOT NULL DEFAULT '0',
  `action_type` tinyint(1) NOT NULL DEFAULT '0',
  `action` longtext COLLATE utf8mb3_unicode_ci,
  `event_order` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `log_id` (`log_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `log_errors`
--

DROP TABLE IF EXISTS `log_errors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `log_errors` (
  `log_id` bigint NOT NULL DEFAULT '0',
  `error_type` tinyint(1) NOT NULL DEFAULT '0',
  `error` longtext COLLATE utf8mb3_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `logs`
--

DROP TABLE IF EXISTS `logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `logs` (
  `log_id` bigint NOT NULL AUTO_INCREMENT,
  `type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_id` int NOT NULL DEFAULT '0',
  `user_id` int NOT NULL DEFAULT '0',
  `error` tinyint(1) NOT NULL DEFAULT '0',
  `date_entered_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`log_id`),
  KEY `computer_id` (`computer_id`),
  KEY `date_entered_epoch` (`date_entered_epoch`),
  KEY `type_date_entered_epoch` (`type`,`date_entered_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `lps_connection_settings`
--

DROP TABLE IF EXISTS `lps_connection_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lps_connection_settings` (
  `lps_connection_settings_id` int NOT NULL AUTO_INCREMENT,
  `jsam_id` int NOT NULL DEFAULT '-1',
  `lps_bind_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lps_bind_port` int NOT NULL DEFAULT '-1',
  `ldap_server_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ldap_server_port` int NOT NULL DEFAULT '-1',
  `ldaps` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`lps_connection_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `lps_server_settings`
--

DROP TABLE IF EXISTS `lps_server_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lps_server_settings` (
  `jsam_id` int NOT NULL DEFAULT '-1',
  `version` int NOT NULL DEFAULT '-1',
  `server_start_timeout_seconds` int NOT NULL DEFAULT '-1',
  `server_shutdown_timeout_seconds` int NOT NULL DEFAULT '-1',
  `transfer_thread_start_timeout_seconds` int NOT NULL DEFAULT '-1',
  `transfer_thread_shutdown_timeout_seconds` int NOT NULL DEFAULT '-1',
  `lps_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`jsam_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `m2m_client_credentials`
--

DROP TABLE IF EXISTS `m2m_client_credentials`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `m2m_client_credentials` (
  `id` int NOT NULL DEFAULT '1',
  `client_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_secret` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `updated_date` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `m2m_client_credentials_pending`
--

DROP TABLE IF EXISTS `m2m_client_credentials_pending`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `m2m_client_credentials_pending` (
  `id` int NOT NULL DEFAULT '1',
  `client_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_secret` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `created_date` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mac_app_deployment`
--

DROP TABLE IF EXISTS `mac_app_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mac_app_deployment` (
  `mac_app_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `mac_app_id` (`mac_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mac_app_deployment_queue`
--

DROP TABLE IF EXISTS `mac_app_deployment_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mac_app_deployment_queue` (
  `device_id` int NOT NULL DEFAULT '-1',
  `mac_app_id` int NOT NULL DEFAULT '-1',
  `date_deployed_epoch` bigint NOT NULL DEFAULT '0',
  `current_state` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_epoch` bigint NOT NULL DEFAULT '0',
  KEY `device_id` (`device_id`),
  KEY `mac_app_id` (`mac_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mac_app_volume_purchase_codes`
--

DROP TABLE IF EXISTS `mac_app_volume_purchase_codes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mac_app_volume_purchase_codes` (
  `mac_app_id` int NOT NULL DEFAULT '-1',
  `code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_redeemed_epoch` bigint NOT NULL DEFAULT '0',
  `redeemed` tinyint(1) NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `computer_id` int NOT NULL DEFAULT '-1',
  `redemption_confirmed` tinyint(1) NOT NULL DEFAULT '0',
  KEY `mac_app_id` (`mac_app_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mac_apps`
--

DROP TABLE IF EXISTS `mac_apps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mac_apps` (
  `mac_app_id` int NOT NULL AUTO_INCREMENT,
  `app_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `deployment_method` tinyint(1) NOT NULL DEFAULT '1',
  `remove_app_when_mdm_profile_removed` tinyint(1) NOT NULL DEFAULT '0',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `is_free` tinyint(1) NOT NULL DEFAULT '1',
  `current_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '-1',
  `icon_attachment_id` int NOT NULL DEFAULT '-1',
  `provisioning_profile_id` int NOT NULL DEFAULT '-1',
  `itunes_store_url` varchar(2083) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `external_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'The iTunes ID. This is actually the trackID in the API.',
  `self_service_description` longtext COLLATE utf8mb3_unicode_ci,
  `install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Install',
  `force_users_to_view_description` tinyint(1) NOT NULL DEFAULT '0',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  `vpp_admin_account_id` int NOT NULL DEFAULT '-1',
  `assign_vpp_device_based_licenses` tinyint(1) NOT NULL DEFAULT '0',
  `keep_description_and_icon_up_to_date` tinyint(1) NOT NULL DEFAULT '0',
  `keep_app_updated_on_devices` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_sync_time` int NOT NULL DEFAULT '0',
  `itunes_default_region` varchar(2) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'US',
  `compliance` tinyint(1) NOT NULL DEFAULT '0',
  `available_in_appstore` tinyint(1) NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`mac_app_id`),
  KEY `bundle_id` (`bundle_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `managed_device_attestation`
--

DROP TABLE IF EXISTS `managed_device_attestation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `managed_device_attestation` (
  `id` int NOT NULL AUTO_INCREMENT,
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `managed_device_attestation_status_value` tinyint(1) NOT NULL DEFAULT '1',
  `attestation_attempt_date_epoch` bigint DEFAULT NULL,
  `last_successful_attestation_date_epoch` bigint DEFAULT NULL,
  `last_successful_nonce` varchar(44) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_request_nonce` varchar(44) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `management_id_unique` (`management_id`),
  KEY `fk_managed_device_attestation_status_value` (`managed_device_attestation_status_value`),
  CONSTRAINT `fk_managed_device_attestation_status_value` FOREIGN KEY (`managed_device_attestation_status_value`) REFERENCES `managed_device_attestation_status_enum` (`enumerator`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `managed_device_attestation_status_enum`
--

DROP TABLE IF EXISTS `managed_device_attestation_status_enum`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `managed_device_attestation_status_enum` (
  `enumerator` tinyint(1) NOT NULL DEFAULT '-1',
  `value` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`enumerator`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `managed_software_plan_feature_toggle`
--

DROP TABLE IF EXISTS `managed_software_plan_feature_toggle`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `managed_software_plan_feature_toggle` (
  `id` int NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `last_toggled_on` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `last_toggled_by_account_id` int NOT NULL DEFAULT '-1',
  `last_toggled_by_account_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `management_framework_id`
--

DROP TABLE IF EXISTS `management_framework_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `management_framework_id` (
  `id` bigint NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `management_identifiers`
--

DROP TABLE IF EXISTS `management_identifiers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `management_identifiers` (
  `management_identifier_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_identifier_type` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lookup_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `secondary_lookup_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`management_identifier_uuid`),
  KEY `idx_lookup_type_value` (`lookup_value`,`secondary_lookup_value`,`management_identifier_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_client`
--

DROP TABLE IF EXISTS `mdm_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_client` (
  `id` int NOT NULL AUTO_INCREMENT,
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `push_magic` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `apn_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `push_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `push_disabled_time` datetime DEFAULT NULL,
  `mdm_client_certificate_id` int NOT NULL DEFAULT '-1',
  `ddm_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `management_id_unique` (`management_id`),
  KEY `apn_token` (`apn_token`),
  KEY `push_enabled` (`push_enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_client_certificate`
--

DROP TABLE IF EXISTS `mdm_client_certificate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_client_certificate` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_certificate` mediumblob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_client_dims_certificate`
--

DROP TABLE IF EXISTS `mdm_client_dims_certificate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_client_dims_certificate` (
  `id` int NOT NULL AUTO_INCREMENT,
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `management_id_unique` (`management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_command_error`
--

DROP TABLE IF EXISTS `mdm_command_error`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_command_error` (
  `mdm_command_id` int NOT NULL DEFAULT '-1',
  `error_code` int NOT NULL DEFAULT '-1',
  `error_domain` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `error_localized_description` longtext COLLATE utf8mb3_unicode_ci,
  `error_english_description` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`mdm_command_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_command_group`
--

DROP TABLE IF EXISTS `mdm_command_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_command_group` (
  `id` int NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_command_queue_settings`
--

DROP TABLE IF EXISTS `mdm_command_queue_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_command_queue_settings` (
  `command_queue_monitor_interval` int NOT NULL DEFAULT '300'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_command_source`
--

DROP TABLE IF EXISTS `mdm_command_source`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_command_source` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mdm_command_id` int NOT NULL DEFAULT '-1',
  `command_source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `command_source` (`command_source`),
  KEY `command_id_source` (`mdm_command_id`,`command_source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_invitation`
--

DROP TABLE IF EXISTS `mdm_invitation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_invitation` (
  `mdm_invitation_id` int NOT NULL AUTO_INCREMENT,
  `udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`mdm_invitation_id`),
  KEY `invitation` (`invitation`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_pending_profile_list`
--

DROP TABLE IF EXISTS `mdm_pending_profile_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_pending_profile_list` (
  `id` int NOT NULL AUTO_INCREMENT,
  `profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `profile_client_management_composite` (`profile_uuid`,`client_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_profile_prototype`
--

DROP TABLE IF EXISTS `mdm_profile_prototype`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_profile_prototype` (
  `id` int NOT NULL AUTO_INCREMENT,
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_profile_prototype` tinyint(1) NOT NULL DEFAULT '-1',
  `device_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `management_id_device_type_unique` (`management_id`,`device_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_renewal_error`
--

DROP TABLE IF EXISTS `mdm_renewal_error`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_renewal_error` (
  `mdm_renewal_error_id` int NOT NULL AUTO_INCREMENT,
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_renewal_error_type` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_renewal_error_timestamp` bigint NOT NULL DEFAULT '-1',
  `mdm_renew_error_failure_count` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`mdm_renewal_error_id`),
  KEY `client_management_id` (`client_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mdm_renewal_strategy`
--

DROP TABLE IF EXISTS `mdm_renewal_strategy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mdm_renewal_strategy` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mdm_renewal_error_id` int NOT NULL DEFAULT '-1',
  `mdm_renewal_strategy_type` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_renewal_strategy_timestamp` bigint NOT NULL DEFAULT '-1',
  `mdm_renewal_check_in_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mdm_renewal_server_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `mdm_renewal_error_id` (`mdm_renewal_error_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `microsoft_scep_challenge_configuration`
--

DROP TABLE IF EXISTS `microsoft_scep_challenge_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `microsoft_scep_challenge_configuration` (
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `scep_username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scep_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_app_volume_purchase_codes`
--

DROP TABLE IF EXISTS `mobile_app_volume_purchase_codes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_app_volume_purchase_codes` (
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_redeemed_epoch` bigint NOT NULL DEFAULT '0',
  `redeemed` tinyint(1) NOT NULL DEFAULT '0',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `redemption_confirmed` tinyint(1) NOT NULL DEFAULT '0',
  KEY `mobile_device_app_id` (`mobile_device_app_id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_activation_lock_clear_queue`
--

DROP TABLE IF EXISTS `mobile_device_activation_lock_clear_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_activation_lock_clear_queue` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `device_management_id` (`device_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_assignments`
--

DROP TABLE IF EXISTS `mobile_device_app_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_assignments` (
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `mobile_device_id` int NOT NULL DEFAULT '0',
  `ldap_server_id` int NOT NULL DEFAULT '0',
  `user_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_group_id` int NOT NULL DEFAULT '0',
  `building_id` int NOT NULL DEFAULT '0',
  `department_id` int NOT NULL DEFAULT '0',
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_associated_domain`
--

DROP TABLE IF EXISTS `mobile_device_app_associated_domain`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_associated_domain` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `associated_domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '255',
  PRIMARY KEY (`id`),
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_config_command`
--

DROP TABLE IF EXISTS `mobile_device_app_config_command`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_config_command` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `retry_count` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `mobile_device_app_id` (`mobile_device_app_id`),
  KEY `command_uuid` (`command_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_contents`
--

DROP TABLE IF EXISTS `mobile_device_app_contents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_contents` (
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `ipa_contents` longblob,
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_deployment`
--

DROP TABLE IF EXISTS `mobile_device_app_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_deployment` (
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_deployment_queue`
--

DROP TABLE IF EXISTS `mobile_device_app_deployment_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_deployment_queue` (
  `device_id` int NOT NULL DEFAULT '-1',
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `date_deployed_epoch` bigint NOT NULL DEFAULT '0',
  `current_state` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_epoch` bigint NOT NULL DEFAULT '0',
  KEY `mobile_device_app_id` (`mobile_device_app_id`),
  KEY `device_id_app_id` (`device_id`,`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_device_families`
--

DROP TABLE IF EXISTS `mobile_device_app_device_families`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_device_families` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `device_family` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_invitations`
--

DROP TABLE IF EXISTS `mobile_device_app_invitations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_invitations` (
  `mobile_device_app_invitation_id` int NOT NULL AUTO_INCREMENT,
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `use_count` int NOT NULL DEFAULT '0',
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `expiration_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`mobile_device_app_invitation_id`),
  KEY `invitation` (`invitation`),
  KEY `mobile_device_app_invitation_app_to_device` (`mobile_device_app_id`,`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_metadata`
--

DROP TABLE IF EXISTS `mobile_device_app_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_metadata` (
  `mobile_device_app_id` int NOT NULL AUTO_INCREMENT,
  `os_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_os_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_app_network_segments`
--

DROP TABLE IF EXISTS `mobile_device_app_network_segments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_app_network_segments` (
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `network_segment_id` int NOT NULL DEFAULT '-1',
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_application_details`
--

DROP TABLE IF EXISTS `mobile_device_application_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_application_details` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `short_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `external_version_identifier` bigint NOT NULL DEFAULT '0',
  `lookup_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `version` (`version`),
  KEY `short_version` (`short_version`),
  KEY `bundle_id` (`bundle_id`),
  KEY `lookup_hash` (`lookup_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_apps`
--

DROP TABLE IF EXISTS `mobile_device_apps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_apps` (
  `mobile_device_app_id` int NOT NULL AUTO_INCREMENT,
  `app_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `deployed_via_self_service` tinyint(1) NOT NULL DEFAULT '1',
  `deploy_as_managed_app` tinyint(1) NOT NULL DEFAULT '1',
  `remove_app_when_mdm_profile_removed` tinyint(1) NOT NULL DEFAULT '0',
  `prevent_backup_of_app_data` tinyint(1) NOT NULL DEFAULT '0',
  `allow_user_to_delete` tinyint(1) NOT NULL DEFAULT '1',
  `keep_description_and_icon_up_to_date` tinyint(1) NOT NULL DEFAULT '0',
  `keep_app_updated_on_devices` tinyint(1) NOT NULL DEFAULT '0',
  `take_over_management` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_sync_time` int NOT NULL DEFAULT '0' COMMENT 'This is the time in seconds after midnight that app version, description, and icon get synced with iTunes App Store.',
  `itunes_region` varchar(2) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'US' COMMENT 'This is the iTunes App Store region used to check for version updates.',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `is_free` tinyint(1) NOT NULL DEFAULT '1',
  `current_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '-1',
  `ipa_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `icon_attachment_id` int NOT NULL DEFAULT '-1',
  `provisioning_profile_id` int NOT NULL DEFAULT '-1',
  `itunes_store_url` varchar(2083) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `all_mobile_devices` tinyint(1) NOT NULL DEFAULT '0',
  `hosting_location` tinyint(1) NOT NULL DEFAULT '0',
  `external_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'The iTunes ID. This is actually the trackID in the API.',
  `hash_type` tinyint(1) NOT NULL DEFAULT '-1',
  `hash_value` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Stores the hex representation of the hash value',
  `per_app_vpn_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'None',
  `per_app_vpn_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '-1',
  `per_app_dns_proxy_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'None',
  `per_app_dns_proxy_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '-1',
  `per_app_content_filter_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'None',
  `per_app_content_filter_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '-1',
  `enable_direct_downloads` tinyint(1) NOT NULL DEFAULT '0',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  `vpp_admin_account_id` int NOT NULL DEFAULT '-1',
  `assign_vpp_device_based_licenses` tinyint(1) NOT NULL DEFAULT '0',
  `available_after_install` tinyint(1) NOT NULL DEFAULT '1',
  `require_network_tethered` tinyint(1) NOT NULL DEFAULT '0',
  `available_in_appstore` tinyint(1) NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `app_config_generator_legal_acknowledged` tinyint(1) NOT NULL DEFAULT '0',
  `compliance` tinyint(1) NOT NULL DEFAULT '0',
  `install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Install',
  `after_install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Reinstall',
  `md5` char(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sha256` char(64) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sha3_512` char(128) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`mobile_device_app_id`),
  KEY `bundle_id` (`bundle_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_available_updates`
--

DROP TABLE IF EXISTS `mobile_device_available_updates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_available_updates` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `product_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `human_readable_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `product_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `build` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_preview` tinyint(1) NOT NULL DEFAULT '0',
  `download_size` bigint NOT NULL DEFAULT '0',
  `install_size` bigint NOT NULL DEFAULT '0',
  `is_critical` tinyint(1) NOT NULL DEFAULT '0',
  `is_configuration_data_update` tinyint(1) NOT NULL DEFAULT '0',
  `is_firmware_update` tinyint(1) NOT NULL DEFAULT '0',
  `restart_required` tinyint(1) NOT NULL DEFAULT '0',
  `allows_install_later` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `report_id_and_hash` (`report_id`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_configuration_profile_deployment`
--

DROP TABLE IF EXISTS `mobile_device_configuration_profile_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_configuration_profile_deployment` (
  `mobile_device_configuration_profile_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `mobile_device_configuration_profile_id` (`mobile_device_configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_configuration_profiles`
--

DROP TABLE IF EXISTS `mobile_device_configuration_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_configuration_profiles` (
  `mobile_device_configuration_profile_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `setting` longblob,
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deployment` tinyint(1) NOT NULL DEFAULT '0',
  `icon_attachment_id` int NOT NULL DEFAULT '-1',
  `redeploy_days_before_certificate_expires` int NOT NULL DEFAULT '0',
  `redeployment_duration_minutes` bigint NOT NULL DEFAULT '-1',
  `payload_identifier` longtext COLLATE utf8mb3_unicode_ci,
  `payload_uuid` longtext COLLATE utf8mb3_unicode_ci,
  `is_signed` tinyint(1) NOT NULL DEFAULT '0',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  `self_service_description` longtext COLLATE utf8mb3_unicode_ci,
  `allow_installing_apps` tinyint(1) NOT NULL DEFAULT '1',
  `hidden_profile` tinyint(1) NOT NULL DEFAULT '0',
  `has_scep_payload` tinyint(1) NOT NULL DEFAULT '0',
  `scep_proxy_payload_uuids` longtext COLLATE utf8mb3_unicode_ci,
  `external_config_profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deferred_action_required` tinyint(1) NOT NULL DEFAULT '0',
  `profile_level` tinyint(1) NOT NULL DEFAULT '1',
  `compliance` tinyint(1) NOT NULL DEFAULT '0',
  `last_save_epoch` bigint NOT NULL DEFAULT '0',
  `source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'UNKNOWN',
  PRIMARY KEY (`mobile_device_configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_details`
--

DROP TABLE IF EXISTS `mobile_device_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_details` (
  `report_id` int NOT NULL DEFAULT '-1',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `guid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `iccid` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `imei` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `imei2` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `eid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_backup_time_epoch` bigint NOT NULL DEFAULT '0',
  `phone_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `model_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_build` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_supplemental_build_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_supplemental_version_extra` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_family` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `modem_firmware` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `network` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `carrier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `disk_size_mb` int NOT NULL DEFAULT '0',
  `disk_available_mb` int NOT NULL DEFAULT '0',
  `disk_percent_full` int NOT NULL DEFAULT '0',
  `computer_id` int NOT NULL DEFAULT '-1',
  `hardware_encryption_capabilities` tinyint(1) NOT NULL DEFAULT '-1',
  `passcode_present` tinyint(1) NOT NULL DEFAULT '0',
  `passcode_is_compliant` tinyint(1) NOT NULL DEFAULT '0',
  `passcode_is_compliant_with_profile` tinyint(1) NOT NULL DEFAULT '0',
  `passcode_lock_grace_period_enforced` bigint DEFAULT NULL,
  `carrier_settings_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_mobile_country_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_mobile_network_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `data_roaming_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `home_mobile_country_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home_mobile_network_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model_version_number` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_roaming` tinyint(1) NOT NULL DEFAULT '0',
  `is_personal_hotspot_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `block_level_encryption` tinyint(1) NOT NULL DEFAULT '0',
  `file_level_encryption` tinyint(1) NOT NULL DEFAULT '0',
  `data_protection` tinyint(1) NOT NULL DEFAULT '0',
  `ip_address` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `battery_level` int NOT NULL DEFAULT '-1',
  `battery_health` int NOT NULL DEFAULT '3',
  `cellular_technology` tinyint(1) NOT NULL DEFAULT '-1',
  `meid` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `voice_roaming_enabled` tinyint(1) NOT NULL DEFAULT '-1',
  `locales` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `languages` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_locator_service_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `do_not_disturb_in_effect` tinyint(1) NOT NULL DEFAULT '0',
  `activation_lock_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `cloud_backup_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `last_cloud_backup_date_epoch` bigint NOT NULL DEFAULT '0',
  `itunes_store_account_is_active` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_store_account_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `diagnostic_submission_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `app_analytics_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`report_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_extension_attribute_popup_choices`
--

DROP TABLE IF EXISTS `mobile_device_extension_attribute_popup_choices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_extension_attribute_popup_choices` (
  `mobile_device_extension_attribute_id` int NOT NULL DEFAULT '-1',
  `choice` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_extension_attribute_values`
--

DROP TABLE IF EXISTS `mobile_device_extension_attribute_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_extension_attribute_values` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mobile_device_extension_attribute_id` int NOT NULL DEFAULT '-1',
  `report_id` int NOT NULL DEFAULT '-1',
  `value_on_client` longtext COLLATE utf8mb3_unicode_ci,
  `date_value_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_report_id_mdea_id_value_on_client` (`report_id`,`mobile_device_extension_attribute_id`,`value_on_client`(25))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_extension_attributes`
--

DROP TABLE IF EXISTS `mobile_device_extension_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_extension_attributes` (
  `mobile_device_extension_attribute_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `data_type` tinyint(1) NOT NULL DEFAULT '0',
  `type` tinyint(1) NOT NULL DEFAULT '0',
  `display_in_section` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checked` tinyint(1) NOT NULL DEFAULT '0',
  `ldap_attribute_mapping` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ldap_extension_attribute_allowed` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_extension_attribute_id`),
  KEY `mdea_display_name_extenstion_attribute_id` (`display_name`,`mobile_device_extension_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_group_memberships`
--

DROP TABLE IF EXISTS `mobile_device_group_memberships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_group_memberships` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mobile_device_group_id` int NOT NULL DEFAULT '-1',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `group_id_mobile_device_id` (`mobile_device_group_id`,`mobile_device_id`),
  KEY `mobile_device_id_group_id` (`mobile_device_id`,`mobile_device_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_groups`
--

DROP TABLE IF EXISTS `mobile_device_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_groups` (
  `mobile_device_group_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_group_description` longtext COLLATE utf8mb3_unicode_ci,
  `is_smart_group` tinyint(1) NOT NULL DEFAULT '0',
  `requires_live_lookup` tinyint(1) NOT NULL DEFAULT '0',
  `notify_on_change` tinyint(1) NOT NULL DEFAULT '0',
  `wallpaper_settings_id` int NOT NULL DEFAULT '-1',
  `watch_enrollment_settings_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`mobile_device_group_id`),
  KEY `is_smart_group` (`is_smart_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_inhouse_app_validator_settings`
--

DROP TABLE IF EXISTS `mobile_device_inhouse_app_validator_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_inhouse_app_validator_settings` (
  `is_enabled` int NOT NULL DEFAULT '0',
  `frequency` int NOT NULL DEFAULT '1',
  `last_validation_epoch_time` bigint NOT NULL DEFAULT '0',
  `next_validation_epoch_time` bigint NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_installed_applications`
--

DROP TABLE IF EXISTS `mobile_device_installed_applications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_installed_applications` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `mobile_device_application_detail_id` int NOT NULL DEFAULT '-1',
  `bundle_size` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '0',
  `dynamic_size` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '0',
  `management_status` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_validated` tinyint(1) NOT NULL DEFAULT '0',
  `has_update_available` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_id_and_details_id` (`mobile_device_id`,`mobile_device_application_detail_id`),
  KEY `mobile_device_application_detail_id` (`mobile_device_application_detail_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_installed_applications_history`
--

DROP TABLE IF EXISTS `mobile_device_installed_applications_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_installed_applications_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `mobile_device_application_detail_id` int NOT NULL DEFAULT '-1',
  `application_history_type_cd` varchar(4) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `mobile_device_application_history_key` (`report_id`,`mobile_device_application_detail_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_installed_certificates`
--

DROP TABLE IF EXISTS `mobile_device_installed_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_installed_certificates` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `common_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `issuer` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_data` mediumblob,
  `cert_blob_lookup_hash` binary(16) GENERATED ALWAYS AS (unhex(md5(cast(`certificate_data` as char charset binary)))) VIRTUAL,
  `is_identity` tinyint(1) NOT NULL DEFAULT '0',
  `expiration_date_epoch` bigint NOT NULL DEFAULT '0',
  `certificate_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `report_id` (`report_id`),
  KEY `certificate_id` (`certificate_id`),
  KEY `cert_blob_lookup_hash` (`cert_blob_lookup_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_installed_profiles`
--

DROP TABLE IF EXISTS `mobile_device_installed_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_installed_profiles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_install_epoch` bigint NOT NULL DEFAULT '-1',
  `removal_disallowed` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `report_id_and_hash` (`report_id`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_installed_provisioning_profiles`
--

DROP TABLE IF EXISTS `mobile_device_installed_provisioning_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_installed_provisioning_profiles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL DEFAULT '-1',
  `hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `expiration_date_epoch` bigint NOT NULL DEFAULT '0',
  `profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `report_id_and_hash` (`report_id`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_installed_user_profiles`
--

DROP TABLE IF EXISTS `mobile_device_installed_user_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_installed_user_profiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_install_epoch` bigint NOT NULL DEFAULT '-1',
  `removal_disallowed` tinyint(1) NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  PRIMARY KEY (`id`),
  KEY `management_id_username_payload_uuid` (`mobile_device_management_id`,`username`,`payload_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_lost_mode`
--

DROP TABLE IF EXISTS `mobile_device_lost_mode`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_lost_mode` (
  `mobile_device_lost_mode_id` int NOT NULL AUTO_INCREMENT COMMENT '[PII]',
  `lost_mode` tinyint(1) NOT NULL DEFAULT '0' COMMENT '[PII]',
  `lost_location_time` bigint NOT NULL DEFAULT '0' COMMENT '[PII]',
  `lost_location_latitude` double(18,8) NOT NULL DEFAULT '0.00000000' COMMENT '[PII]',
  `lost_location_longitude` double(18,8) NOT NULL DEFAULT '0.00000000' COMMENT '[PII]',
  `lost_location_horizontal_accuracy` double(18,8) NOT NULL DEFAULT '-1.00000000' COMMENT '[PII]',
  `lost_location_vertical_accuracy` double(18,8) NOT NULL DEFAULT '-1.00000000' COMMENT '[PII]',
  `lost_location_altitude` double(18,8) NOT NULL DEFAULT '-1.00000000' COMMENT '[PII]',
  `lost_location_speed` double(18,8) NOT NULL DEFAULT '-1.00000000' COMMENT '[PII]',
  `lost_location_course` double(18,8) NOT NULL DEFAULT '-1.00000000' COMMENT '[PII]',
  `lost_location_timestamp` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `lost_message` text COLLATE utf8mb3_unicode_ci COMMENT '[PII]',
  `lost_phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `lost_footnote` text COLLATE utf8mb3_unicode_ci COMMENT '[PII]',
  `lost_persistent` tinyint(1) NOT NULL DEFAULT '0' COMMENT '[PII]',
  KEY `mobile_device_lost_mode_id` (`mobile_device_lost_mode_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_managed_app_configurations`
--

DROP TABLE IF EXISTS `mobile_device_managed_app_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_managed_app_configurations` (
  `mobile_device_managed_app_configuration_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_app_id` int NOT NULL DEFAULT '-1',
  `configuration_plist` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`mobile_device_managed_app_configuration_id`),
  KEY `mobile_device_app_id` (`mobile_device_app_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_management_commands`
--

DROP TABLE IF EXISTS `mobile_device_management_commands`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_management_commands` (
  `mobile_device_management_command_id` int NOT NULL AUTO_INCREMENT,
  `client_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `command` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_id` int NOT NULL DEFAULT '-1',
  `profile_udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_sent_epoch` bigint NOT NULL DEFAULT '0',
  `date_completed_epoch` bigint NOT NULL DEFAULT '0',
  `push_sent_epoch` bigint NOT NULL DEFAULT '0',
  `command_valid_after_epoch` bigint NOT NULL DEFAULT '0',
  `apns_result_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `inactive` tinyint(1) NOT NULL DEFAULT '0',
  `command_attributes` longtext COLLATE utf8mb3_unicode_ci,
  `command_group_id` int NOT NULL DEFAULT '-1',
  `retry_count` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_management_command_id`),
  UNIQUE KEY `uuid_unique` (`uuid`),
  KEY `client_management_id` (`client_management_id`),
  KEY `command_group_id` (`command_group_id`),
  KEY `status_inactive` (`apns_result_status`,`inactive`),
  KEY `client_management_id_and_status` (`client_management_id`,`apns_result_status`),
  KEY `client_management_id_command_profile_id` (`client_management_id`,`profile_id`,`command`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_management_inventory_collection_preferences`
--

DROP TABLE IF EXISTS `mobile_device_management_inventory_collection_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_management_inventory_collection_preferences` (
  `inventory_frequency` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Once every day',
  `collect_unmanaged_apps` tinyint(1) NOT NULL DEFAULT '1',
  `accept_unused_redemption_codes_from_mdm` tinyint(1) NOT NULL DEFAULT '1',
  `update_ldap_info_on_mobile_device_inventory_submissions` tinyint(1) NOT NULL DEFAULT '0',
  `monitor_beacons` tinyint(1) NOT NULL DEFAULT '0',
  `collect_unmanaged_certificates` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_management_ios_app_settings`
--

DROP TABLE IF EXISTS `mobile_device_management_ios_app_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_management_ios_app_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `keep_all_apps_desc_icon_up_to_date` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_sync_time` int NOT NULL DEFAULT '0' COMMENT 'This is the time in seconds after midnight that app version, description, and icon get synced with iTunes App Store.',
  `itunes_default_region` varchar(2) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'US' COMMENT 'This is the iTunes App Store region used to check for version updates.',
  `auto_update_automatically_installed_apps` tinyint(1) NOT NULL DEFAULT '0',
  `auto_update_self_service_installed_apps` tinyint(1) NOT NULL DEFAULT '0',
  `auto_update_ios_in_house_apps_deployed_through_self_service` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_prestage_device_assignments`
--

DROP TABLE IF EXISTS `mobile_device_prestage_device_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_prestage_device_assignments` (
  `mobile_device_prestage_device_assignment_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_prestage_id` int NOT NULL DEFAULT '-1',
  `device_enrollment_program_device_serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `created_by` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_prestage_device_assignment_id`),
  UNIQUE KEY `device_enrollment_program_device_serial_number_unique` (`device_enrollment_program_device_serial_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_prestage_device_names`
--

DROP TABLE IF EXISTS `mobile_device_prestage_device_names`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_prestage_device_names` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_prestage_id` int NOT NULL DEFAULT '-1',
  `device_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `used` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `mobile_device_prestage_id` (`mobile_device_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_prestage_locations`
--

DROP TABLE IF EXISTS `mobile_device_prestage_locations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_prestage_locations` (
  `mobile_device_prestage_location_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_prestage_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `building_id` int NOT NULL DEFAULT '-1',
  `department_id` int NOT NULL DEFAULT '-1',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_prestage_location_id`),
  KEY `mobile_device_prestage_id` (`mobile_device_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_prestage_purchasing`
--

DROP TABLE IF EXISTS `mobile_device_prestage_purchasing`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_prestage_purchasing` (
  `mobile_device_prestage_purchasing_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_prestage_id` int NOT NULL DEFAULT '-1',
  `is_leased` tinyint(1) NOT NULL DEFAULT '0',
  `is_purchased` tinyint(1) NOT NULL DEFAULT '0',
  `applecare_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `po_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `vendor` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_price` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `life_expectancy` int NOT NULL DEFAULT '-1',
  `purchasing_account` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lease_date_epoch` bigint NOT NULL DEFAULT '0',
  `po_date_epoch` bigint NOT NULL DEFAULT '0',
  `warranty_date_epoch` bigint NOT NULL DEFAULT '0',
  `version_lock` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_prestage_purchasing_id`),
  KEY `mobile_device_prestage_id` (`mobile_device_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_prestage_skip_step_associations`
--

DROP TABLE IF EXISTS `mobile_device_prestage_skip_step_associations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_prestage_skip_step_associations` (
  `mobile_device_prestage_skip_step_association_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_prestage_id` int NOT NULL DEFAULT '-1',
  `mobile_device_prestage_skip_step` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`mobile_device_prestage_skip_step_association_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_prestages`
--

DROP TABLE IF EXISTS `mobile_device_prestages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_prestages` (
  `mobile_device_prestage_id` int NOT NULL AUTO_INCREMENT,
  `device_enrollment_program_instance_id` int NOT NULL DEFAULT '-1',
  `profile_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `allow_pairing` tinyint(1) NOT NULL DEFAULT '0',
  `is_supervised` tinyint(1) NOT NULL DEFAULT '0',
  `is_multi_user` tinyint(1) NOT NULL DEFAULT '0',
  `maximum_shared_accounts` int NOT NULL DEFAULT '10',
  `storage_quota_size` int NOT NULL DEFAULT '0',
  `use_storage_quota_size` tinyint(1) NOT NULL DEFAULT '0',
  `auto_advance_setup` tinyint(1) NOT NULL DEFAULT '0',
  `is_mandatory` tinyint(1) NOT NULL DEFAULT '0',
  `is_mdm_removable` tinyint(1) NOT NULL DEFAULT '0',
  `support_phone_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `support_email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_magic` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `department` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `require_authentication` tinyint(1) NOT NULL DEFAULT '0',
  `authentication_prompt` longtext COLLATE utf8mb3_unicode_ci,
  `anchor_certs` longblob,
  `enrollment_site_id` int NOT NULL DEFAULT '-1',
  `keep_existing_site_membership` tinyint(1) NOT NULL DEFAULT '0',
  `device_naming_configured` tinyint(1) NOT NULL DEFAULT '0',
  `assign_names_using` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `assign_names_prefix` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `assign_names_suffix` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `assign_single_device_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `manage_names` tinyint(1) NOT NULL DEFAULT '0',
  `keep_existing_location_information` tinyint(1) NOT NULL DEFAULT '0',
  `default_prestage` tinyint(1) NOT NULL DEFAULT '0',
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  `prevent_activation_lock` tinyint(1) NOT NULL DEFAULT '0',
  `enable_device_based_activation_lock` tinyint(1) NOT NULL DEFAULT '0',
  `configure_device_before_setup_assistant` tinyint(1) NOT NULL DEFAULT '0',
  `version_lock` bigint NOT NULL DEFAULT '0',
  `language` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `region` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enrollment_customization_id` int NOT NULL DEFAULT '0',
  `send_timezone` tinyint(1) NOT NULL DEFAULT '0',
  `timezone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'America/Chicago',
  `temporary_session_only` tinyint(1) NOT NULL DEFAULT '0',
  `enforce_temporary_session_timeout` tinyint(1) NOT NULL DEFAULT '0',
  `temporary_session_timeout` int DEFAULT NULL,
  `enforce_user_session_timeout` tinyint(1) NOT NULL DEFAULT '0',
  `user_session_timeout` int DEFAULT NULL,
  `minimum_os_message_ios` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_os_target_version_ios` int NOT NULL DEFAULT '0',
  `minimum_os_specific_version_ios` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_os_message_ipad` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_os_target_version_ipad` int NOT NULL DEFAULT '0',
  `minimum_os_specific_version_ipad` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `rts_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `rts_config_profile_id` int DEFAULT NULL,
  `is_return_to_service` tinyint(1) NOT NULL DEFAULT '0',
  `install_apps_during_enrollment` tinyint(1) NOT NULL DEFAULT '0',
  `do_not_use_profile_from_backup` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_security`
--

DROP TABLE IF EXISTS `mobile_device_security`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_security` (
  `mobile_device_security_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `bootstrap_token` mediumblob,
  PRIMARY KEY (`mobile_device_security_id`),
  UNIQUE KEY `mobile_device_id_unique` (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_self_service`
--

DROP TABLE IF EXISTS `mobile_device_self_service`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_self_service` (
  `self_service_install_type` tinyint(1) NOT NULL DEFAULT '-1',
  `require_users_to_log_in` tinyint(1) NOT NULL DEFAULT '1',
  `show_install_all_button` tinyint(1) NOT NULL DEFAULT '1',
  `prompt_users_to_update_mdm_profile` tinyint(1) NOT NULL DEFAULT '1',
  `allow_external_app_updates` tinyint(1) NOT NULL DEFAULT '1',
  `allow_internal_app_updates` tinyint(1) NOT NULL DEFAULT '1',
  `user_login_level` tinyint(1) NOT NULL DEFAULT '0',
  `default_landing_page` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'HOME',
  `default_category_id` int NOT NULL DEFAULT '-2147483648'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_device_users`
--

DROP TABLE IF EXISTS `mobile_device_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_device_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `last_logged_in_username_self_service` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `last_logged_in_username_self_service_timestamp` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `mobile_device_id_unique` (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_devices`
--

DROP TABLE IF EXISTS `mobile_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_devices` (
  `mobile_device_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `asset_tag` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `configuration_profile_applied` int NOT NULL DEFAULT '0',
  `wifi_mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bluetooth_mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_managed` tinyint(1) NOT NULL DEFAULT '0',
  `user_removed_mdm_profile` tinyint(1) NOT NULL DEFAULT '0',
  `unlock_token` longtext COLLATE utf8mb3_unicode_ci,
  `completed_inventory_report_since_enrollment` tinyint(1) NOT NULL DEFAULT '1',
  `mdm_access_rights` int NOT NULL DEFAULT '2047',
  `mdm_check_in_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `tethered` tinyint(1) NOT NULL DEFAULT '0',
  `initial_entry_date_epoch` bigint NOT NULL DEFAULT '0',
  `device_push_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `use_cloud_distribution_point` tinyint(1) NOT NULL DEFAULT '0',
  `default_distribution_server_id` int NOT NULL DEFAULT '-1',
  `is_supervised` tinyint(1) NOT NULL DEFAULT '0',
  `exchange_active_sync_device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enrollment_type` int NOT NULL DEFAULT '0',
  `tv_password` text COLLATE utf8mb3_unicode_ci,
  `ble_capable` tinyint(1) NOT NULL DEFAULT '0',
  `location_services_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `device_name_type` tinyint(1) NOT NULL DEFAULT '0',
  `managed_device_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_device_multiuser` tinyint(1) NOT NULL DEFAULT '0',
  `maximum_resident_users` int NOT NULL DEFAULT '-1',
  `mobile_device_lost_mode_id` int NOT NULL DEFAULT '-1',
  `is_network_tethered` tinyint(1) NOT NULL DEFAULT '0',
  `software_update_device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`mobile_device_id`),
  KEY `udid` (`udid`),
  KEY `management_id` (`management_id`),
  KEY `serial_number` (`serial_number`),
  KEY `wifi_mac_address` (`wifi_mac_address`),
  KEY `bluetooth_mac_address` (`bluetooth_mac_address`),
  KEY `mobile_device_lost_mode_id` (`mobile_device_lost_mode_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_devices_denormalized`
--

DROP TABLE IF EXISTS `mobile_devices_denormalized`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_devices_denormalized` (
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `asset_tag` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_report_id` int NOT NULL DEFAULT '-1',
  `last_report_date_epoch` bigint NOT NULL DEFAULT '0',
  `last_backup_time_epoch` bigint NOT NULL DEFAULT '0',
  `last_enrolled_date_epoch` bigint NOT NULL DEFAULT '0',
  `is_managed` tinyint(1) NOT NULL DEFAULT '0',
  `wifi_mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bluetooth_mac_address` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ip_address` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `disk_size_mb` int NOT NULL DEFAULT '0',
  `disk_available_mb` int NOT NULL DEFAULT '0',
  `disk_percent_full` int NOT NULL DEFAULT '0',
  `phone_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `preferred_voice_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `model_version_number` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_version_comparable` int NOT NULL DEFAULT '0',
  `os_build` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_supplemental_build_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_supplemental_version_extra` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_family` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `modem_firmware` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_location_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `department_id` int NOT NULL DEFAULT '-1' COMMENT '[PII]',
  `building_id` int NOT NULL DEFAULT '-1' COMMENT '[PII]',
  `department_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `building_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `po_number` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `vendor` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `applecare_id` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `leased` tinyint(1) NOT NULL DEFAULT '0',
  `purchased` tinyint(1) NOT NULL DEFAULT '0',
  `lease_date_epoch` bigint NOT NULL DEFAULT '0',
  `po_date_epoch` bigint NOT NULL DEFAULT '0',
  `warranty_date_epoch` bigint NOT NULL DEFAULT '0',
  `purchase_price` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `life_expectancy` int NOT NULL DEFAULT '0',
  `purchasing_account` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hardware_encryption_capabilities` tinyint(1) NOT NULL DEFAULT '-1',
  `passcode_present` tinyint(1) NOT NULL DEFAULT '0',
  `block_level_encryption` tinyint(1) NOT NULL DEFAULT '0',
  `file_level_encryption` tinyint(1) NOT NULL DEFAULT '0',
  `data_protection` tinyint(1) NOT NULL DEFAULT '0',
  `passcode_is_compliant` tinyint(1) NOT NULL DEFAULT '0',
  `passcode_is_compliant_with_profile` tinyint(1) NOT NULL DEFAULT '0',
  `passcode_lock_grace_period_enforced` bigint DEFAULT NULL,
  `iccid` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `imei` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `imei2` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `eid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `meid` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cellular_technology` tinyint(1) NOT NULL DEFAULT '-1',
  `voice_roaming_enabled` tinyint(1) NOT NULL DEFAULT '-1',
  `network` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `carrier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `carrier_settings_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_mobile_country_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_mobile_network_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home_mobile_country_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home_mobile_network_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `data_roaming_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `is_roaming` tinyint(1) NOT NULL DEFAULT '0',
  `is_personal_hotspot_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `battery_level` int NOT NULL DEFAULT '-1',
  `battery_health` int NOT NULL DEFAULT '3',
  `is_supervised` tinyint(1) NOT NULL DEFAULT '0',
  `exchange_active_sync_device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enrollment_type` int NOT NULL DEFAULT '0',
  `tv_password` text COLLATE utf8mb3_unicode_ci,
  `locales` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `languages` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_locator_service_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `do_not_disturb_in_effect` tinyint(1) NOT NULL DEFAULT '0',
  `activation_lock_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `cloud_backup_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `last_cloud_backup_date_epoch` bigint NOT NULL DEFAULT '0',
  `mdm_profile_removable` tinyint(1) NOT NULL DEFAULT '0',
  `system_integrity_state` tinyint(1) NOT NULL DEFAULT '-1',
  `ble_capable` tinyint(1) NOT NULL DEFAULT '0',
  `location_services_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `device_name_type` tinyint(1) NOT NULL DEFAULT '0',
  `managed_device_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_store_account_is_active` tinyint(1) NOT NULL DEFAULT '0',
  `itunes_store_account_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_certificate_expiration` bigint NOT NULL DEFAULT '-1',
  `lost_mode` tinyint(1) NOT NULL DEFAULT '0',
  `lost_mode_enabled_date_epoch` bigint NOT NULL DEFAULT '0',
  `is_device_multiuser` tinyint(1) NOT NULL DEFAULT '0',
  `diagnostic_submission_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `app_analytics_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `device_type` tinyint(1) NOT NULL DEFAULT '-1',
  `is_network_tethered` tinyint(1) NOT NULL DEFAULT '0',
  `resident_users` bigint DEFAULT NULL,
  `quota_size` bigint DEFAULT NULL,
  `temporary_session_only` tinyint(1) DEFAULT NULL,
  `temporary_session_timeout` bigint DEFAULT NULL,
  `user_session_timeout` bigint DEFAULT NULL,
  `time_zone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_enrollment_session_token_valid` tinyint(1) NOT NULL DEFAULT '-1',
  `declarative_device_management_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `managed_device_attestation_status_value` tinyint(1) NOT NULL DEFAULT '1',
  `last_attestation_attempt_date_epoch` bigint DEFAULT NULL,
  `last_successful_attestation_date_epoch` bigint DEFAULT NULL,
  `bootstrap_token_escrowed` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`mobile_device_id`),
  KEY `display_name` (`display_name`),
  KEY `udid` (`udid`),
  KEY `management_id` (`management_id`),
  KEY `last_report_id` (`last_report_id`),
  KEY `wifi_mac_address` (`wifi_mac_address`),
  KEY `bluetooth_mac_address` (`bluetooth_mac_address`),
  KEY `serial_number` (`serial_number`),
  KEY `last_location_id` (`last_location_id`),
  KEY `username` (`username`),
  KEY `realname` (`realname`),
  KEY `email` (`email`),
  KEY `department_name` (`department_name`),
  KEY `building_name` (`building_name`),
  KEY `room` (`room`),
  KEY `position` (`position`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mobile_user_pushtoken`
--

DROP TABLE IF EXISTS `mobile_user_pushtoken`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mobile_user_pushtoken` (
  `mobile_user_pushtoken_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL DEFAULT '0',
  `user_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_short_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`mobile_user_pushtoken_id`),
  KEY `user_id` (`user_id`),
  KEY `management_id` (`management_id`),
  KEY `device_and_user_name_and_user_uuid` (`device_management_id`,`user_short_name`,`user_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `msca_endpoint_status`
--

DROP TABLE IF EXISTS `msca_endpoint_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `msca_endpoint_status` (
  `endpoint_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_successful_contact` bigint NOT NULL DEFAULT '0',
  `endpoint_state` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `domain` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`endpoint_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `msca_notification`
--

DROP TABLE IF EXISTS `msca_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `msca_notification` (
  `id` int NOT NULL AUTO_INCREMENT,
  `notification_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_integration_api_mapping`
--

DROP TABLE IF EXISTS `network_integration_api_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_integration_api_mapping` (
  `network_integration_settings_id` int NOT NULL DEFAULT '-1',
  `api_subpath` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`network_integration_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_integration_compliance`
--

DROP TABLE IF EXISTS `network_integration_compliance`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_integration_compliance` (
  `network_integration_settings_id` int NOT NULL DEFAULT '-1',
  `device_type` int NOT NULL DEFAULT '-1',
  `saved_search_id` int NOT NULL DEFAULT '-1',
  `failure_reason` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `remediation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `network_integration_settings_id` (`network_integration_settings_id`),
  KEY `saved_search_id` (`saved_search_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_integration_settings`
--

DROP TABLE IF EXISTS `network_integration_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_integration_settings` (
  `network_integration_settings_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `network_integration_type` int NOT NULL DEFAULT '-1',
  `computer_passcode_encrypted` text COLLATE utf8mb3_unicode_ci,
  `computer_passcode_type` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`network_integration_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_segments`
--

DROP TABLE IF EXISTS `network_segments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_segments` (
  `network_segment_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `starting_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ending_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `distribution_server_id` int NOT NULL DEFAULT '-1',
  `distribution_point_id` int NOT NULL DEFAULT '-1',
  `net_boot_server_id` int NOT NULL DEFAULT '-1',
  `software_update_server_id` int NOT NULL DEFAULT '-1',
  `department_id` int NOT NULL DEFAULT '-1',
  `building_id` int NOT NULL DEFAULT '-1',
  `override_departments` tinyint(1) NOT NULL DEFAULT '-1',
  `override_buildings` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`network_segment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oauth2_authorization`
--

DROP TABLE IF EXISTS `oauth2_authorization`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth2_authorization` (
  `primary_id` int NOT NULL AUTO_INCREMENT,
  `id` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `registered_client_id` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `principal_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `authorization_grant_type` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `authorized_scopes` varchar(2000) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `attributes` text COLLATE utf8mb3_unicode_ci,
  `state` varchar(500) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `authorization_code_value` text COLLATE utf8mb3_unicode_ci,
  `authorization_code_value_lookup_hash` varchar(256) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `authorization_code_issued_at` bigint DEFAULT NULL,
  `authorization_code_expires_at` bigint DEFAULT NULL,
  `authorization_code_metadata` text COLLATE utf8mb3_unicode_ci,
  `access_token_value` text COLLATE utf8mb3_unicode_ci,
  `access_token_value_lookup_hash` varchar(256) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `access_token_issued_at` bigint DEFAULT NULL,
  `access_token_expires_at` bigint DEFAULT NULL,
  `access_token_metadata` text COLLATE utf8mb3_unicode_ci,
  `access_token_type` varchar(100) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `access_token_scopes` varchar(1000) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `oidc_id_token_value` text COLLATE utf8mb3_unicode_ci,
  `oidc_id_token_issued_at` bigint DEFAULT NULL,
  `oidc_id_token_expires_at` bigint DEFAULT NULL,
  `oidc_id_token_metadata` text COLLATE utf8mb3_unicode_ci,
  `oidc_id_token_claims` text COLLATE utf8mb3_unicode_ci,
  `refresh_token_value` text COLLATE utf8mb3_unicode_ci,
  `refresh_token_value_lookup_hash` varchar(256) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `refresh_token_issued_at` bigint DEFAULT NULL,
  `refresh_token_expires_at` bigint DEFAULT NULL,
  `refresh_token_metadata` text COLLATE utf8mb3_unicode_ci,
  `date_created_epoch` bigint NOT NULL DEFAULT '0',
  `date_updated_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`primary_id`),
  KEY `id` (`id`),
  KEY `authorization_code_value_lookup_hash` (`authorization_code_value_lookup_hash`),
  KEY `access_token_value_lookup_hash` (`access_token_value_lookup_hash`),
  KEY `refresh_token_value_lookup_hash` (`refresh_token_value_lookup_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oauth2_registered_client`
--

DROP TABLE IF EXISTS `oauth2_registered_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth2_registered_client` (
  `primary_id` int NOT NULL AUTO_INCREMENT,
  `id` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_id` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_id_issued_at` bigint NOT NULL DEFAULT '-1',
  `client_secret` varchar(200) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `client_secret_expires_at` bigint DEFAULT NULL,
  `client_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_authentication_methods` varchar(1000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `authorization_grant_types` varchar(1000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `redirect_uris` varchar(1000) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `scopes` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_settings` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `token_settings` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_created_epoch` bigint NOT NULL DEFAULT '0',
  `date_updated_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`primary_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oauth_token_associations`
--

DROP TABLE IF EXISTS `oauth_token_associations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_token_associations` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `token_id` bigint NOT NULL DEFAULT '-1',
  `object_type` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `idx_object_id_object_type` (`object_id`,`object_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `object_history`
--

DROP TABLE IF EXISTS `object_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `object_history` (
  `object_history_id` int NOT NULL AUTO_INCREMENT,
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `details` longtext COLLATE utf8mb3_unicode_ci,
  `object_description` longtext COLLATE utf8mb3_unicode_ci,
  `timestamp_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`object_history_id`),
  KEY `object_id` (`object_id`),
  KEY `timestamp_epoch` (`timestamp_epoch`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oidc_session_information`
--

DROP TABLE IF EXISTS `oidc_session_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oidc_session_information` (
  `token_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `oidc_token_subject_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `oidc_token_session_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `client_registration_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `expiration` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`token_uuid`),
  KEY `oidc_token_subject_id` (`oidc_token_subject_id`),
  KEY `oidc_token_session_id` (`oidc_token_session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oidc_signing_certificate`
--

DROP TABLE IF EXISTS `oidc_signing_certificate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oidc_signing_certificate` (
  `id` int NOT NULL DEFAULT '0',
  `keystore_file` mediumblob,
  `keystore_file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_store_pass_encrypted` text COLLATE utf8mb3_unicode_ci,
  `keystore_default_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_pass_encrypted` text COLLATE utf8mb3_unicode_ci,
  `keystore_setup_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oidc_user_subject_id`
--

DROP TABLE IF EXISTS `oidc_user_subject_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oidc_user_subject_id` (
  `oidc_token_subject_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_id` int NOT NULL DEFAULT '-1',
  `group_ids` varchar(2047) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_time` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`oidc_token_subject_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `onboarding_configurations`
--

DROP TABLE IF EXISTS `onboarding_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `onboarding_configurations` (
  `onboarding_configuration_id` int NOT NULL DEFAULT '-1',
  `enabled` tinyint(1) NOT NULL DEFAULT '-1',
  `created_date` bigint NOT NULL DEFAULT '-1',
  `updated_date` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`onboarding_configuration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `onboarding_items`
--

DROP TABLE IF EXISTS `onboarding_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `onboarding_items` (
  `onboarding_item_id` int NOT NULL AUTO_INCREMENT,
  `onboarding_configuration_id` int NOT NULL DEFAULT '-1',
  `entity_id` int NOT NULL DEFAULT '-1',
  `entity_type` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `priority` int NOT NULL DEFAULT '-1',
  `created_date` bigint NOT NULL DEFAULT '-1',
  `updated_date` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`onboarding_item_id`),
  KEY `fk_onboarding_config_id` (`onboarding_configuration_id`),
  CONSTRAINT `fk_onboarding_config_id` FOREIGN KEY (`onboarding_configuration_id`) REFERENCES `onboarding_configurations` (`onboarding_configuration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `operating_systems`
--

DROP TABLE IF EXISTS `operating_systems`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `operating_systems` (
  `report_id` int NOT NULL DEFAULT '0',
  `operating_system` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_build` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_supplemental_build_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operating_system_supplemental_version_extra` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `boot_rom` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `service_pack` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `master_password` tinyint(1) NOT NULL DEFAULT '0',
  `active_directory` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'N/A',
  KEY `report_id` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_installer_categories`
--

DROP TABLE IF EXISTS `os_installer_categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_installer_categories` (
  `os_installer_category_id` int NOT NULL AUTO_INCREMENT,
  `package_id` int NOT NULL DEFAULT '-1',
  `label` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `visible` tinyint(1) NOT NULL DEFAULT '0',
  `value` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`os_installer_category_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_installer_items`
--

DROP TABLE IF EXISTS `os_installer_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_installer_items` (
  `os_installer_item_id` int NOT NULL AUTO_INCREMENT,
  `package_id` int NOT NULL DEFAULT '-1',
  `os_installer_category_id` int NOT NULL DEFAULT '-1',
  `category_label` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'The legacy communication may need this even though we do not use it for lookups now',
  `label` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `visible` tinyint(1) NOT NULL DEFAULT '0',
  `value` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`os_installer_item_id`),
  KEY `os_installer_category_id` (`os_installer_category_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_update_process_manager`
--

DROP TABLE IF EXISTS `os_update_process_manager`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_update_process_manager` (
  `id` int NOT NULL AUTO_INCREMENT,
  `process_manager_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `download` tinyint(1) NOT NULL DEFAULT '-1',
  `install` tinyint(1) NOT NULL DEFAULT '-1',
  `install_later` tinyint(1) NOT NULL DEFAULT '-1',
  `apply_major_update` tinyint(1) NOT NULL DEFAULT '-1',
  `force_restart` tinyint(1) NOT NULL DEFAULT '-1',
  `retry_available_os_updates_count` tinyint(1) NOT NULL DEFAULT '-1',
  `install_action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `product_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `product_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `max_user_deferrals` int NOT NULL DEFAULT '7',
  `priority` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'LOW',
  PRIMARY KEY (`id`),
  KEY `process_manager_uuid` (`process_manager_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_update_process_manager_command_correlation`
--

DROP TABLE IF EXISTS `os_update_process_manager_command_correlation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_update_process_manager_command_correlation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `process_manager_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `os_update_process_manager_command_correlation_idx` (`process_manager_uuid`,`command_uuid`),
  KEY `process_manager_uuid` (`process_manager_uuid`),
  KEY `command_uuid` (`command_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_updates_status`
--

DROP TABLE IF EXISTS `os_updates_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_updates_status` (
  `os_updates_status_id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL DEFAULT '-1',
  `device_object_id` int NOT NULL DEFAULT '-1',
  `product_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `install_action` tinyint(1) NOT NULL DEFAULT '-1',
  `status` tinyint(1) NOT NULL DEFAULT '-1',
  `is_downloaded` tinyint(1) NOT NULL DEFAULT '0',
  `download_percentage` float NOT NULL DEFAULT '0',
  `error_code` int NOT NULL DEFAULT '-1',
  `error_domain` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `error_localized_description` longtext COLLATE utf8mb3_unicode_ci,
  `error_english_description` longtext COLLATE utf8mb3_unicode_ci,
  `deferrals_remaining` int DEFAULT NULL,
  `max_deferrals` int DEFAULT NULL,
  `next_scheduled_install_epoch` bigint DEFAULT NULL,
  `past_notifications` text COLLATE utf8mb3_unicode_ci,
  `created_epoch` bigint NOT NULL DEFAULT '0',
  `updated_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`os_updates_status_id`),
  KEY `error_domain` (`error_domain`),
  KEY `device_object_id_device_id_product_key_idx` (`device_id`,`device_object_id`,`product_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_x_configuration_profile_deployment`
--

DROP TABLE IF EXISTS `os_x_configuration_profile_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_x_configuration_profile_deployment` (
  `os_x_configuration_profile_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `os_x_configuration_profile_id` (`os_x_configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_x_configuration_profile_update_queue`
--

DROP TABLE IF EXISTS `os_x_configuration_profile_update_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_x_configuration_profile_update_queue` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `os_x_configuration_profile_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '255',
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_x_configuration_profiles`
--

DROP TABLE IF EXISTS `os_x_configuration_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_x_configuration_profiles` (
  `os_x_configuration_profile_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `profile_level` tinyint(1) NOT NULL DEFAULT '0',
  `setting` longblob,
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deployment` tinyint(1) NOT NULL DEFAULT '0',
  `icon_attachment_id` int NOT NULL DEFAULT '-1',
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `redeploy_days_before_certificate_expires` int NOT NULL DEFAULT '0',
  `last_save_epoch` bigint NOT NULL DEFAULT '0',
  `redeployment_duration_minutes` bigint NOT NULL DEFAULT '-1',
  `force_users_to_view_description` tinyint(1) NOT NULL DEFAULT '0',
  `self_service_display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_service_description` longtext COLLATE utf8mb3_unicode_ci,
  `self_service_icon_id` int NOT NULL DEFAULT '-1',
  `install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Install',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  `allow_remove` tinyint(1) NOT NULL DEFAULT '0',
  `hidden_profile` tinyint(1) NOT NULL DEFAULT '0',
  `has_scep_payload` tinyint(1) NOT NULL DEFAULT '0',
  `scep_proxy_payload_uuids` longtext COLLATE utf8mb3_unicode_ci,
  `compliance` tinyint(1) NOT NULL DEFAULT '0',
  `deferred_action_required` tinyint(1) NOT NULL DEFAULT '0',
  `requires_uamdm` tinyint(1) NOT NULL DEFAULT '0',
  `external_config_profile_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_signed` tinyint(1) NOT NULL DEFAULT '0',
  `source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'UNKNOWN',
  PRIMARY KEY (`os_x_configuration_profile_id`),
  KEY `external_config_profile_uuid` (`external_config_profile_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `os_x_installed_configuration_profiles`
--

DROP TABLE IF EXISTS `os_x_installed_configuration_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `os_x_installed_configuration_profiles` (
  `computer_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `os_x_configuration_profile_id` int NOT NULL DEFAULT '-1',
  `last_install_epoch` bigint NOT NULL DEFAULT '-1',
  `is_removable` int NOT NULL DEFAULT '1',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `profile_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  UNIQUE KEY `os_x_installed_profile_identifier_key` (`username`(100),`os_x_configuration_profile_id`,`computer_id`,`profile_identifier`(65)),
  KEY `computer_id` (`computer_id`),
  KEY `os_x_configuration_profile_id` (`os_x_configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `package_contents`
--

DROP TABLE IF EXISTS `package_contents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `package_contents` (
  `package_id` int NOT NULL DEFAULT '0',
  `file` longtext COLLATE utf8mb3_unicode_ci,
  `owner_name` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `group_name` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `modification_date` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `size` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mode` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checksum` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `idx_pc_pid_file` (`package_id`,`file`(150))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `package_objects`
--

DROP TABLE IF EXISTS `package_objects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `package_objects` (
  `package_id` int NOT NULL DEFAULT '0',
  `type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `path` longtext COLLATE utf8mb3_unicode_ci,
  `version` varchar(127) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `idx_po_pid_fn` (`package_id`,`file_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `package_receipts`
--

DROP TABLE IF EXISTS `package_receipts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `package_receipts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `package_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `computer_id_package_name` (`computer_id`,`package_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `package_upload_status`
--

DROP TABLE IF EXISTS `package_upload_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `package_upload_status` (
  `upload_status_id` int NOT NULL AUTO_INCREMENT,
  `upload_active` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`upload_status_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `packages`
--

DROP TABLE IF EXISTS `packages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `packages` (
  `package_id` int NOT NULL AUTO_INCREMENT,
  `package_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '0',
  `info` longtext COLLATE utf8mb3_unicode_ci,
  `notes` longtext COLLATE utf8mb3_unicode_ci,
  `priority` int NOT NULL DEFAULT '0',
  `fill_user_template` tinyint(1) NOT NULL DEFAULT '0',
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `size` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `format` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `fill_existing_users` tinyint(1) NOT NULL DEFAULT '0',
  `require_reboot` tinyint(1) NOT NULL DEFAULT '0',
  `install_only_if_swu_requires` tinyint(1) NOT NULL DEFAULT '0',
  `allow_uninstall` tinyint(1) NOT NULL DEFAULT '0',
  `os_requirements` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_heal_notify` tinyint(1) NOT NULL DEFAULT '0',
  `self_heal_action` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'nothing',
  `parent_package_id` int NOT NULL DEFAULT '-1',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `base_path` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ignore_conflicts` tinyint(1) NOT NULL DEFAULT '0',
  `suppress_from_dock` tinyint(1) NOT NULL DEFAULT '0',
  `suppress_eula` tinyint(1) NOT NULL DEFAULT '0',
  `suppress_registration` tinyint(1) NOT NULL DEFAULT '0',
  `suppress_updates` tinyint(1) NOT NULL DEFAULT '0',
  `install_language` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'en_US',
  `os_installer` tinyint(1) NOT NULL DEFAULT '0',
  `md5` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sha256` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hash_type` tinyint(1) NOT NULL DEFAULT '0',
  `hash_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `os_installer_version` varchar(30) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `manifest` text COLLATE utf8mb3_unicode_ci,
  `manifest_file_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sha3_512` char(128) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`package_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `paired_watch`
--

DROP TABLE IF EXISTS `paired_watch`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `paired_watch` (
  `watch_id` int NOT NULL DEFAULT '-1',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`watch_id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  CONSTRAINT `fk_iphone_id` FOREIGN KEY (`mobile_device_id`) REFERENCES `mobile_devices` (`mobile_device_id`),
  CONSTRAINT `fk_watch_id` FOREIGN KEY (`watch_id`) REFERENCES `mobile_devices` (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `parent_app_cleanup`
--

DROP TABLE IF EXISTS `parent_app_cleanup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `parent_app_cleanup` (
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `parent_app_profiles`
--

DROP TABLE IF EXISTS `parent_app_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `parent_app_profiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `restriction_profile_expiration_epoch` bigint NOT NULL DEFAULT '0',
  `allow_list_profile_expiration_epoch` bigint NOT NULL DEFAULT '0',
  `restrictions_keys_to_flip` text COLLATE utf8mb3_unicode_ci,
  `blocked_app_bundle_ids` text COLLATE utf8mb3_unicode_ci,
  `blocked_app_bundle_ids_by_genre` text COLLATE utf8mb3_unicode_ci,
  `allow_listed_bundle_ids` text COLLATE utf8mb3_unicode_ci,
  `allow_listed_websites` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `parent_app_settings`
--

DROP TABLE IF EXISTS `parent_app_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `parent_app_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `is_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `timezone_id` varchar(256) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `restricted_times` text COLLATE utf8mb3_unicode_ci,
  `mobile_device_group_id` int NOT NULL DEFAULT '-1',
  `max_parents` int NOT NULL DEFAULT '-1',
  `allow_templates` tinyint(1) NOT NULL DEFAULT '1',
  `disassociate_on_wipe_and_reenroll` tinyint(1) NOT NULL DEFAULT '1',
  `safelisted_apps` text COLLATE utf8mb3_unicode_ci,
  `allow_clear_passcode` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `password_history`
--

DROP TABLE IF EXISTS `password_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL DEFAULT '-1',
  `password` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `salt` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_changed_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `password_policy`
--

DROP TABLE IF EXISTS `password_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_policy` (
  `id` int NOT NULL DEFAULT '0',
  `lock_out_after_attempts` tinyint(1) NOT NULL DEFAULT '-1',
  `minimum_characters` tinyint(1) NOT NULL DEFAULT '-1',
  `maximum_age` int NOT NULL DEFAULT '-1',
  `minimum_age` tinyint(1) NOT NULL DEFAULT '-1',
  `cannot_reuse_last_passwords` tinyint(1) NOT NULL DEFAULT '-1',
  `require_lowercase` tinyint(1) NOT NULL DEFAULT '0',
  `require_uppercase` tinyint(1) NOT NULL DEFAULT '0',
  `require_number` tinyint(1) NOT NULL DEFAULT '0',
  `require_special_character` tinyint(1) NOT NULL DEFAULT '0',
  `allow_password_reset` tinyint(1) NOT NULL DEFAULT '0',
  `allow_password_reset_on_locked_account` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_calculation_queue`
--

DROP TABLE IF EXISTS `patch_calculation_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_calculation_queue` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `process_id` int NOT NULL DEFAULT '-1',
  `requested_object_id` int NOT NULL DEFAULT '-1',
  `requested_secondary_object_id` int NOT NULL DEFAULT '-1',
  `date_entered_epoch` bigint NOT NULL DEFAULT '0',
  `full_recalculation_required` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_capabilities`
--

DROP TABLE IF EXISTS `patch_capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_capabilities` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_id` int NOT NULL DEFAULT '-1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operator` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `isAnd` tinyint(1) NOT NULL DEFAULT '1',
  `absolute_order_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `patch_id` (`patch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_component_criteria`
--

DROP TABLE IF EXISTS `patch_component_criteria`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_component_criteria` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_component_id` int NOT NULL DEFAULT '-1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operator` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `isAnd` tinyint(1) NOT NULL DEFAULT '1',
  `absolute_order_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `patch_component_id` (`patch_component_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_components`
--

DROP TABLE IF EXISTS `patch_components`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_components` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_id` int NOT NULL DEFAULT '-1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `patch_id` (`patch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_deployment`
--

DROP TABLE IF EXISTS `patch_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_deployment` (
  `patch_policy_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `patch_policy_id` (`patch_policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_disclaimer_agreement`
--

DROP TABLE IF EXISTS `patch_disclaimer_agreement`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_disclaimer_agreement` (
  `accepted_time_epoch` bigint NOT NULL DEFAULT '0',
  `accepted_by_account_id` int NOT NULL DEFAULT '-1',
  `accepted_by_account_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`accepted_time_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_kill_apps`
--

DROP TABLE IF EXISTS `patch_kill_apps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_kill_apps` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_id` int NOT NULL DEFAULT '-1',
  `app_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `patch_id` (`patch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_notifications`
--

DROP TABLE IF EXISTS `patch_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_notifications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_software_title_id` int NOT NULL DEFAULT '-1',
  `latest_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `published_date_epoch` bigint NOT NULL DEFAULT '-1',
  `software_title_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_title_publisher` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_package`
--

DROP TABLE IF EXISTS `patch_package`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_package` (
  `id` int NOT NULL AUTO_INCREMENT,
  `software_title_configuration_id` int NOT NULL DEFAULT '0',
  `patches_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `package_id` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `patches_version` (`patches_version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_policies`
--

DROP TABLE IF EXISTS `patch_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_policies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `target_patch_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_title_id` int NOT NULL DEFAULT '-1',
  `software_title_configuration_id` int NOT NULL DEFAULT '-1',
  `deployment_method` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_service_install_button_text` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_service_self_service_description` longtext COLLATE utf8mb3_unicode_ci,
  `self_service_icon_id` int NOT NULL DEFAULT '-1',
  `self_service_enforce_deadline` tinyint(1) NOT NULL DEFAULT '0',
  `self_service_deadline` int NOT NULL DEFAULT '3',
  `self_service_reminder_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `self_service_reminder_frequency` int NOT NULL DEFAULT '4320',
  `kill_app_delay` int NOT NULL DEFAULT '5',
  `kill_app_message` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `downgrade` tinyint(1) NOT NULL DEFAULT '0',
  `notification_header` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `patch_unknown` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_policy_limitation_scope`
--

DROP TABLE IF EXISTS `patch_policy_limitation_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_policy_limitation_scope` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_policy_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_policy_status_log_actions`
--

DROP TABLE IF EXISTS `patch_policy_status_log_actions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_policy_status_log_actions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_policy_status_log_id` int NOT NULL DEFAULT '-1',
  `action` longtext COLLATE utf8mb3_unicode_ci,
  `action_order` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `patch_policy_status_log_id` (`patch_policy_status_log_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_policy_status_logs`
--

DROP TABLE IF EXISTS `patch_policy_status_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_policy_status_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_policy_id` int NOT NULL DEFAULT '-1',
  `device_id` int NOT NULL DEFAULT '-1',
  `status_code` int NOT NULL DEFAULT '0',
  `status_date` bigint NOT NULL DEFAULT '0',
  `status_message` longtext COLLATE utf8mb3_unicode_ci,
  `attempt_no` int NOT NULL DEFAULT '0',
  `most_recent_attempt` int NOT NULL DEFAULT '0',
  `manual_attempt` int NOT NULL DEFAULT '0',
  `ignored_for_patch_policy_id` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `patch_policy_id` (`patch_policy_id`),
  KEY `device_id` (`device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_queue`
--

DROP TABLE IF EXISTS `patch_queue`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_queue` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `software_title_id` int NOT NULL DEFAULT '-1',
  `device_id` int NOT NULL DEFAULT '-1',
  `have_patch_id` int NOT NULL DEFAULT '-1',
  `max_patch_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_id_and_software_title_id` (`device_id`,`software_title_id`),
  KEY `software_title_id` (`software_title_id`),
  KEY `have_patch_id` (`have_patch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_remote_source`
--

DROP TABLE IF EXISTS `patch_remote_source`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_remote_source` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` longtext COLLATE utf8mb3_unicode_ci,
  `remote_hostname` longtext COLLATE utf8mb3_unicode_ci,
  `remote_port` varchar(12) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ssl_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `certificate_validation_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_remote_source_error`
--

DROP TABLE IF EXISTS `patch_remote_source_error`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_remote_source_error` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patch_remote_source_id` int NOT NULL DEFAULT '-1',
  `error_message` longtext COLLATE utf8mb3_unicode_ci,
  `epoch_time` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_remote_source_internal`
--

DROP TABLE IF EXISTS `patch_remote_source_internal`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_remote_source_internal` (
  `id` int NOT NULL AUTO_INCREMENT,
  `memory_identifier` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_settings`
--

DROP TABLE IF EXISTS `patch_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `retries` int NOT NULL DEFAULT '3',
  `reminder_notification_default_interval_hours` int NOT NULL DEFAULT '24',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_software_title_configuration`
--

DROP TABLE IF EXISTS `patch_software_title_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_software_title_configuration` (
  `id` int NOT NULL AUTO_INCREMENT,
  `software_title_id` int NOT NULL DEFAULT '-1',
  `web_notification_updated_software` tinyint(1) NOT NULL DEFAULT '1',
  `email_notification_updated_software` tinyint(1) NOT NULL DEFAULT '1',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `software_title_id` (`software_title_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_software_title_extension_attribute_scripts`
--

DROP TABLE IF EXISTS `patch_software_title_extension_attribute_scripts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_software_title_extension_attribute_scripts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `keyId` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_title_id` int NOT NULL DEFAULT '-1',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `script_contents` longtext COLLATE utf8mb3_unicode_ci,
  `acknowledged` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `software_title_id` (`software_title_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_software_title_requirements`
--

DROP TABLE IF EXISTS `patch_software_title_requirements`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_software_title_requirements` (
  `id` int NOT NULL AUTO_INCREMENT,
  `software_title_id` int NOT NULL DEFAULT '-1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `operator` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `isAnd` tinyint(1) NOT NULL DEFAULT '1',
  `absolute_order_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `software_title_id` (`software_title_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_software_titles`
--

DROP TABLE IF EXISTS `patch_software_titles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_software_titles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `software_title_summary_name_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `publisher` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_updated` bigint NOT NULL DEFAULT '-1',
  `latest_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `app_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `patch_source_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patch_sourceable`
--

DROP TABLE IF EXISTS `patch_sourceable`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patch_sourceable` (
  `id` int NOT NULL AUTO_INCREMENT,
  `is_enabled` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patches`
--

DROP TABLE IF EXISTS `patches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `software_titles_id` int NOT NULL DEFAULT '-1',
  `version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_operating_system` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `release_date` bigint NOT NULL DEFAULT '-1',
  `reboot` tinyint(1) NOT NULL DEFAULT '1',
  `standalone` tinyint(1) NOT NULL DEFAULT '1',
  `absolute_order_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `version_software_unique` (`software_titles_id`,`version`(180))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `peripheral_type_field_choices`
--

DROP TABLE IF EXISTS `peripheral_type_field_choices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `peripheral_type_field_choices` (
  `peripheral_type_id` int NOT NULL DEFAULT '0',
  `field_number` int NOT NULL DEFAULT '0',
  `choice` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `peripheral_type_id` (`peripheral_type_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `peripheral_types`
--

DROP TABLE IF EXISTS `peripheral_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `peripheral_types` (
  `peripheral_type_id` int NOT NULL AUTO_INCREMENT,
  `peripheral_type_name` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_0_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_0_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_1_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_1_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_2_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_2_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_3_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_3_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_4_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_4_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_5_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_5_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_6_label` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_6_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`peripheral_type_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `peripherals`
--

DROP TABLE IF EXISTS `peripherals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `peripherals` (
  `peripheral_id` int NOT NULL AUTO_INCREMENT,
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_0` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_1` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_2` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_3` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_4` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_5` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_6` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bar_code_1` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `bar_code_2` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`peripheral_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pki_payload_certificate`
--

DROP TABLE IF EXISTS `pki_payload_certificate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pki_payload_certificate` (
  `id` int NOT NULL AUTO_INCREMENT,
  `encrypted_pkcs12` mediumblob,
  `encrypted_password` text COLLATE utf8mb3_unicode_ci,
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `payload_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `issued_certificate_id` int NOT NULL DEFAULT '0',
  `request_state` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `schedule_epoch` bigint NOT NULL DEFAULT '0',
  `identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `certificate_key` (`command_uuid`,`payload_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `platform_identifier`
--

DROP TABLE IF EXISTS `platform_identifier`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_identifier` (
  `identifier` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_type_id` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`identifier`),
  UNIQUE KEY `object_type_id_object_id` (`object_type_id`,`object_id`),
  KEY `identifier_object_type_id` (`identifier`,`object_type_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `plugins`
--

DROP TABLE IF EXISTS `plugins`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `plugins` (
  `report_id` int NOT NULL DEFAULT '-1',
  `plugin_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `plugin_path` longtext COLLATE utf8mb3_unicode_ci,
  `plugin_version` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  UNIQUE KEY `report_id_and_hash` (`report_id`,`hash`),
  KEY `report_id` (`report_id`),
  KEY `plugin_name` (`plugin_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policies`
--

DROP TABLE IF EXISTS `policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policies` (
  `policy_id` int NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '-1',
  `trigger_event_startup` tinyint(1) NOT NULL DEFAULT '0',
  `trigger_event_login` tinyint(1) NOT NULL DEFAULT '0',
  `trigger_event_network_state_change` tinyint(1) NOT NULL DEFAULT '0',
  `trigger_event_enrollment_complete` tinyint(1) NOT NULL DEFAULT '0',
  `trigger_event_checkin` tinyint(1) NOT NULL DEFAULT '0',
  `trigger_manual` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `distribution_server_distribution_point_id` int NOT NULL DEFAULT '-1',
  `distribution_point_id` int NOT NULL DEFAULT '-1',
  `execution_frequency` varchar(128) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `retry_event` tinyint(1) NOT NULL DEFAULT '0',
  `retry_attempts` tinyint(1) NOT NULL DEFAULT '-1',
  `notify_on_each_failed_retry` tinyint(1) NOT NULL DEFAULT '0',
  `run_swu` tinyint(1) NOT NULL DEFAULT '0',
  `restart_option_no_user` tinyint(1) NOT NULL DEFAULT '0',
  `restart_option_with_user` tinyint(1) NOT NULL DEFAULT '0',
  `reboot_in` int NOT NULL DEFAULT '5',
  `start_reboot_timer_immediately` tinyint(1) NOT NULL DEFAULT '0',
  `reboot_type` int NOT NULL DEFAULT '0',
  `start_message` longtext COLLATE utf8mb3_unicode_ci,
  `allow_user_to_defer` tinyint(1) NOT NULL DEFAULT '0',
  `allow_deferral_until_epoch` bigint NOT NULL DEFAULT '0',
  `allow_deferral_minutes` int NOT NULL DEFAULT '0',
  `finish_message` longtext COLLATE utf8mb3_unicode_ci,
  `reboot_message` longtext COLLATE utf8mb3_unicode_ci,
  `reboot_to` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `file_vault_2_reboot` tinyint(1) NOT NULL DEFAULT '0',
  `reboot_to_specified` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `update_inventory` tinyint(1) NOT NULL DEFAULT '0',
  `update_prebindings` tinyint(1) NOT NULL DEFAULT '0',
  `fix_permissions` tinyint(1) NOT NULL DEFAULT '0',
  `fix_by_host_files` tinyint(1) NOT NULL DEFAULT '0',
  `reset_computer_name` tinyint(1) NOT NULL DEFAULT '0',
  `search_for_file` longtext COLLATE utf8mb3_unicode_ci,
  `locate_file` longtext COLLATE utf8mb3_unicode_ci,
  `search_for_process` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `run_command` longtext COLLATE utf8mb3_unicode_ci,
  `delete_file` tinyint(1) NOT NULL DEFAULT '0',
  `update_locate_database` tinyint(1) NOT NULL DEFAULT '0',
  `kill_process` tinyint(1) NOT NULL DEFAULT '0',
  `install_all_cached` tinyint(1) NOT NULL DEFAULT '0',
  `flush_system_caches` tinyint(1) NOT NULL DEFAULT '0',
  `flush_user_caches` tinyint(1) NOT NULL DEFAULT '0',
  `verify_startup_disk` tinyint(1) NOT NULL DEFAULT '0',
  `available_offline` tinyint(1) NOT NULL DEFAULT '0',
  `distribution_server_swu_id` int NOT NULL DEFAULT '-1',
  `software_update_server_id` int NOT NULL DEFAULT '-1',
  `spotlight_search` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `target_drive` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '/',
  `heal` tinyint(1) NOT NULL DEFAULT '0',
  `managed_password_action` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'doNotChange',
  `begin_active_period_epoch` bigint NOT NULL DEFAULT '0',
  `end_active_period_epoch` bigint NOT NULL DEFAULT '0',
  `no_sunday` tinyint(1) NOT NULL DEFAULT '0',
  `no_monday` tinyint(1) NOT NULL DEFAULT '0',
  `no_tuesday` tinyint(1) NOT NULL DEFAULT '0',
  `no_wednesday` tinyint(1) NOT NULL DEFAULT '0',
  `no_thursday` tinyint(1) NOT NULL DEFAULT '0',
  `no_friday` tinyint(1) NOT NULL DEFAULT '0',
  `no_saturday` tinyint(1) NOT NULL DEFAULT '0',
  `no_execute_start_epoch` bigint NOT NULL DEFAULT '0',
  `no_execute_end_epoch` bigint NOT NULL DEFAULT '0',
  `use_for_self_service` tinyint(1) NOT NULL DEFAULT '0',
  `force_users_to_view_description` tinyint(1) NOT NULL DEFAULT '0',
  `self_service_display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `self_service_description` longtext COLLATE utf8mb3_unicode_ci,
  `self_service_icon_id` int NOT NULL DEFAULT '-1',
  `after_install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Reinstall',
  `install_button_text` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Install',
  `featured` tinyint(1) NOT NULL DEFAULT '0',
  `force_afp_smb` tinyint(1) NOT NULL DEFAULT '0',
  `of_mode` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'none',
  `of_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `set_of_password` tinyint(1) NOT NULL DEFAULT '0',
  `created_by` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'jss',
  `network_requirements` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'none',
  `disk_encryption_id` int NOT NULL DEFAULT '-1',
  `disk_encryption_remediate_recovery_key_type` tinyint(1) NOT NULL DEFAULT '0',
  `disk_encryption_institutional_key_id` tinyint(1) NOT NULL DEFAULT '-1',
  `disk_encryption_action` tinyint(1) NOT NULL DEFAULT '-1',
  `location_user_only` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'set to true if this policy should be scoped to just the assigned user based on location information',
  `login_without_filevault_limit` tinyint(1) NOT NULL DEFAULT '0',
  `allow_filevault_at_logout` tinyint(1) NOT NULL DEFAULT '0',
  `auth_restart` tinyint(1) NOT NULL DEFAULT '0',
  `compliance` tinyint(1) NOT NULL DEFAULT '0',
  `perform_workplace_join` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_accounts`
--

DROP TABLE IF EXISTS `policy_accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_accounts` (
  `policy_id` int NOT NULL DEFAULT '0',
  `username` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `action` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `realname` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hint` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `picture` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `backup_home_directory_to` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '/Users/Deleted Users/',
  `delete_home_directory` tinyint(1) NOT NULL DEFAULT '0',
  `admin` tinyint(1) NOT NULL DEFAULT '0',
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `hidden` tinyint(1) NOT NULL DEFAULT '0',
  `secure_token_allowed` tinyint(1) NOT NULL DEFAULT '1',
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_deployment`
--

DROP TABLE IF EXISTS `policy_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_deployment` (
  `policy_deployment_id` int NOT NULL AUTO_INCREMENT,
  `policy_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`policy_deployment_id`),
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_directory_bindings`
--

DROP TABLE IF EXISTS `policy_directory_bindings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_directory_bindings` (
  `policy_id` int NOT NULL DEFAULT '0',
  `directory_id` int NOT NULL DEFAULT '0',
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_dock_items`
--

DROP TABLE IF EXISTS `policy_dock_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_dock_items` (
  `policy_id` int NOT NULL DEFAULT '0',
  `dock_item_id` int NOT NULL DEFAULT '-1',
  `action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_history`
--

DROP TABLE IF EXISTS `policy_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_history` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `policy_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `started_epoch` bigint NOT NULL DEFAULT '0',
  `completed_epoch` bigint NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `log_id` bigint NOT NULL DEFAULT '0',
  `log_truncated` tinyint(1) NOT NULL DEFAULT '0',
  `retry_num` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `username` (`username`),
  KEY `log_id` (`log_id`),
  KEY `policy_id_computer_id_completed_epoch` (`policy_id`,`computer_id`,`completed_epoch`),
  KEY `computer_id_policy_id` (`computer_id`,`policy_id`,`log_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_kextpaths`
--

DROP TABLE IF EXISTS `policy_kextpaths`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_kextpaths` (
  `id` int NOT NULL AUTO_INCREMENT,
  `policy_id` int NOT NULL DEFAULT '0',
  `kext_path` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '1024',
  PRIMARY KEY (`id`),
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_packages`
--

DROP TABLE IF EXISTS `policy_packages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_packages` (
  `policy_package_id` int NOT NULL AUTO_INCREMENT,
  `policy_id` int NOT NULL DEFAULT '0',
  `package_id` int NOT NULL DEFAULT '0',
  `action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `fill_user_template` tinyint(1) NOT NULL DEFAULT '0',
  `fill_existing_users` tinyint(1) NOT NULL DEFAULT '0',
  KEY `policy_package_id` (`policy_package_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_printers`
--

DROP TABLE IF EXISTS `policy_printers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_printers` (
  `policy_printer_id` int NOT NULL AUTO_INCREMENT,
  `policy_id` int NOT NULL DEFAULT '0',
  `printer_id` int NOT NULL DEFAULT '0',
  `make_default` tinyint(1) NOT NULL DEFAULT '0',
  `action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Install',
  KEY `policy_printer_id` (`policy_printer_id`),
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_properties`
--

DROP TABLE IF EXISTS `policy_properties`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_properties` (
  `id` int NOT NULL DEFAULT '0',
  `policies_require_network_state_change` tinyint(1) NOT NULL DEFAULT '0',
  `allow_network_state_change_triggers` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_running`
--

DROP TABLE IF EXISTS `policy_running`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_running` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `policy_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `started_epoch` bigint NOT NULL DEFAULT '0',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `computer_id_policy_id` (`computer_id`,`policy_id`),
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_scripts`
--

DROP TABLE IF EXISTS `policy_scripts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_scripts` (
  `policy_id` int NOT NULL DEFAULT '0',
  `script_id` int NOT NULL DEFAULT '0',
  `priority` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '0',
  `parameter_1` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_2` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_3` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_4` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_5` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_6` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_7` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_8` varchar(2000) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `policy_id` (`policy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy_self_service_categories`
--

DROP TABLE IF EXISTS `policy_self_service_categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_self_service_categories` (
  `policy_id` int NOT NULL DEFAULT '-1',
  `category_id` int NOT NULL DEFAULT '-1',
  `featured` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pre_stage_computer_names`
--

DROP TABLE IF EXISTS `pre_stage_computer_names`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pre_stage_computer_names` (
  `pre_stage_id` int NOT NULL DEFAULT '-1',
  `computer_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `used` tinyint(1) NOT NULL DEFAULT '0',
  UNIQUE KEY `pre_stage_computer_names_id` (`pre_stage_id`,`computer_name`),
  KEY `pre_stage_id` (`pre_stage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pre_stage_logs`
--

DROP TABLE IF EXISTS `pre_stage_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pre_stage_logs` (
  `pre_stage_log_id` int NOT NULL AUTO_INCREMENT,
  `pre_stage_id` int NOT NULL DEFAULT '-1',
  `computer_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_id` int NOT NULL DEFAULT '-1',
  `date_entered_epoch` bigint NOT NULL DEFAULT '0',
  `log_id` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`pre_stage_log_id`),
  KEY `pre_stage_id` (`pre_stage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pre_stage_mac_addresses`
--

DROP TABLE IF EXISTS `pre_stage_mac_addresses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pre_stage_mac_addresses` (
  `pre_stage_id` int NOT NULL DEFAULT '-1',
  `mac_address` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `pre_stage_id` (`pre_stage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pre_stage_network_segments`
--

DROP TABLE IF EXISTS `pre_stage_network_segments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pre_stage_network_segments` (
  `pre_stage_id` int NOT NULL DEFAULT '-1',
  `network_segment_id` int NOT NULL DEFAULT '-1',
  KEY `pre_stage_id` (`pre_stage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pre_stage_serial_numbers`
--

DROP TABLE IF EXISTS `pre_stage_serial_numbers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pre_stage_serial_numbers` (
  `pre_stage_serial_number_id` int NOT NULL AUTO_INCREMENT,
  `pre_stage_id` int NOT NULL DEFAULT '-1',
  `serial_number` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`pre_stage_serial_number_id`),
  KEY `pre_stage_id` (`pre_stage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `prestage_notification`
--

DROP TABLE IF EXISTS `prestage_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `prestage_notification` (
  `id` int NOT NULL DEFAULT '0',
  `cleared` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `prestage_sync_state`
--

DROP TABLE IF EXISTS `prestage_sync_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `prestage_sync_state` (
  `id` int NOT NULL AUTO_INCREMENT,
  `prestage_id` int NOT NULL DEFAULT '-1',
  `state` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp` bigint NOT NULL DEFAULT '0',
  `prestage_type` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `prestage_id` (`prestage_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `printers`
--

DROP TABLE IF EXISTS `printers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `printers` (
  `printer_id` int NOT NULL AUTO_INCREMENT,
  `cups_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_uri` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `location` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '0',
  `model` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `shared` tinyint(1) NOT NULL DEFAULT '1',
  `ppd` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ppd_path` longtext COLLATE utf8mb3_unicode_ci,
  `contents` longblob,
  `info` longtext COLLATE utf8mb3_unicode_ci,
  `notes` longtext COLLATE utf8mb3_unicode_ci,
  `os_requirements` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `make_default` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`printer_id`),
  KEY `display_name` (`display_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_BLOB_TRIGGERS`
--

DROP TABLE IF EXISTS `pro_scheduler_BLOB_TRIGGERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_BLOB_TRIGGERS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `blob_data` blob,
  PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
  CONSTRAINT `fk_blob_triggers` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `pro_scheduler_TRIGGERS` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_CALENDARS`
--

DROP TABLE IF EXISTS `pro_scheduler_CALENDARS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_CALENDARS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `calendar_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `calendar_blob` blob,
  PRIMARY KEY (`sched_name`,`calendar_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_CRON_TRIGGERS`
--

DROP TABLE IF EXISTS `pro_scheduler_CRON_TRIGGERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_CRON_TRIGGERS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cron_expression` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `time_zone_id` varchar(80) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
  CONSTRAINT `fk_cron_triggers` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `pro_scheduler_TRIGGERS` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_FIRED_TRIGGERS`
--

DROP TABLE IF EXISTS `pro_scheduler_FIRED_TRIGGERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_FIRED_TRIGGERS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `entry_id` varchar(95) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `instance_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `fired_time` bigint NOT NULL DEFAULT '-1',
  `sched_time` bigint NOT NULL DEFAULT '-1',
  `priority` int NOT NULL DEFAULT '-1',
  `state` varchar(16) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_name` varchar(200) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `job_group` varchar(200) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `is_nonconcurrent` varchar(1) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `requests_recovery` varchar(1) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`sched_name`,`entry_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_JOB_DETAILS`
--

DROP TABLE IF EXISTS `pro_scheduler_JOB_DETAILS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_JOB_DETAILS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(250) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `job_class_name` varchar(250) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_durable` varchar(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_nonconcurrent` varchar(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_update_data` varchar(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `requests_recovery` varchar(1) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_data` blob,
  PRIMARY KEY (`sched_name`,`job_name`,`job_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_LOCKS`
--

DROP TABLE IF EXISTS `pro_scheduler_LOCKS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_LOCKS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `lock_name` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`sched_name`,`lock_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_PAUSED_TRIGGER_GRPS`
--

DROP TABLE IF EXISTS `pro_scheduler_PAUSED_TRIGGER_GRPS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_PAUSED_TRIGGER_GRPS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`sched_name`,`trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_SCHEDULER_STATE`
--

DROP TABLE IF EXISTS `pro_scheduler_SCHEDULER_STATE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_SCHEDULER_STATE` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `instance_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_checkin_time` bigint NOT NULL DEFAULT '-1',
  `checkin_interval` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`sched_name`,`instance_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_SIMPLE_TRIGGERS`
--

DROP TABLE IF EXISTS `pro_scheduler_SIMPLE_TRIGGERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_SIMPLE_TRIGGERS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `repeat_count` bigint NOT NULL DEFAULT '-1',
  `repeat_interval` bigint NOT NULL DEFAULT '-1',
  `times_triggered` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
  CONSTRAINT `fk_triggers` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `pro_scheduler_TRIGGERS` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_SIMPROP_TRIGGERS`
--

DROP TABLE IF EXISTS `pro_scheduler_SIMPROP_TRIGGERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_SIMPROP_TRIGGERS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `str_prop_1` varchar(512) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `str_prop_2` varchar(512) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `str_prop_3` varchar(512) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `int_prop_1` int DEFAULT NULL,
  `int_prop_2` int DEFAULT NULL,
  `long_prop_1` bigint DEFAULT NULL,
  `long_prop_2` bigint DEFAULT NULL,
  `dec_prop_1` decimal(13,2) DEFAULT NULL,
  `dec_prop_2` decimal(13,2) DEFAULT NULL,
  `bool_prop_1` varchar(1) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `bool_prop_2` varchar(1) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
  CONSTRAINT `fk_prop_triggers` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `pro_scheduler_TRIGGERS` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pro_scheduler_TRIGGERS`
--

DROP TABLE IF EXISTS `pro_scheduler_TRIGGERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pro_scheduler_TRIGGERS` (
  `sched_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_name` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `job_group` varchar(200) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(250) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `next_fire_time` bigint DEFAULT NULL,
  `prev_fire_time` bigint DEFAULT NULL,
  `priority` int DEFAULT NULL,
  `trigger_state` varchar(16) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `trigger_type` varchar(8) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `start_time` bigint NOT NULL DEFAULT '-1',
  `end_time` bigint DEFAULT NULL,
  `calendar_name` varchar(200) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `misfire_instr` int DEFAULT NULL,
  `job_data` blob,
  PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
  KEY `fk_job_details` (`sched_name`,`job_name`,`job_group`),
  CONSTRAINT `fk_job_details` FOREIGN KEY (`sched_name`, `job_name`, `job_group`) REFERENCES `pro_scheduler_JOB_DETAILS` (`sched_name`, `job_name`, `job_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `protect_settings`
--

DROP TABLE IF EXISTS `protect_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `protect_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `registration_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `api_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `api_client_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `api_client_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `platform_plan_sync` tinyint(1) NOT NULL DEFAULT '0',
  `last_sync_epoch` bigint NOT NULL DEFAULT '0',
  `last_sync_attempt_epoch` bigint NOT NULL DEFAULT '1000000000000',
  `sync_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `auto_install_agent` tinyint(1) NOT NULL DEFAULT '1',
  `failed_retries` int NOT NULL DEFAULT '0',
  `email_notification_sent` tinyint(1) NOT NULL DEFAULT '0',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `provisioning_profiles`
--

DROP TABLE IF EXISTS `provisioning_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `provisioning_profiles` (
  `provisioning_profile_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `uuid` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `profile_contents` mediumblob,
  PRIMARY KEY (`provisioning_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `public_key_infrastructure`
--

DROP TABLE IF EXISTS `public_key_infrastructure`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `public_key_infrastructure` (
  `public_key_infrastructure_sequence` int NOT NULL AUTO_INCREMENT,
  `enrollment_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `file_vault_2_comm_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `device_enrollment_program_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `eduction_member_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `education_leader_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `education_photos_client_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `json_web_token_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `config_profile_scep_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `ldap_mutual_tls_certificate_id` int NOT NULL DEFAULT '-1',
  `pki_signing_cert_changed_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`public_key_infrastructure_sequence`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `public_key_infrastructure_backup`
--

DROP TABLE IF EXISTS `public_key_infrastructure_backup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `public_key_infrastructure_backup` (
  `ca_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enrollment_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `file_vault_2_comm_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `device_enrollment_program_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `eduction_member_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `education_leader_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `education_photos_client_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `json_web_token_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `config_profile_scep_signing_certificate_id` int NOT NULL DEFAULT '-1',
  `ldap_mutual_tls_certificate_id` int NOT NULL DEFAULT '-1',
  `backup_date` bigint NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `public_keys`
--

DROP TABLE IF EXISTS `public_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `public_keys` (
  `key_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `public_key` text COLLATE utf8mb3_unicode_ci,
  KEY `key_id` (`key_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `purchasing_information`
--

DROP TABLE IF EXISTS `purchasing_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `purchasing_information` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `peripheral_id` int NOT NULL DEFAULT '0',
  `mobile_device_id` int NOT NULL DEFAULT '0',
  `software_license_id` int NOT NULL DEFAULT '0',
  `enrollment_profile_id` int NOT NULL DEFAULT '0',
  `applecare_id` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `po_number` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `vendor` varchar(60) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `leased` tinyint(1) NOT NULL DEFAULT '0',
  `purchased` tinyint(1) NOT NULL DEFAULT '0',
  `lease_date_epoch` bigint NOT NULL DEFAULT '0',
  `po_date_epoch` bigint NOT NULL DEFAULT '0',
  `warranty_date_epoch` bigint NOT NULL DEFAULT '0',
  `purchase_price` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `life_expectancy` int NOT NULL DEFAULT '0',
  `purchasing_account` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `computer_id` (`computer_id`),
  KEY `peripheral_id` (`peripheral_id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  KEY `software_license_id` (`software_license_id`),
  KEY `enrollment_profile_id` (`enrollment_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `push_notification_framework_settings`
--

DROP TABLE IF EXISTS `push_notification_framework_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `push_notification_framework_settings` (
  `max_push_notifications_to_send_in_batch` int NOT NULL DEFAULT '100',
  `delay_between_push_notification_batches` int NOT NULL DEFAULT '20',
  `failed_batch_size` int NOT NULL DEFAULT '100',
  `sent_batch_size` int NOT NULL DEFAULT '100'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `push_notification_keystores`
--

DROP TABLE IF EXISTS `push_notification_keystores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `push_notification_keystores` (
  `push_notification_keystores_id` int NOT NULL AUTO_INCREMENT,
  `keystore_type` int NOT NULL DEFAULT '-1' COMMENT 'What this keystore record is used for (initially MDM=1,App=2,etc)',
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `keystore` mediumblob,
  `apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'Stores the Apple ID with certificate.',
  PRIMARY KEY (`push_notification_keystores_id`),
  KEY `keystore_type` (`keystore_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `push_notification_proxy_settings`
--

DROP TABLE IF EXISTS `push_notification_proxy_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `push_notification_proxy_settings` (
  `is_dev` tinyint(1) NOT NULL DEFAULT '0',
  `token_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `access_token` text COLLATE utf8mb3_unicode_ci,
  `refresh_token` text COLLATE utf8mb3_unicode_ci,
  `server_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `expires_on` bigint NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `recon_fields`
--

DROP TABLE IF EXISTS `recon_fields`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `recon_fields` (
  `field_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `field_label` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checked` tinyint(1) NOT NULL DEFAULT '0',
  `required` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `recovery_lock_entries`
--

DROP TABLE IF EXISTS `recovery_lock_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `recovery_lock_entries` (
  `id` int NOT NULL AUTO_INCREMENT,
  `recovery_lock_password` text COLLATE utf8mb3_unicode_ci,
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `queued_timestamp` bigint NOT NULL DEFAULT '0',
  `set_timestamp` bigint NOT NULL DEFAULT '0',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `rotate_password` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_command_uuid` (`command_uuid`),
  KEY `management_id` (`management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `reenrollment_settings`
--

DROP TABLE IF EXISTS `reenrollment_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `reenrollment_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `flush_mdm_commands_on_reenroll` tinyint(1) NOT NULL DEFAULT '2',
  `flush_location_information_on_remanage` tinyint(1) NOT NULL DEFAULT '0',
  `flush_location_information_history_on_remanage` tinyint(1) NOT NULL DEFAULT '0',
  `flush_extension_attribute_on_reenroll` tinyint(1) NOT NULL DEFAULT '0',
  `flush_policy_logs_on_remanage` tinyint(1) NOT NULL DEFAULT '0',
  `flush_software_update_plans_on_reenroll` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `remote_administration_connections`
--

DROP TABLE IF EXISTS `remote_administration_connections`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `remote_administration_connections` (
  `id` int NOT NULL AUTO_INCREMENT,
  `site_id` int NOT NULL DEFAULT '-1',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `token` text COLLATE utf8mb3_unicode_ci,
  `status` int NOT NULL DEFAULT '0',
  `session_timeout` bigint NOT NULL DEFAULT '15',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `remote_administration_session_information`
--

DROP TABLE IF EXISTS `remote_administration_session_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `remote_administration_session_information` (
  `id` int NOT NULL AUTO_INCREMENT,
  `connection_configuration_id` int NOT NULL DEFAULT '-1',
  `session_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_id` int NOT NULL DEFAULT '-1',
  `device_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `state` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `supporter_link` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `end_customer_link` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `session_creator` int NOT NULL DEFAULT '-1',
  `session_creator_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `session_creation_timestamp` bigint NOT NULL DEFAULT '0',
  `session_expiration_timestamp` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `connection_configuration_id` (`connection_configuration_id`),
  KEY `session_code` (`session_code`),
  KEY `device_id` (`device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `remote_assist_integration_settings`
--

DROP TABLE IF EXISTS `remote_assist_integration_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `remote_assist_integration_settings` (
  `id` int NOT NULL DEFAULT '0',
  `realm` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `removable_mac_addresses`
--

DROP TABLE IF EXISTS `removable_mac_addresses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `removable_mac_addresses` (
  `removable_mac_address_id` int NOT NULL AUTO_INCREMENT,
  `removable_mac_address` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`removable_mac_address_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `reports`
--

DROP TABLE IF EXISTS `reports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `reports` (
  `report_id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `mobile_device_id` int NOT NULL DEFAULT '0',
  `user_object_id` int NOT NULL DEFAULT '0',
  `date_entered_epoch` bigint NOT NULL DEFAULT '0',
  `total_seconds` int NOT NULL DEFAULT '0',
  `in_process` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`report_id`),
  KEY `computer_id` (`computer_id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  KEY `user_object_id` (`user_object_id`),
  KEY `date_entered_epoch` (`date_entered_epoch`),
  KEY `in_process` (`in_process`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `restricted_software`
--

DROP TABLE IF EXISTS `restricted_software`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `restricted_software` (
  `restricted_software_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `process_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `match_exact_process_name` tinyint(1) NOT NULL DEFAULT '0',
  `send_notification` tinyint(1) NOT NULL DEFAULT '0',
  `kill_process` tinyint(1) NOT NULL DEFAULT '0',
  `delete_executable` tinyint(1) NOT NULL DEFAULT '0',
  `display_message` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`restricted_software_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `restricted_software_deployment`
--

DROP TABLE IF EXISTS `restricted_software_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `restricted_software_deployment` (
  `restricted_software_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `restricted_software_id` (`restricted_software_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `retention_policies`
--

DROP TABLE IF EXISTS `retention_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `retention_policies` (
  `retention_policy_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `qualifier` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `retention_period` int NOT NULL DEFAULT '1',
  `retention_period_unit` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`retention_policy_id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `retention_policy_rules`
--

DROP TABLE IF EXISTS `retention_policy_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `retention_policy_rules` (
  `retention_policy_id` int NOT NULL DEFAULT '-1',
  `sequence` int NOT NULL DEFAULT '-1',
  `qualifier` varchar(50) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `arguments` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `retention_policy_settings`
--

DROP TABLE IF EXISTS `retention_policy_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `retention_policy_settings` (
  `hour_of_day` int NOT NULL DEFAULT '-1',
  `analyze_tables` int NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `retention_policy_tables`
--

DROP TABLE IF EXISTS `retention_policy_tables`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `retention_policy_tables` (
  `retention_policy_table_id` int NOT NULL AUTO_INCREMENT,
  `retention_policy_id` int NOT NULL DEFAULT '-1',
  `table_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `key_column_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `date_column_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parent_table_id` int DEFAULT NULL,
  `qualifier_column_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`retention_policy_table_id`)
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `return_to_service_configurations`
--

DROP TABLE IF EXISTS `return_to_service_configurations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `return_to_service_configurations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `wifi_profile_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `fk_config_id_to_profile_id` (`wifi_profile_id`),
  CONSTRAINT `fk_config_id_to_profile_id` FOREIGN KEY (`wifi_profile_id`) REFERENCES `mobile_device_configuration_profiles` (`mobile_device_configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `return_to_service_device_wipe`
--

DROP TABLE IF EXISTS `return_to_service_device_wipe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `return_to_service_device_wipe` (
  `device_wipe_id` int NOT NULL AUTO_INCREMENT,
  `configuration_id` int NOT NULL DEFAULT '-1',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`device_wipe_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roster_class`
--

DROP TABLE IF EXISTS `roster_class`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roster_class` (
  `roster_class_id` int NOT NULL AUTO_INCREMENT,
  `unique_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `source_system_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `dep_id` int NOT NULL DEFAULT '-1',
  `room` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `class_number` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `course_unique_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `location_unique_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `class_display_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `class_icon_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `status` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`roster_class_id`),
  KEY `unique_identifier` (`unique_identifier`),
  KEY `dep_id` (`dep_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roster_class_instructor`
--

DROP TABLE IF EXISTS `roster_class_instructor`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roster_class_instructor` (
  `class_unique_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_unique_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `class_unique_id` (`class_unique_id`),
  KEY `user_unique_id` (`user_unique_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roster_class_student`
--

DROP TABLE IF EXISTS `roster_class_student`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roster_class_student` (
  `class_unique_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_unique_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `class_unique_id` (`class_unique_id`),
  KEY `user_unique_id` (`user_unique_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roster_course`
--

DROP TABLE IF EXISTS `roster_course`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roster_course` (
  `roster_course_id` int NOT NULL AUTO_INCREMENT,
  `unique_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `source_system_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `dep_id` int NOT NULL DEFAULT '-1',
  `course_number` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `status` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`roster_course_id`),
  KEY `unique_identifier` (`unique_identifier`),
  KEY `rcourse_dep_id_uuid` (`dep_id`,`unique_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roster_location`
--

DROP TABLE IF EXISTS `roster_location`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roster_location` (
  `roster_location_id` int NOT NULL AUTO_INCREMENT,
  `unique_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `source` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `source_system_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `dep_id` int NOT NULL DEFAULT '-1',
  `status` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`roster_location_id`),
  KEY `unique_identifier` (`unique_identifier`),
  KEY `rloc_dep_id_uuid` (`dep_id`,`unique_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roster_user`
--

DROP TABLE IF EXISTS `roster_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roster_user` (
  `roster_user_id` int NOT NULL AUTO_INCREMENT,
  `user_object_id` int NOT NULL DEFAULT '-1',
  `roster_managed_apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `roster_name` text COLLATE utf8mb3_unicode_ci,
  `first_name` text COLLATE utf8mb3_unicode_ci COMMENT '[PII]',
  `middle_name` text COLLATE utf8mb3_unicode_ci COMMENT '[PII]',
  `last_name` text COLLATE utf8mb3_unicode_ci COMMENT '[PII]',
  `roster_source` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `roster_source_system_identifier` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `roster_unique_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `roster_passcode_type` tinyint(1) NOT NULL DEFAULT '2',
  `roster_grade` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `dep_id` int NOT NULL DEFAULT '-1',
  `status` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `person_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `sis_username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL COMMENT '[PII]',
  `is_federated_auth` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`roster_user_id`),
  KEY `user_object_id` (`user_object_id`),
  KEY `roster_managed_apple_id` (`roster_managed_apple_id`),
  KEY `roster_unique_identifier` (`roster_unique_identifier`),
  KEY `dep_id` (`dep_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `running_services`
--

DROP TABLE IF EXISTS `running_services`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `running_services` (
  `id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `service_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `computer_id_service_name` (`computer_id`,`service_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_search_criteria`
--

DROP TABLE IF EXISTS `saved_search_criteria`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_search_criteria` (
  `saved_search_criteria_id` int NOT NULL AUTO_INCREMENT,
  `saved_search_id` int NOT NULL DEFAULT '0',
  `priority` int NOT NULL DEFAULT '0',
  `search_field` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria_display` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `and_or` varchar(5) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `opening_paren` tinyint(1) NOT NULL DEFAULT '0',
  `closing_paren` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`saved_search_criteria_id`),
  KEY `saved_search_id` (`saved_search_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_search_display_fields`
--

DROP TABLE IF EXISTS `saved_search_display_fields`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_search_display_fields` (
  `saved_search_id` int NOT NULL DEFAULT '0',
  `field_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `saved_search_id` (`saved_search_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_search_email_configuration`
--

DROP TABLE IF EXISTS `saved_search_email_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_search_email_configuration` (
  `id` int NOT NULL AUTO_INCREMENT,
  `saved_search_report_configuration_id` int NOT NULL DEFAULT '-1',
  `subject` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `body` text COLLATE utf8mb3_unicode_ci,
  `email_configuration_cron_entry` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `frequency` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scheduled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_search_email_configuration_email`
--

DROP TABLE IF EXISTS `saved_search_email_configuration_email`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_search_email_configuration_email` (
  `saved_search_email_config_id` int NOT NULL DEFAULT '-1',
  `email_address_id` int NOT NULL DEFAULT '-1',
  KEY `saved_search_email_config_id` (`saved_search_email_config_id`),
  KEY `email_address_id` (`email_address_id`),
  KEY `email_config_id_email_address_id` (`saved_search_email_config_id`,`email_address_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_search_report_configuration`
--

DROP TABLE IF EXISTS `saved_search_report_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_search_report_configuration` (
  `id` int NOT NULL AUTO_INCREMENT,
  `saved_search_id` int NOT NULL DEFAULT '-1',
  `format` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `inventory_field` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `saved_search_id_unique` (`saved_search_id`),
  KEY `saved_search_id` (`saved_search_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_search_report_email`
--

DROP TABLE IF EXISTS `saved_search_report_email`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_search_report_email` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `email_address` (`email_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `saved_searches`
--

DROP TABLE IF EXISTS `saved_searches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_searches` (
  `saved_search_id` int NOT NULL AUTO_INCREMENT,
  `type` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `view_as` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sort_1` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sort_2` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sort_3` varchar(64) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`saved_search_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scep_challenges`
--

DROP TABLE IF EXISTS `scep_challenges`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scep_challenges` (
  `scep_challenge_id` int NOT NULL AUTO_INCREMENT,
  `expiration_date_epoch` bigint NOT NULL DEFAULT '0',
  `multiple_uses_allowed` tinyint(1) NOT NULL DEFAULT '0',
  `challenge_password` text COLLATE utf8mb3_unicode_ci,
  `challenge_password_lookup_hash` varchar(256) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`scep_challenge_id`),
  KEY `expiration_date_epoch` (`expiration_date_epoch`),
  KEY `challenge_password_lookup_hash` (`challenge_password_lookup_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scep_pending_transactions`
--

DROP TABLE IF EXISTS `scep_pending_transactions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scep_pending_transactions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_transaction_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_transaction_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_transaction_id_unique` (`device_transaction_id`),
  KEY `device_transaction_id` (`device_transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scheduled_deletions`
--

DROP TABLE IF EXISTS `scheduled_deletions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scheduled_deletions` (
  `scheduled_deletions_id` int NOT NULL AUTO_INCREMENT,
  `table_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deletion_interval` int NOT NULL DEFAULT '0',
  `unit` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'DAY',
  PRIMARY KEY (`scheduled_deletions_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scheduled_report`
--

DROP TABLE IF EXISTS `scheduled_report`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scheduled_report` (
  `id` int NOT NULL AUTO_INCREMENT,
  `advanced_search_id` int NOT NULL DEFAULT '-1',
  `email_configuration_id` int NOT NULL DEFAULT '-1',
  `cron_string` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `advanced_search_id` (`advanced_search_id`),
  KEY `email_configuration_id` (`email_configuration_id`),
  KEY `advanced_search_id_email_configuration_id` (`advanced_search_id`,`email_configuration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scim_audit_log`
--

DROP TABLE IF EXISTS `scim_audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scim_audit_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `scim_audit_log_change_event_id` int NOT NULL DEFAULT '-1',
  `changed_object` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `object_id` int DEFAULT NULL,
  `status` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` text COLLATE utf8mb3_unicode_ci,
  `last_update_timestamp` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `fk_scim_audit_log_change_event_id` (`scim_audit_log_change_event_id`),
  CONSTRAINT `fk_scim_audit_log_change_event_id` FOREIGN KEY (`scim_audit_log_change_event_id`) REFERENCES `scim_audit_log_change_event` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scim_audit_log_change`
--

DROP TABLE IF EXISTS `scim_audit_log_change`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scim_audit_log_change` (
  `id` int NOT NULL AUTO_INCREMENT,
  `value_id` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `scim_audit_log_id` int NOT NULL DEFAULT '-1',
  `old_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `new_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `directory_service_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_scim_audit_log_id` (`scim_audit_log_id`),
  CONSTRAINT `fk_scim_audit_log_id` FOREIGN KEY (`scim_audit_log_id`) REFERENCES `scim_audit_log` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scim_audit_log_change_event`
--

DROP TABLE IF EXISTS `scim_audit_log_change_event`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scim_audit_log_change_event` (
  `id` int NOT NULL AUTO_INCREMENT,
  `event_processing_timestamp` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scim_group_event_queue_data`
--

DROP TABLE IF EXISTS `scim_group_event_queue_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scim_group_event_queue_data` (
  `id` int NOT NULL AUTO_INCREMENT,
  `group_id` varchar(63) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `new_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `previous_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_update_timestamp` bigint NOT NULL DEFAULT '-1',
  `queue_status` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scripts`
--

DROP TABLE IF EXISTS `scripts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scripts` (
  `script_id` int NOT NULL AUTO_INCREMENT,
  `file_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `priority` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '0',
  `info` longtext COLLATE utf8mb3_unicode_ci,
  `notes` longtext COLLATE utf8mb3_unicode_ci,
  `os_requirements` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_1` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_2` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_3` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_4` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_5` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_6` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_7` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `parameter_8` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `script_contents` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`script_id`),
  UNIQUE KEY `unique_file_name` (`file_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `searchable_app_cache`
--

DROP TABLE IF EXISTS `searchable_app_cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `searchable_app_cache` (
  `bundle_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `app_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `timestamp` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`bundle_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_healing_trigger_files`
--

DROP TABLE IF EXISTS `self_healing_trigger_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_healing_trigger_files` (
  `package_id` int NOT NULL DEFAULT '0',
  `file` longtext COLLATE utf8mb3_unicode_ci,
  `compare` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `idx_shtf_pid_file` (`package_id`,`file`(150))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service`
--

DROP TABLE IF EXISTS `self_service`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service` (
  `self_service_id` int NOT NULL DEFAULT '0',
  `self_service_login_level` tinyint(1) NOT NULL DEFAULT '0',
  `self_service_login_type` tinyint(1) NOT NULL DEFAULT '0',
  `install_automatically` tinyint(1) NOT NULL DEFAULT '0',
  `install_location` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '/Applications',
  `notifications_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `alert_user_approved_mdm` tinyint(1) NOT NULL DEFAULT '1',
  `default_home_category` int NOT NULL DEFAULT '-1',
  `default_landing_page` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'HOME',
  `plugins_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'Bookmarks',
  `allow_remember_me` tinyint(1) NOT NULL DEFAULT '1',
  `use_fido2` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`self_service_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_notifications`
--

DROP TABLE IF EXISTS `self_service_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_notifications` (
  `notification_id` int NOT NULL AUTO_INCREMENT,
  `self_service_object_type` int NOT NULL DEFAULT '-1',
  `self_service_object_id` int NOT NULL DEFAULT '-1',
  `notification_subject` longtext COLLATE utf8mb3_unicode_ci,
  `notification_message` longtext COLLATE utf8mb3_unicode_ci,
  `notification_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `notification_type` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`notification_id`),
  KEY `self_service_object_type` (`self_service_object_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_notifications_objects`
--

DROP TABLE IF EXISTS `self_service_notifications_objects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_notifications_objects` (
  `id` int NOT NULL AUTO_INCREMENT,
  `notification_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `notification_status` tinyint(1) NOT NULL DEFAULT '-1',
  `notification_epoch` bigint NOT NULL DEFAULT '0',
  `mac_os_notification_status` tinyint(1) NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `notification_id` (`notification_id`),
  KEY `notification_epoch` (`notification_epoch`),
  KEY `target_status` (`target_type`,`target_id`,`notification_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_plugin_deployment`
--

DROP TABLE IF EXISTS `self_service_plugin_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_plugin_deployment` (
  `self_service_plugin_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `self_service_plugin_id` (`self_service_plugin_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_plugins`
--

DROP TABLE IF EXISTS `self_service_plugins`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_plugins` (
  `self_service_plugin_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `type` tinyint(1) NOT NULL DEFAULT '0',
  `url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` int NOT NULL DEFAULT '0',
  `priority` tinyint(1) NOT NULL DEFAULT '5',
  `icon_attachment_id` int NOT NULL DEFAULT '-1',
  `open_in_browser_automatically` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`self_service_plugin_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_plus_settings`
--

DROP TABLE IF EXISTS `self_service_plus_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_plus_settings` (
  `id` int NOT NULL DEFAULT '0',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_plus_soup_artifacts`
--

DROP TABLE IF EXISTS `self_service_plus_soup_artifacts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_plus_soup_artifacts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `soup_application_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `url` varchar(2048) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version` varchar(80) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `md5` char(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minimum_supported_os` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `updated_date` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  `created_date` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `self_service_session`
--

DROP TABLE IF EXISTS `self_service_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `self_service_session` (
  `udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  PRIMARY KEY (`udid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `serial_number_script_assignments`
--

DROP TABLE IF EXISTS `serial_number_script_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `serial_number_script_assignments` (
  `serial_number_script_id` int NOT NULL DEFAULT '-1',
  `object_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `service_discovery_enrollment_tokens`
--

DROP TABLE IF EXISTS `service_discovery_enrollment_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `service_discovery_enrollment_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `management_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `issued_timestamp` bigint NOT NULL DEFAULT '0',
  `validity` tinyint(1) NOT NULL DEFAULT '0',
  `managed_apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_token` (`token`),
  KEY `management_id` (`management_id`),
  KEY `managed_apple_id` (`managed_apple_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `service_discovery_mdm_url`
--

DROP TABLE IF EXISTS `service_discovery_mdm_url`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `service_discovery_mdm_url` (
  `service_discovery_mdm_url_id` bigint NOT NULL AUTO_INCREMENT,
  `invitation` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `check_in_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `created_timestamp` datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
  PRIMARY KEY (`service_discovery_mdm_url_id`),
  KEY `invitation` (`invitation`),
  KEY `created_timestamp` (`created_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `service_subscriptions`
--

DROP TABLE IF EXISTS `service_subscriptions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `service_subscriptions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `carrier_settings_version` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_carrier_network` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_mobile_country_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `current_mobile_network_code` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `subscriber_carrier_network` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `eid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `iccid` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `imei` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_data_preferred` tinyint(1) NOT NULL DEFAULT '0',
  `is_roaming` tinyint(1) NOT NULL DEFAULT '0',
  `is_voice_preferred` tinyint(1) NOT NULL DEFAULT '0',
  `label` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `label_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `meid` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `phone_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `slot` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `mobile_device_id` (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `shared_device_users`
--

DROP TABLE IF EXISTS `shared_device_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `shared_device_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `report_id` int NOT NULL DEFAULT '-1',
  `managed_apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `has_data_to_sync` int NOT NULL DEFAULT '0',
  `data_quota` bigint NOT NULL DEFAULT '0',
  `data_used` bigint NOT NULL DEFAULT '0',
  `is_logged_in` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `mobile_device_id` (`mobile_device_id`),
  KEY `report_id` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `shared_device_users_remove_command`
--

DROP TABLE IF EXISTS `shared_device_users_remove_command`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `shared_device_users_remove_command` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `is_remove_all` tinyint(1) NOT NULL DEFAULT '0',
  `account_id` int NOT NULL DEFAULT '0',
  `is_force_delete` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `mobile_device_id_unique` (`mobile_device_id`),
  KEY `mobile_device_id` (`mobile_device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `signing_certificates`
--

DROP TABLE IF EXISTS `signing_certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `signing_certificates` (
  `signing_certificate_id` int NOT NULL AUTO_INCREMENT,
  `keystore` mediumblob,
  `keystore_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`signing_certificate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `site_objects`
--

DROP TABLE IF EXISTS `site_objects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `site_objects` (
  `id` int NOT NULL AUTO_INCREMENT,
  `site_id` int NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `object_type_object_id_site_id` (`object_type`,`object_id`,`site_id`),
  KEY `site_id` (`site_id`),
  KEY `object_id` (`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sites`
--

DROP TABLE IF EXISTS `sites`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sites` (
  `site_id` int NOT NULL AUTO_INCREMENT,
  `site_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`site_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `smart_computer_group_criteria`
--

DROP TABLE IF EXISTS `smart_computer_group_criteria`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `smart_computer_group_criteria` (
  `smart_computer_group_criteria_id` int NOT NULL AUTO_INCREMENT,
  `computer_group_id` int NOT NULL DEFAULT '0',
  `priority` int NOT NULL DEFAULT '0',
  `search_field` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria_display` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `and_or` varchar(5) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `opening_paren` tinyint(1) NOT NULL DEFAULT '0',
  `closing_paren` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`smart_computer_group_criteria_id`),
  KEY `computer_group_id` (`computer_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `smart_mobile_device_group_criteria`
--

DROP TABLE IF EXISTS `smart_mobile_device_group_criteria`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `smart_mobile_device_group_criteria` (
  `smart_mobile_device_group_criteria_id` int NOT NULL AUTO_INCREMENT,
  `mobile_device_group_id` int NOT NULL DEFAULT '0',
  `priority` int NOT NULL DEFAULT '0',
  `search_field` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria_display` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `and_or` varchar(5) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `opening_paren` tinyint(1) NOT NULL DEFAULT '0',
  `closing_paren` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`smart_mobile_device_group_criteria_id`),
  KEY `mobile_device_group_id` (`mobile_device_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `smart_user_object_group_criteria`
--

DROP TABLE IF EXISTS `smart_user_object_group_criteria`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `smart_user_object_group_criteria` (
  `smart_user_group_criteria_id` int NOT NULL AUTO_INCREMENT,
  `user_group_id` int NOT NULL DEFAULT '0',
  `priority` int NOT NULL DEFAULT '0',
  `search_field` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `search_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `criteria_display` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `and_or` varchar(5) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `opening_paren` tinyint(1) NOT NULL DEFAULT '0',
  `closing_paren` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`smart_user_group_criteria_id`),
  KEY `user_group_id` (`user_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `smtp_server`
--

DROP TABLE IF EXISTS `smtp_server`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `smtp_server` (
  `id` int NOT NULL DEFAULT '0',
  `enabled` int NOT NULL DEFAULT '0',
  `hostname` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `port` int DEFAULT '25',
  `send_from` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `send_from_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT 'JAMF Software Server',
  `timeout` int DEFAULT '0',
  `requires_auth` tinyint(1) DEFAULT '1',
  `authentication_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'NONE',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `password_encrypted` text COLLATE utf8mb3_unicode_ci,
  `encryption` tinyint(1) DEFAULT '0',
  `encryption_protocol` varchar(32) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `graph_api_tenant_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `graph_api_client_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `graph_api_client_secret_encrypted` text COLLATE utf8mb3_unicode_ci,
  `last_update_timestamp` bigint NOT NULL DEFAULT '0',
  `google_mail_client_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `google_mail_client_secret_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `smtp_server_temp`
--

DROP TABLE IF EXISTS `smtp_server_temp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `smtp_server_temp` (
  `google_mail_client_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `google_oauth_state_encrypted` text COLLATE utf8mb3_unicode_ci,
  `google_oauth_state_encrypted_lookup_hash` varchar(256) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `send_from` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `send_from_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT 'JAMF Software Server',
  `google_mail_client_secret_encrypted` text COLLATE utf8mb3_unicode_ci,
  `created_date` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`google_mail_client_id`),
  KEY `google_oauth_state_encrypted_lookup_hash` (`google_oauth_state_encrypted_lookup_hash`),
  KEY `created_date` (`created_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_id_license_linkage_activation_statuses`
--

DROP TABLE IF EXISTS `software_id_license_linkage_activation_statuses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_id_license_linkage_activation_statuses` (
  `software_id_tag_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `license_linkage_activation_status` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `software_id_tag_id` (`software_id_tag_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_id_license_linkage_channel_types`
--

DROP TABLE IF EXISTS `software_id_license_linkage_channel_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_id_license_linkage_channel_types` (
  `software_id_tag_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `license_linkage_channel_types` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `software_id_tag_id` (`software_id_tag_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_id_license_linkage_customer_types`
--

DROP TABLE IF EXISTS `software_id_license_linkage_customer_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_id_license_linkage_customer_types` (
  `software_id_tag_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '-1',
  `license_linkage_customer_types` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `software_id_tag_id` (`software_id_tag_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_id_tags`
--

DROP TABLE IF EXISTS `software_id_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_id_tags` (
  `software_id_tag_id` int NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '-1',
  `entitlement_required_indicator` tinyint(1) NOT NULL DEFAULT '0',
  `product_title` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `product_version_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `product_version_major` bigint NOT NULL DEFAULT '0',
  `product_version_minor` bigint NOT NULL DEFAULT '0',
  `product_version_build` bigint NOT NULL DEFAULT '0',
  `product_version_review` bigint NOT NULL DEFAULT '0',
  `software_creator_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_creator_regid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_licensor_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_licensor_regid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_id_unique_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `software_id_tag_creator_regid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `tag_creator_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `tag_creator_regid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `license_linkage_channel_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`software_id_tag_id`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_licenses`
--

DROP TABLE IF EXISTS `software_licenses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_licenses` (
  `software_license_id` int NOT NULL AUTO_INCREMENT,
  `licensed_software_id` int NOT NULL DEFAULT '-1',
  `serial_number_1` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `serial_number_2` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `organization_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `registered_to` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `license_type` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `license_count` int NOT NULL DEFAULT '-1',
  `notes` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`software_license_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_event_store`
--

DROP TABLE IF EXISTS `software_update_event_store`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_event_store` (
  `plan_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `events` json NOT NULL,
  `version_lock` bigint NOT NULL DEFAULT '0',
  KEY `plan_uuid` (`plan_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_plan`
--

DROP TABLE IF EXISTS `software_update_plan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_plan` (
  `id` int NOT NULL AUTO_INCREMENT,
  `plan_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `device_id` int NOT NULL DEFAULT '-1',
  `device_object_id` int NOT NULL DEFAULT '-1',
  `update_action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version_action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `specific_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `build_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `max_user_deferrals` int DEFAULT '0',
  `force_install_local_date_time` datetime DEFAULT NULL,
  `software_update_recipe_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `plan_uuid_unique` (`plan_uuid`),
  KEY `software_update_recipe_id` (`software_update_recipe_id`),
  KEY `device_object_id_device_id` (`device_object_id`,`device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_plan_command_correlation`
--

DROP TABLE IF EXISTS `software_update_plan_command_correlation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_plan_command_correlation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `plan_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `command_uuid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `software_update_plan_command_correlation_idx` (`plan_id`,`command_uuid`),
  UNIQUE KEY `command_uuid_unique` (`command_uuid`),
  KEY `plan_id` (`plan_id`),
  KEY `command_uuid` (`command_uuid`),
  CONSTRAINT `fk_plan_id` FOREIGN KEY (`plan_id`) REFERENCES `software_update_plan` (`plan_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_plan_ddm_correlation`
--

DROP TABLE IF EXISTS `software_update_plan_ddm_correlation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_plan_ddm_correlation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `declaration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `activation_declaration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `declaration_assignment_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `plan_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `management_id_unique` (`management_id`),
  UNIQUE KEY `declaration_uuid_unique` (`declaration_uuid`),
  UNIQUE KEY `declaration_assignment_uuid_unique` (`declaration_assignment_uuid`),
  UNIQUE KEY `plan_uuid_unique` (`plan_uuid`),
  UNIQUE KEY `activation_declaration_uuid_unique` (`activation_declaration_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_recipe`
--

DROP TABLE IF EXISTS `software_update_recipe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_recipe` (
  `software_update_recipe_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `category_id` int NOT NULL DEFAULT '-1',
  `update_action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `version_action` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `specific_computer_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `specific_mobile_device_version` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `max_user_deferrals` int DEFAULT '0',
  `force_install_local_date_time` datetime DEFAULT NULL,
  PRIMARY KEY (`software_update_recipe_id`),
  KEY `display_name` (`display_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_recipe_deployment`
--

DROP TABLE IF EXISTS `software_update_recipe_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_recipe_deployment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `software_update_recipe_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `software_update_recipe_id` (`software_update_recipe_id`),
  CONSTRAINT `fk_software_update_recipe_id_deployment` FOREIGN KEY (`software_update_recipe_id`) REFERENCES `software_update_recipe` (`software_update_recipe_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_recipe_status`
--

DROP TABLE IF EXISTS `software_update_recipe_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_recipe_status` (
  `software_update_recipe_id` int NOT NULL DEFAULT '-1',
  `status` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`software_update_recipe_id`),
  CONSTRAINT `fk_software_update_recipe_id_status` FOREIGN KEY (`software_update_recipe_id`) REFERENCES `software_update_recipe` (`software_update_recipe_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_servers`
--

DROP TABLE IF EXISTS `software_update_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_servers` (
  `software_update_server_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `server_address` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `port` int NOT NULL DEFAULT '8088',
  `system_wide` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`software_update_server_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_update_state_machine`
--

DROP TABLE IF EXISTS `software_update_state_machine`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_update_state_machine` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `machine_id` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `state` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `state_machine_context` longblob,
  `error_reasons` varchar(2048) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `completed_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `machine_id_unique` (`machine_id`),
  KEY `completed_epoch` (`completed_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_updates_state_machine_inbound_events`
--

DROP TABLE IF EXISTS `software_updates_state_machine_inbound_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_updates_state_machine_inbound_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `event` json NOT NULL,
  `created_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `created_epoch` (`created_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ss_ios_branding_settings`
--

DROP TABLE IF EXISTS `ss_ios_branding_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ss_ios_branding_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `branding_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `icon_id` int DEFAULT NULL,
  `header_background_color_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `menu_icon_color_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `branding_name_color_code` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `status_bar_text_color` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ss_macos_branding_settings`
--

DROP TABLE IF EXISTS `ss_macos_branding_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ss_macos_branding_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `branding_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `icon_id` int DEFAULT NULL,
  `branding_header_image_id` int DEFAULT NULL,
  `application_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `branding_name_secondary` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `home_heading` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `home_subheading` varchar(1024) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ssmacos_vpp_content_installed`
--

DROP TABLE IF EXISTS `ssmacos_vpp_content_installed`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ssmacos_vpp_content_installed` (
  `object_id` int NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `computer_uuid` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `adam_id` bigint NOT NULL DEFAULT '-1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sso_settings`
--

DROP TABLE IF EXISTS `sso_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sso_settings` (
  `id` int NOT NULL DEFAULT '0',
  `is_enabled_jss` tinyint(1) NOT NULL DEFAULT '0',
  `sso_configuration_type` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'SAML',
  `oidc_user_mapping` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'EMAIL',
  `oidc_jamf_id_authentication_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `oidc_username_attribute_claim_mapping` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'EMAIL',
  `is_enabled_bypass` tinyint(1) NOT NULL DEFAULT '0',
  `is_enabled_osx` tinyint(1) NOT NULL DEFAULT '0',
  `is_enabled_enrollment` tinyint(1) NOT NULL DEFAULT '0',
  `is_enabled_idp_slo` tinyint(1) NOT NULL DEFAULT '0',
  `sso_providerType` tinyint(1) NOT NULL DEFAULT '-1',
  `sso_providerName` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `saml_entity_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `saml_idp_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `saml_session_timeout` int NOT NULL DEFAULT '-1',
  `saml_federationMetadataFileName` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `saml_federationMetadataFile` mediumblob,
  `keystore_file` mediumblob,
  `keystore_fileName` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_storePass` text COLLATE utf8mb3_unicode_ci,
  `keystore_defaultKey` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_pass` text COLLATE utf8mb3_unicode_ci,
  `keystore_setupType` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_type` varchar(10) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `nameId_mapping` tinyint(1) NOT NULL DEFAULT '1',
  `is_user_attribute_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `user_attribute_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `group_attribute_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'http://schemas.xmlsoap.org/claims/Group',
  `group_rdn_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `is_group_enrollment_access_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `group_enrollment_access_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `disabled_token_expiration` tinyint(1) NOT NULL DEFAULT '0',
  `failover_url_key_value` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `failover_url_key_generation_timestamp` bigint NOT NULL DEFAULT '0',
  `enrollment_sso_hosts` text COLLATE utf8mb3_unicode_ci,
  `enrollment_sso_custom_config` json NOT NULL,
  `is_enabled_enrollment_sso` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `startup_message_localized`
--

DROP TABLE IF EXISTS `startup_message_localized`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `startup_message_localized` (
  `startup_message_localized_id` int NOT NULL AUTO_INCREMENT,
  `language_code` varchar(7) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `message_description` longtext COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`startup_message_localized_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `symantec_ca`
--

DROP TABLE IF EXISTS `symantec_ca`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `symantec_ca` (
  `common_certificate_authority_settings_id` int NOT NULL DEFAULT '-1',
  `keystore_id` int NOT NULL DEFAULT '-1',
  `ws_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'https://pki-ws.symauth.com',
  `is_revocation_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `sync_timestamp_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`common_certificate_authority_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `symantec_certificate_profile`
--

DROP TABLE IF EXISTS `symantec_certificate_profile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `symantec_certificate_profile` (
  `id` int NOT NULL AUTO_INCREMENT,
  `symantec_ca_id` int NOT NULL DEFAULT '-1',
  `oid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `deployment_mode` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keysize` int NOT NULL DEFAULT '-1',
  `is_active` tinyint(1) NOT NULL DEFAULT '-1',
  `delivery_format` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `attributes` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`),
  UNIQUE KEY `symantec_certificate_profile_id` (`symantec_ca_id`,`oid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `task_assignments`
--

DROP TABLE IF EXISTS `task_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `task_assignments` (
  `task_id` int NOT NULL DEFAULT '-1',
  `computer_id` int NOT NULL DEFAULT '0',
  `ldap_server_id` int NOT NULL DEFAULT '0',
  `computer_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `building_id` int NOT NULL DEFAULT '0',
  `department_id` int NOT NULL DEFAULT '0',
  `computer_group_id` int NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tasks`
--

DROP TABLE IF EXISTS `tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tasks` (
  `task_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(120) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `command` longtext COLLATE utf8mb3_unicode_ci,
  `run_as_user` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `minute` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `hour` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `day` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `month` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `add_remove` tinyint(1) NOT NULL DEFAULT '0',
  `random_delay_seconds` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '0',
  `all_computers` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`task_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `teacher_app_profiles`
--

DROP TABLE IF EXISTS `teacher_app_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `teacher_app_profiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `teacher_profile_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `mobile_device_id` int NOT NULL DEFAULT '-1',
  `profile_expiration_epoch` bigint NOT NULL DEFAULT '0',
  `restrictions_keys_to_flip` text COLLATE utf8mb3_unicode_ci,
  `blocked_app_bundle_ids_by_genre` text COLLATE utf8mb3_unicode_ci,
  `allow_listed_app_bundle_ids` text COLLATE utf8mb3_unicode_ci,
  `lesson_links` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `teacher_app_settings`
--

DROP TABLE IF EXISTS `teacher_app_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `teacher_app_settings` (
  `id` int NOT NULL DEFAULT '-1',
  `is_enabled` tinyint(1) NOT NULL DEFAULT '-1',
  `timezone_id` varchar(256) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `auto_clear` text COLLATE utf8mb3_unicode_ci,
  `max_restriction_length` bigint DEFAULT NULL,
  `safelisted_apps` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `third_party_mdm_signing_notification`
--

DROP TABLE IF EXISTS `third_party_mdm_signing_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `third_party_mdm_signing_notification` (
  `id` int NOT NULL AUTO_INCREMENT,
  `notification_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `expiration_date` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tls_keystores`
--

DROP TABLE IF EXISTS `tls_keystores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tls_keystores` (
  `keystore_id` int NOT NULL AUTO_INCREMENT,
  `keystore` mediumblob,
  `keystore_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_filename` varchar(500) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `keystore_password_encrypted` text COLLATE utf8mb3_unicode_ci,
  PRIMARY KEY (`keystore_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ui_notification_assignments`
--

DROP TABLE IF EXISTS `ui_notification_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ui_notification_assignments` (
  `ui_notification_assignment_id` int NOT NULL AUTO_INCREMENT,
  `notification_id` int NOT NULL DEFAULT '-1',
  `object_type_id` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`ui_notification_assignment_id`),
  KEY `notification_id` (`notification_id`),
  KEY `object_type_id_object_id` (`object_type_id`,`object_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ui_notifications`
--

DROP TABLE IF EXISTS `ui_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ui_notifications` (
  `notification_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL DEFAULT '-1',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `data` longblob,
  `site_id` int NOT NULL DEFAULT '-1',
  `issued_date_epoch` bigint NOT NULL DEFAULT '-1',
  `expiration_date_epoch` bigint NOT NULL DEFAULT '-1',
  `severity` int NOT NULL DEFAULT '-1',
  `deletable` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`notification_id`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `usage_logs`
--

DROP TABLE IF EXISTS `usage_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usage_logs` (
  `usage_log_id` bigint NOT NULL AUTO_INCREMENT,
  `computer_id` int NOT NULL DEFAULT '0',
  `date_entered_epoch` bigint NOT NULL DEFAULT '0',
  `ip_address` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `action` varchar(8) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `person` varchar(40) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`usage_log_id`),
  KEY `date_entered_epoch` (`date_entered_epoch`),
  KEY `ul_compid_epochdate` (`computer_id`,`date_entered_epoch`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_group_memberships`
--

DROP TABLE IF EXISTS `user_group_memberships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_group_memberships` (
  `group_id` int NOT NULL DEFAULT '-1',
  `user_id` int NOT NULL DEFAULT '-1',
  KEY `group_id` (`group_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_group_roles`
--

DROP TABLE IF EXISTS `user_group_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_group_roles` (
  `group_id` int NOT NULL DEFAULT '0',
  `privilege` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `group_id` (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_groups`
--

DROP TABLE IF EXISTS `user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_groups` (
  `group_id` int NOT NULL AUTO_INCREMENT,
  `group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ldap_server_id` int NOT NULL DEFAULT '0',
  `directory_group_id` varchar(60) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `access_level_type` int NOT NULL DEFAULT '1',
  `privilege_level_type` int NOT NULL DEFAULT '4',
  `site_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object`
--

DROP TABLE IF EXISTS `user_object`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object` (
  `user_object_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `phone` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `position` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT '[PII]',
  `ldap_server_id` int NOT NULL DEFAULT '-1',
  `last_report_id` int NOT NULL DEFAULT '-1',
  `enable_custom_photo_url` tinyint(1) NOT NULL DEFAULT '0',
  `custom_photo_url` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `managed_apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`user_object_id`),
  KEY `username` (`username`),
  KEY `email` (`email`),
  KEY `last_report_id` (`last_report_id`),
  KEY `managed_apple_id` (`managed_apple_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object_extension_attribute_popup_choices`
--

DROP TABLE IF EXISTS `user_object_extension_attribute_popup_choices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object_extension_attribute_popup_choices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_object_extension_attribute_id` int NOT NULL DEFAULT '-1',
  `choice` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `user_object_extension_attribute_id` (`user_object_extension_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object_extension_attribute_values`
--

DROP TABLE IF EXISTS `user_object_extension_attribute_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object_extension_attribute_values` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_object_extension_attribute_id` int NOT NULL DEFAULT '-1',
  `report_id` int NOT NULL DEFAULT '-1',
  `value_on_client` longtext COLLATE utf8mb3_unicode_ci,
  `date_value_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `user_object_extension_attribute_id` (`user_object_extension_attribute_id`),
  KEY `report_id` (`report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object_extension_attributes`
--

DROP TABLE IF EXISTS `user_object_extension_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object_extension_attributes` (
  `user_object_extension_attribute_id` int NOT NULL AUTO_INCREMENT,
  `display_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` longtext COLLATE utf8mb3_unicode_ci,
  `data_type` tinyint(1) NOT NULL DEFAULT '0',
  `type` tinyint(1) NOT NULL DEFAULT '0',
  `display_in_section` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `script_contents_mac` longtext COLLATE utf8mb3_unicode_ci,
  `script_contents_windows` longtext COLLATE utf8mb3_unicode_ci,
  `script_type_windows` varchar(20) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `checked` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`user_object_extension_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object_group_memberships`
--

DROP TABLE IF EXISTS `user_object_group_memberships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object_group_memberships` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_group_id` int NOT NULL DEFAULT '-1',
  `user_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `group_id_user_id` (`user_group_id`,`user_id`),
  KEY `user_id_group_id` (`user_id`,`user_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object_groups`
--

DROP TABLE IF EXISTS `user_object_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object_groups` (
  `user_group_id` int NOT NULL AUTO_INCREMENT,
  `user_group_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_group_description` longtext COLLATE utf8mb3_unicode_ci,
  `is_smart_group` tinyint(1) NOT NULL DEFAULT '0',
  `requires_live_lookup` tinyint(1) NOT NULL DEFAULT '0',
  `notify_on_change` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`user_group_id`),
  KEY `is_smart_group` (`is_smart_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_object_metadata`
--

DROP TABLE IF EXISTS `user_object_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_object_metadata` (
  `has_migrated` tinyint(1) NOT NULL DEFAULT '0',
  `status_id` tinyint(1) NOT NULL DEFAULT '0',
  `status_percent` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_objects`
--

DROP TABLE IF EXISTS `user_objects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_objects` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_object_id` int NOT NULL DEFAULT '-1',
  `object_type` int NOT NULL DEFAULT '-1',
  `object_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `object_type_object_id` (`object_type`,`object_id`),
  KEY `object_id` (`object_id`),
  KEY `user_object_id_object_type` (`user_object_id`,`object_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_preference_json`
--

DROP TABLE IF EXISTS `user_preference_json`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_preference_json` (
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_preference_key` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `json` text COLLATE utf8mb3_unicode_ci,
  KEY `username` (`username`),
  KEY `user_preference_key` (`user_preference_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_preferences`
--

DROP TABLE IF EXISTS `user_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_preferences` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `key_pair_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `key_pair_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `key_pair_name` (`key_pair_name`),
  KEY `user_pref_username_key_pair_name` (`username`(55),`key_pair_name`(55))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_receipts`
--

DROP TABLE IF EXISTS `user_receipts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_receipts` (
  `hash` varchar(32) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `computer_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_guid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `user_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home_directory` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `home_directory_size_mb` bigint NOT NULL DEFAULT '-1',
  `admin` tinyint(1) NOT NULL DEFAULT '0',
  `file_vault_1_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `file_vault_2_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `type` tinyint(1) NOT NULL DEFAULT '0',
  UNIQUE KEY `computer_id_and_hash` (`computer_id`,`hash`),
  KEY `computer_id` (`computer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_roles`
--

DROP TABLE IF EXISTS `user_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_roles` (
  `user_id` int NOT NULL DEFAULT '0',
  `privilege` varchar(100) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `algorithm_type` int NOT NULL DEFAULT '0',
  `salt` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `realname` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `phone` varchar(31) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ldap_server_id` int NOT NULL DEFAULT '0',
  `directory_user_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `distinguished_name` longtext COLLATE utf8mb3_unicode_ci,
  `site_id` int NOT NULL DEFAULT '-1',
  `access_level_type` int NOT NULL DEFAULT '1',
  `privilege_level_type` int NOT NULL DEFAULT '4',
  `last_password_change` bigint NOT NULL DEFAULT '0',
  `change_password_on_next_login` tinyint(1) NOT NULL DEFAULT '0',
  `failed_login_attempts` int NOT NULL DEFAULT '0',
  `account_status` tinyint(1) NOT NULL DEFAULT '1',
  `password_reset_token` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password_reset_token_issued_epoch` bigint NOT NULL DEFAULT '0',
  `account_type` varchar(15) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'DEFAULT',
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `venafi_ca`
--

DROP TABLE IF EXISTS `venafi_ca`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `venafi_ca` (
  `common_certificate_authority_settings_id` int NOT NULL DEFAULT '-1',
  `keystore_id` int NOT NULL DEFAULT '-1',
  `proxy_address` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `is_revocation_enabled` tinyint(1) NOT NULL DEFAULT '1',
  `client_id` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `refresh_token` text COLLATE utf8mb3_unicode_ci,
  `refresh_expiration` bigint NOT NULL DEFAULT '0',
  `access_token` text COLLATE utf8mb3_unicode_ci,
  `access_expiration` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`common_certificate_authority_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `venafi_cert_payload_settings`
--

DROP TABLE IF EXISTS `venafi_cert_payload_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `venafi_cert_payload_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `venafi_id` int NOT NULL DEFAULT '-1',
  `subject` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `ca_distinguished_name` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `dns_names` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `email_addresses` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `zone` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `elliptic_curve` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `key_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `signature_hash` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `key_length` int DEFAULT NULL,
  `friendly_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `upns` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `payload_identifier` (`payload_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `venafi_scep_challenge_configuration`
--

DROP TABLE IF EXISTS `venafi_scep_challenge_configuration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `venafi_scep_challenge_configuration` (
  `id` int NOT NULL AUTO_INCREMENT,
  `payload_identifier` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `configuration_profile_id` int NOT NULL DEFAULT '-1',
  `configuration_profile_type` int NOT NULL DEFAULT '-1',
  `venafi_pki_id` int NOT NULL DEFAULT '-1',
  `username` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `password` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `payload_identifier_unique` (`payload_identifier`),
  KEY `configuration_profile_id` (`configuration_profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_account_purchasing_information`
--

DROP TABLE IF EXISTS `vpp_account_purchasing_information`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_account_purchasing_information` (
  `vpp_account_purchasing_information_id` int NOT NULL AUTO_INCREMENT,
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  `purchasing_contact` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `org_apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`vpp_account_purchasing_information_id`),
  KEY `vpp_location_id` (`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_assets`
--

DROP TABLE IF EXISTS `vpp_assets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_assets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  `adam_id` bigint NOT NULL DEFAULT '-1',
  `license_count` int NOT NULL DEFAULT '1',
  `used_license_count` int NOT NULL DEFAULT '0',
  `product_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `icon_url` varchar(2048) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `cost` decimal(11,2) NOT NULL DEFAULT '0.00',
  `currency` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `reported_license_count` int NOT NULL DEFAULT '0',
  `device_assignable` int NOT NULL DEFAULT '0',
  `pricing_param` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `available_in_appstore` tinyint(1) NOT NULL DEFAULT '1',
  `product_type_id` int NOT NULL DEFAULT '0',
  `b2b_custom_app` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `vpp_assets_key` (`vpp_location_id`,`adam_id`,`pricing_param`),
  KEY `adam_id_vpp_location_id` (`adam_id`,`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_assignment`
--

DROP TABLE IF EXISTS `vpp_assignment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_assignment` (
  `vpp_assignment_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`vpp_assignment_id`),
  KEY `vpp_location_id` (`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_assignment_deployment`
--

DROP TABLE IF EXISTS `vpp_assignment_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_assignment_deployment` (
  `vpp_assignment_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `vpp_assignment_id` (`vpp_assignment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_assignment_licenses`
--

DROP TABLE IF EXISTS `vpp_assignment_licenses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_assignment_licenses` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `vpp_assignment_id` int NOT NULL DEFAULT '-1',
  `adam_id` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_email_notifications`
--

DROP TABLE IF EXISTS `vpp_email_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_email_notifications` (
  `vppAdminId` int NOT NULL DEFAULT '-1',
  `expiration_epoch_time` bigint NOT NULL DEFAULT '0',
  `last_email_epoch_time` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`vppAdminId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_invitation_deployment`
--

DROP TABLE IF EXISTS `vpp_invitation_deployment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_invitation_deployment` (
  `invite_id` int NOT NULL DEFAULT '-1',
  `target_type` int NOT NULL DEFAULT '-1',
  `target_id` int NOT NULL DEFAULT '-1',
  `target_ldap_server_id` int NOT NULL DEFAULT '-1',
  `target_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `exclusion` tinyint(1) NOT NULL DEFAULT '0',
  KEY `invite_id` (`invite_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_invitation_usage`
--

DROP TABLE IF EXISTS `vpp_invitation_usage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_invitation_usage` (
  `id` int NOT NULL AUTO_INCREMENT,
  `invitation_id` int NOT NULL DEFAULT '-1',
  `user_id` int NOT NULL DEFAULT '-1',
  `invitation_uid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `sent_epoch` bigint NOT NULL DEFAULT '0',
  `last_action_enum` int NOT NULL DEFAULT '0' COMMENT 'See VolumePurchaseProgramInvitationLastActionEnum for definitions.',
  `last_action_epoch` bigint NOT NULL DEFAULT '0',
  `vpp_user_account_id` int NOT NULL DEFAULT '-1',
  `valid` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `invitation_id` (`invitation_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_invitations`
--

DROP TABLE IF EXISTS `vpp_invitations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_invitations` (
  `invite_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `message` longtext COLLATE utf8mb3_unicode_ci,
  `method` tinyint(1) NOT NULL DEFAULT '-1',
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  `send_from` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `send_from_display` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `subject` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `require_login` tinyint(1) NOT NULL DEFAULT '1',
  `auto_register_managed_users` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`invite_id`),
  KEY `vpp_location_id` (`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_licenses`
--

DROP TABLE IF EXISTS `vpp_licenses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_licenses` (
  `vpp_license_id` bigint NOT NULL AUTO_INCREMENT,
  `vpp_user_account_id` bigint NOT NULL DEFAULT '-1',
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  `adam_id` bigint NOT NULL DEFAULT '-1',
  `apple_license_id` bigint NOT NULL DEFAULT '-1' COMMENT 'The ID Apple specifies for this license',
  `product_type_id` int NOT NULL DEFAULT '-1',
  `pricing_param` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `license_status` int NOT NULL DEFAULT '-1' COMMENT 'The current status of this license, values defined by java enum',
  `product_type_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `can_revoke` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'Whether or not this license can be revoked (apps=true, books=false initially)',
  `update_epoch` bigint NOT NULL DEFAULT '0',
  `serial_number` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`vpp_license_id`),
  UNIQUE KEY `apple_license_id_unique` (`apple_license_id`),
  KEY `vpp_user_account_id` (`vpp_user_account_id`),
  KEY `adam_id_license_status` (`adam_id`,`license_status`),
  KEY `vpp_location_id_license_status` (`vpp_location_id`,`license_status`),
  KEY `adam_id_serial_number` (`adam_id`,`serial_number`),
  KEY `vpp_location_id_user_id_adam_id` (`vpp_location_id`,`vpp_user_account_id`,`adam_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_location_process_state`
--

DROP TABLE IF EXISTS `vpp_location_process_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_location_process_state` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  `licenses_since_modified_token` text COLLATE utf8mb3_unicode_ci,
  `users_since_modified_token` text COLLATE utf8mb3_unicode_ci,
  `client_context` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `local_client_context` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `vpp_location_id` (`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_locations`
--

DROP TABLE IF EXISTS `vpp_locations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_locations` (
  `vpp_location_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'JSS-side value to distinguish between different admin accounts',
  `organization_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `apple_id` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `service_token` longtext COLLATE utf8mb3_unicode_ci,
  `token_expiration` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_store_region` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `populate_catalog_from_vpp_content` tinyint(1) NOT NULL DEFAULT '0',
  `notify_disassociation` tinyint(1) NOT NULL DEFAULT '1',
  `auto_register_managed_users` tinyint(1) NOT NULL DEFAULT '0',
  `token_revoked` tinyint(1) NOT NULL DEFAULT '0',
  `location_id` bigint NOT NULL DEFAULT '-1',
  `location_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `default_platform` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `last_sync_time_epoch` bigint DEFAULT NULL,
  PRIMARY KEY (`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_retry_after_values`
--

DROP TABLE IF EXISTS `vpp_retry_after_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_retry_after_values` (
  `vpp_retry_after_values_id` int NOT NULL AUTO_INCREMENT,
  `client_context` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `retry_after_epoch` bigint NOT NULL DEFAULT '-1',
  PRIMARY KEY (`vpp_retry_after_values_id`),
  UNIQUE KEY `client_context_unique_key` (`client_context`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_subscriptions`
--

DROP TABLE IF EXISTS `vpp_subscriptions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_subscriptions` (
  `vpp_subscription_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`vpp_subscription_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_subscriptions_locations`
--

DROP TABLE IF EXISTS `vpp_subscriptions_locations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_subscriptions_locations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vpp_subscription_id` int NOT NULL DEFAULT '-1',
  `vpp_location_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `subscription_and_location` (`vpp_subscription_id`,`vpp_location_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_subscriptions_recipients`
--

DROP TABLE IF EXISTS `vpp_subscriptions_recipients`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_subscriptions_recipients` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vpp_subscription_id` int NOT NULL DEFAULT '-1',
  `user_id` int NOT NULL DEFAULT '-1',
  PRIMARY KEY (`id`),
  KEY `subscription_and_user` (`vpp_subscription_id`,`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_subscriptions_recipients_external`
--

DROP TABLE IF EXISTS `vpp_subscriptions_recipients_external`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_subscriptions_recipients_external` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vpp_subscription_id` int NOT NULL DEFAULT '-1',
  `name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `email` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `subscription_and_email` (`vpp_subscription_id`,`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_subscriptions_triggers`
--

DROP TABLE IF EXISTS `vpp_subscriptions_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_subscriptions_triggers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vpp_subscription_id` int NOT NULL DEFAULT '-1',
  `type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `subscription_and_trigger_type` (`vpp_subscription_id`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpp_user_accounts`
--

DROP TABLE IF EXISTS `vpp_user_accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpp_user_accounts` (
  `vpp_user_account_id` int NOT NULL AUTO_INCREMENT,
  `vpp_location_id` int NOT NULL DEFAULT '-1' COMMENT 'The VPP org and/or vpp_location that this user belongs to in the JSS',
  `status` int NOT NULL DEFAULT '-1' COMMENT 'Current account status, values defined by java enum',
  `itunes_store_account_hash` varchar(45) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `itunes_store_invite_url` varchar(255) COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `account_guid` varchar(45) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '' COMMENT 'GUID generated by the JSS for each VPP user account, unique per vpp_admin_account',
  `apple_generated_id` bigint NOT NULL DEFAULT '-1' COMMENT 'User id returned by the VPP service',
  `user_object_id` int NOT NULL DEFAULT '-1',
  `email_cleared` tinyint(1) NOT NULL DEFAULT '0' COMMENT '[PII]',
  PRIMARY KEY (`vpp_user_account_id`),
  KEY `account_guid` (`account_guid`),
  KEY `apple_generated_id` (`apple_generated_id`),
  KEY `user_object_id` (`user_object_id`),
  KEY `vpp_location_id_itunes_store_account_hash` (`vpp_location_id`,`itunes_store_account_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `wallpaper_auto_management_settings`
--

DROP TABLE IF EXISTS `wallpaper_auto_management_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `wallpaper_auto_management_settings` (
  `wallpaper_settings_id` int NOT NULL AUTO_INCREMENT,
  `location` tinyint(1) NOT NULL DEFAULT '1',
  `icon_id` int NOT NULL DEFAULT '-1',
  `schedule_commands` tinyint(1) NOT NULL DEFAULT '0',
  `command_frequency` tinyint(1) NOT NULL DEFAULT '0',
  `command_send_time` int NOT NULL DEFAULT '0',
  `command_next_send_epoch` bigint NOT NULL DEFAULT '0',
  PRIMARY KEY (`wallpaper_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `watch_enrollment_auto_management_settings`
--

DROP TABLE IF EXISTS `watch_enrollment_auto_management_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `watch_enrollment_auto_management_settings` (
  `watch_enrollment_settings_id` int NOT NULL AUTO_INCREMENT,
  `enrollment_enabled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`watch_enrollment_settings_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `watch_enrollment_declaration_identifier`
--

DROP TABLE IF EXISTS `watch_enrollment_declaration_identifier`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `watch_enrollment_declaration_identifier` (
  `id` int NOT NULL AUTO_INCREMENT,
  `client_management_id` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `certificate_asset_declaration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `watch_enrollment_configuration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `activation_declaration_uuid` varchar(36) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `client_management_id` (`client_management_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `watch_enrollment_security_token`
--

DROP TABLE IF EXISTS `watch_enrollment_security_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `watch_enrollment_security_token` (
  `id` int NOT NULL AUTO_INCREMENT,
  `watch_udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `security_token_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `watch_enrolled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `watch_management_pairing_token`
--

DROP TABLE IF EXISTS `watch_management_pairing_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `watch_management_pairing_token` (
  `id` int NOT NULL AUTO_INCREMENT,
  `phone_udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `watch_udid` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `pairing_token_value` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `validated` tinyint(1) NOT NULL DEFAULT '0',
  `watch_enrolled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `web_notifications`
--

DROP TABLE IF EXISTS `web_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `web_notifications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `notification_type` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `notification_params` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `webhook_display_fields`
--

DROP TABLE IF EXISTS `webhook_display_fields`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `webhook_display_fields` (
  `jss_webhook_id` int NOT NULL DEFAULT '-1',
  `field_name` varchar(255) COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-02-28 23:48:40
