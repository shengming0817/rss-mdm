//! Business-owned authority definitions, independent of the host's connection profile.
pub const OBJECTS: &str = include_str!("../schema/objects.json");
pub const ACCESS_CONTRACT: &str = include_str!("../schema/access.json");
pub async fn verify_authority(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    for (signature, source, roles, language, definer, returns_set, result) in [
        (
            "rss_da.binding_application_current(jsonb,bigint)",
            include_str!("../schema/platform-qualifications.sql"),
            &[
                "da_access",
                "da_identity_runtime",
                "da_inventory_runtime",
                "da_scope_runtime",
                "da_policy_runtime",
                "da_telemetry_runtime",
                "da_command_runtime",
                "mdm_access",
                "mdm_identity_runtime",
                "mdm_command_runtime",
                "mdm_policy_runtime",
            ] as &[&str],
            "sql",
            true,
            false,
            "boolean",
        ),
        (
            "rss_da.deployment_valid_until(text,jsonb,uuid,bigint)",
            include_str!("../schema/platform-qualifications.sql"),
            &["da_access", "da_identity_runtime", "mdm_identity_runtime"],
            "sql",
            true,
            false,
            "bigint",
        ),
        (
            "rss_da.platform_session_qualifications(uuid,jsonb,bigint)",
            include_str!("../schema/platform-qualifications.sql"),
            &["da_access", "da_identity_runtime", "mdm_identity_runtime"],
            "sql",
            true,
            true,
            "record",
        ),
        (
            "rss_da.platform_registration_matches(uuid,bigint,jsonb)",
            include_str!("../schema/platform-qualifications.sql"),
            &["da_access", "da_command_runtime", "mdm_command_runtime"],
            "sql",
            true,
            false,
            "boolean",
        ),
        (
            "rss_da.access_policy(uuid,text,bigint)",
            include_str!("../schema/device-access-qualification.sql"),
            &[
                "da_access",
                "da_command_runtime",
                "da_identity_runtime",
                "da_policy_runtime",
                "mdm_policy_runtime",
                "mdm_command_runtime",
                "mdm_identity_runtime",
            ],
            "sql",
            true,
            false,
            "jsonb",
        ),
        (
            "rss_da.active_access_binding(uuid,bigint,bigint)",
            include_str!("../schema/device-access-qualification.sql"),
            &[
                "da_access",
                "da_command_runtime",
                "da_identity_runtime",
                "da_inventory_runtime",
                "da_policy_runtime",
                "da_scope_runtime",
                "da_telemetry_runtime",
                "mdm_command_runtime",
                "mdm_identity_runtime",
            ],
            "plpgsql",
            true,
            false,
            "jsonb",
        ),
        (
            "rss_da.save_retired_access_run(text,uuid,jsonb,jsonb)",
            include_str!("../schema/device-access-tasks.sql"),
            &[
                "da_access",
                "da_command_runtime",
                "mdm_access",
                "mdm_command_runtime",
            ],
            "sql",
            true,
            false,
            "boolean",
        ),
        (
            "rss_da.access_binding_ready(jsonb)",
            include_str!("../schema/device-access.sql"),
            &[
                "da_access",
                "da_command_runtime",
                "da_identity_runtime",
                "da_inventory_runtime",
                "da_policy_runtime",
                "da_scope_runtime",
                "da_telemetry_runtime",
                "mdm_policy_runtime",
                "mdm_command_runtime",
                "mdm_identity_runtime",
            ],
            "sql",
            true,
            false,
            "boolean",
        ),
    ] {
        let name = signature.split('(').next().expect("fixed signature");
        let marker = format!("CREATE FUNCTION {name}(");
        let body = source
            .split_once(&marker)
            .expect("owner declaration")
            .1
            .split("$$")
            .nth(1)
            .expect("owner function body");
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_roles owner ON owner.oid=p.proowner WHERE p.oid=to_regprocedure($1) AND owner.rolname='da_owner' AND NOT owner.rolsuper AND NOT owner.rolbypassrls AND NOT owner.rolcreaterole AND NOT owner.rolcreatedb AND NOT owner.rolreplication AND p.prosrc=$2 AND l.lanname=$3 AND p.prokind='f' AND p.prosecdef=$4 AND p.proretset=$5 AND p.prorettype=to_regtype($6) AND NOT p.proleakproof AND p.proconfig=ARRAY['search_path=pg_catalog'] AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY($7))) AND NOT EXISTS(SELECT FROM unnest($7::text[]) role WHERE role LIKE 'da_%' AND NOT has_function_privilege(role,p.oid,'EXECUTE')))")
            .bind(signature).bind(body).bind(language).bind(definer).bind(returns_set).bind(result).bind(roles).fetch_one(&mut *c).await?;
        if !valid {
            return Err(sqlx::Error::Protocol(format!(
                "DA authority rejected: {signature}"
            )));
        }
    }
    Ok(())
}
