//! Re-encrypt existing Apple owner rows without changing protocol identities or replay MACs.
use crate::{Error, database::db};
use rss_mdm_native_protection::{DerivedAad, Protector};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row, postgres::PgRow};
use uuid::Uuid;

fn aad(tenant: &str, table: &str, column: &str, row: &PgRow) -> Result<DerivedAad, Error> {
    let id = |name| row.try_get::<Uuid, _>(name).map_err(db);
    let number = |name| row.try_get::<i64, _>(name).map_err(db);
    let text = |name| row.try_get::<String, _>(name).map_err(db);
    match table {
        "ade_servers" => crate::ade::aad(
            tenant,
            id("organization")?,
            &if column == "private_key" {
                id("key_id")?.to_string()
            } else {
                number("token_revision")?.to_string()
            },
            if column == "private_key" {
                "apple.ade.key"
            } else {
                "apple.ade.token"
            },
        ),
        "ade_enrollments" => crate::ade::aad(
            tenant,
            id("organization")?,
            &id("enrollment")?.to_string(),
            "apple.ade.profile",
        ),
        "account_flows" => crate::account_enrollment::aad(
            tenant,
            id("id")?,
            if column == "material" {
                "apple.account.material"
            } else {
                "apple.account.profile"
            },
        ),
        "profiles" => crate::profiles::aad(row),
        "declarations" | "status_reports" => crate::ddm::aad_parts(
            tenant,
            id("registration")?,
            number("generation")?,
            &text("user_key")?,
            id(if table == "status_reports" {
                "id"
            } else {
                "operation"
            })?,
            match column {
                "snapshot" => "apple.ddm.publication",
                "projection" => "apple.ddm.projection",
                _ => "apple.ddm.report",
            },
        ),
        "attempts" => crate::protection::aad(
            tenant,
            id("registration")?,
            number("generation")?,
            id("id")?,
            if column == "request" {
                crate::protection::Part::Request
            } else {
                crate::protection::Part::Response
            },
        ),
        "devices" => crate::material::aad(
            tenant,
            id("registration")?,
            number("generation")?,
            "",
            number("bootstrap_revision")?,
            "apple.bootstrap",
        ),
        "channels" => crate::material::aad(
            tenant,
            id("registration")?,
            number("generation")?,
            &text("user_key")?,
            number("token_revision")?,
            "apple.push.material",
        ),
        _ => Err(Error::Malformed),
    }
}
/// One bounded batch per concrete owner column. Caller holds the tenant maintenance transaction.
/// Locked rows are awaited: a skipped lock must not masquerade as completed rotation.
pub async fn run(c: &mut PgConnection, tenant: &str, protection: &Protector) -> Result<u64, Error> {
    let mut changed = 0;
    let prefix = protection.ciphertext_prefix();
    for (table, column) in [
        ("ade_servers", "private_key"),
        ("ade_servers", "token"),
        ("ade_enrollments", "profile"),
        ("account_flows", "material"),
        ("account_flows", "profile"),
        ("profiles", "manifest"),
        ("declarations", "snapshot"),
        ("declarations", "projection"),
        ("status_reports", "evidence"),
        ("attempts", "request"),
        ("attempts", "response"),
        ("devices", "bootstrap"),
        ("channels", "material"),
    ] {
        // Identifiers come exclusively from this exhaustive fixed list, never a caller or configuration.
        let generation = if table == "devices" {
            ",(SELECT r.generation FROM mdm_access.registrations r WHERE r.tenant_id=owned.tenant_id AND r.id=owned.registration) AS generation"
        } else {
            ""
        };
        let query = format!(
            "SELECT ctid::text AS maintenance_row,*{generation} FROM mdm_apple.{table} owned WHERE tenant_id=$1::uuid AND {column} IS NOT NULL AND substring({column} FROM 1 FOR $2)<>$3 ORDER BY ctid LIMIT 64 FOR UPDATE"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(query))
            .bind(tenant)
            .bind(prefix.len() as i32)
            .bind(&prefix)
            .fetch_all(&mut *c)
            .await
            .map_err(db)?;
        let mut qualifications = Vec::<Uuid>::new();
        for row in rows {
            let sealed: Vec<u8> = row.try_get(column).map_err(db)?;
            let value = protection
                .rewrap_bytes(&sealed, &aad(tenant, table, column, &row)?)
                .map_err(|_| Error::Conflict)?;
            let row_id: String = row.try_get("maintenance_row").map_err(db)?;
            let extra = if table == "profiles" {
                let plain = protection
                    .open_bytes(&sealed, &aad(tenant, table, column, &row)?)
                    .map_err(|_| Error::Conflict)?;
                if row
                    .try_get::<Option<Vec<u8>>, _>("manifest_digest")
                    .map_err(db)?
                    .as_deref()
                    != Some(Sha256::digest(plain.expose()).as_slice())
                {
                    return Err(Error::Conflict);
                }
                ",manifest_cipher_digest=sha256($3)"
            } else {
                ""
            };
            let update = format!(
                "UPDATE mdm_apple.{table} SET {column}=$3{extra} WHERE tenant_id=$1::uuid AND ctid=$2::tid"
            );
            let count = sqlx::query(sqlx::AssertSqlSafe(update))
                .bind(tenant)
                .bind(row_id)
                .bind(value)
                .execute(&mut *c)
                .await
                .map_err(db)?
                .rows_affected();
            if count != 1 {
                return Err(Error::Conflict);
            }
            if table == "attempts"
                && column == "response"
                && let Some(operation) = row.try_get::<Option<Uuid>, _>("operation").map_err(db)?
            {
                qualifications.push(operation);
            }
            changed += count;
        }
        // Qualification UPDATEs may move profile ctids. Finish this selected batch first.
        for id in qualifications {
            crate::profiles::qualify_latest(c, protection, tenant, id).await?;
        }
    }
    Ok(changed)
}
