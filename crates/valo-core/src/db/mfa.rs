use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;

/// Store the (encrypted) TOTP secret as a *pending* enrollment — does NOT enable MFA.
pub async fn set_secret(pool: &PgPool, user_id: Uuid, encrypted: &[u8]) -> Result<()> {
    sqlx::query("UPDATE users SET mfa_secret = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(encrypted)
        .execute(pool)
        .await?;
    Ok(())
}

/// Fetch the encrypted TOTP secret, if enrolled or pending.
pub async fn get_secret(pool: &PgPool, user_id: Uuid) -> Result<Option<Vec<u8>>> {
    let secret: Option<Option<Vec<u8>>> =
        sqlx::query_scalar("SELECT mfa_secret FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(secret.flatten())
}

/// Mark MFA enabled (enrollment confirmed).
pub async fn enable(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET mfa_enabled_at = now(), updated_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Disable MFA entirely: clear the secret + flag and delete recovery codes.
pub async fn disable(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET mfa_secret = NULL, mfa_enabled_at = NULL, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Replace a user's recovery codes with the given hashes.
pub async fn replace_recovery_codes(pool: &PgPool, user_id: Uuid, hashes: &[Vec<u8>]) -> Result<()> {
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    for hash in hashes {
        sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(hash)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Atomically consume one unused recovery code by its hash. Returns true if a
/// matching unused code existed (and is now marked used).
pub async fn consume_recovery_code(pool: &PgPool, user_id: Uuid, code_hash: &[u8]) -> Result<bool> {
    let row: Option<Uuid> = sqlx::query_scalar(
        "UPDATE mfa_recovery_codes SET used_at = now() \
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING id",
    )
    .bind(user_id)
    .bind(code_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::create_user;

    #[sqlx::test(migrations = "./migrations")]
    async fn secret_set_get_enable_disable(pool: PgPool) {
        let u = create_user(&pool, "m@b.com", "h").await.unwrap();
        assert!(get_secret(&pool, u.id).await.unwrap().is_none());

        set_secret(&pool, u.id, b"enc").await.unwrap();
        assert_eq!(get_secret(&pool, u.id).await.unwrap().as_deref(), Some(&b"enc"[..]));

        enable(&pool, u.id).await.unwrap();
        disable(&pool, u.id).await.unwrap();
        assert!(get_secret(&pool, u.id).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_codes_are_one_time(pool: PgPool) {
        let u = create_user(&pool, "r@b.com", "h").await.unwrap();
        replace_recovery_codes(&pool, u.id, &[b"hash1".to_vec(), b"hash2".to_vec()]).await.unwrap();

        assert!(consume_recovery_code(&pool, u.id, b"hash1").await.unwrap());
        assert!(!consume_recovery_code(&pool, u.id, b"hash1").await.unwrap());
        assert!(!consume_recovery_code(&pool, u.id, b"nope").await.unwrap());
    }
}
