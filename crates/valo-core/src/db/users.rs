use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified_at: Option<OffsetDateTime>,
    pub mfa_enabled_at: Option<OffsetDateTime>,
    pub password_hash: Option<String>,
    pub token_version: i32,
    pub status: String,
}

const COLS: &str = "id, email::text AS email, email_verified_at, password_hash, token_version, status, mfa_enabled_at";

/// Insert a user. Maps a unique-violation on email to `Error::EmailTaken`.
pub async fn create_user(pool: &PgPool, email: &str, password_hash: &str) -> Result<User> {
    let row = sqlx::query_as::<_, User>(&format!(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) \
         RETURNING {COLS}"
    ))
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await;

    match row {
        Ok(u) => Ok(u),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Err(Error::EmailTaken),
        Err(e) => Err(Error::Db(e)),
    }
}

/// Create a passwordless user from a verified OAuth identity. `email_verified_at`
/// is set because the provider already verified the address.
pub async fn create_oauth_user(pool: &PgPool, email: &str) -> Result<User> {
    let row = sqlx::query_as::<_, User>(&format!(
        "INSERT INTO users (email, email_verified_at) VALUES ($1, now()) RETURNING {COLS}"
    ))
    .bind(email)
    .fetch_one(pool)
    .await;
    match row {
        Ok(u) => Ok(u),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Err(Error::EmailTaken),
        Err(e) => Err(Error::Db(e)),
    }
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>> {
    let u = sqlx::query_as::<_, User>(&format!(
        "SELECT {COLS} FROM users WHERE email = $1::citext"
    ))
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(u)
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>> {
    let u = sqlx::query_as::<_, User>(&format!(
        "SELECT {COLS} FROM users WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(u)
}

pub async fn mark_verified(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn bump_token_version(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET token_version = token_version + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn create_find_and_verify(pool: PgPool) {
        let u = create_user(&pool, "a@b.com", "hash").await.unwrap();
        assert_eq!(u.email, "a@b.com");
        assert!(u.email_verified_at.is_none());

        let found = find_by_email(&pool, "A@B.COM").await.unwrap().unwrap();
        assert_eq!(found.id, u.id);

        mark_verified(&pool, u.id).await.unwrap();
        let after = find_by_id(&pool, u.id).await.unwrap().unwrap();
        assert!(after.email_verified_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn duplicate_email_is_email_taken(pool: PgPool) {
        create_user(&pool, "dup@b.com", "h").await.unwrap();
        let err = create_user(&pool, "dup@b.com", "h").await.unwrap_err();
        assert!(matches!(err, Error::EmailTaken));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn bump_version_increments(pool: PgPool) {
        let u = create_user(&pool, "v@b.com", "h").await.unwrap();
        bump_token_version(&pool, u.id).await.unwrap();
        let after = find_by_id(&pool, u.id).await.unwrap().unwrap();
        assert_eq!(after.token_version, 1);
    }
}
