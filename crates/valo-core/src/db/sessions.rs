use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Insert a new session row keyed by the SHA-256 of the refresh token.
pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    refresh_hash: &[u8],
    expires_at: OffsetDateTime,
) -> Result<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO sessions (user_id, refresh_token_hash, expires_at) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user_id)
    .bind(refresh_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn find_by_refresh_hash(pool: &PgPool, refresh_hash: &[u8]) -> Result<Option<SessionRow>> {
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT id, user_id, expires_at, revoked_at FROM sessions WHERE refresh_token_hash = $1",
    )
    .bind(refresh_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically revoke-and-claim a live session (not revoked, not expired) by its
/// refresh-token hash, returning the claimed row if this caller won. Postgres
/// serializes concurrent UPDATEs on the same row, so exactly one caller can
/// claim a given token; a `None` result means the token was unknown, already
/// spent, or expired — the caller treats that as the reuse signal. This is the
/// rotation primitive that makes refresh race-free.
pub async fn claim_session(pool: &PgPool, refresh_hash: &[u8]) -> Result<Option<SessionRow>> {
    let row = sqlx::query_as::<_, SessionRow>(
        "UPDATE sessions SET revoked_at = now() \
         WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > now() \
         RETURNING id, user_id, expires_at, revoked_at",
    )
    .bind(refresh_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn revoke_session(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revoke every session for a user (used on reuse-detection and signout-all).
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::create_user;

    fn future() -> OffsetDateTime {
        OffsetDateTime::now_utc() + time::Duration::days(30)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_find_revoke(pool: PgPool) {
        let u = create_user(&pool, "s@b.com", "h").await.unwrap();
        let id = create_session(&pool, u.id, b"hash-a", future()).await.unwrap();

        let found = find_by_refresh_hash(&pool, b"hash-a").await.unwrap().unwrap();
        assert_eq!(found.id, id);
        assert!(found.revoked_at.is_none());

        // After revocation the row remains findable by hash (a tombstone) but is
        // marked revoked — this is what lets refresh detect token reuse.
        revoke_session(&pool, id).await.unwrap();
        let after = find_by_refresh_hash(&pool, b"hash-a").await.unwrap().unwrap();
        assert_eq!(after.id, id);
        assert!(after.revoked_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn revoke_all_marks_every_session(pool: PgPool) {
        let u = create_user(&pool, "ra@b.com", "h").await.unwrap();
        let id1 = create_session(&pool, u.id, b"r1", future()).await.unwrap();
        create_session(&pool, u.id, b"r2", future()).await.unwrap();

        revoke_all_for_user(&pool, u.id).await.unwrap();
        let s1 = find_by_refresh_hash(&pool, b"r1").await.unwrap().unwrap();
        assert_eq!(s1.id, id1);
        assert!(s1.revoked_at.is_some());
    }
}
