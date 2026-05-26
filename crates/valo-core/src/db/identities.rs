use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;

/// The valo user id linked to a `(provider, provider_user_id)`, if any.
pub async fn find_user_id_by_identity(
    pool: &PgPool,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<Uuid>> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM identities WHERE provider = $1 AND provider_user_id = $2",
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await?;
    Ok(id)
}

/// Link a provider identity to a user. Idempotent on the unique
/// (provider, provider_user_id) pair.
pub async fn link_identity(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_user_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO identities (user_id, provider, provider_user_id) VALUES ($1, $2, $3) \
         ON CONFLICT (provider, provider_user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_user_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::create_oauth_user;

    #[sqlx::test(migrations = "./migrations")]
    async fn link_then_find(pool: PgPool) {
        let u = create_oauth_user(&pool, "oauth@b.com").await.unwrap();
        assert!(find_user_id_by_identity(&pool, "google", "g-123").await.unwrap().is_none());

        link_identity(&pool, u.id, "google", "g-123").await.unwrap();
        assert_eq!(
            find_user_id_by_identity(&pool, "google", "g-123").await.unwrap(),
            Some(u.id)
        );

        // idempotent
        link_identity(&pool, u.id, "google", "g-123").await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_oauth_user_is_verified_and_passwordless(pool: PgPool) {
        let u = create_oauth_user(&pool, "ouser@b.com").await.unwrap();
        assert_eq!(u.email, "ouser@b.com");
        assert!(u.password_hash.is_none());
        assert!(u.email_verified_at.is_some());
    }
}
