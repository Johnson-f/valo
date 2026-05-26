use redis::aio::ConnectionManager;
use redis::AsyncTypedCommands;
use uuid::Uuid;

use crate::error::Result;

fn verify_key(token_hash_hex: &str) -> String {
    format!("verify:{token_hash_hex}")
}

/// Store an email-verification token -> user_id mapping with a TTL.
pub async fn store_verify_token(
    conn: &mut ConnectionManager,
    token_hash_hex: &str,
    user_id: Uuid,
    ttl_secs: u64,
) -> Result<()> {
    conn.set_ex(verify_key(token_hash_hex), user_id.to_string(), ttl_secs)
        .await?;
    Ok(())
}

/// Atomically fetch-and-delete a verification token (one-time use via GETDEL).
pub async fn consume_verify_token(
    conn: &mut ConnectionManager,
    token_hash_hex: &str,
) -> Result<Option<Uuid>> {
    let val: Option<String> = redis::cmd("GETDEL")
        .arg(verify_key(token_hash_hex))
        .query_async(conn)
        .await?;
    Ok(val.and_then(|s| Uuid::parse_str(&s).ok()))
}

/// Increment a fixed-window counter for `key` and return the new count. The TTL
/// is set only on the first hit (count == 1), so the window starts then and the
/// key self-expires. Used for per-IP / per-email attempt limiting.
pub async fn incr_rate(conn: &mut ConnectionManager, key: &str, window_secs: u64) -> Result<u64> {
    let count: i64 = redis::cmd("INCR").arg(key).query_async(conn).await?;
    if count == 1 {
        let _: i64 = redis::cmd("EXPIRE")
            .arg(key)
            .arg(window_secs)
            .query_async(conn)
            .await?;
    }
    Ok(count as u64)
}

fn token_version_key(user_id: Uuid) -> String {
    format!("tokenver:{user_id}")
}

/// Read a cached `token_version` for strict-mode revocation, if present.
pub async fn get_token_version(conn: &mut ConnectionManager, user_id: Uuid) -> Result<Option<i32>> {
    let val: Option<String> = redis::cmd("GET")
        .arg(token_version_key(user_id))
        .query_async(conn)
        .await?;
    Ok(val.and_then(|s| s.parse::<i32>().ok()))
}

/// Cache a user's current `token_version` with a TTL (refreshed on cache miss).
pub async fn set_token_version(
    conn: &mut ConnectionManager,
    user_id: Uuid,
    version: i32,
    ttl_secs: u64,
) -> Result<()> {
    conn.set_ex(token_version_key(user_id), version.to_string(), ttl_secs)
        .await?;
    Ok(())
}

fn oauth_state_key(provider: &str, state: &str) -> String {
    format!("oauth:{provider}:{state}")
}

/// Store the PKCE verifier for an in-flight OAuth login, keyed by provider+state,
/// with a short TTL. The state doubles as the CSRF token.
pub async fn store_oauth_state(
    conn: &mut ConnectionManager,
    provider: &str,
    state: &str,
    pkce_verifier: &str,
    ttl_secs: u64,
) -> Result<()> {
    conn.set_ex(oauth_state_key(provider, state), pkce_verifier, ttl_secs)
        .await?;
    Ok(())
}

/// Atomically fetch-and-delete the PKCE verifier for a provider+state (one-time
/// use via GETDEL). `None` means unknown/expired/already-used state.
pub async fn consume_oauth_state(
    conn: &mut ConnectionManager,
    provider: &str,
    state: &str,
) -> Result<Option<String>> {
    let val: Option<String> = redis::cmd("GETDEL")
        .arg(oauth_state_key(provider, state))
        .query_async(conn)
        .await?;
    Ok(val)
}

/// Invalidate the cached `token_version` (called when it is bumped).
pub async fn clear_token_version(conn: &mut ConnectionManager, user_id: Uuid) -> Result<()> {
    let _: i64 = redis::cmd("DEL")
        .arg(token_version_key(user_id))
        .query_async(conn)
        .await?;
    Ok(())
}

fn mfa_challenge_key(token: &str) -> String {
    format!("mfa:{token}")
}

/// Store a post-password MFA challenge token -> user_id with a short TTL.
pub async fn store_mfa_challenge(
    conn: &mut ConnectionManager,
    token: &str,
    user_id: Uuid,
    ttl_secs: u64,
) -> Result<()> {
    conn.set_ex(mfa_challenge_key(token), user_id.to_string(), ttl_secs)
        .await?;
    Ok(())
}

/// Atomically fetch-and-delete an MFA challenge token (one-time use).
pub async fn consume_mfa_challenge(
    conn: &mut ConnectionManager,
    token: &str,
) -> Result<Option<Uuid>> {
    let val: Option<String> = redis::cmd("GETDEL")
        .arg(mfa_challenge_key(token))
        .query_async(conn)
        .await?;
    Ok(val.and_then(|s| Uuid::parse_str(&s).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn conn() -> ConnectionManager {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = redis::Client::open(url).unwrap();
        ConnectionManager::new(client).await.unwrap()
    }

    #[tokio::test]
    async fn token_version_set_get_clear() {
        let mut c = conn().await;
        let uid = Uuid::new_v4();

        assert_eq!(get_token_version(&mut c, uid).await.unwrap(), None);

        set_token_version(&mut c, uid, 5, 60).await.unwrap();
        assert_eq!(get_token_version(&mut c, uid).await.unwrap(), Some(5));

        clear_token_version(&mut c, uid).await.unwrap();
        assert_eq!(get_token_version(&mut c, uid).await.unwrap(), None);
    }

    #[tokio::test]
    async fn oauth_state_store_then_consume_once() {
        let mut c = conn().await;
        let state = format!("st-{}", Uuid::new_v4());
        store_oauth_state(&mut c, "google", &state, "pkce-verifier-abc", 60)
            .await
            .unwrap();

        assert_eq!(
            consume_oauth_state(&mut c, "google", &state).await.unwrap(),
            Some("pkce-verifier-abc".to_string())
        );
        // one-time use
        assert_eq!(consume_oauth_state(&mut c, "google", &state).await.unwrap(), None);
    }

    #[tokio::test]
    async fn store_then_consume_once() {
        let mut c = conn().await;
        let uid = Uuid::new_v4();
        let key = format!("test-{}", Uuid::new_v4()); // unique per run
        store_verify_token(&mut c, &key, uid, 60).await.unwrap();

        assert_eq!(consume_verify_token(&mut c, &key).await.unwrap(), Some(uid));
        // second consume returns None (one-time use)
        assert_eq!(consume_verify_token(&mut c, &key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn mfa_challenge_store_then_consume_once() {
        let mut c = conn().await;
        let token = format!("mc-{}", Uuid::new_v4());
        let uid = Uuid::new_v4();
        store_mfa_challenge(&mut c, &token, uid, 60).await.unwrap();
        assert_eq!(consume_mfa_challenge(&mut c, &token).await.unwrap(), Some(uid));
        assert_eq!(consume_mfa_challenge(&mut c, &token).await.unwrap(), None);
    }
}
