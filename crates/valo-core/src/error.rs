use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid email or password")]
    InvalidCredentials,
    #[error("email is not verified")]
    EmailNotVerified,
    #[error("email is already registered")]
    EmailTaken,
    #[error("token is invalid or expired")]
    InvalidToken,
    #[error("account is not active")]
    AccountInactive,
    #[error("weak signing secret: HS256 requires at least 32 bytes")]
    WeakSecret,
    #[error("password hashing failed")]
    Hashing,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("mail delivery failed: {0}")]
    Mail(String),
}

pub type Result<T> = std::result::Result<T, Error>;
