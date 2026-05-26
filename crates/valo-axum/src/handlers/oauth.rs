use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use valo_core::Valo;

use crate::config::AxumConfig;
use crate::error::ApiError;
use crate::response::issue_session;

/// GET /oauth/{provider} — redirect the browser to the provider's consent page.
pub async fn begin(
    State(valo): State<Valo>,
    Path(provider): Path<String>,
) -> Result<Redirect, ApiError> {
    let url = valo.begin_oauth(&provider).await?;
    Ok(Redirect::to(&url))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// GET /oauth/{provider}/callback?code=&state= — complete the exchange and
/// issue a session (per the configured token-delivery mode).
pub async fn callback(
    State(valo): State<Valo>,
    State(config): State<AxumConfig>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let session = valo.complete_oauth(&provider, &q.code, &q.state).await?;
    Ok(issue_session(&config, session).into_response())
}
