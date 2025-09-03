use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    app_state::AppState, domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}
};

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;

    let token = cookie.value().to_owned();

    validate_token(state.banned_token_store.clone(), &token).await.map_err(|_| AuthAPIError::InvalidToken)?;

    let mut banned_token_store = state.banned_token_store.write().await;
    let _ = banned_token_store.store_token(cookie.clone().value().to_owned()).await;

    Ok((jar.remove(JWT_COOKIE_NAME), StatusCode::OK))
}