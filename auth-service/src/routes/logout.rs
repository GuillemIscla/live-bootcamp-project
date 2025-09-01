use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    app_state::AppState, domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}
};

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        _ => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    if validate_token(state.banned_token_store.clone(), &token).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let mut banned_token_store = state.banned_token_store.write().await;
    let _ = banned_token_store.store_token(cookie.clone().value().to_owned()).await;

    let jar = jar.remove(JWT_COOKIE_NAME);


    (jar, Ok(StatusCode::OK))
}