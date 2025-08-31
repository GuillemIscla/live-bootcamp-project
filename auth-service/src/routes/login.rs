use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{app_state::AppState, domain::{email::Email, password::Password, AuthAPIError}};

pub async fn login(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Result<impl IntoResponse, AuthAPIError>   {
    let email = Email::parse(&request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let password = Password::parse(&request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = &state.user_store.read().await;

    if user_store.validate_user(&email, &password).await.is_err() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        _ => return Err(AuthAPIError::IncorrectCredentials),
    };

    Ok(StatusCode::OK.into_response())
}


#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}