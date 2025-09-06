use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::app_state::AppState;
use crate::domain::data_stores::two_fa_code_store::{LoginAttemptId, TwoFACode};
use crate::domain::{AuthAPIError, Email};
use crate::utils::auth::generate_auth_cookie;

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let two_fa_code = TwoFACode::parse(request.two_fa_code).map_err(|_| AuthAPIError::InvalidCredentials)?; 

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let code_tuple = 
        two_fa_code_store.get_code(&email)
            .await
            .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    if code_tuple != (login_attempt_id, two_fa_code) {
        return Err(AuthAPIError::IncorrectCredentials);
    } 

    let auth_cookie = generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    let _ = two_fa_code_store.remove_code(&email).await;

    Ok((updated_jar, StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}