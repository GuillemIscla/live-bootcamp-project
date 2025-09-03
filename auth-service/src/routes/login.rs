use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app_state::AppState, 
    domain::{email::Email, password::Password, AuthAPIError},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>, 
    jar: CookieJar,
    Json(request): Json<LoginRequest>
) ->  Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let password = Password::parse(&request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let user_store = &state.user_store.read().await;

    user_store.validate_user(&email, &password).await.map_err(|_| AuthAPIError::IncorrectCredentials)?;

    user_store.get_user(&email).await.map_err(|_| AuthAPIError::IncorrectCredentials)?;
    
    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}


#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}