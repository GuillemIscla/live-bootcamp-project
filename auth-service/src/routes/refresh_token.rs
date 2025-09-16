use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use crate::{
    app_state::AppState, domain::{email::Email, AuthAPIError}, routes::VerifyTokenSummary, utils::{auth::{generate_auth_cookie, validate_token, Claims}, constants::{JWT_COOKIE_NAME, JWT_SECRET}}
};

pub async fn refresh_token(State(state): State<AppState>, jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthAPIError>  {
    let old_cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;

    let _ = match VerifyTokenSummary::new(validate_token(state.banned_token_store, old_cookie.value()).await) {
        VerifyTokenSummary::Valid => Ok(()),
        VerifyTokenSummary::Invalid => Err(AuthAPIError::InvalidToken),
        VerifyTokenSummary::UnprocessableContent => Err(AuthAPIError::MalformedToken),
        VerifyTokenSummary::UnexpectedError => Err(AuthAPIError::UnexpectedError),
    }?;

    let email_raw =             
            decode::<Claims>(
                &old_cookie.value().to_string(),
                &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
                &Validation::new(Algorithm::HS256))
            .map_err(|_| AuthAPIError::UnexpectedError)?
            .claims
            .sub;
    let email = Email::parse(email_raw).map_err(|_| AuthAPIError::InvalidToken)?;

    let new_cookie = 
        generate_auth_cookie(&email)
            .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    println!("new cookie value {}", new_cookie.value());

    let jar = jar.add(new_cookie);
    let response = (StatusCode::NO_CONTENT, "");

    Ok((jar, response))
}