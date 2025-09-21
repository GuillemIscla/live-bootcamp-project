use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use color_eyre::eyre::Result;
use secrecy::Secret;
use serde::Deserialize;

use crate::{
    app_state::{AppState, BannedTokenStoreType}, 
    auth::verify_token_response::VerifyTokenStatus, 
    utils::auth::{validate_token, Claims}
};

#[allow(dead_code)]
pub enum VerifyTokenSummary {
    Valid,
    Invalid,
}

impl std::fmt::Display for VerifyTokenSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyTokenSummary::Valid => write!(f, "Valid"),
            VerifyTokenSummary::Invalid => write!(f, "Invalid"),
        }
    }
}

impl VerifyTokenSummary {
    pub fn new(validation: Result<Claims>)-> VerifyTokenSummary {
        match validation {
            Ok(_) => VerifyTokenSummary::Valid,
            Err(_) => VerifyTokenSummary::Invalid,
        }
    }
}
#[tracing::instrument(name = "VerifyTokenHtml", skip_all)]
pub async fn verify_token_html(State(state): State<AppState>, Json(request): Json<VerifyTokenRequest>) -> impl IntoResponse {
    let jwt_token = state.auth_settings.http.jwt_token;
    match VerifyTokenSummary::new(validate_token(state.banned_token_store, &request.token, jwt_token).await) {
        VerifyTokenSummary::Valid => StatusCode::OK.into_response(),
        VerifyTokenSummary::Invalid => StatusCode::UNAUTHORIZED.into_response(),
    }
}

#[tracing::instrument(name = "VerifyTokenGrpc", skip_all)]
pub async fn verify_token_grpc(banned_token_store: BannedTokenStoreType, token:Secret<String>, jwt_token: Secret<String>) -> VerifyTokenStatus {
    match VerifyTokenSummary::new(validate_token(banned_token_store, &token, jwt_token).await) {
        VerifyTokenSummary::Valid => VerifyTokenStatus::Valid,
        VerifyTokenSummary::Invalid => VerifyTokenStatus::Invalid,
    }
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: Secret<String>,
}