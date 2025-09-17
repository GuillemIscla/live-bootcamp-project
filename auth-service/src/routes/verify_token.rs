use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
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
    UnprocessableContent,
    UnexpectedError,
}

impl VerifyTokenSummary {
    pub fn new(validation: Result<Claims, jsonwebtoken::errors::Error>)-> VerifyTokenSummary {
        match validation {
            Ok(_) => VerifyTokenSummary::Valid,
            Err(err) => match err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    VerifyTokenSummary::Invalid
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    VerifyTokenSummary::Invalid
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    VerifyTokenSummary::Invalid
                }
                // other cases that mean “bad input”
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
                | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_) => {
                    VerifyTokenSummary::UnprocessableContent
                }
                // catch-all for unexpected errors
                _ => VerifyTokenSummary::UnexpectedError,
            },
        }
    }
}

pub async fn verify_token_html(State(state): State<AppState>, Json(request): Json<VerifyTokenRequest>) -> impl IntoResponse {
    let jwt_token = state.auth_settings.http.jwt_token;
    match VerifyTokenSummary::new(validate_token(state.banned_token_store, &request.token, jwt_token).await) {
        VerifyTokenSummary::Valid => StatusCode::OK.into_response(),
        VerifyTokenSummary::Invalid => StatusCode::UNAUTHORIZED.into_response(),
        VerifyTokenSummary::UnprocessableContent => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        VerifyTokenSummary::UnexpectedError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn verify_token_grpc(banned_token_store: BannedTokenStoreType, token:String, jwt_token: String) -> VerifyTokenStatus {
    match VerifyTokenSummary::new(validate_token(banned_token_store, &token, jwt_token).await) {
        VerifyTokenSummary::Valid => VerifyTokenStatus::Valid,
        VerifyTokenSummary::Invalid => VerifyTokenStatus::Invalid,
        VerifyTokenSummary::UnexpectedError => VerifyTokenStatus::UnexpectedError,
        VerifyTokenSummary::UnprocessableContent => VerifyTokenStatus::UnprocessableContent, 
    }
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}