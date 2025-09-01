use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    app_state::{AppState, BannedTokenStoreType}, 
    auth::verify_token_response::VerifyTokenStatus, 
    utils::auth::validate_token
};

#[allow(dead_code)]
enum VerifyTokenInternal {
    Valid,
    Invalid,
    UnprocessableContent,
    UnexpectedError,
}

pub async fn verify_token_html(State(state): State<AppState>, Json(request): Json<VerifyTokenRequest>) -> impl IntoResponse {
    match verify_token_internal(state.banned_token_store, request.token).await {
        VerifyTokenInternal::Valid => StatusCode::OK.into_response(),
        VerifyTokenInternal::Invalid => StatusCode::UNAUTHORIZED.into_response(),
        VerifyTokenInternal::UnprocessableContent => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        VerifyTokenInternal::UnexpectedError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn verify_token_grpc(banned_token_store: BannedTokenStoreType, token:String) -> VerifyTokenStatus {
    match verify_token_internal(banned_token_store, token).await {
        VerifyTokenInternal::Valid => VerifyTokenStatus::Valid,
        VerifyTokenInternal::Invalid => VerifyTokenStatus::Invalid,
        VerifyTokenInternal::UnprocessableContent => VerifyTokenStatus::UnprocessableContent,
        VerifyTokenInternal::UnexpectedError => VerifyTokenStatus::UnexpectedError,
    }
}

async fn verify_token_internal(banned_token_store: BannedTokenStoreType, token:String) -> VerifyTokenInternal {
    match validate_token(banned_token_store, &token).await {
        Ok(_) => VerifyTokenInternal::Valid,
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                VerifyTokenInternal::Invalid
            }
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                VerifyTokenInternal::Invalid
            }
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                VerifyTokenInternal::Invalid
            }
            // other cases that mean “bad input”
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
            | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
            | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
            | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_) => {
                VerifyTokenInternal::UnprocessableContent
            }
            // catch-all for unexpected errors
            _ => VerifyTokenInternal::UnexpectedError,
        },
    }
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}