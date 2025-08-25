use axum::{http::StatusCode, response::IntoResponse};

use crate::auth::verify_token_response::VerifyTokenStatus;

enum VerifyTokenInternal {
    Valid,
    Invalid,
    UnprocessableContent,
    UnexpectedError,
}

pub async fn verify_token_html() -> impl IntoResponse {
    match verify_token_internal().await {
        VerifyTokenInternal::Valid => StatusCode::OK.into_response(),
        VerifyTokenInternal::Invalid => StatusCode::UNAUTHORIZED.into_response(),
        VerifyTokenInternal::UnprocessableContent => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        VerifyTokenInternal::UnexpectedError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn verify_token_grpc() -> VerifyTokenStatus {
    match verify_token_internal().await {
        VerifyTokenInternal::Valid => VerifyTokenStatus::Valid,
        VerifyTokenInternal::Invalid => VerifyTokenStatus::Invalid,
        VerifyTokenInternal::UnprocessableContent => VerifyTokenStatus::UnprocessableContent,
        VerifyTokenInternal::UnexpectedError => VerifyTokenStatus::UnexpectedError,
    }
}

async fn verify_token_internal() -> VerifyTokenInternal {
    VerifyTokenInternal::Valid
}

