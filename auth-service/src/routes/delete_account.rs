use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{
    app_state::AppState,
    domain::{email::Email, AuthAPIError},
};

pub async fn delete_account(State(state): State<AppState>, headers: HeaderMap, Json(request): Json<DeleteAccountRequest>) -> Result<impl IntoResponse, AuthAPIError> {
    if let Some(auth) = headers.get("authorization") {
        let _auth_str = auth.to_str().unwrap_or("");
        // // to implement when he have login
        // // we could also use a service that determines if a user can use a route, 
        // // like AuthService (not to be confused with the auth-app)
        // if(isAdmin(auth_str)){
        //  return Err(AuthAPIError::Unauthorized)
        //}
    };

    let email = match Email::parse(request.email) {
        Ok(email) => email,
        _ => return Err(AuthAPIError::InvalidCredentials),
    };

    let mut user_store = state.user_store.write().await;

    if user_store.delete_user(&email).await.is_err() {
        return Err(AuthAPIError::UserNotFound);
    }

    let response = Json(DeleteAccountResponse {
        message: "User deleted successfully!".to_string(),
    });

    Ok((StatusCode::OK, response))
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub email: String,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct DeleteAccountResponse {
    pub message: String,
}