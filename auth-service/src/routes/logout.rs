use axum::{extract::{State, Extension}, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    app_state::AppState, domain::AuthAPIError, roles_assignment::UserRole, utils::{auth::{generate_auth_cookie_empty, validate_token}, HttpSettings}
};

pub async fn logout(
    State(state): State<AppState>, 
    jar: CookieJar,
    Extension(_role): Extension<UserRole>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    
    // match _role {
    //     UserRole::Even(_) => println!("Logout for even User"),
    //     UserRole::Odd(_) => println!("Logout for odd User"),
    // }

    let HttpSettings { address: _, jwt_token, jwt_cookie_name} = state.auth_settings.http;
    let cookie = jar.get(&jwt_cookie_name).ok_or(AuthAPIError::MissingToken)?;

    let token = cookie.value().to_owned();


    validate_token(state.banned_token_store.clone(), &token, jwt_token).await.map_err(|_| AuthAPIError::InvalidToken)?;

    let mut banned_token_store = state.banned_token_store.write().await;
    let _ = banned_token_store.add_token(cookie.clone().value().to_owned()).await;


    //This method generates the cookie with no token but with the flags like HttpOnly, SameSite...
    //I found that, in my browser, I would need those flags in the Set-Cookie headers that removes the cookie
    //however, other browsers from other students did not need the flags. 
    let cookie = generate_auth_cookie_empty(jwt_cookie_name);

    Ok((jar.remove(cookie), StatusCode::OK))
}