// use axum::{
//     extract::{Request, State}, http::StatusCode, middleware::Next, response::Response
// };
// use axum_extra::{
//     TypedHeader,
//     extract::CookieJar,
//     headers::{Authorization, authorization::Bearer},
// };

// use crate::{app_state::AppState, roles_assignment::roles_service, routes::VerifyTokenSummary, utils::auth};

// pub async fn auth_middleware(
//     State(state): State<AppState>,
//     authorization_header: Option<TypedHeader<Authorization<Bearer>>>,
//     jar: CookieJar,
//     mut req: Request,
//     next: Next,
// ) -> Result<Response, StatusCode>  {
//     // Get auth token from authorization header or cookie
//     let auth_token = authorization_header
//         .map(|header| header.0.token().to_owned())
//         .or_else(|| {
//             jar.get(&state.auth_settings.http.jwt_cookie_name)
//                 .map(|cookie| cookie.value().to_owned())
//         });

//     let auth_token = match auth_token {
//         Some(token) => token,
//         None => return Ok(next.run(req).await),
//     };

//     // Validate auth token
//     let (claims, token) = auth::validate_token(
//         state.banned_token_store.clone(),
//         &auth_token,
//         state.auth_settings.http.jwt_token
//     )
//     .await
//     .map_err( |jwt_error| match VerifyTokenSummary::new(Err(jwt_error)) {
//         VerifyTokenSummary::Valid => StatusCode::OK,
//         VerifyTokenSummary::Invalid => StatusCode::UNAUTHORIZED,
//         VerifyTokenSummary::UnprocessableContent => StatusCode::UNPROCESSABLE_ENTITY,
//         VerifyTokenSummary::UnexpectedError => StatusCode::INTERNAL_SERVER_ERROR,
//     })
//     .map(|claims| (claims, auth_token))?;

//     let role = roles_service::get_role(claims, token).await;
//     // Make role available to handlers
//     req.extensions_mut().insert(role);

//     Ok(next.run(req).await)
// }