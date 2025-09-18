use std::env;

use askama::Template;
use axum::{
    extract::State, 
    http::StatusCode, 
    response::{Html, IntoResponse}, 
    routing::get, 
    Json, 
    Router
};
use axum_extra::extract::CookieJar;
use serde::Serialize;
use tower_http::services::ServeDir;
use presentation::grpc_auth_service_client_impl::{AuthGrpcServiceClientImpl, VerifyToken};
pub mod auth {
    tonic::include_proto!("auth"); // matches `package auth`
}
use crate::{app_state::AppState, utils::app_settings::AppSettings};

pub mod presentation;
pub mod utils;
pub mod app_state;

#[tokio::main]
async fn main() {

    let app_settings = AppSettings::new();

    let grpc_address = &app_settings.grpc.server_address;
    println!("grpc_address: '{}'", grpc_address);
    let auth_grpc_service_client = 
        AuthGrpcServiceClientImpl::new(grpc_address).await.unwrap();

    let app_state = AppState::new(auth_grpc_service_client);

    let router_internal = Router::new()
        .nest_service("/assets", ServeDir::new("assets"))
        .route("/", get(root))
        .route("/protected", get(protected))
        .with_state(app_state);

    let app = Router::new()
        .nest("/app", router_internal); // <- prepend /app here for nginx

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();

    println!("🌍 HTTP listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    login_link: String,
    logout_link: String,
}

async fn root() -> impl IntoResponse {
    let mut address = env::var("AUTH_SERVICE_IP").unwrap_or("localhost".to_owned());
    if address.is_empty() {
        address = "localhost".to_owned();
    }
    let login_link = format!("http://{}/auth", address);
    let logout_link = format!("http://{}/auth/logout", address);

    let template = IndexTemplate {
        login_link,
        logout_link,
    };
    Html(template.render().unwrap())
}

async fn protected(State(AppState { mut grpc_client}  ): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let jwt_cookie = match jar.get("jwt") {
        Some(cookie) => cookie,
        None => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let response = grpc_client.verify_token(&jwt_cookie.value()).await;
    match response {
        VerifyToken::Invalid | VerifyToken::UnprocessableContent => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        VerifyToken::Valid => Json(ProtectedRouteResponse {
            img_url: "https://cdn.guillemrustbootcamp.xyz/Light-Live-Bootcamp-Certificate.png".to_owned(),
        })
        .into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Serialize)]
pub struct ProtectedRouteResponse {
    pub img_url: String,
}
