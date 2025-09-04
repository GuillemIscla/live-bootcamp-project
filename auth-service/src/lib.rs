use std::error::Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, post},
    serve::Serve,
    Json, Router,
};
use anyhow::Result;
use tower_http::services::ServeDir;
use tokio::try_join;
use tokio::sync::oneshot;
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, auth::auth_grpc_service_server::AuthGrpcServiceServer}; 

use crate::presentation::grpc_auth_service_impl::AuthGrpcServiceImpl;

pub mod app_state;
pub mod domain;
pub mod presentation;
pub mod routes;
pub mod services;
pub mod utils;

pub mod auth {
    tonic::include_proto!("auth"); // matches `package auth`
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
    grpc_router: tonic::transport::server::Router,
    pub grpc_address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str, grpc_address:&str) -> Result<Self, Box<dyn Error>> {

        //Grpc router
        let listener = tokio::net::TcpListener::bind(grpc_address).await?;
        let grpc_address = listener.local_addr()?.to_string();
        let auth_service = AuthGrpcServiceImpl::new(app_state.banned_token_store.clone());
        let grpc_router =  tonic::transport::Server::builder()
            .add_service(AuthGrpcServiceServer::new(auth_service));

        /* REPLACED THE CORS FUNCTIONALITY WITH NGINX IN A SIDE QUEST */
        // let allowed_origins = [
        //     "http://localhost/app".parse()?,
        //     // Replace [YOUR_DROPLET_IP] with your Droplet IP address
        //     "http:/[YOUR_DROPLET_IP]/app".parse()?,
        // ];

        // let cors = CorsLayer::new()
        //     // Allow GET and POST requests
        //     .allow_methods([Method::GET, Method::POST])
        //     // Allow cookies to be included in requests
        //     .allow_credentials(true)
        //     .allow_origin(allowed_origins);

        //Http router
        let router_internal = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token_html))
            .route("/delete-account", delete(routes::delete_account))
            .route("/refresh-token", post(routes::refresh_token))
            .with_state(app_state);
            // .layer(cors);

        let router = Router::new().nest("/auth", router_internal); // <- prepend /auth here for nginx

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address, grpc_router, grpc_address })
    }

    pub async fn run(self, tx_ready: Option<oneshot::Sender<()>>) -> Result<()> {
        println!("🚀 gRPC listening on {}", self.grpc_address);
        println!("🌍 HTTP listening on {}", self.address);

        //At this point the port is already bound
        if let Some(tx) = tx_ready {
            let _ = tx.send(());
        }

        let grpc_server_async = 
            async { 
                self
                    .grpc_router
                    .serve(self.grpc_address.parse()?)
                    .await
                    .map_err(|e| anyhow::Error::new(e).context("gRPC server failed"))
            };

        let http_server_async = 
            async { 
                self
                    .server
                    .await
                    .map_err(|e| anyhow::Error::new(e).context("HTTP server failed")) 
            };

        try_join!(grpc_server_async, http_server_async).map(|_| ())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}


impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Incorrect credentials"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::MalformedToken => (StatusCode::UNPROCESSABLE_ENTITY, "Corrupt token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::Unauthorized => (StatusCode::UNAUTHORIZED, "Not authorized to do this operation"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

