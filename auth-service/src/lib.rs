use std::error::Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use tower_http::services::ServeDir;
use tonic::transport::Server;
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, auth::auth_grpc_service_server::AuthGrpcServiceServer}; 
use crate::auth::auth_grpc_service_server::AuthGrpcService;
use crate::presentation::grpc_auth_service_impl::AuthGrpcServiceImpl;

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod presentation;

pub mod auth {
    tonic::include_proto!("auth"); // matches `package auth`
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str, with_grpc:bool) -> Result<Self, Box<dyn Error>> {
        let router_internal = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token_html))
            .with_state(app_state);

        let router = Router::new().nest("/auth", router_internal); // <- prepend /auth here for nginx

        if with_grpc {
            let addr = "[::1]:50051".parse()?;
            let auth_service = AuthGrpcServiceImpl::default();

            println!("[auth-service] Grpc Server listening on {}", addr);

            Server::builder()
                .add_service(AuthGrpcServiceServer::new(auth_service))
                .serve(addr)
                .await?;
        }

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}


impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

