use auth_service::app_state::UserStoreType;
use auth_service::app_state::AppState;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::Application;
use auth_service::auth::auth_grpc_service_client::AuthGrpcServiceClient;
use tokio::sync::{RwLock, oneshot};
use std::sync::Arc;
use uuid::Uuid;

#[allow(dead_code)]
pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
    pub grpc_address: String,
    pub grpc_client: AuthGrpcServiceClient<tonic::transport::Channel>
}

impl TestApp {
    pub async fn new(mock_user_store:Option<UserStoreType>) -> Self {
        let user_store = mock_user_store.unwrap_or(Arc::new(RwLock::new(HashmapUserStore::default())));
        let app_state = AppState::new(user_store);

        let app = Application::build(app_state, "127.0.0.1:0", "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address: String = format!("http://{}", app.address.clone());
        let grpc_address = format!("http://{}", app.grpc_address.clone());

        // create a ready channel
        let (tx_ready, rx_ready) = oneshot::channel();

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run(Some(tx_ready)));

        // wait for server ready
        rx_ready.await.unwrap();

        let http_client = reqwest::Client::new();
        let grpc_client = AuthGrpcServiceClient::connect(grpc_address.clone())
            .await
            .expect("Failed to connect to gRPC server");

        TestApp {
            address,
            http_client,
            grpc_address,
            grpc_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/auth", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/auth/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/auth/login", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/auth/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/auth/verify-2fa", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/auth/verify-token", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
