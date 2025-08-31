use auth_service::app_state::UserStoreType;
use auth_service::app_state::AppState;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::utils::constants::test;
use auth_service::Application;
use auth_service::auth::auth_grpc_service_client::AuthGrpcServiceClient;
use reqwest::cookie::Jar;
use tokio::sync::{RwLock, oneshot};
use std::sync::Arc;
use uuid::Uuid;


/*
For me to understand:
- TestApp is a struct that contains all the data to simulate a client, i.e. cookie_jar is an in-memory store
for the client 
- I also included the grpc_client so it can test but in a real environment an http_client is a user with its
brower/mobile phone and the grpc_client is just in the server.
- The method TestApp::new creates the struct but also instantiates a server which we call via http with the
helper methods.
*/
#[allow(dead_code)]
pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>, 
    pub http_client: reqwest::Client,
    pub grpc_address: String,
    pub grpc_client: AuthGrpcServiceClient<tonic::transport::Channel>
}

impl TestApp {
    pub async fn new(mock_user_store:Option<UserStoreType>) -> Self {
        let user_store = mock_user_store.unwrap_or(Arc::new(RwLock::new(HashmapUserStore::default())));
        let app_state = AppState::new(user_store);

        let app: Application = Application::build(app_state,  test::APP_ADDRESS, test::GRPC_ADDRESS)
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


        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();
        let grpc_client = AuthGrpcServiceClient::connect(grpc_address.clone())
            .await
            .expect("Failed to connect to gRPC server");

        TestApp {
            address,
            cookie_jar,
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

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response     
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/auth/login", &self.address))
            .json(body)
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
