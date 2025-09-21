use auth_service::app_state::BannedTokenStoreType;
use auth_service::app_state::EmailClientType;
use auth_service::app_state::TwoFACodeStoreType;
use auth_service::app_state::UserStoreType;
use auth_service::app_state::AppState;
use auth_service::auth::VerifyTokenRequest;
use auth_service::auth::VerifyTokenResponse;
use auth_service::services::data_stores::{RedisBannedTokenStore, RedisTwoFACodeStore};
use auth_service::get_postgres_pool;
use auth_service::get_redis_client;
use auth_service::services::data_stores::postgres_user_store::PostgresUserStore;
use auth_service::services::data_stores::mock_email_client::MockEmailClient;
use auth_service::utils::AuthSettings;
use auth_service::Application;
use auth_service::auth::auth_grpc_service_client::AuthGrpcServiceClient;
use reqwest::cookie::Jar;
use secrecy::ExposeSecret;
use secrecy::Secret;
use sqlx::postgres::PgConnectOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::Connection;
use sqlx::Executor;
use sqlx::PgConnection;
use sqlx::PgPool;
use tokio::sync::{RwLock, oneshot};
use std::env;
use std::str::FromStr;
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
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType, 
    pub http_client: reqwest::Client,
    pub db_name: String,
    pub clean_up_called: bool,
    pub grpc_address: String,
    pub grpc_client: AuthGrpcServiceClient<tonic::transport::Channel>,
    pub auth_settings: AuthSettings
}

impl TestApp {
    pub async fn new(mock_user_store:Option<UserStoreType>) -> Self {
        env::set_var("RUN_ENV", "test");
        let auth_settings = AuthSettings::new();

        let (
                user_store, 
                db_name,
                clean_up_called
            ):(UserStoreType, String, bool) = 
            match mock_user_store {
                Some(mock_user_store) => 
                    (
                        mock_user_store, 
                        "mock_database".to_owned(), 
                        true
                    ),
                None => {
                    let (pg_pool, db_name) = Self::configure_postgresql(auth_settings.database.url.clone()).await;
                    (
                        Arc::new(RwLock::new(PostgresUserStore::new(pg_pool))), 
                        db_name, 
                        false
                    )
                },
            };

        let redis_connection = Arc::new(RwLock::new(configure_redis(auth_settings.redis.host_name.clone())));
        let banned_token_store: BannedTokenStoreType = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::clone(&redis_connection), auth_settings.redis.ttl_millis)));
        let two_fa_code_store: TwoFACodeStoreType = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_connection)));
        let email_client: EmailClientType = Arc::new(RwLock::new(MockEmailClient {}));
        let app_state = AppState::new(
            user_store, 
            Arc::clone(&banned_token_store),
            Arc::clone(&two_fa_code_store),
            email_client,
            auth_settings
        );

        let http_address = app_state.auth_settings.http.address.clone();
        let grpc_address = app_state.auth_settings.grpc.address.clone();
        let auth_settings = app_state.auth_settings.clone();

        let app: Application = Application::build(app_state,  &http_address, &grpc_address)
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
            banned_token_store,
            two_fa_code_store,
            http_client,
            db_name,
            clean_up_called,
            grpc_address,
            grpc_client,
            auth_settings,
        }
    }

    async fn configure_postgresql(postgresql_conn_url:Secret<String>) -> (PgPool, String) {
        // We are creating a new database for each test case, and we need to ensure each database has a unique name!
        let db_name = Uuid::new_v4().to_string();

        Self::configure_database(&postgresql_conn_url, &db_name).await;

        let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url.expose_secret(), db_name);

        // Create a new connection pool and return it
        (get_postgres_pool(&Secret::new(postgresql_conn_url_with_db))
            .await
            .expect("Failed to create Postgres connection pool!"), db_name)
    }

    async fn configure_database(db_conn_string: &Secret<String>, db_name: &str) {
        // Create database connection
        let connection = PgPoolOptions::new()
            .connect(db_conn_string.expose_secret())
            .await
            .expect("Failed to create Postgres connection pool.");

        // Create a new database
        connection
            .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
            .await
            .expect("Failed to create database.");


        // Connect to new database
        let db_conn_string = format!("{}/{}", db_conn_string.expose_secret(), db_name);

        let connection = PgPoolOptions::new()
            .connect(&db_conn_string)
            .await
            .expect("Failed to create Postgres connection pool.");

        // Run migrations against new database
        sqlx::migrate!()
            .run(&connection)
            .await
            .expect("Failed to migrate the database");
    }
        
    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/auth", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_refresh_token(&self) -> reqwest::Response  {
        self.http_client
            .post(&format!("{}/auth/refresh-token", &self.address))
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

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/auth/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response 
        where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/auth/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn grpc_verify_token(&mut self, request: impl tonic::IntoRequest<VerifyTokenRequest>) -> tonic::Response<VerifyTokenResponse> {
        self.grpc_client
            .verify_token(request)
            .await
            .expect("Failed to execute request.")
    }

    pub async fn clean_up(&mut self) {
        if !self.clean_up_called{
            delete_database(&self.db_name, self.auth_settings.database.url.clone()).await;
            self.clean_up_called = true
        }
    }
}


impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called {
            panic!("DB with name '{}' has not been cleaned", self.db_name)
        }
    }
}

pub fn get_random_email() -> Secret<String> {
    Secret::new(format!("{}@example.com", Uuid::new_v4()))
}

async fn delete_database(db_name: &str, postgresql_conn_url: Secret<String>) {
    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url.expose_secret())
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                AND pid <> pg_backend_pid();
        "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}

fn configure_redis(redis_host_name:String) -> redis::Connection {
    get_redis_client(redis_host_name)
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}