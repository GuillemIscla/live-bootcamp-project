use auth_service::app_state::AppState;
use auth_service::domain::data_stores::{RedisBannedTokenStore, RedisTwoFACodeStore};
use auth_service::services::data_stores::{
    postgres_user_store::PostgresUserStore,
    mock_email_client::MockEmailClient
};
use auth_service::utils::AuthSettings;
use auth_service::{get_postgres_pool, get_redis_client, Application};
use sqlx::PgPool;
use tokio::sync::RwLock;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let auth_settings = AuthSettings::new();
    let redis_connection = Arc::new(RwLock::new(configure_redis(auth_settings.redis.host_name.clone())));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::clone(&redis_connection), auth_settings.redis.ttl_millis)));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_connection)));
    let email_client = Arc::new(RwLock::new(MockEmailClient {}));
    let pg_pool = configure_postgresql(&auth_settings.database.url).await;
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let http_address = auth_settings.http.address.clone();
    let grpc_address = auth_settings.grpc.address.clone();
    let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client, auth_settings);

    let app = Application::build(app_state, &http_address, &grpc_address)
        .await
        .expect("Failed to build app");

    app.run(None).await.expect("Failed to run app");
}

async fn configure_postgresql(database_url:&str) -> PgPool {
    let pg_pool = get_postgres_pool(database_url)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis(redis_host_name:String) -> redis::Connection {
    get_redis_client(redis_host_name)
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}