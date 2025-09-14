use auth_service::app_state::AppState;
use auth_service::domain::data_stores::{RedisBannedTokenStore, RedisTwoFACodeStore};
use auth_service::services::data_stores::{
    postgres_user_store::PostgresUserStore,
    mock_email_client::MockEmailClient
};
use auth_service::utils::constants::{prod, DATABASE_URL, REDIS_HOST_NAME};
use auth_service::{get_postgres_pool, get_redis_client, Application};
use sqlx::PgPool;
use tokio::sync::RwLock;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let redis_connection = Arc::new(RwLock::new(configure_redis()));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::clone(&redis_connection))));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_connection)));
    let email_client = Arc::new(RwLock::new(MockEmailClient {}));
    let pg_pool = configure_postgresql().await;
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let app_state = AppState::new(user_store, banned_token_store, two_fa_code_store, email_client);

    let app = Application::build(app_state, prod::APP_ADDRESS, prod::GRPC_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run(None).await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}