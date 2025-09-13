use auth_service::app_state::AppState;
use auth_service::services::data_stores::{
    hashmap_two_fa_code_store::HashmapTwoFACodeStore,
    hashmap_user_store::HashmapUserStore,
    hashset_banned_token_store::HashsetBannedTokenStore,
    mock_email_client::MockEmailClient
};
use auth_service::utils::constants::{prod, DATABASE_URL};
use auth_service::{get_postgres_pool, Application};
use sqlx::PgPool;
use tokio::sync::RwLock;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient {}));
    let pg_pool = configure_postgresql().await;
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