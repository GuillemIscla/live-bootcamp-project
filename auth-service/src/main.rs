use auth_service::app_state::AppState;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::utils::constants::prod;
use auth_service::Application;
use tokio::sync::RwLock;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let app_state = AppState::new(user_store);

    let app = Application::build(app_state, prod::APP_ADDRESS, prod::GRPC_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run(None).await.expect("Failed to run app");
}
