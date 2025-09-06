use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::data_stores::{banned_token_store::BannedTokenStore, two_fa_code_store::TwoFACodeStore, user_store::UserStore};

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<dyn UserStore + Sync + Send >>;
pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Sync + Send >>;
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Sync + Send >>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType, 
}

impl AppState {
    pub fn new(user_store: UserStoreType, banned_token_store: BannedTokenStoreType, two_fa_code_store: TwoFACodeStoreType) -> Self {
        Self { user_store, banned_token_store, two_fa_code_store }
    }
}
