use std::sync::Arc;
use color_eyre::eyre::Context;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
    token_ttl_millis: i64,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>, token_ttl_millis: i64) -> Self {
        Self { conn,  token_ttl_millis }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    #[tracing::instrument(name = "AddToken", skip_all)]
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);
        let mut connection: tokio::sync::RwLockWriteGuard<'_, Connection> = self.conn.write().await;
        let ttl_seconds: u64 = 
            (self.token_ttl_millis / 1000)
                .try_into()
                .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64") 
                .map_err(|e| BannedTokenStoreError::UnexpectedError(e))?;

        connection
            .set_ex(key, true, ttl_seconds)
            .wrap_err("failed to set banned token in Redis") 
            .map_err(|e| BannedTokenStoreError::UnexpectedError(e))
    }

    #[tracing::instrument(name = "ContainsToken", skip_all)]
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(&token);
        let mut connection = self.conn.write().await;
        
        connection
            .exists(&key)
                .wrap_err("failed to check if token exists in Redis")
                .map_err(BannedTokenStoreError::UnexpectedError)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
