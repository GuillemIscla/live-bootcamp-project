use std::collections::HashSet;

use crate::domain::data_stores::banned_token_store::{BannedTokenStore, TokenStoreError};

#[derive(Debug, Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore{
    async fn store_token(&mut self, token: String) -> Result<(), TokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn token_exists(&self, token: &str) -> Result<bool, TokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use crate::services::hashset_banned_token_store::HashsetBannedTokenStore;

    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut hashset_banned_user_store = HashsetBannedTokenStore::default();
        let token = "token_to_add".to_owned();
        assert!(hashset_banned_user_store.store_token(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_existing_token() {
        let mut hashset_banned_user_store = HashsetBannedTokenStore::default();
        let token = "token_to_add".to_owned();
        let _ =hashset_banned_user_store.store_token(token.clone()).await;

        assert!(hashset_banned_user_store.token_exists(&token).await == Ok(true))
    }

    #[tokio::test]
    async fn test_get_non_existing_token() {
        let hashset_banned_user_store = HashsetBannedTokenStore::default();
        let token = "not_added_token".to_owned();

        assert!(hashset_banned_user_store.token_exists(&token).await == Ok(false))
    }
}