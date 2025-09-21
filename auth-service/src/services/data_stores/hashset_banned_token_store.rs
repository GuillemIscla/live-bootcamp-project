use std::collections::HashSet;

use secrecy::{ExposeSecret, Secret};

use crate::domain::data_stores::banned_token_store::{BannedTokenStore, BannedTokenStoreError};

#[derive(Debug, Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore{
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().clone());
        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use crate::services::data_stores::hashset_banned_token_store::HashsetBannedTokenStore;

    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut hashset_banned_user_store = HashsetBannedTokenStore::default();
        let token = Secret::new("token_to_add".to_owned());
        assert!(hashset_banned_user_store.add_token(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_existing_token() {
        let mut hashset_banned_user_store = HashsetBannedTokenStore::default();
        let token = Secret::new("token_to_add".to_owned());
        let _ =hashset_banned_user_store.add_token(token.clone()).await;

        assert!(hashset_banned_user_store.contains_token(&token).await == Ok(true))
    }

    #[tokio::test]
    async fn test_get_non_existing_token() {
        let hashset_banned_user_store = HashsetBannedTokenStore::default();
        let token = Secret::new("not_added_token".to_owned());

        assert!(hashset_banned_user_store.contains_token(&token).await == Ok(false))
    }
}