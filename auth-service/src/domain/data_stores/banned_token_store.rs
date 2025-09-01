
#[mockall::automock]
#[async_trait::async_trait]
pub trait BannedTokenStore: Sync + Send {
    async fn store_token(&mut self, token: String) -> Result<(), TokenStoreError>;

    async fn token_exists(&self, token: &str) -> Result<bool, TokenStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TokenStoreError {
    UnexpectedError
}
