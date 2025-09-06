
#[mockall::automock]
#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), TokenStoreError>;

    async fn check_token(&self, token: &str) -> Result<bool, TokenStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TokenStoreError {
    UnexpectedError
}
