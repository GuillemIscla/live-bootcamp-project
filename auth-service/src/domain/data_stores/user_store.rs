use crate::domain::{email::Email, password::Password, User, UserHashed};

#[mockall::automock]
#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;

    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError>;

    async fn get_user(&self, email: &Email) -> Result<UserHashed, UserStoreError>;

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
    QueryError,
    NoConnections,
}
