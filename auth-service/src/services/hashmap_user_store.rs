use std::collections::HashMap;

use crate::domain::{data_stores::user_store::{UserStore, UserStoreError}, email::Email, password::Password, User};

#[derive(Debug, Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(&email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        match self.get_user(email).await {
            Ok(user) if user.password == *password => Ok(()),
            Ok(_) => Err(UserStoreError::InvalidCredentials),
            Err(error) => Err(error), //we return the same UserNotFound error required
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("guillem@letsgetrusty.com").unwrap(),
            Password::parse("RustIsSecure123").unwrap(),
            false,
        );
        let same_user = user.clone();
        assert!(hashmap_user_store.add_user(user).await.is_ok());
        assert_eq!(
            hashmap_user_store.add_user(same_user).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let email = Email::parse("guillem@letsgetrusty.com").unwrap();
        let other_email = Email::parse("other_person@letsgetrusty.com").unwrap();
        let user = User::new(email.clone(), Password::parse("RustIsSecure123").unwrap(), false);

        let _ = hashmap_user_store.add_user(user).await;
        assert!(hashmap_user_store.get_user(&email).await.is_ok());
        assert_eq!(
            hashmap_user_store.get_user(&other_email).await,
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let email = Email::parse("guillem@letsgetrusty.com").unwrap();
        let password = Password::parse("RustIsSecure123").unwrap();
        let other_email = Email::parse("other_person@letsgetrusty.com").unwrap();
        let other_password = Password::parse("OtherPassword456").unwrap();
        let user = User::new(email.clone(), password.clone(), false);

        let _ = hashmap_user_store.add_user(user).await;
        assert!(hashmap_user_store.validate_user(&email, &password).await.is_ok());
        assert_eq!(
            hashmap_user_store.validate_user(&email, &other_password).await,
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            hashmap_user_store.validate_user(&other_email, &other_password).await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
