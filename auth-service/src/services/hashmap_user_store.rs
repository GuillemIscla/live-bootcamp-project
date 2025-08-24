use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug, Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.get_user(email) {
            Ok(user) if user.password == password => Ok(()),
            Ok(_) => Err(UserStoreError::InvalidCredentials),
            Err(error) => Err(error), //we return the same UserNotFound error required
        }
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let user = User::new(
            "guillem@letsgetrusty.com".to_string(),
            "RustIsSecure123".to_string(),
            false,
        );
        let same_user = user.clone();
        assert!(hashmap_user_store.add_user(user).is_ok());
        assert_eq!(
            hashmap_user_store.add_user(same_user),
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let email = "guillem@letsgetrusty.com".to_string();
        let other_email = "other_person@letsgetrusty.com".to_string();
        let user = User::new(email.clone(), "RustIsSecure123".to_string(), false);

        let _ = hashmap_user_store.add_user(user);
        assert!(hashmap_user_store.get_user(&email).is_ok());
        assert_eq!(
            hashmap_user_store.get_user(&other_email),
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let email = "guillem@letsgetrusty.com".to_string();
        let password = "RustIsSecure123".to_string();
        let other_email = "other_person@letsgetrusty.com".to_string();
        let other_password = "OtherPassword456".to_string();
        let user = User::new(email.clone(), password.clone(), false);

        let _ = hashmap_user_store.add_user(user);
        assert!(hashmap_user_store.validate_user(&email, &password).is_ok());
        assert_eq!(
            hashmap_user_store.validate_user(&email, &other_password),
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            hashmap_user_store.validate_user(&other_email, &other_password),
            Err(UserStoreError::UserNotFound)
        );
    }
}
