use std::collections::HashMap;

use crate::domain::{data_stores::user_store::{UserStore, UserStoreError}, email::Email, password::Password, User, UserHashed};

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

    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError> {
        if self.users.contains_key(email) {
            self.users.remove(email);
            Ok(())
        } else {
            Err(UserStoreError::UserNotFound)
        }
    }

    //Here we don't hash the password, therefore password is equal to password_hash
    async fn get_user(&self, email: &Email) -> Result<UserHashed, UserStoreError> {
        match self.users.get(email) {
            Some(User { email, password, requires_2fa}) => 
                Ok(
                    UserHashed { 
                        email: email.clone(),
                        password_hash: password.clone(), 
                        requires_2fa: requires_2fa.clone() 
                }),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        match self.get_user(email).await {
            Ok(user) if user.password_hash == *password => Ok(()),
            Ok(_) => Err(UserStoreError::InvalidCredentials),
            Err(error) => Err(error), //we return the same UserNotFound error required
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;  
    use secrecy::Secret;

    #[tokio::test]
    async fn test_add_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap(),
            Password::parse(Secret::new("RustIsSecure123".to_string())).unwrap(),
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
        let email = Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap();
        let other_email = Email::parse(Secret::new("other_person@letsgetrusty.com".to_owned())).unwrap();
        let user = User::new(email.clone(), Password::parse(Secret::new("RustIsSecure123".to_string())).unwrap(), false);

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
        let email = Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap();
        let password = Password::parse(Secret::new("RustIsSecure123".to_string())).unwrap();
        let other_email = Email::parse(Secret::new("other_person@letsgetrusty.com".to_owned())).unwrap();
        let other_password = Password::parse(Secret::new("OtherPassword456".to_string())).unwrap();
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
