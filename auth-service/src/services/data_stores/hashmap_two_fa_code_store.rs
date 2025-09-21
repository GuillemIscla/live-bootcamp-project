use std::collections::HashMap;

use color_eyre::eyre::eyre;

use crate::domain::{
    data_stores::two_fa_code_store::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>{
        let _ = self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email)
            .ok_or(TwoFACodeStoreError::UnexpectedError(eyre!("Could not remove the code from the store")))
            .map(|_| ())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes.get(email)
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
            .map(|reference| reference.clone())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;

    #[tokio::test]
    async fn test_add_code() {
        let mut two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        assert!(two_fa_code_store.add_code(email, login_attempt_id, code).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_existing_code() {
        let mut two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        let _ = two_fa_code_store.add_code(email.clone(), login_attempt_id.clone(), code.clone()).await;
        assert_eq!(two_fa_code_store.get_code(&email).await, Ok((login_attempt_id, code)))
    }


    #[tokio::test]
    async fn test_get_non_existing_code() {
        let two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap();
        assert_eq!(two_fa_code_store.get_code(&email).await, Err(TwoFACodeStoreError::LoginAttemptIdNotFound))
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("guillem@letsgetrusty.com".to_owned())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        let _ = two_fa_code_store.add_code(email.clone(), login_attempt_id, code).await;
        assert!(two_fa_code_store.remove_code(&email).await.is_ok());
        assert_eq!(two_fa_code_store.get_code(&email).await, Err(TwoFACodeStoreError::LoginAttemptIdNotFound))
    }
}