use color_eyre::eyre::{eyre, Context, Report, Result};
use thiserror::Error;
use rand::Rng;
use uuid::Uuid;

use crate::domain::email::Email;

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(pub String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        let _ = Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(LoginAttemptId(id))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(pub String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        let _ = code.parse::<u32>().wrap_err("Invalid 2FA code")?;
        if code.len() != 6 {
            Err(eyre!("Code '{}' is of lenght '{}', it needs to be of lenght 6", code, code.len()))
        }
        else if !code.chars().all(|c| c.is_ascii_digit()) {
            Err(eyre!("Code '{}' has non-digit characters", code))
        }
        else {
            Ok(TwoFACode(code))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        TwoFACode(rand::thread_rng().gen_range(100000..=999999).to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
