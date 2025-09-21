use std::sync::Arc;
use secrecy::{ExposeSecret, Secret};
use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "AddCode", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa_tuple_json = 
            serde_json::to_string(&TwoFATuple::new(login_attempt_id, code))
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        let mut connection = self.conn.write().await;
        let ttl_seconds: u64 = 
            TEN_MINUTES_IN_SECONDS
                .try_into()
                .wrap_err("failed to serialize 2FA tuple")
                .map_err(TwoFACodeStoreError::UnexpectedError)?;
        connection
            .set_ex(key, two_fa_tuple_json, ttl_seconds)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)
    }

    #[tracing::instrument(name = "RemoveCode", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut connection = self.conn.write().await;
        connection
            .del(key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)
    }

    #[tracing::instrument(name = "GetCode", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut connection = self.conn.write().await;
        let stored_value_raw:String = connection.get(key).map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        let two_fa_tuple: TwoFATuple = 
            serde_json::from_str(&stored_value_raw)
                .wrap_err("failed to deserialize 2FA tuple") 
                .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(two_fa_tuple.split())
    }
}


//Class to manipulate the output of the class, contains sensible information, not to log!
#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

impl TwoFATuple {
    pub fn new(login_attempt_id:LoginAttemptId, code: TwoFACode) -> Self  {
        TwoFATuple(login_attempt_id.0.expose_secret().to_owned(), code.0.expose_secret().to_owned())
    }
    pub fn split(&self) -> (LoginAttemptId, TwoFACode) {
        (LoginAttemptId(Secret::new(self.0.to_owned())), TwoFACode(Secret::new(self.1.clone())))
    }
}

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}
