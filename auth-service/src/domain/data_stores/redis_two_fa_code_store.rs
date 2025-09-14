use std::sync::Arc;

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
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa_tuple_json = 
            serde_json::to_string(&TwoFATuple::new(login_attempt_id, code))
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let mut connection = self.conn.write().await;
        let ttl_seconds: u64 = TEN_MINUTES_IN_SECONDS.try_into().map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        connection.set_ex(key, two_fa_tuple_json, ttl_seconds).map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut connection = self.conn.write().await;
        connection.del(key).map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(&email);
        let mut connection = self.conn.write().await;
        let stored_value_raw:String = connection.get(key).map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        let two_fa_tuple: TwoFATuple = serde_json::from_str(&stored_value_raw).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        Ok(two_fa_tuple.split())
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

impl TwoFATuple {
    pub fn new(login_attempt_id:LoginAttemptId, code: TwoFACode) -> Self  {
        TwoFATuple(login_attempt_id.0, code.0)
    }
    pub fn split(&self) -> (LoginAttemptId, TwoFACode) {
        (LoginAttemptId(self.0.clone()), TwoFACode(self.1.clone()))
    }
}

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
