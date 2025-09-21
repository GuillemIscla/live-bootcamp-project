use sqlx::prelude::FromRow;
use secrecy::Secret;
use sqlx::Row;

use crate::domain::{email::Email, password::Password};

#[derive(PartialEq, Debug, Clone)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> User {
        User {
            email,
            password,
            requires_2fa,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct UserHashed  {
    pub email: Email,
    pub password_hash: Password,
    pub requires_2fa: bool,
}

impl<'r> FromRow<'r, sqlx::postgres::PgRow> for UserHashed {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let email: Email = {
            let raw_email = row.try_get::<String, _>("email")?;
            Email::parse(Secret::new(raw_email.clone())).map_err(|_| sqlx::Error::Decode(format!("Email had the wrong format '{}'", raw_email).into()))?
        };
        let password_hash = {
            let raw_password = Secret::new(row.try_get::<String, _>("password_hash")?);
            Password::parse(raw_password).map_err(|_| sqlx::Error::Decode(format!("Password was not validated").into()))?
        };
        let requires_2fa: bool = row.try_get::<bool, _>("requires_2fa")?;
        Ok(UserHashed {
            email,
            password_hash,
            requires_2fa,
        })
    }
}