use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User, UserHashed
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)] 
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = 
            compute_password_hash(user.password.as_ref())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;
        sqlx::query("INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)")
        .bind(user.email.as_ref())
        .bind(&password_hash)
        .bind(user.requires_2fa)
        .execute(&self.pool)
        .await
        .map_err(|_| UserStoreError::QueryError)?;

        Ok(())
    }

    #[tracing::instrument(name = "Delete user from PostgreSQL", skip_all)]
    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError>{
        sqlx::query(
            "DELETE FROM users where email = $1"
        )
        .bind(email.as_ref())
        .execute(&self.pool)
        .await
        .map_err(|_| UserStoreError::QueryError)?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)] 
    async fn get_user(&self, email: &Email) -> Result<UserHashed, UserStoreError> {
        let user: UserHashed = sqlx::query_as::<_, UserHashed>(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1"
        )
        .bind(email.as_ref())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| UserStoreError::QueryError)?;

        Ok(user)
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)] 
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>{
        match self.get_user(email).await {
            Ok(user) => {
                verify_password_hash(user.password_hash.as_ref(), password.as_ref())
                .await
                .map_err(|_| UserStoreError::InvalidCredentials)
            },
            Err(error) => Err(error), //we return the same UserNotFound error required
        }
    }

}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_password_hash = expected_password_hash.to_string();
    let password_candidate = password_candidate.to_string();

    // Offload CPU-heavy work
    tokio::task::spawn_blocking(move || {
        let expected_hash = PasswordHash::new(&expected_password_hash)?;
        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_hash)
            .map_err(|e| Box::new(e))
    })
    .await??; // First ? unwraps JoinError, second ? unwraps the inner Result

    Ok(())
}

#[tracing::instrument(name = "Computing password hash", skip_all)] 
async fn compute_password_hash(password: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let password = password.to_string();
    let password_hash =  
        tokio::task::spawn_blocking(move || -> Result<String, Box<dyn Error + Send + Sync>> {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let argon2 = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?, 
            );

            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)?
                .to_string();

            Ok(password_hash)
        }).await??;

    Ok(password_hash)
}
