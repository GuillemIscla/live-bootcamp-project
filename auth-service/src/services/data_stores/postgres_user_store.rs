use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use color_eyre::eyre::Result;
use sqlx::PgPool;
use secrecy::{ExposeSecret, Secret}; 
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
            compute_password_hash(user.password.as_ref().to_owned())
            .await
            .map_err(UserStoreError::UnexpectedError)?;
        sqlx::query("INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)")
        .bind(user.email.as_ref().expose_secret())
        .bind(&password_hash.expose_secret())
        .bind(user.requires_2fa)
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?; 

        Ok(())
    }

    #[tracing::instrument(name = "Delete user from PostgreSQL", skip_all)]
    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError>{
        sqlx::query(
            "DELETE FROM users where email = $1"
        )
        .bind(email.as_ref().expose_secret())
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)] 
    async fn get_user(&self, email: &Email) -> Result<UserHashed, UserStoreError> {
        sqlx::query_as::<_, UserHashed>(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1"
        )
        .bind(email.as_ref().expose_secret())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .ok_or(UserStoreError::UserNotFound)
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
    expected_password_hash: &Secret<String>,
    password_candidate: &Secret<String>,
) -> Result<()> {
    let expected_password_hash = expected_password_hash.expose_secret().to_string();
    let password_candidate = password_candidate.expose_secret().to_string();

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
async fn compute_password_hash(password: Secret<String>) -> Result<Secret<String>> {
    let password_hash =  
        tokio::task::spawn_blocking(move || -> Result<String> {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let argon2 = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?, 
            );

            let password_hash = argon2
                .hash_password(password.expose_secret().as_bytes(), &salt)?
                .to_string();

            Ok(password_hash)
        }).await??;

    Ok(Secret::new(password_hash))
}
