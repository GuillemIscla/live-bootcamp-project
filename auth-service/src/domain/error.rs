use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug,Error)]
pub enum AuthAPIError {
    #[error("Invalid credentials")]
    IncorrectCredentials,
    #[error("Incorrect credentials")]
    InvalidCredentials,
    #[error("Malformed token")]
    MalformedToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Missing token")]
    MissingToken,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}