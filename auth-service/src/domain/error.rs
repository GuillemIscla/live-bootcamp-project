pub enum AuthAPIError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    Unauthorized,
    UnexpectedError,
}