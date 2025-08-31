pub enum AuthAPIError {
    UserAlreadyExists,
    UserNotFound,
    IncorrectCredentials,
    InvalidCredentials,
    Unauthorized,
    UnexpectedError,
}