pub enum AuthAPIError {
    IncorrectCredentials,
    InvalidCredentials,
    InvalidToken,
    MissingToken,
    UserAlreadyExists,
    UserNotFound,
    Unauthorized,
    UnexpectedError,
}