pub enum AuthAPIError {
    IncorrectCredentials,
    InvalidCredentials,
    MalformedToken,
    InvalidToken,
    MissingToken,
    UserAlreadyExists,
    UserNotFound,
    Unauthorized,
    UnexpectedError,
}