use crate::utils::auth::Claims;

#[derive(Debug, Clone)]
pub enum UserRole {
    Odd(UserOdd),
    Even(UserEven),
}

#[derive(Debug, Clone)]
pub struct UserOdd{ 
    pub claims:Claims,
    pub token: String
}

#[derive(Debug, Clone)]
pub struct UserEven{ 
    pub claims:Claims,
    pub token: String
}