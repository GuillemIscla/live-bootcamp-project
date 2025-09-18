use crate::utils::auth::Claims;

trait Role {}

pub struct UserOdd{ 
    token: String, 
    claims:Claims
}

impl Role for UserOdd {}

pub struct UserEven{ 
    token: String, 
    claims:Claims
}
impl Role for UserEven {}