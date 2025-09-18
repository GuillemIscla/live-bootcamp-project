use crate::utils::auth::Claims;

pub enum Roles {
    User_Odd{ token: String, claims:Claims},
    User_Even{ token: String, claims:Claims},
}