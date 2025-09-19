use crate::{
    roles_assignment::{
        UserEven, 
        UserOdd,
        user_role::UserRole
    }, 
    utils::auth::Claims
};


//Dummy logic to recreate roles. 
//In practice we would retrieve the role from a repository.
pub async fn get_role(claims: Claims, token: String) -> UserRole {
    if claims.sub.len() % 2 == 0 {
        UserRole::Even(UserEven { claims, token})
    }
    else {
        UserRole::Odd(UserOdd { claims, token})
    }
}