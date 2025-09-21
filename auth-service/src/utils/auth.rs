use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use crate::{app_state::BannedTokenStoreType, domain::email::Email};
use color_eyre::eyre::{eyre, Context, Result};

#[tracing::instrument(name = "GenerateAuthCookie", skip_all)]
pub fn generate_auth_cookie(email: &Email, jwt_secret:Secret<String>, jwt_cookie_name:String, token_ttl_millis:i64) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email, jwt_secret, token_ttl_millis)?;
    Ok(create_auth_cookie(token, false, jwt_cookie_name))
}

#[tracing::instrument(name = "GenerateAuthCookieWithoutDomain", skip_all)]
pub fn generate_auth_cookie_without_domain(email: &Email, jwt_secret:Secret<String>, jwt_cookie_name:String, token_ttl_millis:i64) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email, jwt_secret, token_ttl_millis)?;
    Ok(create_auth_cookie(token, true, jwt_cookie_name))
}

#[tracing::instrument(name = "GenerateAuthCookieEmpty", skip_all)]
pub fn generate_auth_cookie_empty(jwt_cookie_name:String) -> Cookie<'static> {
    create_auth_cookie("".to_owned(), true, jwt_cookie_name)
}

#[tracing::instrument(name = "CreateAuthCookie", skip_all)]
fn create_auth_cookie(token: String, without_domain:bool, jwt_cookie_name:String) -> Cookie<'static> {

    let cookie_build = Cookie::build((jwt_cookie_name, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .secure(true)
        .same_site(SameSite::Lax); // send cookie with "same-site" requests, and with "cross-site" top-level navigations.

    if without_domain {
        cookie_build.build()
    }
    else {
        cookie_build.domain(".guillemrustbootcamp.xyz").build()
    }
}


#[tracing::instrument(name = "GenerateAuthToken", skip_all)]
fn generate_auth_token(email: &Email, jwt_secret: Secret<String>, token_ttl_millis:i64) -> Result<String> {
    let delta = 
        chrono::Duration::try_milliseconds(token_ttl_millis)
            .ok_or(eyre!("failed to create 10 minute time delta"))?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .wrap_err(format!(
            "failed to cast exp time to usize. exp time: {}",
            exp
        ))?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims, jwt_secret)
}

#[tracing::instrument(name = "ValidateToken", skip_all)]
pub async fn validate_token(banned_token_store: BannedTokenStoreType, token: &Secret<String>, jwt_secret:Secret<String>) -> Result<Claims> {
    let _ = match banned_token_store.read().await.contains_token(token).await {
        Ok(false) => (),
        Ok(true) => return Err(eyre!("token is banned")),
        Err(e) => return Err(e.into()),
    };
    decode::<Claims>(
        token.expose_secret(),
        &DecodingKey::from_secret(jwt_secret.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}

#[tracing::instrument(name = "CreateToken", skip_all)]
fn create_token(claims: &Claims, jwt_secret: Secret<String>) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secrecy::Secret;
    use tokio::sync::RwLock;

    use crate::{domain::data_stores::banned_token_store::BannedTokenStore, services::data_stores::hashset_banned_token_store::HashsetBannedTokenStore};

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let jwt_token = Secret::new("secret".to_owned());
        let jwt_cookie_name = "jwt".to_owned();
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let token_ttl_millis:i64 = 100;
        let cookie = generate_auth_cookie(&email, jwt_token, jwt_cookie_name.clone(), token_ttl_millis).unwrap();
        assert_eq!(cookie.name(), &jwt_cookie_name);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let jwt_cookie_name = "jwt".to_owned();
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone(), true, jwt_cookie_name.clone());
        assert_eq!(cookie.name(), jwt_cookie_name);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let jwt_token = Secret::new("secret".to_owned());
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let token_ttl_millis:i64 = 100;
        let result = generate_auth_token(&email, jwt_token, token_ttl_millis).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let jwt_token = Secret::new("secret".to_owned());
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let token_ttl_millis:i64 = 600 * 1000;
        let token = generate_auth_token(&email, jwt_token.clone(), token_ttl_millis).unwrap();
        let result = validate_token(banned_token_store, &Secret::new(token), jwt_token).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_milliseconds(token_ttl_millis - 60 * 1000).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let jwt_token = Secret::new("secret".to_owned());
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let token = Secret::new("invalid_token".to_owned());
        let result = validate_token(banned_token_store, &token, jwt_token).await;
        assert!(result.is_err());
    }

        #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let jwt_token = Secret::new("secret".to_owned());
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let token = Secret::new("banned_token".to_owned());
        let _ = banned_token_store.write().await.add_token(token.clone());
        let result = validate_token(banned_token_store, &token, jwt_token).await;
        assert!(result.is_err());
    }
}
