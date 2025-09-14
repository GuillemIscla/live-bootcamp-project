use crate::helpers::{get_random_email, TestApp};
use auth_service::{domain::email::Email, utils::auth::{generate_auth_cookie, generate_auth_cookie_empty}};
use reqwest::{cookie::CookieStore, Url};

#[tokio::test]
async fn should_return_204_if_the_token_is_valid_and_get_a_new_token() {
    let mut app = TestApp::new(None).await;

    let email = Email::parse(get_random_email()).unwrap();

    let cookie = generate_auth_cookie(&email).unwrap();

    app.cookie_jar.add_cookie_str(
        &format!("{}", cookie),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    //If hitting refresh creating the cookie right away will get exactly the same cookie and 
    //cannot compare if the cookie was refreshed
    std::thread::sleep(std::time::Duration::from_millis(1000));

    let response = app.post_refresh_token().await;
    let new_cookie = 
        app.cookie_jar.cookies(&Url::parse("http://127.0.0.1").expect("Failed to parse URL")).unwrap();

    assert_eq!(response.status().as_u16(), 204);

    let cookie_as_raw_header = format!("\"jwt={}\"", cookie.value());
    let new_cookie_as_raw_header = format!("{:?}", new_cookie);

    assert_ne!(cookie_as_raw_header, new_cookie_as_raw_header);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_the_token_is_malformed() {
    let mut app = TestApp::new(None).await;

    app.cookie_jar.add_cookie_str(
        "jwt=invalid",
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_refresh_token().await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_the_token_is_expired() {
    let mut app = TestApp::new(None).await;

    let cookie = generate_auth_cookie_empty();

    app.cookie_jar.add_cookie_str(
        cookie.value(),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_refresh_token().await;

    assert_eq!(response.status().as_u16(), 400);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_the_token_is_banned() {
    let mut app = TestApp::new(None).await;
    let email = Email::parse(get_random_email()).unwrap();
    let cookie = generate_auth_cookie(&email).unwrap();
    app.cookie_jar.add_cookie_str(
        &format!("{}", cookie),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );
    
    // This is an inner scope to drop banned_token_store write reference once the add_token operation is finished
    {
        let mut banned_token_store = app.banned_token_store.write().await;
        let _ = banned_token_store.add_token(cookie.value().to_owned()).await;
    } // dropping write lock here
    
    let response = app.post_refresh_token().await;

    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}