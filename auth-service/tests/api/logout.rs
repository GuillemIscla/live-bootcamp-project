use auth_service::{domain::email::Email, utils::{auth::generate_auth_cookie, constants::JWT_COOKIE_NAME}, ErrorResponse};
use crate::helpers::{get_random_email, TestApp};
use reqwest::Url;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new(None).await;

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Failed for input: "
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new(None).await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: "
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new(None).await;

    let email = Email::parse("user@domain.com".to_owned()).unwrap();

    let cookie = generate_auth_cookie(&email).unwrap();

    app.cookie_jar.add_cookie_str(
        &format!("{}", cookie),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: "
    );

    {
        let banned_token_store = app.banned_token_store.read().await;
        assert_eq!(
            banned_token_store.contains_token(cookie.value()).await, 
            Ok(true), 
                "Missing token from the store: {}", cookie.value()
        );
    }
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new(None).await;

    let email = Email::parse(get_random_email()).unwrap();

    let cookie = generate_auth_cookie(&email).unwrap();

    app.cookie_jar.add_cookie_str(
        &format!("{}", cookie),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: "
    );

    //Getting the cookie to set and setting it!
    let cookie_to_set = response.headers().get("set-cookie").unwrap().to_str().unwrap();

    app.cookie_jar.add_cookie_str(
        cookie_to_set,
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Failed for input: "
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );

    app.clean_up().await;
}
