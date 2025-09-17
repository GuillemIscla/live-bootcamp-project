use crate::helpers::{get_random_email, TestApp};
use auth_service::{domain::email::Email, routes::TwoFactorAuthResponse, ErrorResponse};

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "Password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "Password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == &app.auth_settings.http.jwt_cookie_name)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email();
    let random_email_typed = Email::parse(random_email.clone()).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "Password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "Password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    assert_eq!(
        response
            .json::<TwoFactorAuthResponse>()
            .await
            .expect("Could not deserialize response body to TwoFactorAuthResponse")
            .message,
        "2FA required".to_owned()
    );

    assert!(app.two_fa_code_store.read().await.get_code(&random_email_typed).await.is_ok());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "Password123"
        }),
        serde_json::json!({
            "email": random_email,
            "password": 123
        }),
        serde_json::json!({
            "email": random_email,
            "word_that_passes": "Password123"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new(None).await;
    let short_password = "short!";
    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": short_password,
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code    
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email();

    let sign_up_request = serde_json::json!({
            "email": random_email,
            "password": "Password123",
            "requires2FA": true
        });

    //Register the user
    let _ = app.post_signup(&sign_up_request).await;

    let login_request = serde_json::json!({
        "email": random_email,
        "password": "NotQuiteThePassword123"
    });


    //Login twice
    let response = app.post_login(&login_request).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        sign_up_request
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    app.clean_up().await;
}

