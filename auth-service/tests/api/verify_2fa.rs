use auth_service::{domain::{data_stores::two_fa_code_store::{LoginAttemptId, TwoFACode}, Email}};
use secrecy::{ExposeSecret, Secret};
use wiremock::{matchers::*, Mock, ResponseTemplate};
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let mut app = TestApp::new(None).await;
    
    let random_email = get_random_email().expose_secret().to_owned();

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

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;


    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let email_typed = Email::parse(Secret::new(random_email.clone())).unwrap();

    let (login_attempt_id, two_fa_code_store) = app.two_fa_code_store.read().await.get_code(&email_typed).await.unwrap();

    let test_case = serde_json::json!({
            "email": random_email,
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": two_fa_code_store.as_ref().expose_secret()
        });

    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: {:?}",
        test_case
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email().expose_secret().to_owned();

    let test_cases = [
        serde_json::json!({
            "emmmmail": random_email,
            "loginAttemptId": "c7dde1f6-8891-48bf-9008-3a410fd7d2f4",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": random_email,
            "loginAtttttttemptId": "c7dde1f6-8891-48bf-9008-3a410fd7d2f4",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "c7dde1f6-8891-48bf-9008-3a410fd7d2f4",
            "42FACode": "123456"
        }),
        serde_json::json!({
            "loginAttemptId": "c7dde1f6-8891-48bf-9008-3a410fd7d2f4",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": random_email,
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "c7dde1f6-8891-48bf-9008-3a410fd7d2f4"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
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

    let random_email = get_random_email().expose_secret().to_owned();
    let random_login_attempt_id = LoginAttemptId::default().as_ref().expose_secret().to_owned();
    let random_two_fa_code = TwoFACode::default().as_ref().expose_secret().to_owned();

    let test_cases = [
        serde_json::json!({
            "email": "invalid_email",
            "loginAttemptId": random_login_attempt_id,
            "2FACode": random_two_fa_code
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "not_really_a_uuid",
            "2FACode": random_two_fa_code
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": random_login_attempt_id,
            "2FACode": "non_digit_code"
        }),

    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new(None).await;

    let random_email_in_store = get_random_email().expose_secret().to_owned();
    let random_login_attempt_id_in_store = LoginAttemptId::default().as_ref().expose_secret().to_owned();
    let random_two_fa_code_not_in_store = TwoFACode::default().as_ref().expose_secret().to_owned();


    let signup_body = serde_json::json!({
        "email": random_email_in_store,
        "password": "Password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email_in_store,
        "password": "Password123",
    });

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;


    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let test_cases = [
        serde_json::json!({
            "email": random_email_in_store,
            "loginAttemptId": random_login_attempt_id_in_store,
            "2FACode": random_two_fa_code_not_in_store
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email().expose_secret().to_owned();

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

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;


    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let email_typed = Email::parse(Secret::new(random_email.clone())).unwrap();

    let (login_attempt_id, two_fa_code_store) = app.two_fa_code_store.read().await.get_code(&email_typed).await.unwrap();

    let verify_new_code = serde_json::json!({
            "email": random_email,
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": two_fa_code_store.as_ref().expose_secret()
        });

    let response = app.post_verify_2fa(&verify_new_code).await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: {:?}",
        verify_new_code
    );

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let verify_old_code = verify_new_code;

    let response = app.post_verify_2fa(&verify_old_code).await;
    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        verify_old_code
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let mut app = TestApp::new(None).await;

    let random_email = get_random_email().expose_secret().to_owned();

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

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;


    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let email_typed = Email::parse(Secret::new(random_email.clone())).unwrap();

    let (login_attempt_id, two_fa_code_store) = app.two_fa_code_store.read().await.get_code(&email_typed).await.unwrap();

    let test_case = serde_json::json!({
            "email": random_email,
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": two_fa_code_store.as_ref().expose_secret()
        });

    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: {:?}",
        test_case
    );

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == app.auth_settings.http.jwt_cookie_name)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response_second_time = app.post_verify_2fa(&test_case).await;

    assert_eq!(
        response_second_time.status().as_u16(),
        401,
        "Failed for input: {:?}",
        test_case
    );

    app.clean_up().await;
    
}