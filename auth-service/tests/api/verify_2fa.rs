use auth_service::{domain::{data_stores::two_fa_code_store::{LoginAttemptId, TwoFACode}, Email}, utils::constants::JWT_COOKIE_NAME};
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new(None).await;

    let random_email = get_random_email();
    let random_login_attempt = LoginAttemptId::default().as_ref().to_owned();
    let random_two_fa_code = TwoFACode::default().as_ref().to_owned();

    let _ = app
                .two_fa_code_store
                .write()
                .await
                .add_code(
                    Email::parse(random_email.clone()).unwrap(), 
                    LoginAttemptId::parse(random_login_attempt.clone()).unwrap(), 
                    TwoFACode::parse(random_two_fa_code.clone()).unwrap()
                ).await;

    let test_case = serde_json::json!({
            "email": random_email,
            "loginAttemptId": random_login_attempt,
            "2FACode": random_two_fa_code
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
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new(None).await;

    let random_email = get_random_email();

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
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new(None).await;

    let random_email = get_random_email();
    let random_login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let random_two_fa_code = TwoFACode::default().as_ref().to_owned();

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
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new(None).await;

    let random_email_not_in_store = get_random_email();
    let random_email_in_store = get_random_email();
    let random_login_attempt_id_in_store = LoginAttemptId::default().as_ref().to_owned();
    let random_two_fa_code_in_store = TwoFACode::default().as_ref().to_owned();
    let random_two_fa_code_not_in_store = TwoFACode::default().as_ref().to_owned();

    let _ = app
                .two_fa_code_store
                .write()
                .await
                .add_code(
                    Email::parse(random_email_in_store.clone()).unwrap(), 
                    LoginAttemptId::parse(random_login_attempt_id_in_store.clone()).unwrap(), 
                    TwoFACode::parse(random_two_fa_code_in_store.clone()).unwrap()
                ).await;

    let test_cases = [
        serde_json::json!({
            "email": random_email_not_in_store,
            "loginAttemptId": random_login_attempt_id_in_store,
            "2FACode": random_two_fa_code_in_store
        }),
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
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new(None).await;

    let random_email_in_store = get_random_email();
    let random_login_attempt_id_in_store = LoginAttemptId::default().as_ref().to_owned();
    let random_two_fa_code_in_store = TwoFACode::default().as_ref().to_owned();
    let random_two_fa_code_not_in_store = TwoFACode::default().as_ref().to_owned();

    let _ = app
                .two_fa_code_store
                .write()
                .await
                .add_code(
                    Email::parse(random_email_in_store.clone()).unwrap(), 
                    LoginAttemptId::parse(random_login_attempt_id_in_store.clone()).unwrap(), 
                    TwoFACode::parse(random_two_fa_code_in_store.clone()).unwrap()
                );

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
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let app = TestApp::new(None).await;

    let random_email = get_random_email();
    let random_login_attempt = LoginAttemptId::default().as_ref().to_owned();
    let random_two_fa_code = TwoFACode::default().as_ref().to_owned();

    let _ = app
                .two_fa_code_store
                .write()
                .await
                .add_code(
                    Email::parse(random_email.clone()).unwrap(), 
                    LoginAttemptId::parse(random_login_attempt.clone()).unwrap(), 
                    TwoFACode::parse(random_two_fa_code.clone()).unwrap()
                ).await;

    let test_case = serde_json::json!({
            "email": random_email,
            "loginAttemptId": random_login_attempt,
            "2FACode": random_two_fa_code
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
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response_second_time = app.post_verify_2fa(&test_case).await;

    assert_eq!(
        response_second_time.status().as_u16(),
        401,
        "Failed for input: {:?}",
        test_case
    );

    
}