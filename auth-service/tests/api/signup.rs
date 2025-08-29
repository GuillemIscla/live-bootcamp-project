use std::sync::Arc;

use auth_service::{domain::{data_stores::user_store::{UserStoreError}, email::Email, User}, routes::SignupResponse, ErrorResponse};
use auth_service::domain::data_stores::user_store::MockUserStore;
use tokio::sync::RwLock;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new(None).await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "Password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "Password123",
            "requires2FA": "yes"
        }),
        serde_json::json!({
            "email": random_email,
            "password": "Password123",
            "requiresMinus2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new(None).await;

    let random_email = get_random_email();

    let test_case = serde_json::json!({
        "email": random_email,
        "password": "Password123",
        "requires2FA": true
    });

    let response = app.post_signup(&test_case).await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

//...

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new(None).await;

    let bad_email_1 = "";
    let bad_email_2 = "user_name_a_domain";
    let short_password = "short!";
    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "email": bad_email_1,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": bad_email_2,
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
        let response = app.post_signup(test_case).await;
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
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code    
    let app = TestApp::new(None).await;

    let random_email = get_random_email();

    let sign_up_request = serde_json::json!({
            "email": random_email,
            "password": "Password123",
            "requires2FA": true
        });

    //Login once
    let _ = app.post_signup(&sign_up_request).await;

    //Login twice
    let response = app.post_signup(&sign_up_request).await;

    assert_eq!(
        response.status().as_u16(),
        409,
        "Failed for input: {:?}",
        sign_up_request
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}


#[tokio::test]
async fn should_return_500_if_store_has_unexpected_error() {
    let email_no_connections_raw = "dont_have_connections@domain.com";
    let email_no_connections = Email::parse(email_no_connections_raw).unwrap();
    let email_query_error_raw = "query_error@domain.com";
    let email_query_error = Email::parse(email_query_error_raw).unwrap();
    let password = "Password123";
    let requires_2fa = true;

    let sign_up_request_no_connections = serde_json::json!({
        "email": email_no_connections_raw,
        "password": password,
        "requires2FA": requires_2fa
    });

    let sign_up_request_query_error = serde_json::json!({
        "email": email_query_error_raw,
        "password": password,
        "requires2FA": requires_2fa
    });


    let mut mock_user_store = MockUserStore::new();


    mock_user_store
        .expect_get_user()
        .returning(|_| Err(UserStoreError::UserNotFound));

    mock_user_store
        .expect_add_user()
        .withf(move |u: &User| u.email == email_no_connections)
        .once()
        .returning(|_| Err(UserStoreError::NoConnections));

    mock_user_store
        .expect_add_user()
        .withf(move |u: &User| u.email == email_query_error)
        .once()
        .returning(|_| Err(UserStoreError::QueryError));


    let app = TestApp::new(Some(Arc::new(RwLock::new(mock_user_store)))).await;

    let response_no_connections = app.post_signup(&sign_up_request_no_connections).await;

    assert_eq!(
        response_no_connections.status().as_u16(),
        500,
        "Failed for input: {:?}",
        sign_up_request_no_connections
    );

    assert_eq!(
        response_no_connections
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Unexpected error".to_owned()
    );

    let response_query_error = app.post_signup(&sign_up_request_query_error).await;

    assert_eq!(
        response_query_error.status().as_u16(),
        500,
        "Failed for input: {:?}",
        sign_up_request_query_error
    );

    assert_eq!(
        response_query_error
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Unexpected error".to_owned()
    );
}