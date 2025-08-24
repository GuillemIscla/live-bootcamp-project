use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "yes"
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
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
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_case = serde_json::json!({
        "email": random_email,
        "password": "password123",
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
    let app = TestApp::new().await;

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
    let app = TestApp::new().await;

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

