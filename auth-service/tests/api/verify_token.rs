use crate::helpers::{get_random_email, TestApp};
use auth_service::{auth::{verify_token_response::VerifyTokenStatus, VerifyTokenRequest}, domain::email::Email, utils::auth::generate_auth_cookie};


//grpc counterpart doesn't make sense here since the client does not accept just any request but 
//something that is already of the right type
#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new(None).await;

    let test_cases = [
        serde_json::json!({
            "token": 123
        }),
        serde_json::json!({
            "tokkkkken": "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGRvbWFpbi5jb20iLCJleHAiOjE3NTY2NzUyMjR9.E9uCKIRmzJqTpgvoOLqy2hgdRtihlHv8W3BmK6j82sk",
        })
    ];


    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new(None).await;

    let random_email = Email::parse(get_random_email()).unwrap();

    let token = generate_auth_cookie(&random_email).unwrap();

    let test_case = serde_json::json!({
        "token": token.value(),
    });

    let response = app.post_verify_token(&test_case).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_200_valid_token_in_grpc() {
    let mut app = TestApp::new(None).await;

    let random_email = Email::parse(get_random_email()).unwrap();

    let token = generate_auth_cookie(&random_email).unwrap();

    let test_case = VerifyTokenRequest { token: token.value().to_owned() } ;

    let response = app.grpc_verify_token(test_case).await.into_inner();

    let status = VerifyTokenStatus::try_from(response.token_status);

    assert_eq!(status, Ok(VerifyTokenStatus::Valid));
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new(None).await;
    let test_case = serde_json::json!({
        "token": "invalid",
    });

    let response = app.post_verify_token(&test_case).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_invalid_token_in_grpc() {
    let mut app = TestApp::new(None).await;

    let test_case = VerifyTokenRequest { token: "invalid".to_owned() } ;

    let response = app.grpc_verify_token(test_case).await.into_inner();

    let status = VerifyTokenStatus::try_from(response.token_status);

    assert_eq!(status, Ok(VerifyTokenStatus::Invalid));
}

// #[tokio::test]
// async fn verify_token_returns_ok() {
//     let app = TestApp::new(None).await;

//     let response = app.post_verify_token().await;

//     assert_eq!(response.status().as_u16(), 200);
// }

// #[tokio::test]
// async fn verify_token_grpc_returns_valid() {
//     let mut app = TestApp::new(None).await;

//     // Prepare request
//     let request = tonic::Request::new(VerifyTokenRequest {
//         token: "test-token".to_string(),
//     });

//     // Call the gRPC endpoint
//     let response = app.grpc_client
//         .verify_token(request)
//         .await
//         .expect("gRPC request failed");

//     let resp = response.into_inner();

//     // Assert on the enum value
//     assert_eq!(resp.token_status, auth_service::auth::verify_token_response::VerifyTokenStatus::Valid as i32);
// }