use crate::helpers::TestApp;
use auth_service::auth::VerifyTokenRequest;

#[tokio::test]
async fn verify_token_returns_ok() {
    let app = TestApp::new(None).await;

    let response = app.post_verify_token().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token_grpc_returns_valid() {
    let mut app = TestApp::new(None).await;

    // Prepare request
    let request = tonic::Request::new(VerifyTokenRequest {
        token: "test-token".to_string(),
    });

    // Call the gRPC endpoint
    let response = app.grpc_client
        .verify_token(request)
        .await
        .expect("gRPC request failed");

    let resp = response.into_inner();

    // Assert on the enum value
    assert_eq!(resp.token_status, auth_service::auth::verify_token_response::VerifyTokenStatus::Valid as i32);
}