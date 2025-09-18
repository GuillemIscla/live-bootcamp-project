use tonic::transport::Channel;
use crate::auth::auth_grpc_service_client::AuthGrpcServiceClient;
use crate::auth::VerifyTokenRequest;
use crate::auth::verify_token_response::VerifyTokenStatus;


pub enum VerifyToken {
    Valid,
    Invalid,
    UnprocessableContent,
    UnexpectedError,
}

#[derive(Clone)]
pub struct AuthGrpcServiceClientImpl {
    internal_client: AuthGrpcServiceClient<Channel>,
}

impl AuthGrpcServiceClientImpl {

    pub async fn new(address: &str) -> Result<AuthGrpcServiceClientImpl, tonic::transport::Error> {
        let internal_client = AuthGrpcServiceClient::connect(address.to_string()).await?;
        Ok(AuthGrpcServiceClientImpl { internal_client })
    }

    pub async fn verify_token(
        &mut self,
        token:&str
    ) -> VerifyToken {
        let token = token.to_owned();
        let response = self.internal_client.verify_token(VerifyTokenRequest { token }).await;

        match response {
            Ok(verify_token_response) => {
                match VerifyTokenStatus::try_from(verify_token_response.into_inner().token_status) {
                    Ok(VerifyTokenStatus::Valid) => VerifyToken::Valid,
                    Ok(VerifyTokenStatus::Invalid) => VerifyToken::Invalid,
                    Ok(VerifyTokenStatus::UnprocessableContent) => VerifyToken::UnprocessableContent,
                    _ => VerifyToken::UnexpectedError,
                }
            },
            Err(status) => {
                eprintln!("gRPC error: {}", status); // rather log when we have such feature in place
                VerifyToken::UnexpectedError
            },
        }
    }
}