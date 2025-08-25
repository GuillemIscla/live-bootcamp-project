use tonic::{Request as TonicRequest, Response as TonicResponse};
use tonic::Status;
use crate::auth::auth_grpc_service_server::AuthGrpcService;
use crate::auth::{VerifyTokenRequest, VerifyTokenResponse};
use crate::routes::verify_token_grpc;

#[derive(Default)]
pub struct AuthGrpcServiceImpl;

#[tonic::async_trait]
impl AuthGrpcService for AuthGrpcServiceImpl {
    async fn verify_token(
        &self,
        _request: TonicRequest<VerifyTokenRequest>,
    ) -> Result<TonicResponse<VerifyTokenResponse>, Status> {
        // let token = request.into_inner().token; //Will uncomment when we add verification logic

        let token_status = verify_token_grpc().await.into();

        let reply = VerifyTokenResponse { token_status };
        Ok(TonicResponse::new(reply))
    }
}