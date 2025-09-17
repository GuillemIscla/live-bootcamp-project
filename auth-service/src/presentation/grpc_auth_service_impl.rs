use tonic::{Request as TonicRequest, Response as TonicResponse};
use tonic::Status;
use crate::app_state::BannedTokenStoreType;
use crate::auth::auth_grpc_service_server::AuthGrpcService;
use crate::auth::{VerifyTokenRequest, VerifyTokenResponse};
use crate::routes::verify_token_grpc;

pub struct AuthGrpcServiceImpl {
    banned_token_store: BannedTokenStoreType,
    jwt_token: String
}

impl AuthGrpcServiceImpl {
    pub fn new(banned_token_store: BannedTokenStoreType, jwt_token: String) -> Self {
        Self { banned_token_store, jwt_token }
    }
}

#[tonic::async_trait]
impl AuthGrpcService for AuthGrpcServiceImpl {
    async fn verify_token(
        &self,
        request: TonicRequest<VerifyTokenRequest>
    ) -> Result<TonicResponse<VerifyTokenResponse>, Status> {
        let token_status = verify_token_grpc(self.banned_token_store.clone(), request.into_inner().token, self.jwt_token.clone()).await.into();

        let reply = VerifyTokenResponse { token_status };
        Ok(TonicResponse::new(reply))
    }
}