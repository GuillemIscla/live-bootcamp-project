use crate::presentation::grpc_auth_service_client_impl::AuthGrpcServiceClientImpl;

#[derive(Clone)]
pub struct AppState {
    pub grpc_client: AuthGrpcServiceClientImpl
}

impl AppState {
    pub fn new(
        grpc_client: AuthGrpcServiceClientImpl) -> Self {
        Self { grpc_client }
    }
}