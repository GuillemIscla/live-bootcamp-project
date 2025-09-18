use serde::Deserialize;
use std::env as std_env;

#[derive(Deserialize, Clone)]
pub struct AppSettings {
    pub grpc: GrpcSettings,
}

#[derive(Deserialize, Clone)]
pub struct GrpcSettings {
    pub server_address: String,
}

impl AppSettings {
    pub fn new() -> Self {

        // Detect environment (default: "default")
        let run_env = std_env::var("RUN_ENV").unwrap_or_else(|_| "default".into());

        let builder = config::Config::builder()
            // Load base config
            .add_source(config::File::with_name("config/default").required(false))
            // Load environment-specific override
            .add_source(config::File::with_name(&format!("config/{}", run_env)).required(false));

        let cfg = builder.build().unwrap();

        let app_settings: AppSettings = cfg.try_deserialize().unwrap();
        app_settings.validate()
    }

    fn validate(self) -> Self {
        self
    }
}
