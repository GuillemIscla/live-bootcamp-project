use serde::Deserialize;
use std::env as std_env;

#[derive(Deserialize, Clone)]
pub struct AuthSettings {
    pub http: HttpSettings,
    pub grpc: GrpcSettings,
    pub database: DatabaseSettings,
    pub redis: RedisSettings,
}

#[derive(Deserialize, Clone)]
pub struct HttpSettings {
    pub address: String,
    pub jwt_token: String,
    pub jwt_cookie_name: String,
}

#[derive(Deserialize, Clone)]
pub struct GrpcSettings {
    pub address: String,
}

#[derive(Deserialize, Clone)]
pub struct DatabaseSettings {
    pub url: String,
}

#[derive(Deserialize, Clone)]
pub struct RedisSettings {
    pub host_name: String,
    pub ttl_millis: i64,
}


impl AuthSettings {
    pub fn new() -> Self {
        dotenvy::dotenv().ok();

        // Detect environment (default: "default")
        let run_env = std_env::var("RUN_ENV").unwrap_or_else(|_| "default".into());

        let jwt = std::env::var(env::JWT_SECRET_ENV_VAR).expect(&format!("{} must be set.", env::JWT_SECRET_ENV_VAR));
        let db_url = std::env::var(env::DATABASE_URL_ENV_VAR).expect(&format!("{} must be set.", env::DATABASE_URL_ENV_VAR));
        let redis_host = std::env::var(env::REDIS_HOST_NAME_ENV_VAR).ok();

        let builder = config::Config::builder()
            // Load base config
            .add_source(config::File::with_name("config/default").required(false))
            // Load environment-specific override
            .add_source(config::File::with_name(&format!("config/{}", run_env)).required(false))
            //load variables from env
            .set_override("http.jwt_token", jwt).unwrap()
            .set_override("database.url", db_url).unwrap()
            .set_override_option("redis.host_name", redis_host).unwrap();

        let cfg = builder.build().unwrap();

        let auth_settings: AuthSettings = cfg.try_deserialize().unwrap();
        auth_settings.validate()
    }

    fn validate(self) -> Self {
        if self.http.jwt_token.trim().is_empty() {
            panic!("JWT_SECRET must be set and not empty.");
        }
        if self.database.url.trim().is_empty() {
            panic!("DATABASE_URL must be set and not empty.");
        }
        // Optional: ensure Redis is always present
        if self.redis.host_name.trim().is_empty() {
            panic!("REDIS_HOST_NAME must not be empty.");
        }
        self
    }
}


mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME"; 
}