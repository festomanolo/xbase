use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub app_id: String,
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub db_max_connections: u32,
    pub supabase_jwt_secret: String,
    pub supabase_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let app_id = env::var("APP_ID").unwrap_or_else(|_| "xbase-saas".to_string());
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .map_err(|e| format!("Invalid PORT: {e}"))?;

        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "Missing required environment variable: DATABASE_URL".to_string())?;

        let db_max_connections = env::var("DB_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .map_err(|e| format!("Invalid DB_MAX_CONNECTIONS: {e}"))?;

        let supabase_jwt_secret = env::var("SUPABASE_JWT_SECRET").map_err(|_| {
            "Missing required environment variable: SUPABASE_JWT_SECRET".to_string()
        })?;

        let supabase_url =
            env::var("SUPABASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

        Ok(Self {
            app_id,
            host,
            port,
            database_url,
            db_max_connections,
            supabase_jwt_secret,
            supabase_url,
        })
    }
}
