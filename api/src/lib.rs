pub mod user;
pub mod telemetry;
pub mod proxy;

use anyhow::Result;
use axum::Router;
use std::env;
use std::sync::OnceLock;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::proxy::{ProxyConfig, ProxyService};

static AMP_API_KEY: OnceLock<String> = OnceLock::new();
static GOOGLE_API_KEY: OnceLock<String> = OnceLock::new();

pub fn get_amp_api_key() -> &'static str {
    AMP_API_KEY.get().expect("AMP_API_KEY not initialized")
}

pub fn get_google_api_key() -> Option<&'static str> {
    GOOGLE_API_KEY.get().map(|s| s.as_str())
}

#[tokio::main]
async fn start() -> Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::registry()
        .with(EnvFilter::new(rust_log))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    // Load required environment variables
    let host = env::var("HOST").expect("HOST is not set in .env file");
    let port = env::var("PORT").expect("PORT is not set in .env file");
    let amp_api_key = env::var("AMP_API_KEY").expect("AMP_API_KEY is not set in .env file");
    AMP_API_KEY.set(amp_api_key).expect("AMP_API_KEY already initialized");
    // Optional Google API key for Google proxy
    if let Ok(google_api_key) = env::var("GOOGLE_API_KEY") {
        let _ = GOOGLE_API_KEY.set(google_api_key);
    }
    let server_url = format!("{host}:{port}");
    
    // Load proxy configuration
    let proxy_config = ProxyConfig::load_from_file("proxy_config.yaml")
        .unwrap_or_else(|e| {
            info!("Using default proxy configuration ({})", e);
            ProxyConfig::default()
        });

    info!("Loaded proxy configuration with {} endpoints", proxy_config.endpoints.len());
    for endpoint in &proxy_config.endpoints {
        info!("  - Path: {}, Response Type: {:?}", endpoint.path, endpoint.response_type);
    }
    
    // Create proxy service
    let proxy_service = ProxyService::new(proxy_config);
    
    // Initialize router
    let app = Router::new()
        .merge(user::router())
        .merge(telemetry::router())
        .merge(proxy_service.create_router())
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    // Start server
    let listener = tokio::net::TcpListener::bind(&server_url).await?;
    info!("Listening on {}", server_url);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Received termination signal shutting down");
}

pub fn main() {
    let result = start();
    if let Err(err) = result {
        error!("Error: {err}");
    }
}
