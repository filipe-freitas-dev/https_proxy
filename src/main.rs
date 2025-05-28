use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use log::error;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

mod proxy_models;
mod service;

use proxy_models::models::*;
use service::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("🚀 Starting Proxy...");

    let config = if let Ok(config_data) = fs::read_to_string("proxy_config.json") {
        match serde_json::from_str(&config_data) {
            Ok(config) => {
                println!("✅ Config loaded from proxy_config.json");
                config
            }
            Err(e) => {
                println!("⚠️  Error to load config: {}. Using default config.", e);
                default_config()
            }
        }
    } else {
        let config = default_config();
        match serde_json::to_string_pretty(&config) {
            Ok(config_json) => {
                if let Err(e) = fs::write("proxy_config.json", config_json) {
                    println!("⚠️  Error to save default config: {}", e);
                } else {
                    println!("📄 proxy_config.json created with default config");
                }
            }
            Err(e) => {
                println!("⚠️  Error to serialize config: {}", e);
            }
        }
        config
    };

    let addr = format!("{}:{}", config.bind_address, config.port);
    let socket_addr: SocketAddr = addr.parse()?;

    let state = Arc::new(ProxyState::new(config));

    println!("📋 Config:");
    println!("   • Address: {}", socket_addr);
    println!(
        "   • Blocked domains: {}",
        state.config.blocked_domains.len()
    );
    println!(
        "   • Blocked keywords: {}",
        state.config.blocked_keywords.len()
    );
    println!(
        "   • Users configured: {}",
        state.config.allowed_users.len()
    );
    println!("   • Log: {}", state.config.log_file);

    let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let state = Arc::clone(&state);
        let client_ip = conn.remote_addr().ip().to_string();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, Arc::clone(&state), client_ip.clone())
            }))
        }
    });

    let server = Server::bind(&socket_addr).serve(make_svc);

    println!("🌐 Proxy HTTP/HTTPS running at http://{}", socket_addr);
    println!("📖 Configure your browser to use this address as proxy HTTP/HTTPS");
    println!("🔐 Users configured: admin/admin123, user1/userpass");
    println!("⚡ Press Ctrl+C to stop");

    if let Err(e) = server.await {
        error!("Error in server: {}", e);
    }

    Ok(())
}
