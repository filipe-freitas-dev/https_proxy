use crate::proxy_models::models::*;
use chrono::Utc;
use hyper::{upgrade::Upgraded, Body, Client, Method, Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use log::{error, info, warn};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub async fn handle_request(
    req: Request<Body>,
    state: Arc<ProxyState>,
    client_ip: String,
) -> Result<Response<Body>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let url = uri.to_string();

    info!("Request: {} {} from {}", method, url, client_ip);

    let user = state.authenticate(&headers);
    if user.is_none() && !state.config.allowed_users.is_empty() {
        let log = RequestLog {
            timestamp: Utc::now(),
            client_ip: client_ip.clone(),
            user: None,
            method: method.to_string(),
            url: url.clone(),
            status: 407,
            blocked: true,
            block_reason: Some(BlockReason::Unauthorized.to_string()),
            response_size: 0,
        };
        state.add_log(log).await;

        return Ok(Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header("Proxy-Authenticate", "Basic realm=\"Corporate Proxy\"")
            .body(Body::from("Authentication required"))
            .unwrap());
    }

    if state.is_domain_blocked(&url) {
        warn!("Domain blocked: {}", url);
        let log = RequestLog {
            timestamp: Utc::now(),
            client_ip: client_ip.clone(),
            user: user.clone(),
            method: method.to_string(),
            url: url.clone(),
            status: 403,
            blocked: true,
            block_reason: Some(BlockReason::BlockedDomain.to_string()),
            response_size: 0,
        };
        state.add_log(log).await;

        return Ok(create_blocked_response(
            "Access denied: Domain blocked by corporate policy",
        ));
    }

    if method == Method::CONNECT {
        return handle_connect(req, state, client_ip, user).await;
    }
    match proxy_request(req, &state.client).await {
        Ok(response) => {
            let status = response.status();

            if status.is_success() {
                let (parts, body) = response.into_parts();
                let body_bytes = hyper::body::to_bytes(body).await.unwrap_or_default();
                let content = String::from_utf8_lossy(&body_bytes);

                if state.contains_blocked_keywords(&content) {
                    warn!("Content blocked by keyword: {}", url);
                    let log = RequestLog {
                        timestamp: Utc::now(),
                        client_ip: client_ip.clone(),
                        user: user.clone(),
                        method: method.to_string(),
                        url: url.clone(),
                        status: 403,
                        blocked: true,
                        block_reason: Some(BlockReason::BlockedKeyword.to_string()),
                        response_size: body_bytes.len(),
                    };
                    state.add_log(log).await;

                    return Ok(create_blocked_response(
                        "Access denied: Content blocked by corporate policy",
                    ));
                }

                let log = RequestLog {
                    timestamp: Utc::now(),
                    client_ip: client_ip.clone(),
                    user: user.clone(),
                    method: method.to_string(),
                    url: url.clone(),
                    status: status.as_u16(),
                    blocked: false,
                    block_reason: None,
                    response_size: body_bytes.len(),
                };
                state.add_log(log).await;

                Ok(Response::from_parts(parts, Body::from(body_bytes)))
            } else {
                let log = RequestLog {
                    timestamp: Utc::now(),
                    client_ip: client_ip.clone(),
                    user: user.clone(),
                    method: method.to_string(),
                    url: url.clone(),
                    status: status.as_u16(),
                    blocked: false,
                    block_reason: None,
                    response_size: 0,
                };
                state.add_log(log).await;

                Ok(response)
            }
        }
        Err(e) => {
            error!("Proxy error: {}", e);
            let log = RequestLog {
                timestamp: Utc::now(),
                client_ip: client_ip.clone(),
                user: user.clone(),
                method: method.to_string(),
                url: url.clone(),
                status: 502,
                blocked: false,
                block_reason: None,
                response_size: 0,
            };
            state.add_log(log).await;

            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Proxy error"))
                .unwrap())
        }
    }
}

pub async fn handle_connect(
    req: Request<Body>,
    state: Arc<ProxyState>,
    client_ip: String,
    user: Option<String>,
) -> Result<Response<Body>, Infallible> {
    let uri = req.uri();
    let host_port = uri
        .authority()
        .map(|auth| auth.to_string())
        .unwrap_or_else(|| "unknown:443".to_string());

    let full_url = format!("https://{}", host_port);
    if state.is_domain_blocked(&full_url) {
        warn!("HTTPS blocked: {}", full_url);
        let log = RequestLog {
            timestamp: Utc::now(),
            client_ip: client_ip.clone(),
            user: user.clone(),
            method: "CONNECT".to_string(),
            url: full_url.clone(),
            status: 403,
            blocked: true,
            block_reason: Some(BlockReason::BlockedDomain.to_string()),
            response_size: 0,
        };
        state.add_log(log).await;

        return Ok(create_blocked_response(
            "HTTPS access denied: Domain blocked",
        ));
    }

    let log = RequestLog {
        timestamp: Utc::now(),
        client_ip: client_ip.clone(),
        user: user.clone(),
        method: "CONNECT".to_string(),
        url: full_url,
        status: 200,
        blocked: false,
        block_reason: None,
        response_size: 0,
    };
    state.add_log(log).await;

    match TcpStream::connect(&host_port).await {
        Ok(target_stream) => {
            info!("Connected to server: {}", host_port);

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        info!("Upgrade completed, starting tunnel to {}", host_port);
                        if let Err(e) = tunnel(upgraded, target_stream).await {
                            error!("Error in tunnel: {}", e);
                        }
                    }
                    Err(e) => error!("Error in upgrade: {}", e),
                }
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        }
        Err(e) => {
            error!("Error to connect with {}: {}", host_port, e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Error to connect with the destination server"))
                .unwrap())
        }
    }
}

pub async fn tunnel(upgraded: Upgraded, server: TcpStream) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(upgraded);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let client_to_server = async {
        tokio::io::copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await
    };

    let server_to_client = async {
        tokio::io::copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await
    };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                error!("Error in tunnel (client -> server): {}", e);
            }
        },
        result = server_to_client => {
            if let Err(e) = result {
                error!("Error in tunnel (server -> client): {}", e);
            }
        },
    }

    Ok(())
}

pub async fn proxy_request(
    mut req: Request<Body>,
    client: &Client<HttpsConnector<hyper::client::HttpConnector>>,
) -> Result<Response<Body>, hyper::Error> {
    req.headers_mut().remove("proxy-authorization");
    req.headers_mut().remove("proxy-connection");

    client.request(req).await
}

pub fn create_blocked_response(message: &str) -> Response<Body> {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Acesso Bloqueado</title>
    <meta charset="utf-8">
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            background-color: #f5f5f5;
        }}
        .container {{ 
            max-width: 600px; 
            margin: 0 auto; 
            text-align: center; 
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .error {{ 
            color: #d32f2f; 
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .message {{
            font-size: 16px;
            margin-bottom: 30px;
            color: #333;
        }}
        .footer {{
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error">🚫 Access Blocked</h1>
        <p class="message">{}</p>
        <p class="footer">Corporate Proxy - Contact the administrator if necessary</p>
    </div>
</body>
</html>"#,
        message
    );

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

pub fn default_config() -> ProxyConfig {
    let mut allowed_users = HashMap::new();
    allowed_users.insert("admin".to_string(), "admin123".to_string());
    allowed_users.insert("user1".to_string(), "userpass".to_string());

    ProxyConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 8080,
        blocked_domains: vec![
            "facebook.com".to_string(),
            "twitter.com".to_string(),
            "x.com".to_string(),
            "youtube.com".to_string(),
            "instagram.com".to_string(),
            "tiktok.com".to_string(),
            "reddit.com".to_string(),
            "9gag.com".to_string(),
        ],
        blocked_keywords: vec![
            "malware".to_string(),
            "virus".to_string(),
            "hack".to_string(),
            "crack".to_string(),
            "torrent".to_string(),
        ],
        allowed_users,
        log_file: "proxy_logs.jsonl".to_string(),
        enable_ssl_bump: false,
        upstream_proxy: None,
    }
}
