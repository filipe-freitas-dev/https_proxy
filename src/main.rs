use base64::Engine;
use chrono::{DateTime, Utc};
use hyper::service::{make_service_fn, service_fn};
use hyper::{upgrade::Upgraded, Body, Client, Method, Request, Response, Server, StatusCode};
use hyper_tls::HttpsConnector;
use log::{error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub bind_address: String,
    pub port: u16,
    pub blocked_domains: Vec<String>,
    pub blocked_keywords: Vec<String>,
    pub allowed_users: HashMap<String, String>, // user -> password
    pub log_file: String,
    pub enable_ssl_bump: bool,
    pub upstream_proxy: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct RequestLog {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub user: Option<String>,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub blocked: bool,
    pub block_reason: Option<String>,
    pub response_size: usize,
}

#[derive(Debug, Clone)]
pub enum BlockReason {
    BlockedDomain,
    BlockedKeyword,
    Unauthorized,
    MaliciousContent,
    PolicyViolation,
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::BlockedDomain => write!(f, "Domínio bloqueado"),
            BlockReason::BlockedKeyword => write!(f, "Palavra-chave bloqueada"),
            BlockReason::Unauthorized => write!(f, "Não autorizado"),
            BlockReason::MaliciousContent => write!(f, "Conteúdo malicioso"),
            BlockReason::PolicyViolation => write!(f, "Violação de política"),
        }
    }
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: ProxyConfig,
    pub client: Client<HttpsConnector<hyper::client::HttpConnector>>,
    pub logs: Arc<RwLock<Vec<RequestLog>>>,
    pub blocked_patterns: Vec<Regex>,
}

impl ProxyState {
    pub fn new(config: ProxyConfig) -> Self {
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);

        let blocked_patterns = config
            .blocked_keywords
            .iter()
            .filter_map(|keyword| {
                let pattern = format!("(?i){}", regex::escape(keyword));
                Regex::new(&pattern).ok()
            })
            .collect();

        Self {
            config,
            client,
            logs: Arc::new(RwLock::new(Vec::new())),
            blocked_patterns,
        }
    }

    pub fn authenticate(&self, headers: &hyper::HeaderMap) -> Option<String> {
        if let Some(auth_header) = headers.get("proxy-authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Basic ") {
                    let encoded = &auth_str[6..];
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        if let Ok(credentials) = String::from_utf8(decoded) {
                            let parts: Vec<&str> = credentials.split(':').collect();
                            if parts.len() == 2 {
                                let (user, pass) = (parts[0], parts[1]);
                                if let Some(stored_pass) = self.config.allowed_users.get(user) {
                                    if stored_pass == pass {
                                        return Some(user.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn is_domain_blocked(&self, url: &str) -> bool {
        if let Ok(parsed_url) = url::Url::parse(url) {
            if let Some(host) = parsed_url.host_str() {
                return self
                    .config
                    .blocked_domains
                    .iter()
                    .any(|domain| host.ends_with(domain));
            }
        }
        false
    }

    pub fn contains_blocked_keywords(&self, content: &str) -> bool {
        self.blocked_patterns
            .iter()
            .any(|pattern| pattern.is_match(content))
    }

    pub async fn add_log(&self, log: RequestLog) {
        let mut logs = self.logs.write().await;
        logs.push(log.clone());
        if let Ok(json) = serde_json::to_string(&log) {
            use std::fs::OpenOptions;
            use std::io::Write;

            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.config.log_file)
            {
                if let Err(e) = writeln!(file, "{}", json) {
                    error!("Erro ao escrever no arquivo de log: {}", e);
                }
            } else {
                error!("Não foi possível abrir o arquivo de log para escrita");
            }
        }
    }
}

async fn handle_request(
    req: Request<Body>,
    state: Arc<ProxyState>,
    client_ip: String,
) -> Result<Response<Body>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let url = uri.to_string();

    info!("Requisição: {} {} de {}", method, url, client_ip);

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
            .body(Body::from("Autenticação necessária"))
            .unwrap());
    }

    if state.is_domain_blocked(&url) {
        warn!("Domínio bloqueado: {}", url);
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
            "Acesso negado: Domínio bloqueado pela política corporativa",
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
                    warn!("Conteúdo bloqueado por palavra-chave: {}", url);
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
                        "Acesso negado: Conteúdo bloqueado pela política corporativa",
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
            error!("Erro no proxy: {}", e);
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
                .body(Body::from("Erro no proxy"))
                .unwrap())
        }
    }
}

async fn handle_connect(
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
        warn!("HTTPS bloqueado: {}", full_url);
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
            "Acesso HTTPS negado: Domínio bloqueado",
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
            info!("Conectado ao servidor: {}", host_port);

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        info!("Upgrade realizado, iniciando tunnel para {}", host_port);
                        if let Err(e) = tunnel(upgraded, target_stream).await {
                            error!("Erro no tunnel: {}", e);
                        }
                    }
                    Err(e) => error!("Erro no upgrade: {}", e),
                }
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        }
        Err(e) => {
            error!("Erro ao conectar com {}: {}", host_port, e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Erro ao conectar com o servidor de destino"))
                .unwrap())
        }
    }
}

async fn tunnel(upgraded: Upgraded, server: TcpStream) -> std::io::Result<()> {
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
                error!("Erro no tunnel (cliente -> servidor): {}", e);
            }
        },
        result = server_to_client => {
            if let Err(e) = result {
                error!("Erro no tunnel (servidor -> cliente): {}", e);
            }
        },
    }

    Ok(())
}

async fn proxy_request(
    mut req: Request<Body>,
    client: &Client<HttpsConnector<hyper::client::HttpConnector>>,
) -> Result<Response<Body>, hyper::Error> {
    req.headers_mut().remove("proxy-authorization");
    req.headers_mut().remove("proxy-connection");

    client.request(req).await
}

fn create_blocked_response(message: &str) -> Response<Body> {
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
        <h1 class="error">🚫 Acesso Bloqueado</h1>
        <p class="message">{}</p>
        <p class="footer">Proxy Corporativo - Entre em contato com o administrador se necessário</p>
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

fn default_config() -> ProxyConfig {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("🚀 Iniciando Proxy Corporativo...");

    let config = if let Ok(config_data) = fs::read_to_string("proxy_config.json") {
        match serde_json::from_str(&config_data) {
            Ok(config) => {
                println!("✅ Configuração carregada de proxy_config.json");
                config
            }
            Err(e) => {
                println!(
                    "⚠️  Erro ao ler configuração: {}. Usando configuração padrão.",
                    e
                );
                default_config()
            }
        }
    } else {
        let config = default_config();
        match serde_json::to_string_pretty(&config) {
            Ok(config_json) => {
                if let Err(e) = fs::write("proxy_config.json", config_json) {
                    println!("⚠️  Erro ao salvar configuração padrão: {}", e);
                } else {
                    println!("📄 Arquivo proxy_config.json criado com configuração padrão");
                }
            }
            Err(e) => {
                println!("⚠️  Erro ao serializar configuração: {}", e);
            }
        }
        config
    };

    let addr = format!("{}:{}", config.bind_address, config.port);
    let socket_addr: SocketAddr = addr.parse()?;

    let state = Arc::new(ProxyState::new(config));

    println!("📋 Configuração:");
    println!("   • Endereço: {}", socket_addr);
    println!(
        "   • Domínios bloqueados: {}",
        state.config.blocked_domains.len()
    );
    println!(
        "   • Palavras-chave bloqueadas: {}",
        state.config.blocked_keywords.len()
    );
    println!(
        "   • Usuários configurados: {}",
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

    println!("🌐 Proxy HTTP/HTTPS rodando em http://{}", socket_addr);
    println!("📖 Configure seu navegador para usar este endereço como proxy HTTP/HTTPS");
    println!("🔐 Usuários padrão: admin/admin123, user1/userpass");
    println!("⚡ Pressione Ctrl+C para parar");

    if let Err(e) = server.await {
        error!("Erro no servidor: {}", e);
    }

    Ok(())
}
