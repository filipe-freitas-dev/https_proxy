use base64::Engine;
use chrono::{DateTime, Utc};
use hyper::Client;
use hyper_tls::HttpsConnector;
use log::error;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
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
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::BlockedDomain => write!(f, "Domínio bloqueado"),
            BlockReason::BlockedKeyword => write!(f, "Palavra-chave bloqueada"),
            BlockReason::Unauthorized => write!(f, "Não autorizado"),
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
