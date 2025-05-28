
# 🔐 Corporate Proxy in Rust

A complete corporate HTTP/HTTPS proxy developed in Rust, focused on **security**, **control**, and **performance**. This proxy is ideal for corporate environments that require **authentication**, **content blocking**, and **traffic logging**.

## 🚀 Features

- 🔐 **Authentication** via `Proxy-Authorization` header (Basic Auth)
- 🌐 **HTTPS support** using the `CONNECT` method
- 🚫 **Domain and keyword blocking** (e.g., "porn", "torrent", etc.)
- 📄 **External configuration** via `proxy_config.json`
- 📦 **Automatic fallback** to default settings if JSON config is missing
- 🧾 **Detailed request logging**
- ⚡ **Multithreaded and asynchronous** with `tokio`

## 📁 Project Structure

```bash
.
.
├── Cargo.lock
├── Cargo.toml
├── LICENSE
├── proxy_config.json
├── proxy_logs.jsonl
├── src
│   └── main.rs
└── README.md

```

## 🛠️ Requirements

- [Rust](https://www.rust-lang.org/) (version 1.70+ recommended)
- Cargo

## 📦 Installation

Clone the repository and build the project:

```bash
git clone https://github.com/your-username/rust-corporate-proxy.git
cd rust-corporate-proxy
cargo build --release
```

## ⚙️ Configuration

You can provide a `proxy_config.json` file with the following structure:

```json
{
  "proxy_port": 8080,
  "username": "admin",
  "password": "supersecret",
  "blocked_domains": ["example.com", "test.org"],
  "blocked_keywords": ["porn", "torrent", "hack"]
}
```

If the file is not found, the proxy will use default settings:

```json
{
  "proxy_port": 8080,
  "username": "admin",
  "password": "password",
  "blocked_domains": [],
  "blocked_keywords": []
}
```

## ▶️ Running

With custom configuration:

```bash
./target/release/rust-corporate-proxy
```

Or directly with default settings:

```bash
cargo run --release
```

## 🔍 Logging

The proxy logs all processed requests:

- Authenticated and blocked requests
- Keyword detection
- Blocked domain access attempts
- TLS/connection errors

Example log:

```
{"timestamp":"2025-05-28T17:03:04.304297450Z","client_ip":"127.0.0.1","user":"admin","method":"GET","url":"http://detectportal.firefox.com/success.txt?ipv6","status":403,"blocked":true,"block_reason":"Domínio bloqueado","response_size":0}
```

## 📋 To-Do

- [ ] Persistent log storage
- [ ] Web dashboard for monitoring
- [ ] Dynamic blocking list via API
- [ ] Rate limiting

## 🧠 About This Project

This proxy was developed as a practical project for studying cybersecurity, networking, and systems programming in Rust. It aims to deliver a robust and extensible tool for monitoring and controlling HTTP/HTTPS traffic in enterprise environments.

---

## 🧑‍💻 Author

Made with 💻, ☕ and curiosity by [Your Name or GitHub](https://github.com/your-username)

## 📄 License

This project is licensed under the [MIT License](LICENSE).
