//! rstunc: QUIC-based tunneling client.
//!
//! Connects to an rstund server, authenticates, and starts TCP/UDP tunnels
//! according to the provided mappings. See --help for details and examples.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{bail, Context, Result};
use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use clap::Parser;
use log::{error, warn};
use rstun::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::watch;

#[derive(serde::Deserialize)]
struct TomlTunnel {
    name: Option<String>,
    protocol: String,
    bind: String,
    destination: String,
}

#[derive(serde::Deserialize)]
struct TimeoutsToml {
    quic_idle_ms: Option<u64>,
    tcp_idle_ms: Option<u64>,
    udp_idle_ms: Option<u64>,
}

#[derive(serde::Deserialize)]
struct TlsClientToml {
    cert: Option<String>,
    cipher: Option<String>,
}

#[derive(serde::Deserialize)]
struct DnsToml {
    servers: Option<String>,
    dot_servers: Option<String>,
}

#[derive(serde::Deserialize)]
struct RstuncToml {
    server_address: Option<String>,
    password: Option<String>,
    workers: Option<usize>,
    log_level: Option<String>,
    retry_interval_ms: Option<u64>,
    connection_migration_interval_ms: Option<u64>,

    tls: Option<TlsClientToml>,
    dns: Option<DnsToml>,
    timeouts: Option<TimeoutsToml>,

    tunnels: Option<Vec<TomlTunnel>>,
}

fn parse_tunnel_addr(value: &str) -> Result<SocketAddr> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    value
        .parse()
        .with_context(|| format!("invalid tunnel address '{value}'"))
}

fn parse_toml_tunnels(tunnels: Option<Vec<TomlTunnel>>) -> Result<Vec<TunnelConfig>> {
    tunnels
        .unwrap_or_default()
        .into_iter()
        .map(|tunnel| {
            let name = tunnel.name.unwrap_or_else(|| "unnamed tunnel".to_string());
            let upstream_type = match tunnel.protocol.to_ascii_lowercase().as_str() {
                "tcp" => UpstreamType::Tcp,
                "udp" => UpstreamType::Udp,
                _ => bail!("tunnel '{name}' protocol must be 'tcp' or 'udp'"),
            };
            Ok(TunnelConfig {
                upstream: Upstream {
                    upstream_addr: Some(parse_tunnel_addr(&tunnel.bind)?),
                    upstream_type,
                },
                local_server_addr: parse_tunnel_addr(&tunnel.destination)?,
            })
        })
        .collect()
}

fn spawn_config_watcher(
    path: String,
    initial_content: String,
    initial_tunnels: Vec<TunnelConfig>,
) -> watch::Receiver<Vec<TunnelConfig>> {
    let (updates, receiver) = watch::channel(initial_tunnels);
    std::thread::spawn(move || {
        let mut last_content = initial_content;
        let mut last_read_error = None;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            if updates.is_closed() {
                break;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    let message = error.to_string();
                    if last_read_error.as_deref() != Some(message.as_str()) {
                        warn!("failed to read config update from {path}: {message}");
                        last_read_error = Some(message);
                    }
                    continue;
                }
            };
            last_read_error = None;
            if content == last_content {
                continue;
            }
            last_content = content.clone();

            let tunnels = toml::from_str::<RstuncToml>(&content)
                .context("failed to parse updated TOML")
                .and_then(|config| parse_toml_tunnels(config.tunnels));
            match tunnels {
                Ok(tunnels) => {
                    if updates.send(tunnels).is_err() {
                        break;
                    }
                }
                Err(error) => warn!("ignored invalid config update: {error:#}"),
            }
        }
    });
    receiver
}

fn main() {
    let mut args = RstuncArgs::parse();
    let cli_tunnels_supplied = !args.tcp_mappings.is_empty() || !args.udp_mappings.is_empty();
    let mut watched_content = None;

    if args.config.is_empty() {
        if !std::path::Path::new("rstunc.toml").exists() {
            let default_config = r#"# rstunc client configuration
server_address = "127.0.0.1:6060"
password = "change_this_password"
workers = 0             # 0 = auto
log_level = "info"
retry_interval_ms = 5000
connection_migration_interval_ms = 0 # 0 = disabled

[tls]
cipher = "chacha20-poly1305"

[timeouts]
quic_idle_ms = 30000
tcp_idle_ms = 30000
udp_idle_ms = 5000

[[tunnels]]
name = "Expose my web server"
protocol = "tcp"
bind = "127.0.0.1:8080"
destination = "9000"
"#;
            if let Err(e) = std::fs::write("rstunc.toml", default_config) {
                println!("failed to create default rstunc.toml: {e}");
            } else {
                println!("Created default rstunc.toml. Please edit it and restart.");
                std::process::exit(0);
            }
        }
        args.config = "rstunc.toml".to_string();
    }

    if !args.config.is_empty() {
        let content = std::fs::read_to_string(&args.config).unwrap_or_else(|e| {
            println!("failed to read config {}: {e}", args.config);
            std::process::exit(1);
        });
        watched_content = Some(content.clone());
        let toml: RstuncToml = toml::from_str(&content).unwrap_or_else(|e| {
            println!("failed to parse TOML config {}: {e}", args.config);
            std::process::exit(1);
        });

        if let Some(v) = toml.server_address {
            if args.server_addr.is_empty() {
                args.server_addr = v;
            }
        }
        if let Some(v) = toml.password {
            if args.password.is_empty() {
                args.password = v;
            }
        }
        if let Some(v) = toml.workers {
            if args.workers == 0 {
                args.workers = v;
            }
        }
        if let Some(v) = toml.log_level {
            if args.loglevel == "I" {
                args.loglevel = match v.to_lowercase().as_str() {
                    "trace" | "t" => "trace",
                    "debug" | "d" => "debug",
                    "info" | "i" => "info",
                    "warn" | "warning" | "w" => "warn",
                    "error" | "e" => "error",
                    _ => "info",
                }
                .to_string();
            }
        }
        if let Some(v) = toml.retry_interval_ms {
            if args.wait_before_retry_ms == 5000 {
                args.wait_before_retry_ms = v;
            }
        }
        if let Some(v) = toml.connection_migration_interval_ms {
            if args.hop_interval_ms == 0 {
                args.hop_interval_ms = v;
            }
        }

        if let Some(tls) = toml.tls {
            if let Some(v) = tls.cert {
                if args.cert.is_empty() {
                    args.cert = v;
                }
            }
            if let Some(v) = tls.cipher {
                if args.cipher == SUPPORTED_CIPHER_SUITE_STRS[0] {
                    args.cipher = v;
                }
            }
        }

        if let Some(dns) = toml.dns {
            if let Some(v) = dns.servers {
                if args.dns.is_empty() {
                    args.dns = v;
                }
            }
            if let Some(v) = dns.dot_servers {
                if args.dot.is_empty() {
                    args.dot = v;
                }
            }
        }

        if let Some(timeouts) = toml.timeouts {
            if let Some(v) = timeouts.quic_idle_ms {
                if args.quic_timeout_ms == 30000 {
                    args.quic_timeout_ms = v;
                }
            }
            if let Some(v) = timeouts.tcp_idle_ms {
                if args.tcp_timeout_ms == 30000 {
                    args.tcp_timeout_ms = v;
                }
            }
            if let Some(v) = timeouts.udp_idle_ms {
                if args.udp_timeout_ms == 5000 {
                    args.udp_timeout_ms = v;
                }
            }
        }

        if toml.tunnels.is_some() && !cli_tunnels_supplied {
            let mut tcp_mappings = Vec::new();
            let mut udp_mappings = Vec::new();

            let tunnels = parse_toml_tunnels(toml.tunnels).unwrap_or_else(|error| {
                println!("invalid tunnel configuration: {error:#}");
                std::process::exit(1);
            });
            for tunnel in tunnels {
                let mapping = format!(
                    "{}^{}",
                    tunnel.upstream.upstream_addr.unwrap(),
                    tunnel.local_server_addr
                );
                match tunnel.upstream.upstream_type {
                    UpstreamType::Tcp => tcp_mappings.push(mapping),
                    UpstreamType::Udp => udp_mappings.push(mapping),
                }
            }

            if !tcp_mappings.is_empty() && args.tcp_mappings.is_empty() {
                args.tcp_mappings = tcp_mappings.join(",");
            }
            if !udp_mappings.is_empty() && args.udp_mappings.is_empty() {
                args.udp_mappings = udp_mappings.join(",");
            }
        }
    }

    if args.server_addr.is_empty() || args.password.is_empty() {
        println!("server_addr and password are required (via CLI or TOML config)");
        std::process::exit(1);
    }

    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstunc", log_filter.as_str());

    let config = ClientConfig::create(
        &args.server_addr,
        &args.password,
        &args.cert,
        &args.cipher,
        &args.tcp_mappings,
        &args.udp_mappings,
        &args.dot,
        &args.dns,
        args.workers,
        args.wait_before_retry_ms,
        args.quic_timeout_ms,
        args.tcp_timeout_ms,
        args.udp_timeout_ms,
        args.hop_interval_ms,
    )
    .map_err(|e| {
        error!("{e}");
    });

    if let Ok(config) = config {
        let initial_tunnels = config.tunnels.clone();
        let mut client = Client::new(config);
        if cli_tunnels_supplied {
            client.start_tunneling();
        } else if let Some(content) = watched_content {
            let updates = spawn_config_watcher(args.config, content, initial_tunnels);
            client.start_tunneling_with_updates(updates);
        } else {
            client.start_tunneling();
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstuncArgs {
    /// Path to TOML configuration file
    #[arg(long, default_value = "")]
    config: String,

    /// Server address (<domain:ip>[:port]) of rstund. Default port is 3515.
    #[arg(short = 'a', long, default_value = "")]
    server_addr: String,

    /// Password for server authentication (must match server's password)
    #[arg(short = 'p', long, default_value = "")]
    password: String,

    /// Comma-separated inbound TCP mappings in the form bind^destination,
    /// e.g. 0.0.0.0:9090^127.0.0.1:8080.
    #[arg(short = 't', long, verbatim_doc_comment, default_value = "")]
    tcp_mappings: String,

    /// Comma-separated inbound UDP mappings in the form bind^destination,
    /// e.g. 0.0.0.0:9090^127.0.0.1:8080.
    #[arg(short = 'u', long, verbatim_doc_comment, default_value = "")]
    udp_mappings: String,

    /// Path to the certificate file (only needed for self-signed certificates)
    #[arg(short = 'c', long, default_value = "")]
    cert: String,

    /// Preferred cipher suite
    #[arg(short = 'e', long, default_value_t = String::from(SUPPORTED_CIPHER_SUITE_STRS[0]),
        value_parser = PossibleValuesParser::new(SUPPORTED_CIPHER_SUITE_STRS).map(|v| v.to_string()))]
    cipher: String,

    /// Number of async worker threads [uses all logical CPUs if 0]
    #[arg(short = 'w', long, default_value_t = 0)]
    workers: usize,

    /// Wait time in milliseconds before retrying connection
    #[arg(short = 'r', long, default_value_t = 5000)]
    wait_before_retry_ms: u64,

    /// QUIC idle timeout in milliseconds
    #[arg(long, default_value_t = 30000)]
    quic_timeout_ms: u64,

    /// TCP idle timeout in milliseconds
    #[arg(long, default_value_t = 30000)]
    tcp_timeout_ms: u64,

    /// UDP idle timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    udp_timeout_ms: u64,

    #[arg(long, default_value_t = 0)]
    hop_interval_ms: u64,

    /// Comma-separated DoT servers (domains) for DNS resolution, e.g. "dns.google,one.one.one.one". Takes precedence over --dns if set.
    #[arg(long, verbatim_doc_comment, default_value = "")]
    dot: String,

    /// Comma-separated DNS servers (IPs) for DNS resolution, e.g. "1.1.1.1,8.8.8.8"
    #[arg(long, verbatim_doc_comment, default_value = "")]
    dns: String,

    /// Log level
    #[arg(short = 'l', long, default_value_t = String::from("I"),
        value_parser = PossibleValuesParser::new(["T", "D", "I", "W", "E"]).map(|v| match v.as_str() {
            "T" => "trace",
            "D" => "debug",
            "I" => "info",
            "W" => "warn",
            "E" => "error",
            _ => "info",
        }.to_string()))]
    loglevel: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_tunnels(tunnels: &str) -> String {
        format!(
            r#"server_address = "127.0.0.1:6060"
password = "secret"
{tunnels}
"#
        )
    }

    #[test]
    fn parses_toml_tunnels_with_canonical_direction() {
        let content = config_with_tunnels(
            r#"[[tunnels]]
protocol = "tcp"
bind = "0.0.0.0:9000"
destination = "127.0.0.1:8080""#,
        );
        let config: RstuncToml = toml::from_str(&content).unwrap();
        let tunnels = parse_toml_tunnels(config.tunnels).unwrap();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(
            tunnels[0].upstream.upstream_addr.unwrap().to_string(),
            "0.0.0.0:9000"
        );
        assert_eq!(tunnels[0].local_server_addr.to_string(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn watcher_ignores_invalid_content_and_emits_next_valid_update() {
        let path = std::env::temp_dir().join(format!(
            "rstunc-hot-reload-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let initial = config_with_tunnels("");
        std::fs::write(&path, &initial).unwrap();
        let mut updates =
            spawn_config_watcher(path.to_string_lossy().into_owned(), initial, vec![]);

        std::fs::write(&path, "not valid toml = [").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(700), updates.changed())
                .await
                .is_err()
        );

        let valid = config_with_tunnels(
            r#"[[tunnels]]
protocol = "udp"
bind = "127.0.0.1:9100"
destination = "127.0.0.1:8100""#,
        );
        std::fs::write(&path, valid).unwrap();
        tokio::time::timeout(Duration::from_secs(2), updates.changed())
            .await
            .unwrap()
            .unwrap();
        let update = updates.borrow_and_update().clone();
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].upstream.upstream_type, UpstreamType::Udp);

        drop(updates);
        std::fs::remove_file(path).unwrap();
    }
}
