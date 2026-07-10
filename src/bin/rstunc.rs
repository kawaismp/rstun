//! rstunc: QUIC-based tunneling client.
//!
//! Connects to an rstund server, authenticates, and starts TCP/UDP tunnels
//! according to the provided mappings. See --help for details and examples.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use clap::Parser;
use log::error;
use rstun::*;

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
    client_id: Option<String>,
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

fn main() {
    let mut args = RstuncArgs::parse();

    if args.config.is_empty() {
        if !std::path::Path::new("rstunc.toml").exists() {
            let default_config = r#"# rstunc client configuration
server_address = "127.0.0.1:6060"
client_id = "home-gateway"
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
        let toml: RstuncToml = toml::from_str(&content).unwrap_or_else(|e| {
            println!("failed to parse TOML config {}: {e}", args.config);
            std::process::exit(1);
        });

        if let Some(v) = toml.server_address {
            if args.server_addr.is_empty() {
                args.server_addr = v;
            }
        }
        if let Some(v) = toml.client_id {
            if args.client_id.is_empty() {
                args.client_id = v;
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

        if let Some(tunnels) = toml.tunnels {
            let mut tcp_mappings = Vec::new();
            let mut udp_mappings = Vec::new();

            for t in tunnels {
                let name = t.name.unwrap_or_else(|| "unnamed tunnel".into());
                let mapping = format!("{}^{}", t.bind, t.destination);

                match t.protocol.to_lowercase().as_str() {
                    "tcp" => tcp_mappings.push(mapping),
                    "udp" => udp_mappings.push(mapping),
                    _ => {
                        println!(
                            "Error in tunnel '{}': protocol must be 'tcp' or 'udp'",
                            name
                        );
                        std::process::exit(1);
                    }
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

    if args.server_addr.is_empty() || args.client_id.is_empty() || args.password.is_empty() {
        println!("server_addr, client_id, and password are required (via CLI or TOML config)");
        std::process::exit(1);
    }

    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstunc", log_filter.as_str());

    let config = ClientConfig::create(
        &args.server_addr,
        &args.client_id,
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
        match Client::new(config) {
            Ok(mut client) => client.start_tunneling(),
            Err(error) => error!("{error}"),
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

    /// Stable identifier for this logical client across process restarts.
    #[arg(long, default_value = "")]
    client_id: String,

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
