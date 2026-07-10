//! rstund: QUIC-based tunneling server.
//!
//! Binds a QUIC endpoint, authenticates incoming clients, and serves
//! TCP/UDP tunnels according to client requests. See --help for options.
//!
//! This binary is built as part of the `rstun` crate.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::builder::PossibleValuesParser;
use clap::builder::TypedValueParser as _;
use clap::Parser;
use log::error;
use log::info;
use rstun::*;

#[derive(serde::Deserialize)]
struct TimeoutsToml {
    quic_idle_ms: Option<u64>,
    tcp_idle_ms: Option<u64>,
    udp_idle_ms: Option<u64>,
}

#[derive(serde::Deserialize)]
struct TlsServerToml {
    cert: Option<String>,
    key: Option<String>,
}

#[derive(serde::Deserialize)]
struct RstundToml {
    bind_address: Option<String>,
    password: Option<String>,
    workers: Option<usize>,
    log_level: Option<String>,

    timeouts: Option<TimeoutsToml>,
    tls: Option<TlsServerToml>,
}

fn main() {
    let mut args = RstundArgs::parse();

    if args.config.is_empty() {
        if !std::path::Path::new("rstund.toml").exists() {
            let default_config = r#"# rstund server configuration
bind_address = "0.0.0.0:6060"
password = "change_this_password"
workers = 1             # Number of async workers (0 = auto)
log_level = "info"      # "info", "debug", "error", etc.

[timeouts]
quic_idle_ms = 40000
tcp_idle_ms = 30000
udp_idle_ms = 30000
"#;
            if let Err(e) = std::fs::write("rstund.toml", default_config) {
                println!("failed to create default rstund.toml: {e}");
            } else {
                println!("Created default rstund.toml. Please edit it and restart.");
                std::process::exit(0);
            }
        }
        args.config = "rstund.toml".to_string();
    }

    if !args.config.is_empty() {
        let content = std::fs::read_to_string(&args.config).unwrap_or_else(|e| {
            println!("failed to read config {}: {e}", args.config);
            std::process::exit(1);
        });
        let toml: RstundToml = toml::from_str(&content).unwrap_or_else(|e| {
            println!("failed to parse TOML config {}: {e}", args.config);
            std::process::exit(1);
        });

        if let Some(v) = toml.bind_address {
            if args.addr.is_empty() {
                args.addr = v;
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

        if let Some(tls) = toml.tls {
            if let Some(v) = tls.cert {
                if args.cert.is_empty() {
                    args.cert = v;
                }
            }
            if let Some(v) = tls.key {
                if args.key.is_empty() {
                    args.key = v;
                }
            }
        }

        if let Some(timeouts) = toml.timeouts {
            if let Some(v) = timeouts.quic_idle_ms {
                if args.quic_timeout_ms == 40000 {
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
    }

    if args.addr.is_empty() || args.password.is_empty() {
        println!("addr and password are required (via CLI or TOML config)");
        std::process::exit(1);
    }

    let log_filter = format!("rstun={},rs_utilities={}", args.loglevel, args.loglevel);
    rs_utilities::LogHelper::init_logger("rstund", log_filter.as_str());

    let workers = if args.workers > 0 {
        args.workers
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };

    info!("will use {} workers", workers);

    let mut builder = if workers == 1 {
        tokio::runtime::Builder::new_current_thread()
    } else {
        let mut b = tokio::runtime::Builder::new_multi_thread();
        b.worker_threads(workers);
        b
    };

    builder.enable_all().build().unwrap().block_on(async {
        run(args)
            .await
            .map_err(|e| {
                error!("{e}");
            })
            .ok();
    })
}

async fn run(mut args: RstundArgs) -> Result<()> {
    if args.addr.is_empty() {
        args.addr = "0.0.0.0:0".to_string();
    }

    if !args.addr.contains(':') {
        args.addr = format!("127.0.0.1:{}", args.addr);
    }

    let config = ServerConfig {
        addr: args.addr,
        password: args.password,
        cert_path: args.cert,
        key_path: args.key,
        quic_timeout_ms: args.quic_timeout_ms,
        tcp_timeout_ms: args.tcp_timeout_ms,
        udp_timeout_ms: args.udp_timeout_ms,
        dashboard_server: "".to_string(),
        dashboard_server_credential: "".to_string(),
    };

    let mut server = Server::new(config);
    server.bind()?;
    server.serve().await?;
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct RstundArgs {
    /// Path to TOML configuration file
    #[arg(long, default_value = "")]
    config: String,

    /// Address ([ip:]port) to listen on. If only a port is given, binds to 127.0.0.1:PORT.
    #[arg(short = 'a', long, default_value = "", verbatim_doc_comment)]
    addr: String,

    /// Default TCP upstream for OUT tunnels ([ip:]port). Used if client does not specify an upstream.
    #[arg(
        short = 't',
        long,
        required = false,
        default_value = "",
        verbatim_doc_comment
    )]
    tcp_upstream: String,

    /// Default UDP upstream for OUT tunnels ([ip:]port). Used if client does not specify an upstream.
    #[arg(
        short = 'u',
        long,
        required = false,
        default_value = "",
        verbatim_doc_comment
    )]
    udp_upstream: String,

    /// Server password (must match client password)
    #[arg(short = 'p', long, default_value = "")]
    password: String,

    /// Path to certificate file (optional). If empty, a self-signed certificate for "localhost" is generated (testing only).
    #[arg(short = 'c', long, default_value = "", verbatim_doc_comment)]
    cert: String,

    /// Path to key file (optional, only needed if --cert is set)
    #[arg(short = 'k', long, default_value = "")]
    key: String,

    /// Number of async worker threads [uses all logical CPUs if 0]
    #[arg(short = 'w', long, default_value_t = 0)]
    workers: usize,

    /// QUIC idle timeout in milliseconds
    #[arg(long, default_value_t = 40000)]
    quic_timeout_ms: u64,

    /// TCP idle timeout in milliseconds
    #[arg(long, default_value_t = 30000)]
    tcp_timeout_ms: u64,

    /// UDP idle timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    udp_timeout_ms: u64,

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
