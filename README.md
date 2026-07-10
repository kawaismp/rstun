# rstun

A high-performance TCP/UDP tunnel over QUIC, written in Rust.

rstun leverages the [Quinn](https://github.com/quinn-rs/quinn) library for [QUIC](https://quicwg.org/) transport, providing efficient, low-latency, and secure bidirectional communication. All traffic is protected by QUIC's integrated TLS layer.

---

## Enhanced Features

This fork focuses on maximum performance and minimal bloat for trusted networks:

- **Disabled Payload Encryption**: TLS is used for handshakes, but application data is sent unencrypted for zero-overhead, ultra-low latency routing.
- **Streamlined Configuration**: A clean, modern TOML file-based configuration replaces verbose CLI arguments.
- **Dedicated Inbound Mode**: Stripped away unnecessary outbound proxy logic to focus purely on high-performance Remote Port Forwarding.
- **Aggressive Optimizations**: Massive QUIC windows (64MB), TCP_NODELAY/QUICKACK, batched UDP forwarding, and 4MB socket buffers to absorb bursts.
- **Higher Limits**: Supports up to 4096 concurrent bidirectional streams for heavy multiplexing.

---

## Features

- **Multiple TCP and UDP tunnels**: Support for running multiple tunnels (TCP and/or UDP) simultaneously in a single client or server instance.
- **Bidirectional tunneling**: Expose local services over QUIC (Remote Port Forwarding).
- **TLS-based QUIC handshake**: Certificate handling and configurable TLS 1.3 cipher selection; payload protection is deliberately disabled in this build.
- **Automatic or custom certificates**: Use your own certificate/key or let rstun generate a self-signed certificate for testing.
- **Connection migration**: Optional periodic migration of QUIC connection to new random local UDP ports to avoid throttling during long data transfers.

---

## Operating Mode

### Inbound Tunneling (Remote Port Forwarding)
Expose a local service (e.g., web server, local database) to the public internet securely through the QUIC tunnel. Useful for making services behind NAT/firewall accessible externally without requiring port forwarding on your router. Traffic arrives at your VPS and is tunneled back to your local machine.

---

## Components

- **rstunc** (client): Establishes and manages tunnels to the server.
- **rstund** (server): Accepts incoming connections and forwards TCP/UDP traffic according to configuration.

---

## Configuration

rstun can be configured either via a **TOML configuration file** (recommended) or via traditional command-line flags.

### TOML Configuration

Using a TOML configuration file is the cleanest and most reliable way to set up your tunnels. You can load it using the `--config` flag:

```sh
rstund --config server.toml
```

```sh
rstunc --config client.toml
```

#### Example `server.toml`

```toml
# rstund server configuration
bind_address = "0.0.0.0:6060"
password = "super_secure_pa$$word"
workers = 1             # Number of async workers (0 = auto)
log_level = "info"      # "info", "debug", "error", etc.

[timeouts]
quic_idle_ms = 40000
tcp_idle_ms = 30000
udp_idle_ms = 30000
```

#### Example `client.toml`

```toml
# rstunc client configuration
server_address = "127.0.0.1:6060"
password = "super_secure_pa$$word"
workers = 4
log_level = "info"
retry_interval_ms = 5000
connection_migration_interval_ms = 30000 # Avoid UDP throttling

[tls]
cipher = "aes-128-gcm"

[timeouts]
quic_idle_ms = 30000
tcp_idle_ms = 30000
udp_idle_ms = 5000

[[tunnels]]
name = "Web server"
protocol = "tcp"
bind = "127.0.0.1:8080"     # What the server listens on (e.g. your VPS)
destination = "9000"        # Where the client forwards traffic locally

[[tunnels]]
name = "Minecraft server"
protocol = "udp"
bind = "0.0.0.0:25565"
destination = "127.0.0.1:25565"
```

### CLI Configuration (Legacy)

<details>
<summary>Click to view command-line flag documentation</summary>

You can completely bypass TOML files by passing all configurations inline. Flags passed via the CLI will override any defaults set in a TOML configuration file.

#### Start the server
```sh
rstund --addr 0.0.0.0:6060 --password 123456
```

#### Start the client
```sh
rstunc --server-addr 1.2.3.4:6060 --password 123456 \
  --tcp-mappings "127.0.0.1:8080^9000" \
  --udp-mappings "0.0.0.0:25565^25565" \
  --hop-interval-ms 30000
```

#### rstund Options
```
  --config <FILE>              Path to TOML configuration file
  -a, --addr <ADDR>            Address ([ip:]port) to listen on
  -p, --password <PASSWORD>    Server password
  -c, --cert <CERT>            Path to certificate file
  -k, --key <KEY>              Path to key file
  -w, --workers <N>            Number of async worker threads [default: 0]
      --quic-timeout-ms <MS>   QUIC idle timeout (ms) [default: 40000]
```

#### rstunc Options
```
  --config <FILE>                  Path to TOML configuration file
  -a, --server-addr <ADDR>         Server address (<domain:ip>[:port])
  -p, --password <PASSWORD>        Password for server authentication
  -t, --tcp-mappings <MAPPINGS>    Comma-separated TCP tunnel mappings
  -u, --udp-mappings <MAPPINGS>    Comma-separated UDP tunnel mappings
  -c, --cert <CERT>                Path to certificate file
  -e, --cipher <CIPHER>            Cipher suite [default: chacha20-poly1305]
  -w, --workers <N>                Number of async worker threads [default: 0]
      --hop-interval-ms <MS>       Interval for connection migration (ms)
```
</details>

---

## Connection Migration

The client supports optional connection migration via the `--hop-interval-ms` parameter. When specified, the QUIC connection will periodically migrate to a new random local UDP port at the given interval (in millseconds). This feature helps avoid UDP throttling that may occur during long data transfers while maintaining the upper-layer QUIC connection without interruption.

**Benefits:**
- Prevents UDP port-based rate limiting during extended data transfers
- Maintains seamless connectivity without breaking existing tunnels
- Helps bypass certain network restrictions that may throttle long-lived UDP flows

**Usage:**
- If `--hop-interval-ms` is not specified, connection migration is disabled
- Recommended intervals range from 60 to 600 seconds depending on network conditions
- Shorter intervals provide more frequent migration but may cause brief latency spikes

---

## Notes

- **Multiple tunnels**: You can specify multiple TCP and/or UDP tunnels in a single client or server instance using the new `--tcp-mappings` and `--udp-mappings` options.
- **Mapping format**: Each mapping is `bind_address^destination_address`. For example, `127.0.0.1:8080^9000`.
- **Self-signed certificates**: If no certificate is provided, a self-signed certificate for `localhost` is generated (for testing only).
- **Security**: For production, always use a valid certificate and connect via domain name.
- **Connection migration**: Use `--hop-interval-ms` to enable periodic port migration for improved performance in environments with UDP throttling.

---

## License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, you can obtain one at [http://mozilla.org/MPL/2.0/](http://mozilla.org/MPL/2.0/).
