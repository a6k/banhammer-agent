# BanHammer Agent

Lightweight server agent that monitors Fail2Ban activity and serves a local REST API. Connects directly to the BanHammer macOS/iOS app — no central server required. Your data stays on your server.

## How it works

```
[Your Server]
  └── banhammer-agent (runs as dedicated user)
        ├── Monitors Fail2Ban logs and jails
        ├── Stores events in local SQLite database
        ├── Enriches IPs with geo-location data
        └── Serves HTTPS API + WebSocket for the BanHammer app
              ↑
[BanHammer macOS / iOS App] ← connects directly, no cloud relay
```

## Quick Start

### 1. Install

```bash
git clone https://github.com/a6k/banhammer-agent.git
cd banhammer-agent
pip install -e .

# Optional: GeoIP support (recommended)
pip install -e ".[geo]"
```

### 2. Initialize

```bash
sudo banhammer-agent init
```

This generates an API key, a random path prefix, and creates `/etc/banhammer/config.toml`. **Save the API key and path prefix** — you'll need both in the BanHammer app.

### 3. Set up dedicated user (recommended)

```bash
sudo useradd -r -s /sbin/nologin banhammer
sudo chown -R banhammer:banhammer /var/lib/banhammer /etc/banhammer
sudo usermod -aG adm banhammer  # Read access to /var/log/fail2ban.log

# Sudo rules for fail2ban-client
sudo tee /etc/sudoers.d/banhammer << 'EOF'
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status *
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set * unbanip *
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set * addignoreip *
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set * delignoreip *
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client get * logpath
banhammer ALL=(root) NOPASSWD: /usr/bin/fail2ban-client get * journalmatch
EOF
sudo chmod 440 /etc/sudoers.d/banhammer
```

Then enable sudo in the config:

```toml
[fail2ban]
use_sudo = true
```

### 4. Run

Install as a systemd service (recommended):

```bash
sudo cp systemd/banhammer-agent.service /etc/systemd/system/
sudo systemctl enable --now banhammer-agent
```

Or run directly for testing (as root):

```bash
sudo banhammer-agent run
```

### 5. Connect the app

Open the BanHammer app (macOS or iOS), add your server with the URL (including path prefix) and API key from step 2. The app is available for macOS, iPhone, and iPad — all sharing the same SwiftUI codebase.

## Features

- **Live ban feed** — real-time ban/unban events from Fail2Ban logs
- **Geo-IP enrichment** — automatic country/city lookup for banned IPs (GeoLite2 or ip-api.com fallback)
- **Timeline stats** — hourly ban aggregation for trend charts and heatmaps
- **Country stats** — ban counts by country for geographic analysis
- **Whitelist management** — add/remove IPs from the Fail2Ban ignore list
- **Bulk unban** — unban multiple IPs in one request
- **WebSocket real-time** — instant ban events via WebSocket, no polling delay
- **GeoLite2 auto-update** — automatic database refresh when older than 30 days
- **Capability advertisement** — the app auto-detects supported features

## API

The agent serves a REST API on port 8443 (configurable). All endpoints are prefixed with a random path (e.g. `/x7k9m2p4q8w1`) generated during `init` — this makes the API invisible to port scanners.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/{prefix}/api/v1/health` | No | Status check |
| GET | `/{prefix}/api/v1/status` | API-Key | Jail status, active bans, IPs, capabilities |
| GET | `/{prefix}/api/v1/events` | API-Key | Ban/unban events with geo data (paginated) |
| GET | `/{prefix}/api/v1/stats` | API-Key | Top attackers (with first/last seen), bans by jail |
| GET | `/{prefix}/api/v1/stats/timeline` | API-Key | Hourly ban buckets (24h/7d/30d) |
| GET | `/{prefix}/api/v1/stats/countries` | API-Key | Ban counts aggregated by country |
| POST | `/{prefix}/api/v1/unban` | API-Key | Unban an IP from a jail |
| POST | `/{prefix}/api/v1/unban/bulk` | API-Key | Bulk unban (max 25 entries) |
| GET | `/{prefix}/api/v1/whitelist` | API-Key | List whitelisted IPs |
| POST | `/{prefix}/api/v1/whitelist` | API-Key | Add IP to whitelist (also unbans) |
| DELETE | `/{prefix}/api/v1/whitelist/{ip}` | API-Key | Remove IP from whitelist |
| WS | `/{prefix}/api/v1/ws` | Token | WebSocket for real-time events |

Auth header: `Authorization: Bearer bh_your_api_key`
WebSocket auth: `Authorization: Bearer bh_your_api_key` (same header as REST; query parameter `?token=KEY` still accepted for backwards compatibility)

## Deployment

### Behind Nginx (recommended)

The agent listens on localhost:8443. Use a location block on an existing domain — no extra subdomain needed, no trace in DNS:

```nginx
# Add to an existing server block (e.g. your mail or web server)
location /x7k9m2p4q8w1/ {
    proxy_pass http://127.0.0.1:8443/x7k9m2p4q8w1/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # WebSocket support
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # Keep WebSocket connections alive (default 60s would drop idle connections)
    proxy_read_timeout 86400;
    proxy_send_timeout 86400;
}

```

Replace `x7k9m2p4q8w1` with the `path_prefix` from your config. The app URL becomes `https://your-existing-domain.com/x7k9m2p4q8w1`.

### Cloudflare

**Do not proxy the agent endpoint through Cloudflare's orange-cloud.** Cloudflare forces HTTP/2 on proxied connections, but WebSocket over HTTP/2 (RFC 8441) is not supported by iOS `URLSessionWebSocketTask` — the connection silently fails with a 404. The BanHammer app will fall back to polling instead of receiving live events.

**Workaround:** Create a dedicated DNS subdomain for the agent and set it to **grey-cloud** (DNS-only, no proxy):

```
agent.yourdomain.com  →  your-server-ip  (grey cloud, DNS only)
```

Add a separate nginx `server` block for this subdomain with a Let's Encrypt certificate:

```nginx
server {
    listen 443 ssl;
    server_name agent.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/agent.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/agent.yourdomain.com/privkey.pem;

    location /x7k9m2p4q8w1/ {
        proxy_pass http://127.0.0.1:8443/x7k9m2p4q8w1/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
```

Your main domain (`yourdomain.com`) can keep the orange-cloud proxy. Only the agent subdomain needs to bypass Cloudflare.

### Direct HTTPS (no Nginx)

```toml
[api]
bind = "0.0.0.0"
port = 8443
tls_cert = "/etc/banhammer/cert.pem"
tls_key = "/etc/banhammer/key.pem"
```

## GeoIP Setup

For IP-to-location enrichment (map pins, country stats):

### Option A: GeoLite2 local database (recommended, private)

1. Create a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup)
2. Download `GeoLite2-City.mmdb`
3. Place it at `/var/lib/banhammer/GeoLite2-City.mmdb`
4. Add to config:

```toml
[geo]
geoip_db_path = "/var/lib/banhammer/GeoLite2-City.mmdb"
```

### Auto-Update (recommended)

Add your MaxMind license key to enable automatic updates when the DB is older than 30 days:

```toml
[geo]
geoip_db_path = "/var/lib/banhammer/GeoLite2-City.mmdb"
maxmind_license_key = "your_key_here"
```

The agent checks the DB age at startup and downloads a fresh copy automatically. You can also trigger a manual update:

```bash
banhammer-agent update-geodb
```

### Option B: ip-api.com fallback (simple, but sends IPs in plaintext)

```toml
[geo]
allow_http_fallback = true
```

> **Security note:** This sends banned IPs to ip-api.com over plaintext HTTP. Only enable if you accept the privacy trade-off.

### Backfill existing events

```bash
banhammer-agent backfill-geo
```

This enriches all existing events that don't have geo data yet.

## Configuration

See [config.example.toml](config.example.toml) for all options.

```toml
[api]
bind = "127.0.0.1"         # Use "0.0.0.0" for direct access (requires TLS)
port = 8443
api_key = "bh_..."          # Generated by 'banhammer-agent init'
path_prefix = "/x7k9m2p4q8w1"  # Random, generated by init

[agent]
server_id = "my-server"    # Default: hostname
poll_interval = 60          # Seconds between Fail2Ban polls

[fail2ban]
log_path = "/var/log/fail2ban.log"
client_path = "/usr/bin/fail2ban-client"
# use_sudo = true           # Required when running as non-root user

[storage]
db_path = "/var/lib/banhammer/banhammer.db"
retention_days = 90         # Auto-delete old events

[geo]
# geoip_db_path = "/var/lib/banhammer/GeoLite2-City.mmdb"
# maxmind_license_key = "your_key"  # enables auto-update
# allow_http_fallback = false
```

## CLI

| Command | Description |
|---------|-------------|
| `banhammer-agent init` | Generate config and API key |
| `banhammer-agent run` | Start monitoring + API server |
| `banhammer-agent status` | Show local DB stats and API status |
| `banhammer-agent backfill-geo` | Enrich existing events with geo data |
| `banhammer-agent update-geodb` | Download/update GeoLite2 database |

## Security

The agent has been through 14 security audits; the macOS/iOS app through 31. Key hardening:

- Runs as dedicated `banhammer` user (not root)
- API key with constant-time comparison (`hmac.compare_digest`)
- TLS enforced for non-loopback binds
- Random path prefix (obscurity layer on top of auth)
- Rate limiting (10 req/s per IP)
- All subprocess calls use list form (no shell injection)
- All SQL parameterized (no SQL injection)
- IP and jail name validation at every boundary
- Log paths validated and restricted to `/var/log/`
- GeoIP HTTP fallback is opt-in with security warning
- WebSocket token via `Authorization: Bearer` header, constant-time comparison
- GeoLite2 download integrity verified via SHA256 checksum
- WebSocket status broadcasts strip raw syslog lines (data minimization)
- SQLite queries bounded with LIMIT; blocking DB calls wrapped in asyncio.to_thread
- GeoLite2 tar extraction path verified via realpath() before move
- Dependencies pinned with hashes in `requirements.lock`

## Requirements

- Python >= 3.10
- Fail2Ban installed and running
- Dedicated `banhammer` user with sudo access to fail2ban-client

## License

MIT
