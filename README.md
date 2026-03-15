# BanHammer Agent

Lightweight server agent that monitors Fail2Ban/SSHGuard logs and sends ban events to the [BanHammer](https://github.com/a6k) iOS app backend.

## Quick Start

### Install

```bash
pip install banhammer-agent
```

### Configure

```bash
sudo banhammer-agent init
```

This creates `/etc/banhammer/config.toml`. You'll need your Backend URL and API key.

### Run

```bash
sudo banhammer-agent run
```

Or install as a systemd service:

```bash
sudo cp systemd/banhammer-agent.service /etc/systemd/system/
sudo systemctl enable --now banhammer-agent
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `banhammer-agent run` | Start the agent |
| `banhammer-agent init` | Create initial configuration |
| `banhammer-agent status` | Show queue size and connection info |
| `banhammer-agent test` | Send a test event to the backend |

Use `-c /path/to/config.toml` to specify a custom config location.

## Configuration

See [config.example.toml](config.example.toml) for all options.

Minimal config:

```toml
[backend]
url = "https://your-backend.example.com/events"
api_key = "bh_your_api_key"
```

The API key can also be set via the `BANHAMMER_API_KEY` environment variable.

## Requirements

- Python >= 3.10
- Fail2Ban installed and running
- Root access (for fail2ban-client and log access)

## License

MIT
