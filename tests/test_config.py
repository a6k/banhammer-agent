import textwrap

from banhammer.config import load_config


def test_load_config_from_file(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        url = "https://api.example.com/events"
        api_key = "bh_testkey123"

        [agent]
        server_id = "test-server"
        poll_interval = 30

        [fail2ban]
        log_path = "/var/log/fail2ban.log"
        client_path = "/usr/bin/fail2ban-client"

        [storage]
        queue_db = "/tmp/test-queue.db"
    """))
    config = load_config(str(config_file))
    assert config["backend"]["url"] == "https://api.example.com/events"
    assert config["backend"]["api_key"] == "bh_testkey123"
    assert config["agent"]["server_id"] == "test-server"
    assert config["agent"]["poll_interval"] == 30


def test_load_config_defaults(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        url = "https://api.example.com/events"
        api_key = "bh_testkey123"
    """))
    config = load_config(str(config_file))
    assert config["agent"]["poll_interval"] == 60
    assert config["agent"]["heartbeat_interval"] == 300
    assert config["agent"]["batch_size"] == 50
    assert config["agent"]["retry_max"] == 5
    assert config["agent"]["retry_backoff"] == 2
    assert config["fail2ban"]["log_path"] == "/var/log/fail2ban.log"
    assert config["fail2ban"]["client_path"] == "/usr/bin/fail2ban-client"
    assert config["storage"]["queue_max_events"] == 10000


def test_load_config_env_var_overrides_api_key(tmp_path, monkeypatch):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        url = "https://api.example.com/events"
        api_key = "bh_from_file"
    """))
    monkeypatch.setenv("BANHAMMER_API_KEY", "bh_from_env")
    config = load_config(str(config_file))
    assert config["backend"]["api_key"] == "bh_from_env"


def test_load_config_server_id_defaults_to_hostname(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        url = "https://api.example.com/events"
        api_key = "bh_testkey123"
    """))
    config = load_config(str(config_file))
    import socket
    assert config["agent"]["server_id"] == socket.gethostname()


def test_load_config_missing_url_raises(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        api_key = "bh_testkey123"
    """))
    import pytest
    with pytest.raises(ValueError, match="backend.url"):
        load_config(str(config_file))


def test_load_config_missing_api_key_raises(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        url = "https://api.example.com/events"
    """))
    import pytest
    with pytest.raises(ValueError, match="api_key"):
        load_config(str(config_file))
