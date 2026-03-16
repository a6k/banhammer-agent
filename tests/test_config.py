import textwrap

import pytest

from banhammer.config import load_config


def test_load_config_with_api_section(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [api]
        bind = "127.0.0.1"
        port = 8443
        api_key = "bh_testapikey1234567890abcdef1234"

        [agent]
        server_id = "test-server"
        poll_interval = 30

        [fail2ban]
        log_path = "/var/log/fail2ban.log"
        client_path = "/usr/bin/fail2ban-client"

        [storage]
        db_path = "/var/lib/banhammer/banhammer.db"
        retention_days = 90
    """))
    config = load_config(str(config_file))
    assert config["api"]["bind"] == "127.0.0.1"
    assert config["api"]["port"] == 8443
    assert config["api"]["api_key"] == "bh_testapikey1234567890abcdef1234"
    assert config["agent"]["server_id"] == "test-server"
    assert config["agent"]["poll_interval"] == 30


def test_load_config_defaults(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [api]
        api_key = "bh_testapikey1234567890abcdef1234"
    """))
    config = load_config(str(config_file))
    assert config["api"]["bind"] == "127.0.0.1"
    assert config["api"]["port"] == 8443
    assert config["agent"]["poll_interval"] == 60
    assert config["agent"]["heartbeat_interval"] == 300
    assert config["fail2ban"]["log_path"] == "/var/log/fail2ban.log"
    assert config["fail2ban"]["client_path"] == "/usr/bin/fail2ban-client"
    assert config["storage"]["db_path"] == "/var/lib/banhammer/banhammer.db"
    assert config["storage"]["retention_days"] == 90


def test_load_config_env_var_overrides_api_key(tmp_path, monkeypatch):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [api]
        api_key = "bh_from_file_1234567890abcdef1234"
    """))
    monkeypatch.setenv("BANHAMMER_API_KEY", "bh_from_env_1234567890abcdef1234")
    config = load_config(str(config_file))
    assert config["api"]["api_key"] == "bh_from_env_1234567890abcdef1234"


def test_load_config_server_id_defaults_to_hostname(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [api]
        api_key = "bh_testapikey1234567890abcdef1234"
    """))
    config = load_config(str(config_file))
    import socket
    assert config["agent"]["server_id"] == socket.gethostname()


def test_load_config_missing_api_key_raises(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [api]
        bind = "127.0.0.1"
    """))
    with pytest.raises(ValueError, match="api.api_key"):
        load_config(str(config_file))


def test_load_config_tls_required_when_bind_all(tmp_path):
    """If bind=0.0.0.0 and no TLS, config loading must raise."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [api]
        bind = "0.0.0.0"
        api_key = "bh_testapikey1234567890abcdef1234"
    """))
    with pytest.raises(ValueError, match="TLS is required"):
        load_config(str(config_file))


def test_load_config_tls_with_bind_all_ok(tmp_path):
    """If bind=0.0.0.0 with TLS cert+key, config loading succeeds."""
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent(f"""\
        [api]
        bind = "0.0.0.0"
        api_key = "bh_testapikey1234567890abcdef1234"
        tls_cert = "{cert}"
        tls_key = "{key}"
    """))
    config = load_config(str(config_file))
    assert config["api"]["bind"] == "0.0.0.0"
    assert config["api"]["tls_cert"] == str(cert)


def test_old_backend_section_ignored_with_warning(tmp_path, caplog):
    """Old [backend] section is ignored with a warning."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(textwrap.dedent("""\
        [backend]
        url = "https://old.example.com"
        api_key = "bh_old_key"

        [api]
        api_key = "bh_testapikey1234567890abcdef1234"
    """))
    import logging
    with caplog.at_level(logging.WARNING):
        config = load_config(str(config_file))
    assert "backend" in caplog.text.lower() or "ignored" in caplog.text.lower()
    assert config["api"]["api_key"] == "bh_testapikey1234567890abcdef1234"
