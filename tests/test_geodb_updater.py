import os
import time
from unittest.mock import patch
import pytest
from banhammer.geodb_updater import db_age_days, check_and_update


def test_db_age_returns_none_for_missing_file():
    assert db_age_days("/nonexistent/path.mmdb") is None


def test_db_age_returns_days(tmp_path):
    db = tmp_path / "test.mmdb"
    db.write_text("test")
    age = db_age_days(str(db))
    assert age is not None
    assert age < 1


def test_check_and_update_logs_without_license_key(tmp_path, caplog):
    db = tmp_path / "test.mmdb"
    with caplog.at_level("INFO"):
        check_and_update(str(db), license_key=None)
    assert "maxmind_license_key" in caplog.text


def test_check_and_update_skips_fresh_db(tmp_path):
    db = tmp_path / "test.mmdb"
    db.write_text("test")
    with patch("banhammer.geodb_updater.download_geodb") as mock:
        check_and_update(str(db), license_key="test_key", max_age_days=30)
    mock.assert_not_called()


def test_check_and_update_triggers_for_old_db(tmp_path):
    db = tmp_path / "test.mmdb"
    db.write_text("test")
    # Make file appear old
    old_time = time.time() - 40 * 86400
    os.utime(str(db), (old_time, old_time))
    with patch("banhammer.geodb_updater.download_geodb") as mock:
        check_and_update(str(db), license_key="test_key", max_age_days=30)
    mock.assert_called_once()
