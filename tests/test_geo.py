import pytest
from unittest.mock import patch, MagicMock
from banhammer.geo import GeoIPService


def test_lookup_returns_none_for_private_ip():
    geo = GeoIPService(db_path=None)
    result = geo.lookup("192.168.1.1")
    assert result is None


def test_lookup_returns_none_for_invalid_ip():
    geo = GeoIPService(db_path=None)
    result = geo.lookup("not-an-ip")
    assert result is None


def test_lookup_returns_geo_dict_keys():
    geo = GeoIPService(db_path=None)
    with patch.object(geo, "_lookup_api") as mock_api:
        mock_api.return_value = {
            "lat": 39.9, "lon": 116.4,
            "country_code": "CN", "country_name": "China", "city": "Beijing",
        }
        result = geo.lookup("8.8.8.8")
    assert result is not None
    assert set(result.keys()) == {"lat", "lon", "country_code", "country_name", "city"}


def test_lookup_caches_result():
    geo = GeoIPService(db_path=None)
    with patch.object(geo, "_lookup_api") as mock_api:
        mock_api.return_value = {
            "lat": 39.9, "lon": 116.4,
            "country_code": "CN", "country_name": "China", "city": "Beijing",
        }
        geo.lookup("8.8.8.8")
        geo.lookup("8.8.8.8")
    assert mock_api.call_count == 1


def test_lookup_returns_none_on_api_failure():
    geo = GeoIPService(db_path=None)
    with patch.object(geo, "_lookup_api", side_effect=Exception("timeout")):
        result = geo.lookup("8.8.8.8")
    assert result is None
