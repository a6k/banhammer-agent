import ipaddress
import logging
from typing import Optional

logger = logging.getLogger("banhammer")


class GeoIPService:
    """IP geolocation with GeoLite2 (primary) and ip-api.com (fallback)."""

    def __init__(self, db_path: str | None = None):
        self._reader = None
        if db_path:
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(db_path)
                logger.info("GeoLite2 database loaded: %s", db_path)
            except Exception as e:
                logger.warning("GeoLite2 database not available: %s", e)
        self._cache: dict[str, Optional[dict]] = {}
        self._max_cache = 10000

    def lookup(self, ip: str) -> dict | None:
        """Resolve IP to geo data. Returns None for private/invalid IPs or on failure."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        if addr.is_private or addr.is_reserved or addr.is_loopback:
            return None

        if ip in self._cache:
            return self._cache[ip]

        result = None

        if self._reader:
            try:
                result = self._lookup_geoip2(ip)
            except Exception:
                pass

        if result is None:
            try:
                result = self._lookup_api(ip)
            except Exception:
                pass

        # Evict oldest entries if cache is full
        if len(self._cache) >= self._max_cache:
            for key in list(self._cache.keys())[:1000]:
                del self._cache[key]
        self._cache[ip] = result
        return result

    def _lookup_geoip2(self, ip: str) -> dict | None:
        resp = self._reader.city(ip)
        if resp.location.latitude is None:
            return None
        return {
            "lat": resp.location.latitude,
            "lon": resp.location.longitude,
            "country_code": resp.country.iso_code,
            "country_name": resp.country.name,
            "city": resp.city.name,
        }

    def _lookup_api(self, ip: str) -> dict | None:
        """Fallback: ip-api.com (free tier, 45 req/min).
        Note: HTTP not HTTPS — free tier only supports HTTP."""
        import httpx
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,lat,lon,countryCode,country,city"},
            timeout=5.0,
        )
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "lat": data["lat"],
            "lon": data["lon"],
            "country_code": data["countryCode"],
            "country_name": data["country"],
            "city": data.get("city"),
        }

    def close(self):
        if self._reader:
            self._reader.close()
