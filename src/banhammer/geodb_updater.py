import logging
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

import httpx

logger = logging.getLogger("banhammer")

MAXMIND_URL = "https://download.maxmind.com/app/geoip_download"
EDITION = "GeoLite2-City"


def db_age_days(db_path: str) -> float | None:
    p = Path(db_path)
    if not p.exists():
        return None
    return (time.time() - p.stat().st_mtime) / 86400


def download_geodb(license_key: str, db_path: str) -> bool:
    try:
        logger.info("Downloading GeoLite2-City database...")
        dest_dir = os.path.dirname(db_path)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=dest_dir, suffix=".tar.gz")
        try:
            _MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MB hard cap
            _downloaded = 0
            # Close the raw fd first so we can reopen via path; avoids fd
            # leak if the httpx.stream context raises before fdopen.
            os.close(tmp_fd)
            with httpx.stream(
                "GET",
                MAXMIND_URL,
                params={
                    "edition_id": EDITION,
                    "license_key": license_key,
                    "suffix": "tar.gz",
                },
                timeout=60.0,
                follow_redirects=True,
            ) as resp:
                resp.raise_for_status()
                with open(tmp_path, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=65536):
                        _downloaded += len(chunk)
                        if _downloaded > _MAX_DOWNLOAD_BYTES:
                            raise ValueError(
                                f"GeoLite2 download exceeded {_MAX_DOWNLOAD_BYTES // (1024*1024)} MB limit"
                            )
                        f.write(chunk)

            with tarfile.open(tmp_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".mmdb"):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, path=dest_dir, filter="data")
                        extracted = os.path.join(dest_dir, member.name)

                        if os.path.exists(db_path):
                            shutil.copy2(db_path, db_path + ".bak")
                            os.chmod(db_path + ".bak", 0o600)

                        shutil.move(extracted, db_path)
                        os.chmod(db_path, 0o600)
                        break
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        logger.info("GeoLite2-City database updated: %s", db_path)
        return True

    except Exception as e:
        # Avoid logging the URL which contains the license key as a query parameter
        logger.warning("Failed to update GeoLite2 database: %s", type(e).__name__)
        return False


def check_and_update(db_path: str, license_key: str | None, max_age_days: int = 30):
    if not license_key:
        age = db_age_days(db_path)
        if age is not None and age > max_age_days:
            logger.warning(
                "GeoLite2 DB is %.0f days old. Configure maxmind_license_key for auto-update.", age
            )
        elif age is None:
            logger.info("No GeoLite2 DB at %s. Configure maxmind_license_key for auto-download.", db_path)
        return

    age = db_age_days(db_path)
    if age is not None and age <= max_age_days:
        logger.info("GeoLite2 DB is %.0f days old (max %d) — no update needed.", age, max_age_days)
        return

    download_geodb(license_key, db_path)
