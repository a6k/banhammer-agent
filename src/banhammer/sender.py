import json
import logging
import time

import requests

logger = logging.getLogger(__name__)


class Sender:
    def __init__(
        self,
        url: str,
        api_key: str,
        batch_size: int = 50,
        retry_max: int = 5,
        retry_backoff: int = 2,
        ca_bundle: str | None = None,
    ):
        self.url = url
        self.api_key = api_key
        self.batch_size = batch_size
        self.retry_max = retry_max
        self.retry_backoff = retry_backoff
        self.ca_bundle = ca_bundle

    def send_batch(self, events: list[tuple[int, dict]]) -> list[int]:
        if not events:
            return []

        payload = [event_data for _, event_data in events]
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        verify = self.ca_bundle if self.ca_bundle else True

        delay = 1.0
        for attempt in range(self.retry_max):
            try:
                response = requests.post(
                    self.url,
                    data=json.dumps(payload),
                    headers=headers,
                    verify=verify,
                    timeout=30,
                )
                response.raise_for_status()
                return [event_id for event_id, _ in events]
            except Exception:
                logger.warning(
                    "Send attempt %d/%d failed",
                    attempt + 1,
                    self.retry_max,
                    exc_info=True,
                )
                if attempt < self.retry_max - 1:
                    time.sleep(delay)
                    delay = min(delay * self.retry_backoff, 300)

        return []
