from unittest.mock import patch, MagicMock

from banhammer.sender import Sender


def _make_sender(**kwargs):
    defaults = {
        "url": "https://api.example.com/events",
        "api_key": "bh_test",
        "batch_size": 10,
        "retry_max": 3,
        "retry_backoff": 2,
        "ca_bundle": None,
    }
    defaults.update(kwargs)
    return Sender(**defaults)


@patch("banhammer.sender.requests.post")
def test_send_batch_success(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    sender = _make_sender()
    events = [
        (1, {"type": "ban", "ip": "1.2.3.4"}),
        (2, {"type": "ban", "ip": "5.6.7.8"}),
    ]
    sent_ids = sender.send_batch(events)
    assert sent_ids == [1, 2]
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert call_kwargs[1]["headers"]["Authorization"] == "Bearer bh_test"


@patch("banhammer.sender.requests.post")
def test_send_batch_failure_returns_empty(mock_post):
    mock_post.side_effect = Exception("Connection refused")
    sender = _make_sender(retry_max=1)
    events = [(1, {"type": "ban", "ip": "1.2.3.4"})]
    sent_ids = sender.send_batch(events)
    assert sent_ids == []


@patch("banhammer.sender.requests.post")
def test_send_batch_sets_content_type(mock_post):
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    sender = _make_sender()
    sender.send_batch([(1, {"type": "ban"})])
    call_kwargs = mock_post.call_args
    assert call_kwargs[1]["headers"]["Content-Type"] == "application/json"


@patch("banhammer.sender.requests.post")
def test_send_batch_uses_ca_bundle(mock_post):
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    sender = _make_sender(ca_bundle="/etc/ssl/custom-ca.pem")
    sender.send_batch([(1, {"type": "ban"})])
    call_kwargs = mock_post.call_args
    assert call_kwargs[1]["verify"] == "/etc/ssl/custom-ca.pem"
