from banhammer.log_tailer import parse_fail2ban_line, LogTailer


def test_parse_ban_line():
    line = "2026-03-15 06:09:12,345 fail2ban.actions        [12345]: NOTICE  [sshd] Ban 203.0.113.42"
    event = parse_fail2ban_line(line)
    assert event is not None
    assert event["type"] == "ban"
    assert event["jail"] == "sshd"
    assert event["ip"] == "203.0.113.42"
    assert event["timestamp"].year == 2026


def test_parse_unban_line():
    line = "2026-03-15 06:19:12,345 fail2ban.actions        [12345]: NOTICE  [sshd] Unban 203.0.113.42"
    event = parse_fail2ban_line(line)
    assert event is not None
    assert event["type"] == "unban"
    assert event["jail"] == "sshd"
    assert event["ip"] == "203.0.113.42"


def test_parse_irrelevant_line():
    line = "2026-03-15 06:09:12,345 fail2ban.filter          [12345]: INFO    [sshd] Found 203.0.113.42"
    event = parse_fail2ban_line(line)
    assert event is None


def test_parse_empty_line():
    assert parse_fail2ban_line("") is None
    assert parse_fail2ban_line("\n") is None


def test_log_tailer_reads_new_lines(tmp_path):
    log_file = tmp_path / "fail2ban.log"
    log_file.write_text("")
    tailer = LogTailer(str(log_file))
    with open(log_file, "a") as f:
        f.write("2026-03-15 06:09:12,345 fail2ban.actions        [12345]: NOTICE  [sshd] Ban 1.2.3.4\n")
    events = list(tailer.poll())
    assert len(events) == 1
    assert events[0]["type"] == "ban"


def test_log_tailer_handles_rotation(tmp_path):
    log_file = tmp_path / "fail2ban.log"
    log_file.write_text(
        "2026-03-15 06:00:00,000 fail2ban.actions        [1]: NOTICE  [sshd] Ban 1.1.1.1\n"
    )
    tailer = LogTailer(str(log_file))
    list(tailer.poll())  # consume existing

    # Simulate rotation: truncate file and write new content
    log_file.write_text("")
    with open(log_file, "a") as f:
        f.write("2026-03-15 07:00:00,000 fail2ban.actions        [1]: NOTICE  [sshd] Ban 2.2.2.2\n")
    events = list(tailer.poll())
    assert len(events) == 1
    assert events[0]["ip"] == "2.2.2.2"
