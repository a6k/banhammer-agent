from banhammer.poller import parse_status_output, parse_jail_status_output


def test_parse_status_output():
    output = """Status
|- Number of jail:\t3
`- Jail list:\tsshd, postfix, dovecot"""
    jails = parse_status_output(output)
    assert jails == ["sshd", "postfix", "dovecot"]


def test_parse_status_output_single_jail():
    output = """Status
|- Number of jail:\t1
`- Jail list:\tsshd"""
    jails = parse_status_output(output)
    assert jails == ["sshd"]


def test_parse_jail_status_output():
    output = """Status for the jail: sshd
|- Filter
|  |- Currently failed:\t5
|  |- Total failed:\t234
|  `- File list:\t/var/log/auth.log
`- Actions
   |- Currently banned:\t3
   |- Total banned:\t127
   `- Banned IP list:\t1.2.3.4 5.6.7.8 9.10.11.12"""
    result = parse_jail_status_output(output)
    assert result["active_bans"] == 3
    assert result["total_bans"] == 127
    assert result["banned_ips"] == ["1.2.3.4", "5.6.7.8", "9.10.11.12"]


def test_parse_jail_status_output_no_bans():
    output = """Status for the jail: sshd
|- Filter
|  |- Currently failed:\t0
|  |- Total failed:\t10
|  `- File list:\t/var/log/auth.log
`- Actions
   |- Currently banned:\t0
   |- Total banned:\t0
   `- Banned IP list:\t"""
    result = parse_jail_status_output(output)
    assert result["active_bans"] == 0
    assert result["total_bans"] == 0
    assert result["banned_ips"] == []
