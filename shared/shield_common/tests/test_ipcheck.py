import ipaddress

import pytest

from shield_common.ipcheck import TargetRejected, normalize_ip, parse_ip, validate_block_target


def test_public_ipv4_ok():
    assert validate_block_target("8.8.8.8") == ipaddress.ip_address("8.8.8.8")


def test_public_ipv6_ok():
    validate_block_target("2606:4700:4700::1111")


@pytest.mark.parametrize("bad", [
    "", "1.2.3", "999.1.1.1", "01.2.3.4", " 1.2.3.4", "fe80::1%eth0",
    "1.2.3.4; rm -rf /", "-d 1.2.3.4", "$(reboot)", "1.2.3.4\n", "localhost",
])
def test_garbage_rejected(bad):
    with pytest.raises(TargetRejected):
        validate_block_target(bad, lab_mode=True)


def test_non_string_rejected():
    with pytest.raises(TargetRejected):
        validate_block_target(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.56.103", "172.16.0.5", "2001:db8::1"])
def test_private_rejected_outside_lab_mode(ip):
    with pytest.raises(TargetRejected):
        validate_block_target(ip)


def test_private_allowed_in_lab_mode():
    assert str(validate_block_target("192.168.56.103", lab_mode=True)) == "192.168.56.103"


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "224.0.0.1", "0.0.0.0", "169.254.1.1", "255.255.255.255"])
def test_special_addresses_always_rejected(ip):
    for lab in (False, True):
        with pytest.raises(TargetRejected):
            validate_block_target(ip, lab_mode=lab)


def test_protected_exact_and_cidr():
    protected = ["192.168.56.1", "192.168.56.0/30", "2606:4700::/32"]
    with pytest.raises(TargetRejected):
        validate_block_target("192.168.56.1", protected, lab_mode=True)
    with pytest.raises(TargetRejected):
        validate_block_target("192.168.56.2", protected, lab_mode=True)
    with pytest.raises(TargetRejected):
        validate_block_target("2606:4700:4700::1111", protected)
    # outside the protected ranges is fine
    validate_block_target("192.168.56.103", protected, lab_mode=True)
    validate_block_target("8.8.8.8", protected)


def test_ipv4_mapped_ipv6_cannot_bypass_checks():
    with pytest.raises(TargetRejected):
        validate_block_target("::ffff:192.168.1.1")
    with pytest.raises(TargetRejected):
        validate_block_target("::ffff:127.0.0.1", lab_mode=True)
    with pytest.raises(TargetRejected):
        validate_block_target("::ffff:8.8.8.8", ["8.8.8.8"])
    assert validate_block_target("::ffff:8.8.8.8") == ipaddress.ip_address("8.8.8.8")


def test_bad_protected_entry_is_a_config_error():
    with pytest.raises(ValueError) as exc:
        validate_block_target("8.8.8.8", ["not-a-network"])
    assert not isinstance(exc.value, TargetRejected)


def test_normalize_ip():
    assert normalize_ip("2001:db8:0:0:0:0:0:1") == "2001:db8::1"
    with pytest.raises(ValueError):
        parse_ip("fe80::1%eth0")
