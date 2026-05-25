"""
Unit tests for ymap.utils — input validation & helpers.
Run with:  pytest tests/test_utils.py -v
"""

import pytest
from ymap.utils import (
    validate_target,
    validate_ports,
    validate_timing,
    expand_targets,
    timing_params,
)


class TestValidateTarget:
    def test_ipv4(self):
        assert validate_target("192.168.1.1") == "192.168.1.1"

    def test_cidr(self):
        assert validate_target("10.0.0.0/24") == "10.0.0.0/24"

    def test_hostname(self):
        assert validate_target("example.com") == "example.com"

    def test_range(self):
        assert validate_target("192.168.1.1-50") == "192.168.1.1-50"

    def test_rejects_shell_injection(self):
        with pytest.raises(ValueError):
            validate_target("192.168.1.1; rm -rf /")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_target("")


class TestValidatePorts:
    def test_single(self):
        assert validate_ports("80") == [80]

    def test_comma_list(self):
        assert validate_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert validate_ports("1-5") == [1, 2, 3, 4, 5]

    def test_all(self):
        result = validate_ports("-")
        assert result[0] == 1
        assert result[-1] == 65535
        assert len(result) == 65535

    def test_out_of_bounds(self):
        with pytest.raises(ValueError):
            validate_ports("0-100")

    def test_deduplication(self):
        assert validate_ports("80,80,443") == [80, 443]


class TestValidateTiming:
    def test_valid(self):
        for i in range(6):
            assert validate_timing(i) == i

    def test_too_high(self):
        with pytest.raises(ValueError):
            validate_timing(6)

    def test_negative(self):
        with pytest.raises(ValueError):
            validate_timing(-1)


class TestExpandTargets:
    def test_single_ip(self):
        assert expand_targets("10.0.0.1") == ["10.0.0.1"]

    def test_cidr_small(self):
        hosts = expand_targets("192.168.1.0/30")
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts
        assert len(hosts) == 2   # /30 has 2 usable hosts

    def test_range(self):
        hosts = expand_targets("10.0.0.1-3")
        assert hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


class TestTimingParams:
    def test_returns_tuple(self):
        timeout, delay = timing_params(4)
        assert isinstance(timeout, float)
        assert isinstance(delay, float)

    def test_paranoid_slow(self):
        timeout0, _ = timing_params(0)
        timeout5, _ = timing_params(5)
        assert timeout0 > timeout5
