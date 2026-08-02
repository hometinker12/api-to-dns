import pytest

from src.hostnames import validate_dns_hostname


@pytest.mark.parametrize(
    "name",
    [
        "apitodns.local",
        "api.example.com",
        "localhost",
        "a",
        "xn--bcher-kva.example",
    ],
)
def test_validate_dns_hostname_accepts(name: str) -> None:
    assert validate_dns_hostname(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        " ",
        "bad name",
        "evil.com/path",
        "evil.com\\path",
        "../etc/passwd",
        "name;rm",
        "a" * 64 + ".com",
        "-leading.example",
        "trailing-.example",
    ],
)
def test_validate_dns_hostname_rejects(name: str) -> None:
    with pytest.raises(ValueError):
        validate_dns_hostname(name)
