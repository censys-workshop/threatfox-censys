import pytest

from threatfox_censys.utils import get_censys_search_link_from_query, is_ipv4_address


def test_get_censys_search_link_from_query():
    expected = (
        "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25"
        + "&virtual_hosts=EXCLUDE&q=ip%3A1.1.1.1&ref=threatfox"
    )
    assert get_censys_search_link_from_query("ip:1.1.1.1", False) == expected


@pytest.mark.parametrize(
    "ip_address,expected",
    [
        ("1.1.1.1", True),
        ("2606:4700:4700::1111", False),
        ("google.com", False),
        ("test", False),
    ],
)
def test_is_ipv4_address(ip_address: str, expected: bool):
    assert is_ipv4_address(ip_address) == expected
