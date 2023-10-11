import pytest

from threatfox_censys import (
    Fingerprint,
    get_censys_search_link_for_fingerprint,
    get_censys_search_link_from_query,
    load_fingerprints_from_yaml,
)


@pytest.fixture
def fingerprint() -> Fingerprint:
    return Fingerprint(
        name="Test",
        censys_query="ip:1.1.1.1",
        malware_name="Test",
        confidence_level=50,
    )


def test_get_censys_search_link_for_fingerprint(fingerprint: Fingerprint):
    expected = (
        "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25"
        + "&virtual_hosts=EXCLUDE&q=ip%3A1.1.1.1&ref=threatfox"
    )
    assert get_censys_search_link_for_fingerprint(fingerprint) == expected


def test_get_censys_search_link_from_query():
    expected = (
        "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25"
        + "&virtual_hosts=EXCLUDE&q=ip%3A1.1.1.1&ref=threatfox"
    )
    assert get_censys_search_link_from_query("ip:1.1.1.1", False) == expected


def test_load_fingerprints_from_yaml():
    fingerprints = load_fingerprints_from_yaml("tests/test_fingerprints.yaml")
    assert len(fingerprints) == 1
    assert fingerprints[0].name == "Test"
    assert fingerprints[0].censys_query == "ip:1.1.1.2"
    assert fingerprints[0].malware_name == "Test"
    assert fingerprints[0].confidence_level == 50
    assert fingerprints[0].tags == ["test"]
    assert fingerprints[0].censys_virtual_hosts is True
