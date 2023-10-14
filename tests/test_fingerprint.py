import pytest

from threatfox_censys.fingerprint import (
    Fingerprint,
    get_censys_search_link_for_fingerprint,
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


def test_load_fingerprints_from_yaml():
    fingerprints = load_fingerprints_from_yaml("tests/test_fingerprints.yaml")
    assert len(fingerprints) == 1
    assert fingerprints[0].name == "Test"
    assert fingerprints[0].censys_query == "ip:1.1.1.2"
    assert fingerprints[0].malware_name == "Test"
    assert fingerprints[0].confidence_level == 50
    assert fingerprints[0].tags == ["test"]
    assert fingerprints[0].censys_virtual_hosts is True


def test_load_fingerprints_from_yaml_invalid():
    with pytest.raises(ValueError):
        load_fingerprints_from_yaml("tests/test_fingerprints_invalid.yaml")
