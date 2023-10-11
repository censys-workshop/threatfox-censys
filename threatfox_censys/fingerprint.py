from urllib.parse import quote_plus

import yaml
from pydantic import BaseModel, ValidationError


class Fingerprint(BaseModel):
    name: str
    censys_query: str
    censys_virtual_hosts: bool = False
    threat_type: str = "botnet_cc"
    malware_name: str
    confidence_level: int = 50
    tags: list[str] | None = None


def get_censys_search_link_from_query(query: str, virtual_hosts: bool = False) -> str:
    """
    Get the Censys search URL from a fingerprint.

    :param fingerprint: The fingerprint to get the Censys search URL from.
    :return: The Censys search URL.
    """
    return (
        "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25"
        + "&virtual_hosts="
        + ("INCLUDE" if virtual_hosts else "EXCLUDE")
        + "&q="
        + quote_plus(query)
        + "&ref=threatfox"
    )


def get_censys_search_link_for_fingerprint(fingerprint: Fingerprint) -> str:
    """
    Get the Censys search URL from a fingerprint.

    :param fingerprint: The fingerprint to get the Censys search URL from.
    :return: The Censys search URL.
    """
    return get_censys_search_link_from_query(
        fingerprint.censys_query, fingerprint.censys_virtual_hosts
    )


def load_fingerprints_from_yaml(file_path: str) -> list[Fingerprint]:
    raw_data = []
    with open(file_path) as file:
        for item in yaml.safe_load_all(file):
            if item is not None:
                raw_data.append(item)

    if not isinstance(raw_data, list):
        raise ValueError("Expected a list of fingerprints in the YAML file.")

    fingerprints = []
    for item in raw_data:
        try:
            fingerprint = Fingerprint(**item)
            fingerprints.append(fingerprint)
        except ValidationError as e:
            print(f"Error parsing item: {item}. Error: {e}")

    return fingerprints
