import logging

import yaml
from pydantic import BaseModel, ValidationError

from .utils import get_censys_search_link_from_query


class Fingerprint(BaseModel):
    name: str
    censys_query: str
    censys_virtual_hosts: bool = False
    threat_type: str = "botnet_cc"
    malware_name: str
    confidence_level: int = 50
    tags: list[str] | None = None


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
        try:
            for item in yaml.safe_load_all(file):
                if item is not None:
                    raw_data.append(item)
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML file: {e}") from e

    fingerprints = []
    for item in raw_data:
        try:
            fingerprint = Fingerprint(**item)
            fingerprints.append(fingerprint)
        except ValidationError as e:  # pragma: no cover
            item_name = item["name"] if "name" in item else "Unknown"
            logging.warning(
                f"Error parsing fingerprint {item_name} from YAML file: {e}"
            )

    return fingerprints
