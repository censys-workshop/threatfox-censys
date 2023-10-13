from ipaddress import IPv4Address
from urllib.parse import quote_plus


def is_ipv4_address(ip_address: str) -> bool:
    """
    Check if a string is an IPv4 address.

    :param ip_address: The string to check.
    :return: True if the string is an IPv4 address, False otherwise.
    """
    try:
        IPv4Address(ip_address)
        return True
    except ValueError:
        return False


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
