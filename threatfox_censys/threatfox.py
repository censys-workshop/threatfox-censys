from typing import Any, Optional

import requests


class ThreatFoxClient:
    """
    Client for the ThreatFox API.

    Documentation: https://threatfox.abuse.ch/api/

    Example usage:
    >>> from threatfox_censys.threatfox.api import ThreatFoxClient
    >>> client = ThreatFoxClient(api_key="YOUR_API_KEY")
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://threatfox-api.abuse.ch/api/v1/",
        timeout: int = 30,
    ):
        """
        Initialize the ThreatFoxClient with the given parameters.

        :param api_key: API key for threatfox.
        :param base_url: Base URL for the API (default is their v1 endpoint).
        :param timeout: Timeout for requests (in seconds).
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")  # Remove trailing slash if it exists
        self.timeout = timeout
        self.headers = {"API-KEY": self.api_key, "Accept": "application/json"}

    def _send_request(
        self, endpoint: str, method: str = "GET", data: Optional[Any] = None
    ):
        """
        Internal method to send requests to the API.

        :param endpoint: Endpoint for the API call.
        :param method: HTTP method (GET or POST).
        :param data: Dictionary with data to send (only for POST requests).
        :return: Response from the server.
        """
        url = f"{self.base_url}/{endpoint}"
        if method == "GET":
            if data:
                raise ValueError("GET requests cannot have a data parameter")
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
        elif method == "POST":
            response = requests.post(
                url, headers=self.headers, json=data, timeout=self.timeout
            )
        else:
            raise ValueError("Unsupported HTTP method")

        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()

    def submit_ioc(
        self,
        threat_type: str,
        ioc_type: str,
        malware: str,
        iocs: list[str],
        confidence_level: int = 50,
        reference: Optional[str] = None,
        comment: Optional[str] = None,
        anonymous: bool = False,
        tags: Optional[list[str]] = None,
    ):
        data = {
            "query": "submit_ioc",
            "threat_type": threat_type,
            "ioc_type": ioc_type,
            "malware": malware,
            "confidence_level": confidence_level,
            "iocs": iocs,
            "anonymous": 0 if not anonymous else 1,
        }

        # Add optional fields to the data dictionary if provided
        if reference:
            data["reference"] = reference
        if comment:
            data["comment"] = comment
        if tags:
            data["tags"] = tags

        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def search_ioc(self, search_term: str):
        """
        Search for an IOC on ThreatFox.

        :param search_term: The IOC you want to search for.
        :return: Response from the server.
        """
        data = {"query": "search_ioc", "search_term": search_term}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def get_label(self, malware: str, platform: Optional[str] = None):
        """
        Identify the malware name (label) on ThreatFox.

        :param malware: Malware you want to look for.
        :param platform: Platform (optional; can be win, osx, apk, jar, or elf).
        :return: Response from the server.
        """
        data = {"query": "get_label", "malware": malware}
        if platform:
            data["platform"] = platform

        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    # Add your method examples here...
