import logging
from typing import Any

import requests

from .fingerprint import Fingerprint


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
    ) -> None:
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
        self, endpoint: str, method: str = "GET", data: Any | None = None
    ) -> dict:
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

        # Check for HTTP errors
        if not response.ok:
            # Log the error
            logging.error(
                f"Error sending request to {url}. Status code: {response.status_code}."
            )
            # Log the data if it exists
            if data:
                logging.error(f"Data: {data}")
            raise requests.HTTPError(response=response)

        return response.json()

    def get_recent_iocs(self, days: int = 3) -> dict:
        """
        Get recent IOCs on ThreatFox.

        :param days: Number of days to look back.
        :return: Response from the server.
        """
        data = {"query": "get_iocs", "days": days}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def get_ioc_by_id(self, ioc_id: str) -> dict:
        """
        Get an IOC by its ID.

        :param ioc_id: ID of the IOC.
        :return: Response from the server.
        """
        data = {"query": "ioc", "id": ioc_id}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def search_iocs(self, search_term: str) -> dict:
        """
        Search for an IOC on ThreatFox.

        :param search_term: The IOC you want to search for.
        :return: Response from the server.
        """
        data = {"query": "search_ioc", "search_term": search_term}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def search_iocs_by_file_hash(self, file_hash: str) -> dict:
        """
        Search for an IOC on ThreatFox.

        :param file_hash: The file hash you want to search for.
        :return: Response from the server.
        """
        data = {"query": "search_hash", "hash": file_hash}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def search_iocs_by_tag(self, tag: str, limit: int = 100) -> dict:
        """
        Search for an IOC on ThreatFox.

        :param tag: The tag you want to search for.
        :param limit: The maximum number of results to return.
        :return: Response from the server.
        """
        data = {"query": "taginfo", "tag": tag, "limit": limit}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def search_iocs_by_malware(self, malware: str, limit: int = 100) -> dict:
        """
        Search for an IOC on ThreatFox.

        :param malware: The malware you want to search for.
        :param limit: The maximum number of results to return.
        :return: Response from the server.
        """
        data = {"query": "malwareinfo", "malware": malware, "limit": limit}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def submit_ioc(
        self,
        threat_type: str,
        ioc_type: str,
        malware: str,
        iocs: list[str],
        confidence_level: int = 50,
        reference: str | None = None,
        comment: str | None = None,
        anonymous: bool = False,
        tags: list[str] | None = None,
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

    def get_malware_label(self, malware: str, platform: str | None = None):
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

    def get_malware_list(self):
        """
        Get the list of malware names on ThreatFox.

        :return: Response from the server.
        """
        data = {"query": "malware_list"}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def get_threat_types(self):
        """
        Get the list of threat types on ThreatFox.

        :return: Response from the server.
        """
        data = {"query": "threat_types"}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def get_tag_list(self):
        """
        Get the list of tags on ThreatFox.

        :return: Response from the server.
        """
        data = {"query": "tag_list"}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response


def log_threatfox_response_data(
    fingerprint: Fingerprint, threatfox_response_data: dict | None
) -> None:
    """
    Log the ThreatFox response data.

    :param fingerprint: The fingerprint.
    :param threatfox_response_data: The ThreatFox response data.
    """
    # If the response data is None, return
    if threatfox_response_data is None:
        return

    # Get the reward
    reward = int(threatfox_response_data.get("reward", 0))

    # Get the number of IoCs
    num_iocs = len(threatfox_response_data.get("ok", []))

    # Get the number of ignored IoCs
    num_ignored_iocs = len(threatfox_response_data.get("ignored", []))

    # Get the number of duplicated IoCs
    num_duplicated_iocs = len(threatfox_response_data.get("duplicated", []))

    # Create the reward string
    reward_str = f"Reward: {reward}" if reward > 0 else "No reward"

    # Log the response
    logging.info(
        f"Submitted fingerprint {fingerprint.name} to ThreatFox. {reward_str}."
    )
    logging.debug(
        f"IoCs: {num_iocs} | Ignored: {num_ignored_iocs} | Duplicated:"
        f" {num_duplicated_iocs}"
    )
