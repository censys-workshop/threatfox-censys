import logging
from datetime import datetime
from enum import Enum, auto
from typing import Any

import backoff
import requests
from requests.utils import default_user_agent

from .fingerprint import Fingerprint

# import csv

# Global variables
total_submitted = 0
total_reward = 0


def fatal_code(e: requests.exceptions.RequestException) -> bool:
    assert isinstance(e, requests.exceptions.RequestException)
    assert e.response is not None
    assert isinstance(e.response, requests.Response)
    assert e.response.status_code is not None
    assert isinstance(e.response.status_code, int)
    return 400 <= e.response.status_code < 500


class ThreatFoxClient:
    """
    Client for the ThreatFox API.

    Documentation: https://threatfox.abuse.ch/api/

    Example usage:
    >>> from threatfox_censys.threatfox.api import ThreatFoxClient
    >>> client = ThreatFoxClient(api_key="YOUR_API_KEY")
    """

    api_key: str
    base_url: str
    timeout: int

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
        self.headers = {
            "API-KEY": self.api_key,
            "Accept": "application/json",
            "User-Agent": (
                f"{default_user_agent()} (ThreatfoxCensys;"
                " +https://github.com/censys-workshop/threatfox-censys)"
            ),
        }

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.RequestException,
        max_time=60,
        giveup=fatal_code,  # type: ignore[arg-type]
    )
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
            response = requests.get(
                url, headers=self.headers, timeout=self.timeout
            )  # pragma: no cover
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


class ThreatFoxExportFormat(Enum):
    """
    Enum for the ThreatFox export formats.
    """

    CSV = auto()
    JSON = auto()


class ThreatFoxExportClient:
    """
    Client for the ThreatFox export API.

    Documentation: https://threatfox.abuse.ch/export/
    """

    base_url: str
    timeout: int

    def __init__(
        self,
        base_url: str = "https://threatfox.abuse.ch/export/",
        timeout: int = 30,
    ) -> None:
        """
        Initialize the ThreatFoxExportClient with the given parameters.

        :param base_url: Base URL for the API (default is their v1 endpoint).
        :param timeout: Timeout for requests (in seconds).
        """
        self.base_url = base_url.rstrip("/")  # Remove trailing slash if it exists
        self.timeout = timeout
        self.headers = {
            "User-Agent": (
                f"{default_user_agent()} (ThreatfoxCensys;"
                " +https://github.com/censys-workshop/threatfox-censys)"
            ),
        }

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.RequestException,
        max_time=60,
        giveup=fatal_code,  # type: ignore[arg-type]
    )
    def _send_request(
        self,
        export_name: str | None = None,
        full: bool = False,
        format: ThreatFoxExportFormat = ThreatFoxExportFormat.JSON,
        write_to_file: bool = False,
    ) -> dict:
        """
        Internal method to send requests to the API.

        :param export_name: Name of the export.
        :param full: Whether to get the full export or the recent export.
        :param format: Format of the response (CSV or JSON).
        :param write_to_file: Whether to write the response to a file.
        :return: Response from the server.
        """
        format_path = "json" if format == ThreatFoxExportFormat.JSON else "csv"
        full_path = "full" if full else "recent"
        url_components = [self.base_url, format_path]
        if export_name:
            url_components.append(export_name)
        url_components.append(full_path)
        url = "/".join(url_components)
        response = requests.get(url, headers=self.headers, timeout=self.timeout)

        # Check for HTTP errors
        if not response.ok:
            # Log the error
            logging.error(
                f"Error sending request to {url}. Status code: {response.status_code}."
            )
            raise requests.HTTPError(response=response)

        # Write the response to a file if requested
        file_prefix = "threatfox_export"
        if export_name:
            file_prefix += f"_{export_name}"
        file_prefix += f"_{full_path}"
        file_prefix += f"_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        if format == ThreatFoxExportFormat.JSON:
            res = response.json()
            if write_to_file:
                with open(f"{file_prefix}.json", "w") as f:
                    f.write(response.text)
            return res
        # if format == ThreatFoxExportFormat.CSV:
        #     rows = response.text.splitlines()
        #     # The first couple rows start with a # and are comments
        #     # Except for the last comment which is the header
        #     # So we need to remove the first couple rows and add the header back
        #     # Get the comment rows
        #     comment_rows = []
        #     for row in rows:
        #         if row.startswith("#"):
        #             comment_rows.append(row)
        #         else:
        #             break
        #     # Remove the comment rows
        #     for comment_row in comment_rows:
        #         rows.remove(comment_row)
        #     # Add the header back
        #     rows.insert(0, comment_rows[-1].lstrip("# "))
        #     # Write the rows to a CSV file
        #     reader = csv.DictReader(
        #         rows,
        #         fieldnames=[
        #             "first_seen_utc",
        #             "ioc_id",
        #             "ioc_value",
        #             "ioc_type",
        #             "threat_type",
        #             "fk_malware",
        #             "malware_alias",
        #             "malware_printable",
        #             "last_seen_utc",
        #             "confidence_level",
        #             "reference",
        #             "tags",
        #             "anonymous",
        #             "reporter",
        #         ],
        #         delimiter=",",
        #     )
        #     writer = csv.DictWriter(
        #         open(f"{file_prefix}.csv", "w"), fieldnames=reader.fieldnames
        #     )
        #     writer.writeheader()
        #     writer.writerows(list(reader))
        #     return reader.__dict__
        raise ValueError("Unsupported format")


def log_threatfox_response_data(
    fingerprint: Fingerprint, ioc: str, threatfox_response_data: dict
) -> None:  # pragma: no cover
    """
    Log the ThreatFox response data.

    :param fingerprint: The fingerprint.
    :param ioc: The IoC.
    :param threatfox_response_data: The ThreatFox response data.
    """
    # Get global variables
    global total_reward
    global total_submitted

    # Get the reward
    reward = int(threatfox_response_data.get("reward", 0))

    # Update the global variables
    total_reward += reward
    total_submitted += 1

    # Get the number of IoCs
    num_iocs = len(threatfox_response_data.get("ok", []))

    # Get the number of ignored IoCs
    num_ignored_iocs = len(threatfox_response_data.get("ignored", []))

    # Get the number of duplicated IoCs
    num_duplicated_iocs = len(threatfox_response_data.get("duplicated", []))

    # Create the reward string
    reward_str = f"Reward: {reward}" if reward > 0 else "No reward - already submitted"

    # Log the response
    logging.info(
        f"Submitted {fingerprint.name} IoC '{ioc}' to ThreatFox. {reward_str}."
    )
    logging.debug(
        f"IoCs: {num_iocs} | Ignored: {num_ignored_iocs} | Duplicated:"
        f" {num_duplicated_iocs}"
    )


def log_summary(logger: logging.Logger | None = None) -> None:  # pragma: no cover
    """
    Log the summary of the ThreatFox submissions.
    """
    global total_reward
    global total_submitted

    if not logger:
        logger = logging.getLogger()
    logger.info(f"Summary: {total_submitted} submissions | {total_reward} reward")
