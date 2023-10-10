import logging
import os
from argparse import ArgumentParser

from censys.search import CensysHosts
from dotenv import load_dotenv

from .fingerprint import get_censys_search_link_from_query, load_fingerprints_from_yaml
from .threatfox import ThreatFoxClient


def parse_args():
    parser = ArgumentParser(
        description="Submit IOCs from Censys to ThreatFox for rewards."
    )
    parser.add_argument(
        "--fingerprints",
        "-f",
        type=str,
        default="fingerprints.yaml",
        help="The fingerprints YAML file to load.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print verbose output.",
    )
    return parser.parse_args()


def main():
    # Parse the arguments
    args = parse_args()

    # Set the log level
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Load environment variables from .env file
    load_dotenv()

    # Get the ThreatFox API key from the environment
    threatfox_api_key = os.getenv("THREATFOX_API_KEY")

    # Create a ThreatFoxClient instance
    threatfox_client = ThreatFoxClient(api_key=threatfox_api_key)

    # Create a CensysHosts instance
    censys_client = CensysHosts()

    # Load fingerprints from YAML file
    fingerprints = load_fingerprints_from_yaml("fingerprints.yaml")

    # Count the rewards
    rewards = 0

    # For each fingerprint, search Censys and submit the results to ThreatFox
    for fingerprint in fingerprints:
        # Get the virtual hosts
        virtual_hosts = "ONLY" if fingerprint.censys_virtual_hosts else "EXCLUDE"

        # Search Censys
        query_response = censys_client.search(
            fingerprint.censys_query, virtual_hosts=virtual_hosts, pages=-1
        )

        # Log that we're searching Censys
        logging.info(f"Searching Censys for fingerprint {fingerprint.name}...")

        # Gather the results
        hosts = []
        for page in query_response:
            for host in page:
                hosts.append(host)

        # Log the number of results
        logging.info(f"Found {len(hosts)} results.")

        iocs = []
        ioc_type: str
        if fingerprint.censys_virtual_hosts:
            ioc_type = "domain"
            # Parse out the name
            for host in hosts:
                iocs.append(host["name"])
        else:
            ioc_type = "ip:port"
            # Parse out the host:port combinations
            for host in hosts:
                for matched_service in host["matched_services"]:
                    iocs.append(f"{host['ip']}:{matched_service['port']}")

        # Create the tag list
        tags = list(set(["censys"] + fingerprint.tags if fingerprint.tags else []))

        # Create the reference
        reference = get_censys_search_link_from_query(fingerprint)

        # Log that we're submitting the IOCs to ThreatFox
        logging.info(
            f"Submitting IOCs to ThreatFox for fingerprint {fingerprint.name}..."
        )

        # Submit the IOCs to ThreatFox
        threatfox_response = threatfox_client.submit_ioc(
            threat_type="payload_delivery",
            ioc_type=ioc_type,
            malware=fingerprint.malware_name,
            iocs=iocs,
            confidence_level=fingerprint.confidence_level,
            reference=reference,
            comment=fingerprint.comment,
            tags=tags,
        )
        # {
        #     "query_status": "ok",
        #     "data": {
        #         "ok": [],
        #         "ignored": [],
        #         "duplicated": [
        #             "54.39.198.245:2351",
        #             "148.113.1.180:2351",
        #             "162.33.179.65:2351",
        #             "149.248.0.82:2351",
        #             "81.19.135.139:2351",
        #             "89.248.193.66:2351",
        #         ],
        #         "reward": 0,
        #     },
        # }

        # Get the data from the response
        threatfox_response_data = threatfox_response.get("data", {})

        # Add the reward to the total
        reward = threatfox_response_data.get("reward", 0)
        rewards += reward

        # Get the status of the query
        query_status = threatfox_response.get("query_status", "unknown")
        is_ok = query_status == "ok"

        # Log the response
        logging.info(f"Response for fingerprint {fingerprint.name}:")
        logging.info(f"    Query status: {threatfox_response['query_status']}")
        if is_ok:
            logging.info(f"    OK IOCs: {len(threatfox_response_data['ok'])}")
            logging.info(f"    Ignored IOCs: {len(threatfox_response_data['ignored'])}")
            logging.info(
                f"    Duplicated IOCs: {len(threatfox_response_data['duplicated'])}"
            )
            logging.info(f"    Reward: {reward}")

    # Print the total rewards
    logging.info(f"Total rewards: {rewards}")


if __name__ == "__main__":
    main()
