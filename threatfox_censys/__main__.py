import logging
from argparse import ArgumentParser, Namespace
from ipaddress import IPv4Address

from censys.common.version import __version__ as censys_version
from censys.search import CensysHosts
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .fingerprint import (
    Fingerprint,
    get_censys_search_link_from_query,
    load_fingerprints_from_yaml,
)
from .models import IoC
from .settings import Settings
from .threatfox import ThreatFoxClient

USER_AGENT = (
    f"censys-python/{censys_version} (ThreatfoxCensys;"
    " +https://github.com/censys-workshop/threatfox-censys)"
)


def parse_args() -> Namespace:
    """
    Parse the arguments.

    :return: The parsed arguments.
    """
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
        "--database-migrations",
        "-m",
        action="store_true",
        help="Run database migrations.",
    )
    return parser.parse_args()


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


def submit_ioc(
    session: Session,
    threatfox_client: ThreatFoxClient,
    fingerprint: Fingerprint,
    ioc: str,
    ioc_type: str,
    additional_tags: list[str] | None = None,
) -> dict | None:
    """
    Submit an IoC to ThreatFox.

    :param session: The database session.
    :param threatfox_client: The ThreatFox client.
    :param fingerprint: The fingerprint.
    :param ioc: The IoC.
    :param ioc_type: The IoC type.
    :param additional_tags: Additional tags to add to the IoC.
    :return: The ThreatFox response data.
    """
    # Check if the IoC is already in the database
    ioc_in_database = (
        session.query(IoC)
        .filter(
            IoC.ioc == ioc,
            IoC.ioc_type == ioc_type,
            IoC.threat_type == fingerprint.threat_type,
        )
        .first()
        is not None
    )

    # If the IoC is already in the database, return None
    if ioc_in_database:
        logging.debug(f"IoC {ioc} already in database.")
        return None

    # Get fingerprint tags
    fingerprint_tags = []

    # If the fingerprint has tags, add them
    if fingerprint.tags:
        fingerprint_tags.extend(fingerprint.tags)

    # Get additional tags
    fingerprint_tags.extend(additional_tags or [])

    # Add the "censys" tag
    fingerprint_tags.append("censys")

    # Create the tag list
    tags = list(set(fingerprint_tags))

    # Log the tags
    logging.debug(f"Tags: {tags}")

    reference: str | None = None
    # If the IoC is an IP address, create the search link
    if ioc_type == "ip:port":
        # Get the IP address
        ip_address = ioc.split(":")[0]

        # Create the reference
        reference = f"https://search.censys.io/hosts/{ip_address}"
    # If the IoC is a domain, create the search link
    elif ioc_type == "domain":
        # Create the query
        censys_query = f"name: {ioc}"
        # Create the reference
        reference = get_censys_search_link_from_query(censys_query, True)

    # Log that we're submitting the IoC to ThreatFox
    logging.info(f"Submitting IoC {ioc} to ThreatFox...")

    # Submit the IoC to ThreatFox
    threatfox_response = threatfox_client.submit_ioc(
        threat_type=fingerprint.threat_type,
        ioc_type=ioc_type,
        malware=fingerprint.malware_name,
        iocs=[ioc],
        confidence_level=fingerprint.confidence_level,
        reference=reference,
        tags=tags,
    )
    # {
    #     "query_status": "ok",
    #     "data": {
    #         "ok": [],
    #         "ignored": [],
    #         "duplicated": [
    #             "1.1.1.1:2351",
    #         ],
    #         "reward": 0,
    #     },
    # }

    # Get the query status
    query_status = threatfox_response.get("query_status", "unknown")

    # If the query was successful, add the IoC to the database
    if query_status == "ok":
        # Create the IoC
        ioc_obj = IoC(
            ioc=ioc,
            ioc_type=ioc_type,
            threat_type=fingerprint.threat_type,
            submitted=True,
        )

        # Add the IoC to the database
        session.add(ioc_obj)

        # Commit the session
        session.commit()

        # Return the response
        return threatfox_response.get("data", {})

    # If the query was not successful, log the response
    logging.error(f"Error submitting IoC {ioc} to ThreatFox.")

    # Return None
    return None


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
    reward = threatfox_response_data.get("reward", 0)

    # Get the number of IoCs
    num_iocs = len(threatfox_response_data.get("ok", []))

    # Get the number of ignored IoCs
    num_ignored_iocs = len(threatfox_response_data.get("ignored", []))

    # Get the number of duplicated IoCs
    num_duplicated_iocs = len(threatfox_response_data.get("duplicated", []))

    # Log the response
    logging.info(
        f"Submitted fingerprint {fingerprint.name} to ThreatFox. Reward: {reward}."
    )
    logging.debug(
        f"IoCs: {num_iocs} | Ignored: {num_ignored_iocs} | Duplicated:"
        f" {num_duplicated_iocs}"
    )


def main():
    # Parse the arguments
    args = parse_args()

    # Load environment variables from .env file
    load_dotenv()

    # Load settings from environment variables
    settings = Settings()  # type: ignore[call-arg]

    # Set the log level
    logging.basicConfig(level=settings.LOGGING_LEVEL)

    # Create the database engine
    engine = create_engine(settings.DATABASE_URL.unicode_string())

    # Run database migrations
    if args.database_migrations:
        from .models import Base

        with Session(engine) as session:
            # Create the tables
            Base.metadata.create_all(bind=engine)

            # Commit the session
            session.commit()

        # Log that we're done
        logging.info("Database migrations complete.")

        # Exit
        return

    # Create a ThreatFoxClient instance
    threatfox_client = ThreatFoxClient(api_key=settings.THREATFOX_API_KEY)

    # Create a CensysHosts instance
    censys_client = CensysHosts(user_agent=USER_AGENT)

    # Load fingerprints from YAML file
    fingerprints = load_fingerprints_from_yaml(args.fingerprints)

    # For each fingerprint, search Censys and submit the results to ThreatFox
    for fingerprint in fingerprints:
        # Get the virtual hosts
        virtual_hosts = "INCLUDE" if fingerprint.censys_virtual_hosts else "EXCLUDE"

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

        # Create the session
        with Session(engine) as session:
            # Parse out the name
            for host in hosts:
                # Try to get the name
                name: str | None = host.get("name", None)

                # Get autonomous_system.name
                autonomous_system_name = host["autonomous_system"]["name"]

                # Build the tag list
                additional_tags = []

                # If the autonomous_system.name does not contain a space, add it
                if " " not in autonomous_system_name:
                    additional_tags.append(autonomous_system_name)

                # Loop over the matched services if there is no name
                if name is None:
                    ip = host["ip"]
                    if not is_ipv4_address(ip):
                        logging.warning(
                            f"IP {ip} is not a valid IPv4 address. Skipping..."
                        )
                        continue

                    for matched_service in host["matched_services"]:
                        # Get the ip:port combination
                        ip_port = f"{host['ip']}:{matched_service['port']}"

                        # Submit the ip:port combination
                        threatfox_response_data = submit_ioc(
                            session,
                            threatfox_client,
                            fingerprint,
                            ip_port,
                            "ip:port",
                            additional_tags=additional_tags,
                        )
                        log_threatfox_response_data(
                            fingerprint, threatfox_response_data
                        )
                else:
                    # Submit the name
                    threatfox_response_data = submit_ioc(
                        session,
                        threatfox_client,
                        fingerprint,
                        name,
                        "domain",
                        additional_tags=additional_tags,
                    )
                    log_threatfox_response_data(fingerprint, threatfox_response_data)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        pass
