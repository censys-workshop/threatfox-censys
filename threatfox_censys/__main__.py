import logging
from argparse import ArgumentParser, Namespace
from enum import Enum

import yaml
from censys.common.exceptions import CensysException
from censys.common.version import __version__ as censys_version
from censys.search import CensysHosts
from InquirerPy import prompt
from InquirerPy.validator import EmptyInputValidator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .fingerprint import (
    Fingerprint,
    get_censys_search_link_from_query,
    load_fingerprints_from_yaml,
)
from .models import Base, IoC
from .settings import settings
from .threatfox import ThreatFoxClient, log_summary, log_threatfox_response_data
from .utils import is_ipv4_address

# Constants
TIMEOUT = 45
USER_AGENT = (
    f"censys-python/{censys_version} (ThreatfoxCensys;"
    " +https://github.com/censys-workshop/threatfox-censys)"
)


# Create the database engine
engine = create_engine(settings.DATABASE_URL)

# Create a ThreatFoxClient instance
threatfox_client = ThreatFoxClient(api_key=settings.THREATFOX_API_KEY)

# Create a CensysHosts instance
censys_client = CensysHosts(
    api_id=settings.CENSYS_API_ID,
    api_secret=settings.CENSYS_API_SECRET,
    user_agent=USER_AGENT,
    timeout=TIMEOUT,
)


class IoCType(str, Enum):
    """
    IoC types.
    """

    IP_PORT = "ip:port"
    DOMAIN = "domain"
    URL = "url"  # Currently not supported by ThreatFox Censys


def migrate_database(_: Namespace) -> int:
    with Session(engine) as session:
        # Create the tables
        Base.metadata.create_all(bind=engine)

        # Commit the session
        try:
            session.commit()
        except Exception as e:
            logging.error(f"Error committing session: {e}")
            return 1

    # Log that we're done
    logging.info("Database migrations complete.")

    # Exit
    return 0


def submit_ioc(
    session: Session,
    threatfox_client: ThreatFoxClient,
    fingerprint: Fingerprint,
    ioc: str,
    ioc_type: IoCType,
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
    if ioc_type == IoCType.IP_PORT:
        # Get the IP address
        ip_address = ioc.split(":")[0]

        # Create the reference
        reference = f"https://search.censys.io/hosts/{ip_address}"
    # If the IoC is a domain, create the search link
    elif ioc_type == IoCType.DOMAIN:
        # Create the query
        censys_query = f"name: {ioc}"
        # Create the reference
        reference = get_censys_search_link_from_query(censys_query, True)

    # Log that we're submitting the IoC to ThreatFox
    logging.info(f"Submitting IoC {ioc} to ThreatFox...")

    # Submit the IoC to ThreatFox
    threatfox_response = threatfox_client.submit_ioc(
        threat_type=fingerprint.threat_type,
        ioc_type=ioc_type.value,
        malware=fingerprint.malware_name,
        iocs=[ioc],
        confidence_level=fingerprint.confidence_level,
        reference=reference,
        tags=tags,
    )

    # Get the query status
    query_status = threatfox_response.get("query_status", "unknown")

    # If the query was successful, add the IoC to the database
    if query_status == "ok":
        # Create the IoC
        ioc_obj = IoC(
            ioc=ioc,
            ioc_type=ioc_type.value,
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


def scan(args: Namespace) -> int:
    # Load fingerprints from YAML file
    fingerprints = load_fingerprints_from_yaml(args.fingerprints)

    # If the user wants to include tarpits, make them confirm
    if args.include_tarpits:
        # Create the questions
        questions = [
            {
                "type": "confirm",
                "message": (
                    "Are you sure you want to include tarpits? Please note that"
                    " tarpits will increase the number of false positives."
                ),
                "default": False,
                "mandatory": True,
            }
        ]

        # Prompt the user
        results = prompt(questions=questions)

        # If the user does not want to include tarpits, exit
        if not results[0]:
            return 0

    # For each fingerprint, search Censys and submit the results to ThreatFox
    for fingerprint in fingerprints:
        # Get the virtual hosts
        virtual_hosts = "INCLUDE" if fingerprint.censys_virtual_hosts else "EXCLUDE"

        # If we're not including tarpits, exclude them
        censys_query = fingerprint.censys_query
        if not args.include_tarpits:
            censys_query += " and not labels: tarpit"

        # Search Censys
        query_response = censys_client.search(
            censys_query, virtual_hosts=virtual_hosts, pages=-1
        )

        # Log that we're searching Censys
        logging.info(f"Searching Censys for fingerprint {fingerprint.name}...")

        # Gather the results
        hosts: list[dict] = []
        try:
            for page in query_response:
                for host in page:
                    hosts.append(host)
        except CensysException as e:
            logging.error(f"Error searching Censys: {e}")
            continue

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
                        logging.debug(
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
                            IoCType.IP_PORT,
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
                        IoCType.DOMAIN,
                        additional_tags=additional_tags,
                    )
                    log_threatfox_response_data(fingerprint, threatfox_response_data)

    # Log the summary
    log_summary()

    # Return 0
    return 0


def create_fingerprint(args: Namespace) -> int:
    # Get the malware list
    malware_list = threatfox_client.get_malware_list()
    malware_list_data: dict = malware_list.get("data", {})

    # Parse the malware list
    malware_names = []
    for malware_name, malware_data in malware_list_data.items():
        malware_printable = malware_data.get("malware_printable", None)
        if malware_printable is not None:
            malware_names.append(malware_printable)

        malware_alias = malware_data.get("malware_alias", None)
        if malware_alias is not None:
            malware_names.append(malware_alias)

        malware_names.append(malware_name)

    # Create a function to transform the malware name
    def transform_malware_name(result: str) -> str:
        # If the result is in the malware names, return it
        if result in malware_list_data:
            return result

        # If the result is not in the malware names, try to find it
        for malware_name, malware_data in malware_list_data.items():
            malware_printable = malware_data.get("malware_printable", None)
            if malware_printable is not None and malware_printable == result:
                return malware_name

            malware_alias = malware_data.get("malware_alias", None)
            if malware_alias is not None and malware_alias == result:
                return malware_name

        # If we can't find it, return the result
        return "unknown"

    # Create a function to validate the malware name is in the malware list
    def validate_malware_name(result: str) -> bool:
        if result == "unknown":
            return True
        return result in malware_names

    # Create the questions
    questions = [
        {
            "type": "input",
            "message": "Fingerprint Name:",
            "validate": EmptyInputValidator(),
            "mandatory": True,
        },
        {
            "type": "fuzzy",
            "message": "Malware Name:",
            "choices": malware_names,
            "filter": transform_malware_name,
            "validate": validate_malware_name,
            "transformer": lambda result: (
                result
                if result != "unknown" and result is not None
                else "Unknown malware"
            ),
            "mandatory": True,
        },
        {
            "type": "input",
            "message": "Censys Query:",
            "validate": EmptyInputValidator(),
            "mandatory": True,
        },
        {
            "type": "confirm",
            "message": "Include virtual hosts?",
            "default": False,
            "mandatory": False,
        },
        {
            "type": "number",
            "message": "Confidence Level:",
            "default": 50,
            "min_allowed": 0,
            "max_allowed": 100,
            "validate": EmptyInputValidator(),
            "mandatory": True,
        },
        {
            "type": "input",
            "message": "Tags:",
            "instruction": "Comma-separated list of tags.",
            "validate": EmptyInputValidator(),
            "mandatory": False,
            "default": "C2",
            "filter": lambda result: result.split(","),
        },
    ]

    # Prompt the user
    try:
        results = prompt(questions=questions)
    except KeyboardInterrupt:
        return 0

    # Get the name
    name: str = results[0]

    # Get the malware name
    malware_name: str = results[1]

    # Get the Censys query
    censys_query: str = results[2]

    # Get the virtual hosts
    censys_virtual_hosts: bool = results[3]

    # Get the confidence level
    confidence_level: int = results[4]

    # Get the tags
    tags: list[str] = results[5]

    # Create the fingerprint
    fingerprint = Fingerprint(
        name=name,
        malware_name=malware_name,
        censys_query=censys_query,
        censys_virtual_hosts=censys_virtual_hosts,
        confidence_level=confidence_level,
        tags=tags,
    )

    # Dump the fingerprint
    fingerprint_dict = fingerprint.model_dump(exclude=["threat_type"])

    # Print the fingerprint as YAML
    print("Add the following fingerprint to fingerprints.yaml:\n---")
    print(yaml.dump(fingerprint_dict, sort_keys=False, default_flow_style=None))

    # Return 0
    return 0


def parse_args() -> Namespace:
    """
    Parse the arguments.

    :return: The parsed arguments.
    """
    parser = ArgumentParser(
        prog="threatfox-censys",
        description="Submit IOCs from Censys to ThreatFox for rewards.",
    )

    def print_help(_: Namespace) -> None:
        parser.print_help()

    parser.add_argument(
        "--log-level",
        "-l",
        type=str,
        default="INFO",
        help="The logging level. (Default: INFO)",
    )
    parser.set_defaults(func=print_help)

    # Subparsers
    subparsers = parser.add_subparsers(
        help="The command to run.",
    )

    # Database migrations
    migrations_parser = subparsers.add_parser(
        "database-migrations",
        help="Run database migrations and exit.",
    )
    migrations_parser.set_defaults(func=migrate_database)

    # Scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan Censys and submit the results to ThreatFox.",
    )
    scan_parser.add_argument(
        "--fingerprints",
        "-f",
        type=str,
        default="fingerprints.yaml",
        help="The fingerprints YAML file to load. (Default: fingerprints.yaml)",
    )
    scan_parser.add_argument(
        "--include-tarpits",
        "-t",
        action="store_true",
        help=(
            "Include tarpits in the results. Please note that tarpits may increase"
            " the number of false positives. (Default: False)"
        ),
    )
    scan_parser.set_defaults(func=scan)

    # Create fingerprint
    create_fingerprint_parser = subparsers.add_parser(
        "create-fingerprint",
        help="Create a fingerprint.",
    )
    create_fingerprint_parser.set_defaults(func=create_fingerprint)

    # Parse the arguments
    return parser.parse_args()


def main():
    # Parse the arguments
    args = parse_args()

    # Set the log level
    logging.basicConfig(level=args.log_level)

    # Run the command
    try:
        code = args.func(args)
        exit(code)
    except KeyboardInterrupt:
        exit(0)


if __name__ == "__main__":
    main()
