#!/usr/bin/env python3
"""This is the main entrypoint for ThreatFox Censys."""
import logging
from argparse import ArgumentParser, Namespace
from datetime import datetime
from enum import Enum

import yaml
from censys.common.exceptions import CensysException
from censys.common.version import __version__ as censys_version
from censys.search import CensysHosts
from InquirerPy import prompt
from InquirerPy.validator import EmptyInputValidator
from mastodon import Mastodon
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .fingerprint import Fingerprint, load_fingerprints_from_yaml
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

# Create the scan logger
scan_logger = logging.getLogger("scan")

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

# If Mastodon is configured, create a Mastodon instance
mastodon_client = None
if settings.MASTODON_API_URL and settings.MASTODON_ACCESS_TOKEN:
    mastodon_client = Mastodon(
        api_base_url=settings.MASTODON_API_URL,
        access_token=settings.MASTODON_ACCESS_TOKEN,
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
    reference: str | None = None,
) -> dict | None:
    """
    Submit an IoC to ThreatFox.

    :param session: The database session.
    :param threatfox_client: The ThreatFox client.
    :param fingerprint: The fingerprint.
    :param ioc: The IoC.
    :param ioc_type: The IoC type.
    :param additional_tags: Additional tags to add to the IoC.
    :param reference: The reference to add to the IoC.
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
        scan_logger.debug(f"IoC {ioc} already in database.")
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
    # scan_logger.debug(f"Tags: {tags}")

    # Log that we're submitting the IoC to ThreatFox
    scan_logger.debug(f"Submitting {fingerprint.name} IoC {ioc} to ThreatFox...")

    # Submit the IoC to ThreatFox
    try:
        threatfox_response = threatfox_client.submit_ioc(
            threat_type=fingerprint.threat_type,
            ioc_type=ioc_type.value,
            malware=fingerprint.malware_name,
            iocs=[ioc],
            confidence_level=fingerprint.confidence_level,
            reference=reference,
            tags=tags,
        )
    except Exception as e:
        scan_logger.error(f"Error submitting IoC '{ioc}' to ThreatFox: {e}")
        return None

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

        # Get the data
        if data := threatfox_response.get("data", {}):
            # Log the response data
            log_threatfox_response_data(fingerprint, ioc, data)

            # Post to Mastodon
            if mastodon_client:
                tags_str = ", ".join(tags)
                hashtags = [fingerprint.name.replace(" ", "")]
                if "c2" in tags_str.lower():
                    hashtags.append("C2")
                if "stealer" in tags_str.lower():
                    hashtags.append("Stealer")
                if "rat" in tags_str.lower():
                    hashtags.append("RAT")
                hashtags_str = " ".join([f"#{tag}" for tag in hashtags])
                mastodon_client.toot(
                    f"New {fingerprint.name} IoC: {ioc}\n\n"
                    f"Reference: {reference}\n\n{hashtags_str}"
                )
            return data

    # If the query was not successful, log the response
    scan_logger.error(f"Error submitting IoC '{ioc}' to ThreatFox.")

    # Return None
    return None


def scan(args: Namespace) -> int:
    # Load fingerprints from YAML file
    fingerprints = load_fingerprints_from_yaml(args.fingerprints)

    # If the user specified tags, filter the fingerprints
    if args.tag:
        # Get the specified tags
        specified_tags: set[str] = set(args.tag)

        # If the user specified no tags, exit
        if len(specified_tags) == 0 or (
            len(specified_tags) == 1 and "" in specified_tags
        ):
            scan_logger.error("No tags specified.")
            return 1

        # Convert the tags to lowercase
        specified_tags = {tag.lower() for tag in specified_tags}

        # Filter the fingerprints
        fingerprints = [
            fingerprint
            for fingerprint in fingerprints
            if any(
                tag in [fp_tag.lower() for fp_tag in fingerprint.tags]  # type: ignore
                for tag in specified_tags
            )
        ]

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

    # If the user specified an excluded IOCs file, load it
    excluded_iocs: set[str] = set()
    if args.excluded_iocs:
        # Open the file
        with open(args.excluded_iocs) as f:
            # Read the file
            excluded_iocs_raw = f.read()

        # Split the file by newlines
        excluded_iocs = set(excluded_iocs_raw.split("\n"))

    # Print the current date
    scan_logger.info(f"Scan started at {datetime.now()}")

    # For each fingerprint, search Censys and submit the results to ThreatFox
    for fingerprint in fingerprints:
        # Get the virtual hosts
        virtual_hosts = "INCLUDE" if fingerprint.censys_virtual_hosts else "EXCLUDE"

        # Get the Censys query
        censys_query = fingerprint.censys_query

        # If we're not including tarpits, exclude them
        if not args.include_tarpits:
            censys_query += " and not labels: tarpit"

        # Search Censys
        query_response = censys_client.search(
            censys_query, virtual_hosts=virtual_hosts, pages=-1
        )

        # Log that we're searching Censys
        scan_logger.info(f"Searching Censys for fingerprint {fingerprint.name}...")

        # Gather the results
        hosts: list[dict] = []
        try:
            for page in query_response:
                for host in page:
                    hosts.append(host)
        except CensysException as e:
            scan_logger.error(f"Error searching Censys: {e}")
            continue

        # Log the number of results
        scan_logger.info(f"Found {len(hosts)} {fingerprint.name} results.")

        # Create the session
        with Session(engine) as session:
            # Parse out the name
            for host in hosts:
                # Get the ip
                ip = host["ip"]

                # Try to get the name
                name: str | None = host.get("name", None)

                # Build the tag list
                additional_tags = []

                # Get autonomous_system
                autonomous_system = host.get("autonomous_system", {})

                # Get autonomous_system name
                autonomous_system_name = autonomous_system.get("name")

                # If the autonomous_system.name does not contain a space, add it
                if autonomous_system_name and " " not in autonomous_system_name:
                    additional_tags.append(autonomous_system_name)

                # Get the autonomous system number
                autonomous_system_number = autonomous_system.get("asn")

                # If the asn is not None, add it
                if autonomous_system_number is not None:
                    additional_tags.append(f"AS{autonomous_system_number}")

                # Create the reference
                reference = f"https://search.censys.io/hosts/{ip}"

                # Loop over the matched services if there is no name
                if name is None:
                    if not is_ipv4_address(ip):
                        scan_logger.debug(
                            f"IP {ip} is not a valid IPv4 address. Skipping..."
                        )
                        continue

                    for matched_service in host["matched_services"]:
                        # Get the ip:port combination
                        ip_port = f"{ip}:{matched_service['port']}"

                        # If the ip:port combination is in the excluded IOCs, skip it
                        if ip_port in excluded_iocs:
                            scan_logger.debug(
                                f"IP:Port {ip_port} in excluded IOCs. Skipping..."
                            )
                            continue

                        # Submit the ip:port combination
                        if args.no_submit:
                            scan_logger.info(
                                f"Would submit {ip_port} to ThreatFox. Ref: {reference}"
                            )
                        else:
                            submit_ioc(
                                session,
                                threatfox_client,
                                fingerprint,
                                ip_port,
                                IoCType.IP_PORT,
                                additional_tags=additional_tags,
                                reference=reference,
                            )
                else:
                    # If the name is in the excluded IOCs, skip it
                    if name in excluded_iocs:
                        scan_logger.debug(f"Name {name} in excluded IOCs. Skipping...")
                        continue

                    # Update the reference
                    reference += f"+{name}"

                    # Submit the name
                    if args.no_submit:
                        scan_logger.info(
                            f"Would submit {name} to ThreatFox. Ref: {reference}"
                        )
                    else:
                        submit_ioc(
                            session,
                            threatfox_client,
                            fingerprint,
                            name,
                            IoCType.DOMAIN,
                            additional_tags=additional_tags,
                            reference=reference,
                        )

    # Log the summary or tell the user to rerun without --no-submit
    if args.no_submit:
        scan_logger.info(
            "Rerun without --no-submit to submit the results to ThreatFox."
        )
    else:
        log_summary(scan_logger)

    # Return 0
    return 0


def create_fingerprint(_: Namespace) -> int:
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

    # Create a function to get the default tags
    def get_default_tags(result: dict) -> str:
        name = result["name"].lower()
        malware_name = result["malware_name"].lower()
        if "rat" in name or "rat" in malware_name:
            return "C2,RAT"
        if "stealer" in name or "stealer" in malware_name:
            return "C2,Stealer"
        return "C2"

    # Create the questions
    questions = [
        {
            "name": "name",
            "type": "input",
            "message": "Fingerprint Name:",
            "validate": EmptyInputValidator(),
            "mandatory": True,
        },
        {
            "name": "malware_name",
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
            "default": lambda result: result["name"],
            "mandatory": True,
        },
        {
            "name": "censys_query",
            "type": "input",
            "message": "Censys Query:",
            "validate": EmptyInputValidator(),
            "mandatory": True,
        },
        {
            "name": "censys_virtual_hosts",
            "type": "confirm",
            "message": "Include virtual hosts?",
            # Make the default True if "http" is in the query
            "default": lambda result: "http" in result["censys_query"],
            "mandatory": False,
        },
        {
            "name": "confidence_level",
            "type": "number",
            "message": "Confidence Level:",
            "default": 100,
            "min_allowed": 0,
            "max_allowed": 100,
            "validate": EmptyInputValidator(),
            "mandatory": True,
        },
        {
            "name": "tags",
            "type": "input",
            "message": "Tags:",
            "instruction": "Comma-separated list of tags.",
            "validate": EmptyInputValidator(),
            "mandatory": False,
            # Make the default "C2,RAT" if "RAT" is in the malware name
            "default": get_default_tags,
            "filter": lambda result: result.split(","),
        },
    ]

    # Prompt the user
    try:
        results = prompt(questions=questions)
    except KeyboardInterrupt:
        return 0

    # Get the name
    name: str = results["name"]  # type: ignore[assignment]

    # Get the malware name
    malware_name: str = results["malware_name"]  # type: ignore[assignment,no-redef]

    # Get the Censys query
    censys_query: str = results["censys_query"]  # type: ignore[assignment]

    # Get the virtual hosts
    censys_virtual_hosts: bool = results["censys_virtual_hosts"]  # type: ignore

    # Get the confidence level
    confidence_level: int = results["confidence_level"]  # type: ignore[assignment]

    # Get the tags
    tags: list[str] = results["tags"]  # type: ignore[assignment]

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
    fingerprint_dict = fingerprint.model_dump(exclude={"threat_type"})

    # Create the YAML
    fingerprint_yaml = yaml.dump(
        fingerprint_dict, sort_keys=False, default_flow_style=None
    )
    fingerprint_yaml = f"---\n{fingerprint_yaml}"

    # Print the fingerprint as YAML
    print("Add the following fingerprint to fingerprints.yaml:")
    print(fingerprint_yaml)

    # Return 0
    return 0


def check_ioc_from_query(
    args: Namespace,
) -> int:
    # Get the query
    query: str = args.QUERY  # type: ignore[assignment]

    # Get the virtual hosts
    virtual_hosts: bool = args.virtual_hosts  # type: ignore[assignment]

    # Set th virtual hosts value
    censys_virtual_hosts = "INCLUDE" if virtual_hosts else "EXCLUDE"

    # Search Censys
    query_response = censys_client.search(
        query, virtual_hosts=censys_virtual_hosts, pages=-1
    )

    # Log that we're searching Censys
    logging.info(f"Searching Censys for query {query}...")

    # Gather the results
    hosts: list[dict] = []
    try:
        for page in query_response:
            for host in page:
                hosts.append(host)
    except CensysException as e:
        logging.error(f"Error searching Censys: {e}")
        return 1

    # Get the number of results
    num_results = len(hosts)

    # Log the number of results
    logging.info(f"Found {num_results} results.")

    # Keep track of the number of results with IOCs
    num_results_with_iocs = 0

    # All related IoCs
    all_iocs: list[dict] = []

    # Check each host against ThreatFox
    for host in hosts:
        ip = host["ip"]
        name = host.get("name", None)

        # Set boolean to track if we found an IoC
        found_ioc = False

        # Check the IP
        threatfox_response = threatfox_client.search_iocs(ip)

        # Get the query status
        query_status = threatfox_response.get("query_status", "unknown")

        # If the query was successful, print the results
        if (
            query_status == "ok"
            and (data := threatfox_response.get("data", {}))
            and (len(data) > 0)
        ):
            # Set the found IoC boolean
            found_ioc = True

            # Log the response data
            logging.debug(
                f"IP: {ip} (IoCs: {len(data)}) -"
                f" https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}"
            )

            # Add the IoCs to the list
            all_iocs.extend(data)

        # Check the name
        if name is not None:
            threatfox_response = threatfox_client.search_iocs(name)

            # Get the query status
            query_status = threatfox_response.get("query_status", "unknown")

            # If the query was successful, print the results
            if (
                query_status == "ok"
                and (data := threatfox_response.get("data", {}))
                and (len(data) > 0)
            ):
                # Set the found IoC boolean
                found_ioc = True

                # Log the response data
                logging.debug(
                    f"Name: {name} (IoCs: {len(data)}) -"
                    f" https://threatfox.abuse.ch/browse.php?search=ioc%3A{name}"
                )

                # Add the IoCs to the list
                all_iocs.extend(data)

        # If we found an IoC, increment the number of results with IoCs
        if found_ioc:
            num_results_with_iocs += 1

    # Print the number of results with IoCs
    logging.info(f"Summary {num_results_with_iocs}/{num_results} results with IoCs.")

    # If there are no results with IoCs, exit
    if num_results_with_iocs == 0:
        return 0

    # Group the IoCs by malware name
    iocs_by_malware_name: dict[str, list[dict]] = {}
    for ioc in all_iocs:
        # Get the malware name
        malware_name = ioc.get("malware", "unknown")

        # Add the IoC to the list
        iocs_by_malware_name.setdefault(malware_name, []).append(ioc)

    # Sort the IoCs by number of IoCs
    iocs_by_malware_name = dict(
        sorted(
            iocs_by_malware_name.items(), key=lambda item: len(item[1]), reverse=True
        )
    )

    # Print the IoCs
    logging.info("Malware Families:")
    for malware_name, iocs in iocs_by_malware_name.items():
        logging.info(f"Malware: {malware_name} ({len(iocs)} IoCs)")

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
        "--excluded-iocs",
        "-e",
        type=str,
        help=(
            "The file containing the IOCs to exclude. This file should be a"
            " newline-separated list of IOCs."
        ),
    )
    scan_parser.add_argument(
        "--tag",
        "-t",
        type=str,
        action="append",
        help="The tag of the fingerprints to scan. (Default: all fingerprints)",
    )
    scan_parser.add_argument(
        "--no-submit",
        "-n",
        action="store_true",
        help="Do not submit the results to ThreatFox. (Default: False)",
    )
    scan_parser.add_argument(
        "--include-tarpits",
        "-T",
        action="store_true",
        help=(
            "Include tarpits in the results. Tarpits will increase"
            " the number of false positives. (Default: False)"
        ),
    )
    # TODO: Implement csv output
    # scan_parser.add_argument(
    #     "--output",
    #     "-o",
    #     type=str,
    #     help="The output csv file to write the results to.",
    # )
    scan_parser.set_defaults(func=scan)

    # Create fingerprint
    create_fingerprint_parser = subparsers.add_parser(
        "create-fingerprint",
        help="Create a fingerprint.",
    )
    create_fingerprint_parser.set_defaults(func=create_fingerprint)

    # Check IoC from query
    check_ioc_from_query_parser = subparsers.add_parser(
        "check-ioc",
        help="Check IoC from query.",
    )
    check_ioc_from_query_parser.add_argument(
        "QUERY",
        type=str,
        help="The query to check.",
    )
    check_ioc_from_query_parser.add_argument(
        "--virtual-hosts",
        "-v",
        action="store_true",
        help="Include virtual hosts in the query. (Default: False)",
    )
    check_ioc_from_query_parser.set_defaults(func=check_ioc_from_query)

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
