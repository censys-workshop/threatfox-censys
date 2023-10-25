import pytest
import requests
import responses
from requests.utils import default_user_agent
from responses import matchers

from threatfox_censys.threatfox import ThreatFoxClient

TEST_API_KEY = "test_api_key"
BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"


@pytest.fixture
def threatfox_client() -> ThreatFoxClient:
    return ThreatFoxClient(TEST_API_KEY)


api_key_matcher = matchers.header_matcher(
    {
        "API-KEY": TEST_API_KEY,
        "Accept": "application/json",
        "User-Agent": (
            f"{default_user_agent()} (ThreatfoxCensys;"
            " +https://github.com/censys-workshop/threatfox-censys)"
        ),
    },
)


@responses.activate
def test_get_recent_iocs(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": [
            {
                "id": "41",
                "ioc": "gaga.com",
                "threat_type": "botnet_cc",
                "threat_type_desc": (
                    "Indicator that identifies a botnet command&control server (C&C)"
                ),
                "ioc_type": "domain",
                "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
                "malware": "win.dridex",
                "malware_printable": "Dridex",
                "malware_alias": None,
                "malware_malpedia": (
                    "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex"
                ),
                "confidence_level": 50,
                "first_seen": "2020-12-08 13:36:27 UTC",
                "last_seen": None,
                "reporter": "abuse_ch",
                "reference": (
                    "https://twitter.com/JAMESWT_MHT/status/1336229725082177536"
                ),
                "tags": ["exe", "test"],
            },
            {
                "id": "40",
                "ioc": "susu.com",
                "threat_type": "botnet_cc",
                "threat_type_desc": (
                    "Indicator that identifies a botnet command&control server (C&C)"
                ),
                "ioc_type": "domain",
                "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
                "malware": "win.dridex",
                "malware_printable": "Dridex",
                "malware_alias": None,
                "malware_malpedia": (
                    "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex"
                ),
                "confidence_level": 50,
                "first_seen": "2020-12-08 13:36:27 UTC",
                "last_seen": None,
                "reporter": "abuse_ch",
                "reference": None,
                "tags": ["exe", "test"],
            },
        ],
    }

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {"query": "get_iocs", "days": 1}, strict_match=True
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.get_recent_iocs(days=1)

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_get_ioc_by_id(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "id": "41",
        "ioc": "gaga.com",
        "threat_type": "botnet_cc",
        "threat_type_desc": (
            "Indicator that identifies a botnet command&control server (C&C)"
        ),
        "ioc_type": "domain",
        "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
        "malware": "win.dridex",
        "malware_printable": "Dridex",
        "malware_alias": None,
        "malware_malpedia": (
            "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex"
        ),
        "confidence_level": 50,
        "first_seen": "2020-12-08 13:36:27 UTC",
        "last_seen": None,
        "reference": "https://twitter.com/JAMESWT_MHT/status/1336229725082177536",
        "reporter": "abuse_ch",
        "comment": "These domains are too bad!",
        "tags": ["exe", "test"],
        "credits": [{"credits_from": "ThreatFox", "credits_amount": 5}],
        "malware_samples": [
            {
                "time_stamp": "2021-03-23 08:18:06 UTC",
                "md5_hash": "5b7e82e051ade4b14d163eea2a17bf8b",
                "sha256_hash": "123",
                "malware_bazaar": "https://bazaar.abuse.ch/sample/123/",
            },
        ],
    }
    TEST_IOC_ID = 41

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {"query": "ioc", "id": TEST_IOC_ID}, strict_match=True
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.get_ioc_by_id(ioc_id=TEST_IOC_ID)

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_search_iocs(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": [
            {
                "id": "12",
                "ioc": "139.180.203.104:443",
                "threat_type": "botnet_cc",
                "threat_type_desc": (
                    "Indicator that identifies a botnet command&control server (C&C)"
                ),
                "ioc_type": "ip:port",
                "ioc_type_desc": (
                    "ip:port combination that is used for botnet Command&control (C&C)"
                ),
                "malware": "win.cobalt_strike",
                "malware_printable": "Cobalt Strike",
                "malware_alias": "Agentemis,BEACON,CobaltStrike",
                "malware_malpedia": (
                    "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
                ),
                "confidence_level": 75,
                "first_seen": "2020-12-06 09:10:23 UTC",
                "last_seen": None,
                "reference": None,
                "reporter": "abuse_ch",
                "tags": None,
                "malware_samples": [
                    {
                        "time_stamp": "2021-03-23 08:18:06 UTC",
                        "md5_hash": "5b7e82e051ade4b14d163eea2a17bf8b",
                        "sha256_hash": "123",
                        "malware_bazaar": "https://bazaar.abuse.ch/sample/123/",
                    },
                ],
            }
        ],
    }
    TEST_SEARCH_TERM = "139.180.203.104"

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {"query": "search_ioc", "search_term": TEST_SEARCH_TERM},
                strict_match=True,
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.search_iocs(search_term=TEST_SEARCH_TERM)

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_search_iocs_by_file_hash(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": [
            {
                "id": "4726",
                "ioc": "http://harold.jetos.com:3606/is-ready",
                "threat_type": "botnet_cc",
                "threat_type_desc": (
                    "Indicator that identifies a botnet command&control server (C&C)"
                ),
                "ioc_type": "url",
                "ioc_type_desc": "URL that is used for botnet Command&control (C&C)",
                "malware": "win.houdini",
                "malware_printable": "Houdini",
                "malware_alias": "Hworm,Jenxcus,Kognito,Njw0rm,WSHRAT,dinihou,dunihi",
                "malware_malpedia": (
                    "https://malpedia.caad.fkie.fraunhofer.de/details/win.houdini"
                ),
                "confidence_level": 100,
                "first_seen": "2021-03-23 14:50:33 UTC",
                "last_seen": None,
                "reference": None,
                "reporter": "abuse_ch",
                "tags": ["WSHRAT"],
            }
        ],
    }
    TEST_FILE_HASH = "2151c4b970eff0071948dbbc19066aa4"

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {"query": "search_hash", "hash": TEST_FILE_HASH},
                strict_match=True,
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.search_iocs_by_file_hash(file_hash=TEST_FILE_HASH)

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_search_iocs_by_tag(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": [
            {
                "id": "29",
                "ioc": "jquery.su",
                "threat_type": "cc_skimming",
                "threat_type_desc": (
                    "Indicator that identifies credit card skimming infrastructure (NOT"
                    " phishing)"
                ),
                "ioc_type": "domain",
                "ioc_type_desc": (
                    "Domain used for credit card skimming (usually related to Magecart"
                    " attacks)"
                ),
                "malware": "js.magecart",
                "malware_printable": "magecart",
                "malware_alias": None,
                "malware_malpedia": (
                    "https://malpedia.caad.fkie.fraunhofer.de/details/js.magecart"
                ),
                "confidence_level": 50,
                "first_seen": "2020-12-06 15:04:03 UTC",
                "last_seen": None,
                "reference": (
                    "https://twitter.com/AffableKraut/status/1335501765031174145"
                ),
                "reporter": "abuse_ch",
                "tags": ["Magecart"],
            }
        ],
    }
    TEST_TAG = "Magecart"

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {"query": "taginfo", "tag": TEST_TAG, "limit": 1}, strict_match=True
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.search_iocs_by_tag(tag=TEST_TAG, limit=1)

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_search_iocs_by_malware(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": [
            {
                "id": "21",
                "ioc": "43.255.30.192:8848",
                "threat_type": "botnet_cc",
                "threat_type_desc": (
                    "Indicator that identifies a botnet command&control server (C&C)"
                ),
                "ioc_type": "ip:port",
                "ioc_type_desc": (
                    "ip:port combination that is used for botnet Command&control (C&C)"
                ),
                "malware": "win.cobalt_strike",
                "malware_printable": "Cobalt Strike",
                "malware_alias": "Agentemis,BEACON,CobaltStrike",
                "malware_malpedia": (
                    "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
                ),
                "confidence_level": 50,
                "first_seen": "2020-12-06 09:47:30 UTC",
                "last_seen": None,
                "reference": None,
                "reporter": "abuse_ch",
                "tags": None,
            }
        ],
    }
    TEST_MALWARE = "Cobalt Strike"

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {"query": "malwareinfo", "malware": TEST_MALWARE, "limit": 100},
                strict_match=True,
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.search_iocs_by_malware(malware=TEST_MALWARE)

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_submit_ioc(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": "IOC submitted successfully",
    }
    TEST_THREAT_TYPE = "botnet_cc"
    TEST_IOC_TYPE = "ip:port"
    TEST_MALWARE = "Cobalt Strike"
    TEST_IOCS = ["1.1.1.1:443"]
    TEST_CONFIDENCE_LEVEL = 50
    TEST_REFERENCE = "https://twitter.com/JAMESWT_MHT/status/1336229725082177536"
    TEST_COMMENT = "This is a test"
    TEST_ANONYMOUS = False
    TEST_TAGS = ["test"]

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {
                    "query": "submit_ioc",
                    "threat_type": TEST_THREAT_TYPE,
                    "ioc_type": TEST_IOC_TYPE,
                    "malware": TEST_MALWARE,
                    "confidence_level": TEST_CONFIDENCE_LEVEL,
                    "iocs": TEST_IOCS,
                    "reference": TEST_REFERENCE,
                    "comment": TEST_COMMENT,
                    "anonymous": 0 if not TEST_ANONYMOUS else 1,
                    "tags": TEST_TAGS,
                },
                strict_match=True,
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.submit_ioc(
        threat_type=TEST_THREAT_TYPE,
        ioc_type=TEST_IOC_TYPE,
        malware=TEST_MALWARE,
        iocs=TEST_IOCS,
        confidence_level=TEST_CONFIDENCE_LEVEL,
        reference=TEST_REFERENCE,
        comment=TEST_COMMENT,
        anonymous=TEST_ANONYMOUS,
        tags=TEST_TAGS,
    )

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_get_malware_label(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": [
            {
                "malware": "win.ave_maria",
                "malware_printable": "Ave Maria",
                "malware_alias": "AVE_MARIA,AveMariaRAT,Warzone RAT,avemaria",
            }
        ],
    }
    TEST_MALWARE = "warzone"
    TEST_PLATFORM = "win"

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher(
                {
                    "query": "get_label",
                    "malware": TEST_MALWARE,
                    "platform": TEST_PLATFORM,
                },
                strict_match=True,
            ),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.get_malware_label(
        malware=TEST_MALWARE, platform=TEST_PLATFORM
    )

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_get_malware_list(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": {
            "win.sparksrv": {"malware_printable": "Sparksrv", "malware_alias": None},
            "win.sslmm": {"malware_printable": "SslMM", "malware_alias": None},
            "win.hermes_ransom": {
                "malware_printable": "Hermes Ransomware",
                "malware_alias": None,
            },
            "apk.doublelocker": {
                "malware_printable": "DoubleLocker",
                "malware_alias": None,
            },
        },
    }

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher({"query": "malware_list"}, strict_match=True),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.get_malware_list()

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_get_threat_types(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": {
            "1": {
                "ioc_type": "url",
                "fk_threat_type": "payload_delivery",
                "description": "URL that delivers a malware payload",
            },
            "2": {
                "ioc_type": "domain",
                "fk_threat_type": "payload_delivery",
                "description": "Domain name that delivers a malware payload",
            },
            "3": {
                "ioc_type": "ip:port",
                "fk_threat_type": "payload_delivery",
                "description": "ip:port combination that delivery a malware payload",
            },
        },
    }

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher({"query": "threat_types"}, strict_match=True),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.get_threat_types()

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_get_tag_list(threatfox_client: ThreatFoxClient):
    # Set up the response
    JSON_RESPONSE = {
        "query_status": "ok",
        "data": {
            "exe": {
                "first_seen": "2020-12-06 09:16:18",
                "last_seen": "2020-12-08 13:36:27",
                "color": "#D984D4",
            },
            "js": {
                "first_seen": "2020-12-06 15:04:03",
                "last_seen": "2020-12-06 15:04:03",
                "color": "#1BA0CD",
            },
            "Magecart": {
                "first_seen": "2020-12-06 15:04:03",
                "last_seen": "2020-12-06 15:04:03",
                "color": "#C41619",
            },
        },
    }

    # Mock the response from the API
    responses.post(
        BASE_URL,
        json=JSON_RESPONSE,
        match=[
            matchers.json_params_matcher({"query": "tag_list"}, strict_match=True),
            api_key_matcher,
        ],
    )

    # Make the request
    response = threatfox_client.get_tag_list()

    # Check the response
    assert response == JSON_RESPONSE


@responses.activate
def test_send_request_error(threatfox_client: ThreatFoxClient):
    # Mock the response from the API
    responses.post(
        BASE_URL,
        json={"query_status": "error", "data": "Invalid API key"},
        match=[
            matchers.json_params_matcher({"query": "get_iocs", "days": 1}),
            api_key_matcher,
        ],
        status=403,
    )

    # Make the request
    with pytest.raises(requests.HTTPError):
        threatfox_client.get_recent_iocs(days=1)


@responses.activate
@pytest.mark.parametrize(
    "method,data,exception,match",
    [
        ("GET", {"test": 1}, ValueError, "GET requests cannot have a data parameter"),
        ("RANDOM", {}, ValueError, "Unsupported HTTP method"),
    ],
)
def test_send_request_exception(
    threatfox_client: ThreatFoxClient,
    method: str,
    data: dict | None,
    exception: Exception,
    match: str,
):
    with pytest.raises(exception, match=match):  # type: ignore[call-overload]
        threatfox_client._send_request(endpoint="test", method=method, data=data)
