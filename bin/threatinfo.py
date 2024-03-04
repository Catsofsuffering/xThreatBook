from __future__ import absolute_import, division, print_function, unicode_literals
import itertools
import sys
import requests

"""Debug"""
# import os

# sys.path.append(
#     os.path.join(os.environ["SPLUNK_HOME"], "etc", "apps", "SA-VSCode", "bin")
# )
# import splunk_debug as dbg

# dbg.enable_debugging(timeout=25)


from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

__version__ = "1.6.241"

__cloudapikey__ = ""

__tipapikey__ = ""


@Configuration()
class Threatinfo(StreamingCommand):
    """
    ##Syntax

    .. code-block::
        threateinfo threat_url=<fieldname>

    ##Description
        This command could fetch threat information from XThreatBook by API according to the IPs or urls which the user put in.

    ##Example
        Execute the following SPL command in the Splunk Search Head:

            | makeresults
            | eval url="159.203.93.255"
            | threatinfo threat_url=url local=false cloud_type=scene_ip_reputation response=both

        There would add a field name "response" about the XThreatBook API responsed. And the field value would like this below:

            {
                "data": {
                    "159.203.93.255": {
                        "severity": "low",
                        "judgments": ["Zombie", "IDC", "Spam"],
                        "tags_classes": [],
                        "basic": {
                            "carrier": "DigitalOcean, LLC",
                            "location": {
                                "country": "United States",
                                "province": "New Jersey",
                                "city": "Clifton",
                                "lng": "-74.16366",
                                "lat": "40.858403",
                                "country_code": "US",
                            },
                        },
                        "asn": {"rank": 4, "info": "DIGITALOCEAN-ASN, US", "number": 14061},
                        "scene": "",
                        "confidence_level": "low",
                        "is_malicious": true,
                        "update_time": "2020-10-29 16:47:43",
                    }
                },
                "response_code": 0,
                "verbose_msg": "OK",
            }

    """

    threat_url = Option(
        doc="""
        **Syntax:** **threat_url=***<fieldname>*
        **Description:**The field containing \
        the urls need to fetch threat information.""",
        require=True,
        validate=validators.Fieldname(),
    )

    local = Option(
        doc="""
        **Syntax:** **local=***<boolean>*
        **Description:**The option determines whether to parse the response.""",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )

    cloud_type: Option = Option(
        doc="""
        **Syntax:** **cloud_type=***<scene_ip_reputation|ip_query|domain_query|scene_dns  \
        |ip_adv_query|domain_adv_query|domain_sub_domains|scene_domain_context>*
        **Description:**The option determines which cloud api to query.""",
        require=False,
        default="scene_ip_reputation",
        validate=validators.Set(
            "scene_ip_reputation",
            "ip_query",
            "domain_query",
            "scene_dns",
            "ip_adv_query",
            "domain_adv_query",
            "domain_sub_domains",
            "scene_domain_context",
        ),
    )

    tip_type = Option(
        doc="""
        **Syntax:** **tip_type=***<dns|ip|location>*
        **Description:**The option determines which tip api to query.""",
        require=False,
        default="dns",
        validate=validators.Set(
            "dns",
            "ip",
            "location",
        ),
    )

    response = Option(
        doc="""
        **Syntax:** **response=***<raw|parse|both>*
        **Description:**The option determines whether to get raw response.""",
        require=False,
        default="raw",
        validate=validators.Set("raw", "parse", "both"),
    )

    def __init__(self):
        super(Threatinfo, self).__init__()
        self.cloud_urls = {
            "scene_ip_reputation": "https://api.threatbook.cn/v3/scene/ip_reputation",
            "ip_query": "https://api.threatbook.cn/v3/ip/query",
            "domain_query": "https://api.threatbook.cn/v3/domain/query",
            "scene_dns": "https://api.threatbook.cn/v3/scene/dns",
            "ip_adv_query": "https://api.threatbook.cn/v3/ip/adv_query",
            "domain_adv_query": "https://api.threatbook.cn/v3/domain/adv_query",
            "domain_sub_domains": "https://api.threatbook.cn/v3/domain/sub_domains",
            "scene_domain_context": "https://api.threatbook.cn/v3/scene/domain_context",
        }
        self.tip_urls = {
            "dns": "http://10.173.16.254:8090/tip_api/v4/dns",
            "ip": "http://10.173.16.254:8090/tip_api/v4/ip",
            "location": "http://10.173.16.254:8090/tip_api/v4/location",
        }
        self.api_key = ""
        self.api_url = ""
        self.chunk_size = {
            "scene_ip_reputation": 100,
            "ip_query": 1,
            "domain_query": 1,
            "scene_dns": 100,
            "ip_adv_query": 1,
            "domain_adv_query": 1,
            "domain_sub_domains": 1,
            "scene_domain_context": 1,
            "dns": 50,
            "ip": 50,
            "location": 50,
        }
        self._chunk_size = 1

    def prepare(self):
        super(Threatinfo, self).prepare()
        will_execute = bool(
            self.metadata.searchinfo.sid
            and not self.metadata.searchinfo.sid.startswith("searchparsetmp_")
        )
        if will_execute:
            self.logger.info("Launching version %s", __version__)

    def _params_check(self):
        if self.local:
            self.api_key = __tipapikey__
            self.api_url = self.tip_urls[self.tip_type]
            self._chunk_size = self.chunk_size[self.tip_type]
        else:
            self.api_key = __cloudapikey__
            self.api_url = self.cloud_urls[self.cloud_type]
            self._chunk_size = self.chunk_size[self.cloud_type]

    def _query_external_api(self, threat_url):
        """
        This method query threatbook API and return response

        Args:
            threat_url (str): The threat url which need to get threat intelligence information

        Returns:
            response: The json dictionary of the API responsed
        """
        self.logger.info("Query the url: %s", threat_url)
        query_params = {
            "apikey": self.api_key,
            "resource": threat_url,
        }
        with requests.Session() as s:
            try:
                response = s.get(self.api_url, params=query_params, timeout=10)
                response.raise_for_status()
                result = response.json()
            except requests.exceptions.RequestException as e:
                result = {
                    "response_code": str(e),
                    "verbose_msg": str(e),
                    "data": str(e),
                }
        return result if isinstance(result, dict) else None

    def _flatten_dict(self, _dict):
        """
        This method flat the nested dictionarie and return paired keys and values.

        Args:
            _dict (dict): The nested dictionarie which need to flat

        Yields:
            (Generator): The paired keys and values which needed
        """
        for k, v in _dict.items():
            if not isinstance(v, dict):
                yield k, v
            else:
                yield from ((k, *q) for q in self._flatten_dict(v))

    def _parse_data(self, threat_url, resp):
        """
        Parse the API response for records in chunks.

        Args:
            threat_url (str): The threat URL for which threat intelligence information is needed.
            resp (dict): The response JSON from the threatbook API.

        Returns:
            dict: Parsed fields extracted from the response.
        """

        result_field = {
            "response_code": resp.get("response_code"),
            "verbose_msg": resp.get("verbose_msg"),
        }
        parse_datas = resp.get("data")
        if self.local:
            for parse_data in parse_datas:
                if threat_url == parse_data.get("ioc") and self.response in [
                    "raw",
                    "both",
                ]:
                    result_field.update(response=parse_data)
                if threat_url == parse_data.get("ioc") and self.response in [
                    "parse",
                    "both",
                ]:
                    [
                        result_field.update(result)
                        for result in parse_data.get("intelligence")
                    ] or [{"response_msg": "No intelligence data"}]
        else:
            if threat_url in parse_datas and self.response in ["raw", "both"]:
                result_field.update(response=parse_datas.get(threat_url))
            if threat_url in parse_datas and self.response in ["parse", "both"]:
                result_field.update(parse_datas.get(threat_url))
        return result_field

    def _chunk_api(self, records):
        """
        This method process records in chunks.

        Args:
            records (iterable): Records to process.

        Yields:
            dict: Processed records.
        """
        for chunk in iter(
            lambda: list(itertools.islice(records, self._chunk_size)), []
        ):
            resource = ",".join(
                str(chunk_record[self.threat_url]) for chunk_record in chunk
            )
            resp = self._query_external_api(resource)
            for record in chunk:
                result_field = self._parse_data(record[self.threat_url], resp)
                for fieldname, fieldvalue in result_field.items():
                    self.add_field(record, fieldname, fieldvalue)
                yield record

    def _single_api(self, records):
        """
        This method process records individually.

        Args:
            records (iterable): Records to process.

        Yields:
            dict: Processed records.
        """
        for index, record in enumerate(records):
            if index % 1 == 0:
                resource = record[self.threat_url]
                resp = self._query_external_api(resource)
                result_field = self._parse_data(resp)
                for fieldname, fieldvalue in result_field.items():
                    self.add_field(record, fieldname, fieldvalue)
            yield record

    def stream(self, records):
        self._params_check()
        if self._chunk_size != 1:
            yield from self._chunk_api(records)
        else:
            yield from self._single_api(records)


if __name__ == "__main__":
    dispatch(Threatinfo, sys.argv, sys.stdin, sys.stdout, __name__)
