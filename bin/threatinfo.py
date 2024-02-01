from __future__ import absolute_import, division, print_function, unicode_literals
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

__version__ = "1.2.246"

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
            | threatinfo threat_url=url local=false cloud_type=scene_ip_reputation get_raw_response=true

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
        **Syntax:** **platform=***<boolean>*
        **Description:**The option determines whether to use local platform(tip).""",
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

    get_raw_response = Option(
        doc="""
        **Syntax:** **get_raw_response=***<boolean>*
        **Description:**The option determines whether to get raw response.""",
        require=False,
        default=False,
        validate=validators.Boolean(),
    )

    def __init__(self):
        super(Threatinfo, self).__init__()
        self.api_urls = {
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

    def prepare(self):
        super(Threatinfo, self).prepare()
        will_execute = bool(
            self.metadata.searchinfo.sid
            and not self.metadata.searchinfo.sid.startswith("searchparsetmp_")
        )
        if will_execute:
            self.logger.info("Launching version %s", __version__)

    def _query_external_api(self, query_api_url, threat_url):
        self.logger.info("Query the url: %s", threat_url)
        query_params = {
            "apikey": self.api_key,
            "resource": threat_url,
        }
        with requests.Session() as s:
            response = s.get(query_api_url, params=query_params)
            result = response.json()
        return result if isinstance(result, dict) else None

    def _flatten_dict(self, _dict):
        """
        This function flat the nested dictionarie and return paired keys and values.

        Args:
            _dict (dict): the nested dictionarie which need to flat

        Yields:
            (Generator): the paired keys and values which needed
        """
        for k, v in _dict.items():
            if not isinstance(v, dict):
                yield k, v
            else:
                yield from ((k, *q) for q in self._flatten_dict(v))

    def stream(self, records):
        if self.local:
            self.api_key = __tipapikey__
            api_url = self.api_urls[self.tip_type]

        else:
            self.api_key = __cloudapikey__
            api_url = self.api_urls[self.cloud_type]

        """ Get api response """
        for index, record in enumerate(records):
            if index % 1 == 0:
                resource = record[self.threat_url]
                resp = self._query_external_api(api_url, resource)

        """If need to get raw response """
        if self.get_raw_response:
            self.add_field(record, "response", resp)

        """ This resp (dictionary) need to be flat and unpacked """
        parse_data = self._flatten_dict(resp)
        for node in parse_data:
            self.add_field(record, node[-2], node[-1])
        yield record


if __name__ == "__main__":
    """Debug"""
    # try:
    #     dispatch(Threatinfo, sys.argv, sys.stdin, sys.stdout, __name__)
    # except Exception as e:
    #     print("Threatinfo executed failed: %s", e)
    dispatch(Threatinfo, sys.argv, sys.stdin, sys.stdout, __name__)