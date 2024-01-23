from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import requests
import json

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

__version__ = "1.0.241"

__apikey__ = ""


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
            | threatinfo threat_url=url

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

    query_type = Option(
        doc="""
        **Syntax:** **query_type=***<scene_ip_reputation|ip_query|domain_query|scene_dns  \
        |ip_adv_query|domain_adv_query|domain_sub_domains|scene_domain_context>*
        **Description:**The option determind which api to query.""",
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

        self.api_key = __apikey__

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
        try:
            response = requests.request("GET", query_api_url, params=query_params)
            result = json.loads(response.text)
        except requests.ConnectionError as e:
            self.logger.error("Aborting due to API connection failure.  %s", e)
        except Exception as e:
            self.logger.exception("Failure while calling API. %s", e)
        return result if isinstance(result, dict) else None

    """ This method is going to flat the nested dictionaries """
    # def _flatten_dict(self, _dict):
    #     for k, v in _dict.items():
    #         if not isinstance(v, dict):
    #             yield k, v
    #         else:
    #             yield from ((k, *q) for q in self._flatten_dict(self, v))

    def stream(self, records):
        for index, record in enumerate(records):
            if index % 1 == 0:
                resp = self._query_external_api(
                    self.api_urls[self.query_type], record[self.threat_url]
                )
                self.add_field(record, "response", resp)

                """Debug"""
                # self.add_field(record, "resource", record[self.threat_url])
                # self.add_field(record, "query_type", self.api_urls[self.query_type])

                """ This resp (dictionary) need to be flat and unpacked """
                # for node in self.resp:
                #     self.add_field(record, str(node[-2]), str(node[-1]))
            yield record


if __name__ == "__main__":
    """Debug"""
    # try:
    #     dispatch(Threatinfo, sys.argv, sys.stdin, sys.stdout, __name__)
    # except Exception as e:
    #     print("Threatinfo executed failed: %s", e)
    dispatch(Threatinfo, sys.argv, sys.stdin, sys.stdout, __name__)
