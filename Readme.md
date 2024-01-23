# Threatinfo Command

## Description

This command fetches threat information from XThreatBook by API based on the IPs or URLs provided by the user.

## Syntax

```spl
threatinfo threat_url=<fieldname> (query_type=(scene_ip_reputation))? (query_type=(ip_query))? (query_type=(domain_query))? (query_type=(scene_dns))? (query_type=(ip_adv_query))? (query_type=(domain_adv_query))? (query_type=(domain_sub_domains))? (query_type=(scene_domain_context))?
```

## Description

This command can fetch threat information from **XThreatBook** by API based on the IPs or URLs provided by the user.

- `<query_type>`: Optional, determines which type of XThreatBook API to use.
- `<threat_url>`: The "url" must be a field, and the result will be output into a field named "response".

Use SPL command "spath" to parse the result.

## Example

```spl
.. | threatinfo threat_url=url
```

# Example

Execute the following SPL command in the Splunk Search Head:

```spl
| makeresults
| eval url="159.203.93.255"
| threatinfo threat_url=url 
```

The "url" must be a field, and the result will be output into a field named "response". Then you can use SPL command "spath" to parse the result. This will add a field named "response" containing the XThreatBook API response. The field value will look like this:

```json
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