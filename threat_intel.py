# Threat Modelling Imports
import requests
import json

"""
*****************
*****************

REFERENCE: https://docs.abuseipdb.com/#configuring-fail2ban

*****************
*****************
"""
# Fetching AbuseIPDB Results - IP Reports and Geolocation Information
def get_abuseipdb(ip_address):
    api_url = "https://api.abuseipdb.com/api/v2/check"

    query_params = {
    'ipAddress': ip_address,
    'maxAgeInDays': '90',
    'verbose': 'yes'
    }

    headers = {
    'Accept': 'application/json',
    'Key': 'dafa3a245e1185857ca31564211291972a9e987b60514217a01eaff734f44ff10ede94c7af48a669'
    }   

    api_response = requests.get(url=api_url, headers=headers, params=query_params)
    json_api_response = json.loads(api_response.text)
    source_country = json_api_response["data"]["countryName"]
    domain = json_api_response["data"]["domain"]
    hostnames = json_api_response["data"]["hostnames"]
    isTor = json_api_response["data"]["isTor"]
    totalReports = json_api_response["data"]["totalReports"]

    json_dict = {
        "source_country":source_country,
        "domain":domain,
        "hostnames":hostnames,
        "isTor":isTor,
    }

    if totalReports != 0:
        reports = json_api_response["data"]["reports"]
        json_dict["reports"] = reports
    
    return json.dumps(json_dict)

# Fetching AlienVault Results - Associated Malware Names & Techniques
def alienvault_get(ip_address):
    alienvalut_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/"+ip_address+"/general"
    
    headers = {
    'X-OTX-API-KEY': '7c57e6aef081866aa4670463955e819d38674dfef132926ea2c2e3a4a9cfaa40'
    } 

    alienvault_response = requests.get(url=alienvalut_url, headers=headers)
    json_api_response = json.loads(alienvault_response.text)
    pulse_info = json_api_response["pulse_info"]["pulses"]

    all_display_names = []
    all_malware = []
        
    for pulse in pulse_info:
        malware_families = pulse["malware_families"]
        if malware_families:
            malware_name = pulse["malware_families"][0]["display_name"]
            all_malware.append(malware_name)
        attack_identifiers = pulse["attack_ids"]
        if attack_identifiers:
            display_names = [ids["display_name"] for ids in attack_identifiers]
            all_display_names.extend(display_names)
    unique_display_names = list(set(all_display_names))
    unique_malware_names = list(set(all_malware))

    otx_dict = {
        "ttp":unique_display_names,
        "malware_names": unique_malware_names
    }
    
    return json.dumps(otx_dict)
            
# alienvault_get("193.42.36.245")

# Fetching Shodan Results - Ports & Vulns
def shodan_details(ip_address):
    shodan_url = "https://api.shodan.io/shodan/host/"+ip_address+"?key=hhzNWTbXZ989cxIbH4r2JSdRzoy2O5n0"
    shodan_response = requests.get(url=shodan_url)
    json_api_response = json.loads(shodan_response.text)
    ports = json_api_response["ports"]
    

    shodan_dict = {
        "ports":ports,
    }

    if json_api_response["vulns"]:
        vulns = json_api_response["vulns"]
        shodan_dict["vulnerabilities"] = vulns
    
    return json.dumps(shodan_dict)

shodan_details("45.230.47.141")