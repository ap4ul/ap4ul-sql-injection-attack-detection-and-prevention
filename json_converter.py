import os
import time
import requests
import json

# Extracting CVEs uusing CVSS API
def cvss_score_api(filename):
    with open(filename, 'r') as sqli_cves:
        cve_list = sqli_cves.read().splitlines()

        for cve in cve_list:
            cvss_api = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+cve)
            json_data = cvss_api.json()
            base_score = json_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            exploitability_score = json_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"]
            impact_score = json_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"]
            cve_score_txt = open(filename+"_scores.txt", "a")
            print("CVE: "+cve,file=cve_score_txt)
            print("Base Score: "+str(base_score), file=cve_score_txt)
            print("Exploitability Score: "+str(exploitability_score),file=cve_score_txt)
            print("Impact Score: "+str(impact_score),file=cve_score_txt)
            cve_score_txt.close()
            time.sleep(5)

# Converting Text File to JSON
def text_to_json(text_file):
    with open(text_file) as text_file:
        text_data = text_file.read().splitlines()

    cve_json_dict = {}

    for text in text_data:
        if text.startswith('CVE: '):
            cve_name = text.split('CVE: ')[1]
            cve_json_dict[cve_name] = {}
        elif text.startswith('Base Score: '):
            cve_json_dict[cve_name]["Base Score"] = float(text.split('Base Score: ')[1])
        elif text.startswith('Exploitability Score: '):
            cve_json_dict[cve_name]["Exploitability Score"] = float(text.split('Exploitability Score: ')[1])
        elif text.startswith('Impact Score: '):
            cve_json_dict[cve_name]["Impact Score"] = float(text.split('Impact Score: ')[1])

    with open(text_file+".json","w") as score_json:
        json.dump(cve_json_dict,score_json,indent = 4)
    
    os.remove(text_file)
    