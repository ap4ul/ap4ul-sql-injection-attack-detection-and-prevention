# Importing Standard Libraries for Risk Analysis
import statistics
import requests
import json

# Importing Asynchronous Request Libraries
import asyncio
import aiohttp

# Calculating Average CVSS Base Score for All Classes
def calculate_cvss(attack):

    if attack == "Authentication Bypass":
        file = open("./CVEs/JSON/authbypass_sqli_cves.json")
    elif attack == "Blind SQLi Injection":
        file = open("./CVEs/JSON/blind_sqli_cves.json")
    elif attack == "Classic SQLi Injection":
        file = open("./CVEs/JSON/classic_sqli_cves.json")
    elif attack == "Denial Of Service SQLi":
        file = open("./CVEs/JSON/dos_sqli_cves.json")
    elif attack == "Remote Code Execution SQLi":
        file = open("./CVEs/JSON/rce_sqli_cves.json")
    
    cve_data = json.load(file)
    total_base = []
    total_exploitability = []
    total_impact = []

    for id, cve in cve_data.items():
        base_score = float(cve['Base Score'])
        exploitability_score = float(cve['Exploitability Score'])
        impact_score = float(cve['Impact Score'])

        total_base.append(base_score)
        total_exploitability.append(exploitability_score)
        total_impact.append(impact_score)

    average_base = round(sum(total_base)/len(total_base),2)
    file.close()
    return average_base

# Calculating Average EPSS Base Score for All Classes
def calculate_epss(attack):

    if attack == "Authentication Bypass":
        with open('./CVEs/authentication_bypass_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Blind SQLi Injection":
        with open('./CVEs/blind_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Classic SQLi Injection":
        with open('./CVEs/classic_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Denial Of Service SQLi":
        with open('./CVEs/dos_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Remote Code Execution SQLi":
        with open('./CVEs/rce_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()

    total_epss = []
    cve_string = ','.join(cve_list)
    epss_api = requests.get('https://api.first.org/data/v1/epss?cve='+cve_string+'&limit=150')
    epss_results = epss_api.json()
    data_key = epss_results['data']

    for value in data_key:
        cve_id = value['cve']
        epss_score = value['epss']
        total_epss.append(float(epss_score))
    cve_instances = len(data_key)
    average_epss = round(sum(total_epss)/cve_instances,6)
    return average_epss


# Calculating Average EE Base Score for All Classes
def calculate_ee(attack):
    """
    *****************
    *****************

    PURPOSE: Faster Retrievel of EE API Requests using Asynchronous Requests
    REFERENCE: https://www.youtube.com/watch?v=GpqAQxH1Afc&ab_channel=ArjanCodes

    *****************
    *****************
    """
    async def fetch_cve(session, cve):
        params = {
            "cveid": cve,
            "model": "prod3_2022_10_03",
        }
        headers = {
            "accept": "application/json",
            "access_token": "Sp94VJWawWMZDZd4qQJnSzR2wyb7CV02",
        }
        
        async with session.get("https://api.exploitability.app/scores/cveid", params=params, headers=headers) as ee:
            ee.raise_for_status()
            return await ee.json()

    async def fetch_complete(cves):
        tasks = []
        async with aiohttp.ClientSession() as session:
            for cve in cves:
                task = asyncio.create_task(fetch_cve(session, cve))
                tasks.append(task)
            return await asyncio.gather(*tasks)
        
    if attack == "Authentication Bypass":
        with open('./CVEs/authentication_bypass_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Blind SQLi Injection":
        with open('./CVEs/blind_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Classic SQLi Injection":
        with open('./CVEs/classic_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Denial Of Service SQLi":
        with open('./CVEs/dos_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()
    elif attack == "Remote Code Execution SQLi":
        with open('./CVEs/rce_sqli_cves.txt', 'r') as file:
            cve_list = file.read().splitlines()

    loop = asyncio.get_event_loop()
    ee_json_list = loop.run_until_complete(fetch_complete(cve_list))
    
    scores = []

    for ee_cve in ee_json_list:
        if ee_cve['results']:
            latest_result =  ee_cve['results'][-1]
            cve_id = latest_result['cveid']
            ee_score = latest_result['score']
            scores.append(ee_score)
    
    average_score = statistics.mean(scores)
    average_score = round(average_score,6)
    return average_score


"""
*****************
*****************

PURPOSE: Normalising All Scores to Values Between 0 and 9
REFERENCE: https://www.statology.org/normalize-data-between-0-and-100/

*****************
*****************
"""
def normalise_scores(score,cvss=True):

    min_value = 0.0
    max_value = 1.0
    if cvss:
        max_value = 10.0

    norm_value = (score - min_value) / (max_value - min_value) * 9
        
    return norm_value


"""
*****************
*****************

PURPOSE: Calculating Likelihood and Impact Levels
REFERENCE: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

*****************
*****************
"""
def likelihood_impact_level(value):
    level = None
    if value >= 0 and value <3:
        level =  "LOW"
    elif value >= 3 and value <6:
        level =  "MEDIUM"
    elif value >= 6 and value <=9:
        level =  "HIGH"
    return level


"""
*****************
*****************

PURPOSE: Calculating Overall Severity
REFERENCE: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

*****************
*****************
"""
def severity_level(impact_val, likelihood_val):
    severity = None
    if impact_val == "HIGH":
        if likelihood_val == "LOW":
            severity = "Medium"
        elif likelihood_val == "MEDIUM":
            severity = "High"
        elif likelihood_val == "HIGH":
            severity = "Critical"
    elif impact_val == "MEDIUM":
        if likelihood_val == "LOW":
            severity = "Low"
        elif likelihood_val == "MEDIUM":
            severity = "Medium"
        elif likelihood_val == "HIGH":
            severity = "High"
    elif impact_val == "LOW":
        if likelihood_val == "LOW":
            severity = "Note"
        elif likelihood_val == "MEDIUM":
            severity = "Low"
        elif likelihood_val == "HIGH":
            severity = "Medium"
        else:
            severity = "Invalid like_value"
    else:
        severity = "Invalid imp_value"

    return severity

# Combining CVSS, EPSS and EE to form RISK R34P3R
def risk_r34p3r(attack_type):
    cvss_score = calculate_cvss(attack_type)
    epss_score = calculate_epss(attack_type)
    ee_score = calculate_ee(attack_type)

    cvss_normalised = normalise_scores(cvss_score)
    epss_normalised = normalise_scores(epss_score,False)
    ee_normalised = normalise_scores(ee_score, False)

    likelihood = (epss_normalised + ee_normalised)/2
    impact = cvss_normalised
    likelihood_level = likelihood_impact_level(likelihood)
    impact_level = likelihood_impact_level(impact)
    severity_val = severity_level(impact_level,likelihood_level)
    
    return severity_val






  