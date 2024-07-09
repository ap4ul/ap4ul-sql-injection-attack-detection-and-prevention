# Importing Proxy Libraries
from mitmproxy import http
import re
import urllib
import json

# Define Variables for Prevention Feature
ip_count = {}
blocked_ips = set()

# Counting SQLi Source IPs
def increment_detected_ip():
    with open("detected_sqli_ips.txt","r") as detected_file:
        ips = detected_file.readlines()
        for ip in ips:
            ip = ip.strip()
            if ip in ip_count:
                ip_count[ip] += 1
            else:
                ip_count[ip] = 1

    for ip, count in ip_count.items():
        if count >= 3:
            blocked_ips.add(ip)
    
    return blocked_ips

# Extract Parameter Values
def extract_value(data):
    token = re.findall(r'=(.*?)(&|$)', data)
    items = []
    for item in token:
        if item[0]:
            items.append(item[0])

    return items

# Set Error Message
error_message = {
    "Error":"Forbidden",
    "Message":"Your IP has been blocked due to suspicious of SQLi Attack. Request dropped"
}
json_error = json.dumps(error_message)

# Capture Responses
def request(flow: http.HTTPFlow) -> None:

    # Capture Source IP Address
    source_ip = flow.client_conn.address[0]

    blocked_ips = increment_detected_ip()
    # print(blocked_ips)

    if source_ip in blocked_ips:
        flow.response = http.Response.make(403, json_error.encode("utf-8"), {"Content-Type": "application/json"})
    with open('client_ips.txt', 'a+') as file:
        file.write(str(source_ip)+"\n")
        file.flush()

    # Capture Web Requests
    with open("http_requests.txt", "a") as f:
        if "&" in flow.request.url:
            extracted_params = extract_value(flow.request.url)
            for text in extracted_params:
                text = urllib.parse.unquote_plus(text)
                f.write(text+"\n")
        for name, value in flow.request.headers.items():
            if name == "User-Agent":
                f.write(value+"\n")
            if name == "Referer":
                referer_url = "/".join(value.split("/")[:3])
                f.write(referer_url+"\n")
            if name == "X-Forwarded-For":
                f.write(value+"\n")
        body = flow.request.content.decode("utf-8")
        if body:
            body_text = extract_value(body)
            for text in body_text:
                text = urllib.parse.unquote_plus(text)
                f.write(text+"\n")