# Disabling TensorFlow GPU Warnings
import os
os.environ['CUDA_VISIBLE_DEVICES'] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2" 

# Importing Classification Libraries
from keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Importing Standard Libraries
import subprocess
import threading
import pickle
import json
import atexit

# Importing Risk Analysis Functions
from risk_modelling import calculate_cvss, calculate_epss, calculate_ee, risk_r34p3r

# Importing Threat Modelling Functions
from threat_intel import get_abuseipdb, alienvault_get, shodan_details

# Importing PCAP Analysis Functions
import pyshark
import pandas as pd
from joblib import load
import warnings
warnings.filterwarnings("ignore")

# Load Tokenizer for CNN-LSTM Model
with open("./Models/Payloads/tokenizer.pickle", "rb") as tokenizer_file:
    tokenizer = pickle.load(tokenizer_file)

# Load the Payload CNN-LSTM Model
model = load_model("./Models/Payloads/lstm_model.h5")

# Load NetFlow Model and Scaler
netflow_model = load_model("./Models/Netflow/netflow_cnnlstm.h5")
netflow_scaler = load("./Models/Netflow/netflow_scaler.pkl")

def check_exfiltration(model, scaler, netlayer):

    networklayer_values = netlayer.values
    values = scaler.transform(networklayer_values)
    values = values.reshape(values.shape[0], values.shape[1], 1)
    prediction = model.predict(values)

    return (prediction > 0.5).astype("int32")[0][0]

# Process The Intercepted Request
def check_sqli(data, tokenizer, cnnlstm_model,payload):
   
    input_sequences = tokenizer.texts_to_sequences([data])
    pad_seq = pad_sequences(input_sequences, maxlen=544)  
    
    # Make predictions
    input_pred = cnnlstm_model.predict(pad_seq)
    input_pred = input_pred.argmax(axis=1)[0]

    source_ip = None

    with open("client_ips.txt", "r") as file:
        ip = file.readlines()
        if not ip:
            print("The file is empty")
        else:
            source_ip = ip[-1].strip()

    print("Source IP: " + source_ip)

    if input_pred == 0:

        with open("detected_sqli_ips.txt", "a") as detected_file:
            detected_file.write(source_ip + "\n")

        cvss_score = calculate_cvss("Authentication Bypass")
        epss_score = calculate_epss("Authentication Bypass")
        ee_score = calculate_ee("Authentication Bypass")
        risk_r34p3r_score = risk_r34p3r("Authentication Bypass")
        ip_report_json = get_abuseipdb("193.42.36.245")
        threat_report_json = alienvault_get("193.42.36.245")
        system_report_json = shodan_details("45.230.47.141")

        ip_report = json.loads(ip_report_json)
        threat_report = json.loads(threat_report_json)
        system_report = json.loads(system_report_json)

        tool_dict = {
            "Classification":"SQL Injection (Auth Bypass) Detected",
            "Payload":payload,
            "CVSSv3":cvss_score,
            "EPSS":epss_score,
            "EE":ee_score,
            "Risk R34p4r":risk_r34p3r_score,
            "IP Report":ip_report,
            "Threat Report":threat_report,
            "System Report":system_report
        }

        tool_output = json.dumps(tool_dict, indent=4)
        print(tool_output)
    elif input_pred == 1:

        with open("detected_sqli_ips.txt", "a") as detected_file:
            detected_file.write(source_ip + "\n")

        cvss_score = calculate_cvss("Blind SQLi Injection")
        epss_score = calculate_epss("Blind SQLi Injection")
        ee_score = calculate_ee("Blind SQLi Injection")
        risk_r34p3r_score = risk_r34p3r("Blind SQLi Injection")
        ip_report_json = get_abuseipdb("193.42.36.245")
        threat_report_json = alienvault_get("193.42.36.245")
        system_report_json = shodan_details("45.230.47.141")

        ip_report = json.loads(ip_report_json)
        threat_report = json.loads(threat_report_json)
        system_report = json.loads(system_report_json)

        tool_dict = {
            "Classification":"SQL Injection (Blind-Based) Detected",
            "Payload":payload,
            "CVSSv3":cvss_score,
            "EPSS":epss_score,
            "EE":ee_score,
            "Risk R34p4r":risk_r34p3r_score,
            "IP Report":ip_report,
            "Threat Report":threat_report,
            "System Report":system_report
        }

        tool_output = json.dumps(tool_dict, indent=4)
        print(tool_output)
    elif input_pred == 2:
        with open("detected_sqli_ips.txt", "a") as detected_file:
            detected_file.write(source_ip + "\n")
        cvss_score = calculate_cvss("Denial Of Service SQLi")
        epss_score = calculate_epss("Denial Of Service SQLi")
        ee_score = calculate_ee("Denial Of Service SQLi")
        risk_r34p3r_score = risk_r34p3r("Denial Of Service SQLi")
        ip_report_json = get_abuseipdb("193.42.36.245")
        threat_report_json = alienvault_get("193.42.36.245")
        system_report_json = shodan_details("45.230.47.141")

        ip_report = json.loads(ip_report_json)
        threat_report = json.loads(threat_report_json)
        system_report = json.loads(system_report_json)

        tool_dict = {
            "Classification":"SQL Injection (Denial-of-Service) Detected",
            "Payload":payload,
            "CVSSv3":cvss_score,
            "EPSS":epss_score,
            "EE":ee_score,
            "Risk R34p4r":risk_r34p3r_score,
            "IP Report":ip_report,
            "Threat Report":threat_report,
            "System Report":system_report
        }

        tool_output = json.dumps(tool_dict, indent=4)
        print(tool_output)
    elif input_pred == 3:
        with open("detected_sqli_ips.txt", "a") as detected_file:
            detected_file.write(source_ip + "\n")

        cvss_score = calculate_cvss("Classic SQLi Injection")
        epss_score = calculate_epss("Classic SQLi Injection")
        ee_score = calculate_ee("Classic SQLi Injection")
        risk_r34p3r_score = risk_r34p3r("Classic SQLi Injection")
        ip_report_json = get_abuseipdb("193.42.36.245")
        threat_report_json = alienvault_get("193.42.36.245")
        system_report_json = shodan_details("45.230.47.141")

        ip_report = json.loads(ip_report_json)
        threat_report = json.loads(threat_report_json)
        system_report = json.loads(system_report_json)

        tool_dict = {
            "Classification":"SQL Injection (Classic) Detected",
            "Payload":payload,
            "CVSSv3":cvss_score,
            "EPSS":epss_score,
            "EE":ee_score,
            "Risk R34p4r":risk_r34p3r_score,
            "IP Report":ip_report,
            "Threat Report":threat_report,
            "System Report":system_report
        }

        tool_output = json.dumps(tool_dict, indent=4)
        print(tool_output)
    elif input_pred == 4:
        with open("detected_sqli_ips.txt", "a") as detected_file:
            detected_file.write(source_ip + "\n")
        cvss_score = calculate_cvss("Remote Code Execution SQLi")
        epss_score = calculate_epss("Remote Code Execution SQLi")
        ee_score = calculate_ee("Remote Code Execution SQLi")
        risk_r34p3r_score = risk_r34p3r("Remote Code Execution SQLi")
        ip_report_json = get_abuseipdb("193.42.36.245")
        threat_report_json = alienvault_get("193.42.36.245")
        system_report_json = shodan_details("45.230.47.141")

        ip_report = json.loads(ip_report_json)
        threat_report = json.loads(threat_report_json)
        system_report = json.loads(system_report_json)

        tool_dict = {
            "Classification":"SQL Injection (Remote Code Execution) Detected",
            "Payload":payload,
            "CVSSv3":cvss_score,
            "EPSS":epss_score,
            "EE":ee_score,
            "Risk R34p4r":risk_r34p3r_score,
            "IP Report":ip_report,
            "Threat Report":threat_report,
            "System Report":system_report
        }

        tool_output = json.dumps(tool_dict, indent=2)
        print(tool_output)
     
   
# payload = input("Enter payload: ")
# check_sqli(payload, tokenizer, model)

# Deleting File After Proxy Exit
def delete_file(filename):
    if os.path.exists(filename):
        os.remove(filename)
atexit.register(delete_file, "http_requests.txt")
atexit.register(delete_file, "client_ips.txt")

ip_file_pos = 0
file_position = 0

# Starting The Proxy
def start_proxy():
    mitm_command = subprocess.Popen("mitmdump --listen-host 0.0.0.0 -s proxy.py", shell=True)

try:

    print("Choose an Option: ")
    print("1. Input PCAP Capture File")
    print("2. Intercept Web Requests")

    option = input("Enter your choice (1/2): ")
    if option == "1":
        cap_file = input("Please Enter Name of PCAP File: ")
        capture = pyshark.FileCapture("./PCAP_Files/"+cap_file, display_filter='dns')

        packet_count = 0
        dns_exfil = None

        for packet in capture:
            dest_port = packet.udp.dstport
            if dest_port == "53":
                packet_count += 1

        for packet in capture:
            packet_size = packet.length
            protocol_num = None

            if hasattr(packet, 'udp'):
                protocol_num = 17
                tcp_flags = 0
                src_port = packet.udp.srcport
                dest_port = packet.udp.dstport

                data = {
                    'dpkts': packet_count,
                    'doctets': packet_size,
                    'srcport': src_port,
                    'dstport': dest_port,
                    'prot': protocol_num,
                    'tos': 0,
                    'tcp_flags': tcp_flags
                }
                
                # Converting Extracted Values into Features
                sample_df = pd.DataFrame([data])
                is_exfiltration = check_exfiltration(netflow_model, netflow_scaler, sample_df)
                if is_exfiltration:
                    output_data = {
                    "alert": "SQLi DNS Data Exfiltration Detected",
                    "c2_domain": packet.dns.qry_name,
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "src_port": src_port,
                    "dst_port": dest_port
                    }
                    print(json.dumps(output_data, indent=4))
                    dns_exfil = True
                    break;

        if not dns_exfil:    
            output_data = {
                "info": "No SQLi DNS Data Exfiltration Detected",
            }

            print(json.dumps(output_data, indent=4))
                
    elif option == "2":
        proxy_proc = threading.Thread(target=start_proxy)
        proxy_proc.start()

        while True:
            """
            *****************
            *****************
            
            REFERENCE:https://stackoverflow.com/questions/62776373/reading-file-continuously-and-appending-new-lines-to-list-python
    
            *****************
            *****************
            """
            with open('http_requests.txt', 'a+') as requests_file:
                requests_file.seek(file_position)
                for line in requests_file:
                    print(line)
                    line_stripped = line.strip()
                    check_sqli(line_stripped, tokenizer, model,line)
                file_position = requests_file.tell()

except KeyboardInterrupt:
    print("\nProxy Shutting Down. Exiting...")
    
