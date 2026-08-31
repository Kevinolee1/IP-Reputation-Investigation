# IP-Reputation-Investigation
Built a Python tool that uses the VirusTotal API to investigate IP addresses and retrieve reputation results, location, network, ASN, and ownership information.

Go to Vs Code and replace yoy existing main.py with this new function under your investigate_url() function:
def investigate_ip(ip_address):

import os
import re
import ipaddress
import requests
import base64

from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": api_key
}


def detect_ioc_type(ioc):
    ioc = ioc.strip()

    if re.fullmatch(r"[A-Fa-f0-9]{64}", ioc):
        return "SHA-256 Hash"

    try:
        ipaddress.ip_address(ioc)
        return "IP Address"
    except ValueError:
        pass

    parsed = urlparse(ioc)

    if parsed.scheme in ("http", "https") and parsed.netloc:
        return "URL"

    domain_pattern = r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"

    if re.fullmatch(domain_pattern, ioc):
        return "Domain"

    return "Unknown"


def print_results(stats):
    print()
    print("VirusTotal Results")
    print("------------------")
    print(f"Malicious:  {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Harmless:   {stats.get('harmless', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")


def investigate_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print_results(stats)

    else:
        print(f"Lookup failed. Status Code: {response.status_code}")
        print(response.text)


def investigate_url(target_url):
    url_id = base64.urlsafe_b64encode(
        target_url.encode()
    ).decode().strip("=")

    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print_results(stats)

    else:
        print(f"Lookup failed. Status Code: {response.status_code}")
        print(response.text)


def investigate_ip(ip_address):
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        stats = attributes["last_analysis_stats"]

        print()
        print("VirusTotal IP Results")
        print("---------------------")
        print(f"Malicious:  {stats.get('malicious', 0)}")
        print(f"Suspicious: {stats.get('suspicious', 0)}")
        print(f"Harmless:   {stats.get('harmless', 0)}")
        print(f"Undetected: {stats.get('undetected', 0)}")

        print()
        print("IP Information")
        print("--------------")
        print(f"Country: {attributes.get('country', 'Unknown')}")
        print(f"Network: {attributes.get('network', 'Unknown')}")
        print(f"ASN: {attributes.get('asn', 'Unknown')}")
        print(f"Owner: {attributes.get('as_owner', 'Unknown')}")

    else:
        print()
        print(f"IP lookup failed. Status Code: {response.status_code}")
        print(response.text)


ioc = input("Enter IOC to investigate: ").strip()

ioc_type = detect_ioc_type(ioc)

print()
print("SOC IOC Investigation Tool")
print("--------------------------")
print(f"IOC:  {ioc}")
print(f"Type: {ioc_type}")


if ioc_type == "Domain":
    investigate_domain(ioc)

elif ioc_type == "URL":
    investigate_url(ioc)

elif ioc_type == "IP Address":
    investigate_ip(ioc)

else:
    print()
    print("This IOC type is not supported in this lab yet.")
 
    Press Ctrl+S to save
    
    Go to PowerShell and type python main.py
    When it asks Enter IOC to investigate:
    use this safe test IP: 8.8.8.8

    You should get output resembling

    SOC IOC Investigation Tool
--------------------------
IOC:  8.8.8.8
Type: IP Address

VirusTotal IP Results
---------------------
Malicious:  0
Suspicious: 0
Harmless:   ...
Undetected: ...

IP Information
--------------
Country: US
Network: ...
ASN: ...
Owner: GOOGLE
