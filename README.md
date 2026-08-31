# IP-Reputation-Investigation
Built a Python tool that uses the VirusTotal API to investigate IP addresses and retrieve reputation results, location, network, ASN, and ownership information.
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/ae37816984d57e72acf7f01a7edcc513c13f8459/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120045.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/cadcba97e02bf49f2e9ba0fe24a2a33f167ea2dd/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120107.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/39bbba79a9f89bda2c78a47dd73216d6424afbaa/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120129.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/5e3e2738f1ce56f1f94b15a9a6887d861af17290/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120153.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/05cc2f4bde21cb4e77bdfe38287577a30aaad1c1/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120220.png)
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
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/5c3f221b045603216b52b79ad9d1d8a2f88a24eb/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120627.png)

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
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/de10eaca46d46d13fb81af47bde82a80bbff8b81/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20122700.png)
Go to AbuseIPDB and copy your API Key
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/0515aaf599879e4444e36e20af5f67905ed60408/README.md)
Then open your .env file in Vs Code and add a second line
ABUSEIPDB_API_KEY=YOUR_REAL_ABUSEIPDB_API_KEY

Your .env should now look like:

VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/24c4de171c94914d3bdb3b31647ddcb1f49cf996/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125256.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/326ec8e1ed20c6027500e1a1dd4276ad3b42067b/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125323.png)
Go to main.py delete the current main.py and type this code into it
import os
import re
import ipaddress
import requests
import base64

from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("VT_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

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

    domain_pattern = (
        r"^(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}$"
    )

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
    api_url = (
        f"https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip_address}"
    )

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
        print(
            f"IP lookup failed. "
            f"Status Code: {response.status_code}"
        )
        print(response.text)


def investigate_ip_abuseipdb(ip_address):
    api_url = "https://api.abuseipdb.com/api/v2/check"

    headers_abuse = {
        "Key": abuseipdb_api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    response = requests.get(
        api_url,
        headers=headers_abuse,
        params=params
    )

    if response.status_code == 200:
        data = response.json()["data"]

        print()
        print("AbuseIPDB Results")
        print("------------------")
        print(
            f"Abuse Confidence Score: "
            f"{data.get('abuseConfidenceScore', 0)}%"
        )
        print(f"Total Reports: {data.get('totalReports', 0)}")
        print(f"Country: {data.get('countryCode', 'Unknown')}")
        print(f"ISP: {data.get('isp', 'Unknown')}")
        print(f"Domain: {data.get('domain', 'Unknown')}")
        print(f"Usage Type: {data.get('usageType', 'Unknown')}")

    else:
        print()
        print(
            f"AbuseIPDB lookup failed. "
            f"Status Code: {response.status_code}"
        )
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
    investigate_ip_abuseipdb(ioc)

else:
    print()
    print("This IOC type is not supported in this lab yet.")
    Press Ctrl+S to save

 Go back to PowerShell and type python main.py
Test again with: 8.8.8.8
You should get a output similar to 

VirusTotal
Malicious:  0
Suspicious: 0
Harmless:   53
Undetected: 38

AbuseIPDB
Abuse Confidence Score: 0%
Total Reports: 195
Country: US
ISP: Google LLC
Domain: google.com
Usage Type: Content Delivery Network 
