# IP-Reputation-Investigation
Built a Python tool that uses the VirusTotal API to investigate IP addresses and retrieve reputation results, location, network, ASN, and ownership information.

Go to Vs Code and replace yoy existing main.py with this new function under your investigate_url() function:
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
