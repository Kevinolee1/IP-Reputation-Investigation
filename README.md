# IP-Reputation-Investigation
Built a Python tool that uses the VirusTotal API to investigate IP addresses and retrieve reputation results, location, network, ASN, and ownership information.
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/ae37816984d57e72acf7f01a7edcc513c13f8459/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120045.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/cadcba97e02bf49f2e9ba0fe24a2a33f167ea2dd/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120107.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/39bbba79a9f89bda2c78a47dd73216d6424afbaa/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120129.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/5e3e2738f1ce56f1f94b15a9a6887d861af17290/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120153.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/05cc2f4bde21cb4e77bdfe38287577a30aaad1c1/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20120220.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/5ca87989427dcb9b6540d48887ddca2b64205b1a/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125427.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/cdea42275ea13142b290dfe12c99f5186021dcfe/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125449.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/4a787ae68172b68b23af69d61222a42292add396/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125449.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/3bda20273da9c9e3a323ba8bd57bcbb0684c1de1/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125523.png)

Go to Vs Code and replace your existing main.py with this new function under your investigate_url() function:
def investigate_ip(ip_address):
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/069a4d99c1ea3a282a5d05f2091a19cc17d2685f/Screenshot%202026-08-31%20184002.png)

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
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/a1567798e39d3cdaadd20019a607cac99efc0e54/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125345.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/c4b9c4f3785360961fa2cd8ea53af3f6fbd5c8f3/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125409.png)
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/b4f8a4aee72cb756a364309ad3863f48fbb9e02b/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20125427.png)
Go to main.py delete the current main.py and type this code into it
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/9cd9e3a9ff1b19979a13a56abf54ee32f3b15367/Screenshot%202026-08-31%20184036.png)

    Press Ctrl+S to save
![Image alt](https://github.com/Kevinolee1/IP-Reputation-Investigation/blob/77c9198613af1dd3a582aa8ee2e9ddd48ce7110c/IP%20Reputation%20Investigation/Screenshot%202026-08-31%20130336.png)

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
