# MITRE ATT&CK mappings for threats detected by Sentinel Eye.
# Each entry maps a threat keyword pattern to a technique ID and name.
# The detector uses these to enrich every detected threat automatically.

MITRE_MAP = [
    # Network scanning and reconnaissance
    {
        "keywords": ["port scan", "nmap", "syn scan", "stealth scan", "service scan"],
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Reconnaissance",
    },
    {
        "keywords": ["ping sweep", "icmp", "host discovery", "ping flood"],
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
    },
    # Credential attacks
    {
        "keywords": ["brute force", "failed login", "4625", "authentication failure",
                     "invalid password", "bad password", "logon failure"],
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["ftp brute", "ftp login", "ftp user", "530 login"],
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing (FTP)",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["ssh brute", "ssh login failed", "ssh authentication"],
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying (SSH)",
        "tactic": "Credential Access",
    },
    # Remote access and lateral movement
    {
        "keywords": ["telnet", "port 23"],
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
    },
    {
        "keywords": ["rdp", "remote desktop", "port 3389", "4624", "logon type 10"],
        "id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
    },
    {
        "keywords": ["smb", "port 445", "port 139", "netbios"],
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    # Web and application attacks
    {
        "keywords": ["sql injection", "sqli", "select from", "union select", "1=1"],
        "id": "T1190",
        "name": "Exploit Public-Facing Application: SQL Injection",
        "tactic": "Initial Access",
    },
    {
        "keywords": ["xss", "cross site", "script alert", "<script>"],
        "id": "T1059.007",
        "name": "Command and Scripting: JavaScript",
        "tactic": "Execution",
    },
    {
        "keywords": ["directory traversal", "../", "path traversal", "etc/passwd"],
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    {
        "keywords": ["suspicious http", "http keyword", "cmd.exe", "cmd http", "/cmd"],
        "id": "T1059.003",
        "name": "Command and Scripting: Windows Command Shell",
        "tactic": "Execution",
    },
    # Denial of service
    {
        "keywords": ["syn flood", "dos attempt", "ddos", "flood", "denial of service"],
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
    },
    # Privilege escalation and account management
    {
        "keywords": ["privilege escalation", "4672", "special privileges", "admin logon"],
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
    },
    {
        "keywords": ["new user", "user created", "4720", "account created"],
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
    },
    {
        "keywords": ["account locked", "4740", "lockout"],
        "id": "T1110",
        "name": "Brute Force: Account Lockout",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["group changed", "4728", "4732", "4756", "group membership"],
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
    },
    # Malware and execution
    {
        "keywords": ["malware", "trojan", "backdoor", "reverse shell", "payload"],
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    {
        "keywords": ["service installed", "7045", "new service"],
        "id": "T1543.003",
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence",
    },
    # Data and exfiltration
    {
        "keywords": ["data exfil", "large upload", "unusual outbound", "ftp upload"],
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    # Suspicious ports
    {
        "keywords": ["port 4444", "metasploit", "meterpreter"],
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
    },
    {
        "keywords": ["port 6667", "irc", "botnet"],
        "id": "T1219",
        "name": "Remote Access Tools",
        "tactic": "Command and Control",
    },
]


def get_mitre_mapping(threat_description: str) -> dict:
    """
    Returns the best matching MITRE technique for a given threat description.
    Matches by checking if any keyword appears in the lowercased description.
    Returns empty strings if no match is found.
    """
    description_lower = threat_description.lower()

    for entry in MITRE_MAP:
        for keyword in entry["keywords"]:
            if keyword in description_lower:
                return {
                    "mitre_id": entry["id"],
                    "mitre_name": entry["name"],
                    "mitre_tactic": entry["tactic"],
                }

    return {
        "mitre_id": "",
        "mitre_name": "",
        "mitre_tactic": "",
    }


def get_all_tactics() -> list:
    """Returns a deduplicated list of all tactics in the map."""
    seen = set()
    tactics = []
    for entry in MITRE_MAP:
        if entry["tactic"] not in seen:
            tactics.append(entry["tactic"])
            seen.add(entry["tactic"])
    return tactics


def get_techniques_by_tactic(tactic: str) -> list:
    """Returns all techniques for a given tactic."""
    return [e for e in MITRE_MAP if e["tactic"] == tactic]