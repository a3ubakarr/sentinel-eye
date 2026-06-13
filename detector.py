from mitre import get_mitre_mapping


# Severity levels in order — used for comparisons
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def get_higher_severity(a: str, b: str) -> str:
    """Returns whichever severity level is higher."""
    a_index = SEVERITY_ORDER.index(a) if a in SEVERITY_ORDER else 0
    b_index = SEVERITY_ORDER.index(b) if b in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[max(a_index, b_index)]


# ---------------------------------------------------------------------------
# Snort threat rules
# Each rule has a list of patterns to match against the description,
# a base severity, and a human-readable threat type label.
# ---------------------------------------------------------------------------

SNORT_RULES = [
    {
        "patterns": ["nmap", "port scan", "syn scan", "stealth scan"],
        "threat_type": "Port Scan Detected",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["syn flood", "dos attempt", "denial of service", "flood"],
        "threat_type": "SYN Flood / DoS Attempt",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["telnet", "port 23"],
        "threat_type": "Telnet Access Attempt",
        "severity": "HIGH",
    },
    {
        "patterns": ["ftp brute", "ftp login", "ftp user", "530"],
        "threat_type": "FTP Brute Force Attempt",
        "severity": "HIGH",
    },
    {
        "patterns": ["sql injection", "sqli", "union select", "1=1", "or 1"],
        "threat_type": "SQL Injection Attempt",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["suspicious http", "http keyword", "cmd.exe", "/cmd"],
        "threat_type": "Suspicious HTTP Payload",
        "severity": "HIGH",
    },
    {
        "patterns": ["icmp", "ping detected", "ping sweep"],
        "threat_type": "ICMP Ping Sweep",
        "severity": "MEDIUM",
    },
    {
        "patterns": ["xss", "cross site", "<script>"],
        "threat_type": "Cross-Site Scripting Attempt",
        "severity": "HIGH",
    },
    {
        "patterns": ["backdoor", "reverse shell", "meterpreter", "metasploit"],
        "threat_type": "Backdoor / Reverse Shell",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["port 4444"],
        "threat_type": "Suspicious Port (Metasploit Default)",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["directory traversal", "../", "etc/passwd"],
        "threat_type": "Directory Traversal Attempt",
        "severity": "HIGH",
    },
]


# ---------------------------------------------------------------------------
# Wireshark threat rules
# Applied against protocol, port, and info/description fields.
# ---------------------------------------------------------------------------

WIRESHARK_RULES = [
    {
        "patterns": ["syn", "port scan"],
        "protocols": ["tcp"],
        "ports": [],
        "threat_type": "Potential Port Scan",
        "severity": "HIGH",
    },
    {
        "patterns": [],
        "protocols": ["tcp"],
        "ports": ["23"],
        "threat_type": "Telnet Traffic Detected",
        "severity": "HIGH",
    },
    {
        "patterns": [],
        "protocols": ["tcp"],
        "ports": ["4444", "1337", "31337"],
        "threat_type": "Suspicious Port Traffic",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["sql", "union select", "1=1"],
        "protocols": ["tcp", "http"],
        "ports": ["80", "443", "8080"],
        "threat_type": "SQL Injection Attempt",
        "severity": "CRITICAL",
    },
    {
        "patterns": ["icmp", "echo"],
        "protocols": ["icmp"],
        "ports": [],
        "threat_type": "ICMP Activity",
        "severity": "LOW",
    },
    {
        "patterns": ["arp", "who has", "is at"],
        "protocols": ["arp"],
        "ports": [],
        "threat_type": "ARP Activity (Possible Spoofing)",
        "severity": "MEDIUM",
    },
    {
        "patterns": [],
        "protocols": ["tcp"],
        "ports": ["445", "139"],
        "threat_type": "SMB Traffic Detected",
        "severity": "MEDIUM",
    },
    {
        "patterns": [],
        "protocols": ["tcp"],
        "ports": ["3389"],
        "threat_type": "RDP Traffic Detected",
        "severity": "MEDIUM",
    },
    {
        "patterns": ["flood", "retransmission", "duplicate ack"],
        "protocols": ["tcp"],
        "ports": [],
        "threat_type": "TCP Anomaly / Possible Flood",
        "severity": "HIGH",
    },
    {
        "patterns": ["dns"],
        "protocols": ["dns"],
        "ports": ["53"],
        "threat_type": "DNS Query",
        "severity": "LOW",
    },
]


# ---------------------------------------------------------------------------
# Windows Event threat rules
# Already parsed with severity hints — we refine them here.
# ---------------------------------------------------------------------------

HIGH_RISK_EVENT_IDS = {"1102", "4625", "4672", "4697", "4720", "4726", "4728",
                       "4732", "4740", "4756", "7045", "4719"}

MEDIUM_RISK_EVENT_IDS = {"4648", "4688", "4698", "4702", "4724", "4776",
                          "4798", "4799", "5157", "4657", "5140"}

CRITICAL_COMBINATIONS = [
    # Audit log cleared is always critical
    {"event_ids": {"1102"}, "threat_type": "Audit Log Cleared", "severity": "CRITICAL"},
    # New service + special privileges in same session = likely persistence
    {"event_ids": {"7045", "4672"}, "threat_type": "Service Install with Elevated Privileges", "severity": "CRITICAL"},
]


def _match_snort_rule(description: str) -> dict | None:
    desc_lower = description.lower()
    for rule in SNORT_RULES:
        for pattern in rule["patterns"]:
            if pattern in desc_lower:
                return rule
    return None


def _match_wireshark_rule(description: str, protocol: str, port: str) -> dict | None:
    desc_lower = description.lower()
    proto_lower = protocol.lower()
    for rule in WIRESHARK_RULES:
        protocol_match = not rule["protocols"] or proto_lower in rule["protocols"]
        port_match = not rule["ports"] or port in rule["ports"]
        pattern_match = not rule["patterns"] or any(p in desc_lower for p in rule["patterns"])
        if protocol_match and (port_match or pattern_match):
            return rule
    return None


# ---------------------------------------------------------------------------
# Main detection functions
# ---------------------------------------------------------------------------

def detect_snort_threats(entries: list, session_id: str, upload_id: str) -> list:
    """
    Runs detection rules against parsed Snort entries.
    Returns a list of threat dicts ready to be saved to the database.
    """
    threats = []

    for entry in entries:
        description = entry.get("description", "")
        rule = _match_snort_rule(description)

        if not rule:
            # Still save unrecognized alerts — they came from Snort so they matter
            rule = {
                "threat_type": "Snort Alert",
                "severity": "MEDIUM",
            }

        mitre = get_mitre_mapping(f"{rule['threat_type']} {description}")

        threats.append({
            "session_id": session_id,
            "upload_id": upload_id,
            "timestamp": entry.get("timestamp", ""),
            "threat_type": rule["threat_type"],
            "description": description,
            "severity": rule["severity"],
            "src_ip": entry.get("src_ip", ""),
            "dst_ip": entry.get("dst_ip", ""),
            "protocol": entry.get("protocol", ""),
            "port": entry.get("port", ""),
            "raw_entry": entry.get("raw_entry", ""),
            "mitre_id": mitre["mitre_id"],
            "mitre_name": mitre["mitre_name"],
        })

    return threats


def detect_wireshark_threats(entries: list, session_id: str, upload_id: str) -> list:
    """
    Runs detection rules against parsed Wireshark packets.
    Only flags entries that match a known suspicious pattern.
    """
    threats = []

    for entry in entries:
        description = entry.get("description", "")
        protocol = entry.get("protocol", "")
        port = entry.get("port", "")
        rule = _match_wireshark_rule(description, protocol, port)

        if not rule:
            continue

        mitre = get_mitre_mapping(f"{rule['threat_type']} {description}")

        threats.append({
            "session_id": session_id,
            "upload_id": upload_id,
            "timestamp": entry.get("timestamp", ""),
            "threat_type": rule["threat_type"],
            "description": description,
            "severity": rule["severity"],
            "src_ip": entry.get("src_ip", ""),
            "dst_ip": entry.get("dst_ip", ""),
            "protocol": protocol,
            "port": port,
            "raw_entry": entry.get("raw_entry", ""),
            "mitre_id": mitre["mitre_id"],
            "mitre_name": mitre["mitre_name"],
        })

    return threats


def detect_windows_threats(entries: list, session_id: str, upload_id: str) -> list:
    """
    Runs detection against parsed Windows Event Log entries.
    Uses event IDs and severity hints from the parser.
    """
    threats = []
    seen_event_ids = set()

    for entry in entries:
        event_id = entry.get("event_id", "")
        description = entry.get("description", "")
        severity_hint = entry.get("severity_hint", "MEDIUM")

        # Use the parser's severity hint as the base
        severity = severity_hint

        # Escalate severity for high-risk event IDs
        if event_id in HIGH_RISK_EVENT_IDS:
            severity = get_higher_severity(severity, "HIGH")
        if event_id in CRITICAL_COMBINATIONS[0]["event_ids"]:
            severity = "CRITICAL"

        seen_event_ids.add(event_id)
        mitre = get_mitre_mapping(description)

        threats.append({
            "session_id": session_id,
            "upload_id": upload_id,
            "timestamp": entry.get("timestamp", ""),
            "threat_type": _windows_threat_type(event_id, description),
            "description": description,
            "severity": severity,
            "src_ip": entry.get("src_ip", ""),
            "dst_ip": "",
            "protocol": "Windows Event",
            "port": event_id,
            "raw_entry": entry.get("raw_entry", ""),
            "mitre_id": mitre["mitre_id"],
            "mitre_name": mitre["mitre_name"],
        })

    # Check for critical combinations across the whole file
    for combo in CRITICAL_COMBINATIONS:
        if combo["event_ids"].issubset(seen_event_ids):
            mitre = get_mitre_mapping(combo["threat_type"])
            threats.append({
                "session_id": session_id,
                "upload_id": upload_id,
                "timestamp": "",
                "threat_type": combo["threat_type"],
                "description": f"Multiple high-risk events detected together: {', '.join(combo['event_ids'])}",
                "severity": combo["severity"],
                "src_ip": "",
                "dst_ip": "",
                "protocol": "Windows Event",
                "port": "",
                "raw_entry": "",
                "mitre_id": mitre["mitre_id"],
                "mitre_name": mitre["mitre_name"],
            })

    return threats


def _windows_threat_type(event_id: str, description: str) -> str:
    """Returns a clean threat type label for a Windows event."""
    # Use the description from parser — it already has the event name
    if "Event" in description and ":" in description:
        return description.split(":", 1)[1].strip()
    return description


def run_detection(log_type: str, entries: list, session_id: str, upload_id: str) -> list:
    """
    Unified entry point called by the app after parsing.
    Routes to the correct detector based on log type.
    """
    if log_type == "snort":
        return detect_snort_threats(entries, session_id, upload_id)
    elif log_type == "wireshark":
        return detect_wireshark_threats(entries, session_id, upload_id)
    elif log_type == "windows_events":
        return detect_windows_threats(entries, session_id, upload_id)
    else:
        return []