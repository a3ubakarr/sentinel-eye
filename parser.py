import re
import io
import csv
from datetime import datetime


MAX_FILE_SIZE_MB = 20
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


def check_file_size(file_bytes: bytes) -> bool:
    """Returns True if file is within the allowed size limit."""
    return len(file_bytes) <= MAX_FILE_SIZE_BYTES


def detect_log_type(filename: str, content: str) -> str:
    """
    Tries to detect the log type from filename and content.
    Returns 'snort', 'wireshark', 'windows_events', or 'unknown'.
    """
    filename_lower = filename.lower()

    if "alert" in filename_lower or filename_lower.endswith(".ids"):
        return "snort"

    if filename_lower.endswith(".csv"):
        first_line = content.strip().split("\n")[0].lower()
        # Wireshark CSV exports always have these columns
        if "protocol" in first_line and "source" in first_line and "destination" in first_line:
            return "wireshark"
        # Windows event log CSV exports have these columns
        if "event id" in first_line or "eventid" in first_line or "task category" in first_line:
            return "windows_events"

    if "[**]" in content:
        return "snort"

    return "unknown"


# ---------------------------------------------------------------------------
# Snort parser
# ---------------------------------------------------------------------------

def parse_snort(content: str) -> list:
    """
    Parses Snort fast-alert format lines.
    Each alert line looks like:
    06/11-23:30:12.648105  [**] [1:1003:1] Nmap Port Scan Detected [**] [Priority: 0] {TCP} 192.168.1.1:54821 -> 192.168.1.10:445
    Returns a list of parsed alert dicts.
    """
    alerts = []
    lines = content.splitlines()

    for line in lines:
        line = line.strip()
        if "[**]" not in line:
            continue

        try:
            parts = line.split("[**]")
            if len(parts) < 2:
                continue

            timestamp = parts[0].strip().lstrip("-").strip()
            middle = parts[1].strip()
            remainder = parts[2].strip() if len(parts) > 2 else ""

            # Extract SID and message from middle section
            sid, message = "", middle
            sid_match = re.search(r"\[(\d+:\d+:\d+)\]", middle)
            if sid_match:
                sid = sid_match.group(1)
                message = middle[sid_match.end():].strip()

            # Extract protocol and IP addresses from remainder
            protocol, src_ip, dst_ip, src_port, dst_port = "", "", "", "", ""
            proto_match = re.search(r"\{(\w+)\}", remainder)
            if proto_match:
                protocol = proto_match.group(1)

            ip_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s*->\s*(\d+\.\d+\.\d+\.\d+)(?::(\d+))?",
                remainder
            )
            if ip_match:
                src_ip = ip_match.group(1)
                src_port = ip_match.group(2) or ""
                dst_ip = ip_match.group(3)
                dst_port = ip_match.group(4) or ""

            if not message:
                continue

            alerts.append({
                "timestamp": timestamp,
                "raw_sid": sid,
                "description": message,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": dst_port,
                "raw_entry": line,
            })

        except Exception:
            continue

    return alerts


# ---------------------------------------------------------------------------
# Wireshark CSV parser
# ---------------------------------------------------------------------------

def parse_wireshark(content: str) -> list:
    """
    Parses Wireshark CSV exports.
    Expected columns: No., Time, Source, Destination, Protocol, Length, Info
    Returns a list of parsed packet dicts.
    """
    packets = []
    reader = csv.DictReader(io.StringIO(content))

    # Normalize column names — Wireshark uses different capitalizations
    for row in reader:
        normalized = {k.strip().lower(): v.strip() for k, v in row.items()}

        src = normalized.get("source", normalized.get("src", ""))
        dst = normalized.get("destination", normalized.get("dst", ""))
        protocol = normalized.get("protocol", normalized.get("proto", ""))
        info = normalized.get("info", "")
        length = normalized.get("length", normalized.get("len", ""))
        time = normalized.get("time", "")

        if not src and not dst:
            continue

        packets.append({
            "timestamp": time,
            "description": info,
            "protocol": protocol,
            "src_ip": _extract_ip(src),
            "dst_ip": _extract_ip(dst),
            "port": _extract_port(dst) or _extract_port(info),
            "raw_entry": str(dict(normalized)),
        })

    return packets


def _extract_ip(value: str) -> str:
    """Pulls an IPv4 address out of a string."""
    match = re.search(r"\d+\.\d+\.\d+\.\d+", value)
    return match.group(0) if match else value


def _extract_port(value: str) -> str:
    """Tries to extract a port number from strings like '192.168.1.1:80' or 'port 80'."""
    colon_match = re.search(r":(\d+)$", value)
    if colon_match:
        return colon_match.group(1)
    port_match = re.search(r"port\s+(\d+)", value, re.IGNORECASE)
    if port_match:
        return port_match.group(1)
    return ""


# ---------------------------------------------------------------------------
# Windows Event Log CSV parser
# ---------------------------------------------------------------------------

# Event IDs we care about and their human-readable descriptions
WINDOWS_EVENT_IDS = {
    "4624": ("Successful logon", "LOW"),
    "4625": ("Failed logon attempt", "HIGH"),
    "4634": ("Account logoff", "LOW"),
    "4647": ("User-initiated logoff", "LOW"),
    "4648": ("Logon with explicit credentials", "MEDIUM"),
    "4672": ("Special privileges assigned to new logon", "HIGH"),
    "4688": ("New process created", "MEDIUM"),
    "4697": ("Service installed on system", "HIGH"),
    "4698": ("Scheduled task created", "MEDIUM"),
    "4702": ("Scheduled task updated", "MEDIUM"),
    "4719": ("System audit policy changed", "HIGH"),
    "4720": ("User account created", "HIGH"),
    "4722": ("User account enabled", "MEDIUM"),
    "4724": ("Password reset attempt", "MEDIUM"),
    "4725": ("User account disabled", "MEDIUM"),
    "4726": ("User account deleted", "HIGH"),
    "4728": ("Member added to security-enabled global group", "HIGH"),
    "4732": ("Member added to security-enabled local group", "HIGH"),
    "4740": ("User account locked out", "HIGH"),
    "4756": ("Member added to universal security group", "HIGH"),
    "4776": ("Credential validation attempt", "MEDIUM"),
    "4798": ("User's local group membership enumerated", "MEDIUM"),
    "4799": ("Security-enabled local group membership enumerated", "MEDIUM"),
    "7034": ("Service crashed unexpectedly", "MEDIUM"),
    "7045": ("New service installed", "HIGH"),
    "1102": ("Audit log cleared", "CRITICAL"),
    "4657": ("Registry value modified", "MEDIUM"),
    "5140": ("Network share accessed", "MEDIUM"),
    "5156": ("Network connection allowed", "LOW"),
    "5157": ("Network connection blocked", "MEDIUM"),
}


def parse_windows_events(content: str) -> list:
    """
    Parses Windows Event Log CSV exports.
    Handles exports from Event Viewer and common SIEM tools.
    Returns a list of parsed event dicts.
    """
    events = []
    reader = csv.DictReader(io.StringIO(content))

    for row in reader:
        normalized = {k.strip().lower(): v.strip() for k, v in row.items()}

        # Try common column name variations for event ID
        event_id = (
            normalized.get("event id") or
            normalized.get("eventid") or
            normalized.get("id") or
            normalized.get("event_id") or
            ""
        ).strip()

        # Skip rows we do not have a mapping for
        if event_id not in WINDOWS_EVENT_IDS:
            continue

        description, severity = WINDOWS_EVENT_IDS[event_id]

        timestamp = (
            normalized.get("date and time") or
            normalized.get("datetime") or
            normalized.get("time created") or
            normalized.get("timestamp") or
            ""
        )

        computer = normalized.get("computer", normalized.get("computer name", ""))
        source = normalized.get("source", normalized.get("source name", ""))
        user = normalized.get("user", normalized.get("account name", ""))
        task = normalized.get("task category", normalized.get("task", ""))

        events.append({
            "timestamp": timestamp,
            "description": f"Event {event_id}: {description}",
            "protocol": "Windows Event",
            "src_ip": computer,
            "dst_ip": "",
            "port": event_id,
            "raw_entry": f"EventID={event_id} | User={user} | Source={source} | Task={task}",
            "event_id": event_id,
            "severity_hint": severity,
        })

    return events


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def parse_log_file(filename: str, file_bytes: bytes) -> dict:
    """
    Main function called by the app.
    Accepts raw file bytes, detects type, parses, and returns structured results.

    Returns:
        {
            "log_type": str,
            "entries": list,
            "error": str or None,
            "total_lines": int,
        }
    """
    if not check_file_size(file_bytes):
        return {
            "log_type": "unknown",
            "entries": [],
            "error": f"File exceeds the {MAX_FILE_SIZE_MB}MB limit.",
            "total_lines": 0,
        }

    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return {
            "log_type": "unknown",
            "entries": [],
            "error": "Could not read file. Make sure it is a plain text or CSV file.",
            "total_lines": 0,
        }

    log_type = detect_log_type(filename, content)

    if log_type == "snort":
        entries = parse_snort(content)
    elif log_type == "wireshark":
        entries = parse_wireshark(content)
    elif log_type == "windows_events":
        entries = parse_windows_events(content)
    else:
        return {
            "log_type": "unknown",
            "entries": [],
            "error": "Could not detect log type. Supported formats: Snort alert.ids, Wireshark CSV, Windows Event Log CSV.",
            "total_lines": 0,
        }

    return {
        "log_type": log_type,
        "entries": entries,
        "error": None,
        "total_lines": len(content.splitlines()),
    }