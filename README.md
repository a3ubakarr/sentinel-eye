# Sentinel Eye

A cloud-based network log analyzer that detects security threats, maps them to the MITRE ATT&CK framework, and explains them through an AI security assistant.

**Live demo:** https://sentinel-eye.streamlit.app

---

## Overview

Sentinel Eye lets you upload a Snort alert file, a Wireshark CSV export, or a Windows Event Log CSV export. It parses the file, runs rule-based threat detection, assigns a severity level to each finding, and maps it to the relevant MITRE ATT&CK technique. An AI assistant is available to explain any detected threat and suggest remediation steps in plain language.

The app supports three access levels — guest, registered user, and admin — each with a different scope of access.

---

## Features

### Authentication
- Sign up / sign in with hashed passwords (SHA-256)
- Guest mode — try the tool instantly with no account required
- Per-account password change

### Threat Detection
- Supports three log formats: Snort `alert.ids`, Wireshark CSV, Windows Event Log CSV
- Rule-based detection engine (port scans, brute force, SYN floods, telnet access, audit log clearing, and more)
- Each finding is assigned a severity level — Critical, High, Medium, or Low
- Every threat is mapped to a MITRE ATT&CK technique ID and name

### Remediation Guidance
- Each detected threat type comes with a short list of concrete remediation steps
- Incident Reports page groups threats by type with a sample raw log entry for context

### AI Security Assistant
- Powered by Groq's Llama 3.3 model
- Has full context of the threats detected in the current session
- Can explain a finding, answer MITRE ATT&CK questions, or walk through a fix

### Admin Dashboard
- Platform-wide statistics: total users, uploads, sessions, audit actions
- Signups-over-time and top-audit-action charts
- User management — enable, disable, or delete accounts
- Full audit log with action-type filtering and CSV export
- System status check (database connectivity)

### Built-in Guide
- Step-by-step instructions for exporting logs from Snort, Wireshark, and Windows Event Viewer
- Explanation of severity levels and how to use the AI assistant

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend / App | Python, Streamlit |
| Database | Supabase (PostgreSQL) |
| AI | Groq API (Llama 3.3 70B) |
| Visualization | Plotly |
| Hosting | Streamlit Community Cloud |

---

## Project Structure

```
sentinel-eye/
├── app.py          # Main Streamlit application and page routing
├── auth.py         # Sign up, sign in, password management
├── database.py     # Supabase queries (users, threats, uploads, audit log)
├── parser.py       # Log file parsing (Snort, Wireshark, Windows Events)
├── detector.py      # Rule-based threat detection engine
├── mitre.py         # MITRE ATT&CK technique mapping
├── chatbot.py        # Groq AI assistant integration
└── requirements.txt
```

---

## How Detection Works

1. **Parsing** — the uploaded file is identified by format and parsed into structured entries (timestamp, source/destination IP, protocol, port, raw text).
2. **Detection** — each entry is checked against a set of rules specific to its log type:
   - Snort: keyword matching against alert descriptions
   - Wireshark: protocol and port combination checks
   - Windows Events: matching against known Event IDs (e.g. `4625` failed logon, `1102` audit log cleared)
3. **Severity assignment** — every match is labeled Critical, High, Medium, or Low.
4. **MITRE mapping** — the threat description is matched against a local MITRE ATT&CK lookup table to attach a technique ID and name.

Detection is fully rule-based and deterministic. The AI assistant is used only to explain results, not to make detection decisions.

---

## Data Isolation

Every browser session is assigned a UUID. All uploads, detected threats, and chat history are scoped to that session ID. Registered users' data persists across sessions tied to their account; guest data is scoped to the browser session only. Admins can view aggregated platform statistics but not other users' individual threat data.

---

## Setup (Local Development)

```bash
git clone https://github.com/a3ubakarr/sentinel-eye.git
cd sentinel-eye
pip install -r requirements.txt
```

Create a `.env` file with:

```
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_secret_key
GROQ_API_KEY=your_groq_api_key
APP_BASE_URL=http://localhost:8501
```

Run the app:

```bash
streamlit run app.py
```

On first run, you'll be prompted to create the admin account.

---

## Author

**Malik Abubakar**
BS Cybersecurity, University of Management and Technology (UMT), Lahore

- GitHub: [github.com/a3ubakarr](https://github.com/a3ubakarr)
- LinkedIn: [linkedin.com/in/malik-abubakar-cyber](https://linkedin.com/in/malik-abubakar-cyber)
- Email: malikabubakar.cyber@gmail.com
