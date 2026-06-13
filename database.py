import os
import hashlib
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()


def get_client() -> Client:
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")
    if not url or not key:
        raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    return create_client(url, key)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Setup — runs once on first launch to create admin account
# ---------------------------------------------------------------------------

def is_first_run(db: Client) -> bool:
    # If no users exist, this is the first run
    response = db.table("users").select("id").limit(1).execute()
    return len(response.data) == 0


def create_admin(db: Client, username: str, full_name: str, email: str, password: str):
    db.table("users").insert({
        "username": username.strip().lower(),
        "full_name": full_name.strip(),
        "email": email.strip().lower(),
        "password": hash_password(password),
        "is_admin": True,
        "is_verified": True,
    }).execute()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def get_user_by_credentials(db: Client, username: str, password: str):
    response = db.table("users").select("*").eq(
        "username", username.strip().lower()
    ).eq(
        "password", hash_password(password)
    ).execute()
    return response.data[0] if response.data else None


def get_user_by_email(db: Client, email: str):
    response = db.table("users").select("*").eq(
        "email", email.strip().lower()
    ).execute()
    return response.data[0] if response.data else None


def get_user_by_id(db: Client, user_id: str):
    response = db.table("users").select("*").eq("id", user_id).execute()
    return response.data[0] if response.data else None


def username_exists(db: Client, username: str) -> bool:
    response = db.table("users").select("id").eq(
        "username", username.strip().lower()
    ).execute()
    return len(response.data) > 0


def email_exists(db: Client, email: str) -> bool:
    response = db.table("users").select("id").eq(
        "email", email.strip().lower()
    ).execute()
    return len(response.data) > 0


def create_user(db: Client, username: str, full_name: str, email: str, password: str) -> str:
    response = db.table("users").insert({
        "username": username.strip().lower(),
        "full_name": full_name.strip(),
        "email": email.strip().lower(),
        "password": hash_password(password),
        "is_admin": False,
        "is_verified": False,
    }).execute()
    return response.data[0]["id"]


def verify_user_email(db: Client, user_id: str):
    db.table("users").update({"is_verified": True}).eq("id", user_id).execute()


def update_password(db: Client, user_id: str, new_password: str):
    db.table("users").update({
        "password": hash_password(new_password)
    }).eq("id", user_id).execute()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def create_session(db: Client, session_id: str, user_id: str = None):
    db.table("sessions").insert({
        "session_id": session_id,
        "user_id": user_id,
    }).execute()


def session_exists(db: Client, session_id: str) -> bool:
    response = db.table("sessions").select("session_id").eq(
        "session_id", session_id
    ).execute()
    return len(response.data) > 0


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------

def save_upload(db: Client, session_id: str, filename: str, log_type: str) -> str:
    response = db.table("uploads").insert({
        "session_id": session_id,
        "filename": filename,
        "log_type": log_type,
    }).execute()
    return response.data[0]["id"]


def get_uploads(db: Client, session_id: str) -> list:
    response = db.table("uploads").select("*").eq(
        "session_id", session_id
    ).order("uploaded_at", desc=True).execute()
    return response.data


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------

def save_threats(db: Client, threats: list):
    if not threats:
        return
    db.table("threats").insert(threats).execute()


def get_threats(db: Client, session_id: str) -> list:
    response = db.table("threats").select(
        "*, uploads(filename, log_type)"
    ).eq("session_id", session_id).order(
        "created_at", desc=True
    ).execute()
    return response.data


def get_threat_summary(db: Client, session_id: str) -> dict:
    response = db.table("threats").select("severity").eq(
        "session_id", session_id
    ).execute()

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
    for row in response.data:
        sev = row["severity"]
        if sev in summary:
            summary[sev] += 1
            summary["total"] += 1
    return summary


def delete_session_threats(db: Client, session_id: str):
    db.table("threats").delete().eq("session_id", session_id).execute()
    db.table("uploads").delete().eq("session_id", session_id).execute()


# ---------------------------------------------------------------------------
# Chat history
# ---------------------------------------------------------------------------

def save_message(db: Client, session_id: str, role: str, content: str):
    db.table("chat_history").insert({
        "session_id": session_id,
        "role": role,
        "content": content,
    }).execute()


def get_chat_history(db: Client, session_id: str, limit: int = 20) -> list:
    response = db.table("chat_history").select("role, content").eq(
        "session_id", session_id
    ).order("sent_at", desc=True).limit(limit).execute()
    # Reverse so oldest message is first — required for Groq API context
    return list(reversed(response.data))


def clear_chat_history(db: Client, session_id: str):
    db.table("chat_history").delete().eq("session_id", session_id).execute()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_action(db: Client, action: str, detail: str = None,
               session_id: str = None, status: str = "SUCCESS"):
    db.table("audit_log").insert({
        "session_id": session_id,
        "action": action,
        "detail": detail,
        "status": status,
    }).execute()


def get_audit_log(db: Client, session_id: str = None, limit: int = 100) -> list:
    query = db.table("audit_log").select("*").order(
        "logged_at", desc=True
    ).limit(limit)
    if session_id:
        query = query.eq("session_id", session_id)
    return query.execute().data


# ---------------------------------------------------------------------------
# Admin — all users view
# ---------------------------------------------------------------------------

def get_all_users(db: Client) -> list:
    response = db.table("users").select(
        "id, username, full_name, email, is_admin, is_verified, created_at"
    ).order("created_at", desc=True).execute()
    return response.data


def delete_user(db: Client, user_id: str):
    db.table("users").delete().eq("id", user_id).execute()


def get_all_threats(db: Client, limit: int = 500) -> list:
    response = db.table("threats").select(
        "*, uploads(filename, log_type), sessions(user_id)"
    ).order("created_at", desc=True).limit(limit).execute()
    return response.data