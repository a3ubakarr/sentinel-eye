import os
import secrets
import hashlib
from datetime import datetime, timedelta
from dotenv import load_dotenv
from supabase import Client
import database as db

load_dotenv()

# Token expires after 24 hours
TOKEN_EXPIRY_HOURS = 24


def generate_verification_token(user_id: str) -> str:
    # Combine user_id with a random secret to make the token unique
    raw = f"{user_id}{secrets.token_hex(16)}"
    return hashlib.sha256(raw.encode()).hexdigest()


def store_verification_token(client: Client, user_id: str, token: str):
    # We store the token in audit_log as a lightweight solution
    # without needing an extra table
    expiry = (datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat()
    client.table("audit_log").insert({
        "action": "EMAIL_VERIFY_TOKEN",
        "detail": f"{token}|{expiry}",
        "session_id": user_id,
        "status": "PENDING",
    }).execute()


def validate_verification_token(client: Client, token: str) -> str | None:
    # Returns user_id if token is valid and not expired, else None
    response = client.table("audit_log").select("*").eq(
        "action", "EMAIL_VERIFY_TOKEN"
    ).eq("status", "PENDING").execute()

    for row in response.data:
        stored_token, expiry_str = row["detail"].split("|")
        if stored_token != token:
            continue
        expiry = datetime.fromisoformat(expiry_str)
        if datetime.utcnow() > expiry:
            # Token expired — mark it so it cannot be reused
            client.table("audit_log").update(
                {"status": "EXPIRED"}
            ).eq("id", row["id"]).execute()
            return None
        # Token is valid — mark as used
        client.table("audit_log").update(
            {"status": "USED"}
        ).eq("id", row["id"]).execute()
        return row["session_id"]  # session_id holds user_id here

    return None


def login(client: Client, username: str, password: str) -> dict | None:
    if not username or not password:
        return None

    user = db.get_user_by_credentials(client, username, password)

    if user:
        if not user.get("is_active", True):
            db.log_action(client, "LOGIN_FAILED", f"Disabled account login attempt: '{username}'", status="FAILED")
            return {"error": "account_disabled"}
        db.log_action(client, "LOGIN", f"User '{username}' logged in")
        return user

    db.log_action(client, "LOGIN_FAILED", f"Failed attempt for '{username}'", status="FAILED")
    return None


def signup(client: Client, username: str, full_name: str, email: str, password: str) -> dict:
    # Returns dict with either user_id on success or error key on failure

    if db.username_exists(client, username):
        return {"error": "username_taken"}

    if db.email_exists(client, email):
        return {"error": "email_taken"}

    if len(password) < 8:
        return {"error": "password_too_short"}

    user_id = db.create_user(client, username, full_name, email, password)
    db.log_action(client, "SIGNUP", f"New user '{username}' registered", session_id=user_id)

    return {"user_id": user_id}


def change_password(client: Client, user_id: str, old_password: str, new_password: str) -> dict:
    if len(new_password) < 8:
        return {"error": "password_too_short"}

    user = db.get_user_by_id(client, user_id)
    if not user:
        return {"error": "user_not_found"}

    # Verify the old password before allowing a change
    from database import hash_password
    if user["password"] != hash_password(old_password):
        return {"error": "wrong_password"}

    db.update_password(client, user_id, new_password)
    db.log_action(client, "PASSWORD_CHANGED", session_id=user_id)
    return {"success": True}


def verify_email(client: Client, token: str) -> dict:
    user_id = validate_verification_token(client, token)
    if not user_id:
        return {"error": "invalid_or_expired_token"}

    db.verify_user_email(client, user_id)
    db.log_action(client, "EMAIL_VERIFIED", session_id=user_id)
    return {"success": True, "user_id": user_id}