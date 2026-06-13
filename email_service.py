import os
import resend
from dotenv import load_dotenv

load_dotenv()

resend.api_key = os.environ.get("RESEND_API_KEY")

APP_NAME = "Sentinel Eye"
FROM_EMAIL = "onboarding@resend.dev"


def send_verification_email(to_email: str, full_name: str, token: str, base_url: str) -> bool:
    # Returns True if email was sent successfully, False otherwise
    verify_link = f"{base_url}?verify_token={token}"

    try:
        resend.Emails.send({
            "from": f"{APP_NAME} <{FROM_EMAIL}>",
            "to": [to_email],
            "subject": f"Verify your {APP_NAME} account",
            "html": _verification_template(full_name, verify_link),
        })
        return True
    except Exception:
        return False


def send_password_reset_email(to_email: str, full_name: str, token: str, base_url: str) -> bool:
    reset_link = f"{base_url}?reset_token={token}"

    try:
        resend.Emails.send({
            "from": f"{APP_NAME} <{FROM_EMAIL}>",
            "to": [to_email],
            "subject": f"Reset your {APP_NAME} password",
            "html": _reset_template(full_name, reset_link),
        })
        return True
    except Exception:
        return False


def _verification_template(full_name: str, verify_link: str) -> str:
    return f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px 24px; background: #ffffff;">
        <div style="margin-bottom: 32px;">
            <span style="font-size: 20px; font-weight: 700; color: #0F1E3D; letter-spacing: 2px;">SENTINEL EYE</span>
        </div>
        <h2 style="color: #0F1E3D; font-size: 22px; margin-bottom: 8px;">Verify your email</h2>
        <p style="color: #5A7299; font-size: 15px; line-height: 1.6; margin-bottom: 24px;">
            Hi {full_name}, click the button below to verify your email address and activate your account.
        </p>
        <a href="{verify_link}"
           style="display: inline-block; background: #1E4DB7; color: #ffffff;
                  text-decoration: none; padding: 12px 28px; border-radius: 8px;
                  font-size: 15px; font-weight: 600; margin-bottom: 24px;">
            Verify Email Address
        </a>
        <p style="color: #8AA0BF; font-size: 13px; margin-bottom: 0;">
            This link expires in 24 hours. If you did not create an account, you can ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid #E2E8F0; margin: 28px 0;">
        <p style="color: #8AA0BF; font-size: 12px; margin: 0;">
            Sentinel Eye — Network Log Analyzer
        </p>
    </div>
    """


def _reset_template(full_name: str, reset_link: str) -> str:
    return f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px 24px; background: #ffffff;">
        <div style="margin-bottom: 32px;">
            <span style="font-size: 20px; font-weight: 700; color: #0F1E3D; letter-spacing: 2px;">SENTINEL EYE</span>
        </div>
        <h2 style="color: #0F1E3D; font-size: 22px; margin-bottom: 8px;">Reset your password</h2>
        <p style="color: #5A7299; font-size: 15px; line-height: 1.6; margin-bottom: 24px;">
            Hi {full_name}, click the button below to reset your password.
        </p>
        <a href="{reset_link}"
           style="display: inline-block; background: #1E4DB7; color: #ffffff;
                  text-decoration: none; padding: 12px 28px; border-radius: 8px;
                  font-size: 15px; font-weight: 600; margin-bottom: 24px;">
            Reset Password
        </a>
        <p style="color: #8AA0BF; font-size: 13px; margin-bottom: 0;">
            This link expires in 24 hours. If you did not request a password reset, you can ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid #E2E8F0; margin: 28px 0;">
        <p style="color: #8AA0BF; font-size: 12px; margin: 0;">
            Sentinel Eye — Network Log Analyzer
        </p>
    </div>
    """