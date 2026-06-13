import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

MODEL = "llama-3.3-70b-versatile"
MAX_TOKENS = 1024


def build_system_prompt(user_name: str, threat_summary: dict, recent_threats: list) -> str:
    """
    Builds a context-aware system prompt for the chatbot.
    Includes the user's name and their current threat analysis results
    so the assistant can give relevant, specific answers.
    """
    threat_lines = []
    for t in recent_threats[:10]:
        threat_lines.append(
            f"- [{t.get('severity', '')}] {t.get('threat_type', '')} "
            f"| {t.get('description', '')} "
            f"| Src: {t.get('src_ip', 'N/A')} -> Dst: {t.get('dst_ip', 'N/A')} "
            f"| MITRE: {t.get('mitre_id', 'N/A')} {t.get('mitre_name', '')}"
        )

    threats_block = "\n".join(threat_lines) if threat_lines else "No threats detected yet."

    summary_block = (
        f"Total: {threat_summary.get('total', 0)} | "
        f"Critical: {threat_summary.get('CRITICAL', 0)} | "
        f"High: {threat_summary.get('HIGH', 0)} | "
        f"Medium: {threat_summary.get('MEDIUM', 0)} | "
        f"Low: {threat_summary.get('LOW', 0)}"
    )

    return f"""You are a cybersecurity analyst assistant inside Sentinel Eye, a network log analysis tool.

The user's name is {user_name}. Address them by name when it feels natural.

Current analysis session summary:
{summary_block}

Most recent threats detected:
{threats_block}

Your role:
- Help {user_name} understand the threats detected in their log files.
- Explain what each threat means in plain language.
- Suggest concrete remediation steps for specific threats.
- Answer questions about MITRE ATT&CK techniques, Snort rules, firewall configuration, and network security.
- If asked about something unrelated to cybersecurity or their current analysis, politely redirect.

Keep answers clear, practical, and concise. Use numbered steps for remediation advice.
Do not make up threat data — only refer to what is shown above."""


def get_response(
    user_name: str,
    user_message: str,
    chat_history: list,
    threat_summary: dict,
    recent_threats: list,
) -> str:
    """
    Sends a message to the Groq API and returns the assistant's response.

    Parameters:
        user_name      -- the logged-in user's display name (or 'there' for guests)
        user_message   -- the message the user just typed
        chat_history   -- list of previous messages [{"role": ..., "content": ...}]
        threat_summary -- dict with severity counts from the current session
        recent_threats -- list of threat dicts from the current session
    """
    system_prompt = build_system_prompt(user_name, threat_summary, recent_threats)

    # Build the full message list for the API
    messages = [{"role": "system", "content": system_prompt}]

    # Include previous conversation turns for context
    for msg in chat_history:
        messages.append({
            "role": msg["role"],
            "content": msg["content"],
        })

    # Add the new user message
    messages.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=0.4,
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        error_msg = str(e).lower()

        if "rate limit" in error_msg:
            return "I am receiving too many requests right now. Please wait a moment and try again."
        if "api key" in error_msg or "authentication" in error_msg:
            return "The AI assistant is not configured correctly. Please check the GROQ_API_KEY in your environment."
        if "model" in error_msg:
            return "The AI model is temporarily unavailable. Please try again shortly."

        return "Something went wrong while contacting the AI assistant. Please try again."


def get_guest_name() -> str:
    """Returns the display name used for unauthenticated users."""
    return "there"