import os
import uuid
import streamlit as st
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv

import database as db
import auth as auth_module
import parser as log_parser
import detector
import chatbot

load_dotenv()

st.set_page_config(
    page_title="Sentinel Eye",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={}
)

def init_session():
    defaults = {
        "logged_in": False,
        "user_id": None,
        "username": None,
        "full_name": None,
        "is_admin": False,
        "session_id": str(uuid.uuid4()),
        "theme": "light",
        "page": "overview",
        "chat_open": False,
        "switch_to_login": False,
        "show_login": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session()

@st.cache_resource
def get_db():
    return db.get_client()

client = get_db()

LIGHT = {
    "bg": "#EEF2F9", "sidebar": "rgba(15,30,61,0.98)", "card": "#FFFFFF",
    "border": "#D0DAEA", "text": "#0F1E3D", "muted": "#5A7299",
    "primary": "#1E4DB7", "sky": "#3B7DD8",
}
DARK = {
    "bg": "#0D1117", "sidebar": "#1C2128", "card": "#161B22",
    "border": "#30363D", "text": "#E6EDF3", "muted": "#8B949E",
    "primary": "#58A6FF", "sky": "#58A6FF",
}

def get_theme():
    return DARK if st.session_state.theme == "dark" else LIGHT

def inject_css():
    t = get_theme()
    st.markdown(f"""
    <style>
    #root > div:first-child {{ margin-top: 0; }}
    .block-container {{ padding-top: 1.2rem !important; padding-bottom: 80px !important; }}
    header[data-testid="stHeader"] {{ background: transparent !important; box-shadow: none !important; }}
    #MainMenu, .stDeployButton, [data-testid="stToolbarActions"], [data-testid="stStatusWidget"] {{ display: none !important; }}
    div[data-testid="InputInstructions"] {{ display: none !important; }}
    .stApp {{ background-color: {t["bg"]}; color: {t["text"]}; font-family: 'Segoe UI', system-ui, sans-serif; }}
    section[data-testid="stSidebar"] {{ background: {t["sidebar"]} !important; border-right: 0.5px solid {t["border"]} !important; }}
    section[data-testid="stSidebar"] * {{ color: #C8DAEF !important; }}
    section[data-testid="stSidebar"] .stRadio label {{ border-radius: 8px !important; padding: 6px 12px !important; font-size: 14px !important; }}
    section[data-testid="stSidebar"] .stRadio label:hover {{ background: rgba(59,125,216,0.15) !important; }}
    h1 {{ color: {t["text"]} !important; font-size: 22px !important; font-weight: 700 !important; }}
    h2, h3 {{ color: {t["text"]} !important; font-weight: 600 !important; }}
    .stTextInput > div > div > input {{
        background: {t["card"]} !important; border: 0.5px solid {t["border"]} !important;
        border-radius: 10px !important; color: {t["text"]} !important;
        font-size: 14px !important; padding: 10px 14px !important; caret-color: {t["primary"]} !important;
    }}
    .stTextInput > div > div > input::placeholder {{ color: {t["muted"]} !important; opacity: 0.7 !important; }}
    .stTextInput > div > div > input:focus {{
        border-color: {t["primary"]} !important;
        box-shadow: 0 0 0 2px {t["primary"]}33 !important;
        outline: none !important;
    }}
    .stTextInput > div > div > input:hover {{ border-color: {t["sky"]} !important; }}
    /* Override Streamlit default red/pink focus ring on ALL input wrappers */
    .stTextInput > div[data-baseweb="input"] {{
        border-color: {t["border"]} !important;
        box-shadow: none !important;
    }}
    .stTextInput > div[data-baseweb="input"]:focus-within {{
        border-color: {t["primary"]} !important;
        box-shadow: 0 0 0 2px {t["primary"]}33 !important;
        outline: none !important;
    }}
    div[data-baseweb="input"] {{
        border-color: {t["border"]} !important;
    }}
    div[data-baseweb="input"]:focus-within {{
        border-color: {t["primary"]} !important;
        box-shadow: 0 0 0 2px {t["primary"]}33 !important;
    }}
    div[data-baseweb="textarea"] {{
        border-color: {t["border"]} !important;
    }}
    div[data-baseweb="textarea"]:focus-within {{
        border-color: {t["primary"]} !important;
    }}
    .stSelectbox > div > div {{ background: {t["card"]} !important; border: 0.5px solid {t["border"]} !important; border-radius: 10px !important; color: {t["text"]} !important; }}
    .stTextInput label, .stSelectbox label, .stTextArea label {{ color: {t["muted"]} !important; font-size: 11px !important; font-weight: 700 !important; text-transform: uppercase !important; letter-spacing: 0.8px !important; }}
    section[data-testid="stSidebar"] .stButton > button {{
        background: rgba(59,125,216,0.12) !important; color: #C8DAEF !important;
        border: 0.5px solid rgba(59,125,216,0.3) !important; border-radius: 10px !important;
        font-weight: 500 !important; font-size: 13px !important; padding: 9px 16px !important;
    }}
    section[data-testid="stSidebar"] .stButton > button:hover {{
        background: rgba(59,125,216,0.22) !important; border-color: rgba(59,125,216,0.55) !important; color: #ffffff !important;
    }}
    .stButton > button, div[data-testid="stFormSubmitButton"] > button {{
        background: linear-gradient(135deg, {t["primary"]} 0%, {t["sky"]} 100%) !important;
        color: #ffffff !important; border: none !important; border-radius: 10px !important;
        font-weight: 600 !important; font-size: 14px !important; padding: 10px 20px !important;
    }}
    .stButton > button:hover {{ transform: translateY(-1px) !important; box-shadow: 0 6px 20px {t["primary"]}44 !important; filter: brightness(1.08) !important; }}
    div[data-testid="stForm"] {{ background: {t["card"]} !important; border: 0.5px solid {t["border"]} !important; border-radius: 16px !important; padding: 24px 28px !important; }}
    .row-card {{ background: {t["card"]}; border: 0.5px solid {t["border"]}; border-radius: 12px; padding: 14px 18px; margin-bottom: 10px; }}
    .stat-card {{ background: {t["card"]}; border: 0.5px solid {t["border"]}; border-radius: 12px; padding: 18px 20px; }}
    .stat-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.9px; color: {t["muted"]}; margin-bottom: 6px; }}
    .stat-value {{ font-size: 34px; font-weight: 800; line-height: 1; }}
    .stDataFrame {{ border: 0.5px solid {t["border"]} !important; border-radius: 12px !important; }}
    div[data-testid="stExpander"] {{ background: {t["card"]} !important; border: 0.5px solid {t["border"]} !important; border-radius: 12px !important; margin-bottom: 8px !important; }}
    div[data-testid="stExpander"] summary {{ color: {t["text"]} !important; font-weight: 500 !important; cursor: default !important; }}
    div[data-testid="stExpander"] summary:hover {{ background: transparent !important; }}
    div[data-testid="stExpander"] p, div[data-testid="stExpander"] li, div[data-testid="stExpander"] span {{ color: {t["text"]} !important; }}
    div[data-testid="stExpander"] code {{ background: {t["bg"]} !important; color: {t["primary"]} !important; border: 0.5px solid {t["border"]} !important; border-radius: 5px !important; padding: 1px 6px !important; }}
    div[data-testid="stInfo"] {{ background: {t["primary"]}11 !important; border: 0.5px solid {t["primary"]}44 !important; border-radius: 10px !important; }}
    div[data-testid="stSuccess"] {{ background: #10B98111 !important; border: 0.5px solid #10B98144 !important; border-radius: 10px !important; }}
    div[data-testid="stError"] {{ background: #DC262611 !important; border: 0.5px solid #DC262644 !important; border-radius: 10px !important; }}
    div[data-testid="stWarning"] {{ background: #F59E0B11 !important; border: 0.5px solid #F59E0B44 !important; border-radius: 10px !important; }}
    hr {{ border-color: {t["border"]} !important; }}
    .chat-bubble-user {{ background: {t["primary"]}22; border: 0.5px solid {t["primary"]}44; border-radius: 12px 12px 4px 12px; padding: 10px 14px; margin: 6px 0; color: {t["text"]}; font-size: 13px; }}
    .chat-bubble-assistant {{ background: {t["card"]}; border: 0.5px solid {t["border"]}; border-radius: 12px 12px 12px 4px; padding: 10px 14px; margin: 6px 0; color: {t["text"]}; font-size: 13px; }}
    [data-testid="stFileUploader"] button {{ background: linear-gradient(135deg, #1E4DB7, #3B7DD8) !important; color: #fff !important; border: none !important; border-radius: 8px !important; }}
    </style>
    """, unsafe_allow_html=True)

inject_css()

def stat_card(label, value, color):
    return f"""<div class="stat-card"><div class="stat-label">{label}</div><div class="stat-value" style="color:{color};">{value}</div></div>"""

def severity_badge(s):
    colors = {"CRITICAL": ("#7F1D1D","#FEE2E2","#FECACA"), "HIGH": ("#78350F","#FEF3C7","#FDE68A"), "MEDIUM": ("#1E3A7A","#DBEAFE","#BFDBFE"), "LOW": ("#166534","#DCFCE7","#BBF7D0")}
    text, bg, border = colors.get(s, ("#374151","#F3F4F6","#E5E7EB"))
    return f'<span style="background:{bg};color:{text};border:0.5px solid {border};border-radius:20px;padding:2px 10px;font-size:10px;font-weight:700;">{s}</span>'

def plot_config():
    return {"displayModeBar": False}

def ensure_session():
    try:
        if not db.session_exists(client, st.session_state.session_id):
            db.create_session(client, st.session_state.session_id, st.session_state.user_id)
    except Exception:
        pass

def page_admin_setup():
    t = get_theme()
    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("<div style='height:60px'></div>", unsafe_allow_html=True)
        st.markdown(f"""<div style="text-align:center;margin-bottom:28px;">
            <div style="font-size:22px;font-weight:800;color:{t['text']};letter-spacing:3px;">SENTINEL EYE</div>
            <div style="color:{t['muted']};font-size:13px;margin-top:4px;">First-time setup — create your admin account</div>
        </div>""", unsafe_allow_html=True)
        with st.form("admin_setup"):
            full_name = st.text_input("Full Name", placeholder="Your full name")
            username  = st.text_input("Username", placeholder="Choose a username")
            email     = st.text_input("Email", placeholder="admin@example.com")
            password  = st.text_input("Password", type="password", placeholder="Min 8 characters")
            confirm   = st.text_input("Confirm Password", type="password", placeholder="Repeat password")
            submitted = st.form_submit_button("Create Admin Account", use_container_width=True)
        if submitted:
            if not all([full_name, username, email, password, confirm]):
                st.warning("Please fill in all fields.")
            elif password != confirm:
                st.error("Passwords do not match.")
            elif len(password) < 8:
                st.error("Password must be at least 8 characters.")
            else:
                db.create_admin(client, username, full_name, email, password)
                st.success("Admin account created. Please log in.")
                st.rerun()

def page_login():
    t = get_theme()
    # Auto switch to sign in tab after signup
    default_tab = 1 if st.session_state.get("switch_to_login") else 0
    if st.session_state.get("switch_to_login"):
        st.session_state["switch_to_login"] = False

    _, col, _ = st.columns([1, 1.1, 1])
    with col:
        st.markdown("<div style='height:48px'></div>", unsafe_allow_html=True)
        st.markdown(f"""<div style="text-align:center;margin-bottom:28px;">
            <div style="font-size:26px;font-weight:800;color:{t['text']};letter-spacing:3px;">SENTINEL EYE</div>
            <div style="color:{t['sky']};font-size:13px;">Network Log Analyzer</div>
            <div style="color:{t['muted']};font-size:11px;margin-top:4px;">University of Management and Technology</div>
        </div>""", unsafe_allow_html=True)

        # After successful signup — show sign in directly
        if st.session_state.get("signup_success"):
            st.session_state["signup_success"] = False
            st.success("Account created successfully. Please sign in below.")

        tab_login, tab_signup = st.tabs(["Sign In", "Sign Up"])

        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                submitted = st.form_submit_button("Sign In", use_container_width=True)
            if submitted:
                if not username or not password:
                    st.warning("Please enter both fields.")
                else:
                    result = auth_module.login(client, username, password)
                    if result is None:
                        st.error("Invalid username or password.")
                    elif isinstance(result, dict) and result.get("error") == "account_disabled":
                        st.error("Your account has been disabled. Please contact the administrator.")
                    else:
                        st.session_state.logged_in  = True
                        st.session_state.user_id    = result["id"]
                        st.session_state.username   = result["username"]
                        st.session_state.full_name  = result["full_name"]
                        st.session_state.is_admin   = result["is_admin"]
                        try:
                            db.create_session(client, st.session_state.session_id, result["id"])
                        except Exception:
                            pass
                        db.log_action(client, "LOGIN", f"User {username} logged in", st.session_state.session_id)
                        st.rerun()

            st.markdown(f"""<p style="text-align:center;color:{t['muted']};font-size:11px;margin-top:16px;">
                Continue as guest — no sign in required<br>
                <a href="?guest=1" style="color:{t['sky']};">Browse as Guest</a>
            </p>""", unsafe_allow_html=True)

            if st.query_params.get("guest"):
                st.session_state.logged_in = False
                st.session_state.full_name = "Guest"
                st.session_state.username  = "guest"
                ensure_session()
                st.query_params.clear()
                st.rerun()

        with tab_signup:
            with st.form("signup_form"):
                s_full  = st.text_input("Full Name", placeholder="Your full name")
                s_user  = st.text_input("Username", placeholder="3-20 characters, letters and numbers only")
                s_email = st.text_input("Email", placeholder="you@example.com")
                s_pass  = st.text_input("Password", type="password", placeholder="Min 8 characters")
                s_conf  = st.text_input("Confirm Password", type="password", placeholder="Repeat password")
                submitted = st.form_submit_button("Create Account", use_container_width=True)
            if submitted:
                if not all([s_full, s_user, s_email, s_pass, s_conf]):
                    st.warning("Please fill in all fields.")
                elif s_pass != s_conf:
                    st.error("Passwords do not match.")
                elif len(s_user) < 3 or not s_user.isalnum():
                    st.error("Username must be 3-20 alphanumeric characters.")
                else:
                    result = auth_module.signup(client, s_user, s_full, s_email, s_pass)
                    if result.get("error") == "username_taken":
                        st.error("That username is already taken.")
                    elif result.get("error") == "email_taken":
                        st.error("An account with that email already exists.")
                    elif result.get("error") == "password_too_short":
                        st.error("Password must be at least 8 characters.")
                    else:
                        st.session_state["signup_success"] = True
                        st.rerun()

        st.markdown(f"""<p style="text-align:center;color:{t['muted']};font-size:10px;margin-top:24px;">
            All access is logged. Authorized use only.</p>""", unsafe_allow_html=True)

def render_sidebar():
    t = get_theme()
    with st.sidebar:
        st.markdown(f"""<div style="padding:14px 0 10px;">
            <div style="font-size:15px;font-weight:800;color:#fff;letter-spacing:2px;">SENTINEL EYE</div>
            <div style="font-size:9px;color:rgba(255,255,255,0.3);margin-top:2px;">Network Log Analyzer</div>
        </div>""", unsafe_allow_html=True)

        name = st.session_state.full_name or "Guest"
        role = "Admin" if st.session_state.is_admin else ("User" if st.session_state.logged_in else "Guest")
        role_color = "#10B981" if st.session_state.is_admin else ("#3B7DD8" if st.session_state.logged_in else "#8B949E")

        st.markdown(f"""<div style="background:rgba(59,125,216,0.12);border:0.5px solid rgba(59,125,216,0.25);
            border-radius:10px;padding:10px 12px;margin:6px 0 14px;">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
                <div style="width:7px;height:7px;background:#22C55E;border-radius:50%;"></div>
                <div style="font-size:13px;font-weight:600;color:#E2EAF5;">{name}</div>
            </div>
            <div style="font-size:9px;color:{role_color};padding-left:13px;font-weight:700;
                text-transform:uppercase;letter-spacing:0.8px;">{role}</div>
        </div>""", unsafe_allow_html=True)

        if st.session_state.is_admin:
            pages = ["Overview", "Admin Panel", "Audit Log", "Settings"]
        elif st.session_state.logged_in:
            pages = ["Overview", "Log Analysis", "Threat Results", "MITRE ATT&CK",
                     "Incident Reports", "Guide", "Assistant", "Settings"]
        else:
            pages = ["Overview", "Log Analysis", "Threat Results", "Guide", "Assistant"]

        page = st.radio("Navigation", pages, label_visibility="collapsed")
        st.session_state.page = page

        if st.session_state.logged_in:
            if st.button("Sign Out", use_container_width=True):
                db.log_action(client, "LOGOUT", session_id=st.session_state.session_id)
                for key in ["logged_in", "user_id", "username", "full_name", "is_admin"]:
                    st.session_state[key] = None
                st.session_state.logged_in = False
                st.rerun()
        elif st.session_state.get("username") == "guest":
            if st.button("Create Account", use_container_width=True):
                st.session_state["show_login"] = True
                st.rerun()
        else:
            if st.button("Sign In", use_container_width=True):
                st.session_state["show_login"] = True
                st.rerun()

    return page


def page_overview():
    t = get_theme()
    ensure_session()
    st.title("Overview")
    st.caption("Summary of your current analysis session")
    st.divider()


    summary = db.get_threat_summary(client, st.session_state.session_id)
    uploads = db.get_uploads(client, st.session_state.session_id)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.markdown(stat_card("Total Threats", summary["total"], "#1E4DB7"), unsafe_allow_html=True)
    c2.markdown(stat_card("Critical", summary["CRITICAL"], "#DC2626"), unsafe_allow_html=True)
    c3.markdown(stat_card("High", summary["HIGH"], "#F59E0B"), unsafe_allow_html=True)
    c4.markdown(stat_card("Medium", summary["MEDIUM"], "#3B7DD8"), unsafe_allow_html=True)
    c5.markdown(stat_card("Files Uploaded", len(uploads), "#10B981"), unsafe_allow_html=True)
    if summary["total"] > 0:
        st.divider()
        threats = db.get_threats(client, st.session_state.session_id)
        ca, cb = st.columns(2)
        with ca:
            st.subheader("Severity Distribution")
            sev_data = pd.DataFrame([{"Severity": s, "Count": summary[s]} for s in ["CRITICAL","HIGH","MEDIUM","LOW"] if summary[s] > 0])
            fig = px.pie(sev_data, names="Severity", values="Count", hole=0.5, color_discrete_sequence=["#DC2626","#F59E0B","#3B7DD8","#10B981"])
            fig.update_layout(height=260, plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color=t["muted"], margin=dict(l=0,r=0,t=10,b=0))
            fig.update_traces(textfont_color="#ffffff")
            st.plotly_chart(fig, use_container_width=True, config=plot_config())
        with cb:
            st.subheader("Threats by Type")
            if threats:
                type_counts = pd.DataFrame(threats)["threat_type"].value_counts().head(8).reset_index()
                type_counts.columns = ["Threat","Count"]
                fig2 = px.bar(type_counts, x="Count", y="Threat", orientation="h", color="Count", color_continuous_scale=["#BFDBFE","#3B7DD8","#1E4DB7"])
                fig2.update_layout(showlegend=False, height=260, plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color=t["muted"], margin=dict(l=0,r=0,t=10,b=0))
                fig2.update_xaxes(showgrid=False, color=t["muted"])
                fig2.update_yaxes(showgrid=False, color=t["muted"])
                st.plotly_chart(fig2, use_container_width=True, config=plot_config())
        st.divider()
        st.subheader("Recent Threats")
        for threat in threats[:6]:
            bc = {"CRITICAL":"#DC2626","HIGH":"#F59E0B","MEDIUM":"#3B7DD8","LOW":"#10B981"}.get(threat["severity"], t["border"])
            st.markdown(f"""<div class="row-card" style="border-left:3px solid {bc};">
                <span style="font-weight:700;color:{t['text']};">{threat['threat_type']}</span>&nbsp;&nbsp;{severity_badge(threat['severity'])}<br>
                <span style="color:{t['muted']};font-size:12px;">{threat['description'][:100]}&nbsp;&middot;&nbsp;Src: {threat.get('src_ip') or 'N/A'}&nbsp;&middot;&nbsp;{threat.get('timestamp') or ''}</span>
            </div>""", unsafe_allow_html=True)
    else:
        st.info("Upload a log file in Log Analysis to see results here.")

def page_log_analysis():
    t = get_theme()
    ensure_session()
    st.title("Log Analysis")
    st.caption("Upload a Snort, Wireshark, or Windows Event log file for analysis")
    st.divider()
    MAX_MB = log_parser.MAX_FILE_SIZE_MB
    uploaded = st.file_uploader(f"Choose a log file (max {MAX_MB}MB)", type=["ids","txt","csv","log"], help="Supported: Snort alert.ids, Wireshark CSV export, Windows Event Log CSV export")
    if uploaded:
        file_bytes = uploaded.read()
        if len(file_bytes) > log_parser.MAX_FILE_SIZE_BYTES:
            st.error(f"File is too large. Maximum allowed size is {MAX_MB}MB.")
            return
        with st.spinner("Parsing log file..."):
            parse_result = log_parser.parse_log_file(uploaded.name, file_bytes)
        if parse_result["error"]:
            st.error(parse_result["error"])
            return
        log_type = parse_result["log_type"]
        entries  = parse_result["entries"]
        total    = parse_result["total_lines"]
        st.success(f"Detected log type: **{log_type.replace('_',' ').title()}** — {total:,} lines, {len(entries):,} entries parsed")
        with st.spinner("Running threat detection..."):
            upload_id = db.save_upload(client, st.session_state.session_id, uploaded.name, log_type)
            threats   = detector.run_detection(log_type, entries, st.session_state.session_id, upload_id)
        if threats:
            db.save_threats(client, threats)
            db.log_action(client, "FILE_ANALYZED", f"{uploaded.name} — {len(threats)} threats found", st.session_state.session_id)
            st.success(f"{len(threats)} threats detected. Go to Threat Results to review them.")
        else:
            st.info("No threats detected in this file.")
        st.divider()
        st.subheader("Upload History")
        uploads = db.get_uploads(client, st.session_state.session_id)
        for u in uploads:
            st.markdown(f"""<div class="row-card">
                <span style="font-weight:700;color:{t['text']};">{u['filename']}</span><br>
                <span style="color:{t['muted']};font-size:12px;">Type: {u['log_type'].replace('_',' ').title()}&nbsp;&middot;&nbsp;Uploaded: {u['uploaded_at'][:19]}</span>
            </div>""", unsafe_allow_html=True)

def page_threat_results():
    t = get_theme()
    ensure_session()
    st.title("Threat Results")
    st.caption("All threats detected in your uploaded log files")
    st.divider()
    threats = db.get_threats(client, st.session_state.session_id)
    if not threats:
        st.info("No threats found yet. Upload a log file in Log Analysis.")
        return
    sev_filter = st.selectbox("Filter by Severity", ["All","CRITICAL","HIGH","MEDIUM","LOW"])
    filtered   = [t_ for t_ in threats if sev_filter == "All" or t_["severity"] == sev_filter]
    st.caption(f"Showing {len(filtered)} of {len(threats)} threats")
    for threat in filtered:
        bc = {"CRITICAL":"#DC2626","HIGH":"#F59E0B","MEDIUM":"#3B7DD8","LOW":"#10B981"}.get(threat["severity"], t["border"])
        mitre_txt = f"{threat.get('mitre_id','')} {threat.get('mitre_name','')}".strip()
        st.markdown(f"""<div class="row-card" style="border-left:3px solid {bc};">
            <span style="font-size:14px;font-weight:700;color:{t['text']};">{threat['threat_type']}</span>&nbsp;&nbsp;{severity_badge(threat['severity'])}<br>
            <span style="color:{t['muted']};font-size:12px;">{threat['description']}</span><br>
            <span style="color:{t['muted']};font-size:11px;">Src: {threat.get('src_ip') or 'N/A'}&nbsp;&middot;&nbsp;Dst: {threat.get('dst_ip') or 'N/A'}&nbsp;&middot;&nbsp;Protocol: {threat.get('protocol') or 'N/A'}&nbsp;&middot;&nbsp;Port: {threat.get('port') or 'N/A'}{f"&nbsp;&middot;&nbsp;MITRE: {mitre_txt}" if mitre_txt else ""}</span>
        </div>""", unsafe_allow_html=True)
    st.divider()
    if st.button("Export Threats as CSV"):
        df  = pd.DataFrame(threats)
        csv = df.to_csv(index=False)
        st.download_button("Download CSV", csv, "sentinel_eye_threats.csv", "text/csv")

def page_mitre():
    t = get_theme()
    ensure_session()
    st.title("MITRE ATT&CK")
    st.caption("Threats from your session mapped to the MITRE ATT&CK framework")
    st.divider()
    threats = db.get_threats(client, st.session_state.session_id)
    mapped  = [t_ for t_ in threats if t_.get("mitre_id")]
    if not mapped:
        st.info("No MITRE mappings available yet. Upload a log file first.")
        return
    tactic_colors = {"Reconnaissance":"#1E4DB7","Discovery":"#F59E0B","Initial Access":"#DC2626","Lateral Movement":"#7C3AED","Credential Access":"#0E7A52","Impact":"#991B1B","Execution":"#B45309","Persistence":"#6D28D9","Privilege Escalation":"#0369A1","Command and Control":"#374151","Exfiltration":"#9D174D"}
    df = pd.DataFrame(mapped)[["threat_type","severity","mitre_id","mitre_name","src_ip","timestamp"]].drop_duplicates()
    df.columns = ["Threat","Severity","Technique ID","Technique Name","Source IP","Timestamp"]
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.divider()
    st.subheader("Technique Cards")
    seen = set()
    for threat in mapped:
        key = threat.get("mitre_id","")
        if key in seen:
            continue
        seen.add(key)
        color = tactic_colors.get(threat.get("mitre_name",""), "#374151")
        st.markdown(f"""<div class="row-card" style="border-left:3px solid {color};">
            <span style="font-weight:700;color:{t['text']};">{threat['mitre_id']} — {threat['mitre_name']}</span><br>
            <span style="color:{t['muted']};font-size:12px;">Detected via: {threat['threat_type']}&nbsp;&middot;&nbsp;Severity: {threat['severity']}</span>
        </div>""", unsafe_allow_html=True)

def page_incident_reports():
    t = get_theme()
    ensure_session()
    st.title("Incident Reports")
    st.caption("Detailed breakdown of each threat category detected in your session")
    st.divider()
    threats = db.get_threats(client, st.session_state.session_id)
    if not threats:
        st.info("No threats detected yet. Upload a log file first.")
        return
    grouped = {}
    for threat in threats:
        tt = threat["threat_type"]
        if tt not in grouped:
            grouped[tt] = []
        grouped[tt].append(threat)
    for threat_type, items in grouped.items():
        severities = [i["severity"] for i in items]
        worst = max(severities, key=lambda s: ["LOW","MEDIUM","HIGH","CRITICAL"].index(s))
        with st.expander(f"{threat_type}  —  {len(items)} occurrence(s)  |  {worst}"):
            st.markdown(f"**Severity:** {worst}  &nbsp; **Count:** {len(items)}")
            sample = items[0]
            if sample.get("mitre_id"):
                st.markdown(f"**MITRE:** `{sample['mitre_id']}` — {sample.get('mitre_name','')}")
            st.markdown("**Sample raw entry:**")
            st.code(sample.get("raw_entry","N/A"), language="text")
            st.markdown("**Recommended response:**")
            _show_remediation(threat_type)

def _show_remediation(threat_type: str):
    remediation = {
        "Port Scan Detected": ["Enable SYN rate limiting on your firewall.","Block the source IP if scanning continues.","Review open ports and close unnecessary services."],
        "SYN Flood / DoS Attempt": ["Enable SYN cookies on the target system.","Configure rate limiting for inbound SYN packets.","Contact your ISP to filter traffic upstream if severe."],
        "Telnet Access Attempt": ["Block port 23 on your firewall immediately.","Replace Telnet with SSH for all remote access.","Investigate the source IP for further activity."],
        "FTP Brute Force Attempt": ["Block port 21 and switch to SFTP.","Implement account lockout after failed attempts.","Review FTP access logs for successful logins."],
        "Failed logon attempt": ["Investigate the account being targeted.","Implement account lockout policies.","Enable multi-factor authentication."],
        "Audit Log Cleared": ["This is a critical indicator of compromise — escalate immediately.","Restore audit logging and review recent system activity.","Check for unauthorized administrator access."],
    }
    steps = remediation.get(threat_type, ["Review the raw log entry above.","Investigate the source IP.","Consult your security policy for escalation procedures."])
    for i, step in enumerate(steps, 1):
        st.markdown(f"{i}. {step}")

def page_guide():
    st.title("How to Use Sentinel Eye")
    st.caption("A step-by-step guide to getting log files and using this tool")
    st.divider()
    sections = [
        ("How to export a Snort alert file", "1. Run Snort with the `-A fast` flag:\n   `snort -i <interface> -c /etc/snort/snort.conf -l /var/log/snort -A fast`\n2. The alert file will be saved as `alert` in your log directory.\n3. Upload it here as-is — no conversion needed."),
        ("How to export a Wireshark capture as CSV", "1. Open Wireshark and capture traffic.\n2. Apply a display filter if needed (e.g. `tcp` or `icmp`).\n3. Go to File > Export Packet Dissections > As CSV.\n4. Make sure 'All packets' is selected.\n5. Save the file and upload it here."),
        ("How to export Windows Event Logs as CSV", "1. Open Event Viewer (search in Start menu).\n2. Navigate to Windows Logs > Security.\n3. Click 'Save All Events As...' in the right panel.\n4. Choose CSV as the format.\n5. Upload the saved file here.\n\nKey event IDs: 4625 (failed login), 4720 (new account), 4672 (elevated privileges), 1102 (audit log cleared)."),
        ("Understanding severity levels", "- CRITICAL — Immediate action required. Active compromise or destructive attack.\n- HIGH     — Significant threat. Investigate within hours.\n- MEDIUM   — Suspicious activity. Review when possible.\n- LOW      — Informational. Normal activity that may warrant monitoring."),
        ("Using the Security Assistant", "1. Navigate to the Assistant page in the sidebar.\n2. Ask questions about the threats detected in your session.\n3. The assistant has full context of your uploaded log analysis.\n\nExample questions:\n- 'What does the port scan alert mean?'\n- 'How do I block the source IP in Windows Firewall?'\n- 'Explain MITRE technique T1046'"),
    ]
    for title, content in sections:
        with st.expander(title):
            st.markdown(content)

def page_assistant():
    t = get_theme()
    ensure_session()
    st.title("Security Assistant")
    st.caption("Ask questions about your detected threats, MITRE techniques, or how to remediate issues")
    st.divider()
    history   = db.get_chat_history(client, st.session_state.session_id)
    summary   = db.get_threat_summary(client, st.session_state.session_id)
    threats   = db.get_threats(client, st.session_state.session_id)
    user_name = st.session_state.full_name or chatbot.get_guest_name()
    if not history:
        st.markdown(f"""<div class="row-card">
            <span style="color:{t['muted']};font-size:13px;">Hi <strong>{user_name}</strong> — Upload a log file first, then ask me about any detected threats.</span>
        </div>""", unsafe_allow_html=True)
    for msg in history:
        css_class = "chat-bubble-user" if msg["role"] == "user" else "chat-bubble-assistant"
        st.markdown(f'<div class="{css_class}">{msg["content"]}</div>', unsafe_allow_html=True)
    with st.form("chat_form", clear_on_submit=True):
        col_input, col_send = st.columns([5, 1])
        user_input = col_input.text_input("Message", placeholder="Ask about threats, MITRE techniques, or remediation steps...", label_visibility="collapsed")
        send = col_send.form_submit_button("Send")
    if send and user_input.strip():
        db.save_message(client, st.session_state.session_id, "user", user_input)
        response = chatbot.get_response(user_name=user_name, user_message=user_input, chat_history=history, threat_summary=summary, recent_threats=threats)
        db.save_message(client, st.session_state.session_id, "assistant", response)
        st.rerun()
    if history:
        st.divider()
        if st.button("Clear conversation", type="secondary"):
            db.clear_chat_history(client, st.session_state.session_id)
            st.rerun()

def page_admin_overview():
    t = get_theme()
    st.title("Admin Overview")
    st.caption("Platform-wide statistics and activity")
    st.divider()

    # Stat cards
    stats = db.get_platform_stats(client)
    login_stats = db.get_login_attempt_stats(client)

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(stat_card("Total Users",    stats["total_users"],   "#1E4DB7"), unsafe_allow_html=True)
    c2.markdown(stat_card("Total Uploads",  stats["total_uploads"], "#3B7DD8"), unsafe_allow_html=True)
    c3.markdown(stat_card("Total Sessions", stats["total_sessions"],"#10B981"), unsafe_allow_html=True)
    c4.markdown(stat_card("Audit Actions",  stats["total_audit"],   "#F59E0B"), unsafe_allow_html=True)

    st.divider()

    # Charts row
    ca, cb = st.columns(2)

    with ca:
        st.subheader("User Signups Over Time")
        signup_data = db.get_signups_over_time(client)
        if signup_data:
            df_signups = pd.DataFrame(signup_data)
            df_signups["date"] = pd.to_datetime(df_signups["created_at"]).dt.date
            df_signups = df_signups.groupby("date").size().reset_index(name="Signups")
            fig = px.line(df_signups, x="date", y="Signups", markers=True,
                         color_discrete_sequence=["#1E4DB7"])
            fig.update_layout(height=240, plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)", font_color=t["muted"],
                margin=dict(l=0,r=0,t=10,b=0))
            fig.update_xaxes(showgrid=False, color=t["muted"])
            fig.update_yaxes(showgrid=False, color=t["muted"])
            st.plotly_chart(fig, use_container_width=True, config=plot_config())
        else:
            st.info("No signup data yet.")

    with cb:
        st.subheader("Top Audit Actions")
        action_data = db.get_top_audit_actions(client)
        if action_data:
            df_actions = pd.DataFrame(action_data)
            action_counts = df_actions["action"].value_counts().head(6).reset_index()
            action_counts.columns = ["Action","Count"]
            fig2 = px.bar(action_counts, x="Count", y="Action", orientation="h",
                         color="Count", color_continuous_scale=["#BFDBFE","#1E4DB7"])
            fig2.update_layout(showlegend=False, height=240,
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                font_color=t["muted"], margin=dict(l=0,r=0,t=10,b=0))
            fig2.update_xaxes(showgrid=False, color=t["muted"])
            fig2.update_yaxes(showgrid=False, color=t["muted"])
            st.plotly_chart(fig2, use_container_width=True, config=plot_config())
        else:
            st.info("No audit data yet.")

    st.divider()

    # Login stats
    st.subheader("Login Attempts")
    lc1, lc2, lc3 = st.columns(3)
    lc1.markdown(stat_card("Successful Logins", login_stats["successful"], "#10B981"), unsafe_allow_html=True)
    lc2.markdown(stat_card("Failed Attempts",   login_stats["failed"],     "#DC2626"), unsafe_allow_html=True)
    total = login_stats["successful"] + login_stats["failed"]
    rate  = round((login_stats["successful"] / total * 100), 1) if total > 0 else 0
    lc3.markdown(stat_card("Success Rate", f"{rate}%", "#3B7DD8"), unsafe_allow_html=True)

    # Recent failed logins
    failed_logins = db.get_failed_logins(client, limit=5)
    if failed_logins:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        st.caption("Recent Failed Login Attempts")
        for fl in failed_logins:
            st.markdown(f"""<div class="row-card" style="border-left:3px solid #DC2626;">
                <span style="font-weight:600;color:{t['text']};">{fl.get('detail','Unknown')}</span><br>
                <span style="color:{t['muted']};font-size:11px;">{fl['logged_at'][:19]}</span>
            </div>""", unsafe_allow_html=True)

    st.divider()

    # Recent signups + Recent activity side by side
    ra, rb = st.columns(2)

    with ra:
        st.subheader("Recent Signups")
        recent_users = db.get_recent_signups(client, limit=5)
        for u in recent_users:
            status_color = "#10B981" if u.get("is_active", True) else "#DC2626"
            status_txt   = "Active" if u.get("is_active", True) else "Disabled"
            st.markdown(f"""<div class="row-card">
                <span style="font-weight:600;color:{t['text']};">{u['full_name']}</span>
                &nbsp;<span style="background:{status_color}22;color:{status_color};border:0.5px solid {status_color}44;
                    border-radius:20px;padding:1px 8px;font-size:9px;font-weight:700;">{status_txt}</span><br>
                <span style="color:{t['muted']};font-size:11px;">@{u['username']} &nbsp;&middot;&nbsp; {u['created_at'][:10]}</span>
            </div>""", unsafe_allow_html=True)

    with rb:
        st.subheader("Recent Activity")
        recent_logs = db.get_audit_log(client, limit=8)
        for log in recent_logs:
            status_color = {"SUCCESS":"#10B981","FAILED":"#DC2626","PENDING":"#F59E0B"}.get(log["status"],"#8B949E")
            st.markdown(f"""<div class="row-card">
                <span style="font-weight:600;color:{t['text']};">{log['action']}</span>
                &nbsp;<span style="background:{status_color}22;color:{status_color};border:0.5px solid {status_color}44;
                    border-radius:20px;padding:1px 8px;font-size:9px;font-weight:700;">{log['status']}</span><br>
                <span style="color:{t['muted']};font-size:11px;">{log.get('detail') or ''} &nbsp;&middot;&nbsp; {log['logged_at'][:19]}</span>
            </div>""", unsafe_allow_html=True)


def page_admin_panel():
    t = get_theme()
    st.title("Admin Panel")
    st.caption("Manage users and platform settings")
    st.divider()

    # ── User Management ──
    st.subheader("User Management")
    users = db.get_all_users_detailed(client)

    # Export users CSV
    if users:
        export_data = db.export_users_csv_data(client)
        df_export = pd.DataFrame(export_data)
        st.download_button(
            "Export Users CSV",
            df_export.to_csv(index=False),
            "sentinel_eye_users.csv",
            "text/csv",
            key="export_users"
        )

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    for user in users:
        col1, col2, col3 = st.columns([5, 1, 1])
        with col1:
            verified   = "Verified" if user["is_verified"] else "Not verified"
            role_txt   = "Admin" if user["is_admin"] else "User"
            is_active  = user.get("is_active", True)
            status_color = "#10B981" if is_active else "#DC2626"
            status_txt   = "Active" if is_active else "Disabled"
            st.markdown(f"""<div class="row-card">
                <span style="font-weight:700;color:{t['text']};">{user['full_name']}</span>
                &nbsp;<span style="background:{t['primary']}22;color:{t['primary']};border:0.5px solid {t['primary']}44;border-radius:20px;padding:1px 8px;font-size:9px;font-weight:700;">{role_txt}</span>
                &nbsp;<span style="background:{status_color}22;color:{status_color};border:0.5px solid {status_color}44;border-radius:20px;padding:1px 8px;font-size:9px;font-weight:700;">{status_txt}</span><br>
                <span style="color:{t['muted']};font-size:11px;">@{user['username']} &nbsp;&middot;&nbsp; {user['email']} &nbsp;&middot;&nbsp; {verified} &nbsp;&middot;&nbsp; Joined: {user['created_at'][:10]}</span>
            </div>""", unsafe_allow_html=True)
        with col2:
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
            if not user["is_admin"]:
                label = "Enable" if not user.get("is_active", True) else "Disable"
                if st.button(label, key=f"toggle_{user['id']}"):
                    db.toggle_user_active(client, user["id"], not user.get("is_active", True))
                    st.rerun()
        with col3:
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
            if not user["is_admin"]:
                if st.button("Delete", key=f"del_{user['id']}"):
                    db.delete_user(client, user["id"])
                    st.success(f"User {user['username']} deleted.")
                    st.rerun()

    st.divider()

    # ── System Info ──
    st.subheader("System Information")
    try:
        db_check = db.get_platform_stats(client)
        db_status = "Connected"
        db_color  = "#10B981"
    except Exception:
        db_status = "Error"
        db_color  = "#DC2626"

    si1, si2 = st.columns(2)
    with si1:
        st.markdown(f"""<div class="row-card">
            <span style="font-weight:600;color:{t['text']};">Supabase Database</span><br>
            <span style="color:{db_color};font-size:12px;font-weight:700;">{db_status}</span>
        </div>""", unsafe_allow_html=True)
    with si2:
        st.markdown(f"""<div class="row-card">
            <span style="font-weight:600;color:{t['text']};">App Version</span><br>
            <span style="color:{t['muted']};font-size:12px;">Sentinel Eye v1.0</span>
        </div>""", unsafe_allow_html=True)

def page_audit_log():
    t = get_theme()
    st.title("Audit Log")
    st.caption("All actions recorded across the application")
    st.divider()
    logs = db.get_audit_log(client, limit=500) if st.session_state.is_admin else db.get_audit_log(client, session_id=st.session_state.session_id, limit=100)
    if not logs:
        st.info("No audit log entries yet.")
        return

    # Filter by action type
    all_actions = sorted(set(log["action"] for log in logs))
    action_filter = st.selectbox("Filter by Action", ["All"] + all_actions)
    filtered_logs = [l for l in logs if action_filter == "All" or l["action"] == action_filter]

    # Export CSV
    if filtered_logs:
        df_audit = pd.DataFrame(filtered_logs)
        st.download_button("Export CSV", df_audit.to_csv(index=False), "audit_log.csv", "text/csv", key="export_audit")

    st.caption(f"Showing {len(filtered_logs)} entries")
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

    for log in filtered_logs:
        status_color = {"SUCCESS":"#10B981","FAILED":"#DC2626","PENDING":"#F59E0B"}.get(log["status"],"#8B949E")
        st.markdown(f"""<div class="row-card">
            <span style="font-weight:700;color:{t['text']};">{log['action']}</span>&nbsp;&nbsp;<span style="background:{status_color}22;color:{status_color};border:0.5px solid {status_color}44;border-radius:20px;padding:2px 8px;font-size:10px;font-weight:700;">{log['status']}</span><br>
            <span style="color:{t['muted']};font-size:12px;">{log.get('detail') or ''}&nbsp;&middot;&nbsp;{log['logged_at'][:19]}</span>
        </div>""", unsafe_allow_html=True)

def page_settings():
    t = get_theme()
    st.title("Settings")
    st.divider()

    # Appearance — available to everyone
    st.subheader("Appearance")
    current = "Dark" if st.session_state.theme == "dark" else "Light"
    theme_label = "Switch to Light Mode" if st.session_state.theme == "dark" else "Switch to Dark Mode"
    st.markdown(f"""<div class="row-card">
        <span style="font-weight:600;color:{t['text']};">Current theme: {current} Mode</span><br>
        <span style="color:{t['muted']};font-size:12px;">Toggle between light and dark interface</span>
    </div>""", unsafe_allow_html=True)
    if st.button(theme_label):
        st.session_state.theme = "dark" if st.session_state.theme == "light" else "light"
        st.rerun()

    if not st.session_state.logged_in:
        st.divider()
        st.info("Sign in to access account settings.")
        return

    user = db.get_user_by_id(client, st.session_state.user_id)
    if not user:
        return

    st.divider()
    st.subheader("Account Information")
    st.markdown(f"""<div class="row-card">
        <span style="font-weight:700;color:{t['text']};">{user['full_name']}</span><br>
        <span style="color:{t['muted']};font-size:13px;">Username: @{user['username']}&nbsp;&middot;&nbsp;Email: {user['email']}&nbsp;&middot;&nbsp;Joined: {user['created_at'][:10]}</span>
    </div>""", unsafe_allow_html=True)

    st.divider()
    st.subheader("Change Password")
    with st.form("change_password", clear_on_submit=True):
        old_pass  = st.text_input("Current Password", type="password")
        new_pass  = st.text_input("New Password", type="password", placeholder="Min 8 characters")
        conf_pass = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Update Password", use_container_width=True)
    if submitted:
        if not old_pass or not new_pass or not conf_pass:
            st.warning("Please fill in all fields.")
        elif new_pass == old_pass:
            st.error("New password cannot be the same as your current password.")
        elif new_pass != conf_pass:
            st.error("New passwords do not match.")
        else:
            result = auth_module.change_password(client, st.session_state.user_id, old_pass, new_pass)
            if result.get("success"):
                st.success("Password updated successfully.")
            elif result.get("error") == "wrong_password":
                st.error("Current password is incorrect.")
            elif result.get("error") == "password_too_short":
                st.error("New password must be at least 8 characters.")

    if not st.session_state.is_admin:
        st.divider()
        st.subheader("Session Data")
        if st.button("Clear my threat history", type="secondary"):
            db.delete_session_threats(client, st.session_state.session_id)
            db.log_action(client, "CLEAR_THREATS", session_id=st.session_state.session_id)
            st.success("Threat history cleared.")
            st.rerun()

def main():
    if db.is_first_run(client):
        page_admin_setup()
        st.stop()

    if st.session_state.get("show_login"):
        st.session_state["show_login"] = False
        st.session_state["username"] = None
        st.session_state["full_name"] = None
        st.rerun()

    if not st.session_state.logged_in and not st.session_state.get("username"):
        page_login()
        st.stop()

    page = render_sidebar()

    page_map = {
        "Overview":         page_admin_overview if st.session_state.is_admin else page_overview,
        "Log Analysis":     page_log_analysis,
        "Threat Results":   page_threat_results,
        "MITRE ATT&CK":     page_mitre,
        "Incident Reports": page_incident_reports,
        "Guide":            page_guide,
        "Assistant":        page_assistant,
        "Admin Panel":      page_admin_panel,
        "Audit Log":        page_audit_log,
        "Settings":         page_settings,
    }

    page_fn = page_map.get(page)
    if page_fn:
        page_fn()


main()