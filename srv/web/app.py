
import base64
import hashlib
import hmac
import html
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import string
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from collections import deque
from datetime import date as date_value_type, datetime, time as time_value_type, timedelta
from pathlib import Path
from urllib.parse import urlencode, urlparse

import pymysql
from active_broadcast_store import list_active_broadcasts
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError
except ImportError:
    PasswordHasher = None
    InvalidHashError = VerificationError = Exception
try:
    from ldap3 import ALL, BASE, SIMPLE, SUBTREE, Connection, Server, Tls
    from ldap3.utils.conv import escape_filter_chars
except ImportError:
    ALL = BASE = SIMPLE = SUBTREE = Connection = Server = Tls = None

    def escape_filter_chars(value):
        text = str(value or "")
        return (
            text.replace("\\", r"\5c")
            .replace("*", r"\2a")
            .replace("(", r"\28")
            .replace(")", r"\29")
            .replace("\x00", r"\00")
        )
try:
    from authlib.integrations.flask_client import OAuth
except ImportError:
    OAuth = None
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
except ImportError:
    OneLogin_Saml2_Auth = None
import endpoints
from clientd import (
    DESKTOP_CLIENT_HEADER,
    GUEST_MEMBER_TOKEN,
    GUEST_TOKEN_TTL_SECONDS,
    build_desktop_refresh_token,
    desktop_member_user_id,
    build_desktop_token,
    desktop_member_token,
    fetch_active_broadcast,
    first_audio_name,
    groups_for_user as desktop_groups_for_user,
    is_desktop_member_token,
    normalize_color,
    product_name as desktop_product_name,
    user_has_connected_client,
    user_in_broadcast,
    verify_desktop_refresh_token,
    verify_desktop_token,
)
from dotenv import load_dotenv
from group_features import all_recipients_disabled, ensure_group_feature_schema, record_is_active_emergency, suspended_bell_groups
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    session,
)
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException


WEB_DIR = Path(__file__).resolve().parent
BASE_DIR = WEB_DIR.parent.parent
WEB_ROOT_DIR = BASE_DIR / "srv" / "web"
WEB_PAGES_DIR = WEB_ROOT_DIR / "pages"
WEB_STATIC_DIR = WEB_ROOT_DIR / "assets"
WEB_ERROR_DIR = WEB_ROOT_DIR / "errors"
DEMO_MODE_HTML_PATH = WEB_ROOT_DIR / "demomode.html"
ENDPOINT_MODULES_DIR = endpoints.MODULE_STORE_DIR
ASSET_DIR = Path(os.getenv("ASSET_PATH", "/var/lib/openpagingserver/assets"))
CERTIFICATE_DIR = Path(os.getenv("OPS_CERTIFICATE_PATH", "/var/lib/openpagingserver/certificates"))
load_dotenv(BASE_DIR / ".env")

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
APP_DEBUG = str(os.getenv("DEBUG", "")).strip().lower() in {"1", "true", "yes", "on"}
ALLOW_SEARCH_INDEX = str(os.getenv("ALLOW_SEARCH_INDEX", "")).strip().lower() == "yes"
TRACEBACKS = {}
API_TOKEN_LABEL_LENGTH = 120
ENDPOINT_IPC_TIMEOUT = max(2.0, float(os.getenv("OPS_ENDPOINT_IPC_TIMEOUT", "5")))
API_TOKEN_HASHER = PasswordHasher() if PasswordHasher is not None else None
MESSAGE_VENDOR_SCHEMA_READY = False
CERTIFICATE_SCHEMA_READY = False
CERTIFICATE_SCHEMA_LOCK = threading.Lock()
IDENTITY_ACCESS_SCHEMA_READY = False
WEB_RATE_LIMIT_BUCKETS = {}
WEB_RATE_LIMIT_LOCK = threading.Lock()
WEB_RATE_LIMIT_EXEMPT_PREFIXES = ("/bundled-assets/", "/assets/file/", "/favicon.ico", "/robots.txt")
TEMP_ASSET_ACCESS_SECONDS = 48 * 60 * 60
TEMP_ASSET_ACCESS = {}
TEMP_ASSET_ACCESS_LOCK = threading.Lock()
DESKTOP_SSO_SESSION_KEY = "desktop_sso_request_id"
DESKTOP_GUEST_SESSION_KEY = "desktop_guest_receiver"
DESKTOP_SSO_REQUEST_TTL_SECONDS = 600
DESKTOP_SSO_COMPLETE_ROUTE = "/desktop/sso/complete"
def _positive_int_env(name, default):
    try:
        return max(1, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


DESKTOP_SSO_REQUEST_TTL_SECONDS = _positive_int_env("OPS_DESKTOP_SSO_REQUEST_TTL_SECONDS", DESKTOP_SSO_REQUEST_TTL_SECONDS)


USER_SESSION_TOUCH_INTERVAL_SECONDS = _positive_int_env("OPS_USER_SESSION_TOUCH_INTERVAL_SECONDS", 60)
EXTERNAL_IDENTITY_CHECK_INTERVAL_SECONDS = _positive_int_env("OPS_EXTERNAL_IDENTITY_CHECK_INTERVAL_SECONDS", 3600)
SCIM_RECONCILE_INTERVAL_SECONDS = max(120, _positive_int_env("OPS_SCIM_RECONCILE_INTERVAL_SECONDS", 300))
SCIM_RECONCILE_THREAD = None
SCIM_RECONCILE_LOCK = threading.Lock()


def generate_runtime_fallback_secret_seed(length=256):
    symbol_chars = string.punctuation
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + symbol_chars
    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(symbol_chars),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(max(0, int(length) - len(chars))))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def derive_app_secret_key():
    explicit_secret = os.getenv("FLASK_SECRET_KEY")
    if explicit_secret:
        return explicit_secret
    if DB_PASS not in (None, ""):
        return hashlib.sha256(DB_PASS.encode()).hexdigest()
    return hashlib.sha256(generate_runtime_fallback_secret_seed(256).encode()).hexdigest()


app = Flask(
    __name__,
    static_folder=str(WEB_STATIC_DIR),
    static_url_path="/bundled-assets",
)
app.secret_key = derive_app_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=128 * 1024 * 1024,
)
DEMO_MODE = str(os.getenv("DEMO_MODE", "")).strip().lower() in {"1", "true", "yes", "on"}
DEMO_MODE_MAINTENANCE_USER = str(os.getenv("DEMOMODE_MAINTENANCE_USER", "") or "").strip()
DEMO_MODE_MAINTENANCE_SESSION_KEY = "demo_mode_maintenance"
DEMO_MODE_MAINTENANCE_PENDING_KEY = "demo_mode_maintenance_pending"
DEMO_MODE_MAINTENANCE_LAST_ACTIVITY_KEY = "demo_mode_maintenance_last_activity"
DEMO_MODE_MAINTENANCE_IDLE_TIMEOUT_SECONDS = 600
DEMO_MODE_MAINTENANCE_BLOCK_SETTING = "demo_mode_block_non_maintenance"
OPS_SYSTEMD_UNIT = "openpagingserver.service"
ADMIN_ROLE_VALUES = {"admin", "tempadmin"}
RECEIVER_ROLE_VALUES = {"receiver", "tempreceiver"}
IDENTITY_PROVIDER_VALUES = {"local", "ldap", "oidc", "saml"}
REDIRECT_IDENTITY_PROVIDER_VALUES = {"oidc", "saml"}
IDENTITY_FAILURE_BEHAVIORS = {"deny", "fallback"}
ACCOUNT_EXPIRATION_NOTIFY_SETTING = "notify_users_about_account_expiration"
GUEST_RECEIVER_SETTING = "guest_receiver_enabled"
ACCOUNT_EXPIRATION_WARNING_WINDOW_DAYS = 14
LDAP_ROLE_MAPPING_SETTING = "ldap_role_mappings"
OIDC_ROLE_MAPPING_SETTING = "oidc_role_mappings"
SAML_ROLE_MAPPING_SETTING = "saml_role_mappings"
USER_PERMISSION_LABELS = [
    ("paging", "Send Pages"),
    ("messages", "Send Messages"),
    ("messages-add", "Add Messages"),
    ("messages-edit", "Edit Messages"),
    ("messages-delete", "Delete Messages"),
    ("history", "View History"),
    ("bells", "Manage Bells"),
    ("assets", "View Assets"),
    ("asset-edit", "Upload Assets"),
    ("groups-manage", "Manage Groups"),
    ("broadcasts-manage", "Manage Broadcasts"),
]
DEFAULT_USER_PAGE_PERMISSIONS = {
    "admin": {"all"},
    "tempadmin": {"all"},
    "user": {"paging", "messages", "history", "bells", "assets"},
    "tempuser": {"paging", "messages", "history", "bells", "assets"},
    "receiver": set(),
    "tempreceiver": set(),
}
LDAP_SETTING_DEFAULTS = {
    "identity_provider": "local",
    "ldap_enabled": "0",
    "ldap_template": "generic",
    "ldap_server_address": "",
    "ldap_server_port": "389",
    "ldap_secure": "0",
    "ldap_ca_certificate": "",
    "ldap_base_dn": "",
    "ldap_bind_username": "",
    "ldap_bind_password": "",
    "ldap_password_change_url": "",
    "ldap_login_field": "uid",
    "ldap_user_search_filter": "({field}={username})",
    "ldap_display_name_field": "cn",
    "ldap_email_field": "mail",
    "ldap_required_group": "",
    "ldap_admin_group": "",
    "ldap_auto_create_users": "0",
    "ldap_local_login_fallback": "1",
    "ldap_connection_timeout": "5",
    "ldap_failure_behavior": "deny",
    "ldap_group_sync": "1",
    "ldap_default_role": "receiver",
    LDAP_ROLE_MAPPING_SETTING: "[]",
}
SSO_SETTING_DEFAULTS = {
    "identity_redirect_auto": "1",
    "identity_allow_local_login": "0",
}
OIDC_SETTING_DEFAULTS = {
    "oidc_discovery_url": "",
    "oidc_client_id": "",
    "oidc_client_secret": "",
    "oidc_password_change_url": "",
    "oidc_scim_enabled": "0",
    "oidc_scim_base_url": "",
    "oidc_scim_bearer_token": "",
    "oidc_scim_timeout": "5",
    "oidc_scim_sync_groups": "1",
    "oidc_scope": "openid profile email",
    "oidc_username_claim": "preferred_username",
    "oidc_display_name_claim": "name",
    "oidc_email_claim": "email",
    "oidc_groups_claim": "groups",
    "oidc_required_group": "",
    "oidc_admin_group": "",
    "oidc_auto_create_users": "0",
    "oidc_group_sync": "1",
    "oidc_default_role": "receiver",
    OIDC_ROLE_MAPPING_SETTING: "[]",
}
SAML_SETTING_DEFAULTS = {
    "saml_idp_entity_id": "",
    "saml_sso_url": "",
    "saml_x509_certificate": "",
    "saml_password_change_url": "",
    "saml_scim_enabled": "0",
    "saml_scim_base_url": "",
    "saml_scim_bearer_token": "",
    "saml_scim_timeout": "5",
    "saml_scim_sync_groups": "1",
    "saml_username_attribute": "uid",
    "saml_display_name_attribute": "displayName",
    "saml_email_attribute": "mail",
    "saml_groups_attribute": "groups",
    "saml_required_group": "",
    "saml_admin_group": "",
    "saml_auto_create_users": "0",
    "saml_group_sync": "1",
    "saml_default_role": "receiver",
    SAML_ROLE_MAPPING_SETTING: "[]",
}
LOGIN_SETTING_DEFAULTS = {
    ACCOUNT_EXPIRATION_NOTIFY_SETTING: "1",
    GUEST_RECEIVER_SETTING: "0",
}


def guest_receiver_enabled(data=None):
    config = data if isinstance(data, dict) else settings()
    return str(config.get(GUEST_RECEIVER_SETTING) or "0").strip() == "1"


def normalize_ldap_default_role(value):
    normalized = str(value or "receiver").strip().lower()
    aliases = {
        "tempadmin": "admin",
        "tempuser": "user",
        "tempreceiver": "receiver",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"admin", "user", "receiver"}:
        return "receiver"
    return normalized


def normalize_identity_mapping_role(value):
    normalized = str(value or "receiver").strip().lower()
    aliases = {
        "tempadmin": "admin",
        "tempuser": "user",
        "tempreceiver": "receiver",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in {"none", "admin", "user", "receiver"}:
        return normalized
    return "receiver"


class IdentityAccessDenied(RuntimeError):
    pass


def is_external_auth_provider(provider):
    return str(provider or "").strip().lower() in {"ldap", "oidc", "saml"}


def identity_password_change_setting_name(provider):
    normalized = str(provider or "").strip().lower()
    if normalized == "ldap":
        return "ldap_password_change_url"
    if normalized == "oidc":
        return "oidc_password_change_url"
    if normalized == "saml":
        return "saml_password_change_url"
    return ""


def identity_password_change_url(provider_or_user, data=None):
    provider = provider_or_user
    if isinstance(provider_or_user, dict):
        provider = provider_or_user.get("auth_provider")
    setting_name = identity_password_change_setting_name(provider)
    if not setting_name:
        return ""
    config = identity_provider_settings(data)
    return str(config.get(setting_name) or "").strip()


def identity_access_denied_message(data=None):
    config = data if isinstance(data, dict) else settings()
    product = str((config or {}).get("product_name") or "Open Paging Server").strip() or "Open Paging Server"
    return f"You don't have access to {product}. Contact your system administrator for more information."


def scim_provider_supported(provider):
    return str(provider or "").strip().lower() in REDIRECT_IDENTITY_PROVIDER_VALUES


def scim_provider_enabled(provider, data=None):
    normalized = str(provider or "").strip().lower()
    if normalized not in REDIRECT_IDENTITY_PROVIDER_VALUES:
        return False
    config = identity_provider_settings(data)
    return (
        config.get(f"{normalized}_scim_enabled") == "1"
        and bool(str(config.get(f"{normalized}_scim_base_url") or "").strip())
        and bool(str(config.get(f"{normalized}_scim_bearer_token") or "").strip())
    )


def parse_account_expiration_value(value, date_only_end_of_day=True):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date_value_type):
        clock = time_value_type(23, 59, 59) if date_only_end_of_day else time_value_type(0, 0, 0)
        return datetime.combine(value, clock)
    text = str(value or "").strip()
    if text in {"0000-00-00", "0000-00-00 00:00:00", "None"}:
        return None
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    try:
        parsed_date = datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        return None
    clock = time_value_type(23, 59, 59) if date_only_end_of_day else time_value_type(0, 0, 0)
    return datetime.combine(parsed_date, clock)


def user_account_expiration_at(user, date_only_end_of_day=True):
    return parse_account_expiration_value((user or {}).get("accountexpire"), date_only_end_of_day=date_only_end_of_day)


def user_account_is_expired(user, now=None):
    expires_at = user_account_expiration_at(user)
    return bool(expires_at and expires_at <= (now or datetime.now()))


def locale_date_text(value):
    if not isinstance(value, datetime):
        return ""
    return value.strftime("%x")


def locale_time_text(value):
    if not isinstance(value, datetime):
        return ""
    return value.strftime("%X")


def humanize_remaining_duration(delta):
    total_seconds = max(0, int((delta or timedelta()).total_seconds()))
    if total_seconds < 60:
        return "less than 1 minute"
    total_minutes = total_seconds // 60
    months = total_minutes // (30 * 24 * 60)
    total_minutes -= months * 30 * 24 * 60
    days = total_minutes // (24 * 60)
    total_minutes -= days * 24 * 60
    hours = total_minutes // 60
    minutes = total_minutes - (hours * 60)
    parts = []
    for count, label in (
        (months, "month"),
        (days, "day"),
        (hours, "hour"),
        (minutes, "minute"),
    ):
        if count:
            parts.append(f"{count} {label}{'' if count == 1 else 's'}")
    return " ".join(parts) if parts else "less than 1 minute"


def account_expiration_warning_enabled(data=None):
    source = data if isinstance(data, dict) else settings()
    return str(source.get(ACCOUNT_EXPIRATION_NOTIFY_SETTING, "1") or "1") == "1"


def int_env(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _trusted_reverse_proxy(remote_addr):
    try:
        remote_ip = ipaddress.ip_address(str(remote_addr or "").strip())
    except ValueError:
        return False
    for part in str(os.getenv("WEB_REVERSE_PROXY_ALLOWED", "") or "").split(","):
        token = part.strip().strip("'").strip('"')
        if not token:
            continue
        try:
            if remote_ip in ipaddress.ip_network(token, strict=False):
                return True
        except ValueError:
            continue
    return False


def _forwarded_client_ip():
    values = (
        request.headers.get("X-Forwarded-For"),
        request.headers.get("X-Real-IP"),
        request.headers.get("CF-Connecting-IP"),
        request.headers.get("True-Client-IP"),
    )
    for value in values:
        for part in str(value or "").split(","):
            token = part.strip()
            if not token:
                continue
            try:
                return str(ipaddress.ip_address(token))
            except ValueError:
                continue
    return ""


def client_ip():
    remote_addr = str(request.remote_addr or "").strip()
    if _trusted_reverse_proxy(remote_addr):
        forwarded_addr = _forwarded_client_ip()
        if forwarded_addr:
            return forwarded_addr
    return remote_addr or "unknown"


def rate_limit_exceeded(scope, key, limit, window_seconds, buckets=WEB_RATE_LIMIT_BUCKETS, lock=WEB_RATE_LIMIT_LOCK):
    if limit <= 0 or window_seconds <= 0:
        return False, 0
    now = time.monotonic()
    bucket_key = (scope, str(key or "unknown"))
    with lock:
        bucket = buckets.setdefault(bucket_key, deque())
        cutoff = now - window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(1, int(window_seconds - (now - bucket[0])))
            return True, retry_after
        bucket.append(now)
    return False, 0


def rate_limited_response(retry_after):
    response = Response("Too many requests. Please wait and try again.", status=429, mimetype="text/plain")
    response.headers["Retry-After"] = str(max(1, int(retry_after or 1)))
    return response


def check_rate_limit(scope, key, limit, window_seconds):
    limited, retry_after = rate_limit_exceeded(scope, key, limit, window_seconds)
    if limited:
        return rate_limited_response(retry_after)
    return None


@app.before_request
def detect_desktop_client_context():
    desktop_param = request.args.get("desktop_client")
    desktop_header = str(request.headers.get(DESKTOP_CLIENT_HEADER) or request.headers.get("X-Desktop-Client") or "").strip().lower()
    if (
        ((desktop_param is not None and str(desktop_param).strip().lower() in {"1", "true", "yes", "on"}) or desktop_header in {"1", "true", "yes", "on"})
        and not bool(session.get("desktop_client"))
    ):
        session["desktop_client"] = True
    if bool(session.get("desktop_client")):
        session.permanent = True


SUPPORTED_BROWSER_MIN_VERSION = {
    "chrome": 87,
    "chromium": 87,
    "edge": 87,
    "opera": 73,
    "firefox": 66,
}
SUPPORTED_SAFARI_MIN_VERSION = (14, 1)
SUPPORTED_IOS_WEBKIT_MIN_VERSION = (14, 5)
BROWSER_GATE_EXEMPT_PREFIXES = ("/api/", "/assets/", "/bundled-assets/", "/.well-known/")
BROWSER_GATE_EXEMPT_PATHS = {"/favicon.ico", "/robots.txt"}


def _ua_version_int(token, low):
    match = re.search(re.escape(token) + r"(\d+)", low)
    return int(match.group(1)) if match else None


def browser_meets_minimum(user_agent):
    ua = str(user_agent or "").strip()
    if not ua:
        return None
    low = ua.lower()

    if "msie " in low or "trident/" in low:
        return False

    if "iphone" in low or "ipod" in low or ("ipad" in low and "version/" in low):
        match = re.search(r"os (\d+)[_.](\d+)", low)
        if match:
            return (int(match.group(1)), int(match.group(2))) >= SUPPORTED_IOS_WEBKIT_MIN_VERSION
        return None

    if re.search(r"\bedge/\d", low):
        return False

    if "edg/" in low or "edga/" in low:
        version = _ua_version_int("edg/", low) or _ua_version_int("edga/", low)
        return version is None or version >= SUPPORTED_BROWSER_MIN_VERSION["edge"]

    if "opr/" in low:
        version = _ua_version_int("opr/", low)
        return version is None or version >= SUPPORTED_BROWSER_MIN_VERSION["opera"]
    if low.startswith("opera/"):
        return False

    if "firefox/" in low and "seamonkey" not in low:
        version = _ua_version_int("firefox/", low)
        return version is None or version >= SUPPORTED_BROWSER_MIN_VERSION["firefox"]

    if "chrome/" in low or "chromium/" in low or "crios/" in low:
        version = (
            _ua_version_int("chrome/", low)
            or _ua_version_int("chromium/", low)
            or _ua_version_int("crios/", low)
        )
        return version is None or version >= SUPPORTED_BROWSER_MIN_VERSION["chrome"]

    if "safari/" in low and "version/" in low:
        match = re.search(r"version/(\d+)\.(\d+)", low)
        if match:
            return (int(match.group(1)), int(match.group(2))) >= SUPPORTED_SAFARI_MIN_VERSION
        return None

    return None


def render_unsupported_browser_response():
    if show_online_docs_on_error_page():
        docs = (
            ' <a href="http://docs.openpagingserver.org/user/web/supportedbrowsers">'
            "Learn more about supported browsers</a>."
        )
    else:
        docs = ""
    body = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>Your browser is outdated and unsupported</title>\n"
        "<style>body{font-family:Arial,Helvetica,sans-serif;margin:0;padding:40px;"
        "color:#333;background:#fff;}h1{font-weight:normal;}"
        "p{max-width:600px;line-height:1.5;}a{color:#1565C0;}</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Your browser is outdated and unsupported</h1>\n"
        "<p>Your browser is too old to support dependencies of this service and to "
        "securely connect to the server. Please update your browser." + docs + "</p>\n"
        "</body>\n"
        "</html>\n"
    )
    response = Response(body, status=403, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.before_request
def enforce_supported_browser():
    if request.method not in {"GET", "HEAD"}:
        return None
    path = request.path or ""
    if path in BROWSER_GATE_EXEMPT_PATHS or any(
        path.startswith(prefix) for prefix in BROWSER_GATE_EXEMPT_PREFIXES
    ):
        return None
    if desktop_client_context():
        return None
    if browser_meets_minimum(request.headers.get("User-Agent")) is False:
        return render_unsupported_browser_response()
    return None


@app.before_request
def enforce_web_rate_limits():
    if str(os.getenv("WEB_RATE_LIMIT_ENABLE", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return None
    path = request.path or ""
    if any(path.startswith(prefix) for prefix in WEB_RATE_LIMIT_EXEMPT_PREFIXES):
        return None
    ip_key = client_ip()
    checks = [
        ("web-ip-minute", ip_key, int_env("WEB_RATE_LIMIT_IP_PER_MINUTE", 240), 60),
        ("web-ip-hour", ip_key, int_env("WEB_RATE_LIMIT_IP_PER_HOUR", 3000), 3600),
    ]
    user_id = session.get("user_id")
    if user_id not in (None, ""):
        checks.append(("web-user-minute", user_id, int_env("WEB_RATE_LIMIT_USER_PER_MINUTE", 300), 60))
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        checks.append(("web-post-ip-minute", ip_key, int_env("WEB_RATE_LIMIT_POST_IP_PER_MINUTE", 60), 60))
        if user_id not in (None, ""):
            checks.append(("web-post-user-minute", user_id, int_env("WEB_RATE_LIMIT_POST_USER_PER_MINUTE", 45), 60))
    for scope, key, limit, window_seconds in checks:
        response = check_rate_limit(scope, key, limit, window_seconds)
        if response is not None:
            return response
    return None


@app.before_request
def enforce_demo_mode_maintenance_controls():
    if not demo_mode_active() or not demo_mode_maintenance_username():
        return None

    path = request.path or ""
    exempt_paths = {"/", "/index", "/logout", "/login/basic-captcha.svg", "/favicon.ico", "/robots.txt", "/demo-mode-maintenance"}
    exempt_prefixes = ("/bundled-assets/", "/assets/", "/demo-mode")
    is_exempt = path in exempt_paths or any(path.startswith(prefix) for prefix in exempt_prefixes)
    now_value = time.time()

    if demo_mode_maintenance_session_active():
        try:
            last_activity = float(session.get(DEMO_MODE_MAINTENANCE_LAST_ACTIVITY_KEY, "0") or 0)
        except (TypeError, ValueError):
            last_activity = 0
        if last_activity and (now_value - last_activity) > DEMO_MODE_MAINTENANCE_IDLE_TIMEOUT_SECONDS:
            session.clear()
            return redirect("/")
        if not is_exempt:
            demo_mode_maintenance_touch(now_value)
        if demo_mode_maintenance_popup_pending():
            allowed_paths = {"/", "/index", "/logout", "/robots.txt", "/demo-mode-maintenance"}
            allowed_prefixes = ("/bundled-assets/", "/assets/", "/demo-mode")
            if path not in allowed_paths and not any(path.startswith(prefix) for prefix in allowed_prefixes):
                return redirect("/")
        return None

    if demo_mode_maintenance_block_enabled():
        user_id = session.get("user_id")
        if user_id not in (None, ""):
            session.clear()
            return redirect("/")
    return None


@app.before_request
def enforce_web_page_permissions():
    path = request.path or ""
    if not path:
        return None
    if path.startswith("/api/") or path.startswith("/bundled-assets/") or path.startswith("/demo-mode"):
        return None
    if path in {"/", "/index", "/login", "/logout", "/login/basic-captcha.svg", "/favicon.ico", "/robots.txt"}:
        return None
    if path in {"/assets/", "/assets/index"} and request.args.get("raw"):
        return None
    user = current_user()
    if not isinstance(user, dict):
        return None
    normalized_path = path[:-1] if path.endswith("/") and path != "/" else path
    if normalized_path.startswith("/dashboard"):
        if not can_access_page(user, "dashboard"):
            abort(403)
        return None
    if normalized_path.startswith("/history"):
        if not can_access_page(user, "history"):
            abort(403)
        return None
    if normalized_path.startswith("/paging"):
        if not can_access_page(user, "paging"):
            abort(403)
        return None
    if normalized_path.startswith("/bells"):
        if not can_access_page(user, "bells"):
            abort(403)
        return None
    if normalized_path in {"/assets", "/assets/index"}:
        if not can_view_assets_page(user):
            abort(403)
        return None
    if normalized_path.startswith("/messages/new"):
        if not can_create_messages(user):
            abort(403)
        return None
    if normalized_path.startswith("/messages/edit"):
        if not can_edit_messages(user):
            abort(403)
        return None
    if normalized_path.startswith("/messages/variable-api-test"):
        if not can_manage_messages(user):
            abort(403)
        return None
    if normalized_path.startswith("/messages/send") or normalized_path.startswith("/messages/custom"):
        if not can_send_messages(user):
            abort(403)
        return None
    if normalized_path.startswith("/messages"):
        if not (can_send_messages(user) or can_manage_messages(user)):
            abort(403)
        return None
    if normalized_path.startswith("/admin/manage-broadcasts"):
        if not (is_admin_user(user) or can_manage_broadcasts(user)):
            abort(403)
        return None
    if normalized_path.startswith("/admin/manage-groups"):
        if not (is_admin_user(user) or can_manage_groups(user)):
            abort(403)
        return None
    return None


@app.before_request
def enforce_demo_mode_protected_pages():
    if not demo_mode_enabled() or request.method not in {"GET", "HEAD"}:
        return None
    normalized_path = (request.path or "").rstrip("/") or "/"
    if normalized_path == "/admin/settings/certificates":
        return redirect("/dashboard?demomodal=settings")
    return None


def dispatch_web_page(relative_path):
    page_path = (WEB_PAGES_DIR / relative_path).resolve()
    if page_path.suffix == "":
        page_path = page_path.with_suffix(".py")
    root = WEB_PAGES_DIR.resolve()
    if root not in page_path.parents and page_path != root:
        abort(404)
    if not page_path.is_file():
        abort(404)
    module_name = "ops_web_page_" + re.sub(r"[^A-Za-z0-9_]", "_", relative_path)
    spec = importlib.util.spec_from_file_location(module_name, page_path)
    if spec is None or spec.loader is None:
        abort(404)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = getattr(module, "handle_request", None)
    if handler is None:
        abort(404)
    return handler()


def db(cursorclass=pymysql.cursors.DictCursor):
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=cursorclass,
        autocommit=False,
    )


def query_all(sql, params=None):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()
    finally:
        conn.close()


def query_one(sql, params=None):
    rows = query_all(sql, params)
    return rows[0] if rows else None


def execute(sql, params=None):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            lastrowid = cur.lastrowid
        conn.commit()
        return lastrowid
    finally:
        conn.close()


def execute_many(statements):
    conn = db()
    try:
        with conn.cursor() as cur:
            for sql, params in statements:
                cur.execute(sql, params or ())
        conn.commit()
    finally:
        conn.close()


def settings():
    rows = query_all("SELECT parameter, value FROM systemsettings")
    return {str(row["parameter"]): "" if row["value"] is None else str(row["value"]) for row in rows}


def save_setting(parameter, value, description):
    execute(
        """
        INSERT INTO systemsettings (`parameter`, `value`, `description`)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), `description` = VALUES(`description`)
        """,
        (parameter, value, description),
    )


CERTIFICATE_SETTING_MAP = {
    "web": (
        "webserver_https_certificate_id",
        "webserver_https_cert",
        "webserver_https_privkey",
    ),
    "api": (
        "api_https_certificate_id",
        "api_https_cert",
        "api_https_privkey",
    ),
    "sip": (
        "secure_sip_certificate_id",
        "secure_sip_cert",
        "secure_sip_privkey",
    ),
}


def tls_certificate_details(certificate_path):
    path = Path(str(certificate_path or "").strip())
    result = {
        "valid_from": None,
        "expires_at": None,
        "subject": "",
        "issuer": "",
        "error": "",
    }
    if not path.is_file():
        result["error"] = "Certificate file is unavailable."
        return result
    try:
        decoded = ssl._ssl._test_decode_cert(str(path))
        if decoded.get("notBefore"):
            result["valid_from"] = int(ssl.cert_time_to_seconds(decoded["notBefore"]))
        if decoded.get("notAfter"):
            result["expires_at"] = int(ssl.cert_time_to_seconds(decoded["notAfter"]))
        for key in ("subject", "issuer"):
            parts = []
            for rdn in decoded.get(key, ()):
                for name, value in rdn:
                    if name in {"commonName", "organizationName"} and value:
                        parts.append(str(value))
            result[key] = ", ".join(parts)
    except Exception as exc:
        result["error"] = f"Unable to read certificate: {exc}"
    return result


def validate_tls_certificate(certificate_path, private_key_path):
    certificate = Path(str(certificate_path or "").strip())
    private_key = Path(str(private_key_path or "").strip())
    if not certificate.is_file():
        raise ValueError("Certificate file does not exist or is not readable.")
    if not private_key.is_file():
        raise ValueError("Private key file does not exist or is not readable.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(f"Certificate and private key could not be loaded: {exc}") from exc
    details = tls_certificate_details(certificate)
    if details.get("error"):
        raise ValueError(details["error"])
    return details


def _legacy_certificate_record(name, certificate_path, private_key_path):
    certificate_path = str(certificate_path or "").strip()
    private_key_path = str(private_key_path or "").strip()
    if not certificate_path or not private_key_path:
        return None
    existing = query_one(
        "SELECT * FROM certificates WHERE certificate_path=%s AND private_key_path=%s LIMIT 1",
        (certificate_path, private_key_path),
    )
    if existing:
        return existing
    existing = query_one("SELECT * FROM certificates WHERE name=%s LIMIT 1", (name,))
    if existing:
        return existing
    certificate_id = execute(
        """
        INSERT INTO certificates (name, certificate_path, private_key_path, managed_upload)
        VALUES (%s,%s,%s,0)
        """,
        (name, certificate_path, private_key_path),
    )
    return query_one("SELECT * FROM certificates WHERE id=%s LIMIT 1", (certificate_id,))


def migrate_legacy_tls_certificates(data=None):
    source = dict(data) if isinstance(data, dict) else settings()
    if not str(source.get("webserver_https_certificate_id", "") or "").strip():
        legacy_web = _legacy_certificate_record(
            "Legacy HTTPS Certificate",
            source.get("webserver_https_cert"),
            source.get("webserver_https_privkey"),
        )
        if legacy_web:
            save_setting(
                "webserver_https_certificate_id",
                str(legacy_web["id"]),
                "Certificate used by the Web HTTPS listener",
            )
            source["webserver_https_certificate_id"] = str(legacy_web["id"])

    if not str(source.get("secure_sip_certificate_id", "") or "").strip():
        legacy_sip = None
        secure_mode = str(source.get("enable_secure_sip", "0") or "0").strip()
        if secure_mode == "1" and source.get("webserver_https_certificate_id"):
            legacy_sip = query_one(
                "SELECT * FROM certificates WHERE id=%s LIMIT 1",
                (source["webserver_https_certificate_id"],),
            )
        elif secure_mode not in {"", "0"}:
            legacy_sip = _legacy_certificate_record(
                "Legacy SIP TLS Certificate",
                source.get("secure_sip_cert"),
                source.get("secure_sip_privkey"),
            )
        if legacy_sip:
            save_setting(
                "secure_sip_certificate_id",
                str(legacy_sip["id"]),
                "Certificate used by the SIP TLS listener",
            )
            save_setting("secure_sip_cert", legacy_sip["certificate_path"], "Certificate path for SIP TLS")
            save_setting("secure_sip_privkey", legacy_sip["private_key_path"], "Private key path for SIP TLS")
            source["secure_sip_certificate_id"] = str(legacy_sip["id"])
    return source


def ensure_certificate_schema(data=None):
    global CERTIFICATE_SCHEMA_READY
    with CERTIFICATE_SCHEMA_LOCK:
        if not CERTIFICATE_SCHEMA_READY:
            execute_many(
                [
                    (
                        """
                        CREATE TABLE IF NOT EXISTS certificates (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            name VARCHAR(255) NOT NULL,
                            certificate_path TEXT NOT NULL,
                            private_key_path TEXT NOT NULL,
                            managed_upload TINYINT(1) NOT NULL DEFAULT 0,
                            certbot_name VARCHAR(255) DEFAULT NULL,
                            certbot_domains TEXT DEFAULT NULL,
                            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            UNIQUE KEY certificates_name_unique (name)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                        """,
                        (),
                    ),
                ]
            )
            certificate_columns = table_columns("certificates")
            certificate_alters = []
            if "certbot_name" not in certificate_columns:
                certificate_alters.append(("ALTER TABLE certificates ADD COLUMN certbot_name VARCHAR(255) DEFAULT NULL AFTER managed_upload", ()))
            if "certbot_domains" not in certificate_columns:
                certificate_alters.append(("ALTER TABLE certificates ADD COLUMN certbot_domains TEXT DEFAULT NULL AFTER certbot_name", ()))
            if certificate_alters:
                execute_many(certificate_alters)
            CERTIFICATE_SCHEMA_READY = True
        return migrate_legacy_tls_certificates(data)


def certificate_record(certificate_id):
    wanted = str(certificate_id or "").strip()
    if not wanted.isdigit():
        return None
    return query_one("SELECT * FROM certificates WHERE id=%s LIMIT 1", (int(wanted),))


def certificate_records():
    records = list(query_all("SELECT * FROM certificates"))
    now = int(time.time())
    for record in records:
        details = tls_certificate_details(record.get("certificate_path"))
        record.update(details)
        expires_at = details.get("expires_at")
        record["expired"] = expires_at is not None and expires_at <= now
        valid_from = details.get("valid_from")
        record["renewal_at"] = None
        if record.get("certbot_name") and valid_from is not None and expires_at is not None and expires_at > valid_from:
            lifetime = expires_at - valid_from
            renewal_fraction = 0.5 if lifetime <= 10 * 24 * 60 * 60 else (2.0 / 3.0)
            record["renewal_at"] = int(valid_from + lifetime * renewal_fraction)
    records.sort(
        key=lambda record: (
            0 if record.get("expired") else 1 if record.get("error") else 2,
            record.get("expires_at") if record.get("expires_at") is not None else 2**63,
            str(record.get("name") or "").lower(),
        )
    )
    return records


def set_certificate_for_service(service, certificate_id):
    keys = CERTIFICATE_SETTING_MAP.get(str(service or "").strip().lower())
    if not keys:
        raise ValueError("Unknown certificate service.")
    record = certificate_record(certificate_id)
    if not record:
        raise ValueError("Select an available certificate.")
    validate_tls_certificate(record["certificate_path"], record["private_key_path"])
    id_key, certificate_key, private_key_key = keys
    save_setting(id_key, str(record["id"]), f"Certificate used by the {service.upper()} TLS listener")
    save_setting(certificate_key, record["certificate_path"], f"Certificate path for {service.upper()} TLS")
    save_setting(private_key_key, record["private_key_path"], f"Private key path for {service.upper()} TLS")
    return record


def refresh_certificate_assignments(certificate_id):
    record = certificate_record(certificate_id)
    if not record:
        return
    data = settings()
    for service, (id_key, _certificate_key, _private_key_key) in CERTIFICATE_SETTING_MAP.items():
        if str(data.get(id_key, "") or "").strip() == str(record["id"]):
            set_certificate_for_service(service, record["id"])


def certificate_usage(certificate_id):
    data = settings()
    wanted = str(certificate_id or "").strip()
    return [
        service
        for service, (id_key, _certificate_key, _private_key_key) in CERTIFICATE_SETTING_MAP.items()
        if str(data.get(id_key, "") or "").strip() == wanted
    ]


def table_columns(table_name):
    rows = query_all(f"SHOW COLUMNS FROM `{table_name}`")
    return {row["Field"] for row in rows if row.get("Field")}


def ensure_message_vendor_schema():
    global MESSAGE_VENDOR_SCHEMA_READY
    if MESSAGE_VENDOR_SCHEMA_READY:
        return
    statements = []
    message_columns = table_columns("messages")
    if "vendor_specific" not in message_columns:
        statements.append(("ALTER TABLE messages ADD COLUMN vendor_specific TEXT DEFAULT NULL", ()))
    message_audio = query_one("SHOW COLUMNS FROM `messages` LIKE 'audio'")
    if message_audio and "text" not in str(message_audio.get("Type") or "").lower():
        statements.append(("ALTER TABLE messages MODIFY COLUMN audio TEXT DEFAULT NULL", ()))
    broadcast_columns = table_columns("broadcasts")
    if "vendor_specific" not in broadcast_columns:
        statements.append(("ALTER TABLE broadcasts ADD COLUMN vendor_specific TEXT DEFAULT NULL", ()))
    else:
        statements.append(("ALTER TABLE broadcasts MODIFY COLUMN vendor_specific TEXT DEFAULT NULL", ()))
    broadcast_audio = query_one("SHOW COLUMNS FROM `broadcasts` LIKE 'audio'")
    if broadcast_audio and "text" not in str(broadcast_audio.get("Type") or "").lower():
        statements.append(("ALTER TABLE broadcasts MODIFY COLUMN audio TEXT DEFAULT NULL", ()))
    if statements:
        execute_many(statements)
    MESSAGE_VENDOR_SCHEMA_READY = True


def truthy(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def demo_mode_active():
    return DEMO_MODE


def demo_mode_maintenance_username():
    if not demo_mode_active():
        return ""
    return DEMO_MODE_MAINTENANCE_USER


def demo_mode_maintenance_username_matches(username):
    configured = demo_mode_maintenance_username()
    candidate = str(username or "").strip()
    return bool(configured and candidate and configured.lower() == candidate.lower())


def demo_mode_maintenance_session_active():
    if not demo_mode_active():
        return False
    if not session.get(DEMO_MODE_MAINTENANCE_SESSION_KEY):
        return False
    return demo_mode_maintenance_username_matches(session.get("username"))


def demo_mode_maintenance_popup_pending():
    return demo_mode_maintenance_session_active() and truthy(session.get(DEMO_MODE_MAINTENANCE_PENDING_KEY))


def demo_mode_maintenance_touch(now_value=None):
    if not demo_mode_maintenance_session_active():
        return
    session[DEMO_MODE_MAINTENANCE_LAST_ACTIVITY_KEY] = str(float(now_value if now_value is not None else time.time()))


def demo_mode_maintenance_clear():
    session.pop(DEMO_MODE_MAINTENANCE_SESSION_KEY, None)
    session.pop(DEMO_MODE_MAINTENANCE_PENDING_KEY, None)
    session.pop(DEMO_MODE_MAINTENANCE_LAST_ACTIVITY_KEY, None)


def demo_mode_maintenance_block_enabled(data=None):
    if not demo_mode_active() or not demo_mode_maintenance_username():
        return False
    source = data if isinstance(data, dict) else settings()
    return truthy((source or {}).get(DEMO_MODE_MAINTENANCE_BLOCK_SETTING, "0"))


def systemctl_available():
    return shutil.which("systemctl") is not None


def systemd_unit_exists(unit=OPS_SYSTEMD_UNIT):
    if not systemctl_available():
        return False
    for command in (
        ["systemctl", "list-unit-files", unit],
        ["systemctl", "list-units", "--all", unit],
    ):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        except Exception:
            continue
        output = (result.stdout or "") + (result.stderr or "")
        if unit in output:
            return True
    return False


def demo_mode_maintenance_can_restart_ops_systemd():
    if os.name == "nt":
        return False
    if not demo_mode_active() or not demo_mode_maintenance_username():
        return False
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    if not Path("/run/systemd/system").exists():
        return False
    return systemd_unit_exists()


def _spawn_background_command(command):
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(command, **kwargs)


def demo_mode_maintenance_restart_ops_systemd():
    if not demo_mode_maintenance_can_restart_ops_systemd():
        raise RuntimeError("OPS systemd restart is not available.")
    _spawn_background_command(["systemctl", "restart", OPS_SYSTEMD_UNIT])


def demo_mode_maintenance_reboot_server():
    if os.name == "nt":
        _spawn_background_command(["shutdown", "/r", "/t", "0"])
        return
    if Path("/run/systemd/system").exists() and systemctl_available():
        _spawn_background_command(["systemctl", "reboot"])
        return
    reboot_binary = shutil.which("reboot")
    if reboot_binary:
        _spawn_background_command([reboot_binary])
        return
    raise RuntimeError("Server reboot is not supported on this system.")


def demo_mode_maintenance_state(data=None):
    source = data if isinstance(data, dict) else settings()
    return {
        "maintenance_user": demo_mode_maintenance_username(),
        "block_non_maintenance_users": demo_mode_maintenance_block_enabled(source),
        "can_restart_ops_systemd": demo_mode_maintenance_can_restart_ops_systemd(),
        "show_reboot_server": True,
    }


def demo_mode_enabled():
    return demo_mode_active() and not demo_mode_maintenance_session_active()


def api_token_hash(token):
    return hashlib.sha256(str(token or "").encode()).hexdigest()


def create_api_token_value():
    return "usr_" + secrets.token_urlsafe(32)


def hash_api_token_value(token):
    if API_TOKEN_HASHER is None:
        raise RuntimeError("Argon2 support is not installed. Install dependencies from requirements.txt.")
    return API_TOKEN_HASHER.hash(str(token or ""))


def verify_api_token_value(token, stored_hash):
    token = str(token or "")
    stored_hash = str(stored_hash or "")
    if not token or not stored_hash:
        return False
    if stored_hash.startswith("$argon2"):
        if API_TOKEN_HASHER is None:
            return False
        try:
            return bool(API_TOKEN_HASHER.verify(stored_hash, token))
        except (VerificationError, InvalidHashError):
            return False
    return hmac.compare_digest(api_token_hash(token), stored_hash)


def ensure_api_token_schema():
    execute_many(
        [
            (
                """
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(255) NOT NULL,
                    token_prefix VARCHAR(24) DEFAULT NULL,
                    token_label VARCHAR(120) DEFAULT NULL,
                    expires_at DATETIME DEFAULT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_used_at DATETIME DEFAULT NULL,
                    UNIQUE KEY api_tokens_hash_unique (token_hash),
                    KEY api_tokens_user_idx (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
        ]
    )
    columns = table_columns("api_tokens")
    statements = []
    if "token_label" not in columns:
        statements.append(("ALTER TABLE api_tokens ADD COLUMN token_label VARCHAR(120) DEFAULT NULL AFTER token_prefix", ()))
    statements.append(("ALTER TABLE api_tokens MODIFY COLUMN token_hash VARCHAR(255) NOT NULL", ()))
    if "token_prefix" in columns:
        statements.append(("ALTER TABLE api_tokens MODIFY COLUMN token_prefix VARCHAR(24) DEFAULT NULL", ()))
    if statements:
        execute_many(statements)


def ensure_desktop_sso_schema():
    execute_many(
        [
            (
                """
                CREATE TABLE IF NOT EXISTS desktop_sso_requests (
                    request_id VARCHAR(64) NOT NULL PRIMARY KEY,
                    secret_hash CHAR(64) NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'pending',
                    user_id INT DEFAULT NULL,
                    auth_provider VARCHAR(32) DEFAULT NULL,
                    ip VARCHAR(64) DEFAULT NULL,
                    user_agent TEXT DEFAULT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    completed_at DATETIME DEFAULT NULL,
                    consumed_at DATETIME DEFAULT NULL,
                    error TEXT DEFAULT NULL,
                    KEY desktop_sso_status_idx (status),
                    KEY desktop_sso_expires_idx (expires_at),
                    KEY desktop_sso_user_idx (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
        ]
    )


def prune_desktop_sso_requests():
    ensure_desktop_sso_schema()
    execute("DELETE FROM desktop_sso_requests WHERE expires_at < (NOW() - INTERVAL 1 HOUR)")


def desktop_sso_secret_hash(request_id, secret):
    message = (str(request_id or "") + ":" + str(secret or "")).encode("utf-8")
    return hmac.new(str(app.secret_key or "").encode("utf-8"), message, hashlib.sha256).hexdigest()


def create_desktop_sso_request():
    ensure_desktop_sso_schema()
    prune_desktop_sso_requests()
    request_id = secrets.token_urlsafe(24)[:64]
    request_secret = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(seconds=DESKTOP_SSO_REQUEST_TTL_SECONDS)
    execute(
        """
        INSERT INTO desktop_sso_requests (
            request_id, secret_hash, status, ip, user_agent, expires_at
        ) VALUES (%s,%s,'pending',%s,%s,%s)
        """,
        (
            request_id,
            desktop_sso_secret_hash(request_id, request_secret),
            client_ip(),
            str(request.headers.get("User-Agent", "unknown") or "unknown"),
            db_datetime_value(expires_at),
        ),
    )
    return request_id, request_secret, expires_at


def desktop_sso_request_record(request_id):
    ensure_desktop_sso_schema()
    wanted = str(request_id or "").strip()
    if not wanted:
        return None
    return query_one("SELECT * FROM desktop_sso_requests WHERE request_id=%s LIMIT 1", (wanted,))


def desktop_sso_request_pending(request_id):
    record = desktop_sso_request_record(request_id)
    if not record:
        return False
    if str(record.get("status") or "").strip().lower() != "pending":
        return False
    expires_at = _session_datetime(record.get("expires_at"))
    return bool(expires_at and expires_at > datetime.now())


def complete_desktop_sso_request(request_id, user, auth_provider):
    if not desktop_sso_request_pending(request_id):
        return False
    execute(
        """
        UPDATE desktop_sso_requests
        SET status='complete', user_id=%s, auth_provider=%s, completed_at=NOW(), error=NULL
        WHERE request_id=%s AND status='pending' AND expires_at > NOW()
        """,
        ((user or {}).get("id"), str(auth_provider or "local"), str(request_id or "")),
    )
    return True


def fail_desktop_sso_request(request_id, error):
    wanted = str(request_id or "").strip()
    if not wanted:
        return False
    ensure_desktop_sso_schema()
    execute(
        """
        UPDATE desktop_sso_requests
        SET status='failed', completed_at=NOW(), error=%s
        WHERE request_id=%s AND status='pending'
        """,
        (str(error or "Desktop SSO failed")[:1000], wanted),
    )
    return True


def desktop_sso_finish_redirect(request_id, ok=True, message=""):
    params = {"request_id": str(request_id or ""), "status": "ok" if ok else "failed"}
    if message:
        params["message"] = str(message)[:300]
    return redirect(DESKTOP_SSO_COMPLETE_ROUTE + "?" + urlencode(params))


def desktop_sso_poll_user_agent():
    client_os = str(request.headers.get("X-OPS-Client-OS") or "").strip()
    return f"OpenPagingServer Desktop Client/1.0 ({client_os})" if client_os else "OpenPagingServer Desktop Client/1.0"


def ensure_identity_access_schema():
    global IDENTITY_ACCESS_SCHEMA_READY
    if IDENTITY_ACCESS_SCHEMA_READY:
        return
    execute_many(
        [
            (
                """
                CREATE TABLE IF NOT EXISTS user_group_access (
                    user_id INT NOT NULL,
                    group_id VARCHAR(100) NOT NULL,
                    PRIMARY KEY (user_id, group_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
            (
                """
                CREATE TABLE IF NOT EXISTS user_message_access (
                    user_id INT NOT NULL,
                    message_id INT NOT NULL,
                    PRIMARY KEY (user_id, message_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
            (
                """
                CREATE TABLE IF NOT EXISTS user_bell_schedule_access (
                    user_id INT NOT NULL,
                    schedule_id INT NOT NULL,
                    PRIMARY KEY (user_id, schedule_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
            (
                """
                CREATE TABLE IF NOT EXISTS loginhistory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT DEFAULT NULL,
                    username VARCHAR(255) DEFAULT NULL,
                    auth_provider VARCHAR(32) NOT NULL DEFAULT 'local',
                    session_id VARCHAR(64) DEFAULT NULL,
                    session_type VARCHAR(16) NOT NULL DEFAULT 'web',
                    ip VARCHAR(64) DEFAULT NULL,
                    user_agent TEXT DEFAULT NULL,
                    login_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    KEY loginhistory_user_idx (user_id),
                    KEY loginhistory_session_idx (session_id),
                    KEY loginhistory_time_idx (login_time)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
            (
                """
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id VARCHAR(64) NOT NULL PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_type VARCHAR(16) NOT NULL DEFAULT 'web',
                    auth_provider VARCHAR(32) NOT NULL DEFAULT 'local',
                    username VARCHAR(255) DEFAULT NULL,
                    ip VARCHAR(64) DEFAULT NULL,
                    user_agent TEXT DEFAULT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME DEFAULT NULL,
                    revoked_at DATETIME DEFAULT NULL,
                    KEY user_sessions_user_idx (user_id),
                    KEY user_sessions_type_idx (session_type),
                    KEY user_sessions_revoked_idx (revoked_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                """,
                (),
            ),
        ]
    )
    user_columns = table_columns("users")
    group_columns = table_columns("groups")
    message_columns = table_columns("messages")
    session_columns = table_columns("user_sessions")
    statements = []
    if "last_full_activity" not in session_columns:
        statements.append(("ALTER TABLE user_sessions ADD COLUMN last_full_activity DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER last_seen_at", ()))
    if "auth_provider" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(32) NOT NULL DEFAULT 'local' AFTER role", ()))
    else:
        statements.append(("ALTER TABLE users MODIFY COLUMN auth_provider VARCHAR(32) NOT NULL DEFAULT 'local'", ()))
    if "external_id" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN external_id VARCHAR(255) DEFAULT NULL AFTER auth_provider", ()))
    if "display_name" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN display_name VARCHAR(255) DEFAULT NULL AFTER external_id", ()))
    if "ldap_groups" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN ldap_groups LONGTEXT DEFAULT NULL AFTER display_name", ()))
    if "identity_recipient_groups" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN identity_recipient_groups LONGTEXT DEFAULT NULL AFTER ldap_groups", ()))
    statements.append(("ALTER TABLE users MODIFY COLUMN accountexpire DATETIME DEFAULT NULL", ()))
    if "restrict_groups" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN restrict_groups TINYINT(1) NOT NULL DEFAULT 0 AFTER userperm", ()))
    if "restrict_messages" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN restrict_messages TINYINT(1) NOT NULL DEFAULT 0 AFTER restrict_groups", ()))
    if "restrict_bell_schedules" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN restrict_bell_schedules TINYINT(1) NOT NULL DEFAULT 0 AFTER restrict_messages", ()))
    if "require_password_change" not in user_columns:
        statements.append(("ALTER TABLE users ADD COLUMN require_password_change TINYINT(1) NOT NULL DEFAULT 0 AFTER restrict_bell_schedules", ()))
    if "owner_user_id" not in group_columns:
        statements.append(("ALTER TABLE `groups` ADD COLUMN owner_user_id INT DEFAULT NULL", ()))
    if "owner_user_id" not in message_columns:
        statements.append(("ALTER TABLE messages ADD COLUMN owner_user_id INT DEFAULT NULL", ()))
    if statements:
        execute_many(statements)
    setting_statements = [
        (
            "INSERT IGNORE INTO systemsettings (`parameter`, `value`, `description`) VALUES (%s,%s,%s)",
            (parameter, value, ""),
        )
        for parameter, value in LDAP_SETTING_DEFAULTS.items()
    ]
    setting_statements.extend(
        (
            "INSERT IGNORE INTO systemsettings (`parameter`, `value`, `description`) VALUES (%s,%s,%s)",
            (parameter, value, ""),
        )
        for parameter, value in LOGIN_SETTING_DEFAULTS.items()
    )
    setting_statements.extend(
        (
            "INSERT IGNORE INTO systemsettings (`parameter`, `value`, `description`) VALUES (%s,%s,%s)",
            (parameter, value, ""),
        )
        for defaults in (SSO_SETTING_DEFAULTS, OIDC_SETTING_DEFAULTS, SAML_SETTING_DEFAULTS)
        for parameter, value in defaults.items()
    )
    if setting_statements:
        execute_many(setting_statements)
    IDENTITY_ACCESS_SCHEMA_READY = True


def db_datetime_value(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    parsed = parse_account_expiration_value(value, date_only_end_of_day=False)
    if parsed is not None:
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def create_user_session_record(user, auth_provider="local", session_type="web", session_id=None, expires_at=None, ip_address=None, user_agent=None):
    ensure_identity_access_schema()
    normalized_user = user or {}
    user_id = normalized_user.get("id")
    if user_id in (None, ""):
        raise RuntimeError("A valid user is required to create a session.")
    session_id = str(session_id or secrets.token_hex(32)).strip()
    if not session_id:
        raise RuntimeError("Session ID is required.")
    execute(
        """
        INSERT INTO user_sessions (
            session_id, user_id, session_type, auth_provider, username, ip, user_agent, expires_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            session_id,
            user_id,
            str(session_type or "web"),
            str(auth_provider or "local"),
            str(normalized_user.get("username") or ""),
            str(ip_address or client_ip() or ""),
            str(user_agent or request.headers.get("User-Agent", "unknown") or "unknown"),
            db_datetime_value(expires_at),
        ),
    )
    return session_id


def touch_user_session_record(session_id):
    ensure_identity_access_schema()
    wanted = str(session_id or "").strip()
    if not wanted:
        return
    execute("UPDATE user_sessions SET last_seen_at=NOW() WHERE session_id=%s", (wanted,))


def repair_loopback_session_ip(session_record):
    record = session_record or {}
    session_id = str(record.get("session_id") or "").strip()
    stored_ip = str(record.get("ip") or "").strip()
    if not session_id or not stored_ip:
        return
    try:
        if not ipaddress.ip_address(stored_ip).is_loopback:
            return
    except ValueError:
        return
    observed_ip = client_ip()
    try:
        if ipaddress.ip_address(observed_ip).is_loopback:
            return
    except ValueError:
        return
    execute("UPDATE user_sessions SET ip=%s WHERE session_id=%s", (observed_ip, session_id))
    execute("UPDATE loginhistory SET ip=%s WHERE session_id=%s", (observed_ip, session_id))
    record["ip"] = observed_ip


SOFT_LOGOUT_AFTER_SECONDS_WEB = _positive_int_env("OPS_WEB_SESSION_REAUTH_SECONDS", 12 * 3600)
SOFT_LOGOUT_AFTER_SECONDS_DESKTOP = _positive_int_env("OPS_DESKTOP_SESSION_REAUTH_SECONDS", 72 * 3600)
SOFT_ACCESS_PATH_PREFIXES = ("/dashboard", "/login", "/logout", "/assets", "/bundled-assets", "/favicon.ico", "/robots.txt", "/desktop/", "/api/", "/demo-mode")


def soft_access_path(path):
    token = str(path or "")
    for prefix in SOFT_ACCESS_PATH_PREFIXES:
        if token == prefix or token.startswith(prefix.rstrip("/") + "/") or token == prefix.rstrip("/"):
            return True
    return False


def desktop_client_context():
    desktop_param = request.args.get("desktop_client")
    desktop_header = str(request.headers.get(DESKTOP_CLIENT_HEADER) or request.headers.get("X-Desktop-Client") or "").strip().lower()
    return (desktop_param is not None and str(desktop_param).strip().lower() in {"1", "true", "yes", "on"}) or desktop_header in {"1", "true", "yes", "on"} or bool(session.get("desktop_client"))


def _session_datetime(value):
    if isinstance(value, datetime):
        return value
    token = str(value or "").strip()
    if not token:
        return None
    try:
        return datetime.strptime(token[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def session_soft_logged_out(record):
    if not record:
        return False
    session_type = str(record.get("session_type") or "web").strip().lower()
    limit = SOFT_LOGOUT_AFTER_SECONDS_DESKTOP if session_type == "desktop" else SOFT_LOGOUT_AFTER_SECONDS_WEB
    reference = _session_datetime(record.get("last_full_activity")) or _session_datetime(record.get("created_at"))
    if reference is None:
        return False
    return (datetime.now() - reference).total_seconds() >= limit


def touch_full_activity(session_id):
    wanted = str(session_id or "").strip()
    if not wanted:
        return
    execute("UPDATE user_sessions SET last_full_activity=NOW() WHERE session_id=%s", (wanted,))


def active_user_session_record(session_id, user_id=None):
    ensure_identity_access_schema()
    wanted = str(session_id or "").strip()
    if not wanted:
        return None
    params = [wanted]
    query = """
        SELECT
            session_id, user_id, session_type, auth_provider, username, ip, user_agent,
            created_at, last_seen_at, last_full_activity, expires_at, revoked_at
        FROM user_sessions
        WHERE session_id=%s
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
    """
    if user_id not in (None, ""):
        query += " AND user_id=%s"
        params.append(user_id)
    query += " LIMIT 1"
    return query_one(query, tuple(params))


def revoke_user_session_record(session_id, user_id=None):
    ensure_identity_access_schema()
    wanted = str(session_id or "").strip()
    if not wanted:
        return 0
    params = [wanted]
    query = "UPDATE user_sessions SET revoked_at=NOW() WHERE session_id=%s AND revoked_at IS NULL"
    if user_id not in (None, ""):
        query += " AND user_id=%s"
        params.append(user_id)
    return execute(query, tuple(params))


def revoke_all_user_session_records(user_id):
    ensure_identity_access_schema()
    if user_id in (None, ""):
        return 0
    return execute("UPDATE user_sessions SET revoked_at=NOW() WHERE user_id=%s AND revoked_at IS NULL", (user_id,))


def record_login_history_entry(user, auth_provider="local", session_id=None, session_type="web", ip_address=None, user_agent=None):
    ensure_identity_access_schema()
    normalized_user = user or {}
    execute(
        """
        INSERT INTO loginhistory (
            user_id, username, auth_provider, session_id, session_type, ip, user_agent
        ) VALUES (%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            normalized_user.get("id"),
            str(normalized_user.get("username") or ""),
            str(auth_provider or "local"),
            str(session_id or ""),
            str(session_type or "web"),
            str(ip_address or client_ip() or ""),
            str(user_agent or request.headers.get("User-Agent", "unknown") or "unknown"),
        ),
    )


def update_user_login_counters(user_id):
    if user_id in (None, ""):
        return
    execute(
        "UPDATE users SET lastlogin=NOW(), logincount=COALESCE(logincount, 0) + 1 WHERE id=%s",
        (user_id,),
    )


def register_login_session(user, auth_provider="local", session_type="web", session_id=None, expires_at=None, ip_address=None, user_agent=None):
    created_session_id = create_user_session_record(
        user,
        auth_provider=auth_provider,
        session_type=session_type,
        session_id=session_id,
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    record_login_history_entry(
        user,
        auth_provider=auth_provider,
        session_id=created_session_id,
        session_type=session_type,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    update_user_login_counters((user or {}).get("id"))
    return created_session_id


def fetch_login_history_rows(user_id, limit=50):
    ensure_identity_access_schema()
    if user_id in (None, ""):
        return []
    if limit == "all":
        return query_all(
            """
            SELECT id, auth_provider, session_id, session_type, ip, user_agent, login_time
            FROM loginhistory
            WHERE user_id=%s
            ORDER BY login_time DESC, id DESC
            """,
            (user_id,),
        )
    try:
        numeric_limit = max(1, int(limit))
    except (TypeError, ValueError):
        numeric_limit = 50
    return query_all(
        """
        SELECT id, auth_provider, session_id, session_type, ip, user_agent, login_time
        FROM loginhistory
        WHERE user_id=%s
        ORDER BY login_time DESC, id DESC
        LIMIT %s
        """,
        (user_id, numeric_limit),
    )


def login_history_total(user_id):
    ensure_identity_access_schema()
    if user_id in (None, ""):
        return 0
    row = query_one("SELECT COUNT(*) AS total FROM loginhistory WHERE user_id=%s", (user_id,)) or {}
    return int(row.get("total") or 0)


def fetch_active_user_sessions(user_id):
    ensure_identity_access_schema()
    if user_id in (None, ""):
        return []
    return query_all(
        """
        SELECT
            session_id, session_type, auth_provider, username, ip, user_agent,
            created_at, last_seen_at, expires_at
        FROM user_sessions
        WHERE user_id=%s
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC, session_id DESC
        """,
        (user_id,),
    )


def normalize_permission_tokens(value):
    tokens = []
    for token in str(value or "").replace(";", ",").split(","):
        normalized = str(token or "").strip().lower()
        if normalized and normalized not in tokens:
            tokens.append(normalized)
    return set(tokens)


def permission_token_set(value):
    if isinstance(value, (list, tuple, set)):
        tokens = set()
        for token in value:
            normalized = str(token or "").strip().lower()
            if normalized:
                tokens.add(normalized)
        return tokens
    return normalize_permission_tokens(value)


def serialize_permission_tokens(value, options=None):
    option_rows = options or USER_PERMISSION_LABELS
    normalized = permission_token_set(value)
    return ",".join(key for key, _label in option_rows if key in normalized)


def role_default_user_permissions(role):
    normalized = str(role or "").strip().lower()
    return set(DEFAULT_USER_PAGE_PERMISSIONS.get(normalized, DEFAULT_USER_PAGE_PERMISSIONS["receiver"]))


def role_permission_mode(role):
    normalized = str(role or "").strip().lower()
    if normalized in {"user", "tempuser"}:
        return "user"
    if normalized in ADMIN_ROLE_VALUES:
        return "admin"
    return "receiver"


def is_admin_user(user):
    return str((user or {}).get("role") or "").strip().lower() in ADMIN_ROLE_VALUES


def is_receiver_user(user):
    return str((user or {}).get("role") or "").strip().lower() in RECEIVER_ROLE_VALUES


def user_permission_tokens(user):
    tokens = normalize_permission_tokens((user or {}).get("userperm"))
    return {"all"} if "all" in tokens else (tokens if tokens else role_default_user_permissions((user or {}).get("role")))


def admin_permission_tokens(user):
    tokens = normalize_permission_tokens((user or {}).get("adminperm"))
    if "all" in tokens:
        return {"all"}
    if tokens:
        return tokens
    return {"all"} if is_admin_user(user) else set()


def user_has_permission(user, token):
    token = str(token or "").strip().lower()
    if not token:
        return False
    for token_set in (user_permission_tokens(user), admin_permission_tokens(user)):
        if "all" in token_set or token in token_set:
            return True
    return False


def can_access_page(user, page_key):
    token = str(page_key or "").strip().lower()
    if not token:
        return False
    if token == "dashboard":
        return bool(user)
    tokens = user_permission_tokens(user)
    return "all" in tokens or token in tokens


def can_send_messages(user):
    return can_access_page(user, "messages")


def can_create_messages(user):
    return user_has_permission(user, "messages-add") or user_has_permission(user, "messages-manage")


def can_edit_messages(user):
    return user_has_permission(user, "messages-edit") or user_has_permission(user, "messages-manage")


def can_delete_messages(user):
    return user_has_permission(user, "messages-delete") or user_has_permission(user, "messages-manage")


def can_manage_messages(user):
    return can_create_messages(user) or can_edit_messages(user) or can_delete_messages(user)


def can_manage_groups(user):
    return user_has_permission(user, "groups-manage")


def can_manage_broadcasts(user):
    return user_has_permission(user, "broadcasts-manage")


def can_create_bell_schedules(user):
    if not user:
        return False
    if is_admin_user(user):
        return True
    return not bell_schedule_access_is_restricted(user)


def can_edit_assets(user):
    return user_has_permission(user, "asset-edit")


def can_view_assets_page(user):
    return can_access_page(user, "assets") or can_edit_assets(user)


def default_web_landing_path(user):
    candidates = [
        ("/dashboard", can_access_page(user, "dashboard")),
        ("/messages/", can_send_messages(user) or can_manage_messages(user)),
        ("/paging/", can_access_page(user, "paging")),
        ("/history/", can_access_page(user, "history")),
        ("/bells/", can_access_page(user, "bells")),
        ("/assets/", can_view_assets_page(user)),
        ("/admin/manage-broadcasts", can_manage_broadcasts(user)),
        ("/admin/manage-groups", can_manage_groups(user)),
    ]
    for path, allowed in candidates:
        if allowed:
            return path
    return "/user/settings"


def permission_selected_values(tokens, options):
    normalized = permission_token_set(tokens)
    if "all" in normalized:
        return [key for key, _label in options]
    return [key for key, _label in options if key in normalized]


def normalize_role_mapping_ids(values, valid_ids=None):
    valid = {str(token).strip() for token in (valid_ids or set()) if str(token).strip()} if valid_ids is not None else None
    if isinstance(values, str):
        try:
            raw_values = json.loads(values)
        except Exception:
            raw_values = [token for token in re.split(r"[\s,;|]+", values) if str(token or "").strip()]
    elif isinstance(values, (list, tuple, set)):
        raw_values = list(values)
    else:
        raw_values = values if isinstance(values, list) else []
    normalized = []
    seen = set()
    for token in raw_values or []:
        value = str(token or "").strip()
        if not value or value in seen:
            continue
        if valid is not None and value not in valid:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def normalize_claim_match_text(value):
    if value in (None, ""):
        return ""
    if isinstance(value, (list, tuple, set)):
        raw_lines = [str(item or "").strip() for item in value]
    else:
        raw_lines = [str(line or "").strip() for line in str(value).replace("\r", "\n").split("\n")]
    lines = []
    for line in raw_lines:
        if not line:
            continue
        parts = [str(part or "").strip() for part in line.split(",") if str(part or "").strip()]
        if parts:
            lines.append(",".join(parts))
    return "\n".join(lines)


def parse_claim_match_clauses(value):
    clauses = []
    for line in normalize_claim_match_text(value).split("\n"):
        if not line:
            continue
        clause = []
        for part in [segment.strip() for segment in line.split(",") if segment.strip()]:
            if "=" not in part:
                continue
            key, expected = part.split("=", 1)
            key = str(key or "").strip().lower()
            expected = str(expected or "").strip()
            if key and expected:
                clause.append((key, expected))
        if clause:
            clauses.append(clause)
    return clauses


def identity_claim_map(source):
    mapped = {}
    if not isinstance(source, dict):
        return mapped

    def append_values(claim_key, values):
        normalized_key = str(claim_key or "").strip().lower()
        if not normalized_key:
            return
        existing = mapped.setdefault(normalized_key, [])
        seen = {str(item or "").strip().lower() for item in existing}
        for item in values:
            token = str(item or "").strip()
            if not token:
                continue
            lowered = token.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            existing.append(token)

    def walk(prefix, raw_value):
        if isinstance(raw_value, dict):
            for raw_key, nested_value in raw_value.items():
                key_text = str(raw_key or "").strip()
                if not key_text:
                    continue
                nested_prefix = f"{prefix}.{key_text}".lower() if prefix else key_text.lower()
                walk(nested_prefix, nested_value)
            return
        if isinstance(raw_value, (list, tuple, set)):
            scalar_values = []
            for item in raw_value:
                if isinstance(item, dict):
                    walk(prefix, item)
                else:
                    scalar_values.append(item)
            if scalar_values:
                append_values(prefix, scalar_values)
            return
        append_values(prefix, [raw_value])

    for key, raw_value in source.items():
        claim_key = str(key or "").strip().lower()
        if not claim_key:
            continue
        walk(claim_key, raw_value)
    return mapped


def claims_match_requirement(claims_source, configured_value):
    clauses = parse_claim_match_clauses(configured_value)
    if not clauses:
        return True
    claim_map = identity_claim_map(claims_source)
    for clause in clauses:
        matched = True
        for key, expected in clause:
            values = claim_map.get(key) or []
            expected_text = expected.lower()
            if expected_text == "any":
                if not values:
                    matched = False
                    break
                continue
            if not any(str(value or "").strip().lower() == expected_text for value in values):
                matched = False
                break
        if matched:
            return True
    return False


def normalize_ldap_role_mapping_entry(entry, valid_group_ids=None, valid_message_ids=None, valid_schedule_ids=None):
    entry = entry if isinstance(entry, dict) else {}
    role = normalize_identity_mapping_role(entry.get("role") or "receiver")
    group_match = str(entry.get("group_match") or entry.get("group") or "").strip()
    fallback = truthy(entry.get("fallback")) or group_match.lower() == "other"
    normalized = {
        "group_match": "other" if fallback else group_match,
        "claim_match": "" if fallback else normalize_claim_match_text(entry.get("claim_match") or entry.get("match_claims") or entry.get("claims") or ""),
        "recipient_groups": normalize_role_mapping_ids(entry.get("recipient_groups") or [], valid_group_ids),
        "role": role,
        "userperm": "",
        "restrict_groups": "0",
        "allowed_groups": [],
        "restrict_messages": "0",
        "allowed_messages": [],
        "restrict_bell_schedules": "0",
        "allowed_bell_schedules": [],
        "fallback": "1" if fallback else "0",
    }
    if role == "user":
        configured_permissions = entry.get("userperm") or entry.get("permissions") or []
        permission_tokens = permission_token_set(configured_permissions)
        if not permission_tokens:
            permission_tokens = role_default_user_permissions("user")
        normalized["userperm"] = serialize_permission_tokens(permission_tokens)
        normalized["restrict_groups"] = "1" if truthy(entry.get("restrict_groups")) else "0"
        normalized["allowed_groups"] = normalize_role_mapping_ids(entry.get("allowed_groups") or [], valid_group_ids)
        normalized["restrict_messages"] = "1" if truthy(entry.get("restrict_messages")) else "0"
        normalized["allowed_messages"] = normalize_role_mapping_ids(entry.get("allowed_messages") or [], valid_message_ids)
        normalized["restrict_bell_schedules"] = "1" if truthy(entry.get("restrict_bell_schedules")) else "0"
        normalized["allowed_bell_schedules"] = normalize_role_mapping_ids(
            entry.get("allowed_bell_schedules") or [],
            valid_schedule_ids,
        )
    return normalized


def normalize_ldap_role_mappings(value, valid_group_ids=None, valid_message_ids=None, valid_schedule_ids=None):
    loaded = value
    if isinstance(value, str):
        text = str(value or "").strip()
        if not text:
            return []
        try:
            loaded = json.loads(text)
        except Exception:
            return []
    if isinstance(loaded, dict):
        loaded = loaded.get("mappings") or []
    if not isinstance(loaded, list):
        return []
    mappings = []
    fallback_mapping = None
    for entry in loaded:
        normalized = normalize_ldap_role_mapping_entry(entry, valid_group_ids, valid_message_ids, valid_schedule_ids)
        if normalized.get("fallback") == "1":
            fallback_mapping = normalized
            continue
        mappings.append(normalized)
    if fallback_mapping is None:
        fallback_mapping = normalize_ldap_role_mapping_entry(
            {"group_match": "other", "fallback": "1", "role": "receiver"},
            valid_group_ids,
            valid_message_ids,
            valid_schedule_ids,
        )
    mappings.append(fallback_mapping)
    return mappings


def ldap_role_mappings(data=None):
    source = data if isinstance(data, dict) else settings()
    return normalize_ldap_role_mappings((source or {}).get(LDAP_ROLE_MAPPING_SETTING))


def provider_role_mapping_setting(provider):
    normalized = str(provider or "").strip().lower()
    if normalized == "ldap":
        return LDAP_ROLE_MAPPING_SETTING
    if normalized == "oidc":
        return OIDC_ROLE_MAPPING_SETTING
    if normalized == "saml":
        return SAML_ROLE_MAPPING_SETTING
    return ""


def provider_role_mappings(config, provider):
    setting_name = provider_role_mapping_setting(provider)
    if not setting_name:
        return []
    return normalize_ldap_role_mappings((config or {}).get(setting_name))


def provider_role_mapping_for_identity(config, provider, raw_groups, claims_source=None):
    fallback_mapping = None
    for mapping in provider_role_mappings(config, provider):
        if str(mapping.get("fallback") or "0") == "1":
            fallback_mapping = mapping
            continue
        if groups_match_requirement(raw_groups, mapping.get("group_match")) and claims_match_requirement(claims_source or {}, mapping.get("claim_match")):
            return mapping
    return fallback_mapping


def identity_access_profile(provider, config, raw_groups, claims_source=None):
    normalized_provider = str(provider or "").strip().lower()
    groups = normalize_identity_group_values(raw_groups or [])
    mapping = provider_role_mapping_for_identity(config, normalized_provider, groups, claims_source)
    if mapping:
        role = normalize_identity_mapping_role(mapping.get("role"))
        if role == "user":
            return {
                "role": "user",
                "recipient_groups": normalize_role_mapping_ids(mapping.get("recipient_groups") or []),
                "userperm": serialize_permission_tokens(mapping.get("userperm") or []),
                "restrict_groups": "1" if truthy(mapping.get("restrict_groups")) else "0",
                "allowed_groups": normalize_role_mapping_ids(mapping.get("allowed_groups") or []),
                "restrict_messages": "1" if truthy(mapping.get("restrict_messages")) else "0",
                "allowed_messages": normalize_role_mapping_ids(mapping.get("allowed_messages") or []),
                "restrict_bell_schedules": "1" if truthy(mapping.get("restrict_bell_schedules")) else "0",
                "allowed_bell_schedules": normalize_role_mapping_ids(mapping.get("allowed_bell_schedules") or []),
                "mapping": mapping,
            }
        return {
            "role": role,
            "recipient_groups": normalize_role_mapping_ids(mapping.get("recipient_groups") or []),
            "userperm": "",
            "restrict_groups": "0",
            "allowed_groups": [],
            "restrict_messages": "0",
            "allowed_messages": [],
            "restrict_bell_schedules": "0",
            "allowed_bell_schedules": [],
            "mapping": mapping,
        }
    return {
        "role": "receiver",
        "recipient_groups": [],
        "userperm": "",
        "restrict_groups": "0",
        "allowed_groups": [],
        "restrict_messages": "0",
        "allowed_messages": [],
        "restrict_bell_schedules": "0",
        "allowed_bell_schedules": [],
        "mapping": None,
    }


def ldap_access_profile(config, ldap_result):
    return identity_access_profile("ldap", config, (ldap_result or {}).get("groups") or [], (ldap_result or {}).get("claims") or {})


def normalize_identity_recipient_groups(value):
    if isinstance(value, str):
        text = str(value or "").strip()
        if not text:
            return []
        try:
            loaded = json.loads(text)
        except Exception:
            loaded = [token for token in re.split(r"[\s,;|]+", text) if str(token or "").strip()]
    elif isinstance(value, (list, tuple, set)):
        loaded = list(value)
    else:
        loaded = []
    return normalize_role_mapping_ids(loaded)


def group_member_token_list(value):
    tokens = []
    seen = set()
    for token in re.split(r"[\s,;|]+", str(value or "")):
        cleaned = str(token or "").strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            tokens.append(cleaned)
    return tokens


def serialize_group_member_tokens(values):
    return ",".join(group_member_token_list(values))


def remove_desktop_member_from_all_groups(user_id):
    member_token = desktop_member_token(user_id)
    if not member_token:
        return
    rows = query_all("SELECT id, members, monitor_members FROM `groups`")
    for row in rows:
        updates = {}
        for field_name in ("members", "monitor_members"):
            tokens = [token for token in group_member_token_list(row.get(field_name)) if token != member_token]
            serialized = serialize_group_member_tokens(tokens)
            if serialized != str(row.get(field_name) or ""):
                updates[field_name] = serialized or None
        if updates:
            execute(
                f"UPDATE `groups` SET {', '.join('`' + key + '`=%s' for key in updates)} WHERE id=%s",
                tuple(updates.values()) + (row.get("id"),),
            )


def sync_identity_recipient_groups(user_id, group_ids):
    ensure_identity_access_schema()
    normalized_group_ids = normalize_role_mapping_ids(group_ids)
    stored = query_one("SELECT identity_recipient_groups FROM users WHERE id=%s LIMIT 1", (user_id,)) or {}
    previous_group_ids = normalize_identity_recipient_groups(stored.get("identity_recipient_groups"))
    target_group_ids = set(normalized_group_ids)
    previous_group_set = set(previous_group_ids)
    if target_group_ids != previous_group_set:
        member_token = desktop_member_token(user_id)
        affected_group_ids = previous_group_set | target_group_ids
        if member_token and affected_group_ids:
            placeholders = ",".join(["%s"] * len(affected_group_ids))
            rows = query_all(
                f"SELECT id, members FROM `groups` WHERE id IN ({placeholders})",
                tuple(sorted(affected_group_ids)),
            )
            for row in rows:
                group_id = str(row.get("id") or "").strip()
                tokens = group_member_token_list(row.get("members"))
                if group_id in target_group_ids and member_token not in tokens:
                    tokens.append(member_token)
                if group_id not in target_group_ids:
                    tokens = [token for token in tokens if token != member_token]
                execute("UPDATE `groups` SET members=%s WHERE id=%s", (serialize_group_member_tokens(tokens) or None, row.get("id")))
    execute(
        "UPDATE users SET identity_recipient_groups=%s WHERE id=%s",
        (json.dumps(normalized_group_ids, separators=(",", ":")) if normalized_group_ids else None, user_id),
    )


def identity_user_select_clause():
    return """
        SELECT
            id, username, email, role, auth_provider, external_id, display_name, ldap_groups, identity_recipient_groups,
            accountexpire,
            adminperm, userperm, msgsendperm, restrict_groups, restrict_messages, restrict_bell_schedules,
            require_password_change
        FROM users
    """


def fetch_identity_user_by_id(user_id):
    return query_one(identity_user_select_clause() + " WHERE id=%s LIMIT 1", (user_id,))


def fetch_synced_identity_user(provider, external_id, username, email):
    provider = str(provider or "").strip().lower()
    if not is_external_auth_provider(provider):
        return None
    external_id = str(external_id or "").strip()
    username = str(username or "").strip()
    email = str(email or "").strip()
    conditions = []
    params = []
    if external_id:
        conditions.append("(auth_provider=%s AND external_id=%s)")
        params.extend([provider, external_id])
    if username:
        conditions.append("(auth_provider=%s AND username=%s)")
        params.extend([provider, username])
    if email:
        conditions.append("(auth_provider=%s AND email=%s)")
        params.extend([provider, email])
    if not conditions:
        return None
    order_parts = []
    order_params = []
    if external_id:
        order_parts.append("WHEN auth_provider=%s AND external_id=%s THEN 0")
        order_params.extend([provider, external_id])
    if username:
        order_parts.append("WHEN auth_provider=%s AND username=%s THEN 1")
        order_params.extend([provider, username])
    if email:
        order_parts.append("WHEN auth_provider=%s AND email=%s THEN 2")
        order_params.extend([provider, email])
    sql = (
        identity_user_select_clause()
        + " WHERE "
        + " OR ".join(conditions)
        + " ORDER BY CASE "
        + " ".join(order_parts)
        + " ELSE 9 END LIMIT 1"
    )
    return query_one(sql, tuple(params + order_params))


def normalized_external_username(value, provider, external_id=""):
    text = str(value or "").strip() or str(external_id or "").strip() or f"{provider}-user"
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^A-Za-z0-9._@-]+", "-", text).strip("-.@_")
    return (text or f"{provider}-user")[:100]


def unique_external_username(provider, preferred_username, email="", external_id="", ignore_user_id=None):
    base = normalized_external_username(preferred_username or email, provider, external_id)
    base_with_provider = base if base.lower().endswith(f"@{provider}") else (base[: max(0, 100 - len(provider) - 1)] + f"@{provider}")
    candidates = [base, base_with_provider]
    seen = set()
    for candidate in candidates:
        trimmed = candidate[:100]
        if trimmed and trimmed.lower() not in seen:
            seen.add(trimmed.lower())
            row = query_one("SELECT id FROM users WHERE username=%s LIMIT 1", (trimmed,))
            if not row or str(row.get("id")) == str(ignore_user_id or ""):
                return trimmed
    for suffix in range(2, 1000):
        suffix_text = f"-{suffix}"
        stem = base[: max(0, 100 - len(suffix_text))]
        candidate = f"{stem}{suffix_text}"
        row = query_one("SELECT id FROM users WHERE username=%s LIMIT 1", (candidate,))
        if not row or str(row.get("id")) == str(ignore_user_id or ""):
            return candidate
    return secrets.token_hex(8)


def unique_external_email(email, ignore_user_id=None):
    text = str(email or "").strip()
    if not text:
        return None
    row = query_one("SELECT id FROM users WHERE email=%s LIMIT 1", (text,))
    if not row or str(row.get("id")) == str(ignore_user_id or ""):
        return text
    return None


def scim_timeout_value(config, provider):
    try:
        timeout_value = int(str((config or {}).get(f"{provider}_scim_timeout") or "5").strip() or "5")
    except ValueError:
        timeout_value = 5
    return min(120, max(1, timeout_value))


def scim_users_endpoint(base_url):
    normalized = str(base_url or "").strip().rstrip("/")
    if not normalized:
        return ""
    if normalized.lower().endswith("/users"):
        return normalized
    return normalized + "/Users"


def scim_filter_value(value):
    return '"' + str(value or "").replace("\\", "\\\\").replace('"', '\\"') + '"'


def scim_request_json(url, bearer_token, timeout_seconds):
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/scim+json, application/json",
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": "OpenPagingServer/SCIM",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def scim_extract_user_email(resource):
    if not isinstance(resource, dict):
        return ""
    emails = resource.get("emails")
    if isinstance(emails, (list, tuple)):
        for item in emails:
            if isinstance(item, dict):
                value = str(item.get("value") or "").strip()
                if value:
                    return value
    return str(resource.get("email") or "").strip()


def scim_extract_group_values(resource):
    if not isinstance(resource, dict):
        return []
    return normalize_identity_group_values(resource.get("groups") or [])


def scim_user_is_active(resource):
    if not isinstance(resource, dict):
        return False
    if "active" not in resource:
        return True
    value = resource.get("active")
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def scim_identity_reference(source):
    if isinstance(source, dict):
        return {
            "external_id": str(source.get("external_id") or "").strip(),
            "username": str(source.get("username") or "").strip(),
            "email": str(source.get("email") or "").strip(),
            "display_name": str(source.get("display_name") or "").strip(),
        }
    return {"external_id": "", "username": "", "email": "", "display_name": ""}


def scim_identity_with_resource(provider, config, source, resource):
    identity = dict(source or {}) if isinstance(source, dict) else {}
    if not isinstance(resource, dict):
        return identity
    merged_groups = normalize_identity_group_values(identity.get("groups") or [])
    if (config or {}).get(f"{provider}_scim_sync_groups") == "1":
        if "groups" in resource:
            merged_groups = normalize_identity_group_values(merged_groups + scim_extract_group_values(resource))
        else:
            identity["scim_sync_incomplete"] = True
    elif not merged_groups:
        merged_groups = scim_extract_group_values(resource)
    identity["groups"] = merged_groups
    identity["username"] = (
        str(identity.get("username") or "").strip()
        or str(resource.get("userName") or "").strip()
        or str(resource.get("externalId") or "").strip()
    )
    identity["email"] = str(identity.get("email") or "").strip() or scim_extract_user_email(resource)
    identity["display_name"] = (
        str(identity.get("display_name") or "").strip()
        or str(resource.get("displayName") or "").strip()
        or identity.get("username")
        or identity.get("email")
    )
    identity["external_id"] = (
        str(identity.get("external_id") or "").strip()
        or str(resource.get("externalId") or "").strip()
        or str(resource.get("id") or "").strip()
    )
    identity["scim_resource"] = resource
    return identity


def scim_lookup_user_resource(provider, config, source):
    normalized_provider = str(provider or "").strip().lower()
    if not scim_provider_enabled(normalized_provider, config):
        return "disabled", None
    endpoint = scim_users_endpoint((config or {}).get(f"{normalized_provider}_scim_base_url"))
    bearer_token = str((config or {}).get(f"{normalized_provider}_scim_bearer_token") or "").strip()
    if not endpoint or not bearer_token:
        return "disabled", None
    identity = scim_identity_reference(source)
    filters = []
    external_id = identity.get("external_id")
    username = identity.get("username")
    email = identity.get("email")
    if external_id:
        filters.extend(
            [
                f"externalId eq {scim_filter_value(external_id)}",
                f"id eq {scim_filter_value(external_id)}",
            ]
        )
    if username:
        filters.append(f"userName eq {scim_filter_value(username)}")
    if email:
        filters.append(f'emails.value eq {scim_filter_value(email)}')
    timeout_seconds = scim_timeout_value(config, normalized_provider)
    seen_filters = set()
    try:
        for filter_text in filters:
            if filter_text in seen_filters:
                continue
            seen_filters.add(filter_text)
            url = endpoint + "?" + urlencode({"filter": filter_text})
            payload = scim_request_json(url, bearer_token, timeout_seconds)
            resources = payload.get("Resources") if isinstance(payload, dict) else None
            if isinstance(resources, list) and resources:
                for resource in resources:
                    if scim_user_is_active(resource):
                        return "found", resource
                return "missing", None
        return "missing", None
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError):
        return "error", None


def scim_identity_result(provider, config, source):
    identity = dict(source or {}) if isinstance(source, dict) else {}
    status, resource = scim_lookup_user_resource(provider, config, identity)
    if status == "missing":
        raise IdentityAccessDenied(identity_access_denied_message(config))
    if status != "found" or not isinstance(resource, dict):
        if status == "error":
            identity["scim_sync_incomplete"] = True
        return identity
    return scim_identity_with_resource(provider, config, identity, resource)


def identity_groups_text(groups):
    return "\n".join(normalize_identity_group_values(groups or []))


def external_identity_claim_source(source):
    if not isinstance(source, dict):
        return {}
    merged = {}
    for key in ("userinfo", "attributes", "scim_resource"):
        value = source.get(key)
        if isinstance(value, dict):
            for claim_key, claim_value in value.items():
                if claim_key not in merged:
                    merged[claim_key] = claim_value
    for claim_key, claim_value in source.items():
        if claim_key in {"userinfo", "attributes", "scim_resource"}:
            continue
        if claim_key not in merged:
            merged[claim_key] = claim_value
    if isinstance(source.get("scim_resource"), dict):
        merged.setdefault("scim", source.get("scim_resource"))
    return merged or dict(source)


def sync_redirect_identity_user(user_id, provider, config, identity_result):
    source = identity_result if isinstance(identity_result, dict) else {}
    if scim_provider_enabled(provider, config) and not isinstance(source.get("scim_resource"), dict):
        source = scim_identity_result(provider, config, source)
    groups = normalize_identity_group_values(source.get("groups") or [])
    if source.get("scim_sync_incomplete") and not groups:
        stored = query_one("SELECT ldap_groups FROM users WHERE id=%s LIMIT 1", (user_id,)) or {}
        groups = normalize_identity_group_values(str(stored.get("ldap_groups") or "").splitlines())
    groups_text = identity_groups_text(groups)
    external_id = str(source.get("external_id") or source.get("sub") or source.get("name_id") or "").strip()
    username = str(source.get("username") or "").strip() or external_id or "external-user"
    email = str(source.get("email") or "").strip()
    display_name = str(source.get("display_name") or "").strip() or username or email
    claims_source = external_identity_claim_source(source)
    access_profile = identity_access_profile(provider, config, groups, claims_source)
    role_value = normalize_identity_mapping_role(access_profile.get("role") or "receiver")
    if role_value == "none":
        raise IdentityAccessDenied(identity_access_denied_message(config))
    target_username = unique_external_username(provider, username, email, external_id, user_id)
    safe_email = unique_external_email(email, user_id)
    return apply_identity_access_profile_to_user(
        user_id,
        provider,
        target_username,
        safe_email,
        display_name,
        external_id,
        groups_text,
        access_profile,
    )


def refresh_redirect_identity_user(user, config):
    provider = str((user or {}).get("auth_provider") or "").strip().lower()
    if provider not in REDIRECT_IDENTITY_PROVIDER_VALUES:
        return user
    if not scim_provider_enabled(provider, config):
        return user
    source = {
        "external_id": str((user or {}).get("external_id") or "").strip(),
        "username": str((user or {}).get("username") or "").strip(),
        "email": str((user or {}).get("email") or "").strip(),
        "display_name": str((user or {}).get("display_name") or "").strip(),
    }
    try:
        status, resource = scim_lookup_user_resource(provider, config, source)
        if status == "missing":
            return None
        if status != "found" or not isinstance(resource, dict):
            return user
        return user
    except IdentityAccessDenied:
        return None
    except Exception:
        return user


def clear_external_user_password(user_id):
    execute("UPDATE users SET password='', salt='', require_password_change=0 WHERE id=%s", (user_id,))


def apply_identity_access_profile_to_user(user_id, provider, username, email, display_name, external_id, ldap_groups, access_profile):
    role_value = normalize_identity_mapping_role(access_profile.get("role") or "receiver")
    userperm_value = str(access_profile.get("userperm") or "")
    restrict_groups = "1" if truthy(access_profile.get("restrict_groups")) and role_value == "user" else "0"
    restrict_messages = "1" if truthy(access_profile.get("restrict_messages")) and role_value == "user" else "0"
    restrict_bell_schedules = "1" if truthy(access_profile.get("restrict_bell_schedules")) and role_value == "user" else "0"
    allowed_group_ids = normalize_role_mapping_ids(access_profile.get("allowed_groups") or [])
    allowed_message_ids = normalize_role_mapping_ids(access_profile.get("allowed_messages") or [])
    allowed_bell_schedule_ids = normalize_role_mapping_ids(access_profile.get("allowed_bell_schedules") or [])
    recipient_group_ids = normalize_role_mapping_ids(access_profile.get("recipient_groups") or [])
    safe_email = unique_external_email(email, user_id)
    execute(
        """
        UPDATE users
        SET username=%s, email=%s, display_name=%s, auth_provider=%s, external_id=%s, ldap_groups=%s,
            role=%s, userperm=%s, restrict_groups=%s, restrict_messages=%s, restrict_bell_schedules=%s,
            require_password_change=0
        WHERE id=%s
        """,
        (
            username,
            safe_email,
            display_name or None,
            provider,
            external_id or None,
            ldap_groups or None,
            role_value,
            userperm_value if role_value == "user" else "",
            restrict_groups,
            restrict_messages,
            restrict_bell_schedules,
            user_id,
        ),
    )
    clear_external_user_password(user_id)
    set_user_group_access_ids(user_id, allowed_group_ids if restrict_groups == "1" else [])
    set_user_message_access_ids(user_id, allowed_message_ids if restrict_messages == "1" else [])
    set_user_bell_schedule_access_ids(user_id, allowed_bell_schedule_ids if restrict_bell_schedules == "1" else [])
    sync_identity_recipient_groups(user_id, recipient_group_ids)
    return fetch_identity_user_by_id(user_id)


def delete_provider_managed_user(user_id):
    target_id = str(user_id if user_id is not None else "").strip()
    if not target_id:
        return
    revoke_all_user_session_records(target_id)
    execute("DELETE FROM api_tokens WHERE user_id=%s", (target_id,))
    execute("DELETE FROM user_group_access WHERE user_id=%s", (target_id,))
    execute("DELETE FROM user_message_access WHERE user_id=%s", (target_id,))
    execute("DELETE FROM user_bell_schedule_access WHERE user_id=%s", (target_id,))
    remove_desktop_member_from_all_groups(target_id)
    execute("DELETE FROM users WHERE id=%s", (target_id,))


def accessible_group_owner_ids(user_id):
    return {
        str(row.get("id") or "").strip()
        for row in query_all("SELECT id FROM `groups` WHERE owner_user_id=%s", (user_id,))
        if str(row.get("id") or "").strip()
    }


def accessible_message_owner_ids(user_id):
    return {
        str(row.get("messageid") or "").strip()
        for row in query_all("SELECT messageid FROM messages WHERE owner_user_id=%s", (user_id,))
        if str(row.get("messageid") or "").strip()
    }


def fetch_user_group_access_ids(user_id):
    ensure_identity_access_schema()
    return {
        str(row.get("group_id") or "").strip()
        for row in query_all("SELECT group_id FROM user_group_access WHERE user_id=%s", (user_id,))
        if str(row.get("group_id") or "").strip()
    }


def fetch_user_message_access_ids(user_id):
    ensure_identity_access_schema()
    return {
        str(row.get("message_id") or "").strip()
        for row in query_all("SELECT message_id FROM user_message_access WHERE user_id=%s", (user_id,))
        if str(row.get("message_id") or "").strip()
    }


def fetch_user_bell_schedule_access_ids(user_id):
    ensure_identity_access_schema()
    return {
        str(row.get("schedule_id") or "").strip()
        for row in query_all("SELECT schedule_id FROM user_bell_schedule_access WHERE user_id=%s", (user_id,))
        if str(row.get("schedule_id") or "").strip()
    }


def set_user_group_access_ids(user_id, group_ids):
    ensure_identity_access_schema()
    user_id = str(user_id if user_id is not None else "").strip()
    if not user_id:
        return
    wanted = []
    seen = set()
    for group_id in group_ids or []:
        token = str(group_id or "").strip()
        if token and token not in seen:
            seen.add(token)
            wanted.append(token)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_group_access WHERE user_id=%s", (user_id,))
            for group_id in wanted:
                cur.execute(
                    "INSERT INTO user_group_access (user_id, group_id) VALUES (%s,%s)",
                    (user_id, group_id),
                )
        conn.commit()
    finally:
        conn.close()


def set_user_message_access_ids(user_id, message_ids):
    ensure_identity_access_schema()
    user_id = str(user_id if user_id is not None else "").strip()
    if not user_id:
        return
    wanted = []
    seen = set()
    for message_id in message_ids or []:
        token = str(message_id or "").strip()
        if token and token not in seen:
            seen.add(token)
            wanted.append(token)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_message_access WHERE user_id=%s", (user_id,))
            for message_id in wanted:
                cur.execute(
                    "INSERT INTO user_message_access (user_id, message_id) VALUES (%s,%s)",
                    (user_id, message_id),
                )
        conn.commit()
    finally:
        conn.close()


def set_user_bell_schedule_access_ids(user_id, schedule_ids):
    ensure_identity_access_schema()
    user_id = str(user_id if user_id is not None else "").strip()
    if not user_id:
        return
    wanted = []
    seen = set()
    for schedule_id in schedule_ids or []:
        token = str(schedule_id or "").strip()
        if token and token not in seen:
            seen.add(token)
            wanted.append(token)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_bell_schedule_access WHERE user_id=%s", (user_id,))
            for schedule_id in wanted:
                cur.execute(
                    "INSERT INTO user_bell_schedule_access (user_id, schedule_id) VALUES (%s,%s)",
                    (user_id, schedule_id),
                )
        conn.commit()
    finally:
        conn.close()


def group_access_is_restricted(user):
    return truthy((user or {}).get("restrict_groups", "0"))


def message_access_is_restricted(user):
    return truthy((user or {}).get("restrict_messages", "0"))


def bell_schedule_access_is_restricted(user):
    return truthy((user or {}).get("restrict_bell_schedules", "0"))


def accessible_group_ids_for_user(user):
    if not user or not group_access_is_restricted(user):
        return None
    user_id = user.get("id")
    if user_id in (None, ""):
        return set()
    return fetch_user_group_access_ids(user_id) | accessible_group_owner_ids(user_id)


def accessible_message_ids_for_user(user):
    if not user or not message_access_is_restricted(user):
        return None
    user_id = user.get("id")
    if user_id in (None, ""):
        return set()
    return fetch_user_message_access_ids(user_id) | accessible_message_owner_ids(user_id)


def accessible_bell_schedule_ids_for_user(user):
    if not user or not bell_schedule_access_is_restricted(user):
        return None
    user_id = user.get("id")
    if user_id in (None, ""):
        return set()
    return fetch_user_bell_schedule_access_ids(user_id)


def user_can_access_group(user, group_id):
    allowed = accessible_group_ids_for_user(user)
    if allowed is None:
        return True
    return str(group_id or "").strip() in allowed


def user_can_access_message(user, message_id):
    allowed = accessible_message_ids_for_user(user)
    if allowed is None:
        return True
    return str(message_id or "").strip() in allowed


def user_can_access_bell_schedule(user, schedule_id):
    allowed = accessible_bell_schedule_ids_for_user(user)
    if allowed is None:
        return True
    return str(schedule_id or "").strip() in allowed


def filter_group_rows_for_user(user, rows):
    allowed = accessible_group_ids_for_user(user)
    if allowed is None:
        return list(rows or [])
    return [row for row in rows or [] if str((row or {}).get("id") or "").strip() in allowed]


def filter_message_rows_for_user(user, rows):
    allowed = accessible_message_ids_for_user(user)
    if allowed is None:
        return list(rows or [])
    return [row for row in rows or [] if str((row or {}).get("messageid") or "").strip() in allowed]


def filter_bell_schedule_rows_for_user(user, rows):
    allowed = accessible_bell_schedule_ids_for_user(user)
    if allowed is None:
        return list(rows or [])
    return [row for row in rows or [] if str((row or {}).get("id") or "").strip() in allowed]


def restricted_group_endpoint_tokens(user, rows):
    if not user or is_admin_user(user) or not group_access_is_restricted(user):
        return None
    tokens = []
    seen = set()
    for row in filter_group_rows_for_user(user, rows):
        for field_name in ("members", "monitor_members"):
            for token in str((row or {}).get(field_name) or "").replace(",", " ").split():
                cleaned = str(token or "").strip()
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    tokens.append(cleaned)
    return set(tokens)


def delete_group_access_records(group_id):
    ensure_identity_access_schema()
    execute("DELETE FROM user_group_access WHERE group_id=%s", (group_id,))


def delete_message_access_records(message_id):
    ensure_identity_access_schema()
    execute("DELETE FROM user_message_access WHERE message_id=%s", (message_id,))


def _temporary_asset_user_key(user):
    token = str((user or {}).get("id") if (user or {}).get("id") is not None else "").strip()
    return token


def prune_temporary_asset_access(now=None):
    now_value = float(now if now is not None else time.time())
    with TEMP_ASSET_ACCESS_LOCK:
        empty_users = []
        for user_key, grants in list(TEMP_ASSET_ACCESS.items()):
            expired_names = [name for name, expires_at in list(grants.items()) if float(expires_at or 0) <= now_value]
            for name in expired_names:
                grants.pop(name, None)
            if not grants:
                empty_users.append(user_key)
        for user_key in empty_users:
            TEMP_ASSET_ACCESS.pop(user_key, None)


def grant_temporary_asset_access(user, asset_name, ttl_seconds=TEMP_ASSET_ACCESS_SECONDS):
    normalized_name = asset_filename(asset_name)
    if not normalized_name:
        return
    user_key = _temporary_asset_user_key(user)
    if not user_key:
        return
    prune_temporary_asset_access()
    expires_at = time.time() + max(1, int(ttl_seconds or TEMP_ASSET_ACCESS_SECONDS))
    with TEMP_ASSET_ACCESS_LOCK:
        TEMP_ASSET_ACCESS.setdefault(user_key, {})[normalized_name] = expires_at


def user_temporary_asset_names(user):
    user_key = _temporary_asset_user_key(user)
    if not user_key:
        return set()
    prune_temporary_asset_access()
    with TEMP_ASSET_ACCESS_LOCK:
        grants = TEMP_ASSET_ACCESS.get(user_key) or {}
        return {str(name) for name in grants if str(name).strip()}


def rename_temporary_asset_access(old_name, new_name):
    old_token = asset_filename(old_name)
    new_token = asset_filename(new_name)
    if not old_token or not new_token:
        return
    prune_temporary_asset_access()
    with TEMP_ASSET_ACCESS_LOCK:
        for grants in TEMP_ASSET_ACCESS.values():
            expires_at = grants.pop(old_token, None)
            if expires_at:
                grants[new_token] = expires_at


def revoke_temporary_asset_access(asset_name, user=None):
    wanted = asset_filename(asset_name)
    if not wanted:
        return
    prune_temporary_asset_access()
    with TEMP_ASSET_ACCESS_LOCK:
        if user is not None:
            grants = TEMP_ASSET_ACCESS.get(_temporary_asset_user_key(user)) or {}
            grants.pop(wanted, None)
            return
        for grants in TEMP_ASSET_ACCESS.values():
            grants.pop(wanted, None)


def iter_asset_files():
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return sorted([item for item in ASSET_DIR.iterdir() if item.is_file()], key=lambda item: item.name.lower())
    except OSError:
        return []


def asset_reference_names(value):
    names = set()
    for token in str(value or "").split(":"):
        normalized = asset_filename(token)
        if not normalized:
            continue
        for candidate in asset_lookup_names(normalized):
            names.add(str(candidate).lower())
    return names


def resource_asset_names_for_user(user):
    if not user or is_admin_user(user) or can_access_page(user, "assets"):
        return set()
    cache = getattr(g, "_resource_asset_names_for_user", None)
    if cache is None:
        cache = {}
        g._resource_asset_names_for_user = cache
    cache_key = (
        str((user or {}).get("id") if (user or {}).get("id") is not None else ""),
        str((user or {}).get("role") or ""),
        str((user or {}).get("userperm") or ""),
        str((user or {}).get("restrict_groups") or ""),
        str((user or {}).get("restrict_messages") or ""),
    )
    if cache_key in cache:
        return set(cache[cache_key])
    names = set()
    if can_send_messages(user) or can_manage_messages(user):
        try:
            message_rows = filter_message_rows_for_user(
                user,
                query_all("SELECT messageid, icon, image, audio FROM messages"),
            )
        except Exception:
            message_rows = []
        for row in message_rows:
            for field_name in ("icon", "image", "audio"):
                names.update(asset_reference_names((row or {}).get(field_name)))
    if can_access_page(user, "bells"):
        try:
            bell_rows = query_all("SELECT audio FROM bell_events")
        except Exception:
            bell_rows = []
        for row in bell_rows:
            names.update(asset_reference_names((row or {}).get("audio")))
    cache[cache_key] = set(names)
    return names


def user_can_manage_asset(user, asset_name):
    normalized_name = asset_filename(asset_name)
    if not normalized_name:
        return False
    if is_admin_user(user) or can_access_page(user, "assets"):
        return True
    lookup = {candidate.lower() for candidate in asset_lookup_names(normalized_name)}
    temporary_names = {name.lower() for name in user_temporary_asset_names(user)}
    return any(candidate in temporary_names for candidate in lookup)


def user_can_access_asset(user, asset_name):
    normalized_name = asset_filename(asset_name)
    if not normalized_name:
        return False
    if is_admin_user(user) or can_access_page(user, "assets"):
        return True
    lookup = {candidate.lower() for candidate in asset_lookup_names(normalized_name)}
    temporary_names = {name.lower() for name in user_temporary_asset_names(user)}
    return any(candidate in temporary_names for candidate in lookup)


def visible_asset_paths_for_user(user):
    files = iter_asset_files()
    if is_admin_user(user) or can_access_page(user, "assets"):
        return files
    allowed_names = {name.lower() for name in user_temporary_asset_names(user)}
    if not allowed_names:
        return []
    visible = []
    for path in files:
        candidates = {candidate.lower() for candidate in asset_lookup_names(path.name)}
        if path.name.lower() in allowed_names or any(candidate in allowed_names for candidate in candidates):
            visible.append(path)
    return visible


def asset_inline_image_data_url(asset):
    if isinstance(asset, Path):
        try:
            base = ASSET_DIR.resolve()
            path = asset.resolve()
        except Exception:
            return ""
        if path != base and base not in path.parents:
            return ""
    else:
        normalized_name = asset_filename(asset)
        if not normalized_name:
            return ""
        try:
            path = asset_path(normalized_name)
        except Exception:
            return ""
    if not path or not path.is_file():
        return ""
    mime = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".bmp": "image/bmp",
    }.get(path.suffix.lower())
    if not mime:
        return ""
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def identity_provider_settings(data=None):
    source = data if isinstance(data, dict) else settings()
    normalized = dict(LDAP_SETTING_DEFAULTS)
    normalized.update(SSO_SETTING_DEFAULTS)
    normalized.update(OIDC_SETTING_DEFAULTS)
    normalized.update(SAML_SETTING_DEFAULTS)
    normalized.update({key: "" if value is None else str(value) for key, value in (source or {}).items()})
    provider = str(normalized.get("identity_provider") or "local").strip().lower()
    if provider not in IDENTITY_PROVIDER_VALUES:
        provider = "local"
    normalized["identity_provider"] = provider
    normalized["ldap_enabled"] = "1" if provider == "ldap" else "0"
    normalized["identity_redirect_auto"] = "1" if truthy(normalized.get("identity_redirect_auto", "1")) else "0"
    normalized["identity_allow_local_login"] = "1" if truthy(normalized.get("identity_allow_local_login", "0")) else "0"
    normalized["ldap_secure"] = "1" if truthy(normalized.get("ldap_secure", "0")) else "0"
    normalized["ldap_auto_create_users"] = "1" if truthy(normalized.get("ldap_auto_create_users", "1")) else "0"
    normalized["ldap_local_login_fallback"] = "1" if truthy(normalized.get("ldap_local_login_fallback", "1")) else "0"
    normalized["ldap_group_sync"] = "1" if truthy(normalized.get("ldap_group_sync", "1")) else "0"
    normalized["oidc_auto_create_users"] = "1" if truthy(normalized.get("oidc_auto_create_users", "1")) else "0"
    normalized["oidc_group_sync"] = "1" if truthy(normalized.get("oidc_group_sync", "1")) else "0"
    normalized["saml_auto_create_users"] = "1" if truthy(normalized.get("saml_auto_create_users", "1")) else "0"
    normalized["saml_group_sync"] = "1" if truthy(normalized.get("saml_group_sync", "1")) else "0"
    normalized["oidc_scim_enabled"] = "1" if truthy(normalized.get("oidc_scim_enabled", "0")) else "0"
    normalized["saml_scim_enabled"] = "1" if truthy(normalized.get("saml_scim_enabled", "0")) else "0"
    normalized["oidc_scim_sync_groups"] = "1" if truthy(normalized.get("oidc_scim_sync_groups", "1")) else "0"
    normalized["saml_scim_sync_groups"] = "1" if truthy(normalized.get("saml_scim_sync_groups", "1")) else "0"
    failure_behavior = str(normalized.get("ldap_failure_behavior") or "deny").strip().lower()
    normalized["ldap_failure_behavior"] = failure_behavior if failure_behavior in IDENTITY_FAILURE_BEHAVIORS else "deny"
    normalized["ldap_default_role"] = normalize_ldap_default_role(normalized.get("ldap_default_role"))
    normalized["oidc_default_role"] = normalize_ldap_default_role(normalized.get("oidc_default_role"))
    normalized["saml_default_role"] = normalize_ldap_default_role(normalized.get("saml_default_role"))
    normalized["oidc_scope"] = str(normalized.get("oidc_scope") or OIDC_SETTING_DEFAULTS["oidc_scope"]).strip() or OIDC_SETTING_DEFAULTS["oidc_scope"]
    for timeout_name in ("oidc_scim_timeout", "saml_scim_timeout"):
        try:
            timeout_value = int(str(normalized.get(timeout_name) or "5").strip() or "5")
        except ValueError:
            timeout_value = 5
        normalized[timeout_name] = str(min(120, max(1, timeout_value)))
    normalized["ldap_role_mappings"] = normalize_ldap_role_mappings(normalized.get(LDAP_ROLE_MAPPING_SETTING))
    normalized[OIDC_ROLE_MAPPING_SETTING] = normalize_ldap_role_mappings(normalized.get(OIDC_ROLE_MAPPING_SETTING))
    normalized[SAML_ROLE_MAPPING_SETTING] = normalize_ldap_role_mappings(normalized.get(SAML_ROLE_MAPPING_SETTING))
    return normalized


def configured_identity_provider(data=None):
    config = identity_provider_settings(data)
    provider = str(config.get("identity_provider") or "local").strip().lower()
    return provider if provider in IDENTITY_PROVIDER_VALUES else "local"


def identity_provider_uses_redirect(data=None):
    return configured_identity_provider(data) in REDIRECT_IDENTITY_PROVIDER_VALUES


def identity_redirect_auto_enabled(data=None):
    config = identity_provider_settings(data)
    return configured_identity_provider(config) in REDIRECT_IDENTITY_PROVIDER_VALUES and config.get("identity_redirect_auto") == "1"


def identity_local_login_allowed(data=None):
    config = identity_provider_settings(data)
    provider = configured_identity_provider(config)
    if provider in {"local", "ldap"}:
        return True
    return config.get("identity_allow_local_login") == "1"


def sso_failure_count():
    try:
        return max(0, int(session.get("sso_failure_count", "0") or 0))
    except (TypeError, ValueError):
        return 0


def clear_sso_failure_state():
    session.pop("sso_failure_count", None)
    session.pop("sso_error_detail", None)
    session.pop("sso_start_times", None)


def increment_sso_failure_count():
    count = sso_failure_count() + 1
    session["sso_failure_count"] = str(count)
    return count


def set_sso_error_detail(message):
    text = str(message or "").strip()
    if not text:
        session.pop("sso_error_detail", None)
        return
    session["sso_error_detail"] = text[:600]


def pop_sso_error_detail():
    return str(session.pop("sso_error_detail", "") or "").strip()


def current_user():
    ensure_identity_access_schema()
    ensure_scim_reconcile_thread()
    user_id = session.get("user_id")
    if user_id is None or user_id == "":
        return None
    session_id = str(session.get("web_session_id") or "").strip()
    session_record = active_user_session_record(session_id, user_id) if session_id else None
    user = query_one(
        """
        SELECT
            id, username, email, role, auth_provider, external_id, display_name,
            adminperm, userperm, msgsendperm, accountexpire, restrict_groups, restrict_messages,
            restrict_bell_schedules, require_password_change
        FROM users
        WHERE id=%s
        LIMIT 1
        """,
        (user_id,),
    )
    if not user:
        if session_id:
            revoke_user_session_record(session_id)
        session.clear()
        return None
    if user_account_is_expired(user):
        if session_id:
            revoke_user_session_record(session_id, user_id)
        session.clear()
        return None
    if session_id and not session_record:
        session.clear()
        return None
    if session_record:
        repair_loopback_session_ip(session_record)
    provider = str((user or {}).get("auth_provider") or session.get("auth_provider") or "local").strip().lower()
    if is_external_auth_provider(provider):
        try:
            last_identity_check = float(session.get("external_identity_checked_at", "0") or 0)
        except (TypeError, ValueError):
            last_identity_check = 0
        now_value = time.time()
        if now_value - last_identity_check >= EXTERNAL_IDENTITY_CHECK_INTERVAL_SECONDS:
            refreshed_user = refresh_synced_identity_user(user)
            if not refreshed_user:
                if session_id:
                    revoke_user_session_record(session_id, user_id)
                session.clear()
                return None
            user = refreshed_user
            session["external_identity_checked_at"] = str(now_value)
    if not session_id:
        session["web_session_id"] = register_login_session(
            user,
            auth_provider=str(session.get("auth_provider") or user.get("auth_provider") or "local"),
            session_type="web",
        )
        session["web_session_touched_at"] = str(time.time())
    else:
        soft = session_soft_logged_out(session_record)
        g.ops_soft_logout = soft
        try:
            last_touched = float(session.get("web_session_touched_at", "0") or 0)
        except (TypeError, ValueError):
            last_touched = 0
        now_value = time.time()
        if now_value - last_touched >= USER_SESSION_TOUCH_INTERVAL_SECONDS:
            touch_user_session_record(session_id)
            session["web_session_touched_at"] = str(now_value)
        if not soft and not soft_access_path(request.path or ""):
            try:
                last_full_touched = float(session.get("full_activity_touched_at", "0") or 0)
            except (TypeError, ValueError):
                last_full_touched = 0
            if now_value - last_full_touched >= USER_SESSION_TOUCH_INTERVAL_SECONDS:
                touch_full_activity(session_id)
                session["full_activity_touched_at"] = str(now_value)
    return user


def verify_local_password(password, user):
    expected_hash = hashlib.sha256((str(password or "") + str((user or {}).get("salt") or "")).encode()).hexdigest()
    return hmac.compare_digest(expected_hash, str((user or {}).get("password") or ""))


def local_user_record(username):
    return query_one(
        """
        SELECT
            id, username, email, password, salt, role, auth_provider, external_id,
            display_name, adminperm, userperm, msgsendperm, accountexpire,
            loginsleft, restrict_groups, restrict_messages, restrict_bell_schedules, require_password_change
        FROM users
        WHERE username=%s OR email=%s
        LIMIT 1
        """,
        (username, username),
    )


def authenticate_local_user(username, password):
    user = local_user_record(username)
    if not user or str(user.get("auth_provider") or "local").strip().lower() != "local":
        return None
    if not verify_local_password(password, user):
        return None
    if user_account_is_expired(user):
        return None
    return user


def user_requires_password_change(user, login_provider=None):
    if not truthy((user or {}).get("require_password_change", "0")):
        return False
    provider = str(login_provider or (user or {}).get("auth_provider") or session.get("auth_provider") or "").strip().lower()
    return provider == "local"


def password_change_redirect_target():
    return "/user/settings?open=password"


def parse_group_match_values(value):
    tokens = []
    seen = set()
    for token in re.split(r"[\r\n,;|]+", str(value or "")):
        normalized = str(token or "").strip()
        if normalized and normalized.lower() not in seen:
            seen.add(normalized.lower())
            tokens.append(normalized)
    return tokens


def ldap_group_aliases(raw_groups):
    aliases = set()
    for group in raw_groups or []:
        text = str(group or "").strip()
        if not text:
            continue
        aliases.add(text.lower())
        match = re.search(r"(?:^|,)cn=([^,]+)", text, re.IGNORECASE)
        if match:
            aliases.add(match.group(1).strip().lower())
    return aliases


def groups_match_requirement(raw_groups, configured_value):
    wanted = [token.lower() for token in parse_group_match_values(configured_value)]
    if not wanted:
        return True
    aliases = ldap_group_aliases(raw_groups)
    return any(token in aliases for token in wanted)


def ldap_ca_certificate_file(value):
    raw = str(value or "").strip()
    if not raw:
        return None, None
    candidate = Path(raw)
    if "\n" not in raw and candidate.is_file():
        return str(candidate), None
    if "BEGIN CERTIFICATE" not in raw:
        raise RuntimeError("CA certificate must be blank, a valid file path, or PEM text.")
    handle = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False, encoding="utf-8")
    try:
        handle.write(raw)
    finally:
        handle.close()
    return handle.name, handle.name


def ldap_server_for_config(config):
    if Connection is None or Server is None:
        raise RuntimeError("LDAP support requires the ldap3 package.")
    ca_path = None
    temp_path = None
    try:
        ca_path, temp_path = ldap_ca_certificate_file(config.get("ldap_ca_certificate"))
        tls = None
        if config.get("ldap_secure") == "1":
            tls = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_file=ca_path) if ca_path else Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
        server = Server(
            str(config.get("ldap_server_address") or "").strip(),
            port=int(config.get("ldap_server_port") or 389),
            use_ssl=config.get("ldap_secure") == "1",
            get_info=ALL,
            connect_timeout=int(config.get("ldap_connection_timeout") or 5),
            tls=tls,
        )
        return server, temp_path
    except Exception:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise


def ldap_search_filter(config, username):
    template = str(config.get("ldap_user_search_filter") or "({field}={username})")
    escaped_username = escape_filter_chars(username)
    field = str(config.get("ldap_login_field") or "uid").strip()
    return (
        template.replace("{username}", escaped_username)
        .replace("{login}", escaped_username)
        .replace("{field}", field)
        .replace("{login_field}", field)
    )


def authenticate_ldap_user(username, password, config):
    if not str(password or ""):
        return {"ok": False, "reason": "invalid"}
    server = None
    temp_ca_path = None
    bind_connection = None
    user_connection = None
    try:
        server, temp_ca_path = ldap_server_for_config(config)
        bind_username = str(config.get("ldap_bind_username") or "").strip()
        bind_password = str(config.get("ldap_bind_password") or "")
        bind_kwargs = {
            "server": server,
            "authentication": SIMPLE,
            "raise_exceptions": True,
            "auto_bind": True,
        }
        if bind_username:
            bind_kwargs["user"] = bind_username
            bind_kwargs["password"] = bind_password
        bind_connection = Connection(**bind_kwargs)
        login_field = str(config.get("ldap_login_field") or "uid").strip() or "uid"
        display_field = str(config.get("ldap_display_name_field") or "cn").strip() or "cn"
        email_field = str(config.get("ldap_email_field") or "mail").strip() or "mail"
        attributes = list({login_field, display_field, email_field, "memberOf"})
        search_ok = bind_connection.search(
            search_base=str(config.get("ldap_base_dn") or "").strip(),
            search_filter=ldap_search_filter(config, username),
            search_scope=SUBTREE,
            attributes=attributes,
            size_limit=2,
        )
        if not search_ok or len(bind_connection.entries) != 1:
            return {"ok": False, "reason": "invalid"}
        entry = bind_connection.entries[0]
        user_dn = str(entry.entry_dn or "").strip()
        user_connection = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=SIMPLE,
            raise_exceptions=True,
            auto_bind=True,
        )
        groups = []
        try:
            member_values = entry.memberOf.values if hasattr(entry, "memberOf") else []
            groups = [str(value).strip() for value in member_values if str(value).strip()]
        except Exception:
            groups = []
        display_name = ""
        email = ""
        login_value = ""
        for attr_name, target_name in ((display_field, "display_name"), (email_field, "email"), (login_field, "login")):
            try:
                attr = entry[attr_name]
                value = str(attr.value or "").strip()
            except Exception:
                value = ""
            if target_name == "display_name":
                display_name = value
            elif target_name == "email":
                email = value
            else:
                login_value = value
        claims = {
            login_field: [login_value or username],
            display_field: [display_name] if display_name else [],
            email_field: [email] if email else [],
            "memberof": list(groups),
        }
        return {
            "ok": True,
            "dn": user_dn,
            "username": login_value or username,
            "display_name": display_name,
            "email": email,
            "groups": groups,
            "claims": claims,
        }
    except Exception as exc:
        return {"ok": False, "reason": "connection", "error": str(exc)}
    finally:
        for connection in (user_connection, bind_connection):
            if connection is not None:
                try:
                    connection.unbind()
                except Exception:
                    pass
        if temp_ca_path:
            try:
                os.unlink(temp_ca_path)
            except OSError:
                pass


def unusable_password_record():
    random_value = secrets.token_hex(32)
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((random_value + salt).encode()).hexdigest()
    return password_hash, salt


def ldap_role_value(config, ldap_result):
    return str(ldap_access_profile(config, ldap_result).get("role") or "receiver")


def sync_ldap_user_record(config, ldap_result):
    ensure_identity_access_schema()
    external_id = str(ldap_result.get("dn") or "").strip()
    username = str(ldap_result.get("username") or "").strip() or external_id or "ldap-user"
    email = str(ldap_result.get("email") or "").strip()
    display_name = str(ldap_result.get("display_name") or "").strip()
    access_profile = ldap_access_profile(config, ldap_result)
    ldap_groups = "\n".join(ldap_result.get("groups") or [])
    matched_user = fetch_synced_identity_user("ldap", external_id, username, email)
    role_value = normalize_identity_mapping_role(access_profile.get("role") or "receiver")
    if role_value == "none":
        if matched_user:
            delete_provider_managed_user(matched_user.get("id"))
        raise IdentityAccessDenied(identity_access_denied_message(config))
    target_username = unique_external_username("ldap", username, email, external_id, matched_user.get("id") if matched_user else None)
    safe_email = unique_external_email(email, matched_user.get("id") if matched_user else None)
    if matched_user:
        return apply_identity_access_profile_to_user(
            matched_user.get("id"),
            "ldap",
            target_username,
            safe_email,
            display_name,
            external_id,
            ldap_groups,
            access_profile,
        )
    user_id = execute(
        """
        INSERT INTO users (
            username, email, password, salt, role, auth_provider, external_id, display_name, ldap_groups, identity_recipient_groups,
            userperm, restrict_groups, restrict_messages, restrict_bell_schedules, require_password_change
        ) VALUES (%s,%s,'','',%s,'ldap',%s,%s,%s,NULL,'',0,0,0,0)
        """,
        (
            target_username,
            safe_email,
            role_value if role_value in {"admin", "user", "receiver"} else "receiver",
            external_id or None,
            display_name or None,
            ldap_groups or None,
        ),
    )
    return apply_identity_access_profile_to_user(
        user_id,
        "ldap",
        target_username,
        safe_email,
        display_name,
        external_id,
        ldap_groups,
        access_profile,
    )


def normalize_identity_group_values(values):
    def extract_group_values(raw_value):
        if raw_value in (None, ""):
            return []
        if isinstance(raw_value, dict):
            collected = []
            for key in ("display", "value", "name", "id", "$ref"):
                if key in raw_value:
                    collected.extend(extract_group_values(raw_value.get(key)))
            if not collected:
                collected.extend(extract_group_values(json.dumps(raw_value, sort_keys=True)))
            return collected
        if isinstance(raw_value, (list, tuple, set)):
            collected = []
            for item in raw_value:
                collected.extend(extract_group_values(item))
            return collected
        text = str(raw_value or "").strip()
        return [text] if text else []

    raw_values = extract_group_values(values)
    normalized = []
    seen = set()
    for value in raw_values:
        text = str(value or "").strip()
        if not text:
            continue
        lower = text.lower()
        if lower in seen:
            continue
        seen.add(lower)
        normalized.append(text)
    return normalized


def identity_claim_value(source, claim_name):
    claim = str(claim_name or "").strip()
    if not claim:
        return ""
    current = source
    for part in claim.split("."):
        if isinstance(current, dict) and part in current:
            current = current.get(part)
        else:
            return ""
    if isinstance(current, (list, tuple, set)):
        for item in current:
            text = str(item or "").strip()
            if text:
                return text
        return ""
    return str(current or "").strip()


def identity_claim_values(source, claim_name):
    claim = str(claim_name or "").strip()
    if not claim:
        return []
    current = source
    for part in claim.split("."):
        if isinstance(current, dict) and part in current:
            current = current.get(part)
        else:
            return []
    return normalize_identity_group_values(current)


def sync_external_user_record(provider, config, identity_result):
    ensure_identity_access_schema()
    provider = str(provider or "").strip().lower()
    if provider not in REDIRECT_IDENTITY_PROVIDER_VALUES:
        return None
    source = identity_result if isinstance(identity_result, dict) else {}
    if scim_provider_enabled(provider, config):
        source = scim_identity_result(provider, config, source)
    groups = normalize_identity_group_values(source.get("groups") or [])
    external_id = str(source.get("external_id") or source.get("sub") or source.get("name_id") or "").strip()
    username = str(source.get("username") or "").strip() or external_id or "external-user"
    email = str(source.get("email") or "").strip()
    display_name = str(source.get("display_name") or "").strip() or username or email
    matched_user = fetch_synced_identity_user(provider, external_id, username, email)
    if source.get("scim_sync_incomplete") and not groups and matched_user:
        groups = normalize_identity_group_values(str(matched_user.get("ldap_groups") or "").splitlines())
    groups_text = identity_groups_text(groups)
    claims_source = external_identity_claim_source(source)
    access_profile = identity_access_profile(provider, config, groups, claims_source)
    role_value = normalize_identity_mapping_role(access_profile.get("role") or "receiver")
    if role_value == "none":
        if matched_user:
            delete_provider_managed_user(matched_user.get("id"))
        raise IdentityAccessDenied(identity_access_denied_message(config))
    target_username = unique_external_username(provider, username, email, external_id, matched_user.get("id") if matched_user else None)
    safe_email = unique_external_email(email, matched_user.get("id") if matched_user else None)
    if matched_user:
        return apply_identity_access_profile_to_user(
            matched_user.get("id"),
            provider,
            target_username,
            safe_email,
            display_name,
            external_id,
            groups_text,
            access_profile,
        )
    user_id = execute(
        """
        INSERT INTO users (
            username, email, password, salt, role, auth_provider, external_id, display_name, identity_recipient_groups,
            userperm, restrict_groups, restrict_messages, restrict_bell_schedules, require_password_change
        ) VALUES (%s,%s,'','',%s,%s,%s,%s,NULL,'',0,0,0,0)
        """,
        (
            target_username,
            safe_email,
            role_value if role_value in {"admin", "user", "receiver"} else "receiver",
            provider,
            external_id or None,
            display_name or None,
        ),
    )
    return apply_identity_access_profile_to_user(
        user_id,
        provider,
        target_username,
        safe_email,
        display_name,
        external_id,
        groups_text,
        access_profile,
    )


def ldap_identity_exists_for_user(user, config):
    provider = str((user or {}).get("auth_provider") or "").strip().lower()
    if provider != "ldap":
        return True
    external_id = str((user or {}).get("external_id") or "").strip()
    username = str((user or {}).get("username") or "").strip()
    if not username and not external_id:
        return False
    server = None
    temp_ca_path = None
    connection = None
    try:
        server, temp_ca_path = ldap_server_for_config(config)
        bind_username = str(config.get("ldap_bind_username") or "").strip()
        bind_password = str(config.get("ldap_bind_password") or "")
        bind_kwargs = {
            "server": server,
            "authentication": SIMPLE,
            "raise_exceptions": True,
            "auto_bind": True,
        }
        if bind_username:
            bind_kwargs["user"] = bind_username
            bind_kwargs["password"] = bind_password
        connection = Connection(**bind_kwargs)
        if external_id and BASE is not None:
            try:
                if connection.search(
                    search_base=external_id,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["memberOf"],
                    size_limit=1,
                ) and connection.entries:
                    return True
            except Exception:
                pass
        if not username:
            return False
        search_ok = connection.search(
            search_base=str(config.get("ldap_base_dn") or "").strip(),
            search_filter=ldap_search_filter(config, username),
            search_scope=SUBTREE,
            attributes=["memberOf"],
            size_limit=5,
        )
        if not search_ok or not connection.entries:
            return False
        if external_id:
            for entry in connection.entries:
                if str(entry.entry_dn or "").strip() == external_id:
                    return True
            return False
        return True
    except Exception:
        return True
    finally:
        if connection is not None:
            try:
                connection.unbind()
            except Exception:
                pass
        if temp_ca_path:
            try:
                os.unlink(temp_ca_path)
            except OSError:
                pass


def synced_user_still_exists(user, data=None):
    return refresh_synced_identity_user(user, data) is not None


def refresh_synced_identity_user(user, data=None):
    provider = str((user or {}).get("auth_provider") or "").strip().lower()
    config = identity_provider_settings(data)
    if provider == "ldap":
        return user if ldap_identity_exists_for_user(user, config) else None
    if provider in REDIRECT_IDENTITY_PROVIDER_VALUES:
        return refresh_redirect_identity_user(user, config)
    return user


def reconcile_scim_managed_users_once(data=None):
    config = identity_provider_settings(data)
    enabled_providers = [provider for provider in REDIRECT_IDENTITY_PROVIDER_VALUES if scim_provider_enabled(provider, config)]
    if not enabled_providers:
        return
    placeholders = ",".join(["%s"] * len(enabled_providers))
    rows = query_all(
        f"SELECT id, username, email, auth_provider, external_id, display_name FROM users WHERE auth_provider IN ({placeholders})",
        tuple(enabled_providers),
    )
    for row in rows:
        refreshed_user = refresh_synced_identity_user(row, config)
        if refreshed_user is None:
            delete_provider_managed_user(row.get("id"))


def scim_reconcile_loop():
    while True:
        try:
            reconcile_scim_managed_users_once()
        except Exception:
            try:
                app.logger.exception("SCIM reconciliation failed")
            except Exception:
                pass
        time.sleep(SCIM_RECONCILE_INTERVAL_SECONDS)


def ensure_scim_reconcile_thread():
    global SCIM_RECONCILE_THREAD
    config = identity_provider_settings(settings())
    if not any(scim_provider_enabled(provider, config) for provider in REDIRECT_IDENTITY_PROVIDER_VALUES):
        return
    with SCIM_RECONCILE_LOCK:
        if SCIM_RECONCILE_THREAD is not None and SCIM_RECONCILE_THREAD.is_alive():
            return
        SCIM_RECONCILE_THREAD = threading.Thread(target=scim_reconcile_loop, name="ops-scim-reconcile", daemon=True)
        SCIM_RECONCILE_THREAD.start()


def build_oidc_client(config):
    if OAuth is None:
        raise RuntimeError("OIDC Python library not installed in running environment")
    discovery_url = str(config.get("oidc_discovery_url") or "").strip()
    if not discovery_url:
        raise RuntimeError("OIDC discovery URL is required.")
    client_id = str(config.get("oidc_client_id") or "").strip()
    client_secret = str(config.get("oidc_client_secret") or "").strip()
    if not client_id or not client_secret:
        raise RuntimeError("OIDC client ID and client secret are required.")
    oauth = OAuth(app)
    return oauth.register(
        "ops_oidc",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=discovery_url,
        client_kwargs={"scope": str(config.get("oidc_scope") or OIDC_SETTING_DEFAULTS["oidc_scope"]).strip() or OIDC_SETTING_DEFAULTS["oidc_scope"]},
    )


def oidc_identity_result(config, token):
    client = build_oidc_client(config)
    userinfo = token.get("userinfo") if isinstance(token, dict) else {}
    if not isinstance(userinfo, dict):
        try:
            userinfo = userinfo.json()
        except Exception:
            userinfo = {}
    if not userinfo:
        try:
            response = client.get("userinfo")
            response.raise_for_status()
            userinfo = response.json()
        except Exception:
            userinfo = {}
    username = (
        identity_claim_value(userinfo, config.get("oidc_username_claim"))
        or identity_claim_value(userinfo, "preferred_username")
        or identity_claim_value(userinfo, "email")
        or identity_claim_value(userinfo, "sub")
    )
    email = identity_claim_value(userinfo, config.get("oidc_email_claim")) or identity_claim_value(userinfo, "email")
    display_name = identity_claim_value(userinfo, config.get("oidc_display_name_claim")) or identity_claim_value(userinfo, "name")
    return {
        "external_id": identity_claim_value(userinfo, "sub") or username or email,
        "username": username or email or identity_claim_value(userinfo, "sub"),
        "email": email,
        "display_name": display_name or username or email,
        "groups": identity_claim_values(userinfo, config.get("oidc_groups_claim")),
        "userinfo": userinfo,
    }


def saml_request_data():
    parsed = urlparse(request.url)
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "server_port": str(parsed.port or (443 if request.scheme == "https" else 80)),
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        "query_string": request.query_string.decode("utf-8", errors="ignore") if isinstance(request.query_string, bytes) else str(request.query_string or ""),
    }


def saml_settings_dict(config):
    if OneLogin_Saml2_Auth is None:
        raise RuntimeError("SAML Python library not installed in running environment")
    idp_entity_id = str(config.get("saml_idp_entity_id") or "").strip()
    sso_url = str(config.get("saml_sso_url") or "").strip()
    x509_cert = str(config.get("saml_x509_certificate") or "").strip()
    if not idp_entity_id or not sso_url or not x509_cert:
        raise RuntimeError("SAML IdP entity ID, SSO URL, and X.509 certificate are required.")
    base_url = request.url_root.rstrip("/")
    return {
        "strict": True,
        "debug": APP_DEBUG,
        "sp": {
            "entityId": base_url + "/login/saml/metadata",
            "assertionConsumerService": {
                "url": base_url + "/login/saml/callback",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": base_url + "/logout",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": {
            "entityId": idp_entity_id,
            "singleSignOnService": {
                "url": sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": x509_cert,
        },
        "security": {
            "requestedAuthnContext": False,
        },
    }


def build_saml_auth(config):
    return OneLogin_Saml2_Auth(saml_request_data(), old_settings=saml_settings_dict(config))


def saml_identity_result(config, auth):
    attributes = auth.get_attributes() or {}
    username = (
        identity_claim_value(attributes, config.get("saml_username_attribute"))
        or str(auth.get_nameid() or "").strip()
    )
    email = identity_claim_value(attributes, config.get("saml_email_attribute"))
    display_name = identity_claim_value(attributes, config.get("saml_display_name_attribute")) or username or email
    return {
        "external_id": str(auth.get_nameid() or "").strip() or username or email,
        "username": username or email or str(auth.get_nameid() or "").strip(),
        "email": email,
        "display_name": display_name,
        "groups": identity_claim_values(attributes, config.get("saml_groups_attribute")),
        "attributes": attributes,
        "name_id": str(auth.get_nameid() or "").strip(),
    }


def begin_web_login_session(user, auth_provider="local"):
    user_agent = request.headers.get("User-Agent", "unknown")
    ip_address = client_ip()
    was_desktop_client = bool(session.get("desktop_client"))
    now_value = time.time()
    session.clear()
    if was_desktop_client:
        session["desktop_client"] = True
        session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["auth_provider"] = str(auth_provider or "local")
    session["web_session_id"] = register_login_session(
        user,
        auth_provider=session["auth_provider"],
        session_type="web",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    session["web_session_touched_at"] = str(now_value)
    session["external_identity_checked_at"] = str(now_value)
    session["full_activity_touched_at"] = str(now_value)


def post_login_redirect_target(user, auth_provider="local"):
    return password_change_redirect_target() if user_requires_password_change(user, auth_provider) else default_web_landing_path(user)


def should_try_local_fallback(config, ldap_result):
    if config.get("ldap_local_login_fallback") != "1":
        return False
    reason = str(ldap_result.get("reason") or "").strip().lower()
    if reason == "invalid":
        return True
    return reason == "connection" and config.get("ldap_failure_behavior") == "fallback"


def authenticate_user_credentials(username, password, data=None):
    config = identity_provider_settings(data)
    provider = configured_identity_provider(config)
    if provider == "ldap":
        ldap_result = authenticate_ldap_user(username, password, config)
        if ldap_result.get("ok"):
            try:
                user = sync_ldap_user_record(config, ldap_result)
                if user:
                    return {"ok": True, "user": user, "provider": "ldap"}
            except IdentityAccessDenied as exc:
                return {"ok": False, "provider": "ldap", "reason": "denied", "error": str(exc)}
        if should_try_local_fallback(config, ldap_result):
            user = authenticate_local_user(username, password)
            if user:
                return {"ok": True, "user": user, "provider": "local"}
        return {"ok": False, "provider": "ldap", "reason": ldap_result.get("reason") or "invalid", "error": ldap_result.get("error") or ""}
    user = authenticate_local_user(username, password)
    if user:
        return {"ok": True, "user": user, "provider": "local"}
    return {"ok": False, "provider": "local", "reason": "invalid", "error": ""}

def require_user():
    user = current_user()
    if not user:
        return redirect("/login")
    if getattr(g, "ops_soft_logout", False) and not soft_access_path(request.path or ""):
        return redirect("/login?reauth=1")
    if user_requires_password_change(user) and request.path.rstrip("/") != "/user/settings":
        return redirect(password_change_redirect_target())
    return user


def require_admin():
    user = require_user()
    if not isinstance(user, dict):
        return user
    if not is_admin_user(user):
        abort(403)
    return user


def require_non_receiver():
    return require_user()


def h(value):
    return html.escape("" if value is None else str(value), quote=True)


def product_context():
    data = settings()
    return {
        "settings": data,
        "product_name": data.get("product_name") or "Open Paging Server",
        "favicon": data.get("favicon") or "",
        "show_online_docs": data.get("show_online_docs", "1"),
    }


def ops_sidebar_brand_html(data, product_name):
    data = data if isinstance(data, dict) else {}
    product_name = "" if product_name is None else str(product_name)
    use_logo = truthy(data.get("use_logo_in_sidebar", "1"))
    light_logo = str(data.get("sidebar_logo_light") or "/assets/OPENPAGINGSERVER-768x576-LIGHTMODE.png").strip()
    dark_logo = str(data.get("sidebar_logo_dark") or "/assets/OPENPAGINGSERVER-768x576-DARKMODE.png").strip()
    demo_badge = ""
    if demo_mode_active():
        demo_badge = '<span class="sidebar-demo-mode"><i class="fa-solid fa-bag-shopping"></i> Demo Mode</span>'
    if not use_logo or not light_logo:
        return f'<div class="sidebar-brand"><div class="sidebar-brand-inner"><span>{h(product_name)}</span>{demo_badge}</div></div>'
    dark_source = f'<source media="(prefers-color-scheme: dark)" srcset="{h(dark_logo)}">' if dark_logo else ""
    return (
        '<div class="sidebar-brand sidebar-brand-logo"><div class="sidebar-brand-inner"><picture>'
        f'{dark_source}<img src="{h(light_logo)}" alt="{h(product_name)}">'
        f"</picture>{demo_badge}</div></div>"
    )


def demo_mode_iframe_html(topic=""):
    if DEMO_MODE_HTML_PATH.is_file():
        return Response(DEMO_MODE_HTML_PATH.read_text(encoding="utf-8"), mimetype="text/html")
    return Response('<!DOCTYPE html><html lang="en"><body><p>Demo Mode</p></body></html>', mimetype="text/html")


def demo_mode_page(title, ctx, active, topic):
    iframe_src = "/demo-mode?" + urlencode({"topic": topic})
    content = f"""<h1>{h(title)}</h1>
    <div class="card" style="padding:0; overflow:hidden;">
        <iframe src="{h(iframe_src)}" style="width:100%; min-height:260px; border:0; border-radius:12px; display:block;" title="Demo Mode"></iframe>
    </div>"""
    return legacy_page(title, ctx, active, LEGACY_GENERIC_STYLE, content)


def demo_mode_inline_notice(topic):
    iframe_src = "/demo-mode?" + urlencode({"topic": topic})
    return f"""<div class="card" style="padding:0; overflow:hidden; margin-bottom:16px;">
        <iframe src="{h(iframe_src)}" style="width:100%; min-height:240px; border:0; border-radius:12px; display:block;" title="Demo Mode"></iframe>
    </div>"""


def legacy_user_context(user=None):
    if user is None:
        user = current_user()
    user = user or {}
    role = user.get("role") or ""
    if user.get("id") is not None and user.get("id") != "" and not role:
        role_row = query_one("SELECT role FROM users WHERE id = %s LIMIT 1", (user.get("id"),)) or {}
        role = role_row.get("role") or ""
    data = settings()
    product_name = data.get("product_name") or "Open Paging Server"
    display_name = str(user.get("display_name") or "").strip()
    username = display_name or user.get("username") or session.get("username") or "User"
    return {
        "user": user,
        "role": role,
        "is_desktop_client": desktop_client_context(),
        "username": username,
        "is_admin": is_admin_user(user),
        "is_receiver": is_receiver_user(user),
        "can_manage_messages": can_manage_messages(user),
        "can_manage_broadcasts": can_manage_broadcasts(user),
        "can_manage_groups": can_manage_groups(user),
        "can_edit_assets": can_edit_assets(user),
        "settings": data,
        "product_name": product_name,
        "favicon": data.get("favicon") or "",
        "show_online_docs": data.get("show_online_docs", "1"),
        "brand_html": ops_sidebar_brand_html(data, product_name),
    }


def legacy_guest_context():
    data = settings()
    product_name = data.get("product_name") or "Open Paging Server"
    return {
        "user": {},
        "role": "guest",
        "is_desktop_client": desktop_client_context(),
        "username": "Guest",
        "is_admin": False,
        "is_receiver": True,
        "is_guest": True,
        "can_manage_messages": False,
        "can_manage_broadcasts": False,
        "can_manage_groups": False,
        "can_edit_assets": False,
        "settings": data,
        "product_name": product_name,
        "favicon": data.get("favicon") or "",
        "show_online_docs": data.get("show_online_docs", "1"),
        "brand_html": ops_sidebar_brand_html(data, product_name),
    }


def _request_behind_reverse_proxy():
    proxy_headers = (
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "Via",
        "Forwarded",
    )
    return any(request.headers.get(header) for header in proxy_headers)


def request_is_insecure():
    insecure = request.scheme != "https"
    forwarded = str(
        request.headers.get("X-Forwarded-Proto")
        or request.headers.get("x-forwarded-proto")
        or request.headers.get("X-Ops-Forwarded-Proto")
        or request.headers.get("x-ops-forwarded-proto")
        or ""
    ).split(",", 1)[0].strip().lower()
    if forwarded == "https":
        insecure = False
    if insecure and _request_behind_reverse_proxy():
        insecure = False
    return insecure


def system_banner_records(ctx):
    banners = []
    now = datetime.now()
    if getattr(g, "ops_soft_logout", False):
        banners.append(
            {
                "key": "",
                "level": "info",
                "icon": "fa-solid fa-circle-info",
                "message": "Login again to access all features",
                "action_html": '<a class="system-banner-action" href="/login?reauth=1">Login</a>',
                "no_dismiss": True,
            }
        )
    if request_is_insecure():
        banners.append(
            {
                "key": "plain-http-warning",
                "level": "warning",
                "icon": "fa-solid fa-triangle-exclamation",
                "message": "You are connected to the server over plain HTTP. Content sent is not encrypted while in transit. Avoid sending private or confidential information if possible until this is resolved.",
                "dismiss_seconds": 86400,
            }
        )
    user = ctx.get("user") or {}
    if not (user or {}).get("accountexpire") and session.get("user_id") not in (None, ""):
        refreshed_user = current_user()
        if isinstance(refreshed_user, dict):
            user = refreshed_user
    expires_at = user_account_expiration_at(user)
    if (
        expires_at
        and account_expiration_warning_enabled(ctx.get("settings"))
        and expires_at > now
        and expires_at <= now + timedelta(days=ACCOUNT_EXPIRATION_WARNING_WINDOW_DAYS)
    ):
        remaining = humanize_remaining_duration(expires_at - now)
        user_key = str((user or {}).get("id") if (user or {}).get("id") not in (None, "") else session.get("user_id") or "").strip()
        banners.append(
            {
                "key": "account-expiration-" + (user_key or "unknown") + "-" + expires_at.strftime("%Y%m%d%H%M%S"),
                "level": "warning-expiration",
                "icon": "fa-solid fa-hourglass-half",
                "message": (
                    f"Your account will expire at {locale_time_text(expires_at)} {locale_date_text(expires_at)} "
                    f"(in {remaining}). Contact your system administrator for more information."
                ),
                "dismiss_seconds": 3600,
            }
        )
    if ctx.get("is_admin"):
        try:
            conn = db()
            try:
                with conn.cursor() as cur:
                    groups = suspended_bell_groups(cur)
            finally:
                conn.close()
        except Exception:
            groups = []
        names = [str(group.get("name") or group.get("id") or "").strip() for group in groups if str(group.get("name") or group.get("id") or "").strip()]
        if names:
            active_emergency_ids = [
                str(record.get("id") or "").strip()
                for record in list_active_broadcasts(limit=500)
                if record_is_active_emergency(record) and str(record.get("id") or "").strip()
            ]
            banners.insert(
                0,
                {
                    "key": "bells-suspended-"
                    + "-".join(str(group.get("id") or "").strip() for group in groups if str(group.get("id") or "").strip())
                    + "-broadcasts-"
                    + "-".join(active_emergency_ids),
                    "level": "danger",
                    "icon": "fa-solid fa-circle-exclamation",
                    "message": f"Bells for {', '.join(names)} are currently suspended because an emergency-priority message is in effect.",
                },
            )
    return banners


def render_system_banners(ctx):
    banners = system_banner_records(ctx)
    if not banners:
        return ""
    items = []
    for banner in banners:
        key = str(banner.get("key") or "").strip()
        dismiss_seconds = int(banner.get("dismiss_seconds") or 0)
        key_attr = f' data-banner-key="{h(key)}"' if key else ""
        dismiss_attr = f' data-dismiss-seconds="{dismiss_seconds}"' if dismiss_seconds > 0 else ""
        action_html = str(banner.get("action_html") or "")
        close_html = (
            ""
            if banner.get("no_dismiss")
            else '<button type="button" class="system-banner-close" onclick="dismissSystemBanner(this)" aria-label="Dismiss banner"><i class="fa-solid fa-xmark"></i></button>'
        )
        items.append(
            f"""<div class="system-banner system-banner-{h(banner.get('level') or 'warning')}"{key_attr}{dismiss_attr}>
    <div class="system-banner-main">
        <span class="system-banner-icon"><i class="{h(banner.get('icon') or 'fa-solid fa-circle-info')}"></i></span>
        <span class="system-banner-text">{h(banner.get('message') or '')}</span>
        {action_html}
    </div>
    {close_html}
</div>"""
        )
    return '<div id="ops-system-banners" class="system-banners">' + "".join(items) + "</div>"


def legacy_sidebar_html(ctx, active):
    user = ctx.get("user") or {}
    desktop_settings_button = ""
    if ctx.get("is_desktop_client"):
        desktop_settings_button = '<a class="desktop-app-settings-btn" href="/desktop/app-settings"><span class="nav-icon"><i class="fa-solid fa-sliders"></i></span><span class="nav-label">App Settings</span></a>'
    if ctx.get("is_guest"):
        cls = ' class="active"' if active == "dashboard" else ""
        nav_links = [
            f'<a href="/dashboard"{cls}><span class="nav-icon"><i class="fa-solid fa-house"></i></span><span class="nav-label">Dashboard</span></a>'
        ]
        if ctx.get("show_online_docs") == "1":
            nav_links.append(
                '<a href="https://docs.openpagingserver.org"><span class="nav-icon"><i class="fa-solid fa-book"></i></span><span class="nav-label">Online Documentation</span></a>'
            )
        rendered = [
            ctx["brand_html"],
            '<div class="sidebar-nav">',
            *nav_links,
            "</div>",
            '<div class="sidebar-account">',
            desktop_settings_button,
            '<a class="login-btn" href="/login"><span class="nav-icon"><i class="fa-solid fa-sign-in-alt"></i></span><span class="nav-label">Login</span></a>',
            '<div class="mobile-nav-divider"></div>',
            "</div>",
        ]
        return "\n    ".join(item for item in rendered if item)
    user_settings_class = ' class="active user-settings-link"' if active == "user-settings" else ' class="user-settings-link"'
    user_settings_link = f'<a href="/user/settings"{user_settings_class}><span class="nav-icon"><i class="fa-solid fa-user"></i></span><span class="nav-label">{h(ctx.get("username") or "User")}</span></a>'
    logout_button = '<button class="logout-btn" onclick="logout()"><span class="nav-icon"><i class="fa-solid fa-sign-out-alt"></i></span><span class="nav-label">Logout</span></button>'
    links = []
    if can_access_page(user, "dashboard"):
        links.append(("/dashboard", "house", "Dashboard", "dashboard"))
    if can_access_page(user, "paging"):
        links.append(("/paging/", "bullhorn", "Paging", "paging"))
    if can_send_messages(user) or can_manage_messages(user):
        links.append(("/messages/", "message", "Messages", "messages"))
    if can_access_page(user, "history"):
        links.append(("/history/", "clock-rotate-left", "History", "history"))
    if can_access_page(user, "bells"):
        links.append(("/bells/", "bell", "Bells", "bells"))
    if can_view_assets_page(user):
        links.append(("/assets/", "folder-open", "Assets", "assets"))
    nav_links = []
    for href, icon, label, key in links:
        cls = ' class="active"' if active == key else ""
        nav_links.append(
            f'<a href="{h(href)}"{cls}><span class="nav-icon"><i class="fa-solid fa-{icon}"></i></span><span class="nav-label">{h(label)}</span></a>'
        )
    if ctx.get("is_admin"):
        admin_links = [
            ("/admin/manage-broadcasts", "tower-broadcast", "Manage Broadcasts", "broadcasts"),
            ("/admin/manage-users", "users-cog", "Manage Users", "users"),
            ("/admin/manage-endpoints", "shapes", "Manage Endpoints", "endpoints"),
            ("/admin/manage-groups", "user-group", "Manage Groups", "groups"),
            ("/admin/settings/general", "cogs", "Server Settings", "settings"),
        ]
        for href, icon, label, key in admin_links:
            cls = "admin-only active" if active == key else "admin-only"
            nav_links.append(
                f'<a href="{h(href)}" class="{cls}"><span class="nav-icon"><i class="fa-solid fa-{icon}"></i></span><span class="nav-label">{h(label)}</span></a>'
            )
    else:
        if can_manage_broadcasts(user):
            cls = "admin-only active" if active == "broadcasts" else "admin-only"
            nav_links.append(
                f'<a href="/admin/manage-broadcasts" class="{cls}"><span class="nav-icon"><i class="fa-solid fa-tower-broadcast"></i></span><span class="nav-label">Manage Broadcasts</span></a>'
            )
        if can_manage_groups(user):
            cls = "admin-only active" if active == "groups" else "admin-only"
            nav_links.append(
                f'<a href="/admin/manage-groups" class="{cls}"><span class="nav-icon"><i class="fa-solid fa-user-group"></i></span><span class="nav-label">Manage Groups</span></a>'
            )
    if ctx.get("show_online_docs") == "1":
        nav_links.append(
            '<a href="https://docs.openpagingserver.org"><span class="nav-icon"><i class="fa-solid fa-book"></i></span><span class="nav-label">Online Documentation</span></a>'
        )
    rendered = [
        ctx["brand_html"],
        '<div class="sidebar-nav">',
        *nav_links,
        "</div>",
        '<div class="sidebar-account">',
        desktop_settings_button,
        user_settings_link,
        logout_button,
        '<div class="mobile-nav-divider"></div>',
        "</div>",
    ]
    return "\n    ".join(item for item in rendered if item)


def legacy_page(title, ctx, active, style, content, extra_script="", extra_after=""):
    favicon_html = '<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">'
    common_sidebar_style = """
#sidebar a,.logout-btn,.admin-only,.desktop-app-settings-btn{display:flex!important;align-items:center;gap:10px}
#sidebar .nav-icon,.logout-btn .nav-icon,.admin-only .nav-icon,.desktop-app-settings-btn .nav-icon{width:20px;display:inline-flex;justify-content:center;flex:0 0 20px}
#sidebar .nav-label,.logout-btn .nav-label,.admin-only .nav-label,.desktop-app-settings-btn .nav-label{min-width:0}
#sidebar a i,.logout-btn i,.admin-only i,.desktop-app-settings-btn i{margin-right:0!important;width:auto!important;text-align:center}
.logout-btn,.desktop-app-settings-btn{display:flex!important;width:100%}
.logout-btn:hover,.logout-btn-mobile:hover{background-color:#B71C1C!important;text-decoration:none}
.logout-btn-mobile{display:none!important}
.sidebar-nav{display:flex;flex-direction:column;flex:1 1 auto;min-height:0;overflow-y:auto}
.sidebar-account{display:flex;flex-direction:column;margin-top:auto;flex:0 0 auto}
#sidebar>.sidebar-brand{flex:0 0 auto}
.mobile-nav-divider{display:none}
#ops-page-banners{position:fixed;top:0;left:0;right:0;z-index:1300;overflow:hidden}
#ops-page-banners .system-banners{display:flex;flex-direction:column;gap:0;margin:0}
#ops-page-banners .system-banner{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:8px 16px;border:1px solid transparent;border-left:none;border-right:none;border-radius:0;box-shadow:none;box-sizing:border-box;width:100%}
#ops-page-banners .system-banner[data-banner-key]{display:none}
#ops-page-banners .system-banner.system-banner-visible{display:flex}
#ops-page-banners .system-banner + .system-banner{border-top:none}
#ops-page-banners .system-banner-main{display:flex;align-items:flex-start;gap:10px;min-width:0}
#ops-page-banners .system-banner-icon{font-size:1em;line-height:1.2;flex:0 0 auto}
#ops-page-banners .system-banner-text{line-height:1.4;min-width:0;font-size:0.94em;overflow-wrap:anywhere}
#ops-page-banners .system-banner-close{border:none;background:transparent;color:inherit;padding:2px 4px;cursor:pointer;border-radius:999px;flex:0 0 auto}
#ops-page-banners .system-banner-close:hover{background:rgba(0,0,0,.08)}
#ops-page-banners .system-banner-danger{background:#FDECEA;border-color:#F4B1AB;color:#A50E0E}
#ops-page-banners .system-banner-info{background:#E3F2FD;border-color:#90CAF9;color:#0D47A1}
#ops-page-banners .system-banner-action{display:inline-block;flex:0 0 auto;background:var(--ops-accent-hover);color:#FFF;padding:3px 14px;border-radius:999px;text-decoration:none;font-size:0.9em;align-self:center}
#ops-page-banners .system-banner-action:hover{background:var(--ops-accent-hover)}
#ops-page-banners .system-banner-warning{background:#FFF8E1;border-color:#F2C94C;color:#8A5A00}
#ops-page-banners .system-banner-warning-expiration{background:#FFF3E0;border-color:#FB8C00;color:#B85C00}
body.has-system-banners #sidebar{top:var(--ops-banner-offset, 0px)!important;height:calc(100vh - var(--ops-banner-offset, 0px))!important}
body.has-system-banners #mobile-header{top:var(--ops-banner-offset, 0px)!important}
body.has-system-banners #content{margin-top:var(--ops-banner-offset, 0px)!important;height:calc(100vh - var(--ops-banner-offset, 0px))!important;min-height:calc(100vh - var(--ops-banner-offset, 0px))!important}
@media(max-width:767px){.sidebar-account{margin-top:0;order:0}.sidebar-nav{order:1}.mobile-nav-divider{display:block;height:1px;background:#000;margin:0}#ops-page-banners .system-banner{padding:10px 12px}#ops-page-banners .system-banner-text{font-size:0.95em}}
"""
    banner_markup = render_system_banners(ctx)
    demo_markup = ""
    demo_script = ""
    demo_modal_requested = False
    if demo_mode_enabled():
        demo_modal_requested = request.environ.get("ops.demo_modal") == "1"
        demo_markup = """
<div id="demo-mode-overlay" onclick="closeDemoModePopupOnOverlay(event)" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.72); z-index:2500; align-items:center; justify-content:center; padding:20px; box-sizing:border-box;">
    <button type="button" onclick="closeDemoModePopup()" aria-label="Close demo mode popup" style="position:fixed; top:12px; right:12px; width:42px; height:42px; border:none; border-radius:50%; background:transparent; color:#FFF; cursor:pointer; z-index:2502; font-size:22px;"><i class="fa-solid fa-xmark"></i></button>
    <div style="position:relative; width:min(720px, 100%);">
        <iframe id="demo-mode-frame" src="/demo-mode" style="width:100%; min-height:320px; border:0; border-radius:18px; background:transparent; display:block;"></iframe>
    </div>
</div>"""
        demo_script = """
function openDemoModePopup(topic) {
  var overlay = document.getElementById('demo-mode-overlay');
  var frame = document.getElementById('demo-mode-frame');
  if (!overlay || !frame) return;
  frame.src = '/demo-mode?topic=' + encodeURIComponent(topic || '');
  overlay.style.display = 'flex';
}
function closeDemoModePopup() {
  var overlay = document.getElementById('demo-mode-overlay');
  if (overlay) overlay.style.display = 'none';
}
function closeDemoModePopupOnOverlay(event) {
  if (event && event.target && event.target.id === 'demo-mode-overlay') closeDemoModePopup();
}
document.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') closeDemoModePopup();
});
"""
        if demo_modal_requested:
            demo_topic = str(request.args.get("demomodal") or "")
            demo_topic_json = json.dumps(demo_topic).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            demo_script += f"""
document.addEventListener('DOMContentLoaded', function() {{
  openDemoModePopup({demo_topic_json});
}});
"""
    desktop_mode = (
        str(request.args.get("desktop_client") or "").strip().lower() in {"1", "true", "yes", "on"}
        or bool(session.get("desktop_client"))
    )
    desktop_inject = '<script>window.__OPS_DESKTOP_CLIENT__ = true;</script>' if desktop_mode else ''

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{h(title)} - {h(ctx["product_name"])}</title>
{favicon_html}
<link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin />
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
<link href="/assets/sidebar-brand.css" rel="stylesheet" />
{desktop_inject}
<script defer src="/assets/broadcast-sync.js"></script>
<style>
{LEGACY_GENERIC_STYLE}
{style}
{common_sidebar_style}
</style>
<link rel="stylesheet" href="/assets/theme.css"></head>
<body class="{'has-system-banners' if banner_markup else ''}" data-page="{h(active)}">
{f'<div id="ops-page-banners">{banner_markup}</div>' if banner_markup else ''}
<script>
function bannerDismissStorageKey(key) {{
  return 'ops-banner-dismissed:' + key;
}}
function bannerDismissed(key) {{
  if (!key) return false;
  try {{
    var raw = localStorage.getItem(bannerDismissStorageKey(key));
    if (!raw) return false;
    if (raw === '1') return true;
    var expiresAt = parseInt(raw, 10);
    if (!isNaN(expiresAt) && expiresAt > 1) {{
      if (Date.now() < expiresAt) return true;
      localStorage.removeItem(bannerDismissStorageKey(key));
    }}
  }} catch (_error) {{}}
  return false;
}}
function rememberBannerDismissal(key, banner) {{
  if (!key) return;
  try {{
    var seconds = parseInt((banner && banner.getAttribute('data-dismiss-seconds')) || '0', 10);
    if (!isNaN(seconds) && seconds > 0) {{
      localStorage.setItem(bannerDismissStorageKey(key), String(Date.now() + (seconds * 1000)));
    }} else {{
      localStorage.setItem(bannerDismissStorageKey(key), '1');
    }}
  }} catch (_error) {{}}
}}
(function() {{
  var container = document.getElementById('ops-system-banners');
  if (!container) return;
  Array.from(container.querySelectorAll('.system-banner')).forEach(function(banner) {{
    var key = banner.getAttribute('data-banner-key');
    if (bannerDismissed(key)) {{
      banner.remove();
    }} else {{
      banner.classList.add('system-banner-visible');
    }}
  }});
  if (!container.children.length) {{
    container.remove();
    document.body.classList.remove('has-system-banners');
    document.documentElement.style.setProperty('--ops-banner-offset', '0px');
    return;
  }}
  document.body.classList.add('has-system-banners');
  document.documentElement.style.setProperty('--ops-banner-offset', (document.getElementById('ops-page-banners').offsetHeight || 0) + 'px');
}})();
</script>
<div id="mobile-header">
    <span class="hamburger" onclick="toggleSidebar()"><i class="fa-solid fa-bars"></i></span>
    {ctx["brand_html"]}
</div>
<div id="overlay" onclick="closeSidebar()"></div>
<div id="sidebar">
    {legacy_sidebar_html(ctx, active)}
</div>
<div id="content" onclick="closeSidebarOnContentClick()">
{content}
</div>
<script>
function toggleSidebar() {{
  const sidebar = document.getElementById("sidebar");
  sidebar.classList.toggle("open");
  document.getElementById("overlay").classList.toggle("active", sidebar.classList.contains("open"));
}}
function closeSidebar() {{
  document.getElementById("sidebar").classList.remove("open");
  document.getElementById("overlay").classList.remove("active");
}}
function closeSidebarOnContentClick() {{
  if (document.getElementById("sidebar").classList.contains("open")) closeSidebar();
}}
function logout() {{
  window.location.href = "/logout";
}}
function openDesktopAppSettings() {{
  window.location.href = "/desktop/app-settings";
}}
function syncSystemBannerOffset() {{
  var container = document.getElementById('ops-page-banners');
  var hasBanners = !!(container && container.children.length);
  document.body.classList.toggle('has-system-banners', hasBanners);
  document.documentElement.style.setProperty('--ops-banner-offset', hasBanners ? (container.offsetHeight + 'px') : '0px');
}}
function dismissSystemBanner(button) {{
  var banner = button && button.closest ? button.closest('.system-banner') : null;
  if (!banner) return;
  var key = banner.getAttribute('data-banner-key');
  rememberBannerDismissal(key, banner);
  banner.remove();
  var container = document.getElementById('ops-system-banners');
  if (container && !container.children.length) container.remove();
  syncSystemBannerOffset();
}}
document.addEventListener('DOMContentLoaded', function() {{
  var container = document.getElementById('ops-system-banners');
  if (container) {{
    Array.from(container.querySelectorAll('.system-banner[data-banner-key]')).forEach(function(banner) {{
      var key = banner.getAttribute('data-banner-key');
      if (bannerDismissed(key)) banner.remove();
    }});
    if (!container.children.length) container.remove();
  }}
  syncSystemBannerOffset();
}});
window.addEventListener('resize', syncSystemBannerOffset);
{demo_script}
{extra_script}
</script>
{demo_markup}
{extra_after}
</body>
</html>"""
    return Response(html_doc, mimetype="text/html")


def sidebar(active="dashboard", is_admin=False, is_receiver=False):
    ctx = product_context()
    data = ctx["settings"]
    user = current_user() or {"role": "receiver" if is_receiver else ("admin" if is_admin else "user")}
    brand = h(ctx["product_name"])
    if truthy(data.get("use_logo_in_sidebar", "1")):
        logo = data.get("sidebar_logo_light") or "/assets/OPENPAGINGSERVER-768x576-LIGHTMODE.png"
        brand = f'<img class="sidebar-logo" src="{h(logo)}" alt="{h(ctx["product_name"])}">'
    links = []
    if can_access_page(user, "dashboard"):
        links.append(("/dashboard", "house", "Dashboard", "dashboard"))
    if can_access_page(user, "paging"):
        links.append(("/paging/", "bullhorn", "Paging", "paging"))
    if can_send_messages(user) or can_manage_messages(user):
        links.append(("/messages/", "message", "Messages", "messages"))
    if can_access_page(user, "history"):
        links.append(("/history/", "clock-rotate-left", "History", "history"))
    if can_access_page(user, "bells"):
        links.append(("/bells/", "bell", "Bells", "bells"))
    if can_view_assets_page(user):
        links.append(("/assets/", "folder-open", "Assets", "assets"))
    if is_admin:
        links.extend(
            [
                ("/admin/manage-broadcasts", "tower-broadcast", "Manage Broadcasts", "broadcasts"),
                ("/admin/manage-users", "users-cog", "Manage Users", "users"),
                ("/admin/manage-endpoints", "shapes", "Manage Endpoints", "endpoints"),
                ("/admin/manage-groups", "user-group", "Manage Groups", "groups"),
                ("/admin/settings/general", "cogs", "Server Settings", "settings"),
            ]
        )
    else:
        if can_manage_broadcasts(user):
            links.append(("/admin/manage-broadcasts", "tower-broadcast", "Manage Broadcasts", "broadcasts"))
        if can_manage_groups(user):
            links.append(("/admin/manage-groups", "user-group", "Manage Groups", "groups"))
    if ctx["show_online_docs"] == "1":
        links.append(("https://docs.openpagingserver.org", "book", "Online Documentation", "docs"))
    rendered = [f'<div class="brand">{brand}</div>']
    for href, icon, label, key in links:
        cls = "active" if active == key else ""
        rendered.append(
            f'<a class="{cls}" href="{h(href)}"><span class="nav-icon"><i class="fa-solid fa-{icon}"></i></span><span class="nav-label">{h(label)}</span></a>'
        )
    rendered.append(
        '<a class="logout" href="/logout"><span class="nav-icon"><i class="fa-solid fa-sign-out-alt"></i></span><span class="nav-label">Logout</span></a>'
    )
    return "\n".join(rendered)


BASE_CSS = """
body,html{margin:0;padding:0;font-family:Tahoma,Arial,sans-serif;background:#fff;color:#222;min-height:100%}
a{color:var(--ops-accent);text-decoration:none}a:hover{text-decoration:underline}
.layout{display:flex;min-height:100vh}.sidebar{width:220px;background:var(--ops-accent);color:white;position:fixed;inset:0 auto 0 0;display:flex;flex-direction:column;box-shadow:2px 0 8px rgba(0,0,0,.2)}
.sidebar a,.sidebar .brand{color:white;display:flex;align-items:center;gap:10px;padding:12px 20px;border-bottom:1px solid rgba(255,255,255,.14);box-sizing:border-box}.sidebar a.active,.sidebar a:hover{background:var(--ops-accent-hover);text-decoration:none}.sidebar .nav-icon{width:24px;display:inline-flex;justify-content:center;flex:0 0 24px}.sidebar .logout{margin-top:auto;background:#c62828}.sidebar .logout:hover{background:#b71c1c!important}.sidebar-logo{display:block;max-width:170px;max-height:64px;object-fit:contain;margin:auto}
.content{margin-left:220px;padding:24px;box-sizing:border-box;width:calc(100% - 220px)}h1,h2{font-weight:400;color:var(--ops-accent)}.card{border:1px solid #e5e5e5;border-radius:8px;padding:16px;margin:0 0 16px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select,textarea{box-sizing:border-box;width:100%;padding:10px;border:1px solid #bbb;border-radius:4px;font:inherit;background:#fff;color:#222}textarea{min-height:110px}.button,button{display:inline-flex;align-items:center;gap:8px;border:0;border-radius:4px;background:var(--ops-accent);color:#fff;padding:10px 14px;font:inherit;cursor:pointer;text-decoration:none}.button:hover,button:hover{background:var(--ops-accent-hover);text-decoration:none}.danger{background:#c62828}.danger:hover{background:#b71c1c}.muted{color:#666}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #eee;text-align:left;padding:10px;vertical-align:top}.flash{padding:12px;border-radius:4px;margin-bottom:16px}.success{background:#e8f5e9;color:#1b5e20}.error{background:#ffebee;color:#b71c1c}.tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}.tabs a{padding:10px 14px;background:#f5f5f5;border-radius:5px 5px 0 0}.tabs a.active{background:var(--ops-accent);color:#fff;text-decoration:none}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#e3f2fd;color:var(--ops-accent-hover)}
.md-checkbox-container{display:flex;align-items:center;position:relative;cursor:pointer;font-size:14px;font-weight:500;color:#222;user-select:none;gap:12px}.md-checkbox-container input{position:absolute;opacity:0;cursor:pointer;height:0;width:0}.md-checkmark{position:relative;display:inline-block;flex:0 0 auto;height:20px;width:20px;background:#fff;border:2px solid #5f6368;border-radius:2px;transition:all .2s}.md-checkbox-container:hover input ~ .md-checkmark{border-color:#202124}.md-checkbox-container input:checked ~ .md-checkmark{background:var(--ops-accent);border-color:var(--ops-accent)}.md-checkmark:after{content:"";position:absolute;display:none;left:6px;top:2px;width:4px;height:10px;border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg)}.md-checkbox-container input:checked ~ .md-checkmark:after{display:block}
@media(max-width:767px){.layout{display:block}.sidebar{position:static;width:100%;min-height:auto}.content{margin-left:0;width:100%;padding:16px}.table{display:block;overflow-x:auto}}
@media(prefers-color-scheme:dark){body,html{background:#121212;color:#e0e0e0}.sidebar{background:#424242}.sidebar a.active,.sidebar a:hover{background:#505050}.card{background:#1e1e1e;border-color:#333;box-shadow:none}.table th,.table td{border-color:#333}input,select,textarea{background:#222;color:#e0e0e0;border-color:#555}h1,h2{color:#90caf9}.muted{color:#bbb}.tabs a{background:#222}.pill{background:#263238;color:#90caf9}.md-checkbox-container{color:#E0E0E0}.md-checkmark{border-color:#9AA0A6;background:#1E1E1E}.md-checkbox-container:hover input ~ .md-checkmark{border-color:#E8EAED}.md-checkbox-container input:checked ~ .md-checkmark{background:#8AB4F8;border-color:#8AB4F8}.md-checkmark:after{border-color:#1E1E1E}}
"""

LEGACY_GENERIC_STYLE = """
body, html { margin:0; padding:0; font-family:"Tahoma",sans-serif; font-weight:300; background-color:#FFF; height:100%; }
#sidebar { width:220px; background-color:var(--ops-accent); color:#FFF; height:100vh; position:fixed; top:0; left:0; display:flex; flex-direction:column; box-shadow:2px 0 8px rgba(0,0,0,0.2); transition:transform 0.3s ease; z-index:1200; }
@media (max-width:767px){ #sidebar{ transform:translateX(-100%); } #sidebar.open{ transform:translateX(0); } }
#sidebar a,.logout-btn,.logout-btn-mobile,.admin-only,.desktop-app-settings-btn{ color:#FFF; padding:12px 20px; display:flex; align-items:center; gap:10px; border-bottom:1px solid rgba(255,255,255,0.1); text-decoration:none; transition:background 0.3s; font-size:0.9em; text-align:left; box-sizing:border-box; }
#sidebar .nav-icon,.logout-btn .nav-icon,.logout-btn-mobile .nav-icon,.admin-only .nav-icon,.desktop-app-settings-btn .nav-icon { width:20px; display:inline-flex; justify-content:center; flex:0 0 20px; }
#sidebar .nav-label,.logout-btn .nav-label,.logout-btn-mobile .nav-label,.admin-only .nav-label,.desktop-app-settings-btn .nav-label { min-width:0; }
#sidebar a:hover,#sidebar a.active{ background-color:var(--ops-accent-hover); }
.logout-btn{ background-color:#C62828; border:none; cursor:pointer; margin-top:auto; transition:background-color 0.3s; }
.desktop-app-settings-btn{ background-color:transparent; border:none; border-radius:0; cursor:pointer; margin-top:0; transition:background-color 0.3s; width:100%; font-family:inherit; }
.login-btn{ background-color:#2E7D32; border:none; cursor:pointer; margin-top:auto; transition:background-color 0.3s; color:#FFF; padding:12px 20px; display:flex; align-items:center; gap:10px; border-bottom:1px solid rgba(255,255,255,0.1); text-decoration:none; font-size:0.9em; text-align:left; box-sizing:border-box; width:100%; }
.login-btn:hover{ background-color:#1B5E20; text-decoration:none; }
.login-btn .nav-icon{ width:20px; display:inline-flex; justify-content:center; flex:0 0 20px; }
.logout-btn-mobile{ background-color:#C62828; border:none; cursor:pointer; transition:background-color 0.3s; display:none; }
.logout-btn:hover,.logout-btn-mobile:hover{ background-color:#B71C1C; }
@media(max-width:767px){ .logout-btn{ display:none; } .logout-btn-mobile{ display:flex; } }
#mobile-header{ display:flex; background-color:var(--ops-accent-hover); color:#FFF; padding:calc(12px + env(safe-area-inset-top)) 16px 12px 16px; align-items:center; justify-content:space-between; position:fixed; top:0; left:0; right:0; z-index:1100; }
#mobile-header h2{ margin:0; font-size:1.1em; font-weight:400; color:#FFF; }
#mobile-header .hamburger{ font-size:1.5em; cursor:pointer; }
#overlay{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.3); z-index:900; }
#overlay.active{ display:block; }
#content{ margin-left:220px; padding:24px; height:100vh; overflow-y:auto; width:calc(100% - 220px); box-sizing:border-box; transition:margin-left 0.3s ease; }
@media(max-width:767px){ #content{ margin-left:0; width:100%; padding-top:70px; } }
#content h1{ font-weight:400; }
@media(min-width:768px){ #mobile-header{ display:none; } }
.card{ background:#FFF; padding:16px; border:1px solid #EEE; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,0.1); margin-bottom:16px; }
.grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; }
.actions{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.table{ width:100%; border-collapse:collapse; }
.table th,.table td{ border-bottom:1px solid #EEE; padding:10px; text-align:left; vertical-align:top; }
.button,button{ background:var(--ops-accent); color:#FFF; border:none; padding:10px 16px; border-radius:6px; font-size:14px; cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; gap:8px; font-family:inherit; }
.button:hover,button:hover{ background:var(--ops-accent-hover); text-decoration:none; }
.danger{ background:#C62828; }
.danger:hover{ background:#B71C1C; }
.muted{ color:#777; }
input,select,textarea{ box-sizing:border-box; padding:10px; border:1px solid #DDD; border-radius:4px; background:#FFF; color:#000; font-family:inherit; }
label{ display:block; margin-bottom:10px; }
.md-checkbox-container{display:flex;align-items:center;position:relative;cursor:pointer;font-size:14px;font-weight:500;color:#202124;user-select:none;gap:12px}.md-checkbox-container input{position:absolute;opacity:0;cursor:pointer;height:0;width:0}.md-checkmark{position:relative;display:inline-block;flex:0 0 auto;height:20px;width:20px;background:#FFF;border:2px solid #5f6368;border-radius:2px;transition:all .2s}.md-checkbox-container:hover input ~ .md-checkmark{border-color:#202124}.md-checkbox-container input:checked ~ .md-checkmark{background:var(--ops-accent);border-color:var(--ops-accent)}.md-checkmark:after{content:"";position:absolute;display:none;left:6px;top:2px;width:4px;height:10px;border:solid #FFF;border-width:0 2px 2px 0;transform:rotate(45deg)}.md-checkbox-container input:checked ~ .md-checkmark:after{display:block}
.flash{ padding:12px 14px; border-radius:8px; margin-bottom:14px; }
.success{ background:#E6F4EA; border:1px solid #CEEAD6; color:#137333; }
.error{ background:#FCE8E6; border:1px solid #F6AEA9; color:#A50E0E; }
.tabs{ display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
.tabs a{ padding:10px 14px; background:#F5F5F5; border-radius:5px 5px 0 0; text-decoration:none; }
.tabs a.active{ background:var(--ops-accent); color:#FFF; }
@media(prefers-color-scheme:dark){
body,html{ background-color:#121212; color:#E0E0E0; }
#sidebar{ background-color:#424242; }
#sidebar a,.logout-btn,.logout-btn-mobile,.admin-only{ color:#E0E0E0; }
#sidebar a.active,#sidebar a:hover{ background-color:#505050; }
#mobile-header{ background-color:#424242; }
#content{ background-color:#121212; }
.card{ border:1px solid #333; background-color:#1E1E1E; box-shadow:none; }
.table th,.table td{ border-color:#333; }
input,select,textarea{ background:#333; border-color:#444; color:#FFF; }
.md-checkbox-container{color:#E0E0E0;}
.md-checkmark{border-color:#9AA0A6;background:#1E1E1E;}
.md-checkbox-container:hover input ~ .md-checkmark{border-color:#E8EAED;}
.md-checkbox-container input:checked ~ .md-checkmark{background:#8AB4F8;border-color:#8AB4F8;}
.md-checkmark:after{border-color:#1E1E1E;}
.button,button{ background:#8AB4F8; color:#10233A; }
.button:hover,button:hover{ background:#9CC0FA; }
.danger{ background:#CF6679; color:#000; }
.muted{ color:#AAA; }
.tabs a{ background:#222; }
}
"""


def page(title, body, active="dashboard", user=None, status=200):
    if user is None:
        user = current_user()
    flashes = "".join(f'<div class="flash {h(cat)}">{h(msg)}</div>' for cat, msg in session.pop("_flashes", []))
    response = legacy_page(title, legacy_user_context(user), active, LEGACY_GENERIC_STYLE, flashes + body)
    response.status_code = status
    return response


def module_page(title, body, active="endpoints", user=None, status=200):
    flashes = "".join(f'<div class="flash {h(cat)}">{h(msg)}</div>' for cat, msg in session.pop("_flashes", []))
    return Response(
        render_template_string(
            """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title><style>{{ css }}</style><link rel="stylesheet" href="/assets/theme.css"></head><body><main class="content" style="margin-left:0;width:100%">{{ flashes|safe }}{{ body|safe }}</main></body></html>""",
            title=title,
            css=BASE_CSS,
            flashes=flashes,
            body=body,
        ),
        status=status,
        mimetype="text/html",
    )


def simple_form(title, fields, action, values=None, submit="Save", extra=""):
    values = values or {}
    controls = []
    for name, label, kind, options in fields:
        value = values.get(name, "")
        if kind == "textarea":
            controls.append(f'<label>{h(label)}<textarea name="{h(name)}">{h(value)}</textarea></label>')
        elif kind == "select":
            opts = "".join(
                f'<option value="{h(opt)}"{" selected" if str(opt)==str(value) else ""}>{h(text)}</option>'
                for opt, text in options
            )
            controls.append(f'<label>{h(label)}<select name="{h(name)}">{opts}</select></label>')
        elif kind == "checkbox":
            controls.append(f'<label class="md-checkbox-container"><input type="checkbox" name="{h(name)}" value="1"{" checked" if truthy(value) else ""}><span class="md-checkmark"></span><span>{h(label)}</span></label>')
        else:
            controls.append(f'<label>{h(label)}<input type="{h(kind)}" name="{h(name)}" value="{h(value)}"></label>')
    return f'<h1>{h(title)}</h1><form method="post" enctype="multipart/form-data" action="{h(action)}" class="card grid">{"".join(controls)}{extra}<div class="actions"><button type="submit"><i class="fa-solid fa-save"></i>{h(submit)}</button></div></form>'


def alias(rule, endpoint=None, **options):
    def decorator(func):
        route_endpoint = endpoint or f"{func.__name__}_{re.sub(r'[^A-Za-z0-9_]+', '_', rule).strip('_') or 'root'}"
        app.route(rule, endpoint=route_endpoint, **options)(func)
        return func
    return decorator


def load_html_document(path):
    return path.read_text(encoding="utf-8")


def show_online_docs_on_error_page():
    try:
        data = settings()
    except Exception:
        return True
    return data.get("show_online_docs", "1") == "1"


def stash_traceback(exc):
    if not APP_DEBUG:
        return ""
    trace_id = uuid.uuid4().hex
    source_exc = getattr(exc, "original_exception", None) or exc
    TRACEBACKS[trace_id] = "".join(traceback.format_exception(type(source_exc), source_exc, source_exc.__traceback__))
    return trace_id


def render_error_document(filename, status_code, exc=None):
    path = WEB_ERROR_DIR / filename
    if not path.is_file():
        return Response(f"{status_code}", status=status_code, mimetype="text/plain")
    html_doc = load_html_document(path)
    if filename == "500.html":
        docs_paragraph = "<p>If this issue persists, ensure the server is up-to-date and consult the online documentation for troubleshooting, and debuging information.</p>"
        if not show_online_docs_on_error_page():
            html_doc = html_doc.replace(docs_paragraph, "")
        trace_link_markup = '<a href="/"><i class="fa-solid fa-bug"></i> Show Traceback</a>'
        trace_id = stash_traceback(exc) if exc is not None else ""
        if trace_id:
            html_doc = html_doc.replace(
                trace_link_markup,
                f'<a href="/__traceback__/{h(trace_id)}" target="_blank" rel="noopener"><i class="fa-solid fa-bug"></i> Show Traceback</a>',
            )
        else:
            html_doc = html_doc.replace(trace_link_markup, "")
    return Response(html_doc, status=status_code, mimetype="text/html")


def endpoint_output_capable(endpoint):
    if endpoint.get("output_capable") is False:
        return False
    direction = (str(endpoint.get("direction") or "") + " " + str(endpoint.get("input_type") or "")).lower()
    if "output" in direction:
        return True
    capabilities = endpoint.get("capabilities") or []
    return isinstance(capabilities, list) and ("output" in capabilities or "bells" in capabilities)


def endpoint_is_available(endpoint):
    if not endpoint_output_capable(endpoint):
        return False
    if "available" in endpoint:
        return bool(endpoint.get("available"))
    return str(endpoint.get("status") or "").strip().lower() in {"online", "configured", "ready", "ok", "up"}


def group_member_tokens(members):
    return [token for token in re.split(r"[\s,;|]+", str(members or "")) if token]


def desktop_eligible_users():
    return query_all(
        """
        SELECT id, username, role
        FROM users
        WHERE role IS NULL OR role = '' OR role NOT IN ('receiver', 'tempreceiver')
        ORDER BY username ASC
        """
    )


def desktop_user_choices():
    rows = desktop_eligible_users()
    choices = [
        {
            "value": desktop_member_token(row.get("id")),
            "label": str(row.get("username") or ""),
        }
        for row in rows
        if str(row.get("id") if row.get("id") is not None else "").strip()
    ]
    if guest_receiver_enabled():
        choices.append({"value": GUEST_MEMBER_TOKEN, "label": "Guest (logged-out)"})
    return choices


def group_member_available(member, endpoint_availability):
    token = str(member or "").strip()
    if not token:
        return False
    if token == GUEST_MEMBER_TOKEN:
        return guest_receiver_enabled()
    if is_desktop_member_token(token):
        return True
    if token in endpoint_availability:
        return bool(endpoint_availability.get(token))
    lowered = token.lower()
    if lowered != token and lowered in endpoint_availability:
        return bool(endpoint_availability.get(lowered))
    return False


def any_desktop_recipient_available():
    return bool(desktop_eligible_users())


def any_recipient_available(endpoint_availability):
    return any(bool(value) for value in (endpoint_availability or {}).values()) or any_desktop_recipient_available() or guest_receiver_enabled()


def endpoint_availability_map(endpoint_payload):
    availability = {}
    aliases = {}

    def add_alias(alias, value):
        token = str(alias or "").strip()
        if not token:
            return
        aliases.setdefault(token, []).append(bool(value))
        lowered = token.lower()
        if lowered != token:
            aliases.setdefault(lowered, []).append(bool(value))

    if not isinstance(endpoint_payload, dict):
        return availability
    for module_info in endpoint_payload.get("modules") or []:
        module_name = str(module_info.get("module") or "").strip()
        if not module_name:
            continue
        for endpoint in module_info.get("endpoints") or []:
            endpoint_id = str(endpoint.get("id") or "").strip()
            if endpoint_id:
                is_available = endpoint_is_available(endpoint)
                add_alias(f"{module_name}/{endpoint_id}", is_available)
                add_alias(endpoint_id, is_available)
                endpoint_name = str(endpoint.get("name") or "").strip()
                endpoint_address = str(endpoint.get("address") or "").strip()
                for extra in (endpoint_name, endpoint_address):
                    if extra:
                        add_alias(extra, is_available)
                        add_alias(f"{module_name}/{extra}", is_available)
    for token, statuses in aliases.items():
        if len(statuses) == 1 or all(status == statuses[0] for status in statuses):
            availability[token] = statuses[0]
    return availability


def all_group_ids_value(user=None):
    if all_recipients_disabled(settings()):
        return ""
    rows = query_all("SELECT id, owner_user_id FROM `groups` ORDER BY name ASC")
    rows = filter_group_rows_for_user(user, rows)
    ids = [str(row.get("id") or "").strip() for row in rows if str(row.get("id") or "").strip()]
    return ".".join(ids) if ids else "0"


def safe_module_name(value):
    return re.fullmatch(r"[A-Za-z0-9_-]+", str(value or "")) is not None


def load_endpoint_web(module):
    if not safe_module_name(module):
        abort(400)
    try:
        return endpoints.load_endpoint_web_module(module)
    except FileNotFoundError:
        abort(404)
    except Exception:
        abort(404)


def safe_load_endpoint_web_module(module_name, trusted=False):
    if not trusted:
        return None, ""
    try:
        return endpoints.load_endpoint_web_module(module_name, missing_ok=True), ""
    except Exception as exc:
        return None, str(exc)


def discovered_endpoint_modules():
    modules = {}
    for module_name, package in endpoints.discover_endpoint_packages(extract_if_trusted=True).items():
        manifest = package.get("manifest") or {}
        verification = package.get("verification") or {}
        trusted = bool(package.get("trusted"))
        web_mod, web_load_error = safe_load_endpoint_web_module(module_name, trusted=trusted)
        modules[module_name] = {
            "module": module_name,
            "name": manifest.get("name") or module_name,
            "description": manifest.get("description") or "",
            "developer": manifest.get("developer") or manifest.get("author") or "",
            "input_type": manifest.get("input_type") or manifest.get("type") or "Output",
            "version": manifest.get("version") or "",
            "minimum_ops_version": manifest.get("minimum_ops_version") or endpoints.OPS_VERSION,
            "requirements": manifest.get("requirements") or [],
            "trusted": trusted,
            "can_load": trusted,
            "input_capable": endpoints.module_type_has_input(manifest.get("input_type") or manifest.get("type") or "Output"),
            "output_capable": endpoints.module_type_has_output(manifest.get("input_type") or manifest.get("type") or "Output"),
            "signature_state": verification.get("signature_state") or "unsigned",
            "signature_label": verification.get("signature_label") or "",
            "signer": verification.get("organization") or "",
            "load_error": "" if trusted else package.get("load_error") or endpoints.UNSIGNED_ERROR,
            "web_load_error": web_load_error,
            "has_settings_page": bool(getattr(web_mod, "render_settings", None)) if web_mod else False,
            "has_forms": bool(getattr(web_mod, "forms", None)) if web_mod else False,
        }
    return dict(sorted(modules.items(), key=lambda item: (item[1]["name"].lower(), item[0].lower())))


def ensure_endpoint_module_state_table():
    endpoints.ensure_module_registry_table()


def endpoint_module_state_map(modules=None):
    modules = modules or discovered_endpoint_modules()
    ensure_endpoint_module_state_table()
    rows = query_all("SELECT `dir`, enabled FROM endpointmodulesloaded")
    states = {}
    for row in rows:
        module_name = str(row.get("dir") or "")
        if safe_module_name(module_name):
            states[module_name] = str(row.get("enabled") or "").strip().lower() == "true"
    if not rows:
        for module_name in modules:
            states[module_name] = True
    else:
        for module_name in modules:
            states.setdefault(module_name, False)
    return states


def builtin_endpoint_modules():
    sip_web_mod, sip_web_error = safe_load_endpoint_web_module("siptrunks", trusted=True)
    multicast_web_mod, multicast_web_error = safe_load_endpoint_web_module(endpoints.MULTICAST_RTP_MODULE, trusted=True)
    http_request_web_mod, http_request_web_error = safe_load_endpoint_web_module(endpoints.HTTP_REQUEST_MODULE, trusted=True)
    service_monitor_web_mod, service_monitor_web_error = safe_load_endpoint_web_module(endpoints.SERVICE_MONITOR_MODULE, trusted=True)
    return {
        "siptrunks": {
            "module": "siptrunks",
            "name": "SIP Trunks",
            "description": "Interconnect Open Paging Server with a VoIP-based PBX or ITSP",
            "developer": "Open Paging Server",
            "input_type": "Input+Output",
            "version": endpoints.OPS_VERSION,
            "enabled": True,
            "loaded": True,
            "trusted": True,
            "can_load": True,
            "system_builtin": True,
            "input_capable": True,
            "output_capable": True,
            "web_load_error": sip_web_error,
            "has_settings_page": False,
            "has_forms": bool(getattr(sip_web_mod, "forms", None)) if sip_web_mod else False,
        },
        endpoints.MULTICAST_RTP_MODULE: {
            "module": endpoints.MULTICAST_RTP_MODULE,
            "name": endpoints.MULTICAST_RTP_NAME,
            "description": endpoints.MULTICAST_RTP_DESCRIPTION,
            "developer": "Open Paging Server",
            "input_type": "Output",
            "version": endpoints.OPS_VERSION,
            "enabled": True,
            "loaded": True,
            "trusted": True,
            "can_load": True,
            "system_builtin": True,
            "input_capable": False,
            "output_capable": True,
            "web_load_error": multicast_web_error,
            "has_settings_page": False,
            "has_forms": bool(getattr(multicast_web_mod, "forms", None)) if multicast_web_mod else False,
        },
        endpoints.HTTP_REQUEST_MODULE: {
            "module": endpoints.HTTP_REQUEST_MODULE,
            "name": endpoints.HTTP_REQUEST_NAME,
            "description": endpoints.HTTP_REQUEST_DESCRIPTION,
            "developer": "Open Paging Server",
            "input_type": "Output",
            "version": endpoints.OPS_VERSION,
            "enabled": True,
            "loaded": True,
            "trusted": True,
            "can_load": True,
            "system_builtin": True,
            "input_capable": False,
            "output_capable": True,
            "web_load_error": http_request_web_error,
            "has_settings_page": False,
            "has_forms": bool(getattr(http_request_web_mod, "forms", None)) if http_request_web_mod else False,
        },
        endpoints.SERVICE_MONITOR_MODULE: {
            "module": endpoints.SERVICE_MONITOR_MODULE,
            "name": endpoints.SERVICE_MONITOR_NAME,
            "description": endpoints.SERVICE_MONITOR_DESCRIPTION,
            "developer": "Open Paging Server",
            "input_type": "Input",
            "version": endpoints.OPS_VERSION,
            "enabled": True,
            "loaded": True,
            "trusted": True,
            "can_load": True,
            "system_builtin": True,
            "input_capable": True,
            "output_capable": False,
            "web_load_error": service_monitor_web_error,
            "has_settings_page": False,
            "has_forms": bool(getattr(service_monitor_web_mod, "forms", None)) if service_monitor_web_mod else False,
        },
    }


def endpoint_module_catalog(include_system=False):
    local_modules = discovered_endpoint_modules()
    states = endpoint_module_state_map(local_modules)
    payload = endpoint_ipc("LIST_ENDPOINT_MODULES")
    modules = {}
    for module_name, module_info in local_modules.items():
        merged = dict(module_info)
        merged["enabled"] = bool(states.get(module_name))
        merged["loaded"] = False
        modules[module_name] = merged
    if isinstance(payload, dict):
        for module_info in payload.get("modules") or []:
            module_name = str(module_info.get("module") or "")
            if not safe_module_name(module_name):
                continue
            merged = dict(modules.get(module_name) or {})
            merged.update(module_info)
            if module_name in local_modules:
                merged["has_settings_page"] = local_modules[module_name]["has_settings_page"]
                merged["has_forms"] = local_modules[module_name]["has_forms"]
                merged["name"] = merged.get("name") or local_modules[module_name]["name"]
                merged["description"] = merged.get("description") or local_modules[module_name]["description"]
                merged["version"] = merged.get("version") or local_modules[module_name]["version"]
            merged["module"] = module_name
            merged["enabled"] = bool(merged.get("enabled", states.get(module_name)))
            merged["loaded"] = bool(merged.get("loaded"))
            modules[module_name] = merged
    if include_system:
        modules.update(builtin_endpoint_modules())
    return dict(sorted(modules.items(), key=lambda item: (str(item[1].get("name") or item[0]).lower(), item[0].lower())))


@app.errorhandler(403)
def forbidden(_exc):
    return render_error_document("403.html", 403)


@app.errorhandler(404)
def not_found(_exc):
    return render_error_document("404.html", 404)


@app.errorhandler(500)
def internal_error(exc):
    return render_error_document("500.html", 500, exc)


@app.route("/__traceback__/<trace_id>")
def traceback_view(trace_id):
    if not APP_DEBUG:
        abort(404)
    trace_text = TRACEBACKS.get(str(trace_id or ""))
    if not trace_text:
        abort(404)
    return Response(trace_text, mimetype="text/plain")


@app.after_request
def apply_search_index_headers(response):
    if not ALLOW_SEARCH_INDEX and request.path != "/robots.txt":
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


@app.route("/robots.txt")
def robots_txt():
    body = "User-agent: *\nAllow: /\n" if ALLOW_SEARCH_INDEX else "User-agent: *\nDisallow: /\n"
    response = Response(body, mimetype="text/plain")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/assets/<path:filename>")
def bundled_asset(filename):
    safe_path = (WEB_STATIC_DIR / filename).resolve()
    root = WEB_STATIC_DIR.resolve()
    if root not in safe_path.parents and safe_path != root:
        abort(404)
    if not safe_path.is_file():
        abort(404)
    response = send_from_directory(WEB_STATIC_DIR, filename)
    response.headers["Cache-Control"] = "public, max-age=3600, stale-while-revalidate=86400"
    return response


@app.route("/", methods=["GET", "POST"])
@alias("/index", methods=["GET", "POST"])
def index_root():
    if session.get("user_id") not in (None, ""):
        return redirect("/dashboard")
    if guest_receiver_enabled():
        return redirect("/dashboard")
    return redirect("/login")


@alias("/login", methods=["GET", "POST"])
def login():
    return dispatch_web_page("index")


@alias("/login/basic-captcha.svg")
def login_basic_captcha():
    return dispatch_web_page("login-captcha")


@alias("/logout")
def logout():
    return dispatch_web_page("logout")


@alias("/login/sso/start")
def login_sso_start():
    config = identity_provider_settings()
    provider = configured_identity_provider(config)
    desktop_sso_request_id = str(session.get(DESKTOP_SSO_SESSION_KEY) or "").strip()
    if provider not in REDIRECT_IDENTITY_PROVIDER_VALUES:
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, "SSO is not enabled.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message="SSO is not enabled.")
        return redirect("/login")
    if not desktop_sso_request_id:
        now_value = time.time()
        recent_starts = [
            float(ts)
            for ts in (session.get("sso_start_times") or [])
            if isinstance(ts, (int, float, str)) and str(ts).replace(".", "", 1).isdigit() and now_value - float(ts) < 20
        ]
        recent_starts.append(now_value)
        session["sso_start_times"] = recent_starts
        if len(recent_starts) >= 3:
            session.pop("sso_start_times", None)
            set_sso_error_detail(
                "The login page kept redirecting to the identity provider without completing. "
                "Please try again."
            )
            increment_sso_failure_count()
            return redirect("/login?sso_error=failed")
    try:
        if provider == "oidc":
            client = build_oidc_client(config)
            redirect_uri = request.url_root.rstrip("/") + "/login/oidc/callback"
            return client.authorize_redirect(redirect_uri, prompt="login")
        auth = build_saml_auth(config)
        return redirect(auth.login(return_to=request.url_root.rstrip("/") + "/", force_authn=True))
    except Exception as exc:
        set_sso_error_detail(exc)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, exc)
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=str(exc))
        increment_sso_failure_count()
        return redirect("/login?sso_error=failed")


@alias("/login/oidc/callback")
def login_oidc_callback():
    config = identity_provider_settings()
    desktop_sso_request_id = str(session.get(DESKTOP_SSO_SESSION_KEY) or "").strip()
    if configured_identity_provider(config) != "oidc":
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, "OIDC is not enabled.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message="OIDC is not enabled.")
        return redirect("/login")
    if request.args.get("error"):
        error_code = str(request.args.get("error") or "").strip()
        error_description = str(request.args.get("error_description") or "").strip()
        set_sso_error_detail(error_description or error_code)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, error_description or error_code or "OIDC login was cancelled.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=error_description or error_code or "Login cancelled.")
        if error_code == "access_denied":
            return redirect("/login?sso_error=cancelled")
        increment_sso_failure_count()
        return redirect("/login?sso_error=failed")
    try:
        client = build_oidc_client(config)
        token = client.authorize_access_token()
        identity_result = oidc_identity_result(config, token)
        user = sync_external_user_record("oidc", config, identity_result)
        if not user:
            raise RuntimeError("Unable to complete OIDC login.")
        clear_sso_failure_state()
        if desktop_sso_request_id:
            if user_requires_password_change(user, "oidc"):
                raise RuntimeError("Password change required through the web interface.")
            if not complete_desktop_sso_request(desktop_sso_request_id, user, "oidc"):
                raise RuntimeError("The desktop login request expired. Start SSO again from the desktop app.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=True)
        begin_web_login_session(user, "oidc")
        return redirect(post_login_redirect_target(user, "oidc"))
    except IdentityAccessDenied as exc:
        set_sso_error_detail(exc)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, exc)
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=str(exc))
        return redirect("/login?sso_error=denied")
    except Exception as exc:
        set_sso_error_detail(exc)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, exc)
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=str(exc))
        increment_sso_failure_count()
        return redirect("/login?sso_error=failed")


@alias("/login/saml/callback", methods=["GET", "POST"])
def login_saml_callback():
    config = identity_provider_settings()
    desktop_sso_request_id = str(session.get(DESKTOP_SSO_SESSION_KEY) or "").strip()
    if configured_identity_provider(config) != "saml":
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, "SAML is not enabled.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message="SAML is not enabled.")
        return redirect("/login")
    if request.values.get("error"):
        error_code = str(request.values.get("error") or "").strip()
        error_description = str(request.values.get("error_description") or "").strip()
        set_sso_error_detail(error_description or error_code)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, error_description or error_code or "SAML login was cancelled.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=error_description or error_code or "Login cancelled.")
        if error_code == "access_denied":
            return redirect("/login?sso_error=cancelled")
        increment_sso_failure_count()
        return redirect("/login?sso_error=failed")
    try:
        auth = build_saml_auth(config)
        auth.process_response()
        if auth.get_errors() or not auth.is_authenticated():
            raise RuntimeError("Unable to complete SAML login.")
        identity_result = saml_identity_result(config, auth)
        user = sync_external_user_record("saml", config, identity_result)
        if not user:
            raise RuntimeError("Unable to complete SAML login.")
        clear_sso_failure_state()
        if desktop_sso_request_id:
            if user_requires_password_change(user, "saml"):
                raise RuntimeError("Password change required through the web interface.")
            if not complete_desktop_sso_request(desktop_sso_request_id, user, "saml"):
                raise RuntimeError("The desktop login request expired. Start SSO again from the desktop app.")
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=True)
        begin_web_login_session(user, "saml")
        return redirect(post_login_redirect_target(user, "saml"))
    except IdentityAccessDenied as exc:
        set_sso_error_detail(exc)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, exc)
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=str(exc))
        return redirect("/login?sso_error=denied")
    except Exception as exc:
        set_sso_error_detail(exc)
        if desktop_sso_request_id:
            fail_desktop_sso_request(desktop_sso_request_id, exc)
            session.pop(DESKTOP_SSO_SESSION_KEY, None)
            return desktop_sso_finish_redirect(desktop_sso_request_id, ok=False, message=str(exc))
        increment_sso_failure_count()
        return redirect("/login?sso_error=failed")


@alias("/login/saml/metadata")
def login_saml_metadata():
    config = identity_provider_settings()
    try:
        auth = build_saml_auth(config)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        if errors:
            return Response("\n".join(errors), status=500, mimetype="text/plain")
        return Response(metadata, mimetype="application/samlmetadata+xml")
    except Exception as exc:
        return Response(str(exc), status=500, mimetype="text/plain")


@alias("/demo-mode-maintenance", methods=["GET", "POST"])
def demo_mode_maintenance():
    return dispatch_web_page("demo-mode-maintenance")


def desktop_authorized_user():
    auth_header = str(request.headers.get("Authorization") or "")
    token = auth_header.split(" ", 1)[1].strip() if auth_header.lower().startswith("bearer ") else ""
    if not token:
        token = str(request.args.get("token") or "").strip()
    return verify_desktop_token(token)


def require_desktop_client():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    user = desktop_authorized_user()
    if not user:
        return jsonify(error="Unauthorized"), 401
    return user


def desktop_user_session_id(user):
    sid = str((user or {}).get("desktop_session_id") or (user or {}).get("session_id") or "").strip()
    return sid if sid and len(sid) <= 128 else ""


def desktop_session_soft_required(user):
    sid = desktop_user_session_id(user)
    uid = (user or {}).get("id")
    if not sid or uid in (None, "", GUEST_MEMBER_TOKEN):
        return False
    return session_soft_logged_out(active_user_session_record(sid, uid))


def desktop_user_with_session(user, session_id):
    result = dict(user or {})
    sid = str(session_id or "").strip()
    if sid:
        result["desktop_session_id"] = sid
    return result


def desktop_guest_session_active():
    return bool(session.get(DESKTOP_GUEST_SESSION_KEY))


def ensure_desktop_guest_session():
    current_session_id = str(session.get("web_session_id") or "").strip()
    current_user_id = session.get("user_id")
    if current_session_id and current_user_id not in (None, "", GUEST_MEMBER_TOKEN):
        revoke_user_session_record(current_session_id, current_user_id)
    if current_session_id or current_user_id not in (None, "", GUEST_MEMBER_TOKEN) or not desktop_guest_session_active() or not bool(session.get("desktop_client")):
        session.clear()
    session["desktop_client"] = True
    session[DESKTOP_GUEST_SESSION_KEY] = True


def set_desktop_guest_session(active):
    if active:
        session["desktop_client"] = True
        session[DESKTOP_GUEST_SESSION_KEY] = True
    else:
        session.pop(DESKTOP_GUEST_SESSION_KEY, None)


def desktop_login_user_agent():
    client_os = str(request.headers.get("X-OPS-Client-OS") or "").strip()
    return f"OpenPagingServer Desktop Client/1.0 ({client_os})" if client_os else "OpenPagingServer Desktop Client/1.0"


def desktop_session_json(user, session_id=None, include_refresh=True, token_ttl=None, refresh_ttl=None, extra=None):
    session_user = desktop_user_with_session(user, session_id or desktop_user_session_id(user))
    token, expires_at = build_desktop_token(session_user, ttl_seconds=token_ttl, session_id=desktop_user_session_id(session_user))
    body = {
        "token": token,
        "expires_at": expires_at,
        "websocket_path": "/desktop/ws",
        "keepalive_path": "/desktop/session/ping",
        "product_name": desktop_product_name(),
        "user": {"id": session_user.get("id"), "username": session_user.get("username"), "role": session_user.get("role")},
        "groups": desktop_groups_for_user(session_user.get("id")),
        "reauth_required": desktop_session_soft_required(session_user),
    }
    if include_refresh:
        refresh_token, refresh_expires_at = build_desktop_refresh_token(session_user, ttl_seconds=refresh_ttl, session_id=desktop_user_session_id(session_user))
        body["refresh_token"] = refresh_token
        body["refresh_expires_at"] = refresh_expires_at
    if isinstance(extra, dict):
        body.update(extra)
    return jsonify(body)


def bind_desktop_web_session(user, auth_provider="local", session_id=None):
    sid = str(session_id or desktop_user_session_id(user)).strip()
    if not sid:
        return False
    record = active_user_session_record(sid, (user or {}).get("id"))
    if not record:
        return False
    was_desktop_client = bool(session.get("desktop_client"))
    now_value = str(time.time())
    session.clear()
    if was_desktop_client:
        session["desktop_client"] = True
        session.permanent = True
    session.pop(DESKTOP_GUEST_SESSION_KEY, None)
    session["user_id"] = (user or {}).get("id")
    session["username"] = (user or {}).get("username")
    session["auth_provider"] = str(auth_provider or (user or {}).get("auth_provider") or record.get("auth_provider") or "local")
    session["web_session_id"] = sid
    session["web_session_touched_at"] = now_value
    session["external_identity_checked_at"] = now_value
    session["full_activity_touched_at"] = now_value
    touch_user_session_record(sid)
    touch_full_activity(sid)
    return True


@alias("/desktop/sso/start", methods=["POST"])
def desktop_sso_start():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    config = identity_provider_settings()
    provider = configured_identity_provider(config)
    if provider not in REDIRECT_IDENTITY_PROVIDER_VALUES:
        return jsonify(error="SSO is not enabled."), 404
    request_id, request_secret, expires_at = create_desktop_sso_request()
    browser_url = request.url_root.rstrip("/") + "/desktop/sso/browser/" + request_id
    return jsonify(
        ok=True,
        provider=provider,
        request_id=request_id,
        request_secret=request_secret,
        expires_at=db_datetime_value(expires_at),
        expires_in=DESKTOP_SSO_REQUEST_TTL_SECONDS,
        browser_url=browser_url,
        poll_path="/desktop/sso/poll",
    )


@alias("/desktop/sso/browser/<request_id>")
def desktop_sso_browser(request_id):
    wanted = str(request_id or "").strip()
    if not desktop_sso_request_pending(wanted):
        return desktop_sso_finish_redirect(wanted, ok=False, message="The desktop login request expired. Start SSO again from the desktop app.")
    session[DESKTOP_SSO_SESSION_KEY] = wanted
    session["desktop_sso_started_at"] = str(time.time())
    return redirect("/login/sso/start")


@alias("/desktop/sso/poll", methods=["GET", "POST"])
def desktop_sso_poll():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    payload = request.get_json(silent=True) or request.values.to_dict()
    request_id = str(payload.get("request_id") or "").strip()
    request_secret = str(payload.get("request_secret") or payload.get("secret") or "").strip()
    if not request_id or not request_secret:
        return jsonify(error="Desktop SSO request ID and secret are required."), 400
    record = desktop_sso_request_record(request_id)
    if not record:
        return jsonify(status="expired", error="The desktop login request expired."), 410
    expected = str(record.get("secret_hash") or "")
    actual = desktop_sso_secret_hash(request_id, request_secret)
    if not hmac.compare_digest(expected, actual):
        return jsonify(error="Unauthorized"), 401
    expires_at = _session_datetime(record.get("expires_at"))
    if not expires_at or expires_at <= datetime.now():
        return jsonify(status="expired", error="The desktop login request expired."), 410
    status = str(record.get("status") or "pending").strip().lower()
    if status == "pending":
        response = jsonify(status="pending")
        response.status_code = 202
        return response
    if status == "failed":
        return jsonify(status="failed", error=str(record.get("error") or "Desktop SSO failed.")), 401
    if status == "consumed":
        return jsonify(status="consumed", error="This desktop login request was already used."), 410
    if status != "complete":
        return jsonify(status=status or "unknown", error="The desktop login request is not ready."), 409
    user_id = record.get("user_id")
    user = query_one("SELECT id, username, role, email, accountexpire, loginsleft, auth_provider FROM users WHERE id=%s LIMIT 1", (user_id,))
    if not user:
        return jsonify(error="Unauthorized"), 401
    if user_requires_password_change(user, record.get("auth_provider")):
        return jsonify(error="Password change required through the web interface."), 403
    execute(
        "UPDATE desktop_sso_requests SET status='consumed', consumed_at=NOW() WHERE request_id=%s AND status='complete'",
        (request_id,),
    )
    auth_provider = str(record.get("auth_provider") or user.get("auth_provider") or "local")
    session_id = register_login_session(
        user,
        auth_provider=auth_provider,
        session_type="desktop",
        ip_address=client_ip(),
        user_agent=desktop_sso_poll_user_agent(),
    )
    return desktop_session_json(user, session_id=session_id, extra={"status": "complete"})


@alias(DESKTOP_SSO_COMPLETE_ROUTE)
def desktop_sso_complete():
    status = str(request.args.get("status") or "").strip().lower()
    message = str(request.args.get("message") or "").strip()
    ok = status == "ok"
    try:
        ctx = product_context()
        data = ctx["settings"]
    except Exception:
        data = {}
    product_name = str(data.get("product_name") or "Open Paging Server")
    favicon = str(data.get("favicon") or "")
    separate_dark_logo = truthy(data.get("separate_dark_logo"))
    enable_login_logo = truthy(data.get("enable_login_logo"))
    login_logo_light = str(data.get("login_logo_light") or "")
    login_logo_dark = str(data.get("login_logo_dark") or "")
    banner_enabled = truthy(data.get("login_banner_enabled"))
    banner_title = str(data.get("login_banner_title") or "")
    banner_message = str(data.get("login_banner_message") or "")
    title = "Login complete" if ok else "Login failed"
    detail = "You may now close this window and return to the app." if ok else (message or "Please return to the app and try again. If this issue persists, please contact your system administrator.")
    favicon_html = f'<link rel="icon" href="{h(favicon)}" type="image/x-icon">' if favicon else ""
    dark_logo_css = ".logo-light { display: none; }\n        .logo-dark { display: block; }" if separate_dark_logo else ""
    logo_html = ""
    if enable_login_logo:
        if separate_dark_logo:
            logo_html = f"""
    <div class="logo">
        <img src="{h(login_logo_light)}" alt="{h(product_name)} logo" class="logo-light" />
        <img src="{h(login_logo_dark)}" alt="{h(product_name)} logo" class="logo-dark" />
    </div>"""
        else:
            logo_html = f"""
    <div class="logo">
        <img src="{h(login_logo_light)}" alt="{h(product_name)} logo" />
    </div>"""
    banner_html = ""
    if banner_enabled and (banner_title or banner_message):
        title_html = f"<h3>{h(banner_title)}</h3>" if banner_title else ""
        message_html = f"<p>{h(banner_message).replace(chr(10), '<br>')}</p>" if banner_message else ""
        banner_html = f"""
        <div class="login-banner">
          {title_html}
          {message_html}
        </div>"""
    demo_mode_html = ""
    if demo_mode_active():
        demo_mode_html = """
        <div class="demo-mode-login">
          <i class="fa-solid fa-bag-shopping"></i>
          <span>Demo Mode</span>
        </div>"""
    icon_class = "fa-circle-check" if ok else "fa-circle-xmark"
    state_class = "success" if ok else "error"
    body = f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{h(title)} - {h(product_name)}</title>
    {favicon_html}
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"/>
    <style>
      *, *::before, *::after {{ box-sizing: border-box; }}
      body, html {{ margin: 0; padding: 0; font-family: "Tahoma", sans-serif; height: 100%; width: 100%; position: fixed; display: flex; align-items: center; justify-content: center; background: #e3f2fd; overflow-x: hidden; }}
      @keyframes fadeInPage {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
      .background-slideshow {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; }}
      @media (max-width: 768px) {{ .background-slideshow {{ display: none; }} }}
      .center-container {{ display: flex; flex-direction: column; justify-content: center; align-items: center; width: 100%; height: 100%; position: relative; z-index: 1; }}
      .logo {{ position: fixed; top: 20px; left: 50%; transform: translateX(-50%); z-index: 2; width: 830px; height: 97px; display: flex; justify-content: center; align-items: center; }}
      .logo img {{ max-width: 100%; max-height: 100%; object-fit: contain; }}
      .logo-light {{ display: block; }}
      .logo-dark {{ display: none; }}
      @media (max-width: 768px) {{ .logo {{ position: relative; top: auto; left: auto; transform: none; width: min(82vw, 360px); height: auto; margin: 18px auto 12px auto; padding: 0; flex: 0 0 auto; }} .logo img {{ width: 100%; height: auto; max-height: 110px; }} }}
      @media (min-width: 769px) {{ .logo.logo-corner {{ top: 16px; left: 16px; transform: none; width: min(320px, 34vw); height: auto; justify-content: flex-start; }} .logo.logo-corner img {{ width: 100%; height: auto; max-height: 70px; object-fit: contain; object-position: left center; }} }}
      .login-banner {{ background: #fff3e0; border: 1px solid #ffe0b2; border-radius: 6px; padding: 15px; margin-bottom: 15px; width: 100%; max-width: 390px; box-sizing: border-box; text-align: left; color: #e65100; box-shadow: 0 2px 4px rgba(0,0,0,0.05); animation: fadeInPage 1s ease-in-out; }}
      .login-banner h3 {{ margin: 0 0 5px 0; font-size: 15px; font-weight: 700; text-transform: uppercase; }}
      .login-banner p {{ margin: 0; font-size: 14px; line-height: 1.4; }}
      .login-box {{ background: #fff; padding: 30px; border-radius: 6px; box-shadow: 0 4px 6px rgba(0,0,0,0.1),0 1px 3px rgba(0,0,0,0.08); max-width: 390px; width: min(92vw, 390px); text-align: center; animation: fadeInPage 1.5s ease-in-out; }}
      .login-box h2 {{ color: var(--ops-accent); font-weight: 500; margin-bottom: 14px; margin-top: 0; }}
      .sso-status-icon {{ font-size: 44px; margin-bottom: 14px; }}
      .sso-status-icon.success {{ color: #2e7d32; }}
      .sso-status-icon.error {{ color: #c62828; }}
      .sso-status-message {{ color: #555; font-size: 0.94em; line-height: 1.45; margin: 0; overflow-wrap: anywhere; }}
      .demo-mode-login {{ position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%); z-index: 2; color: #000; font-size: 0.95em; display: flex; align-items: center; justify-content: center; gap: 8px; }}
      @media (max-width: 768px) {{
        body, html {{ position: static; height: auto; min-height: 100%; display: block; }}
        body {{ background: #fff; min-height: 100vh; overflow-y: auto; }}
        .center-container {{ width: 100%; height: auto; min-height: auto; padding: 0 16px 24px 16px; align-items: center; justify-content: flex-start; }}
        .login-box {{ max-width: 360px; width: 100%; height: auto; border-radius: 6px; padding: 22px; }}
        .login-banner {{ max-width: 360px; width: 100%; border-radius: 4px; }}
        .demo-mode-login {{ position: static; transform: none; margin: 16px 0 10px 0; }}
      }}
      @media (prefers-color-scheme: dark) {{
        body, html {{ background: #121212; color: #fff; }}
        .login-banner {{ background: #3e2723; border: 1px solid #5d4037; color: #ffb74d; }}
        .login-box {{ background: #1e1e1e; box-shadow: 0 4px 6px rgba(0,0,0,0.6); }}
        .login-box h2 {{ color: #fff; }}
        .sso-status-icon.success {{ color: #81c784; }}
        .sso-status-icon.error {{ color: #ef9a9a; }}
        .sso-status-message {{ color: #bbb; }}
        .demo-mode-login {{ color: #fff; }}
        {dark_logo_css}
      }}
      @media (prefers-color-scheme: dark) and (max-width: 768px) {{ body {{ background: #121212; }} }}
    </style>
  <link rel="stylesheet" href="/assets/theme.css"></head>
  <body>
    <div class="background-slideshow"></div>
    {logo_html}
    <div class="center-container">
      {banner_html}
      <div class="login-box">
        <div class="sso-status-icon {state_class}"><i class="fa-solid {icon_class}"></i></div>
        <h2>{h(title)}</h2>
        <p class="sso-status-message">{h(detail)}</p>
      </div>
      {demo_mode_html}
    </div>
    <script>
      function rectsOverlap(a, b) {{
        return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
      }}
      function adjustLogoPosition() {{
        const logo = document.querySelector('.logo');
        if (!logo) return;
        if (window.innerWidth <= 768) {{
          logo.classList.remove('logo-corner');
          return;
        }}
        logo.classList.remove('logo-corner');
        requestAnimationFrame(() => {{
          const logoRect = logo.getBoundingClientRect();
          const targets = Array.from(document.querySelectorAll('.login-banner, .login-box'));
          const horizontallyClipped = logoRect.left < 8 || logoRect.right > window.innerWidth - 8;
          const overlaps = targets.some((target) => rectsOverlap(logoRect, target.getBoundingClientRect()));
          if (horizontallyClipped || overlaps) logo.classList.add('logo-corner');
        }});
      }}
      window.addEventListener('load', adjustLogoPosition);
      window.addEventListener('resize', adjustLogoPosition);
      document.addEventListener('DOMContentLoaded', adjustLogoPosition);
      Array.from(document.images).forEach((img) => img.addEventListener('load', adjustLogoPosition));
    </script>
  </body>
</html>"""
    return Response(body, mimetype="text/html")


@alias("/desktop/session/login", methods=["POST"])
def desktop_session_login():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    payload = request.get_json(silent=True) or request.form.to_dict()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    if not username or not password:
        return jsonify(error="Username and password are required."), 400
    result = authenticate_user_credentials(username, password)
    user = result.get("user") if result.get("ok") else None
    if not user:
        return jsonify(error="Invalid username or password."), 401
    if user_requires_password_change(user, result.get("provider")):
        return jsonify(error="Password change required through the web interface."), 403
    auth_provider = str(result.get("provider") or user.get("auth_provider") or "local")
    session_id = register_login_session(
        user,
        auth_provider=auth_provider,
        session_type="desktop",
        ip_address=client_ip(),
        user_agent=desktop_login_user_agent(),
    )
    session["desktop_client"] = True
    bind_desktop_web_session(user, auth_provider=auth_provider, session_id=session_id)
    set_desktop_guest_session(False)
    return desktop_session_json(user, session_id=session_id)


@alias("/desktop/session/guest", methods=["POST"])
def desktop_session_guest():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    if not guest_receiver_enabled():
        return jsonify(error="Guest receiver is not enabled."), 403
    guest = {"id": GUEST_MEMBER_TOKEN, "username": "Guest", "role": "guest"}
    ensure_desktop_guest_session()
    return desktop_session_json(guest, token_ttl=GUEST_TOKEN_TTL_SECONDS, refresh_ttl=GUEST_TOKEN_TTL_SECONDS)


@alias("/desktop/session/token", methods=["GET", "POST"])
def desktop_session_token():
    if not desktop_client_context():
        return jsonify(error="Desktop client context required"), 400
    user = current_user()
    if not isinstance(user, dict) or not user:
        return jsonify(error="Not logged in"), 401
    web_session_id = str(session.get("web_session_id") or "").strip()
    if web_session_id:
        execute(
            "UPDATE user_sessions SET session_type='desktop', user_agent=%s, last_seen_at=NOW() WHERE session_id=%s",
            (desktop_login_user_agent(), web_session_id),
        )
        now_value = str(time.time())
        session["desktop_client"] = True
        session["web_session_touched_at"] = now_value
    set_desktop_guest_session(False)
    return desktop_session_json(user, session_id=web_session_id)


@alias("/desktop/session/web-login", methods=["POST"])
def desktop_session_web_login():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    user = desktop_authorized_user()
    if not isinstance(user, dict) or not user:
        return jsonify(error="Unauthorized"), 401
    role = str(user.get("role") or "").strip().lower()
    if role == "guest":
        ensure_desktop_guest_session()
        return jsonify(ok=True, guest=True, user={"id": GUEST_MEMBER_TOKEN, "username": "Guest", "role": "guest"})
    user_id = user.get("id")
    full_user = query_one(
        "SELECT id, username, role, auth_provider FROM users WHERE id=%s LIMIT 1",
        (user_id,),
    )
    if not full_user:
        return jsonify(error="Unauthorized"), 401
    if not bind_desktop_web_session(full_user, auth_provider=str(full_user.get("auth_provider") or "local"), session_id=desktop_user_session_id(user)):
        return jsonify(error="Unauthorized"), 401
    session["desktop_client"] = True
    set_desktop_guest_session(False)
    return jsonify(
        ok=True,
        guest=False,
        reauth_required=desktop_session_soft_required(user),
        user={"id": full_user.get("id"), "username": full_user.get("username"), "role": full_user.get("role")},
    )


@alias("/desktop/session/refresh", methods=["POST"])
def desktop_session_refresh():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    payload = request.get_json(silent=True) or request.form.to_dict()
    refresh_token = str(payload.get("refresh_token") or "").strip()
    user = verify_desktop_refresh_token(refresh_token)
    if not isinstance(user, dict) or not user:
        return jsonify(error="Unauthorized"), 401
    sid = desktop_user_session_id(user)
    if sid:
        touch_user_session_record(sid)
    session["desktop_client"] = True
    if str(user.get("role") or "").strip().lower() == "guest":
        ensure_desktop_guest_session()
    else:
        bind_desktop_web_session(
            user,
            auth_provider=str(user.get("auth_provider") or "local"),
            session_id=sid,
        )
        set_desktop_guest_session(False)
    return desktop_session_json(user, session_id=sid)


@alias("/desktop/session/logout", methods=["POST"])
def desktop_session_logout():
    if not str(request.headers.get(DESKTOP_CLIENT_HEADER) or "").strip():
        return jsonify(error="Desktop client header required"), 400
    payload = request.get_json(silent=True) or request.form.to_dict()
    refresh_token = str(payload.get("refresh_token") or "").strip()
    user = desktop_authorized_user()
    if not isinstance(user, dict) or not user:
        user = verify_desktop_refresh_token(refresh_token)
    sid = desktop_user_session_id(user) if isinstance(user, dict) else ""
    uid = (user or {}).get("id") if isinstance(user, dict) else None
    if sid and uid not in (None, "", GUEST_MEMBER_TOKEN):
        revoke_user_session_record(sid, uid)
    web_session_id = str(session.get("web_session_id") or "").strip()
    web_user_id = session.get("user_id")
    if web_session_id and web_session_id != sid:
        revoke_user_session_record(web_session_id, web_user_id)
    session.clear()
    response = jsonify(ok=True, guest_receiver_enabled=guest_receiver_enabled())
    response.headers["Cache-Control"] = "no-store"
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return response


@alias("/desktop/app-settings", methods=["GET"])
def desktop_app_settings_placeholder():
    return redirect("/dashboard")


@alias("/desktop/server-info", methods=["GET"])
def desktop_server_info():
    config = identity_provider_settings()
    provider = configured_identity_provider(config)
    if provider not in REDIRECT_IDENTITY_PROVIDER_VALUES:
        provider = ""
    return jsonify(
        product_name=desktop_product_name(),
        guest_receiver_enabled=guest_receiver_enabled(),
        websocket_path="/desktop/ws",
        keepalive_path="/desktop/session/ping",
        sso_provider=provider or "",
        sso_start_path="/login/sso/start" if provider else "",
        desktop_sso_start_path="/desktop/sso/start" if provider else "",
        desktop_sso_poll_path="/desktop/sso/poll" if provider else "",
        sso_auto_redirect=bool(provider and identity_redirect_auto_enabled(config)),
    )


@alias("/desktop/session/ping", methods=["GET", "OPTIONS"])
def desktop_session_ping():
    user = require_desktop_client()
    if not isinstance(user, dict):
        return user
    sid = desktop_user_session_id(user)
    if sid:
        touch_user_session_record(sid)
    if str(user.get("role") or "").strip().lower() == "guest":
        ensure_desktop_guest_session()
    else:
        set_desktop_guest_session(False)
    response = jsonify(
        ok=True,
        product_name=desktop_product_name(),
        server_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        reauth_required=desktop_session_soft_required(user),
        user={"id": user.get("id"), "username": user.get("username"), "role": user.get("role")},
        groups=desktop_groups_for_user(user.get("id")),
    )
    response.status_code = 200
    return response


@alias("/desktop/broadcasts/<broadcast_id>/audio")
def desktop_broadcast_audio(broadcast_id):
    user = require_desktop_client()
    if not isinstance(user, dict):
        return user
    broadcast = fetch_active_broadcast(broadcast_id)
    if not broadcast:
        abort(404)
    if not user_in_broadcast(user.get("id"), broadcast):
        abort(403)
    recording_path = str(broadcast.get("runtime_recording") or "").strip()
    if recording_path:
        recording_file = Path(recording_path)
        if recording_file.is_file():
            return send_file(recording_file, as_attachment=False, conditional=True)
    audio_name = first_audio_name(broadcast)
    if not audio_name:
        abort(404)
    return send_file(asset_path(audio_name), as_attachment=False, conditional=True)


@alias("/desktop/broadcasts/<broadcast_id>/icon")
def desktop_broadcast_icon(broadcast_id):
    user = require_desktop_client()
    if not isinstance(user, dict):
        return user
    broadcast = fetch_active_broadcast(broadcast_id)
    if not broadcast:
        abort(404)
    if not user_in_broadcast(user.get("id"), broadcast):
        abort(403)
    icon_name = str(broadcast.get("icon") or "").strip()
    if not icon_name:
        abort(404)
    return send_file(asset_path(icon_name), as_attachment=False, conditional=True)


@alias("/dashboard")
def dashboard():
    return dispatch_web_page("dashboard")


def dashboard_authorized_user_id():
    user = current_user()
    if isinstance(user, dict) and user:
        return user.get("id"), user
    if desktop_guest_session_active() and guest_receiver_enabled():
        return GUEST_MEMBER_TOKEN, {"id": GUEST_MEMBER_TOKEN, "username": "Guest", "role": "guest"}
    return None, None


@alias("/dashboard/ws-session", methods=["GET"])
def dashboard_ws_session():
    user_id, user = dashboard_authorized_user_id()
    if user_id is None:
        abort(403)
    ttl = GUEST_TOKEN_TTL_SECONDS if str(user.get("role") or "") == "guest" else None
    session_id = "" if str(user.get("role") or "").strip().lower() == "guest" else str(session.get("web_session_id") or "").strip()
    token, expires_at = build_desktop_token(user, ttl_seconds=ttl, session_id=session_id)
    return jsonify(
        token=token,
        expires_at=expires_at,
        websocket_path="/desktop/ws",
        product_name=desktop_product_name(),
        reauth_required=desktop_session_soft_required(desktop_user_with_session(user, session_id)),
        user={"id": user.get("id"), "username": user.get("username"), "role": user.get("role")},
        groups=desktop_groups_for_user(user.get("id")),
    )


@alias("/dashboard/broadcast-icon")
def dashboard_broadcast_icon():
    user_id, _user = dashboard_authorized_user_id()
    if user_id is None:
        abort(403)
    broadcast = fetch_active_broadcast(request.args.get("bid") or "")
    if not broadcast:
        abort(404)
    if not user_in_broadcast(user_id, broadcast):
        abort(403)
    icon_name = str(broadcast.get("icon") or "").strip()
    if not icon_name:
        abort(404)
    return send_file(asset_path(icon_name), as_attachment=False, conditional=True)


@alias("/dashboard/broadcast-audio")
def dashboard_broadcast_audio():
    user_id, _user = dashboard_authorized_user_id()
    if user_id is None:
        abort(403)
    broadcast = fetch_active_broadcast(request.args.get("bid") or "")
    if not broadcast:
        abort(404)
    if not user_in_broadcast(user_id, broadcast):
        abort(403)
    recording_path = str(broadcast.get("runtime_recording") or "").strip()
    if recording_path:
        recording_file = Path(recording_path)
        if recording_file.is_file():
            return send_file(recording_file, as_attachment=False, conditional=True)
    audio_name = first_audio_name(broadcast)
    if not audio_name:
        abort(404)
    return send_file(asset_path(audio_name), as_attachment=False, conditional=True)


@app.route("/oobe/", methods=["GET", "POST"])
@alias("/oobe/index", methods=["GET", "POST"])
def oobe():
    return dispatch_web_page("oobe/index")


@app.route("/history/")
@alias("/history/index")
def history():
    return dispatch_web_page("history/index")


def audio_files():
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    return sorted([p.name for p in ASSET_DIR.iterdir() if p.is_file() and p.suffix.lower() in {".wav", ".mp3", ".ogg"}], key=str.lower)


def next_message_id():
    rows = query_all("SELECT messageid FROM messages ORDER BY messageid ASC")
    used = {int(row["messageid"]) for row in rows if row.get("messageid") is not None}
    candidate = 1
    while candidate in used:
        candidate += 1
    return candidate


def message_fields(values=None):
    values = values or {}
    afiles = [("", "None")] + [(name, name) for name in audio_files()]
    return [
        ("name", "Name", "text", None),
        ("type", "Type", "select", [("text", "Text"), ("audio", "Audio"), ("text+audio", "Text + Audio"), ("liveaudio", "Live Page"), ("liveaudio+text", "Live Page + Text")]),
        ("shortmessage", "Short Message", "text", None),
        ("longmessage", "Long Message", "textarea", None),
        ("audio", "Audio File", "select", afiles),
        ("image", "Image", "text", None),
        ("color", "Color", "text", None),
        ("icon", "Icon", "text", None),
        ("expires", "Expires Rule", "text", None),
        ("priority", "Priority", "select", [("Low", "Low"), ("Normal", "Normal"), ("High", "High"), ("Emergency", "Emergency")]),
    ]


@app.route("/messages/")
@alias("/messages/index")
def messages_index():
    return dispatch_web_page("messages/index")


@alias("/messages/new", methods=["GET", "POST"])
def messages_new():
    return dispatch_web_page("messages/new")


@alias("/messages/edit", methods=["GET", "POST"])
def messages_edit():
    return dispatch_web_page("messages/edit")


def create_broadcast(message_id, groups, sender, overrides=None):
    sys.path.insert(0, str(BASE_DIR))
    from broadcasts import (
        create_broadcast_from_template,
        expire_broadcasts_triggered_by_template,
        expire_message_rule_broadcasts,
        fetch_template,
    )

    ensure_message_vendor_schema()
    conn = db()
    try:
        with conn.cursor() as cur:
            template = fetch_template(cur, message_id)
            if not template:
                raise RuntimeError("Message not found")
            broadcast_id, expires_rule = create_broadcast_from_template(cur, template, groups, sender, overrides=overrides)
            trigger_priority = ((overrides or {}).get("priority") if isinstance(overrides, dict) else None) or template.get("priority")
            if str(trigger_priority or "").strip().lower() != "emergency":
                expire_message_rule_broadcasts(
                    cur,
                    expires_rule,
                    [broadcast_id],
                    trigger_groups=groups,
                )
                expire_broadcasts_triggered_by_template(
                    cur,
                    message_id,
                    [broadcast_id],
                    trigger_groups=groups,
                )
        conn.commit()
    finally:
        conn.close()
    return broadcast_id


@alias("/messages/send", methods=["GET", "POST"])
def messages_send():
    return dispatch_web_page("messages/send")


@alias("/messages/send-status", methods=["GET"])
def messages_send_status():
    return dispatch_web_page("messages/send-status")


@alias("/messages/custom", methods=["GET", "POST"])
def messages_custom():
    return dispatch_web_page("messages/custom")


@alias("/messages/variable-api-test", methods=["POST"])
def messages_variable_api_test():
    return dispatch_web_page("messages/variable-api-test")


@alias("/messages/tts-preview", methods=["GET", "POST"])
def messages_tts_preview():
    return dispatch_web_page("messages/tts-preview")


def asset_filename(name):
    raw = str(name or "").replace("\0", "").replace("\\", "/").split("/")[-1].strip()
    if not raw or raw.startswith("."):
        return ""
    return raw


def asset_lookup_names(name):
    raw = asset_filename(name)
    if not raw:
        return []
    names = [raw]
    secure = secure_filename(raw)
    if secure and secure not in names:
        names.append(secure)
    return names


def asset_path(name):
    names = asset_lookup_names(name)
    if not names:
        abort(400)
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    base = ASSET_DIR.resolve()
    for candidate_name in names:
        path = (base / candidate_name).resolve()
        if base not in path.parents:
            abort(400)
        if path.is_file():
            return path
    wanted = {candidate.lower() for candidate in names}
    try:
        for path in base.iterdir():
            if path.is_file() and path.name.lower() in wanted:
                return path.resolve()
    except OSError:
        pass
    path = (base / names[0]).resolve()
    if base not in path.parents:
        abort(400)
    return path


@app.route("/assets/", methods=["GET", "POST"])
@alias("/assets/index", methods=["GET", "POST"])
def assets():
    return dispatch_web_page("assets/index")


@app.route("/paging/")
@alias("/paging/index")
def paging():
    return dispatch_web_page("paging/index")


@alias("/admin/manage-groups", methods=["GET", "POST"])
def manage_groups():
    return dispatch_web_page("admin/manage-groups")


@alias("/admin/manage-broadcasts", methods=["GET", "POST"])
def manage_broadcasts():
    return dispatch_web_page("admin/manage-broadcasts")


@alias("/admin/manage-users", methods=["GET", "POST"])
def manage_users():
    return dispatch_web_page("admin/manage-users")


@alias("/user/settings", methods=["GET", "POST"])
def user_settings():
    return dispatch_web_page("user/settings")


def endpoint_ipc(command):
    try:
        with endpoints.connect_endpoint_ipc(timeout=ENDPOINT_IPC_TIMEOUT) as sock:
            sock.sendall(command.encode() + b"\n")
            raw = endpoints.recv_line(sock)
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                return {"ok": False, "error": "Endpoint manager returned an empty response", "modules": []}
            try:
                return json.loads(text)
            except Exception:
                return {"ok": False, "error": f"Invalid endpoint manager response: {text[:200]}", "modules": []}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "modules": []}


@app.route(
    "/endpoints/<module>",
    defaults={"module_path": ""},
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@app.route(
    "/endpoints/<module>/",
    defaults={"module_path": ""},
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@app.route(
    "/endpoints/<module>/<path:module_path>",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
def endpoint_module_web(module, module_path):
    return dispatch_web_page("endpoints/index")


@alias("/admin/manage-endpoints")
def manage_endpoints():
    return dispatch_web_page("admin/manage-endpoints")


@alias("/admin/new-endpoint")
def new_endpoint():
    return dispatch_web_page("admin/new-endpoint")


@alias("/admin/new-endpoint-configure")
def new_endpoint_configure():
    return dispatch_web_page("admin/new-endpoint-configure")


@alias("/admin/endpoint-form-frame", methods=["GET", "POST"])
def endpoint_form_frame():
    return dispatch_web_page("admin/endpoint-form-frame")


@alias("/admin/servicemonitor-kuma-monitors", methods=["POST"])
def servicemonitor_kuma_monitors():
    user = require_admin()
    if not isinstance(user, dict):
        return jsonify({"ok": False, "error": "Not authorized"}), 403
    base_url = str(request.form.get("base_url") or "").strip()
    api_key = str(request.form.get("api_key") or "").strip()
    if not api_key:
        endpoint_id = str(request.form.get("endpoint_id") or "").strip()
        kind, _, row_id = endpoint_id.partition("-")
        if kind == "monitor" and row_id.isdigit():
            row = endpoints.service_monitor_row(row_id)
            if row:
                api_key = str(row.get("uk_api_key") or "")
                if not base_url:
                    base_url = str(row.get("uk_base_url") or "")
    try:
        monitors = endpoints.service_monitor_list_kuma_monitors(base_url, api_key)
        return jsonify({"ok": True, "monitors": monitors})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc) or "Could not reach Uptime Kuma."})


@alias("/admin/endpoint-action-page", methods=["GET", "POST"])
@alias("/admin/endpoint-action-frame", methods=["GET", "POST"])
def endpoint_action_page():
    return dispatch_web_page("admin/endpoint-action-page")


@alias("/admin/endpoint-module-settings", methods=["GET", "POST"])
def endpoint_module_settings():
    return dispatch_web_page("admin/endpoint-module-settings")


@alias("/admin/endpoint-module-settings-configure", methods=["GET", "POST"])
@alias("/admin/endpoint-module-settings-frame")
def endpoint_module_settings_configure():
    return dispatch_web_page("admin/endpoint-module-settings-configure")


SETTINGS_TABS = "<div class='tabs'><a href='/admin/settings/general'>General</a><a href='/admin/settings/login'>Login</a><a href='/admin/settings/sip'>SIP</a><a href='/admin/settings/branding'>Branding</a><a href='/admin/settings/advanced'>Advanced</a><a href='/admin/settings/about'>About</a></div>"


@alias("/admin/settings/general", methods=["GET", "POST"])
def settings_general():
    return dispatch_web_page("admin/settings/general")


@alias("/admin/settings/multicast-gateway", methods=["GET", "POST"])
def settings_multicast_gateway():
    return dispatch_web_page("admin/settings/multicast-gateway")


@alias("/admin/settings/login", methods=["GET", "POST"])
def settings_login():
    return dispatch_web_page("admin/settings/login")


@alias("/admin/settings/branding", methods=["GET", "POST"])
def settings_branding():
    return dispatch_web_page("admin/settings/branding")


@alias("/admin/settings/advanced", methods=["GET", "POST"])
def settings_advanced():
    return dispatch_web_page("admin/settings/advanced")


@alias("/admin/settings/sip", methods=["GET", "POST"])
def settings_sip():
    return dispatch_web_page("admin/settings/sip")


@alias("/admin/sip-dns-check")
def admin_sip_dns_check():
    return dispatch_web_page("admin/sip-dns-check")


@alias("/admin/settings/web", methods=["GET", "POST"])
def settings_web():
    return dispatch_web_page("admin/settings/web")


@alias("/admin/settings/api", methods=["GET", "POST"])
def settings_api():
    return dispatch_web_page("admin/settings/api")


@alias("/admin/settings/certificates", methods=["GET", "POST"])
def settings_certificates():
    try:
        return dispatch_web_page("admin/settings/certificates")
    except HTTPException as exc:
        if request.method == "POST" and request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(status="error", message=exc.description or "The certificate request was rejected."), int(exc.code or 500)
        raise
    except Exception as exc:
        if request.method == "POST" and request.headers.get("X-Requested-With") == "XMLHttpRequest":
            app.logger.exception("Unhandled certificate settings request failure")
            return jsonify(status="error", message=str(exc) or "The certificate request failed."), 500
        raise


def read_version():
    try:
        for line in (BASE_DIR / "pyproject.toml").read_text().splitlines():
            if line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        return ""
    return ""


@alias("/admin/settings/about")
def settings_about():
    return dispatch_web_page("admin/settings/about")


@alias("/demo-mode")
def demo_mode_info():
    return demo_mode_iframe_html(request.args.get("topic", ""))


def ensure_bell_schema():
    execute_many(
        [
            ("CREATE TABLE IF NOT EXISTS bell_schedules (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, enabled TINYINT(1) NOT NULL DEFAULT 1, created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP, timezone VARCHAR(64) NOT NULL DEFAULT 'server')", ()),
            ("CREATE TABLE IF NOT EXISTS bell_lists (id INT AUTO_INCREMENT PRIMARY KEY, schedule_id INT NOT NULL DEFAULT 0, name VARCHAR(100) NOT NULL, created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP)", ()),
            ("CREATE TABLE IF NOT EXISTS bell_events (id INT AUTO_INCREMENT PRIMARY KEY, list_id INT NOT NULL, fire_time TIME NOT NULL, audio TEXT NOT NULL, days_of_week VARCHAR(32) NOT NULL DEFAULT '0,1,2,3,4,5,6')", ()),
            ("CREATE TABLE IF NOT EXISTS bell_schedule_groups (schedule_id INT NOT NULL, group_id VARCHAR(100) NOT NULL, PRIMARY KEY (schedule_id, group_id))", ()),
            ("CREATE TABLE IF NOT EXISTS bell_calendar_lists (schedule_id INT NOT NULL, bell_date DATE NOT NULL, list_id INT NOT NULL, PRIMARY KEY (schedule_id, bell_date, list_id))", ()),
        ]
    )


@app.route("/bells/")
@alias("/bells/index")
def bells_index():
    return dispatch_web_page("bells/index")


@alias("/bells/time")
def bells_time():
    return dispatch_web_page("bells/time")


@alias("/bells/new", methods=["GET", "POST"])
def bells_new():
    return dispatch_web_page("bells/new")


@alias("/bells/edit", methods=["GET", "POST"])
def bells_edit():
    return dispatch_web_page("bells/edit")


@alias("/bells/lists", methods=["GET", "POST"])
@alias("/bells/bell-lists", methods=["GET", "POST"])
def bells_lists():
    return dispatch_web_page("bells/lists")


@alias("/bells/groups", methods=["GET", "POST"])
def bells_groups():
    return dispatch_web_page("bells/groups")


@alias("/bells/calendar", methods=["GET", "POST"])
def bells_calendar():
    return dispatch_web_page("bells/calendar")


@alias("/bells/devices")
def bells_devices():
    return dispatch_web_page("bells/devices")


@alias("/admin/delete-endpoint")
def delete_endpoint_redirect():
    return dispatch_web_page("admin/delete-endpoint")


@alias("/admin/edit-endpoint")
def edit_endpoint_redirect():
    return dispatch_web_page("admin/edit-endpoint")


if __name__ == "__main__":
    app.run("0.0.0.0", int(os.getenv("PORT", "8080")))
