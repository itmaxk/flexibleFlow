#!/usr/bin/env python3
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import string
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import urllib.request
import uuid
import secrets
from datetime import UTC, datetime

# --- Runtime mode ---
SAFE_MODE = "--safe" in sys.argv or os.environ.get("VLESS_CASCADE_SAFE_MODE") == "1"


# --- Auto-install optional dependencies ---
def install_deps():
    print("Installing optional dependency: qrcode[pil]...")
    subprocess.run(["apt-get", "update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["apt-get", "install", "-y", "python3-pip"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([sys.executable, "-m", "pip", "install", "qrcode[pil]"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

qrcode = None
try:
    import qrcode as _qrcode
    qrcode = _qrcode
except ImportError:
    if not SAFE_MODE:
        install_deps()
        try:
            import qrcode as _qrcode
            qrcode = _qrcode
        except ImportError:
            qrcode = None


# --- Configuration ---
DB_PATH = "/etc/x-ui/x-ui.db"
CONFIG_STORE = "/root/.vpn_manager_settings.json"
ROUTES_STORE = "/etc/vless-cascade/routes.json"
BACKUP_DIR = "/etc/vless-cascade/backups"
LOG_PATH = "/var/log/vless-cascade.log"
TRAFFIC_LOG_PATH = "/var/log/vless-cascade-traffic.log"
XRAY_BIN = "/usr/local/x-ui/bin/xray"
XUI_INSTALL_URL = "https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"
MIKROTIK_BOOTSTRAP_FILENAME = "mikrotik_bootstrap_v7213.rsc"
MIKROTIK_TEMPLATE_RELATIVE = os.path.join("mikrotik", MIKROTIK_BOOTSTRAP_FILENAME)

DEFAULT_ROUTES = {
    "direct_domains": [
        "geosite:category-ru",
        "regexp:(^|\\.)[A-Za-z0-9-]+\\.ru$",
        "regexp:(^|\\.)[A-Za-z0-9-]+\\.su$",
        "regexp:(^|\\.)[A-Za-z0-9-]+\\.xn--p1ai$",
    ],
    "direct_ips": ["geoip:ru", "geoip:private"],
    "proxy_domains": [],
    "proxy_ips": [],
}

ROUTE_PROFILES = {
    "1": {
        "name": "RU only direct (recommended)",
        "routes": {
            "direct_domains": [
                "geosite:category-ru",
                "regexp:(^|\\.)[A-Za-z0-9-]+\\.ru$",
                "regexp:(^|\\.)[A-Za-z0-9-]+\\.su$",
                "regexp:(^|\\.)[A-Za-z0-9-]+\\.xn--p1ai$",
            ],
            "direct_ips": ["geoip:ru", "geoip:private"],
            "proxy_domains": [],
            "proxy_ips": [],
        },
    },
    "2": {
        "name": "Mixed (RU + Telegram direct)",
        "routes": {
            "direct_domains": [
                "geosite:category-ru",
                "geosite:telegram",
                "regexp:(^|\\.)[A-Za-z0-9-]+\\.ru$",
                "regexp:(^|\\.)[A-Za-z0-9-]+\\.su$",
                "regexp:(^|\\.)[A-Za-z0-9-]+\\.xn--p1ai$",
            ],
            "direct_ips": ["geoip:ru", "geoip:private"],
            "proxy_domains": [],
            "proxy_ips": [],
        },
    },
    "3": {
        "name": "Full proxy (only private direct)",
        "routes": {
            "direct_domains": [],
            "direct_ips": ["geoip:private"],
            "proxy_domains": [],
            "proxy_ips": [],
        },
    },
}


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    END = "\033[0m"


# --- Utilities ---
def log_event(level, message, with_traceback=False):
    try:
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} [{level}] {message}\n"
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
            if with_traceback:
                f.write(traceback.format_exc())
                f.write("\n")
    except OSError:
        pass


def run(cmd, desc=None, stream=False):
    if desc:
        print(f"{Colors.CYAN}[...]{Colors.END} {desc}")
    cmd_str = " ".join(shlex.quote(x) for x in cmd)
    log_event("INFO", f"run: {cmd_str}")
    try:
        if stream:
            subprocess.run(cmd, check=True, text=True)
        else:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        err = (e.stderr or e.stdout or "").strip()
        print(f"{Colors.RED}[ERROR]{Colors.END} {err}")
        log_event("ERROR", f"run failed ({e.returncode}): {cmd_str}; {err}")
        return False
    except Exception:
        print(f"{Colors.RED}[ERROR]{Colors.END} unexpected command execution error")
        log_event("ERROR", f"run unexpected error: {cmd_str}", with_traceback=True)
        return False

def execute_menu_action(label, fn):
    started = datetime.now(UTC)
    print(f"{Colors.CYAN}[START]{Colors.END} {label}")
    log_event("INFO", f"{label}: START")
    try:
        result = fn()
        duration = int((datetime.now(UTC) - started).total_seconds())
        if result is False:
            print(f"{Colors.RED}[FAILED]{Colors.END} {label} ({duration}s)")
            log_event("ERROR", f"{label}: FAILED ({duration}s)")
            return False
        print(f"{Colors.GREEN}[DONE]{Colors.END} {label} ({duration}s)")
        log_event("INFO", f"{label}: DONE ({duration}s)")
        return True
    except Exception:
        duration = int((datetime.now(UTC) - started).total_seconds())
        print(f"{Colors.RED}[FAILED]{Colors.END} {label} ({duration}s)")
        log_event("ERROR", f"{label}: EXCEPTION ({duration}s)", with_traceback=True)
        return False


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def can_bind_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


def choose_foreign_inbound_port():
    preferred = [443, 8443, 2053, 2083, 2087, 2096]
    for port in preferred:
        if can_bind_port(port):
            return port
    # Last resort: random free high port.
    return find_free_port()


def valid_hostname(value):
    if not value or len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]
    labels = value.split(".")
    allowed = re.compile(r"^[A-Za-z0-9-]{1,63}$")
    return all(lbl and allowed.match(lbl) and not lbl.startswith("-") and not lbl.endswith("-") for lbl in labels)


def fetch_text(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "vless-cascade/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def find_xray_binary():
    candidates = [
        XRAY_BIN,
        shutil.which("xray"),
        "/usr/local/bin/xray",
        "/usr/bin/xray",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def find_xui_binaries():
    candidates = [
        "/usr/local/x-ui/x-ui",
        shutil.which("x-ui"),
        "/usr/bin/x-ui",
    ]
    result = []
    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            if candidate not in result:
                result.append(candidate)
    return result


def validate_xray_config_with_xray(config_obj):
    xray_bin = find_xray_binary()
    if not xray_bin:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Xray binary not found. Skipping xray -test validation.")
        return True

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".json") as tmp:
            json.dump(config_obj, tmp)
            tmp_path = tmp.name

        proc = subprocess.run(
            [xray_bin, "run", "-test", "-config", tmp_path],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            print(f"{Colors.RED}[ERROR]{Colors.END} xray -test failed: {err}")
            return False
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} failed to run xray -test: {e}")
        return False
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

def get_public_ip():
    for endpoint in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            ip = fetch_text(endpoint, timeout=8).strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    return None


def get_3x_ui_panel_url(server_ip=None):
    ip = server_ip or get_public_ip()
    if not ip:
        return None

    port = "54321"
    base_path = ""
    use_https = False

    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key IN ('webPort','webBasePath','webCertFile','webKeyFile')"
            ).fetchall()
            settings = {k: (v or "").strip() for k, v in rows}
            if settings.get("webPort", "").isdigit():
                port = settings["webPort"]
            base_path = settings.get("webBasePath", "").strip().strip("/")
            use_https = bool(settings.get("webCertFile")) and bool(settings.get("webKeyFile"))
    except Exception:
        pass

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}"
    if base_path:
        url = f"{url}/{base_path}"
    return url


def get_3x_ui_panel_credentials():
    cached = load_json(CONFIG_STORE, {})
    if isinstance(cached, dict) and cached.get("panel_username") and cached.get("panel_password"):
        return cached["panel_username"], cached["panel_password"]

    username = "admin"
    password = "admin"
    password_is_hashed = False

    hash_pattern = re.compile(r"^\$2[aby]\$|^\$argon2|^[a-f0-9]{32,}$", re.IGNORECASE)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Try settings first (some forks keep web credentials here).
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key IN ('webUser','webUsername','webPass','webPassword','username','password')"
            ).fetchall()
            settings = {k: (v or "").strip() for k, v in rows}
            for key in ("webUser", "webUsername", "username"):
                if settings.get(key):
                    username = settings[key]
                    break
            for key in ("webPass", "webPassword", "password"):
                if settings.get(key):
                    password = settings[key]
                    break

            # Probe common user tables if present.
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for table in ("users", "user", "admin", "admins"):
                if table not in tables:
                    continue
                columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
                if "username" in columns:
                    row = conn.execute(f"SELECT username FROM {table} ORDER BY rowid DESC LIMIT 1").fetchone()
                    if row and row[0]:
                        username = str(row[0]).strip() or username
                if "password" in columns:
                    row = conn.execute(f"SELECT password FROM {table} ORDER BY rowid DESC LIMIT 1").fetchone()
                    if row and row[0]:
                        db_password = str(row[0]).strip()
                        if db_password:
                            if hash_pattern.match(db_password):
                                password_is_hashed = True
                            else:
                                password = db_password
    except Exception:
        pass

    if password_is_hashed:
        # Hash means we cannot recover plaintext password from DB.
        return username, "(unknown; set via menu 10)"
    return username, password


def generate_panel_credentials():
    username = f"admin{secrets.randbelow(9000) + 1000}"
    alphabet = string.ascii_letters + string.digits + "-_"
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    if password.startswith("-"):
        password = "A" + password[1:]
    return username, password


def redact_secret(text, secret):
    if not text:
        return ""
    redacted = text
    if secret:
        redacted = redacted.replace(secret, "***")
    return redacted


def apply_3x_ui_panel_credentials(username, password):
    xui_bins = find_xui_binaries()
    if not xui_bins:
        log_event("ERROR", "apply_3x_ui_panel_credentials: x-ui command not found")
        return False
    log_event("INFO", f"apply_3x_ui_panel_credentials: start username={username} xui_bins={xui_bins}")

    def db_has_username(expected):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                for table in ("users", "user", "admin", "admins"):
                    if table not in tables:
                        continue
                    columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
                    if "username" not in columns:
                        continue
                    row = conn.execute(f"SELECT username FROM {table} ORDER BY rowid DESC LIMIT 1").fetchone()
                    if row and str(row[0]).strip() == expected:
                        log_event("INFO", f"apply_3x_ui_panel_credentials: DB username verified in table={table}")
                        return True
        except Exception:
            log_event("WARN", "apply_3x_ui_panel_credentials: DB username verification failed")
            return False
        return False

    usage_markers = (
        "x-ui control menu usages",
        "subcommands",
        "admin management script",
    )

    for xui_cmd in xui_bins:
        attempts = [
            {
                "cmd": [xui_cmd, "setting", "-username", username, "-password", password],
                "input": None,
                "label": "setting-flags",
            },
            {
                "cmd": [xui_cmd, "setting", "--username", username, "--password", password],
                "input": None,
                "label": "setting-long-flags",
            },
            {
                "cmd": [xui_cmd, "settings", "-username", username, "-password", password],
                "input": None,
                "label": "settings-flags",
            },
            {
                "cmd": [xui_cmd, "setting"],
                "input": f"{username}\n{password}\n",
                "label": "setting-interactive",
            },
        ]

        for attempt in attempts:
            safe_cmd = " ".join(shlex.quote(part) for part in attempt["cmd"])
            proc = subprocess.run(
                attempt["cmd"],
                input=attempt["input"],
                check=False,
                capture_output=True,
                text=True,
            )
            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            output = redact_secret(output, password)
            lower_output = output.lower()
            log_event(
                "INFO",
                f"apply_3x_ui_panel_credentials: bin={xui_cmd} method={attempt['label']} rc={proc.returncode} cmd={safe_cmd} output={output[:500]}",
            )
            if proc.returncode != 0:
                continue
            if "flag provided but not defined" in lower_output or "unknown" in lower_output:
                continue
            if any(marker in lower_output for marker in usage_markers):
                continue
            if db_has_username(username):
                log_event("INFO", f"apply_3x_ui_panel_credentials: success via {xui_cmd}::{attempt['label']} with DB verification")
                return True
            if "error" not in lower_output:
                log_event("INFO", f"apply_3x_ui_panel_credentials: success via {xui_cmd}::{attempt['label']} without DB verification")
                return True

    log_event("ERROR", "apply_3x_ui_panel_credentials: all update methods failed")
    return False


def rotate_3x_ui_panel_credentials():
    username, password = generate_panel_credentials()
    if not apply_3x_ui_panel_credentials(username, password):
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Could not auto-update 3x-ui credentials. Use menu 10 to set them manually.")
        return False
    settings = load_settings()
    settings["panel_username"] = username
    settings["panel_password"] = password
    save_settings(settings)
    print(f"{Colors.GREEN}[INFO]{Colors.END} 3x-ui credentials updated after install.")
    return True


def print_3x_ui_panel_info(server_ip=None):
    panel_url = get_3x_ui_panel_url(server_ip)
    if not panel_url:
        return
    username, password = get_3x_ui_panel_credentials()
    print(f"{Colors.CYAN}3x-ui panel:{Colors.END} {panel_url}")
    print(f"{Colors.CYAN}3x-ui login:{Colors.END} {username}")
    print(f"{Colors.CYAN}3x-ui password:{Colors.END} {password}")


def get_xray_keys():
    xray_bin = find_xray_binary()
    if not xray_bin:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Xray binary not found. Attempting to install...")
        log_event("WARN", "get_xray_keys: xray binary not found, attempting to install")
        if install_xray():
            xray_bin = find_xray_binary()
        if not xray_bin:
            log_event("ERROR", "get_xray_keys: xray binary not found after installation attempt")
            return None, None

    try:
        out = subprocess.check_output([xray_bin, "x25519"], text=True)
        # Handle output differences across xray versions/builds.
        priv_match = re.search(r"(?im)^\s*Private key:\s*(\S+)\s*$", out)
        pub_match = re.search(r"(?im)^\s*Public key:\s*(\S+)\s*$", out)

        if not priv_match:
            priv_match = re.search(r"(?im)^\s*privateKey:\s*(\S+)\s*$", out)
        if not pub_match:
            pub_match = re.search(r"(?im)^\s*publicKey:\s*(\S+)\s*$", out)

        if not priv_match or not pub_match:
            # Last-resort parser: pick first two base64url-looking tokens.
            tokens = re.findall(r"[A-Za-z0-9_-]{32,}", out)
            if len(tokens) >= 2:
                priv, pub = tokens[0], tokens[1]
            else:
                log_event("ERROR", f"get_xray_keys: unrecognized x25519 output: {out!r}")
                return None, None
        else:
            priv = priv_match.group(1).strip()
            pub = pub_match.group(1).strip()
        return priv, pub
    except Exception as e:
        log_event("ERROR", f"get_xray_keys: failed to run x25519: {e}")
        return None, None


def print_qr(data):
    if qrcode is None:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} qrcode package is not available, QR output skipped.")
        return
    qr_obj = qrcode.QRCode(version=1, box_size=1, border=4)
    qr_obj.add_data(data)
    qr_obj.make(fit=True)
    qr_obj.print_ascii(invert=True)

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_json(path, defaults):
    if not os.path.exists(path):
        return defaults.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            merged = defaults.copy()
            if isinstance(data, dict):
                merged.update(data)
            return merged
    except Exception:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} failed to read {path}, using defaults")
        return defaults.copy()

def validate_route_item(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 255:
        return False
    # Allow regex metacharacters used in Xray routing rules: ( ) [ ] { } ^ $ . | ? * + - : / _
    return re.match(r"^[A-Za-z0-9:._*/\[\]{}()?^$|+\\-]+$", value) is not None


def validate_routes(cfg):
    for key in ("direct_domains", "direct_ips", "proxy_domains", "proxy_ips"):
        items = cfg.get(key)
        if not isinstance(items, list):
            raise ValueError(f"Field '{key}' must be a list of strings.")
        for item in items:
            if not validate_route_item(item):
                raise ValueError(f"Invalid value in '{key}': {item}")

def append_if_missing(items, value):
    if value not in items:
        items.append(value)


def ensure_default_route_policy(routes):
    direct_domains = list(routes.get("direct_domains", []))
    direct_ips = list(routes.get("direct_ips", []))

    append_if_missing(direct_domains, "geosite:category-ru")
    append_if_missing(direct_domains, "regexp:(^|\\.)[A-Za-z0-9-]+\\.ru$")
    append_if_missing(direct_domains, "regexp:(^|\\.)[A-Za-z0-9-]+\\.su$")
    append_if_missing(direct_domains, "regexp:(^|\\.)[A-Za-z0-9-]+\\.xn--p1ai$")
    append_if_missing(direct_ips, "geoip:ru")
    append_if_missing(direct_ips, "geoip:private")

    routes["direct_domains"] = direct_domains
    routes["direct_ips"] = direct_ips
    return routes


def load_routes():
    routes = load_json(ROUTES_STORE, DEFAULT_ROUTES)
    merged = DEFAULT_ROUTES.copy()
    for key in merged:
        if key in routes:
            merged[key] = routes[key]
    merged = ensure_default_route_policy(merged)
    validate_routes(merged)

    if not os.path.exists(ROUTES_STORE):
        save_json(ROUTES_STORE, merged)
    else:
        current = load_json(ROUTES_STORE, DEFAULT_ROUTES)
        if current.get("direct_domains") != merged.get("direct_domains") or current.get("direct_ips") != merged.get("direct_ips"):
            save_json(ROUTES_STORE, merged)

    return merged


def apply_route_profile():
    print("\nAvailable route profiles:")
    print("1. RU only direct (recommended)")
    print("2. Mixed (RU + Telegram direct)")
    print("3. Full proxy (only private direct)")
    choice = input("Choose profile [1-3]: ").strip()
    profile = ROUTE_PROFILES.get(choice)
    if not profile:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unknown profile")
        log_event("ERROR", f"apply_route_profile: invalid choice {choice}")
        return False
    save_json(ROUTES_STORE, profile["routes"])
    print(f"{Colors.GREEN}Applied profile:{Colors.END} {profile['name']}")
    log_event("INFO", f"apply_route_profile: {profile['name']}")
    log_routing_config(profile["routes"])
    return True

def load_settings():
    defaults = {
        "client_port": "auto",
        "client_sni": "google.com",
        "last_foreign_link": "",
        "last_client_link": "",
        "actual_port": None,
        "panel_username": "",
        "panel_password": "",
        "traffic_logging_enabled": False,
    }
    return load_json(CONFIG_STORE, defaults)


def save_settings(settings):
    save_json(CONFIG_STORE, settings)


def parse_port_setting(value):
    if value == "auto":
        return "auto"
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("Port must be in range 1..65535")
    return str(port)

def parse_foreign_link(link):
    parsed = urllib.parse.urlparse(link)
    if parsed.scheme != "vless":
        raise ValueError("Link must start with vless://")
    if not parsed.username:
        raise ValueError("User UUID is missing in the link.")

    try:
        uuid.UUID(parsed.username)
    except ValueError:
        raise ValueError("Invalid UUID in VLESS link.")

    if not parsed.hostname:
        raise ValueError("Server address is missing in the link.")

    port = parsed.port or 443
    if port < 1 or port > 65535:
        raise ValueError("Port in link must be in range 1..65535.")

    query = urllib.parse.parse_qs(parsed.query)
    required = ("sni", "pbk", "sid")
    for key in required:
        if key not in query or not query[key] or not query[key][0].strip():
            raise ValueError(f"Required parameter '{key}' is missing.")

    sni = query["sni"][0].strip()
    pbk = query["pbk"][0].strip()
    sid = query["sid"][0].strip()

    if not valid_hostname(sni):
        raise ValueError("Invalid SNI in foreign link.")
    if re.match(r"^[A-Za-z0-9_-]{20,}$", pbk) is None:
        raise ValueError("Invalid public key (pbk) in foreign link.")
    if re.match(r"^[0-9a-fA-F]{1,16}$", sid) is None:
        raise ValueError("Invalid short id (sid) in foreign link.")

    return {
        "address": parsed.hostname,
        "port": port,
        "id": parsed.username,
        "sni": sni,
        "pbk": pbk,
        "sid": sid,
    }


def extract_foreign_from_xray_config_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("SELECT value FROM settings WHERE key = 'xrayConfig' LIMIT 1")
            row = cur.fetchone()
        if not row or not row[0]:
            return None
        cfg = json.loads(row[0])
        outbounds = cfg.get("outbounds", [])
        for ob in outbounds:
            if ob.get("protocol") != "vless":
                continue
            settings = ob.get("settings", {})
            vnext = settings.get("vnext", [])
            if not vnext:
                continue
            first = vnext[0]
            users = first.get("users", [])
            if not users:
                continue
            reality = ob.get("streamSettings", {}).get("realitySettings", {})
            candidate = {
                "address": first.get("address", ""),
                "port": int(first.get("port", 443)),
                "id": users[0].get("id", ""),
                "sni": reality.get("serverName", ""),
                "pbk": reality.get("publicKey", ""),
                "sid": reality.get("shortId", ""),
            }
            if all(candidate.get(k) for k in ("address", "id", "sni", "pbk", "sid")):
                return candidate
    except Exception as e:
        log_event("ERROR", f"extract_foreign_from_xray_config_db failed: {e}", with_traceback=True)
    return None


def get_script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def get_mikrotik_bootstrap_target_path():
    return os.path.join(get_script_dir(), MIKROTIK_BOOTSTRAP_FILENAME)


def build_mikrotik_bootstrap_fallback(foreign):
    return (
        "# Auto-generated by vless_cascade.py\n"
        "# RouterOS bootstrap variables for cascade VLESS\n"
        "# Target RouterOS: 7.21.3\n\n"
        f":local VLESS_SERVER \"{foreign['address']}\"\n"
        f":local VLESS_PORT {foreign['port']}\n"
        f":local UUID \"{foreign['id']}\"\n"
        f":local SNI \"{foreign['sni']}\"\n"
        f":local PBK \"{foreign['pbk']}\"\n"
        f":local SID \"{foreign['sid']}\"\n\n"
        "# Full bootstrap template was not found near this script.\n"
        "# Place full script in ./mikrotik/mikrotik_bootstrap_v7213.rsc and rerun menu 1/2\n"
        "# to generate a complete ready-to-import file with these values.\n"
    )


def render_mikrotik_bootstrap_content(foreign):
    template_path = os.path.join(get_script_dir(), MIKROTIK_TEMPLATE_RELATIVE)
    if not os.path.exists(template_path):
        return build_mikrotik_bootstrap_fallback(foreign)

    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    replacements = {
        "REPLACE_SERVER": foreign["address"],
        "REPLACE_UUID": foreign["id"],
        "REPLACE_SNI": foreign["sni"],
        "REPLACE_REALITY_PBK": foreign["pbk"],
        "REPLACE_REALITY_SID": foreign["sid"],
    }

    for old, new in replacements.items():
        content = content.replace(old, new)

    # Also patch explicit RouterOS variable lines, so generation works even if
    # the template no longer contains REPLACE_* placeholders.
    content = re.sub(r':local VLESS_SERVER "[^"]*"', f':local VLESS_SERVER "{foreign["address"]}"', content, count=1)
    content = re.sub(r":local VLESS_PORT \d+", f':local VLESS_PORT {foreign["port"]}', content, count=1)
    content = re.sub(r':local UUID "[^"]*"', f':local UUID "{foreign["id"]}"', content, count=1)
    content = re.sub(r':local SNI "[^"]*"', f':local SNI "{foreign["sni"]}"', content, count=1)
    content = re.sub(r':local PBK "[^"]*"', f':local PBK "{foreign["pbk"]}"', content, count=1)
    content = re.sub(r':local SID "[^"]*"', f':local SID "{foreign["sid"]}"', content, count=1)
    return content


def print_mikrotik_settings(foreign):
    target = get_mikrotik_bootstrap_target_path()
    print(f"\n{Colors.CYAN}MikroTik settings (RouterOS 7.21.3):{Colors.END}")
    print(f"  VLESS_SERVER = {foreign['address']}")
    print(f"  VLESS_PORT   = {foreign['port']}")
    print(f"  UUID         = {foreign['id']}")
    print(f"  SNI          = {foreign['sni']}")
    print(f"  PBK          = {foreign['pbk']}")
    print(f"  SID          = {foreign['sid']}")
    print(f"  Output file  = {target}")


def generate_mikrotik_bootstrap_file(foreign):
    target = get_mikrotik_bootstrap_target_path()
    content = render_mikrotik_bootstrap_content(foreign)
    with open(target, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"{Colors.GREEN}[DONE]{Colors.END} Generated MikroTik bootstrap: {target}")
    print(
        f"{Colors.CYAN}[INFO]{Colors.END} "
        "Applied values: "
        f"server={foreign['address']} port={foreign['port']} "
        f"uuid={foreign['id']} sni={foreign['sni']}"
    )
    log_event("INFO", f"generated MikroTik bootstrap: {target}")
    return target


def sync_mikrotik_bootstrap(foreign):
    try:
        print_mikrotik_settings(foreign)
        generate_mikrotik_bootstrap_file(foreign)
        return True
    except Exception as e:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Failed to generate MikroTik bootstrap: {e}")
        log_event("ERROR", f"sync_mikrotik_bootstrap failed: {e}", with_traceback=True)
        return False

def build_routing(foreign, routes, traffic_logging_enabled=False):
    rules = []

    if routes["direct_domains"]:
        rules.append({"type": "field", "outboundTag": "direct", "domain": routes["direct_domains"]})
    if routes["direct_ips"]:
        rules.append({"type": "field", "outboundTag": "direct", "ip": routes["direct_ips"]})
    if routes["proxy_domains"]:
        rules.append({"type": "field", "outboundTag": "proxy", "domain": routes["proxy_domains"]})
    if routes["proxy_ips"]:
        rules.append({"type": "field", "outboundTag": "proxy", "ip": routes["proxy_ips"]})

    # Fallback: everything else (except direct domains) goes through foreign proxy.
    # We need to exclude direct domains from the fallback to ensure they are routed directly.
    if routes["direct_domains"]:
        rules.append({
            "type": "field",
            "outboundTag": "proxy",
            "network": "tcp,udp",
            "domain": [f"!{d}" for d in routes["direct_domains"]]
        })
    else:
        rules.append({"type": "field", "outboundTag": "proxy", "network": "tcp,udp"})

    config = {
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": rules,
        },
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": foreign["address"],
                            "port": foreign["port"],
                            "users": [
                                {
                                    "id": foreign["id"],
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": foreign["sni"],
                        "publicKey": foreign["pbk"],
                        "shortId": foreign["sid"],
                    },
                },
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }

    # Only add log configuration if traffic logging is enabled
    if traffic_logging_enabled:
        config["log"] = {
            "access": TRAFFIC_LOG_PATH,
            "error": "/var/log/xray-error.log",
            "loglevel": "info"
        }

    return config


def log_routing_config(routes, foreign=None):
    """Log the current routing configuration for diagnostic purposes."""
    try:
        log_event("INFO", "=== Routing Configuration ===")
        log_event("INFO", f"Direct domains ({len(routes.get('direct_domains', []))}): {', '.join(routes.get('direct_domains', []))}")
        log_event("INFO", f"Direct IPs ({len(routes.get('direct_ips', []))}): {', '.join(routes.get('direct_ips', []))}")
        log_event("INFO", f"Proxy domains ({len(routes.get('proxy_domains', []))}): {', '.join(routes.get('proxy_domains', []))}")
        log_event("INFO", f"Proxy IPs ({len(routes.get('proxy_ips', []))}): {', '.join(routes.get('proxy_ips', []))}")
        if foreign:
            log_event("INFO", f"Foreign proxy: {foreign['address']}:{foreign['port']}")
        log_event("INFO", f"Traffic log path: {TRAFFIC_LOG_PATH}")
        log_event("INFO", "=== End Routing Configuration ===")
    except Exception as e:
        log_event("ERROR", f"log_routing_config: failed to log config: {e}")


def is_3x_ui_present():
    xui_cmd = shutil.which("x-ui")
    xray_cmd = shutil.which("xray")
    has_db = os.path.exists(DB_PATH)
    # Check if xray binary exists and is executable
    has_xray = False
    if os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        has_xray = True
    elif xray_cmd and os.access(xray_cmd, os.X_OK):
        has_xray = True
    has_unit = subprocess.run(
        ["systemctl", "cat", "x-ui"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    return (xui_cmd is not None) and (has_db or has_xray or has_unit)

def install_3x_ui():
    print(f"{Colors.CYAN}[1/3]{Colors.END} Downloading 3X-UI installer...")
    try:
        script_text = fetch_text(XUI_INSTALL_URL, timeout=30)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to download 3x-ui installer: {e}")
        log_event("ERROR", f"install_3x_ui: download failed: {e}")
        return False

    script_path = "/tmp/3x-ui-install.sh"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_text)
    os.chmod(script_path, 0o700)

    nginx_was_active = False
    try:
        nginx_was_active = subprocess.run(
            ["systemctl", "is-active", "--quiet", "nginx"],
            check=False,
        ).returncode == 0
    except Exception:
        nginx_was_active = False

    if nginx_was_active:
        print(f"{Colors.CYAN}[2/4]{Colors.END} Stopping nginx temporarily for certificate setup...")
        if not run(["systemctl", "stop", "nginx"], "Stopping nginx", stream=True):
            log_event("ERROR", "install_3x_ui: failed to stop nginx")
            try:
                os.remove(script_path)
            except OSError:
                pass
            return False

    print(f"{Colors.CYAN}[3/4]{Colors.END} Running installer (this can take a few minutes)...")
    try:
        ok = run(["bash", script_path], "Installing 3X-UI", stream=True)
    finally:
        if nginx_was_active:
            print(f"{Colors.CYAN}[4/4]{Colors.END} Starting nginx back...")
            if not run(["systemctl", "start", "nginx"], "Starting nginx", stream=True):
                log_event("ERROR", "install_3x_ui: failed to start nginx after install")

    try:
        os.remove(script_path)
    except OSError:
        pass

    print(f"{Colors.CYAN}[done]{Colors.END} Verifying 3X-UI availability...")
    if ok and is_3x_ui_present():
        rotate_3x_ui_panel_credentials()
    log_event("INFO", f"install_3x_ui: finished with status={ok}")
    return ok


def install_xray():
    """Install Xray binary if not found."""
    xray_bin = find_xray_binary()
    if xray_bin:
        print(f"{Colors.GREEN}[INFO]{Colors.END} Xray binary found at: {xray_bin}")
        return True
    
    print(f"{Colors.CYAN}[1/3]{Colors.END} Downloading Xray installer...")
    install_url = "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
    try:
        script_text = fetch_text(install_url, timeout=30)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to download Xray installer: {e}")
        log_event("ERROR", f"install_xray: download failed: {e}")
        return False

    script_path = "/tmp/xray-install.sh"
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_text)
        os.chmod(script_path, 0o700)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to write Xray installer script: {e}")
        log_event("ERROR", f"install_xray: write script failed: {e}")
        return False

    print(f"{Colors.CYAN}[2/3]{Colors.END} Running Xray installer (this can take a few minutes)...")
    try:
        ok = run(["bash", script_path], "Installing Xray", stream=True)
    finally:
        try:
            os.remove(script_path)
        except OSError:
            pass

    print(f"{Colors.CYAN}[3/3]{Colors.END} Verifying Xray installation...")
    xray_bin = find_xray_binary()
    if ok and xray_bin:
        print(f"{Colors.GREEN}[INFO]{Colors.END} Xray installed successfully at: {xray_bin}")
        log_event("INFO", f"install_xray: finished successfully, binary at {xray_bin}")
        return True
    else:
        print(f"{Colors.RED}[ERROR]{Colors.END} Xray installation failed or binary not found.")
        log_event("ERROR", "install_xray: installation failed")
        return False


def ensure_3x_ui():
    if is_3x_ui_present():
        return True

    answer = input("3X-UI is not installed. Install now? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes", "Р Т‘", "Р Т‘Р В°"):
        if install_3x_ui():
            # Installer can return before service is fully available.
            for _ in range(3):
                if is_3x_ui_present():
                    return True
                time.sleep(1)
            run(["systemctl", "daemon-reload"], "Reloading systemd units")
            run(["systemctl", "enable", "--now", "x-ui"], "Starting x-ui service", stream=True)
            if is_3x_ui_present():
                return True
        print(f"{Colors.RED}[ERROR]{Colors.END} 3X-UI is not installed or installation failed.")
        log_event("ERROR", "ensure_3x_ui: installation failed")
        return False

    print(f"{Colors.YELLOW}[INFO]{Colors.END} 3X-UI installation skipped by user.")
    log_event("INFO", "ensure_3x_ui: installation skipped")
    return False

def backup_current_xray_config(conn):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    cur = conn.execute("SELECT value FROM settings WHERE key = 'xrayConfig' LIMIT 1")
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    backup_path = os.path.join(BACKUP_DIR, f"xrayConfig-{uuid.uuid4().hex[:8]}.json")
    with open(backup_path, "w", encoding="utf-8") as f:
        f.write(row[0])
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass
    return backup_path


def list_xray_backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    backups = []
    for name in os.listdir(BACKUP_DIR):
        if name.startswith("xrayConfig-") and name.endswith(".json"):
            path = os.path.join(BACKUP_DIR, name)
            if os.path.isfile(path):
                backups.append(path)
    backups.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return backups


def rollback_xray_config():
    backups = list_xray_backups()
    if not backups:
        print(f"{Colors.YELLOW}[INFO]{Colors.END} No xrayConfig backups found in {BACKUP_DIR}")
        return

    print("\nRollback xrayConfig from backup")
    print("1. Restore latest backup")
    print("2. Choose backup manually")
    choice = input("Choose action [1-2]: ").strip()

    backup_path = None
    if choice == "1":
        backup_path = backups[0]
    elif choice == "2":
        print("\nAvailable backups:")
        for idx, path in enumerate(backups, start=1):
            print(f"{idx}. {path}")
        index_raw = input("Backup number: ").strip()
        try:
            index = int(index_raw)
            if index < 1 or index > len(backups):
                raise ValueError
            backup_path = backups[index - 1]
        except Exception:
            print(f"{Colors.RED}[ERROR]{Colors.END} Invalid backup number")
            return
    else:
        print(f"{Colors.RED}[ERROR]{Colors.END} Invalid action")
        return

    confirm = input(f"Restore from {backup_path}? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print("Rollback cancelled")
        return

    try:
        raw = open(backup_path, "r", encoding="utf-8").read()
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Backup xrayConfig must contain a JSON object.")
        if "routing" not in parsed or "outbounds" not in parsed:
            raise ValueError("Backup is missing required sections: routing/outbounds.")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to read backup: {e}")
        return

    if not validate_xray_config_with_xray(parsed):
        return

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'xrayConfig'",
                (raw,),
            )
            if cur.rowcount == 0:
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    ("xrayConfig", raw),
                )
            conn.commit()
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to write xrayConfig to DB: {e}")
        return

    if not run(["x-ui", "restart"], "Restarting 3X-UI"):
        return
    print(f"{Colors.GREEN}xrayConfig restored from backup successfully.{Colors.END}")

def create_client_inbound():
    settings = load_settings()

    try:
        if settings["client_port"] == "auto":
            port = find_free_port()
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Auto-selected free port: {port}")
        else:
            port = int(settings["client_port"])
            if port < 1 or port > 65535:
                raise ValueError("Client port must be in range 1..65535")
            if not can_bind_port(port):
                print(f"{Colors.YELLOW}[WARN]{Colors.END} Configured client port {port} is busy. Falling back to auto port.")
                log_event("WARN", f"create_client_inbound: configured port {port} busy, fallback to auto")
                port = find_free_port()
                settings["actual_port"] = port
    except Exception:
        print(f"{Colors.RED}[ERROR]{Colors.END} Invalid client_port value in settings. Use integer 1..65535 or auto.")
        return None

    sni = settings.get("client_sni", "google.com").strip()
    if not valid_hostname(sni):
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Invalid SNI in settings, fallback to google.com")
        sni = "google.com"
        settings["client_sni"] = sni

    user_uuid = str(uuid.uuid4())
    short_id = uuid.uuid4().hex[:8]
    private_key, public_key = get_xray_keys()

    if not private_key or not public_key:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to generate Xray keys (x25519).")
        return None

    inbound_settings = {
        "clients": [{"id": user_uuid, "flow": "xtls-rprx-vision"}],
        "decryption": "none",
    }
    stream_settings = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "dest": f"{sni}:443",
            "proxyProtocol": 0,
            "serverNames": [sni],
            "privateKey": private_key,
            "shortIds": [short_id],
        },
    }
    sniffing = {"enabled": True, "destOverride": ["http", "tls", "quic"]}

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM inbounds WHERE remark='User-Access'")
            conn.execute(
                "INSERT INTO inbounds (enable, remark, port, protocol, settings, stream_settings, sniffing, tag) VALUES (?,?,?,?,?,?,?,?)",
                (
                    1,
                    "User-Access",
                    port,
                    "vless",
                    json.dumps(inbound_settings),
                    json.dumps(stream_settings),
                    json.dumps(sniffing),
                    f"inbound-{port}",
                ),
            )
            conn.commit()

        my_ip = get_public_ip()
        if not my_ip:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to detect public IP address.")
            return None

        link = (
            f"vless://{user_uuid}@{my_ip}:{port}?encryption=none&security=reality"
            f"&sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp&flow=xtls-rprx-vision#MyCascadeVPN"
        )

        settings["last_client_link"] = link
        settings["actual_port"] = port
        save_settings(settings)
        return link
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create client inbound: {e}")
        return None

def setup_foreign():
    if not ensure_3x_ui():
        return False

    settings = load_settings()
    existing_foreign_link = settings.get("last_foreign_link", "").strip()
    if existing_foreign_link:
        print(f"\n{Colors.GREEN}Foreign server already configured.{Colors.END}")
        print(f"{Colors.YELLOW}Current Foreign link:{Colors.END}\n{existing_foreign_link}\n")
        try:
            sync_mikrotik_bootstrap(parse_foreign_link(existing_foreign_link))
        except Exception as e:
            print(f"{Colors.YELLOW}[WARN]{Colors.END} Could not parse existing Foreign link for MikroTik: {e}")
            log_event("ERROR", f"setup_foreign: parse existing foreign link failed: {e}")
        print_3x_ui_panel_info()
        log_event("INFO", "setup_foreign: already configured, returned existing link")
        return True

    user_uuid = str(uuid.uuid4())
    short_id = uuid.uuid4().hex[:8]
    private_key, public_key = get_xray_keys()

    if not private_key or not public_key:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to generate Xray keys (x25519).")
        log_event("ERROR", "setup_foreign: x25519 key generation failed")
        return False

    inbound_settings = {
        "clients": [{"id": user_uuid, "flow": "xtls-rprx-vision"}],
        "decryption": "none",
    }
    inbound_port = choose_foreign_inbound_port()
    if inbound_port != 443:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Port 443 is busy. Using {inbound_port} for Foreign inbound.")
        log_event("WARN", f"setup_foreign: 443 busy, selected inbound port {inbound_port}")

    stream_settings = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "google.com:443",
            "serverNames": ["google.com"],
            "privateKey": private_key,
            "shortIds": [short_id],
        },
    }

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM inbounds WHERE remark='Cascade-Exit'")
            conn.execute(
                "INSERT INTO inbounds (enable, remark, port, protocol, settings, stream_settings, sniffing, tag) VALUES (?,?,?,?,?,?,?,?)",
                (
                    1,
                    "Cascade-Exit",
                    inbound_port,
                    "vless",
                    json.dumps(inbound_settings),
                    json.dumps(stream_settings),
                    json.dumps({"enabled": True}),
                    f"exit-{inbound_port}",
                ),
            )
            conn.commit()
    except Exception as e:
        print(f"{Colors.RED}[DB ERROR]{Colors.END} {e}")
        log_event("ERROR", f"setup_foreign: db error: {e}")
        return False

    if not run(["x-ui", "restart"], "Restarting 3X-UI"):
        return False

    ip = get_public_ip()
    if not ip:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to detect public server IP.")
        log_event("ERROR", "setup_foreign: public IP detection failed")
        return False

    link = (
        f"vless://{user_uuid}@{ip}:{inbound_port}?encryption=none&security=reality"
        f"&sni=google.com&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp&flow=xtls-rprx-vision#Foreign"
    )

    settings["last_foreign_link"] = link
    save_settings(settings)
    sync_mikrotik_bootstrap(
        {
            "address": ip,
            "port": inbound_port,
            "id": user_uuid,
            "sni": "google.com",
            "pbk": public_key,
            "sid": short_id,
        }
    )

    print(f"\n{Colors.GREEN}Foreign server configured successfully!{Colors.END}")
    print(f"{Colors.YELLOW}Share this link with RU server:{Colors.END}\n{link}\n")
    print_3x_ui_panel_info(ip)
    print()
    log_event("INFO", "setup_foreign: completed")
    return True

def setup_ru():
    if not ensure_3x_ui():
        return False

    settings = load_settings()
    existing_client_link = settings.get("last_client_link", "").strip()
    if existing_client_link:
        print(f"\n{Colors.GREEN}RU bridge already configured.{Colors.END}")
        print_qr(existing_client_link)
        print(f"{Colors.YELLOW}Current client link:{Colors.END} {existing_client_link}")
        existing_foreign_link = settings.get("last_foreign_link", "").strip()
        if existing_foreign_link:
            try:
                sync_mikrotik_bootstrap(parse_foreign_link(existing_foreign_link))
            except Exception as e:
                print(f"{Colors.YELLOW}[WARN]{Colors.END} Could not parse saved Foreign link for MikroTik: {e}")
                log_event("ERROR", f"setup_ru: parse saved foreign link failed: {e}")
        else:
            foreign_from_db = extract_foreign_from_xray_config_db()
            if foreign_from_db:
                print(f"{Colors.CYAN}[INFO]{Colors.END} Foreign link not saved; using values from current xrayConfig.")
                sync_mikrotik_bootstrap(foreign_from_db)
            else:
                print(f"{Colors.YELLOW}[WARN]{Colors.END} Foreign link is not saved and xrayConfig has no proxy values.")
                print(f"{Colors.YELLOW}[WARN]{Colors.END} MikroTik file generation skipped.")
        print_3x_ui_panel_info()
        log_event("INFO", "setup_ru: already configured, returned existing link")
        return True

    foreign_link = input(f"\n{Colors.CYAN}Paste VLESS link from Foreign server: {Colors.END}").strip()
    try:
        foreign = parse_foreign_link(foreign_link)
        routes = load_routes()
        traffic_logging_enabled = settings.get("traffic_logging_enabled", False)
        xray_config = build_routing(foreign, routes, traffic_logging_enabled)
        if not validate_xray_config_with_xray(xray_config):
            return False

        with sqlite3.connect(DB_PATH) as conn:
            backup_path = backup_current_xray_config(conn)
            if backup_path:
                print(f"{Colors.CYAN}[...]{Colors.END} xrayConfig backup: {backup_path}")
            cur = conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'xrayConfig'",
                (json.dumps(xray_config),),
            )
            if cur.rowcount == 0:
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    ("xrayConfig", json.dumps(xray_config)),
                )
            conn.commit()

        link = create_client_inbound()
        if not link:
            log_event("ERROR", "setup_ru: create_client_inbound failed")
            return False

        if not run(["x-ui", "restart"], "Restarting 3X-UI"):
            return False

        sync_mikrotik_bootstrap(foreign)
        print(f"\n{Colors.GREEN}RU bridge configured successfully!{Colors.END}")
        print_qr(link)
        print(f"{Colors.YELLOW}Client link:{Colors.END} {link}")
        print_3x_ui_panel_info()
        log_routing_config(routes, foreign)
        log_event("INFO", f"setup_ru: completed, traffic_logging={traffic_logging_enabled}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} {e}")
        log_event("ERROR", f"setup_ru: exception: {e}", with_traceback=True)
        return False

def edit_routes_file():
    try:
        routes = load_routes()
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to load routes: {e}")
        log_event("ERROR", f"edit_routes_file: load failed: {e}")
        return False

    print(f"\nRoutes file: {ROUTES_STORE}")
    print(json.dumps(routes, ensure_ascii=False, indent=2))
    print("\nEdit JSON and save. Only string entries without spaces are allowed.")

    answer = input("Open file in editor now? [Y/n]: ").strip().lower()
    if answer not in ("", "y", "yes", "д", "да"):
        return True

    editor = os.environ.get("EDITOR", "nano")
    cmd = shlex.split(editor) + [ROUTES_STORE]
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print(f"{Colors.RED}[ERROR]{Colors.END} Editor '{editor}' not found.")
        log_event("ERROR", f"edit_routes_file: editor not found: {editor}")
        return False

    try:
        new_routes = load_routes()
        print(f"{Colors.GREEN}Routes saved and validated.{Colors.END}")
        log_event("INFO", "edit_routes_file: updated")
        log_routing_config(new_routes)
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Invalid routes JSON: {e}")
        log_event("ERROR", f"edit_routes_file: invalid JSON: {e}")
        return False


# --- Main menu ---
def regenerate_client_link():
    if not ensure_3x_ui():
        return False
    link = create_client_inbound()
    if not link:
        return False
    if not run(["x-ui", "restart"], "Restarting 3X-UI"):
        return False
    print_qr(link)
    print(f"\n{Colors.YELLOW}New client link:{Colors.END} {link}")
    print_3x_ui_panel_info()
    return True

def update_client_settings():
    settings = load_settings()
    port_input = input(f"Port [{settings['client_port']}] (or 'auto'): ").strip()
    if port_input:
        try:
            settings["client_port"] = parse_port_setting(port_input)
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} {e}")
            log_event("ERROR", f"update_client_settings: invalid port: {e}")
            return False

    sni_input = input(f"SNI [{settings['client_sni']}]: ").strip()
    if sni_input:
        if valid_hostname(sni_input):
            settings["client_sni"] = sni_input
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Invalid SNI")
            log_event("ERROR", "update_client_settings: invalid SNI")
            return False

    save_settings(settings)
    return True


def update_panel_credentials():
    if not ensure_3x_ui():
        return False

    current_user, _ = get_3x_ui_panel_credentials()
    username = input(f"Panel login [{current_user}]: ").strip() or current_user
    if not username:
        print(f"{Colors.RED}[ERROR]{Colors.END} Login must not be empty.")
        return False

    password = input("New panel password (leave empty to auto-generate): ").strip()
    if not password:
        _, password = generate_panel_credentials()
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Generated new password: {password}")
    elif password.startswith("-"):
        print(f"{Colors.RED}[ERROR]{Colors.END} Password must not start with '-' (CLI compatibility).")
        return False
    log_event("INFO", f"update_panel_credentials: requested username={username} password_len={len(password)}")

    if not apply_3x_ui_panel_credentials(username, password):
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to update panel credentials.")
        log_event("ERROR", "update_panel_credentials: apply failed")
        return False

    settings = load_settings()
    settings["panel_username"] = username
    settings["panel_password"] = password
    save_settings(settings)

    restarted = run(["x-ui", "restart"], "Restarting 3X-UI")
    log_event("INFO", f"update_panel_credentials: x-ui restart status={restarted}")
    print(f"{Colors.GREEN}[DONE]{Colors.END} Panel credentials updated.")
    print_3x_ui_panel_info()
    log_event("INFO", "update_panel_credentials: updated")
    return True


def view_log_file():
    if not os.path.exists(LOG_PATH):
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Log file not found: {LOG_PATH}")
        return True

    tail_raw = input("How many last log lines to show? [200]: ").strip()
    try:
        tail_n = int(tail_raw) if tail_raw else 200
        if tail_n < 1:
            raise ValueError
    except ValueError:
        print(f"{Colors.RED}[ERROR]{Colors.END} Invalid line count")
        return False

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        print(f"\n{Colors.CYAN}=== Last {min(tail_n, len(lines))} lines from {LOG_PATH} ==={Colors.END}")
        for line in lines[-tail_n:]:
            print(line.rstrip("\n"))
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to read log: {e}")
        log_event("ERROR", f"view_log_file: read failed: {e}")
        return False


def view_traffic_log():
    """View and analyze Xray traffic access log to understand routing decisions."""
    settings = load_settings()
    traffic_logging_enabled = settings.get("traffic_logging_enabled", False)
    
    if not traffic_logging_enabled:
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Traffic logging is currently DISABLED.")
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Enable it via menu 10 to start logging traffic.")
        return True

    if not os.path.exists(TRAFFIC_LOG_PATH):
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Traffic log file not found: {TRAFFIC_LOG_PATH}")
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Traffic logging is enabled but no log file exists yet.")
        print(f"{Colors.YELLOW}[INFO]{Colors.END} This may happen if Xray was just restarted or no traffic has been logged.")
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Wait for some traffic to be generated and try again.")
        return True

    tail_raw = input("How many last traffic log lines to show? [100]: ").strip()
    try:
        tail_n = int(tail_raw) if tail_raw else 100
        if tail_n < 1:
            raise ValueError
    except ValueError:
        print(f"{Colors.RED}[ERROR]{Colors.END} Invalid line count")
        return False

    try:
        with open(TRAFFIC_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        
        if not lines:
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Traffic log is empty. No traffic recorded yet.")
            return True

        print(f"\n{Colors.CYAN}=== Last {min(tail_n, len(lines))} lines from {TRAFFIC_LOG_PATH} ==={Colors.END}")
        print(f"{Colors.CYAN}Format: timestamp username@source_ip:port accepted destination -> outbound_tag{Colors.END}")
        print(f"{Colors.GREEN}direct{Colors.END} = routed directly (no proxy)")
        print(f"{Colors.YELLOW}proxy{Colors.END} = routed through foreign proxy")
        print("-" * 80)
        
        # Parse and display traffic logs
        direct_count = 0
        proxy_count = 0
        for line in lines[-tail_n:]:
            line_stripped = line.rstrip("\n")
            # Colorize based on outbound tag
            if "direct" in line_stripped.lower():
                direct_count += 1
                # Highlight direct routes in green
                print(f"{Colors.GREEN}{line_stripped}{Colors.END}")
            elif "proxy" in line_stripped.lower() or "vless" in line_stripped.lower():
                proxy_count += 1
                # Highlight proxy routes in yellow
                print(f"{Colors.YELLOW}{line_stripped}{Colors.END}")
            else:
                print(line_stripped)
        
        # Show summary
        total_shown = min(tail_n, len(lines))
        print("-" * 80)
        print(f"{Colors.CYAN}Summary (last {total_shown} entries):{Colors.END}")
        print(f"  {Colors.GREEN}Direct routes:{Colors.END} {direct_count}")
        print(f"  {Colors.YELLOW}Proxy routes:{Colors.END} {proxy_count}")
        print(f"  Total: {direct_count + proxy_count}")
        
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to read traffic log: {e}")
        log_event("ERROR", f"view_traffic_log: read failed: {e}")
        return False


def toggle_traffic_logging():
    """Enable or disable traffic logging."""
    settings = load_settings()
    current_status = settings.get("traffic_logging_enabled", False)
    
    print(f"\nCurrent traffic logging status: {Colors.GREEN if current_status else Colors.RED}{ 'ENABLED' if current_status else 'DISABLED' }{Colors.END}")
    print(f"{Colors.YELLOW}[WARN]{Colors.END} Traffic logs can grow large and consume disk space.")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Enable logging only when diagnosing routing issues.")
    
    choice = input(f"\nToggle traffic logging? [Y/n]: ").strip().lower()
    if choice in ("", "y", "yes", "д", "да"):
        new_status = not current_status
        settings["traffic_logging_enabled"] = new_status
        save_settings(settings)
        
        status_text = f"{Colors.GREEN}ENABLED{Colors.END}" if new_status else f"{Colors.RED}DISABLED{Colors.END}"
        print(f"{Colors.GREEN}[INFO]{Colors.END} Traffic logging is now {status_text}")
        log_event("INFO", f"toggle_traffic_logging: traffic_logging_enabled={new_status}")
        
        # Automatically restart Xray to apply the change
        if not is_3x_ui_present():
            print(f"{Colors.YELLOW}[WARN]{Colors.END} 3X-UI is not installed. Restart Xray manually to apply changes.")
            return True
        
        print(f"{Colors.CYAN}[INFO]{Colors.END} Restarting Xray service to apply changes...")
        if restart_xray_service():
            if new_status:
                print(f"{Colors.GREEN}[DONE]{Colors.END} Traffic logging is now active. View logs via Menu 9.")
            else:
                print(f"{Colors.GREEN}[DONE]{Colors.END} Traffic logging is now disabled.")
        else:
            print(f"{Colors.YELLOW}[WARN]{Colors.END} Failed to restart Xray. Restart manually via Menu 11.")
        
        return True
    else:
        print("Toggle cancelled.")
        return True


def restart_xray_service():
    """Restart Xray/3x-ui service to apply configuration changes."""
    if not is_3x_ui_present():
        print(f"{Colors.RED}[ERROR]{Colors.END} 3X-UI is not installed or not running.")
        return False
    
    settings = load_settings()
    traffic_logging_enabled = settings.get("traffic_logging_enabled", False)
    
    # Create traffic log file if it doesn't exist and logging is enabled
    if traffic_logging_enabled and not os.path.exists(TRAFFIC_LOG_PATH):
        try:
            log_dir = os.path.dirname(TRAFFIC_LOG_PATH)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            # Create empty log file with proper permissions
            with open(TRAFFIC_LOG_PATH, "a", encoding="utf-8") as f:
                pass
            try:
                os.chmod(TRAFFIC_LOG_PATH, 0o644)
            except OSError:
                pass
            log_event("INFO", f"restart_xray_service: created traffic log file {TRAFFIC_LOG_PATH}")
            print(f"{Colors.CYAN}[INFO]{Colors.END} Created traffic log file: {TRAFFIC_LOG_PATH}")
        except Exception as e:
            log_event("ERROR", f"restart_xray_service: failed to create traffic log file: {e}")
            print(f"{Colors.YELLOW}[WARN]{Colors.END} Failed to create traffic log file: {e}")
    
    # Try to update xrayConfig with current traffic logging setting
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("SELECT value FROM settings WHERE key = 'xrayConfig' LIMIT 1")
            row = cur.fetchone()
            if row and row[0]:
                try:
                    xray_config = json.loads(row[0])
                    # Update log configuration based on current setting
                    if traffic_logging_enabled:
                        xray_config["log"] = {
                            "access": TRAFFIC_LOG_PATH,
                            "error": "/var/log/xray-error.log",
                            "loglevel": "info"
                        }
                        log_event("INFO", f"restart_xray_service: added log config with path={TRAFFIC_LOG_PATH}")
                    elif "log" in xray_config:
                        # Remove log configuration if traffic logging is disabled
                        del xray_config["log"]
                        log_event("INFO", "restart_xray_service: removed log config from xrayConfig")
                    
                    # Save updated config
                    conn.execute(
                        "UPDATE settings SET value = ? WHERE key = 'xrayConfig'",
                        (json.dumps(xray_config),),
                    )
                    conn.commit()
                    log_event("INFO", f"restart_xray_service: updated xrayConfig with traffic_logging={traffic_logging_enabled}")
                    print(f"{Colors.CYAN}[INFO]{Colors.END} Updated Xray configuration (traffic logging: {Colors.GREEN if traffic_logging_enabled else Colors.RED}{'enabled' if traffic_logging_enabled else 'disabled'}{Colors.END})")
                    if traffic_logging_enabled:
                        print(f"{Colors.CYAN}[INFO]{Colors.END} Traffic will be logged to: {TRAFFIC_LOG_PATH}")
                except json.JSONDecodeError as e:
                    log_event("ERROR", f"restart_xray_service: failed to parse xrayConfig: {e}")
                    print(f"{Colors.YELLOW}[WARN]{Colors.END} Could not update Xray configuration, will just restart service.")
            else:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} No xrayConfig found in database, will just restart service.")
                log_event("INFO", "restart_xray_service: no xrayConfig found in database")
    except Exception as e:
        log_event("ERROR", f"restart_xray_service: failed to update xrayConfig: {e}")
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Could not update Xray configuration, will just restart service.")
    
    print(f"{Colors.CYAN}[INFO]{Colors.END} Restarting Xray/3x-ui service...")
    
    if run(["x-ui", "restart"], "Restarting 3X-UI"):
        print(f"{Colors.GREEN}[DONE]{Colors.END} Xray/3x-ui service restarted successfully.")
        log_event("INFO", "restart_xray_service: service restarted")
        if traffic_logging_enabled:
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Generate some VPN traffic and check log file: {TRAFFIC_LOG_PATH}")
        return True
    else:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to restart Xray/3x-ui service.")
        log_event("ERROR", "restart_xray_service: restart failed")
        return False


def analyze_routing():
    """Analyze current routing configuration and test how domains are routed."""
    routes = load_routes()
    
    print(f"\n{Colors.CYAN}=== Current Routing Configuration ==={Colors.END}")
    print(f"\n{Colors.GREEN}Direct (no proxy):{Colors.END}")
    print(f"  Domains ({len(routes.get('direct_domains', []))}):")
    for domain in routes.get("direct_domains", []):
        print(f"    - {domain}")
    print(f"  IPs ({len(routes.get('direct_ips', []))}):")
    for ip in routes.get("direct_ips", []):
        print(f"    - {ip}")
    
    print(f"\n{Colors.YELLOW}Proxy (through Foreign server):{Colors.END}")
    print(f"  Domains ({len(routes.get('proxy_domains', []))}):")
    for domain in routes.get("proxy_domains", []):
        print(f"    - {domain}")
    print(f"  IPs ({len(routes.get('proxy_ips', []))}):")
    for ip in routes.get("proxy_ips", []):
        print(f"    - {ip}")
    
    print(f"\n{Colors.CYAN}=== Routing Logic ==={Colors.END}")
    print("1. Direct rules are checked first")
    print("2. If domain/IP matches a direct rule → routed directly (green)")
    print("3. If domain/IP matches a proxy rule → routed through proxy (yellow)")
    print("4. If no rules match → routed through proxy (fallback)")
    
    print(f"\n{Colors.CYAN}=== Common Issues ==={Colors.END}")
    print(f"{Colors.YELLOW}Issue:{Colors.END} Foreign sites going directly instead of through proxy")
    print(f"{Colors.CYAN}Possible causes:{Colors.END}")
    print("  1. Domain is in direct_domains list")
    print("  2. Domain matches a regex pattern in direct_domains")
    print("  3. Domain's IP is in direct_ips list (geoip:ru, geoip:private)")
    print("  4. Fallback rule is routing to proxy instead of direct")
    print(f"\n{Colors.CYAN}Solution:{Colors.END}")
    print("  1. Remove domain from direct_domains if it should go through proxy")
    print("  2. Add domain to proxy_domains if it should go through proxy")
    print("  3. Check traffic log (Menu 9) to see actual routing")
    
    log_event("INFO", f"analyze_routing: displayed current routing configuration")
    return True


def reset_cascade_state():
    print(f"{Colors.YELLOW}[WARN]{Colors.END} FULL RESET will remove all configuration and installed components from this script.")
    print("- remove inbounds and xrayConfig changes from x-ui DB (if present)")
    print("- uninstall 3x-ui (best effort)")
    print("- stop/disable x-ui and xray services")
    print("- remove files: /etc/x-ui, /usr/local/x-ui, routes/settings/logs")
    print(f"- keep backups: {BACKUP_DIR}")
    print("- remove Python deps installed by script: qrcode, pillow")
    print("- remove apt dependency installed by script: python3-pip")
    confirm = input("Type RESET ALL to continue: ").strip()
    if confirm != "RESET ALL":
        print("Full reset cancelled.")
        return False

    deleted_inbounds = 0
    uninstalled_3xui = False

    if os.path.exists(DB_PATH):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute("DELETE FROM inbounds WHERE remark IN ('Cascade-Exit','User-Access')")
                deleted_inbounds = cur.rowcount if cur.rowcount is not None else 0
                conn.execute("DELETE FROM settings WHERE key = 'xrayConfig'")
                conn.commit()
        except Exception as e:
            log_event("ERROR", f"reset_cascade_state: DB cleanup failed: {e}", with_traceback=True)

    # Stop services before uninstall/removal.
    run(["systemctl", "stop", "x-ui"], "Stopping x-ui service", stream=True)
    run(["systemctl", "disable", "x-ui"], "Disabling x-ui service", stream=True)
    run(["systemctl", "stop", "xray"], "Stopping xray service", stream=True)
    run(["systemctl", "disable", "xray"], "Disabling xray service", stream=True)

    # Best-effort official uninstall commands.
    for xui_bin in find_xui_binaries():
        for cmd in ([xui_bin, "uninstall"], [xui_bin, "remove"], [xui_bin, "del"]):
            proc = subprocess.run(cmd, input="y\n", check=False, capture_output=True, text=True)
            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            log_event("INFO", f"reset_cascade_state: try {' '.join(cmd)} rc={proc.returncode} output={output[:300]}")
            if proc.returncode == 0:
                uninstalled_3xui = True
                break
        if uninstalled_3xui:
            break

    # Remove known files/directories.
    for path in (
        "/etc/x-ui",
        "/usr/local/x-ui",
        "/etc/vless-cascade/routes.json",
    ):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.isfile(path):
                os.remove(path)
        except Exception as e:
            log_event("WARN", f"reset_cascade_state: failed to remove dir {path}: {e}")

    for path in (
        CONFIG_STORE,
        DB_PATH,
        LOG_PATH,
        TRAFFIC_LOG_PATH,
        "/var/log/xray-error.log",
        "/usr/bin/x-ui",
        "/usr/local/bin/x-ui",
        "/etc/systemd/system/x-ui.service",
    ):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            log_event("WARN", f"reset_cascade_state: failed to remove file {path}: {e}")

    run(["systemctl", "daemon-reload"], "Reloading systemd units", stream=True)

    # Remove dependencies installed by this script (best effort).
    run([sys.executable, "-m", "pip", "uninstall", "-y", "qrcode", "pillow"], "Removing Python deps (qrcode/pillow)", stream=True)
    run(["apt-get", "remove", "-y", "python3-pip"], "Removing python3-pip", stream=True)
    run(["apt-get", "autoremove", "-y"], "Autoremove unused packages", stream=True)

    print(f"{Colors.GREEN}[DONE]{Colors.END} Full reset complete.")
    print(f"Removed inbounds from DB: {deleted_inbounds}")
    print(f"3x-ui uninstall command succeeded: {'yes' if uninstalled_3xui else 'no (manual cleanup applied)'}")
    log_event("INFO", f"reset_cascade_state: full reset done deleted_inbounds={deleted_inbounds} uninstall_ok={uninstalled_3xui}")
    return True


def main():
    if os.getuid() != 0:
        sys.exit("Run with sudo")

    log_event("INFO", "script started")

    while True:
        settings = load_settings()
        os.system("clear")
        print(f"{Colors.CYAN}=== VPN Cascade Automator ==={Colors.END}")
        print(f"Configured client port: {settings['client_port']} | SNI: {settings['client_sni']}")
        if settings.get("actual_port"):
            print(f"Current active port: {Colors.GREEN}{settings['actual_port']}{Colors.END}")
        print(f"Routes file: {ROUTES_STORE}")
        print(f"Logs: {LOG_PATH}")
        traffic_logging_status = settings.get("traffic_logging_enabled", False)
        status_color = Colors.GREEN if traffic_logging_status else Colors.RED
        status_text = "ENABLED" if traffic_logging_status else "DISABLED"
        print(f"Traffic logging: {status_color}{status_text}{Colors.END} ({TRAFFIC_LOG_PATH})")
        if SAFE_MODE:
            print(f"{Colors.YELLOW}[SAFE MODE]{Colors.END} Auto-install of dependencies is disabled")
            if qrcode is None:
                print(f"{Colors.YELLOW}[SAFE MODE]{Colors.END} QR code unavailable (qrcode module missing)")
        print("-" * 40)
        print("1. [Foreign] Configure exit server")
        print("2. [RU Server] Configure bridge (cascade)")
        print("3. [RU Server] Regenerate client QR and link")
        print("4. Update client settings (port / SNI)")
        print("5. Edit routes (JSON)")
        print("6. Apply route profile")
        print("7. Rollback xrayConfig from backup")
        print("8. View logs")
        print("9. View traffic routing log")
        print("10. Toggle traffic logging (enable/disable)")
        print("11. Analyze routing configuration")
        print("12. Restart Xray service (apply changes)")
        print("13. Exit")
        print("14. Change 3x-ui panel login/password")
        print("15. Full reset (menu 1/2 changes)")

        choice = input("\nSelect: ").strip()

        if choice == "1":
            execute_menu_action("Menu 1: Configure Foreign server", setup_foreign)
        elif choice == "2":
            execute_menu_action("Menu 2: Configure RU bridge", setup_ru)
        elif choice == "3":
            execute_menu_action("Menu 3: Regenerate client link", regenerate_client_link)
        elif choice == "4":
            execute_menu_action("Menu 4: Update client settings", update_client_settings)
        elif choice == "5":
            execute_menu_action("Menu 5: Edit routes", edit_routes_file)
        elif choice == "6":
            execute_menu_action("Menu 6: Apply route profile", apply_route_profile)
        elif choice == "7":
            execute_menu_action("Menu 7: Rollback xrayConfig", rollback_xray_config)
        elif choice == "8":
            execute_menu_action("Menu 8: View logs", view_log_file)
        elif choice == "9":
            execute_menu_action("Menu 9: View traffic routing log", view_traffic_log)
        elif choice == "10":
            execute_menu_action("Menu 10: Toggle traffic logging", toggle_traffic_logging)
        elif choice == "11":
            execute_menu_action("Menu 11: Analyze routing configuration", analyze_routing)
        elif choice == "12":
            execute_menu_action("Menu 12: Restart Xray service", restart_xray_service)
        elif choice == "13":
            log_event("INFO", "script stopped by user")
            break
        elif choice == "14":
            execute_menu_action("Menu 14: Change 3x-ui panel credentials", update_panel_credentials)
        elif choice == "15":
            execute_menu_action("Menu 15: Full reset of menu 1/2 state", reset_cascade_state)
        else:
            print("Unknown menu option")
            log_event("WARN", f"unknown menu choice: {choice}")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
