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
XRAY_BIN = "/usr/local/x-ui/bin/xray"
XUI_INSTALL_URL = "https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"

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


def find_xui_binary():
    candidates = [
        shutil.which("x-ui"),
        "/usr/local/x-ui/x-ui",
        "/usr/bin/x-ui",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


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
    return username, password


def apply_3x_ui_panel_credentials(username, password):
    xui_cmd = find_xui_binary()
    if not xui_cmd:
        log_event("ERROR", "apply_3x_ui_panel_credentials: x-ui command not found")
        return False

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
                        return True
        except Exception:
            return False
        return False

    attempts = [
        {
            "cmd": [xui_cmd, "setting", "-username", username, "-password", password],
            "input": None,
            "label": "flags",
        },
        {
            "cmd": [xui_cmd, "setting"],
            "input": f"{username}\n{password}\n",
            "label": "interactive",
        },
    ]

    for attempt in attempts:
        proc = subprocess.run(
            attempt["cmd"],
            input=attempt["input"],
            check=False,
            capture_output=True,
            text=True,
        )
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode != 0:
            log_event("WARN", f"apply_3x_ui_panel_credentials: {attempt['label']} failed: {output}")
            continue
        if "flag provided but not defined" in output.lower() or "unknown" in output.lower():
            log_event("WARN", f"apply_3x_ui_panel_credentials: {attempt['label']} unsupported syntax: {output}")
            continue
        if db_has_username(username):
            return True
        # If DB validation is unavailable, still accept successful process.
        if "error" not in output.lower():
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
        log_event("ERROR", "get_xray_keys: xray binary not found")
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
    return re.match(r"^[A-Za-z0-9:._*/-]+$", value) is not None


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

def build_routing(foreign, routes):
    rules = []

    if routes["direct_domains"]:
        rules.append({"type": "field", "outboundTag": "direct", "domain": routes["direct_domains"]})
    if routes["direct_ips"]:
        rules.append({"type": "field", "outboundTag": "direct", "ip": routes["direct_ips"]})
    if routes["proxy_domains"]:
        rules.append({"type": "field", "outboundTag": "proxy", "domain": routes["proxy_domains"]})
    if routes["proxy_ips"]:
        rules.append({"type": "field", "outboundTag": "proxy", "ip": routes["proxy_ips"]})

    # Fallback: everything else goes through foreign proxy.
    rules.append({"type": "field", "outboundTag": "proxy", "network": "tcp,udp"})

    return {
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


def is_3x_ui_present():
    xui_cmd = shutil.which("x-ui")
    xray_cmd = shutil.which("xray")
    has_db = os.path.exists(DB_PATH)
    has_xray = os.path.exists(XRAY_BIN) or (xray_cmd is not None)
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


def ensure_3x_ui():
    if is_3x_ui_present():
        return True

    answer = input("3X-UI is not installed. Install now? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes", "Рґ", "РґР°"):
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
        print_3x_ui_panel_info()
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
            conn.execute("DELETE FROM inbounds WHERE port=443")
            conn.execute(
                "INSERT INTO inbounds (enable, remark, port, protocol, settings, stream_settings, sniffing, tag) VALUES (?,?,?,?,?,?,?,?)",
                (
                    1,
                    "Cascade-Exit",
                    443,
                    "vless",
                    json.dumps(inbound_settings),
                    json.dumps(stream_settings),
                    json.dumps({"enabled": True}),
                    "exit-443",
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
        f"vless://{user_uuid}@{ip}:443?encryption=none&security=reality"
        f"&sni=google.com&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp&flow=xtls-rprx-vision#Foreign"
    )

    settings["last_foreign_link"] = link
    save_settings(settings)

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
        print_3x_ui_panel_info()
        return True

    foreign_link = input(f"\n{Colors.CYAN}Paste VLESS link from Foreign server: {Colors.END}").strip()
    try:
        foreign = parse_foreign_link(foreign_link)
        routes = load_routes()
        xray_config = build_routing(foreign, routes)
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

        print(f"\n{Colors.GREEN}RU bridge configured successfully!{Colors.END}")
        print_qr(link)
        print(f"{Colors.YELLOW}Client link:{Colors.END} {link}")
        print_3x_ui_panel_info()
        log_event("INFO", "setup_ru: completed")
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
        load_routes()
        print(f"{Colors.GREEN}Routes saved and validated.{Colors.END}")
        log_event("INFO", "edit_routes_file: updated")
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

    if not apply_3x_ui_panel_credentials(username, password):
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to update panel credentials.")
        log_event("ERROR", "update_panel_credentials: apply failed")
        return False

    settings = load_settings()
    settings["panel_username"] = username
    settings["panel_password"] = password
    save_settings(settings)

    run(["x-ui", "restart"], "Restarting 3X-UI")
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
        print("9. Exit")
        print("10. Change 3x-ui panel login/password")

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
            log_event("INFO", "script stopped by user")
            break
        elif choice == "10":
            execute_menu_action("Menu 10: Change 3x-ui panel credentials", update_panel_credentials)
        else:
            print("Unknown menu option")
            log_event("WARN", f"unknown menu choice: {choice}")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()


