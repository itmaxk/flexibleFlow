#!/usr/bin/env python3
import ipaddress
import json
import os
import re
import shlex
import socket
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import uuid

# --- Runtime mode ---
SAFE_MODE = "--safe" in sys.argv or os.environ.get("VLESS_CASCADE_SAFE_MODE") == "1"


# --- Auto-install optional dependencies ---
def install_deps():
    print("Проверка и установка зависимостей (qrcode)...")
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
def run(cmd, desc=None):
    if desc:
        print(f"{Colors.CYAN}[...]{Colors.END} {desc}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        err = (e.stderr or e.stdout or "").strip()
        print(f"{Colors.RED}[Ошибка]{Colors.END} {err}")
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


def validate_xray_config_with_xray(config_obj):
    if not os.path.exists(XRAY_BIN):
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Xray binary не найден: {XRAY_BIN}. Проверка xray -test пропущена.")
        return True

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".json") as tmp:
            json.dump(config_obj, tmp)
            tmp_path = tmp.name

        proc = subprocess.run(
            [XRAY_BIN, "run", "-test", "-config", tmp_path],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            print(f"{Colors.RED}[Ошибка]{Colors.END} xray -test не пройден: {err}")
            return False
        return True
    except Exception as e:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось выполнить xray -test: {e}")
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


def get_xray_keys():
    try:
        out = subprocess.check_output([XRAY_BIN, "x25519"], text=True)
        priv = re.search(r"Private key: (.*)", out).group(1).strip()
        pub = re.search(r"Public key: (.*)", out).group(1).strip()
        return priv, pub
    except Exception:
        return None, None


def print_qr(data):
    if qrcode is None:
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Модуль qrcode не установлен, вывод QR пропущен.")
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
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Файл {path} поврежден. Используются значения по умолчанию.")
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
            raise ValueError(f"Поле '{key}' должно быть списком")
        for item in items:
            if not validate_route_item(item):
                raise ValueError(f"Недопустимое значение в '{key}': {item}")


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
    print("\nДоступные профили маршрутов:")
    print("1. RU only direct (recommended)")
    print("2. Mixed (RU + Telegram direct)")
    print("3. Full proxy (only private direct)")
    choice = input("Выберите профиль [1-3]: ").strip()
    profile = ROUTE_PROFILES.get(choice)
    if not profile:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Неизвестный профиль")
        return
    save_json(ROUTES_STORE, profile["routes"])
    print(f"{Colors.GREEN}Применен профиль:{Colors.END} {profile['name']}")


def load_settings():
    defaults = {
        "client_port": "auto",
        "client_sni": "google.com",
        "last_client_link": "",
        "actual_port": None,
    }
    return load_json(CONFIG_STORE, defaults)


def save_settings(settings):
    save_json(CONFIG_STORE, settings)


def parse_port_setting(value):
    if value == "auto":
        return "auto"
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("Порт должен быть в диапазоне 1..65535")
    return str(port)


def parse_foreign_link(link):
    parsed = urllib.parse.urlparse(link)
    if parsed.scheme != "vless":
        raise ValueError("Ссылка должна начинаться с vless://")
    if not parsed.username:
        raise ValueError("В ссылке отсутствует UUID пользователя")

    try:
        uuid.UUID(parsed.username)
    except ValueError:
        raise ValueError("UUID в ссылке Foreign некорректен")

    if not parsed.hostname:
        raise ValueError("В ссылке отсутствует адрес сервера")

    port = parsed.port or 443
    if port < 1 or port > 65535:
        raise ValueError("Некорректный порт в ссылке Foreign")

    query = urllib.parse.parse_qs(parsed.query)
    required = ("sni", "pbk", "sid")
    for key in required:
        if key not in query or not query[key] or not query[key][0].strip():
            raise ValueError(f"В ссылке отсутствует параметр '{key}'")

    sni = query["sni"][0].strip()
    pbk = query["pbk"][0].strip()
    sid = query["sid"][0].strip()

    if not valid_hostname(sni):
        raise ValueError("Некорректный SNI в ссылке Foreign")
    if re.match(r"^[A-Za-z0-9_-]{20,}$", pbk) is None:
        raise ValueError("Некорректный public key (pbk) в ссылке Foreign")
    if re.match(r"^[0-9a-fA-F]{1,16}$", sid) is None:
        raise ValueError("Некорректный short id (sid) в ссылке Foreign")

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
    return os.path.exists(DB_PATH) and os.path.exists(XRAY_BIN)


def install_3x_ui():
    try:
        script_text = fetch_text(XUI_INSTALL_URL, timeout=30)
    except Exception as e:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось скачать установщик 3x-ui: {e}")
        return False

    script_path = "/tmp/3x-ui-install.sh"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_text)
    os.chmod(script_path, 0o700)

    ok = run(["bash", script_path], "Установка 3X-UI")

    try:
        os.remove(script_path)
    except OSError:
        pass

    return ok


def ensure_3x_ui():
    if is_3x_ui_present():
        return True

    answer = input("3X-UI не найден. Установить сейчас? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes", "д", "да"):
        if install_3x_ui() and is_3x_ui_present():
            return True
        print(f"{Colors.RED}[Ошибка]{Colors.END} 3X-UI не установлен или установлен некорректно.")
        return False

    print(f"{Colors.YELLOW}[INFO]{Colors.END} Установка 3X-UI пропущена пользователем.")
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
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Бэкапы не найдены: {BACKUP_DIR}")
        return

    print("\nОткат xrayConfig из бэкапа")
    print("1. Восстановить последний бэкап")
    print("2. Выбрать из списка")
    choice = input("Выбор [1-2]: ").strip()

    backup_path = None
    if choice == "1":
        backup_path = backups[0]
    elif choice == "2":
        print("\nДоступные бэкапы:")
        for idx, path in enumerate(backups, start=1):
            print(f"{idx}. {path}")
        index_raw = input("Номер бэкапа: ").strip()
        try:
            index = int(index_raw)
            if index < 1 or index > len(backups):
                raise ValueError
            backup_path = backups[index - 1]
        except Exception:
            print(f"{Colors.RED}[Ошибка]{Colors.END} Некорректный номер бэкапа")
            return
    else:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Неизвестный пункт")
        return

    confirm = input(f"Восстановить из {backup_path}? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes", "д", "да"):
        print("Откат отменен.")
        return

    try:
        raw = open(backup_path, "r", encoding="utf-8").read()
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Формат должен быть JSON-объектом")
        if "routing" not in parsed or "outbounds" not in parsed:
            raise ValueError("В бэкапе отсутствуют ключи routing/outbounds")
    except Exception as e:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Бэкап невалиден: {e}")
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
        print(f"{Colors.RED}[Ошибка БД]{Colors.END} {e}")
        return

    if not run(["x-ui", "restart"], "Перезапуск 3X-UI после отката"):
        return
    print(f"{Colors.GREEN}Откат xrayConfig выполнен успешно.{Colors.END}")


# --- 3X-UI database operations ---
def create_client_inbound():
    settings = load_settings()

    try:
        if settings["client_port"] == "auto":
            port = find_free_port()
            print(f"{Colors.YELLOW}Автоматически выбран свободный порт: {port}{Colors.END}")
        else:
            port = int(settings["client_port"])
            if port < 1 or port > 65535:
                raise ValueError("Некорректный порт")
    except Exception:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Некорректный client_port в настройках. Используется auto.")
        port = find_free_port()
        settings["client_port"] = "auto"

    sni = settings.get("client_sni", "google.com")
    if not valid_hostname(sni):
        print(f"{Colors.YELLOW}[WARN]{Colors.END} Некорректный SNI в настройках. Используется google.com")
        sni = "google.com"
        settings["client_sni"] = sni

    user_uuid = str(uuid.uuid4())
    short_id = uuid.uuid4().hex[:8]
    private_key, public_key = get_xray_keys()

    if not private_key or not public_key:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось получить ключи Xray (x25519).")
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
            print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось определить публичный IP сервера.")
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
        print(f"{Colors.RED}[Ошибка БД]{Colors.END} {e}")
        return None


# --- Scenarios ---
def setup_foreign():
    if not ensure_3x_ui():
        return

    user_uuid = str(uuid.uuid4())
    short_id = uuid.uuid4().hex[:8]
    private_key, public_key = get_xray_keys()

    if not private_key or not public_key:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось получить ключи Xray (x25519).")
        return

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
        print(f"{Colors.RED}[Ошибка БД]{Colors.END} {e}")
        return

    if not run(["x-ui", "restart"], "Перезапуск 3X-UI"):
        return

    ip = get_public_ip()
    if not ip:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось определить публичный IP сервера.")
        return

    link = (
        f"vless://{user_uuid}@{ip}:443?encryption=none&security=reality"
        f"&sni=google.com&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp&flow=xtls-rprx-vision#Foreign"
    )

    print(f"\n{Colors.GREEN}Иностранный сервер настроен!{Colors.END}")
    print(f"{Colors.YELLOW}Ссылка для RU сервера:{Colors.END}\n{link}\n")


def setup_ru():
    if not ensure_3x_ui():
        return

    foreign_link = input(f"\n{Colors.CYAN}Вставьте ссылку с Foreign сервера: {Colors.END}").strip()
    try:
        foreign = parse_foreign_link(foreign_link)
        routes = load_routes()
        xray_config = build_routing(foreign, routes)
        if not validate_xray_config_with_xray(xray_config):
            return

        with sqlite3.connect(DB_PATH) as conn:
            backup_path = backup_current_xray_config(conn)
            if backup_path:
                print(f"{Colors.CYAN}[...]{Colors.END} Бэкап xrayConfig: {backup_path}")
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
            return

        if not run(["x-ui", "restart"], "Перезапуск 3X-UI"):
            return

        print(f"\n{Colors.GREEN}RU Bridge настроен!{Colors.END}")
        print_qr(link)
        print(f"{Colors.YELLOW}Ваша ссылка:{Colors.END} {link}")
    except Exception as e:
        print(f"{Colors.RED}[Ошибка]{Colors.END} {e}")


def edit_routes_file():
    try:
        routes = load_routes()
    except Exception as e:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Не удалось загрузить маршруты: {e}")
        return

    print(f"\nФайл маршрутов: {ROUTES_STORE}")
    print(json.dumps(routes, ensure_ascii=False, indent=2))
    print("\nОтредактируйте JSON и сохраните. Допустимы только строки без пробелов.")

    answer = input("Открыть файл в редакторе сейчас? [Y/n]: ").strip().lower()
    if answer not in ("", "y", "yes", "д", "да"):
        return

    editor = os.environ.get("EDITOR", "nano")
    cmd = shlex.split(editor) + [ROUTES_STORE]
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print(f"{Colors.RED}[Ошибка]{Colors.END} Редактор '{editor}' не найден.")
        return

    try:
        load_routes()
        print(f"{Colors.GREEN}Маршруты сохранены и валидны.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[Ошибка]{Colors.END} JSON маршрутов невалиден: {e}")


# --- Main menu ---
def main():
    if os.getuid() != 0:
        sys.exit("Запустите через sudo")

    while True:
        settings = load_settings()
        os.system("clear")
        print(f"{Colors.CYAN}=== VPN Cascade Automator ==={Colors.END}")
        if SAFE_MODE:
            print(f"{Colors.YELLOW}[SAFE MODE]{Colors.END} Автоустановка зависимостей отключена.")
            if qrcode is None:
                print(f"{Colors.YELLOW}[SAFE MODE]{Colors.END} QR-код недоступен (нет модуля qrcode).")
        print(f"Клиентский порт: {settings['client_port']} | SNI: {settings['client_sni']}")
        if settings.get("actual_port"):
            print(f"Текущий рабочий порт: {Colors.GREEN}{settings['actual_port']}{Colors.END}")
        print(f"Маршруты: {ROUTES_STORE}")
        print("-" * 40)
        print("1. [Foreign] Настроить выходной сервер")
        print("2. [RU Server] Настроить мост (каскад)")
        print("3. [RU Server] Перегенерировать QR и ссылку (смена порта/SNI)")
        print("4. Изменить настройки клиента (порт / SNI)")
        print("5. Редактировать маршруты (JSON)")
        print("6. Применить готовый профиль маршрутов")
        print("7. Откатить xrayConfig из бэкапа")
        print("8. Выход")

        choice = input("\nВыбор: ").strip()

        if choice == "1":
            setup_foreign()
        elif choice == "2":
            setup_ru()
        elif choice == "3":
            if ensure_3x_ui():
                link = create_client_inbound()
                if link and run(["x-ui", "restart"], "Перезапуск 3X-UI"):
                    print_qr(link)
                    print(f"\n{Colors.YELLOW}Новая ссылка:{Colors.END} {link}")
        elif choice == "4":
            port_input = input(f"Порт [{settings['client_port']}] (или 'auto'): ").strip()
            if port_input:
                try:
                    settings["client_port"] = parse_port_setting(port_input)
                except Exception as e:
                    print(f"{Colors.RED}[Ошибка]{Colors.END} {e}")

            sni_input = input(f"SNI [{settings['client_sni']}]: ").strip()
            if sni_input:
                if valid_hostname(sni_input):
                    settings["client_sni"] = sni_input
                else:
                    print(f"{Colors.RED}[Ошибка]{Colors.END} Некорректный SNI")

            save_settings(settings)
        elif choice == "5":
            edit_routes_file()
        elif choice == "6":
            apply_route_profile()
        elif choice == "7":
            rollback_xray_config()
        elif choice == "8":
            break
        else:
            print("Неизвестный пункт меню")

        input("\nНажмите Enter для продолжения...")


if __name__ == "__main__":
    main()
