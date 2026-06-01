#!/usr/bin/env python3
"""
FunVPN — Proxy/VPN Collector Bot v3.1
Разработчики: FUN RUSSIA CRMP | TOO Oink Tech Ltd Co

Порядок нод в конфиге:
  1. ⭐ ParadoxVPN (приоритет, всегда первые)
  2. 🛡️ Резервные Cloudflare-ноды (всегда в конфиге)
  3. 🌐 Остальные VPN-ноды (проверены TCP-connect)
  4. 🔗 HTTP-прокси

Приложения (Happ, V2RayTun, Hiddify) при включённом
Auto-select / Best-latency сами перебирают весь список
и подключаются к первой рабочей ноде.
"""

import asyncio
import aiohttp
import json
import re
import os
import time
import base64
import random
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import quote, unquote, urlsplit, urlunsplit

# ──────────────────────────────────────────────
# НАСТРОЙКИ
# ──────────────────────────────────────────────
MAX_CONCURRENT_CHECKS   = 150
VPN_CONCURRENT_CHECKS   = 200
CHECK_TIMEOUT           = 8
VPN_CHECK_TIMEOUT       = 6
FETCH_TIMEOUT           = 30
MAX_PING_MS             = 4000
MAX_PROXIES_IN_CONFIG   = 300
MAX_VPN_NODES_IN_CONFIG = 500

TEST_URL      = "http://httpbin.org/ip"
OUTPUT_CONFIG = "configs/free_config.txt"
OUTPUT_JSON   = "configs/proxies.json"
OUTPUT_LOG    = "configs/last_update.log"

SUPPORTED_NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
PROXY_SCHEMES = ("http", "https", "socks4", "socks5")

# URL ParadoxVPN — грузится ОТДЕЛЬНО и идёт первым
PARADOX_VPN_URL = "https://raw.githubusercontent.com/Parad1st/ParadoxVPN/main/configs/free_config.txt"

COUNTRY_EMOJI = {
    "RU":"🇷🇺","US":"🇺🇸","DE":"🇩🇪","NL":"🇳🇱","FR":"🇫🇷",
    "GB":"🇬🇧","UA":"🇺🇦","PL":"🇵🇱","TR":"🇹🇷","CN":"🇨🇳",
    "KR":"🇰🇷","JP":"🇯🇵","SG":"🇸🇬","IN":"🇮🇳","BR":"🇧🇷",
    "CA":"🇨🇦","AU":"🇦🇺","IT":"🇮🇹","ES":"🇪🇸","FI":"🇫🇮",
    "SE":"🇸🇪","NO":"🇳🇴","CH":"🇨🇭","AT":"🇦🇹","CZ":"🇨🇿",
    "HU":"🇭🇺","RO":"🇷🇴","BG":"🇧🇬","SK":"🇸🇰","LT":"🇱🇹",
    "LV":"🇱🇻","EE":"🇪🇪","GR":"🇬🇷","HR":"🇭🇷","RS":"🇷🇸",
    "BA":"🇧🇦","MD":"🇲🇩","AM":"🇦🇲","GE":"🇬🇪","KZ":"🇰🇿",
    "BY":"🇧🇾","AZ":"🇦🇿","UZ":"🇺🇿","TH":"🇹🇭","VN":"🇻🇳",
    "ID":"🇮🇩","MY":"🇲🇾","PH":"🇵🇭","HK":"🇭🇰","TW":"🇹🇼",
    "MX":"🇲🇽","AR":"🇦🇷","CL":"🇨🇱","CO":"🇨🇴","ZA":"🇿🇦",
    "IR":"🇮🇷","AE":"🇦🇪","IL":"🇮🇱",
}

COUNTRY_NAMES_RU = {
    "RU":"Россия","US":"США","DE":"Германия","NL":"Нидерланды","FR":"Франция",
    "GB":"Британия","UA":"Украина","PL":"Польша","TR":"Турция","CN":"Китай",
    "KR":"Корея","JP":"Япония","SG":"Сингапур","IN":"Индия","BR":"Бразилия",
    "CA":"Канада","AU":"Австралия","IT":"Италия","ES":"Испания","FI":"Финляндия",
    "SE":"Швеция","NO":"Норвегия","CH":"Швейцария","AT":"Австрия","CZ":"Чехия",
    "HU":"Венгрия","RO":"Румыния","BG":"Болгария","SK":"Словакия","LT":"Литва",
    "LV":"Латвия","EE":"Эстония","GR":"Греция","HR":"Хорватия","RS":"Сербия",
    "BA":"Босния","MD":"Молдова","AM":"Армения","GE":"Грузия","KZ":"Казахстан",
    "BY":"Беларусь","AZ":"Азербайджан","UZ":"Узбекистан","TH":"Таиланд","VN":"Вьетнам",
    "ID":"Индонезия","MY":"Малайзия","PH":"Филиппины","HK":"Гонконг","TW":"Тайвань",
    "MX":"Мексика","AR":"Аргентина","CL":"Чили","CO":"Колумбия","ZA":"ЮАР",
    "IR":"Иран","AE":"ОАЭ","IL":"Израиль",
}

COUNTRY_ALIASES = {
    "RUSSIA":"RU","РОССИЯ":"RU","USA":"US","UNITED STATES":"US","США":"US",
    "GERMANY":"DE","DEUTSCHLAND":"DE","ГЕРМАНИЯ":"DE",
    "NETHERLANDS":"NL","HOLLAND":"NL","НИДЕРЛАНДЫ":"NL",
    "FRANCE":"FR","ФРАНЦИЯ":"FR","UNITED KINGDOM":"GB","UK":"GB","BRITAIN":"GB",
    "БРИТАНИЯ":"GB","UKRAINE":"UA","УКРАИНА":"UA","POLAND":"PL","ПОЛЬША":"PL",
    "TURKEY":"TR","ТУРЦИЯ":"TR","CHINA":"CN","КИТАЙ":"CN",
    "KOREA":"KR","КОРЕЯ":"KR","JAPAN":"JP","ЯПОНИЯ":"JP",
    "SINGAPORE":"SG","СИНГАПУР":"SG","CANADA":"CA","КАНАДА":"CA",
}
FLAG_TO_COUNTRY = {flag: code for code, flag in COUNTRY_EMOJI.items()}

# ──────────────────────────────────────────────
# РЕЗЕРВНЫЕ СТАТИЧНЫЕ НОДЫ (Cloudflare — всегда живые)
# ──────────────────────────────────────────────
RESERVE_STATIC_NODES = [
    "vless://478cc26d-16b3-4fdd-be64-60d5a58c1622@172.64.146.143:80?path=/&security=none&encryption=none&host=tt.andishehparenting.com&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-1",
    "vless://478cc26d-16b3-4fdd-be64-60d5a58c1622@172.64.146.143:80?path=/&security=none&encryption=none&host=tt.andishehparenting.com&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-2",
    "trojan://humanity@104.18.32.47:443?allowInsecure=1&host=www.gossipglove.com&path=%2Fassignment&sni=www.gossipglove.com&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-3",
    "vless://41f37ced-2021-4111-93a8-82d57ff2eb5b@217.163.76.118:2083?path=/?ed&security=tls&encryption=none&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=fl0.lizardshop.org#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-4",
    "vmess://eyJhZGQiOiIxNzIuNjcuMjA0LjIzIiwiYWlkIjoiMCIsImFscG4iOiIiLCJob3N0IjoiY2NwcC45MXBhbi5vbmUiLCJpZCI6IjczNWZmNDMwLTlkMWEtNGY1Ny1mYjY2LWU0M2EyNmE3NmY3MCIsIm5ldCI6IndzIiwicGF0aCI6Ii9jY3BwIiwicG9ydCI6IjgwIiwicHMiOiLwn5mhIFJlc2VydmUtQ0YtNSIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIifQ==",
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@162.159.134.61:443?security=tls&encryption=none&host=jrsis.ir&type=ws&path=%2Fvless&sni=jrsis.ir#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-6",
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@162.159.135.233:443?security=tls&encryption=none&host=jrsis.ir&type=ws&path=%2Fvless&sni=jrsis.ir#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-7",
    "trojan://telegram-id-directvpn@3.75.187.100:22222?security=tls&type=tcp&headerType=none&sni=trojan.burgerip.net#%F0%9F%9B%A1%EF%B8%8F%20Reserve-DE-8",
    "trojan://telegram-id-directvpn@13.37.87.172:22222?security=tls&type=tcp&headerType=none&sni=trojan.burgerip.net#%F0%9F%9B%A1%EF%B8%8F%20Reserve-FR-9",
    "vless://7de47379-76ef-4b9b-a8c5-ad60ee9826e2@104.21.90.187:80?path=%2Fvless&security=none&encryption=none&host=vl.shoppingtoday.co&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-10",
]

# ──────────────────────────────────────────────
# ИСТОЧНИКИ VPN-НОД (ParadoxVPN грузится отдельно!)
# ──────────────────────────────────────────────
VPN_NODE_SOURCES = [
    {"name": "mahdibland V2RayAggregator",   "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",                          "format": "subscription"},
    {"name": "aiboboxx v2rayfree",           "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                                                   "format": "subscription"},
    {"name": "Pawdroid Free-servers",        "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",                                               "format": "subscription"},
    {"name": "Barabama FreeNodes merge",     "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt",                                     "format": "subscription"},
    {"name": "Epodonios v2ray-configs all",  "url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",                             "format": "subscription"},
    {"name": "mheidari98 aggregated",        "url": "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",                                                   "format": "subscription"},
    {"name": "ermaozi get_subscribe main",   "url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",                               "format": "subscription"},
    {"name": "peasoft NoMoreWalls",          "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",                                          "format": "subscription"},
    {"name": "Leon406 SubCrawler nodes",     "url": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all",                                        "format": "subscription"},
    {"name": "free18 v2ray",                 "url": "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",                                                      "format": "subscription"},
    {"name": "surfboardv2ray proxy-list",    "url": "https://raw.githubusercontent.com/surfboardv2ray/TGParse/main/configtg.txt",                                     "format": "subscription"},
    {"name": "chengaopan AutoMerge",         "url": "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",                              "format": "subscription"},
    {"name": "YasserDivaR v2ray-configs",    "url": "https://raw.githubusercontent.com/YasserDivaR/pr0xy/main/V2Ray.txt",                                            "format": "subscription"},
    {"name": "ssrsub v2ray",                 "url": "https://raw.githubusercontent.com/ssrsub/ssr/master/V2Ray",                                                      "format": "subscription"},
    {"name": "freefq free",                  "url": "https://raw.githubusercontent.com/freefq/free/master/v2",                                                        "format": "subscription"},
    {"name": "barry-far All_Configs_Sub",    "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",                              "format": "subscription"},
    {"name": "barry-far VLESS",              "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",                   "format": "subscription"},
    {"name": "barry-far VMess",              "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",                   "format": "subscription"},
    {"name": "barry-far Trojan",             "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",                  "format": "subscription"},
    {"name": "MatinGhanbari super-sub",      "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",           "format": "subscription"},
    {"name": "MatinGhanbari vless",          "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",       "format": "subscription"},
    {"name": "MatinGhanbari trojan",         "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",      "format": "subscription"},
    {"name": "igareck vless-reality Russia", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt", "format": "subscription"},
    {"name": "igareck General-Sub",          "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/General-Sub.txt",                          "format": "subscription"},
    {"name": "IranianCypherpunks Sub",       "url": "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",                                           "format": "subscription"},
    {"name": "awesome-vpn all",              "url": "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",                                           "format": "subscription"},
    {"name": "Everyday-VPN main",            "url": "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",                         "format": "subscription"},
    {"name": "ALIILAPRO v2rayNG",            "url": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",                                        "format": "subscription"},
    {"name": "soroushmirzaei mixed",         "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",                "format": "subscription"},
    {"name": "soroushmirzaei vless",         "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless",                "format": "subscription"},
    {"name": "soroushmirzaei trojan",        "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan",               "format": "subscription"},
    {"name": "roosterkid V2RAY_RAW",         "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",                                  "format": "subscription"},
    {"name": "tbbatbb v2ray config",         "url": "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",                                  "format": "subscription"},
    {"name": "MrPooyaX VpnsFucking",         "url": "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/Shitte.txt",                                        "format": "subscription"},
    {"name": "resasanian Mirza",             "url": "https://raw.githubusercontent.com/resasanian/Mirza/main/sub",                                                    "format": "subscription"},
]

# ──────────────────────────────────────────────
# ИСТОЧНИКИ HTTP/SOCKS ПРОКСИ
# ──────────────────────────────────────────────
SOURCES = [
    {"name": "ProxyScrape HTTP",   "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",  "format": "text", "proto": "http"},
    {"name": "ProxyScrape HTTPS",  "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all", "format": "text", "proto": "https"},
    {"name": "ProxyScrape SOCKS5", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=5000",                                "format": "text", "proto": "socks5"},
    {"name": "ProxyScrape SOCKS4", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=5000",                                "format": "text", "proto": "socks4"},
    {"name": "GeoNode Free",       "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps%2Csocks4%2Csocks5", "format": "geonode_json", "proto": "mixed"},
    {"name": "OpenProxySpace HTTP",    "url": "https://api.openproxy.space/list/http",   "format": "openproxy_json", "proto": "http"},
    {"name": "OpenProxySpace SOCKS5",  "url": "https://api.openproxy.space/list/socks5", "format": "openproxy_json", "proto": "socks5"},
    {"name": "TheSpeedX HTTP",   "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",   "format": "text", "proto": "http"},
    {"name": "TheSpeedX SOCKS5", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "monosans HTTP",    "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",   "format": "text", "proto": "http"},
    {"name": "monosans SOCKS5",  "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "jetkai HTTP",   "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",   "format": "text", "proto": "http"},
    {"name": "jetkai SOCKS5", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "hookzof socks5",    "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",                   "format": "text", "proto": "socks5"},
    {"name": "ShiftyTR HTTP",     "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",                    "format": "text", "proto": "http"},
    {"name": "proxifly HTTP",     "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", "format": "text", "proto": "http"},
    {"name": "proxifly SOCKS5",   "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt","format": "text", "proto": "socks5"},
    {"name": "mmpx12 HTTP",       "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",                     "format": "text", "proto": "http"},
    {"name": "zloi-user HTTP",    "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",                     "format": "text", "proto": "http"},
    {"name": "zloi-user SOCKS5",  "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",                   "format": "text", "proto": "socks5"},
]

IP_PORT_RE = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})(?!\d)")


# ──────────────────────────────────────────────
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(p) <= 255 for p in ip.split(".")) and ip.count(".") == 3
    except ValueError:
        return False


def is_public_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_global
    except ValueError:
        return True


def unquote_deep(value: str, max_rounds: int = 4) -> str:
    prev = value
    for _ in range(max_rounds):
        cur = unquote(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def normalize_label(value: str) -> str:
    label = unquote_deep(value or "")
    label = re.sub(r"[|_/\\]+", " ", label)
    return re.sub(r"\s+", " ", label).strip(" -•—:[]")


def infer_country(label: str) -> str:
    clean = normalize_label(label).upper()
    for flag, code in FLAG_TO_COUNTRY.items():
        if flag in label:
            return code
    for alias, code in COUNTRY_ALIASES.items():
        if re.search(rf"(?<![A-ZА-Я]){re.escape(alias)}(?![A-ZА-Я])", clean):
            return code
    return ""


def decode_vmess(payload: str) -> Optional[dict]:
    compact = payload.strip()
    if not compact:
        return None
    padded = compact + "=" * (-len(compact) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            data = json.loads(dec(padded).decode("utf-8", errors="ignore"))
            return data if isinstance(data, dict) else None
        except Exception:
            pass
    return None


def encode_vmess(data: dict) -> str:
    return base64.b64encode(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    ).decode("ascii")


def set_node_label(uri: str, label: str) -> Optional[str]:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        data = decode_vmess(uri.split("://", 1)[1])
        if not data:
            return None
        data["ps"] = label
        return f"vmess://{encode_vmess(data)}"
    try:
        p = urlsplit(uri)
    except ValueError:
        return None
    if not p.scheme or not p.netloc or not is_public_host(p.hostname or ""):
        return None
    return urlunsplit((p.scheme.lower(), p.netloc, p.path, p.query, quote(label, safe="")))


def clean_node_uri(uri: str) -> Optional[str]:
    uri = uri.strip().strip('"\'`,;]}')
    if not uri.lower().startswith(SUPPORTED_NODE_SCHEMES):
        return None
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        return uri if decode_vmess(uri.split("://", 1)[1]) else None
    try:
        p = urlsplit(uri)
    except ValueError:
        return None
    if not p.scheme or not p.netloc or not is_public_host(p.hostname or ""):
        return None
    frag = quote(normalize_label(p.fragment), safe="") if p.fragment else ""
    return urlunsplit((p.scheme.lower(), p.netloc, p.path, p.query, frag))


def parse_node_endpoint(uri: str) -> Optional[tuple]:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        data = decode_vmess(uri.split("://", 1)[1])
        if not data:
            return None
        host = str(data.get("add", "")).strip()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            return None
        return (host, port) if host and 1 <= port <= 65535 and is_public_host(host) else None
    try:
        p = urlsplit(uri)
        if p.hostname and p.port and 1 <= p.port <= 65535 and is_public_host(p.hostname):
            return p.hostname, p.port
    except ValueError:
        pass
    if scheme == "ss":
        compact = uri.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
        try:
            decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="ignore")
            if "@" in decoded:
                hp = decoded.rsplit("@", 1)[1]
                if ":" in hp:
                    h, pt = hp.rsplit(":", 1)
                    pn = int(pt)
                    if h and 1 <= pn <= 65535 and is_public_host(h):
                        return h, pn
        except Exception:
            pass
    return None


def maybe_decode_b64(body: str) -> str:
    compact = "".join(body.split())
    if not compact or any(s in body for s in SUPPORTED_NODE_SCHEMES):
        return body
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return body
    padded = compact + "=" * (-len(compact) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = dec(padded).decode("utf-8", errors="ignore")
            if any(s in decoded for s in SUPPORTED_NODE_SCHEMES):
                return decoded
        except Exception:
            pass
    return body


def parse_subscription_nodes(body: str) -> List[str]:
    decoded = maybe_decode_b64(body)
    candidates: List[str] = []
    for line in decoded.replace("\r", "\n").split("\n"):
        line = line.strip()
        if line.lower().startswith(SUPPORTED_NODE_SCHEMES):
            candidates.append(line)
        else:
            candidates.extend(re.findall(r"(?:vless|vmess|trojan|ss|ssr)://[^\s<>\"']+", line, flags=re.I))
    nodes, seen = [], set()
    for raw in candidates:
        node = clean_node_uri(raw)
        if node and node not in seen:
            seen.add(node)
            nodes.append(node)
    return nodes


def parse_text(body: str, proto: str) -> List[Dict]:
    proxies = []
    for ip, pt in IP_PORT_RE.findall(body):
        port = int(pt)
        if is_valid_ip(ip) and 1 <= port <= 65535:
            proxies.append({"ip": ip, "port": port, "proto": proto})
    return proxies


def parse_geonode(body: str) -> List[Dict]:
    try:
        result = []
        for p in json.loads(body).get("data", []):
            ip = str(p.get("ip", "")).strip()
            port = int(p.get("port", 0))
            protos = [str(x).lower() for x in p.get("protocols", ["http"])]
            proto = next((x for x in protos if x in PROXY_SCHEMES), "http")
            cc = str(p.get("country", "")).upper()
            if is_valid_ip(ip) and 1 <= port <= 65535:
                result.append({"ip": ip, "port": port, "proto": proto, "country": cc})
        return result
    except Exception:
        return []


def parse_openproxy(body: str, default_proto: str) -> List[Dict]:
    try:
        data = json.loads(body)
    except Exception:
        return parse_text(body, default_proto)
    result = []
    for item in (data.get("data", []) if isinstance(data, dict) else []):
        proto = str(item.get("protocol", default_proto)).lower()
        if proto not in PROXY_SCHEMES:
            proto = default_proto
        for raw in item.get("items", []):
            for ip, pt in IP_PORT_RE.findall(str(raw)):
                port = int(pt)
                if is_valid_ip(ip) and 1 <= port <= 65535:
                    result.append({"ip": ip, "port": port, "proto": proto})
    return result


def parse_source(body: str, fmt: str, proto: str) -> List[Dict]:
    if fmt == "text":        return parse_text(body, proto)
    if fmt == "geonode_json": return parse_geonode(body)
    if fmt == "openproxy_json": return parse_openproxy(body, proto)
    return []


def relabel_vpn_nodes(nodes: List[Dict]) -> List[str]:
    relabeled, seen = [], set()
    for item in nodes:
        uri = str(item.get("uri", ""))
        ping = item.get("ping")
        cc = infer_country(unquote_deep(urlsplit(uri).fragment if "vmess" not in uri else ""))
        flag = COUNTRY_EMOJI.get(cc, "🌐")
        country_name = COUNTRY_NAMES_RU.get(cc, "Auto")
        ping_s = f" ({ping}ms)" if ping else ""
        label = f"{flag} {country_name} {len(relabeled)+1:03d}{ping_s}"
        new = set_node_label(uri, label)
        if new and new not in seen:
            seen.add(new)
            relabeled.append(new)
    return relabeled


# ──────────────────────────────────────────────
# СЕТЕВЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────

async def fetch_text(session: aiohttp.ClientSession, src: dict) -> Optional[str]:
    try:
        async with session.get(
            src["url"],
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "Mozilla/5.0 FunVPN-Robot/3.1"},
        ) as resp:
            if resp.status != 200:
                print(f"  [SKIP] {src['name']} → HTTP {resp.status}")
                return None
            return await resp.text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"  [ERR]  {src['name']} → {type(e).__name__}: {e}")
        return None


async def fetch_paradox_nodes(session: aiohttp.ClientSession) -> List[str]:
    """Загружаем ParadoxVPN отдельно — он идёт ПЕРВЫМ в конфиге."""
    print("\n⭐ Загружаем ParadoxVPN (приоритет #1)...")
    src = {"name": "ParadoxVPN", "url": PARADOX_VPN_URL}
    body = await fetch_text(session, src)
    if not body:
        print("  [WARN] ParadoxVPN недоступен, повтор через 5 сек...")
        await asyncio.sleep(5)
        body = await fetch_text(session, src)
    if not body:
        print("  [WARN] ParadoxVPN недоступен")
        return []
    nodes = parse_subscription_nodes(body)
    print(f"  [OK]   ParadoxVPN → {len(nodes)} нод")
    return nodes


async def fetch_vpn_source(session: aiohttp.ClientSession, src: dict) -> List[str]:
    body = await fetch_text(session, src)
    if not body:
        return []
    nodes = parse_subscription_nodes(body)
    print(f"  [OK]   {src['name']} → {len(nodes)} нод")
    return nodes


async def collect_other_vpn_nodes() -> List[str]:
    print("\n🧩 Загружаем дополнительные VPN-ноды...")
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *(fetch_vpn_source(session, s) for s in VPN_NODE_SOURCES),
            return_exceptions=True,
        )
    nodes, seen = [], set()
    for result in results:
        if isinstance(result, list):
            for node in result:
                if node not in seen:
                    seen.add(node)
                    nodes.append(node)
    print(f"\n✅ Дополнительных уникальных VPN-нод: {len(nodes)}")
    return nodes


async def check_vpn_node(semaphore: asyncio.Semaphore, node: str) -> Optional[Dict]:
    ep = parse_node_endpoint(node)
    if not ep:
        return None
    host, port = ep
    async with semaphore:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=VPN_CHECK_TIMEOUT
            )
            ping = int((time.monotonic() - t0) * 1000)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:
                pass
            if ping <= MAX_PING_MS:
                return {"uri": node, "ping": ping}
        except Exception:
            pass
    return None


async def check_all_vpn_nodes(nodes: List[str]) -> List[Dict]:
    if not nodes:
        return []
    print(f"\n🔌 TCP-проверка {len(nodes)} нод (параллельно {VPN_CONCURRENT_CHECKS})...")
    semaphore = asyncio.Semaphore(VPN_CONCURRENT_CHECKS)
    tasks = [check_vpn_node(semaphore, n) for n in nodes]
    alive, done = [], 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if r:
            alive.append(r)
        if done % 1000 == 0 or done == len(tasks):
            print(f"  [{done*100//len(tasks):3d}%] {done}/{len(tasks)}, живых: {len(alive)}")
    alive.sort(key=lambda x: x["ping"])
    print(f"\n🟢 Живых VPN-нод: {len(alive)}")
    return alive


async def collect_proxies() -> List[Dict]:
    print("\n📡 Загружаем HTTP/SOCKS-прокси...")
    connector = aiohttp.TCPConnector(limit=40, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *(fetch_text(session, s) for s in SOURCES), return_exceptions=True
        )
    all_p: List[Dict] = []
    for src, r in zip(SOURCES, results):
        if isinstance(r, str):
            parsed = parse_source(r, src["format"], src["proto"])
            print(f"  [OK]   {src['name']} → {len(parsed)}")
            all_p.extend(parsed)
    seen, unique = set(), []
    for p in all_p:
        k = f"{p.get('proto','http')}://{p['ip']}:{p['port']}"
        if k not in seen:
            seen.add(k)
            unique.append(p)
    print(f"\n✅ Уникальных прокси: {len(unique)}")
    return unique


async def check_proxy(sem: asyncio.Semaphore, session: aiohttp.ClientSession, proxy: Dict) -> Optional[Dict]:
    ip, port, proto = proxy["ip"], proxy["port"], proxy.get("proto", "http")
    async with sem:
        t0 = time.monotonic()
        try:
            async with session.get(
                TEST_URL, proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT), allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="ignore")
                    if "origin" in body or ip in body:
                        ping = int((time.monotonic() - t0) * 1000)
                        if ping <= MAX_PING_MS:
                            return {**proxy, "proto": proto, "ping": ping}
        except Exception:
            pass
    return None


async def check_all_proxies(proxies: List[Dict]) -> List[Dict]:
    http_p = [p for p in proxies if p.get("proto", "http") in ("http", "https")]
    if not http_p:
        return []
    print(f"\n🔍 Проверяем {len(http_p)} HTTP-прокси (параллельно {MAX_CONCURRENT_CHECKS})...")
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_CHECKS + 10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_proxy(sem, session, p) for p in http_p]
        alive, done = [], 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            done += 1
            if r:
                alive.append(r)
            if done % 500 == 0 or done == len(tasks):
                print(f"  [{done*100//len(tasks):3d}%] {done}/{len(tasks)}, живых: {len(alive)}")
    alive.sort(key=lambda x: x["ping"])
    print(f"\n🟢 Живых HTTP-прокси: {len(alive)}")
    return alive


async def enrich_countries(session: aiohttp.ClientSession, proxies: List[Dict]) -> List[Dict]:
    need = [p for p in proxies if not p.get("country")]
    for i in range(0, min(len(need), MAX_PROXIES_IN_CONFIG), 100):
        batch = need[i:i+100]
        try:
            async with session.post(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                data=json.dumps([{"query": p["ip"]} for p in batch]),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    for r in await resp.json():
                        if r.get("status") == "success":
                            for p in batch:
                                if p["ip"] == r.get("query"):
                                    p["country"] = r.get("countryCode", "")
        except Exception:
            pass
    return proxies


# ──────────────────────────────────────────────
# ГЕНЕРАЦИЯ КОНФИГА
# ──────────────────────────────────────────────

def next_month_reset_timestamp() -> int:
    """Возвращает Unix timestamp начала следующего месяца (1-е число, 00:00 UTC)."""
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_reset = datetime(now.year + 1, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    else:
        next_reset = datetime(now.year, now.month + 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return int(next_reset.timestamp())


def build_config(
    proxies: List[Dict],
    paradox_nodes: List[str],
    other_vpn_nodes: List[str],
    top_n: int = MAX_PROXIES_IN_CONFIG,
) -> str:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%d %H:%M UTC")

    # 200 ГБ в байтах, сброс 1-го числа каждого месяца
    total_bytes = 200 * 1024 ** 3   # 214748364800
    expire_ts   = next_month_reset_timestamp()

    lines = [
        "#profile-title: base64:" + base64.b64encode("🎮 FunVPN".encode()).decode(),
        "#profile-update-interval: 6",
        # upload=0, download=0 → показывает «0 использовано из 200 ГБ»
        # expire = 1-е число следующего месяца → автосброс в приложении
        f"#subscription-userinfo: upload=0; download=0; total={total_bytes}; expire={expire_ts}",
        "#support-url: https://github.com/FunVPN",
        "#profile-web-page-url: https://github.com/FunVPN",
        f"#announce: FunVPN {now} | 200 ГБ/мес | Включи Auto-select в Happ/V2RayTun!",
        "",
        "# ╔══════════════════════════════════════════════════════╗",
        "# ║  ⭐ ParadoxVPN — ПРИОРИТЕТ #1 (идут самыми первыми) ║",
        "# ║  Приложение попробует их первыми при Auto-select     ║",
        "# ╚══════════════════════════════════════════════════════╝",
    ]

    node_count = 0

    # 1. ParadoxVPN — самые первые
    if paradox_nodes:
        for idx, node in enumerate(paradox_nodes, 1):
            labeled = set_node_label(node, f"⭐ ParadoxVPN {idx:03d}")
            lines.append(labeled if labeled else node)
            node_count += 1
    else:
        lines.append("# ParadoxVPN временно недоступен — используются резервные ноды")

    lines.append("")
    lines.append("# ══════════════════════════════════════════════════════════")
    lines.append("# 🛡️  РЕЗЕРВНЫЕ НОДЫ (Cloudflare — работают почти всегда)")
    lines.append("# ══════════════════════════════════════════════════════════")

    # 2. Резервные Cloudflare-ноды
    for node in RESERVE_STATIC_NODES:
        lines.append(node)
        node_count += 1

    lines.append("")

    # 3. Остальные VPN-ноды
    if other_vpn_nodes:
        lines.append("# ══════════════════════════════════════════════════════════")
        lines.append("# 🌐  ДОПОЛНИТЕЛЬНЫЕ VPN-НОДЫ (проверены TCP-connect)")
        lines.append("# ══════════════════════════════════════════════════════════")
        for node in other_vpn_nodes[:MAX_VPN_NODES_IN_CONFIG]:
            lines.append(node)
            node_count += 1
        lines.append("")

    # 4. HTTP-прокси
    proxy_count = 0
    if proxies:
        lines.append("# ══════════════════════════════════════════════════════════")
        lines.append("# 🔗  ПРОВЕРЕННЫЕ HTTP-ПРОКСИ")
        lines.append("# ══════════════════════════════════════════════════════════")
        for idx, p in enumerate(proxies[:top_n], 1):
            ip, port = p["ip"], p["port"]
            proto = "http" if p.get("proto", "http") == "https" else p.get("proto", "http")
            ping = p.get("ping", 0)
            cc = p.get("country", "")
            label = quote(f"{COUNTRY_EMOJI.get(cc,'🌐')} HTTP {COUNTRY_NAMES_RU.get(cc, cc or 'Auto')} {idx:03d} ({ping}ms)", safe="")
            lines.append(f"{proto}://{ip}:{port}#{label}")
            proxy_count += 1

    lines += [
        "",
        f"# ParadoxVPN нод: {len(paradox_nodes)}",
        f"# Резервных нод: {len(RESERVE_STATIC_NODES)}",
        f"# Дополнительных VPN-нод: {min(len(other_vpn_nodes), MAX_VPN_NODES_IN_CONFIG)}",
        f"# HTTP-прокси: {proxy_count}",
        f"# Обновлено: {now}",
        "# FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    ]
    return "\n".join(lines)


def build_json(proxies: List[Dict], paradox_nodes: List[str], other_nodes: List[str]) -> str:
    return json.dumps({
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "paradox_nodes": paradox_nodes,
        "paradox_nodes_count": len(paradox_nodes),
        "other_vpn_nodes": other_nodes[:MAX_VPN_NODES_IN_CONFIG],
        "other_vpn_nodes_count": len(other_nodes),
        "reserve_nodes_count": len(RESERVE_STATIC_NODES),
        "proxies": proxies[:MAX_PROXIES_IN_CONFIG],
        "proxies_count": len(proxies),
        "credits": "FunVPN — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    }, ensure_ascii=False, indent=2)


def build_log(n_paradox: int, n_other: int, n_proxy: int, elapsed: float) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"=== FunVPN Robot v3.1 — {now} ===\n"
        f"ParadoxVPN нод:        {n_paradox}\n"
        f"Резервных нод:         {len(RESERVE_STATIC_NODES)}\n"
        f"Доп. VPN-нод:          {min(n_other, MAX_VPN_NODES_IN_CONFIG)}\n"
        f"HTTP-прокси:           {min(n_proxy, MAX_PROXIES_IN_CONFIG)}\n"
        f"Время:                 {elapsed:.1f} сек\n"
        f"FUN RUSSIA CRMP | TOO Oink Tech Ltd Co\n"
    )


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

async def main():
    t0 = time.monotonic()
    print("=" * 55)
    print("🤖  FunVPN Robot v3.1 — ParadoxVPN приоритет")
    print("    FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")
    print("=" * 55)

    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # ParadoxVPN — отдельно, первым
        paradox_nodes = await fetch_paradox_nodes(session)

    # Остальные ноды
    raw_other = await collect_other_vpn_nodes()
    alive_other_raw = await check_all_vpn_nodes(raw_other)
    other_vpn_nodes = relabel_vpn_nodes(alive_other_raw)

    # HTTP-прокси
    raw_proxies = await collect_proxies()
    alive_proxies = await check_all_proxies(raw_proxies)

    # Если совсем ничего — всё равно пишем резервный конфиг, не падаем
    os.makedirs("configs", exist_ok=True)

    # Страны для HTTP-прокси
    if alive_proxies:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            alive_proxies = await enrich_countries(session, alive_proxies)

    config = build_config(alive_proxies, paradox_nodes, other_vpn_nodes)
    with open(OUTPUT_CONFIG, "w", encoding="utf-8") as f:
        f.write(config)
    print(f"\n💾 Конфиг: {OUTPUT_CONFIG}")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        f.write(build_json(alive_proxies, paradox_nodes, other_vpn_nodes))
    print(f"💾 JSON:   {OUTPUT_JSON}")

    elapsed = time.monotonic() - t0
    log = build_log(len(paradox_nodes), len(other_vpn_nodes), len(alive_proxies), elapsed)
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        f.write(log)
    print("\n" + log)
    print(f"✅ Готово за {elapsed:.1f} сек.")


if __name__ == "__main__":
    asyncio.run(main())
