#!/usr/bin/env python3
"""
FunVPN — Proxy/VPN Collector Bot v3.3
FUN RUSSIA CRMP | TOO Oink Tech Ltd Co

Порядок нод в конфиге:
  1. ⭐ ParadoxVPN (приоритет, первые)
  2. 🛡️ Резервные Cloudflare-ноды
  3. 🌐 Остальные VPN-ноды (только TCP-живые, по пингу)
  4. 🔗 HTTP-прокси
"""

import asyncio
import aiohttp
import json
import re
import os
import time
import base64
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import quote, unquote, urlsplit, urlunsplit

# ──────────────────────────────────────────────
# НАСТРОЙКИ
# ──────────────────────────────────────────────
MAX_CONCURRENT_CHECKS   = 150
VPN_CONCURRENT_CHECKS   = 250   # увеличено для скорости
CHECK_TIMEOUT           = 8
VPN_CHECK_TIMEOUT       = 5     # уменьшено — быстрее отсеиваем мёртвые
FETCH_TIMEOUT           = 25
MAX_PING_MS             = 3000  # уменьшено — только реально быстрые
MAX_PROXIES_IN_CONFIG   = 300
MAX_VPN_NODES_IN_CONFIG = 600   # увеличено

TEST_URL      = "http://www.gstatic.com/generate_204"  # быстрее httpbin
OUTPUT_CONFIG = "configs/free_config.txt"
OUTPUT_JSON   = "configs/proxies.json"
OUTPUT_LOG    = "configs/last_update.log"

SUPPORTED_NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
PROXY_SCHEMES = ("http", "https", "socks4", "socks5")

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
# РЕЗЕРВНЫЕ CLOUDFLARE-НОДЫ (статичные, всегда живые)
# ──────────────────────────────────────────────
RESERVE_STATIC_NODES = [
    "vless://478cc26d-16b3-4fdd-be64-60d5a58c1622@172.64.146.143:80?path=/&security=none&encryption=none&host=tt.andishehparenting.com&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-1",
    "trojan://humanity@104.18.32.47:443?allowInsecure=1&host=www.gossipglove.com&path=%2Fassignment&sni=www.gossipglove.com&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-2",
    "vless://41f37ced-2021-4111-93a8-82d57ff2eb5b@217.163.76.118:2083?path=/?ed&security=tls&encryption=none&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=fl0.lizardshop.org#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-3",
    "vmess://eyJhZGQiOiIxNzIuNjcuMjA0LjIzIiwiYWlkIjoiMCIsImFscG4iOiIiLCJob3N0IjoiY2NwcC45MXBhbi5vbmUiLCJpZCI6IjczNWZmNDMwLTlkMWEtNGY1Ny1mYjY2LWU0M2EyNmE3NmY3MCIsIm5ldCI6IndzIiwicGF0aCI6Ii9jY3BwIiwicG9ydCI6IjgwIiwicHMiOiLwn5mhIFJlc2VydmUtQ0YtNCIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIifQ==",
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@162.159.134.61:443?security=tls&encryption=none&host=jrsis.ir&type=ws&path=%2Fvless&sni=jrsis.ir#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-5",
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@162.159.135.233:443?security=tls&encryption=none&host=jrsis.ir&type=ws&path=%2Fvless&sni=jrsis.ir#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-6",
    "trojan://telegram-id-directvpn@3.75.187.100:22222?security=tls&type=tcp&headerType=none&sni=trojan.burgerip.net#%F0%9F%9B%A1%EF%B8%8F%20Reserve-DE-7",
    "trojan://telegram-id-directvpn@13.37.87.172:22222?security=tls&type=tcp&headerType=none&sni=trojan.burgerip.net#%F0%9F%9B%A1%EF%B8%8F%20Reserve-FR-8",
    "vless://7de47379-76ef-4b9b-a8c5-ad60ee9826e2@104.21.90.187:80?path=%2Fvless&security=none&encryption=none&host=vl.shoppingtoday.co&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-9",
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@172.64.146.144:443?security=tls&encryption=none&host=jrsis.ir&type=ws&path=%2Fvless&sni=jrsis.ir#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-10",
]

# ──────────────────────────────────────────────
# ИСТОЧНИКИ VPN-НОД — 60+ источников
# ParadoxVPN грузится ОТДЕЛЬНО (идёт первым)
# ──────────────────────────────────────────────
VPN_NODE_SOURCES = [
    # ── Крупные агрегаторы ──
    {"name": "mahdibland merged",        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"},
    {"name": "Epodonios ALL",            "url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"},
    {"name": "Leon406 all",              "url": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all"},
    {"name": "chengaopan merged",        "url": "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt"},
    {"name": "soroushmirzaei mixed",     "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed"},
    {"name": "awesome-vpn all",          "url": "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all"},
    # ── barry-far (обновляется ежедневно) ──
    {"name": "barry-far ALL",            "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt"},
    {"name": "barry-far vless",          "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt"},
    {"name": "barry-far vmess",          "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt"},
    {"name": "barry-far trojan",         "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt"},
    {"name": "barry-far ss",             "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt"},
    # ── MatinGhanbari ──
    {"name": "MatinGhanbari super",      "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"},
    {"name": "MatinGhanbari vless",      "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt"},
    {"name": "MatinGhanbari trojan",     "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt"},
    {"name": "MatinGhanbari vmess",      "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt"},
    # ── Россия / СНГ ──
    {"name": "igareck vless-reality",    "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt"},
    {"name": "igareck general",          "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/General-Sub.txt"},
    # ── soroushmirzaei ──
    {"name": "soroushmirzaei vless",     "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless"},
    {"name": "soroushmirzaei trojan",    "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan"},
    {"name": "soroushmirzaei vmess",     "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vmess"},
    # ── Другие активные репо ──
    {"name": "aiboboxx v2rayfree",       "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2"},
    {"name": "Pawdroid sub",             "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"},
    {"name": "Barabama merged",          "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt"},
    {"name": "mheidari98 all",           "url": "https://raw.githubusercontent.com/mheidari98/.proxy/main/all"},
    {"name": "ermaozi v2ray",            "url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"},
    {"name": "peasoft NoMoreWalls",      "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt"},
    {"name": "free18 v2ray",             "url": "https://raw.githubusercontent.com/free18/v2ray/main/v.txt"},
    {"name": "surfboardv2ray tgparse",   "url": "https://raw.githubusercontent.com/surfboardv2ray/TGParse/main/configtg.txt"},
    {"name": "YasserDivaR pr0xy",        "url": "https://raw.githubusercontent.com/YasserDivaR/pr0xy/main/V2Ray.txt"},
    {"name": "ssrsub V2Ray",             "url": "https://raw.githubusercontent.com/ssrsub/ssr/master/V2Ray"},
    {"name": "freefq free",              "url": "https://raw.githubusercontent.com/freefq/free/master/v2"},
    {"name": "ALIILAPRO v2rayNG",        "url": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt"},
    {"name": "Everyday-VPN main",        "url": "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt"},
    {"name": "IranianCypherpunks",       "url": "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config"},
    {"name": "resasanian Mirza",         "url": "https://raw.githubusercontent.com/resasanian/Mirza/main/sub"},
    {"name": "MrPooyaX VpnsFucking",     "url": "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/Shitte.txt"},
    {"name": "roosterkid V2RAY",         "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt"},
    {"name": "tbbatbb v2ray",            "url": "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt"},
    {"name": "vxiaov free_proxies",      "url": "https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml"},
    {"name": "anaer Sub",                "url": "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml"},
    # ── Новые источники ──
    {"name": "freev2ray sub",            "url": "https://raw.githubusercontent.com/xrayfree/free-ssr-ss-v2ray-vpn-clash/main/sub/sub.txt"},
    {"name": "liasica shadowrocket",     "url": "https://raw.githubusercontent.com/liasica/liasicaSSR/master/Shadowrocket"},
    {"name": "Flik91 v2rayN",            "url": "https://raw.githubusercontent.com/Flik91/Xray-Sub/main/vless_vmess.txt"},
    {"name": "coldwater v2ray",          "url": "https://raw.githubusercontent.com/coldwater-10/V2Hub/main/split/reality"},
    {"name": "coldwater v2hub all",      "url": "https://raw.githubusercontent.com/coldwater-10/V2Hub/main/V2Hub"},
    {"name": "Renzhan v2ray",            "url": "https://raw.githubusercontent.com/Renzhan/vProxy/main/merge"},
    {"name": "ts-sf clash",              "url": "https://raw.githubusercontent.com/ts-sf/fly/main/v2"},
    {"name": "w1g007 nodes",             "url": "https://raw.githubusercontent.com/w1g007/free-v2ray-nodes/main/sub"},
    {"name": "LidongSub nodes",          "url": "https://raw.githubusercontent.com/LidongSub/Free-Nodes/main/sub"},
    {"name": "pawdroid2 sub",            "url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub"},
    {"name": "vpn-configs-free",         "url": "https://raw.githubusercontent.com/vpn-configs-free/free-vpn-configs/main/subscriptions/all"},
    {"name": "pojiezhiyuanjun freev2",   "url": "https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/0827.txt"},
    {"name": "go4sharing sub",           "url": "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml"},
    {"name": "freev2ray_links",          "url": "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt"},
    {"name": "mahsanet mtn",             "url": "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt"},
    {"name": "mahsanet sub2",            "url": "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_2.txt"},
    {"name": "arshiacomplus configs",    "url": "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix.html"},
    {"name": "yebekhe TVC",              "url": "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix"},
    {"name": "yebekhe TVC plain",        "url": "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix"},
    {"name": "lagzian v2ray",            "url": "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS_new.txt"},
    {"name": "lagzian TG configs",       "url": "https://raw.githubusercontent.com/lagzian/TG-Collector/main/protocols/mix"},
    {"name": "mfuu clash",               "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml"},
    {"name": "mfuu v2ray",               "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray"},
    {"name": "itsyebekhe meta",          "url": "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix"},
    {"name": "Surfboardv2ray API",       "url": "https://raw.githubusercontent.com/surfboardv2ray/Subs/main/Raw"},
    {"name": "Sub-Zero mix",             "url": "https://raw.githubusercontent.com/Sub-Zero-1/V2Ray/main/Sub-Zero"},
    {"name": "zhangkaiitugithub openit", "url": "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml"},
]

# ──────────────────────────────────────────────
# ИСТОЧНИКИ HTTP/SOCKS ПРОКСИ
# ──────────────────────────────────────────────
SOURCES = [
    {"name": "ProxyScrape HTTP",   "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",  "format": "text", "proto": "http"},
    {"name": "ProxyScrape HTTPS",  "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all", "format": "text", "proto": "https"},
    {"name": "ProxyScrape SOCKS5", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=5000",                                "format": "text", "proto": "socks5"},
    {"name": "GeoNode Free",       "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps%2Csocks4%2Csocks5", "format": "geonode_json", "proto": "mixed"},
    {"name": "OpenProxySpace HTTP",  "url": "https://api.openproxy.space/list/http",   "format": "openproxy_json", "proto": "http"},
    {"name": "OpenProxySpace S5",    "url": "https://api.openproxy.space/list/socks5", "format": "openproxy_json", "proto": "socks5"},
    {"name": "TheSpeedX HTTP",   "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",   "format": "text", "proto": "http"},
    {"name": "TheSpeedX SOCKS5", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "monosans HTTP",    "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",   "format": "text", "proto": "http"},
    {"name": "monosans SOCKS5",  "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "jetkai HTTP",      "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",   "format": "text", "proto": "http"},
    {"name": "jetkai SOCKS5",    "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "hookzof socks5",   "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",                   "format": "text", "proto": "socks5"},
    {"name": "proxifly HTTP",    "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", "format": "text", "proto": "http"},
    {"name": "proxifly SOCKS5",  "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt","format": "text", "proto": "socks5"},
    {"name": "mmpx12 HTTP",      "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",   "format": "text", "proto": "http"},
    {"name": "zloi-user HTTP",   "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",   "format": "text", "proto": "http"},
    {"name": "zloi-user SOCKS5", "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "ShiftyTR HTTP",    "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "format": "text", "proto": "http"},
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


def unquote_deep(value: str, rounds: int = 4) -> str:
    prev = value
    for _ in range(rounds):
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
            candidates.extend(re.findall(
                r"(?:vless|vmess|trojan|ss|ssr)://[^\s<>\"'\[\]]+", line, flags=re.I
            ))
    nodes, seen = [], set()
    for raw in candidates:
        node = clean_node_uri(raw)
        if node and node not in seen:
            seen.add(node)
            nodes.append(node)
    return nodes


def parse_text(body: str, proto: str) -> List[Dict]:
    return [
        {"ip": ip, "port": int(pt), "proto": proto}
        for ip, pt in IP_PORT_RE.findall(body)
        if is_valid_ip(ip) and 1 <= int(pt) <= 65535
    ]


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
    if fmt == "text":            return parse_text(body, proto)
    if fmt == "geonode_json":    return parse_geonode(body)
    if fmt == "openproxy_json":  return parse_openproxy(body, proto)
    return []


def relabel_vpn_nodes(nodes: List[Dict]) -> List[str]:
    relabeled, seen = [], set()
    for item in nodes:
        uri  = str(item.get("uri", ""))
        ping = item.get("ping")
        # Пытаемся определить страну из фрагмента
        try:
            frag = urlsplit(uri).fragment
        except Exception:
            frag = ""
        if not frag and uri.startswith("vmess://"):
            data = decode_vmess(uri.split("://", 1)[1])
            frag = str(data.get("ps", "")) if data else ""
        cc   = infer_country(unquote_deep(frag))
        flag = COUNTRY_EMOJI.get(cc, "🌐")
        name = COUNTRY_NAMES_RU.get(cc, "Auto")
        ping_s = f" ({ping}ms)" if ping else ""
        label  = f"{flag} {name} {len(relabeled)+1:03d}{ping_s}"
        new = set_node_label(uri, label)
        if new and new not in seen:
            seen.add(new)
            relabeled.append(new)
    return relabeled


def next_month_reset_ts() -> int:
    now = datetime.now(timezone.utc)
    if now.month == 12:
        nxt = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        nxt = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)
    return int(nxt.timestamp())


# ──────────────────────────────────────────────
# СЕТЕВЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────

async def fetch_url(session: aiohttp.ClientSession, url: str, name: str) -> Optional[str]:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "Mozilla/5.0 FunVPN-Robot/3.3"},
        ) as resp:
            if resp.status == 200:
                return await resp.text(encoding="utf-8", errors="ignore")
            print(f"  [SKIP] {name} → HTTP {resp.status}")
    except Exception as e:
        print(f"  [ERR]  {name} → {type(e).__name__}")
    return None


async def fetch_paradox_nodes(session: aiohttp.ClientSession) -> List[str]:
    """ParadoxVPN — отдельно, идёт ПЕРВЫМ в конфиге."""
    print("\n⭐ Загружаем ParadoxVPN (приоритет #1)...")
    body = await fetch_url(session, PARADOX_VPN_URL, "ParadoxVPN")
    if not body:
        print("  [WARN] ParadoxVPN недоступен, повтор через 8 сек...")
        await asyncio.sleep(8)
        body = await fetch_url(session, PARADOX_VPN_URL, "ParadoxVPN retry")
    if not body:
        print("  [WARN] ParadoxVPN недоступен")
        return []
    nodes = parse_subscription_nodes(body)
    print(f"  [OK]   ParadoxVPN → {len(nodes)} нод")
    return nodes


async def collect_other_vpn_nodes() -> List[str]:
    print(f"\n🧩 Загружаем {len(VPN_NODE_SOURCES)} источников VPN-нод...")
    connector = aiohttp.TCPConnector(limit=25, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = {s["name"]: fetch_url(session, s["url"], s["name"]) for s in VPN_NODE_SOURCES}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    nodes, seen = [], set()
    for src, r in zip(VPN_NODE_SOURCES, results):
        if isinstance(r, str):
            parsed = parse_subscription_nodes(r)
            print(f"  [OK]   {src['name']} → {len(parsed)}")
            for node in parsed:
                if node not in seen:
                    seen.add(node)
                    nodes.append(node)
    print(f"\n✅ Дополнительных уникальных нод: {len(nodes)}")
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
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass
            if ping <= MAX_PING_MS:
                return {"uri": node, "ping": ping}
        except Exception:
            pass
    return None


async def check_all_vpn_nodes(nodes: List[str], label: str = "") -> List[Dict]:
    if not nodes:
        return []
    tag = f" [{label}]" if label else ""
    print(f"\n🔌 TCP-проверка{tag} {len(nodes)} нод (параллельно {VPN_CONCURRENT_CHECKS})...")
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
    print(f"  🟢 Живых{tag}: {len(alive)} из {len(nodes)}")
    return alive


async def collect_proxies() -> List[Dict]:
    print("\n📡 Загружаем HTTP/SOCKS-прокси...")
    connector = aiohttp.TCPConnector(limit=40, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *(fetch_url(session, s["url"], s["name"]) for s in SOURCES),
            return_exceptions=True
        )
    all_p: List[Dict] = []
    for src, r in zip(SOURCES, results):
        if isinstance(r, str):
            parsed = parse_source(r, src["format"], src["proto"])
            all_p.extend(parsed)
    seen, unique = set(), []
    for p in all_p:
        k = f"{p.get('proto','http')}://{p['ip']}:{p['port']}"
        if k not in seen:
            seen.add(k)
            unique.append(p)
    print(f"✅ Уникальных прокси: {len(unique)}")
    return unique


async def check_proxy(sem: asyncio.Semaphore, session: aiohttp.ClientSession, p: Dict) -> Optional[Dict]:
    ip, port, proto = p["ip"], p["port"], p.get("proto", "http")
    async with sem:
        t0 = time.monotonic()
        try:
            async with session.get(
                TEST_URL, proxy=f"http://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                allow_redirects=True,
            ) as resp:
                if resp.status in (200, 204):
                    ping = int((time.monotonic() - t0) * 1000)
                    if ping <= MAX_PING_MS:
                        return {**p, "proto": proto, "ping": ping}
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
    print(f"  🟢 Живых HTTP-прокси: {len(alive)}")
    return alive


async def enrich_countries(proxies: List[Dict]) -> List[Dict]:
    need = [p for p in proxies if not p.get("country")][:MAX_PROXIES_IN_CONFIG]
    if not need:
        return proxies
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(need), 100):
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

def build_config(
    proxies: List[Dict],
    paradox_nodes: List[str],
    other_vpn_nodes: List[str],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_bytes = 200 * 1024 ** 3
    expire_ts   = next_month_reset_ts()

    lines = [
        "#profile-title: base64:" + base64.b64encode("🎮 FunVPN".encode()).decode(),
        "#profile-update-interval: 6",
        f"#subscription-userinfo: upload=0; download=0; total={total_bytes}; expire={expire_ts}",
        "#support-url: https://github.com/FunVPN",
        "#profile-web-page-url: https://github.com/FunVPN",
        f"#announce: FunVPN {now} | 200GB/мес | Auto-select в Happ/V2RayTun = автопереключение на рабочую!",
        "",
        "# ╔══════════════════════════════════════════════════════════╗",
        "# ║  ⭐ ParadoxVPN — ПРИОРИТЕТ #1                           ║",
        "# ║  Включи Auto-select/URL-Test — само найдёт рабочую ноду ║",
        "# ╚══════════════════════════════════════════════════════════╝",
    ]

    node_count = 0

    # 1. ParadoxVPN — первые
    if paradox_nodes:
        for idx, node in enumerate(paradox_nodes, 1):
            labeled = set_node_label(node, f"⭐ ParadoxVPN {idx:03d}")
            lines.append(labeled if labeled else node)
            node_count += 1
    else:
        lines.append("# ParadoxVPN временно недоступен")

    lines += [
        "",
        "# ══════════════════════════════════════════════════════════",
        "# 🛡️  РЕЗЕРВНЫЕ НОДЫ (Cloudflare — почти всегда живые)",
        "# ══════════════════════════════════════════════════════════",
    ]

    # 2. Резервные CF-ноды
    for node in RESERVE_STATIC_NODES:
        lines.append(node)
        node_count += 1

    # 3. Остальные VPN-ноды (только живые по TCP)
    if other_vpn_nodes:
        lines += [
            "",
            "# ══════════════════════════════════════════════════════════",
            f"# 🌐  VPN-НОДЫ ({len(other_vpn_nodes[:MAX_VPN_NODES_IN_CONFIG])} шт., проверены TCP-connect, по пингу)",
            "# ══════════════════════════════════════════════════════════",
        ]
        for node in other_vpn_nodes[:MAX_VPN_NODES_IN_CONFIG]:
            lines.append(node)
            node_count += 1

    # 4. HTTP-прокси
    proxy_count = 0
    if proxies:
        lines += [
            "",
            "# ══════════════════════════════════════════════════════════",
            "# 🔗  ПРОВЕРЕННЫЕ HTTP-ПРОКСИ",
            "# ══════════════════════════════════════════════════════════",
        ]
        for idx, p in enumerate(proxies[:MAX_PROXIES_IN_CONFIG], 1):
            ip, port = p["ip"], p["port"]
            proto = "http" if p.get("proto") == "https" else p.get("proto", "http")
            ping  = p.get("ping", 0)
            cc    = p.get("country", "")
            label = quote(
                f"{COUNTRY_EMOJI.get(cc,'🌐')} HTTP {COUNTRY_NAMES_RU.get(cc, cc or 'Auto')} {idx:03d} ({ping}ms)",
                safe=""
            )
            lines.append(f"{proto}://{ip}:{port}#{label}")
            proxy_count += 1

    lines += [
        "",
        f"# ParadoxVPN нод: {len(paradox_nodes)}",
        f"# Резервных CF-нод: {len(RESERVE_STATIC_NODES)}",
        f"# Доп. VPN-нод: {min(len(other_vpn_nodes), MAX_VPN_NODES_IN_CONFIG)}",
        f"# HTTP-прокси: {proxy_count}",
        f"# Всего в конфиге: {node_count + proxy_count}",
        f"# Обновлено: {now}",
        "# FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    ]
    return "\n".join(lines)


def build_json(proxies, paradox_nodes, other_nodes) -> str:
    return json.dumps({
        "updated_at":          datetime.now(timezone.utc).isoformat(),
        "paradox_nodes":       paradox_nodes,
        "paradox_count":       len(paradox_nodes),
        "reserve_count":       len(RESERVE_STATIC_NODES),
        "other_vpn_nodes":     other_nodes[:MAX_VPN_NODES_IN_CONFIG],
        "other_vpn_count":     len(other_nodes),
        "proxies":             proxies[:MAX_PROXIES_IN_CONFIG],
        "proxies_count":       len(proxies),
        "vpn_sources_total":   len(VPN_NODE_SOURCES),
        "credits":             "FunVPN — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    }, ensure_ascii=False, indent=2)


def build_log(n_paradox, n_other, n_proxy, elapsed) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"=== FunVPN Robot v3.3 — {now} ===\n"
        f"ParadoxVPN нод:        {n_paradox}\n"
        f"Резервных CF-нод:      {len(RESERVE_STATIC_NODES)}\n"
        f"Доп. VPN-нод (живых):  {min(n_other, MAX_VPN_NODES_IN_CONFIG)}\n"
        f"Источников VPN:        {len(VPN_NODE_SOURCES)}\n"
        f"HTTP-прокси (живых):   {min(n_proxy, MAX_PROXIES_IN_CONFIG)}\n"
        f"Время:                 {elapsed:.1f} сек\n"
        f"FUN RUSSIA CRMP | TOO Oink Tech Ltd Co\n"
    )


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

async def main():
    t0 = time.monotonic()
    print("=" * 58)
    print("🤖  FunVPN Robot v3.3 — только живые ноды")
    print("    FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")
    print("=" * 58)
    print(f"📋 Источников VPN: {len(VPN_NODE_SOURCES)} | Макс. пинг: {MAX_PING_MS}ms")

    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        paradox_nodes = await fetch_paradox_nodes(session)

    # TCP-проверка ParadoxVPN нод
    if paradox_nodes:
        alive_paradox_raw = await check_all_vpn_nodes(paradox_nodes, "ParadoxVPN")
        # Оставляем живые, но если совсем мало — берём все (CF их доставит)
        if alive_paradox_raw:
            alive_paradox_uris = [x["uri"] for x in alive_paradox_raw]
        else:
            print("  ⚠️  ParadoxVPN TCP-недоступен, включаем все ноды из него как есть")
            alive_paradox_uris = paradox_nodes
    else:
        alive_paradox_uris = []

    # Остальные ноды
    raw_other = await collect_other_vpn_nodes()
    alive_other_raw = await check_all_vpn_nodes(raw_other, "дополнительные")
    other_vpn_nodes = relabel_vpn_nodes(alive_other_raw)

    # HTTP-прокси
    raw_proxies   = await collect_proxies()
    alive_proxies = await check_all_proxies(raw_proxies)
    if alive_proxies:
        alive_proxies = await enrich_countries(alive_proxies)

    os.makedirs("configs", exist_ok=True)

    config = build_config(alive_proxies, alive_paradox_uris, other_vpn_nodes)
    with open(OUTPUT_CONFIG, "w", encoding="utf-8") as f:
        f.write(config)
    print(f"\n💾 Конфиг: {OUTPUT_CONFIG}")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        f.write(build_json(alive_proxies, alive_paradox_uris, other_vpn_nodes))

    elapsed = time.monotonic() - t0
    log = build_log(len(alive_paradox_uris), len(other_vpn_nodes), len(alive_proxies), elapsed)
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        f.write(log)
    print("\n" + log)
    print(f"✅ Готово за {elapsed:.1f} сек.")


if __name__ == "__main__":
    asyncio.run(main())
