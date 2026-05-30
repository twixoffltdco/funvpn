#!/usr/bin/env python3
"""
FunVPN — Proxy/VPN Collector Bot
Разработчики: FUN RUSSIA CRMP | TOO Oink Tech Ltd Co

Собирает публичные VPN-ноды и HTTP/SOCKS-прокси из открытых источников,
проверяет HTTP-прокси реальным запросом и обновляет подписку для Happ,
v2rayTun, Hiddify, Shadowrocket и похожих клиентов.
"""

import asyncio
import aiohttp
import json
import re
import os
import time
import base64
import sys
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import quote, urlsplit, urlunsplit

# ──────────────────────────────────────────────
# НАСТРОЙКИ
# ──────────────────────────────────────────────
MAX_CONCURRENT_CHECKS = 80       # параллельных проверок HTTP-прокси
CHECK_TIMEOUT         = 6        # секунд на один HTTP-прокси
FETCH_TIMEOUT         = 20       # секунд на загрузку источника
MAX_PING_MS           = 5000     # максимальный принимаемый пинг
MAX_PROXIES_IN_CONFIG = 200      # лимит HTTP/SOCKS-прокси в итоговом конфиге
MAX_VPN_NODES_IN_CONFIG = 250    # лимит VLESS/Trojan/SS/VMess-ноды в конфиге
TEST_URL              = "http://httpbin.org/ip"   # что открываем через прокси

OUTPUT_CONFIG         = "configs/free_config.txt"
OUTPUT_JSON           = "configs/proxies.json"
OUTPUT_LOG            = "configs/last_update.log"

SUPPORTED_NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
PROXY_SCHEMES = ("http", "https", "socks4", "socks5")

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
}

# ──────────────────────────────────────────────
# ИСТОЧНИКИ ГОТОВЫХ VPN-НОД
# ──────────────────────────────────────────────
# HTTP-прокси сами по себе не являются VLESS/Trojan VPN-серверами. Чтобы Happ и
# другие Xray-клиенты получали рабочую подписку, сначала добавляем реальные
# VPN-ноды из открытых подписок, а HTTP-прокси кладём ниже отдельным блоком.
VPN_NODE_SOURCES = [
    {
        "name": "ParadoxVPN free_config",
        "url": "https://raw.githubusercontent.com/Parad1st/ParadoxVPN/main/configs/free_config.txt",
        "format": "subscription",
    },
    {
        "name": "mahdibland V2RayAggregator",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "format": "subscription",
    },
    {
        "name": "aiboboxx v2rayfree",
        "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
        "format": "subscription",
    },
    {
        "name": "Pawdroid Free-servers",
        "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        "format": "subscription",
    },
]

# ──────────────────────────────────────────────
# ИСТОЧНИКИ ПУБЛИЧНЫХ HTTP/SOCKS-ПРОКСИ (20+ разных API/листов)
# ──────────────────────────────────────────────
SOURCES = [
    {"name": "ProxyScrape HTTP", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all", "format": "text", "proto": "http"},
    {"name": "ProxyScrape HTTPS", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all", "format": "text", "proto": "https"},
    {"name": "ProxyScrape SOCKS5", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=5000", "format": "text", "proto": "socks5"},
    {"name": "ProxyScrape SOCKS4", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=5000", "format": "text", "proto": "socks4"},
    {"name": "GeoNode Free", "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps%2Csocks4%2Csocks5", "format": "geonode_json", "proto": "mixed"},
    {"name": "OpenProxySpace HTTP", "url": "https://api.openproxy.space/list/http", "format": "openproxy_json", "proto": "http"},
    {"name": "OpenProxySpace SOCKS4", "url": "https://api.openproxy.space/list/socks4", "format": "openproxy_json", "proto": "socks4"},
    {"name": "OpenProxySpace SOCKS5", "url": "https://api.openproxy.space/list/socks5", "format": "openproxy_json", "proto": "socks5"},
    {"name": "Proxy-List.download HTTP", "url": "https://www.proxy-list.download/api/v1/get?type=http", "format": "text", "proto": "http"},
    {"name": "Proxy-List.download HTTPS", "url": "https://www.proxy-list.download/api/v1/get?type=https", "format": "text", "proto": "https"},
    {"name": "Proxy-List.download SOCKS4", "url": "https://www.proxy-list.download/api/v1/get?type=socks4", "format": "text", "proto": "socks4"},
    {"name": "Proxy-List.download SOCKS5", "url": "https://www.proxy-list.download/api/v1/get?type=socks5", "format": "text", "proto": "socks5"},
    {"name": "Spys.me HTTP", "url": "https://spys.me/proxy.txt", "format": "text", "proto": "http"},
    {"name": "clarketm/proxy-list", "url": "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "format": "text", "proto": "http"},
    {"name": "TheSpeedX HTTP", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "format": "text", "proto": "http"},
    {"name": "TheSpeedX SOCKS5", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "TheSpeedX SOCKS4", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "format": "text", "proto": "socks4"},
    {"name": "monosans HTTP", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "format": "text", "proto": "http"},
    {"name": "monosans HTTPS", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt", "format": "text", "proto": "https"},
    {"name": "monosans SOCKS4", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "format": "text", "proto": "socks4"},
    {"name": "monosans SOCKS5", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "jetkai HTTP", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", "format": "text", "proto": "http"},
    {"name": "jetkai HTTPS", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt", "format": "text", "proto": "https"},
    {"name": "jetkai SOCKS4", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "format": "text", "proto": "socks4"},
    {"name": "jetkai SOCKS5", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "hookzof/socks5_list", "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "format": "text", "proto": "socks5"},
    {"name": "ShiftyTR HTTP", "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "format": "text", "proto": "http"},
    {"name": "sunny9577 proxy-scraper", "url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.json", "format": "sunny_json", "proto": "http"},
    {"name": "roosterkid openproxylist HTTP", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "format": "text", "proto": "https"},
    {"name": "roosterkid openproxylist SOCKS4", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "format": "text", "proto": "socks4"},
    {"name": "roosterkid openproxylist SOCKS5", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "format": "text", "proto": "socks5"},
    {"name": "officialputuid KANG HTTP", "url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt", "format": "text", "proto": "http"},
]

# ──────────────────────────────────────────────
# ПАРСЕРЫ
# ──────────────────────────────────────────────

IP_PORT_RE = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})(?!\d)")


def is_valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in ip.split(".")) and ip.count(".") == 3
    except ValueError:
        return False


def parse_text(body: str, proto: str) -> List[Dict]:
    """Достаёт все валидные ip:port, даже если источник добавил страну/анонимность после адреса."""
    proxies = []
    for ip, port_text in IP_PORT_RE.findall(body):
        port = int(port_text)
        if is_valid_ip(ip) and 1 <= port <= 65535:
            proxies.append({"ip": ip, "port": port, "proto": proto})
    return proxies


def parse_geonode(body: str) -> List[Dict]:
    try:
        data = json.loads(body)
        result = []
        for p in data.get("data", []):
            ip = str(p.get("ip", "")).strip()
            port = int(p.get("port", 0))
            protos = [str(x).lower() for x in p.get("protocols", ["http"])]
            proto = next((x for x in protos if x in PROXY_SCHEMES), "http")
            country = str(p.get("country", "")).upper()
            if is_valid_ip(ip) and 1 <= port <= 65535:
                result.append({"ip": ip, "port": port, "proto": proto, "country": country})
        return result
    except Exception:
        return []


def parse_sunny(body: str) -> List[Dict]:
    try:
        data = json.loads(body)
        result = []
        if isinstance(data, dict):
            values = data.get("proxies") or data.get("data") or []
        else:
            values = data
        for p in values:
            if not isinstance(p, dict):
                continue
            ip = str(p.get("ip") or p.get("host") or "").strip()
            port = int(p.get("port", 0))
            proto = str(p.get("type") or p.get("protocol") or "http").lower()
            if proto not in PROXY_SCHEMES:
                proto = "http"
            if is_valid_ip(ip) and 1 <= port <= 65535:
                result.append({"ip": ip, "port": port, "proto": proto})
        return result
    except Exception:
        return []


def parse_openproxy(body: str, default_proto: str) -> List[Dict]:
    try:
        data = json.loads(body)
    except Exception:
        return parse_text(body, default_proto)

    result = []
    for item in data.get("data", []) if isinstance(data, dict) else []:
        proto = str(item.get("protocol", default_proto)).lower()
        if proto not in PROXY_SCHEMES:
            proto = default_proto
        for raw in item.get("items", []):
            for ip, port_text in IP_PORT_RE.findall(str(raw)):
                port = int(port_text)
                if is_valid_ip(ip) and 1 <= port <= 65535:
                    result.append({"ip": ip, "port": port, "proto": proto})
    return result


def parse_source(body: str, fmt: str, proto: str) -> List[Dict]:
    if fmt == "text":
        return parse_text(body, proto)
    if fmt == "geonode_json":
        return parse_geonode(body)
    if fmt == "sunny_json":
        return parse_sunny(body)
    if fmt == "openproxy_json":
        return parse_openproxy(body, proto)
    return []


def maybe_decode_base64_subscription(body: str) -> str:
    compact = "".join(body.split())
    if not compact or any(scheme in body for scheme in SUPPORTED_NODE_SCHEMES):
        return body
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return body
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded).decode("utf-8", errors="ignore")
            if any(scheme in decoded for scheme in SUPPORTED_NODE_SCHEMES):
                return decoded
        except Exception:
            pass
    return body


def clean_node_uri(uri: str) -> str | None:
    uri = uri.strip().strip('"\'`,;')
    if not uri.lower().startswith(SUPPORTED_NODE_SCHEMES):
        return None
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        # vmess:// обычно целиком base64; не ломаем его urlsplit-ом.
        return uri
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    fragment = quote(parts.fragment, safe="") if parts.fragment else ""
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, fragment))


def parse_subscription_nodes(body: str) -> List[str]:
    decoded = maybe_decode_base64_subscription(body)
    candidates: List[str] = []
    for line in decoded.replace("\r", "\n").split("\n"):
        line = line.strip()
        if line.lower().startswith(SUPPORTED_NODE_SCHEMES):
            candidates.append(line)
            continue
        candidates.extend(re.findall(r"(?:vless|vmess|trojan|ss|ssr)://[^\s<>\"']+", line, flags=re.I))

    nodes = []
    seen = set()
    for raw in candidates:
        node = clean_node_uri(raw)
        if node and node not in seen:
            seen.add(node)
            nodes.append(node)
    return nodes


# ──────────────────────────────────────────────
# ЗАГРУЗКА ИСТОЧНИКОВ
# ──────────────────────────────────────────────

async def fetch_text(session: aiohttp.ClientSession, src: dict) -> str | None:
    try:
        async with session.get(src["url"], timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)) as resp:
            if resp.status != 200:
                print(f"  [SKIP] {src['name']} → HTTP {resp.status}")
                return None
            return await resp.text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"  [ERR]  {src['name']} → {e}")
        return None


async def fetch_source(session: aiohttp.ClientSession, src: dict) -> List[Dict]:
    body = await fetch_text(session, src)
    if body is None:
        return []
    proxies = parse_source(body, src["format"], src["proto"])
    print(f"  [OK]   {src['name']} → {len(proxies)} прокси")
    return proxies


async def fetch_vpn_source(session: aiohttp.ClientSession, src: dict) -> List[str]:
    body = await fetch_text(session, src)
    if body is None:
        return []
    nodes = parse_subscription_nodes(body)
    print(f"  [OK]   {src['name']} → {len(nodes)} VPN-нод")
    return nodes


async def collect_vpn_nodes() -> List[str]:
    print("\n🧩 Загружаем готовые VPN-ноды для Happ/v2rayTun...")
    connector = aiohttp.TCPConnector(limit=8, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *(fetch_vpn_source(session, s) for s in VPN_NODE_SOURCES),
            return_exceptions=True,
        )

    nodes: List[str] = []
    seen = set()
    for result in results:
        if isinstance(result, list):
            for node in result:
                if node not in seen:
                    seen.add(node)
                    nodes.append(node)

    print(f"\n✅ Собрано уникальных VPN-нод: {len(nodes)}")
    return nodes


async def collect_all() -> List[Dict]:
    print("\n📡 Загружаем источники HTTP/SOCKS-прокси...")
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, s) for s in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_proxies: List[Dict] = []
    for r in results:
        if isinstance(r, list):
            all_proxies.extend(r)

    # Дедупликация по proto://ip:port, чтобы HTTP и SOCKS на одном адресе не затирали друг друга.
    seen = set()
    unique = []
    for p in all_proxies:
        proto = p.get("proto", "http")
        key = f"{proto}://{p['ip']}:{p['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(p)

    print(f"\n✅ Собрано уникальных прокси: {len(unique)}")
    return unique


# ──────────────────────────────────────────────
# ПРОВЕРКА ДОСТУПНОСТИ
# ──────────────────────────────────────────────

async def check_proxy(semaphore: asyncio.Semaphore,
                      session: aiohttp.ClientSession,
                      proxy: Dict) -> Dict | None:
    ip, port, proto = proxy["ip"], proxy["port"], proxy.get("proto", "http")
    proxy_url = f"http://{ip}:{port}"

    async with semaphore:
        t0 = time.monotonic()
        try:
            async with session.get(
                TEST_URL,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    ping = int((time.monotonic() - t0) * 1000)
                    if ping <= MAX_PING_MS:
                        return {**proxy, "proto": proto, "ping": ping}
        except Exception:
            pass
    return None


async def check_all(proxies: List[Dict]) -> List[Dict]:
    http_proxies = [p for p in proxies if p.get("proto", "http") in ("http", "https")]
    print(
        f"\n🔍 Проверяем {len(http_proxies)} HTTP/HTTPS-прокси "
        f"из {len(proxies)} собранных (параллельно {MAX_CONCURRENT_CHECKS})..."
    )
    if not http_proxies:
        return []

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_CHECKS + 10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_proxy(semaphore, session, p) for p in http_proxies]

        alive = []
        done = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            done += 1
            if result:
                alive.append(result)
            if done % 200 == 0 or done == len(tasks):
                pct = done * 100 // len(tasks)
                print(f"  [{pct:3d}%] проверено {done}/{len(tasks)}, живых HTTP: {len(alive)}")

    alive.sort(key=lambda x: x["ping"])
    print(f"\n🟢 Живых HTTP/HTTPS-прокси: {len(alive)}")
    return alive


# ──────────────────────────────────────────────
# ОПРЕДЕЛЕНИЕ СТРАНЫ (по API)
# ──────────────────────────────────────────────

async def enrich_countries(session: aiohttp.ClientSession,
                           proxies: List[Dict]) -> List[Dict]:
    """Пробуем ip-api.com batch пачками до 100 штук."""
    need = [p for p in proxies if not p.get("country")]
    if not need:
        return proxies

    for i in range(0, min(len(need), MAX_PROXIES_IN_CONFIG), 100):
        batch = need[i:i + 100]
        try:
            payload = json.dumps([{"query": p["ip"]} for p in batch])
            async with session.post(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                data=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ip_to_cc = {
                        r.get("query", ""): r.get("countryCode", "")
                        for r in data
                        if r.get("status") == "success"
                    }
                    for p in batch:
                        p["country"] = ip_to_cc.get(p["ip"], p.get("country", ""))
        except Exception:
            pass
    return proxies


# ──────────────────────────────────────────────
# ГЕНЕРАЦИЯ КОНФИГА
# ──────────────────────────────────────────────

def build_config(proxies: List[Dict], vpn_nodes: List[str] | None = None,
                 top_n: int = MAX_PROXIES_IN_CONFIG) -> str:
    vpn_nodes = vpn_nodes or []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "#profile-title: 🎮 FunVPN",
        "#profile-update-interval: 3",
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0",
        "#support-url: https://github.com/FunVPN",
        f"#announce: FunVPN — обновлено {now}. Сначала идут VLESS/Trojan/SS ноды для Happ, ниже проверенные HTTP-прокси.",
        "",
    ]

    node_count = 0
    if vpn_nodes:
        lines.append("# === VPN-ноды для Happ / v2rayTun / Hiddify ===")
        for node in vpn_nodes[:MAX_VPN_NODES_IN_CONFIG]:
            lines.append(node)
            node_count += 1
        lines.append("")

    proxy_count = 0
    if proxies:
        lines.append("# === Проверенные HTTP-прокси ===")
    for p in proxies[:top_n]:
        ip = p["ip"]
        port = p["port"]
        proto = "http" if p.get("proto", "http") == "https" else p.get("proto", "http")
        ping = p.get("ping", 0)
        country = p.get("country", "")
        flag = COUNTRY_EMOJI.get(country, "🌐")
        label = quote(f"{flag} FunVPN-HTTP-{country or 'XX'} ({ping}ms)", safe="")
        lines.append(f"{proto}://{ip}:{port}#{label}")
        proxy_count += 1

    lines.append("")
    lines.append(f"# VPN-нод в конфиге: {node_count}")
    lines.append(f"# Проверенных HTTP-прокси в конфиге: {proxy_count}")
    lines.append(f"# Обновлено: {now}")
    lines.append("# FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")

    return "\n".join(lines)


def build_json_report(proxies: List[Dict], vpn_nodes: List[str] | None = None) -> str:
    now = datetime.now(timezone.utc).isoformat()
    vpn_nodes = vpn_nodes or []
    return json.dumps({
        "updated_at": now,
        "vpn_nodes_total": len(vpn_nodes),
        "vpn_nodes_in_config": min(len(vpn_nodes), MAX_VPN_NODES_IN_CONFIG),
        "http_proxies_total": len(proxies),
        "http_proxies_in_config": min(len(proxies), MAX_PROXIES_IN_CONFIG),
        "vpn_nodes": vpn_nodes[:MAX_VPN_NODES_IN_CONFIG],
        "proxies": proxies[:MAX_PROXIES_IN_CONFIG],
        "proxy_sources": len(SOURCES),
        "vpn_node_sources": len(VPN_NODE_SOURCES),
        "credits": "FunVPN — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    }, ensure_ascii=False, indent=2)


def build_log(collected: int, alive: int, vpn_nodes: int, elapsed: float) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"=== FunVPN Proxy Robot — {now} ===\n"
        f"VPN-нод:   {vpn_nodes}\n"
        f"Прокси собрано:   {collected}\n"
        f"HTTP живых:       {alive}\n"
        f"В конфиге VPN:    {min(vpn_nodes, MAX_VPN_NODES_IN_CONFIG)}\n"
        f"В конфиге HTTP:   {min(alive, MAX_PROXIES_IN_CONFIG)}\n"
        f"Источников прокси:{len(SOURCES)}\n"
        f"Время:            {elapsed:.1f} сек\n"
        f"FUN RUSSIA CRMP | TOO Oink Tech Ltd Co\n"
    )


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

async def main():
    t_start = time.monotonic()
    print("=" * 55)
    print("🤖  FunVPN Proxy/VPN Robot")
    print("    FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")
    print("=" * 55)

    # 1. Собрать реальные VPN-ноды для Happ/v2rayTun.
    vpn_nodes = await collect_vpn_nodes()

    # 2. Собрать HTTP/SOCKS-прокси из 20+ источников.
    raw = await collect_all()

    # 3. Проверить только HTTP/HTTPS-прокси реальным запросом.
    alive = await check_all(raw)

    if not vpn_nodes and not alive:
        print("\n⚠️  Не найдено ни VPN-нод, ни живых HTTP-прокси. Конфиг не обновляется.")
        sys.exit(1)

    # 4. Страны для HTTP-прокси.
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        alive = await enrich_countries(session, alive)

    # 5. Сохранить.
    os.makedirs("configs", exist_ok=True)

    config_text = build_config(alive, vpn_nodes)
    with open(OUTPUT_CONFIG, "w", encoding="utf-8") as f:
        f.write(config_text)
    print(f"\n💾 Конфиг сохранён: {OUTPUT_CONFIG}")

    json_text = build_json_report(alive, vpn_nodes)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        f.write(json_text)
    print(f"💾 JSON отчёт: {OUTPUT_JSON}")

    elapsed = time.monotonic() - t_start
    log_text = build_log(len(raw), len(alive), len(vpn_nodes), elapsed)
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        f.write(log_text)

    print("\n" + log_text)
    print(f"✅ Готово за {elapsed:.1f} сек.")


if __name__ == "__main__":
    asyncio.run(main())
