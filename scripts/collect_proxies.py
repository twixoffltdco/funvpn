#!/usr/bin/env python3
"""
FunVPN — Proxy Collector Bot
Разработчики: FUN RUSSIA CRMP | TOO Oink Tech Ltd Co

Собирает публичные прокси из открытых источников,
проверяет их доступность и обновляет конфиг.
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
from typing import List, Dict

# ──────────────────────────────────────────────
# НАСТРОЙКИ
# ──────────────────────────────────────────────
MAX_CONCURRENT_CHECKS = 80       # параллельных проверок
CHECK_TIMEOUT         = 6        # секунд на один прокси
MAX_PING_MS           = 5000     # максимальный принимаемый пинг
MAX_PROXIES_IN_CONFIG = 200      # лимит строк в итоговом конфиге
TEST_URL              = "http://httpbin.org/ip"   # что открываем через прокси

OUTPUT_CONFIG         = "configs/free_config.txt"
OUTPUT_JSON           = "configs/proxies.json"
OUTPUT_LOG            = "configs/last_update.log"

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
# ИСТОЧНИКИ ПУБЛИЧНЫХ ПРОКСИ (бесплатные листы)
# ──────────────────────────────────────────────
SOURCES = [
    {
        "name": "ProxyScrape HTTP",
        "url": "https://api.proxyscrape.com/v3/free-proxy-list/get"
                "?request=displayproxies&protocol=http&timeout=5000"
                "&country=all&ssl=all&anonymity=all",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "ProxyScrape SOCKS5",
        "url": "https://api.proxyscrape.com/v3/free-proxy-list/get"
                "?request=displayproxies&protocol=socks5&timeout=5000",
        "format": "text",
        "proto": "socks5",
    },
    {
        "name": "ProxyScrape SOCKS4",
        "url": "https://api.proxyscrape.com/v3/free-proxy-list/get"
                "?request=displayproxies&protocol=socks4&timeout=5000",
        "format": "text",
        "proto": "socks4",
    },
    {
        "name": "GeoNode Free",
        "url": "https://proxylist.geonode.com/api/proxy-list"
                "?limit=100&page=1&sort_by=lastChecked&sort_type=desc"
                "&protocols=http%2Chttps%2Csocks4%2Csocks5",
        "format": "geonode_json",
        "proto": "mixed",
    },
    {
        "name": "Spys.me HTTP",
        "url": "https://spys.me/proxy.txt",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "Free-Proxy-List.net",
        "url": "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "TheSpeedX/PROXY-List HTTP",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "TheSpeedX/PROXY-List SOCKS5",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "format": "text",
        "proto": "socks5",
    },
    {
        "name": "TheSpeedX/PROXY-List SOCKS4",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "format": "text",
        "proto": "socks4",
    },
    {
        "name": "hookzof/socks5_list",
        "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "format": "text",
        "proto": "socks5",
    },
    {
        "name": "monosans/proxy-list HTTP",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "monosans/proxy-list SOCKS5",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "format": "text",
        "proto": "socks5",
    },
    {
        "name": "jetkai/proxy-list HTTP",
        "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "jetkai/proxy-list SOCKS5",
        "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "format": "text",
        "proto": "socks5",
    },
    {
        "name": "ShiftyTR/Proxy-List",
        "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "format": "text",
        "proto": "http",
    },
    {
        "name": "sunny9577/proxy-scraper",
        "url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.json",
        "format": "sunny_json",
        "proto": "http",
    },
]

# ──────────────────────────────────────────────
# ПАРСЕРЫ
# ──────────────────────────────────────────────

def parse_text(body: str, proto: str) -> List[Dict]:
    """ip:port построчно"""
    proxies = []
    for line in body.splitlines():
        line = line.strip()
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})", line)
        if m:
            proxies.append({"ip": m.group(1), "port": int(m.group(2)), "proto": proto})
    return proxies


def parse_geonode(body: str) -> List[Dict]:
    try:
        data = json.loads(body)
        result = []
        for p in data.get("data", []):
            ip   = p.get("ip", "")
            port = int(p.get("port", 0))
            protos = p.get("protocols", ["http"])
            proto  = protos[0] if protos else "http"
            country = p.get("country", "")
            if ip and port:
                result.append({"ip": ip, "port": port, "proto": proto, "country": country})
        return result
    except Exception:
        return []


def parse_sunny(body: str) -> List[Dict]:
    try:
        data = json.loads(body)
        result = []
        for p in data:
            if "ip" in p and "port" in p:
                result.append({"ip": p["ip"], "port": int(p["port"]), "proto": "http"})
        return result
    except Exception:
        return []


def parse_source(body: str, fmt: str, proto: str) -> List[Dict]:
    if fmt == "text":         return parse_text(body, proto)
    if fmt == "geonode_json": return parse_geonode(body)
    if fmt == "sunny_json":   return parse_sunny(body)
    return []


# ──────────────────────────────────────────────
# ЗАГРУЗКА ИСТОЧНИКОВ
# ──────────────────────────────────────────────

async def fetch_source(session: aiohttp.ClientSession, src: dict) -> List[Dict]:
    try:
        async with session.get(src["url"], timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                print(f"  [SKIP] {src['name']} → HTTP {resp.status}")
                return []
            body = await resp.text(encoding="utf-8", errors="ignore")
            proxies = parse_source(body, src["format"], src["proto"])
            print(f"  [OK]   {src['name']} → {len(proxies)} записей")
            return proxies
    except Exception as e:
        print(f"  [ERR]  {src['name']} → {e}")
        return []


async def collect_all() -> List[Dict]:
    print("\n📡 Загружаем источники прокси...")
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, s) for s in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_proxies: List[Dict] = []
    for r in results:
        if isinstance(r, list):
            all_proxies.extend(r)

    # Дедупликация по ip:port
    seen = set()
    unique = []
    for p in all_proxies:
        key = f"{p['ip']}:{p['port']}"
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

    if proto in ("socks4", "socks5"):
        proxy_url = f"{proto}://{ip}:{port}"
    else:
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
                        return {**proxy, "ping": ping}
        except Exception:
            pass
    return None


async def check_all(proxies: List[Dict]) -> List[Dict]:
    print(f"\n🔍 Проверяем {len(proxies)} прокси (параллельно {MAX_CONCURRENT_CHECKS})...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    # aiohttp не поддерживает socks «из коробки» — нужен aiohttp-socks.
    # Если его нет, проверяем только http-прокси через стандартный клиент.
    try:
        from aiohttp_socks import ProxyConnector  # noqa: F401
        has_socks = True
    except ImportError:
        has_socks = False
        proxies = [p for p in proxies if p.get("proto", "http") == "http"]
        print("  ⚠️  aiohttp-socks не установлен — проверяем только HTTP-прокси")

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_CHECKS + 10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_proxy(semaphore, session, p) for p in proxies]

        alive = []
        done = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            done += 1
            if result:
                alive.append(result)
            if done % 200 == 0 or done == len(tasks):
                pct = done * 100 // len(tasks)
                print(f"  [{pct:3d}%] проверено {done}/{len(tasks)}, живых: {len(alive)}")

    alive.sort(key=lambda x: x["ping"])
    print(f"\n🟢 Живых прокси: {len(alive)}")
    return alive


# ──────────────────────────────────────────────
# ОПРЕДЕЛЕНИЕ СТРАНЫ (по диапазонам или API)
# ──────────────────────────────────────────────

async def enrich_countries(session: aiohttp.ClientSession,
                             proxies: List[Dict]) -> List[Dict]:
    """Пробуем ip-api.com batch (до 100 штук бесплатно)"""
    need = [p for p in proxies if not p.get("country")]
    if not need:
        return proxies

    batch = need[:100]
    try:
        payload = json.dumps([{"query": p["ip"]} for p in batch])
        async with session.post(
            "http://ip-api.com/batch?fields=countryCode,query",
            data=payload,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                ip_to_cc = {r.get("query",""): r.get("countryCode","") for r in data}
                for p in proxies:
                    if not p.get("country"):
                        p["country"] = ip_to_cc.get(p["ip"], "")
    except Exception:
        pass
    return proxies


# ──────────────────────────────────────────────
# ГЕНЕРАЦИЯ КОНФИГА
# ──────────────────────────────────────────────

def build_config(proxies: List[Dict], top_n: int = MAX_PROXIES_IN_CONFIG) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"#profile-title: 🎮 FunVPN",
        f"#profile-update-interval: 6",
        f"#subscription-userinfo: upload=0; download=0; total=0; expire=0",
        f"#support-url: https://github.com/FunVPN",
        f"#announce: FunVPN — обновлено {now} | FUN RUSSIA CRMP | Oink Tech Ltd Co",
        "",
    ]

    added = 0
    for p in proxies[:top_n]:
        ip      = p["ip"]
        port    = p["port"]
        proto   = p.get("proto", "http")
        ping    = p.get("ping", 0)
        country = p.get("country", "")
        flag    = COUNTRY_EMOJI.get(country, "🌐")
        label   = f"{flag} FunVPN-{country or 'XX'} ({ping}ms)"

        if proto == "http":
            # Оборачиваем HTTP-прокси как VLESS-запись (совместимо с Happ/v2rayTun)
            encoded_label = label.encode("utf-8")
            # Простой текстовый формат: http://ip:port#label
            lines.append(f"http://{ip}:{port}#{label}")
        elif proto in ("socks5", "socks4"):
            lines.append(f"{proto}://{ip}:{port}#{label}")
        else:
            lines.append(f"http://{ip}:{port}#{label}")

        added += 1

    lines.append("")
    lines.append(f"# Всего активных серверов: {added}")
    lines.append(f"# Обновлено: {now}")
    lines.append("# FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")

    return "\n".join(lines)


def build_json_report(proxies: List[Dict]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    return json.dumps({
        "updated_at": now,
        "total": len(proxies),
        "proxies": proxies[:MAX_PROXIES_IN_CONFIG],
        "credits": "FunVPN — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    }, ensure_ascii=False, indent=2)


def build_log(collected: int, alive: int, elapsed: float) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"=== FunVPN Proxy Robot — {now} ===\n"
        f"Собрано:   {collected}\n"
        f"Живых:     {alive}\n"
        f"В конфиге: {min(alive, MAX_PROXIES_IN_CONFIG)}\n"
        f"Время:     {elapsed:.1f} сек\n"
        f"FUN RUSSIA CRMP | TOO Oink Tech Ltd Co\n"
    )


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

async def main():
    t_start = time.monotonic()
    print("=" * 55)
    print("🤖  FunVPN Proxy Robot")
    print("    FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")
    print("=" * 55)

    # 1. Собрать
    raw = await collect_all()

    # 2. Проверить
    alive = await check_all(raw)

    if not alive:
        print("\n⚠️  Живых прокси не найдено. Конфиг не обновляется.")
        sys.exit(1)

    # 3. Страны
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        alive = await enrich_countries(session, alive)

    # 4. Сохранить
    os.makedirs("configs", exist_ok=True)

    config_text = build_config(alive)
    with open(OUTPUT_CONFIG, "w", encoding="utf-8") as f:
        f.write(config_text)
    print(f"\n💾 Конфиг сохранён: {OUTPUT_CONFIG}")

    json_text = build_json_report(alive)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        f.write(json_text)
    print(f"💾 JSON отчёт: {OUTPUT_JSON}")

    elapsed = time.monotonic() - t_start
    log_text = build_log(len(raw), len(alive), elapsed)
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        f.write(log_text)

    print("\n" + log_text)
    print(f"✅ Готово за {elapsed:.1f} сек.")


if __name__ == "__main__":
    asyncio.run(main())
