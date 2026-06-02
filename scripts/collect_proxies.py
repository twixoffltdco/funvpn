#!/usr/bin/env python3
"""
FunVPN — Self-Healing Autonomous Proxy/VPN Collector Bot v5.0
Разработчики: FUN RUSSIA CRMP | TOO Oink Tech Ltd Co

Особенности:
- Автоматический поиск и добавление новых источников (GitHub, Telegram)
- Самовосстанавливающийся список узлов и прокси
- Протокольная проверка узлов (vless/vmess/trojan)
- 200 ГБ трафика с ежемесячным сбросом
- Приоритет ParadoxVPN в универсальном узле
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
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import quote, unquote, urlsplit, urlunsplit

# ──────────────────────────────────────────────
# НАСТРОЙКИ
# ──────────────────────────────────────────────
MAX_CONCURRENT_CHECKS   = 150
VPN_CONCURRENT_CHECKS   = 200
CHECK_TIMEOUT           = 8
VPN_CHECK_TIMEOUT       = 8
FETCH_TIMEOUT           = 30
MAX_PING_MS             = 4000
MAX_PROXIES_IN_CONFIG   = 300
MAX_VPN_NODES_IN_CONFIG = 500
MAX_SOURCES             = 150

TEST_URL                = "http://httpbin.org/ip"
OUTPUT_CONFIG = "configs/free_config.txt"
OUTPUT_JSON   = "configs/proxies.json"
OUTPUT_LOG    = "configs/last_update.log"

SUPPORTED_NODE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
PROXY_SCHEMES = ("http", "https", "socks4", "socks5")

# Параметры поискового робота
GITHUB_SEARCH_QUERIES = [
    "v2ray free config",
    "vless subscription",
    "vmess free nodes",
    "trojan free servers",
    "бесплатные vless ноды",
    "free v2ray servers list",
    "v2ray коллекция конфигураций",
    "free shadowsocks config"
]
TELEGRAM_CHANNELS = [
    "https://t.me/s/abc_configs",      # Abc Configs[reference:2]
    "https://t.me/s/vpngate_updates",  # Пример канала
    "https://t.me/s/free_v2ray_configs" # Пример канала
]

# Статичные источники (всегда в списке)
STATIC_SOURCES = [
    {"name": "ParadoxVPN", "url": "https://raw.githubusercontent.com/Parad1st/ParadoxVPN/main/configs/free_config.txt", "type": "subscription"},
    {"name": "FreeFolksOn", "url": "https://raw.githubusercontent.com/FreeFolksOn/abc-configs-free-vpn-proxy-list/main/README.md", "type": "subscription"}, # Содержит configs[reference:3]
    {"name": "RTWO2 FastNodes", "url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/README.md", "type": "subscription"}, # Содержит configs[reference:4]
    {"name": "FLAT447 V2Ray Lists", "url": "https://raw.githubusercontent.com/FLAT447/v2ray-lists/main/README.md", "type": "subscription"}, # Много ссылок[reference:5]
    {"name": "crashgfw free-airport-nodes", "url": "https://raw.githubusercontent.com/crashgfw/free-airport-nodes/main/README.md", "type": "subscription"}, # Содержит configs[reference:6]
    {"name": "MatinGhanbari v2ray-configs", "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/README.md", "type": "subscription"}, # Содержит ссылки[reference:7]
    {"name": "NinjaStrikers Nexus Nodes", "url": "https://raw.githubusercontent.com/ninjastrikers/nexus-nodes/main/README.md", "type": "subscription"}, # Много ссылок[reference:8]
    {"name": "Electron V2Ray Telegram", "url": "https://raw.githubusercontent.com/electron-v2ray/Telegram-Config-Dumpr/main/config.txt", "type": "subscription"}, # Прямая ссылка[reference:9]
    {"name": "Pourih PFS Servers", "url": "https://raw.githubusercontent.com/pourih/pfs-servers-list/main/pfs_servers.txt", "type": "subscription"}, # Прямая ссылка[reference:10]
    {"name": "Nikita29a Free Proxy List", "url": "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/README.md", "type": "subscription"} # Содержит ссылки[reference:11]
    # ... (оставлены только новые)
]

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
    "GERMANY":"DE","DEUTSCHLAND":"DE","ГЕРМАНИЯ":"DE","NETHERLANDS":"NL","HOLLAND":"NL",
    "НИДЕРЛАНДЫ":"NL","FRANCE":"FR","ФРАНЦИЯ":"FR","UNITED KINGDOM":"GB","UK":"GB",
    "BRITAIN":"GB","БРИТАНИЯ":"GB","UKRAINE":"UA","УКРАИНА":"UA","POLAND":"PL",
    "ПОЛЬША":"PL","TURKEY":"TR","ТУРЦИЯ":"TR","CHINA":"CN","КИТАЙ":"CN",
    "KOREA":"KR","КОРЕЯ":"KR","JAPAN":"JP","ЯПОНИЯ":"JP","SINGAPORE":"SG",
    "СИНГАПУР":"SG","CANADA":"CA","КАНАДА":"CA",
}

FLAG_TO_COUNTRY = {flag: code for code, flag in COUNTRY_EMOJI.items()}

# ──────────────────────────────────────────────
# РЕЗЕРВНЫЕ СТАТИЧНЫЕ НОДЫ (ВСЕГДА ЖИВЫЕ)
# ──────────────────────────────────────────────
RESERVE_STATIC_NODES = [
    "vless://478cc26d-16b3-4fdd-be64-60d5a58c1622@172.64.146.143:80?path=/&security=none&encryption=none&host=tt.andishehparenting.com&type=ws#%F0%9F%9B%A1%EF%B8%8F%20Reserve-CF-1",
    # ... (оставлены для краткости)
]

# ──────────────────────────────────────────────
# РАСШИРЕННЫЙ ПАРСИНГ ИСТОЧНИКОВ
# ──────────────────────────────────────────────

async def search_github(session: aiohttp.ClientSession, query: str) -> List[str]:
    """Ищет репозитории GitHub по ключевым словам и извлекает ссылки на конфиги."""
    urls = []
    search_url = f"https://api.github.com/search/repositories?q={quote(query)}+extension:txt+OR+path:README.md&sort=updated&order=desc&per_page=10"
    headers = {"Accept": "application/vnd.github.v3+json"}
    try:
        async with session.get(search_url, headers=headers, timeout=15) as resp:
            if resp.status == 200:
                data = await resp.json()
                for repo in data.get("items", []):
                    # Проверяем README.md и другие текстовые файлы
                    repo_url = repo.get("html_url", "")
                    if repo_url:
                        # Добавляем ссылку на сырой README
                        raw_readme = f"https://raw.githubusercontent.com/{repo['full_name']}/main/README.md"
                        urls.append(raw_readme)
                        # Ищем возможные файлы с конфигами
                        contents_url = f"https://api.github.com/repos/{repo['full_name']}/contents/"
                        try:
                            async with session.get(contents_url, headers=headers, timeout=10) as contents_resp:
                                if contents_resp.status == 200:
                                    for file in await contents_resp.json():
                                        if file.get("name", "").endswith((".txt", ".config", ".yaml", ".yml")):
                                            urls.append(file.get("download_url", ""))
                        except:
                            pass
    except Exception as e:
        print(f"GitHub search error: {e}")
    return urls

async def parse_telegram_channel(session: aiohttp.ClientSession, channel_url: str) -> List[str]:
    """Парсит Telegram канал на предмет ссылок на конфигурации."""
    urls = []
    try:
        async with session.get(channel_url, timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                # Ищем все ссылки на конфигурации в сообщениях
                config_urls = re.findall(r'(?:https?://[^\s]+\.txt|https?://[^\s]+raw[^\s]+)', text)
                urls.extend(config_urls)
    except Exception as e:
        print(f"Telegram channel parse error: {e}")
    return urls

def extract_subscription_links(content: str) -> List[str]:
    """Извлекает всевозможные ссылки на подписки из текстового содержимого."""
    urls = []
    # Шаблоны для ссылок на подписки
    patterns = [
        r'https?://raw\.githubusercontent\.com/[^\s<>"\']+\.txt',
        r'https?://[^\s<>"\']+/subscription(?:s?)/[^\s<>"\']+',
        r'https?://[^\s<>"\']+\.txt',
        r'https?://[^\s<>"\']+node[^\s<>"\']+',
        r'(?:vless|vmess|trojan|ss|ssr)://[^\s<>"\']+'
    ]
    for pattern in patterns:
        matches = re.findall(pattern, content)
        urls.extend(matches)
    return urls

async def collect_dynamic_sources(session: aiohttp.ClientSession) -> List[Dict]:
    """Собирает источники конфигураций через GitHub и Telegram."""
    dynamic_sources = []
    # Поиск на GitHub
    print("🔎 Поиск источников на GitHub...")
    github_tasks = [search_github(session, query) for query in GITHUB_SEARCH_QUERIES]
    github_results = await asyncio.gather(*github_tasks, return_exceptions=True)
    # Обработка результатов
    for result in github_results:
        if isinstance(result, list):
            for url in result:
                dynamic_sources.append({"name": f"GitHub-Auto-{len(dynamic_sources)}", "url": url, "type": "subscription"})
    # Парсинг Telegram каналов
    print("✈️ Парсинг Telegram каналов...")
    telegram_tasks = [parse_telegram_channel(session, channel) for channel in TELEGRAM_CHANNELS]
    telegram_results = await asyncio.gather(*telegram_tasks, return_exceptions=True)
    for result in telegram_results:
        if isinstance(result, list):
            for url in result:
                dynamic_sources.append({"name": f"Telegram-Auto-{len(dynamic_sources)}", "url": url, "type": "subscription"})
    # Объединяем статические и динамические источники
    all_sources = STATIC_SOURCES + dynamic_sources
    print(f"✅ Собрано источников: {len(all_sources)} (Static: {len(STATIC_SOURCES)}, Dynamic: {len(dynamic_sources)})")
    return all_sources[:MAX_SOURCES]

async def fetch_content(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Загружает содержимое по URL."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
                               headers={"User-Agent": "Mozilla/5.0 FunVPN-Robot/5.0"}) as resp:
            if resp.status == 200:
                return await resp.text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Fetch error: {e}")
    return None

async def fetch_vpn_source(session: aiohttp.ClientSession, source: Dict) -> List[str]:
    """Загружает и парсит конфиги из источника."""
    content = await fetch_content(session, source["url"])
    if not content:
        return []
    # Извлекаем ссылки на конфиги
    config_links = extract_subscription_links(content)
    nodes = []
    for link in config_links:
        # Если ссылка на файл с конфигами, загружаем его
        if link.endswith(('.txt', '.config')):
            sub_content = await fetch_content(session, link)
            if sub_content:
                nodes.extend(parse_subscription_nodes(sub_content))
        else:
            # Пробуем распарсить как конфиг
            node = clean_node_uri(link)
            if node:
                nodes.append(node)
    print(f"  [OK] {source['name']} -> {len(nodes)} нод")
    return nodes

# ──────────────────────────────────────────────
# ПРОТОКОЛЬНАЯ ПРОВЕРКА НОД
# ──────────────────────────────────────────────
# (Функции проверки протоколов и общие парсеры остались без изменений,
# так как они уже были качественно реализованы в предыдущей версии.)
# ... (Код функций decode_vmess, check_vless_proto, check_vmess_proto и т.д. здесь был бы,
# но для краткости я их опускаю, они полностью идентичны твоим.)

# Главная функция проверки узла с учётом протокола
async def check_vpn_node(semaphore: asyncio.Semaphore, node: str) -> Optional[Dict]:
    # ... (Реализация из предыдущей версии)
    pass

# ... (Остальные функции остаются без изменений)

# ──────────────────────────────────────────────
# ГЕНЕРАЦИЯ КОНФИГА С ЛИМИТОМ 200 ГБ И УНИВЕРСАЛЬНЫМ УЗЛОМ
# ──────────────────────────────────────────────

def next_month_timestamp() -> int:
    """Возвращает Unix-время начала следующего месяца (сброс трафика)."""
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    else:
        next_month = datetime(now.year, now.month + 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return int(next_month.timestamp())

def make_universal_node(alive_vpn_nodes: List[Dict]) -> Optional[str]:
    """Создаёт универсальную ноду: самая быстрая нода с приоритетом ParadoxVPN."""
    if not alive_vpn_nodes:
        return None
    # Сначала пытаемся найти ноду из ParadoxVPN
    paradox_nodes = [n for n in alive_vpn_nodes if "paradox" in n.get("uri", "").lower()]
    if paradox_nodes:
        best = min(paradox_nodes, key=lambda x: x["ping"])
    else:
        best = min(alive_vpn_nodes, key=lambda x: x["ping"])
    uri = best["uri"]
    ping = best["ping"]
    label = f"🌐 Универсальный (авто выбор) — {ping}ms"
    labeled = set_node_label(uri, label)
    return labeled if labeled else uri

def build_config(proxies: List[Dict], vpn_nodes: List[str] = None,
                 top_n: int = MAX_PROXIES_IN_CONFIG) -> str:
    vpn_nodes = vpn_nodes or []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_bytes = 200 * 1024 ** 3   # 200 ГБ в байтах
    expire_ts = next_month_timestamp()
    lines = [
        "#profile-title: base64:" + base64.b64encode("🎮 FunVPN ULTRA".encode()).decode(),
        "#profile-update-interval: 6",
        f"#subscription-userinfo: upload=0; download=0; total={total_bytes}; expire={expire_ts}",
        "#support-url: https://github.com/FunVPN",
        "#profile-web-page-url: https://github.com/FunVPN",
        f"#announce: FunVPN — обновлено {now}. 200 ГБ/мес, сброс 1-го числа.",
        "",
        "# ═══════════════════════════════════════════════════",
        "# 🛡️  РЕЗЕРВНЫЕ НОДЫ FunVPN (Cloudflare, всегда живые)",
        "# ═══════════════════════════════════════════════════",
    ]
    for static_node in RESERVE_STATIC_NODES:
        lines.append(static_node)
    lines.append("")
    node_count = len(RESERVE_STATIC_NODES)
    if vpn_nodes:
        lines.append("# ═══════════════════════════════════════════════════")
        lines.append("# 🌐  ОСНОВНЫЕ VPN-НОДЫ (проверены по протоколу)")
        lines.append("# ═══════════════════════════════════════════════════")
        # Добавляем универсальный узел (самый быстрый) в начало
        fastest = vpn_nodes[0]
        ping_match = re.search(r"\((\d+)ms\)", fastest)
        ping_str = f" — {ping_match.group(1)}ms" if ping_match else ""
        universal_label = f"🌐 Универсальный (авто выбор){ping_str}"
        universal_node = set_node_label(fastest, universal_label)
        lines.append(universal_node if universal_node else fastest)
        node_count += 1
        # Остальные ноды
        for node in vpn_nodes[1:MAX_VPN_NODES_IN_CONFIG]:
            lines.append(node)
            node_count += 1
        lines.append("")
    proxy_count = 0
    if proxies:
        lines.append("# ═══════════════════════════════════════════════════")
        lines.append("# 🔗  ПРОВЕРЕННЫЕ HTTP-ПРОКСИ")
        lines.append("# ═══════════════════════════════════════════════════")
    for idx, p in enumerate(proxies[:top_n], start=1):
        ip, port = p["ip"], p["port"]
        proto = "http" if p.get("proto", "http") == "https" else p.get("proto", "http")
        ping = p.get("ping", 0)
        country = p.get("country", "")
        flag = COUNTRY_EMOJI.get(country, "🌐")
        country_name = COUNTRY_NAMES_RU.get(country, country or "Auto")
        label = quote(f"{flag} HTTP {country_name} {idx:03d} ({ping}ms)", safe="")
        lines.append(f"{proto}://{ip}:{port}#{label}")
        proxy_count += 1
    lines += [
        "",
        f"# VPN-нод в конфиге: {node_count}",
        f"# Проверенных HTTP-прокси в конфиге: {proxy_count}",
        f"# Обновлено: {now}",
        "# FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    ]
    return "\n".join(lines)

# ... (Остальные функции build_json, build_log, main остаются без изменений)

async def main():
    # Основная логика с новым сборщиком источников
    t_start = time.monotonic()
    print("=" * 55)
    print("🤖  FunVPN Self-Healing Robot v5.0")
    print("    FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")
    print("=" * 55)
    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 1. Собираем динамические источники
        print("🔍 Сбор динамических источников...")
        sources = await collect_dynamic_sources(session)
        # 2. Загружаем ParadoxVPN отдельно (он всегда в приоритете)
        paradox_nodes = []
        paradox_source = next((s for s in sources if s["name"] == "ParadoxVPN"), None)
        if paradox_source:
            paradox_nodes = await fetch_vpn_source(session, paradox_source)
        # 3. Загружаем остальные источники
        other_sources = [s for s in sources if s["name"] != "ParadoxVPN"]
        other_nodes = []
        for source in other_sources:
            nodes = await fetch_vpn_source(session, source)
            other_nodes.extend(nodes)
        # 4. Объединяем, проверяем, генерируем
        all_nodes = paradox_nodes + other_nodes
        print(f"\n📦 Всего нод до проверки: {len(all_nodes)}")
        alive_nodes = await check_all_vpn_nodes(all_nodes)
        vpn_nodes = relabel_vpn_nodes(alive_nodes)
        # 5. Прокси и финальные шаги
        raw_proxies = await collect_proxies() # Оставляем из старой версии
        alive_proxies = await check_all_proxies(raw_proxies)
        async with aiohttp.ClientSession(connector=connector) as session:
            alive_proxies = await enrich_countries(session, alive_proxies)
        # Сохраняем результаты
        os.makedirs("configs", exist_ok=True)
        config = build_config(alive_proxies, vpn_nodes)
        with open(OUTPUT_CONFIG, "w", encoding="utf-8") as f:
            f.write(config)
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            f.write(build_json_report(alive_proxies, vpn_nodes))
        elapsed = time.monotonic() - t_start
        log_text = build_log(len(raw_proxies), len(alive_proxies), len(vpn_nodes), elapsed)
        with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
            f.write(log_text)
        print("\n" + log_text)
        print(f"✅ Готово за {elapsed:.1f} сек.")

if __name__ == "__main__":
    asyncio.run(main())
