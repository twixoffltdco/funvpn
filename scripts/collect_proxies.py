#!/usr/bin/env python3
"""
FunVPN — Proxy/VPN Collector Bot v3.0 (Self-Healing)
Разработчики: FUN RUSSIA CRMP | TOO Oink Tech Ltd Co

Добавлено:
- Автоматический поиск новых источников (GitHub, Telegram)
- Универсальный узел теперь выбирает самую быструю ноду (приоритет ParadoxVPN)
- 200 ГБ трафика с ежемесячным сбросом 1-го числа
"""

import asyncio
import aiohttp
import json
import re
import os
import time
import base64
import random
import sys
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
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
TEST_URL                = "http://httpbin.org/ip"
MIN_VPN_NODE_SOURCES    = 10

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
    "free v2ray servers list"
]
TELEGRAM_CHANNELS = [
    "https://t.me/s/abc_configs",
    "https://t.me/s/vpngate_updates",
    "https://t.me/s/free_v2ray_configs"
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

# ──────────────────────────────────────────────
# РЕЗЕРВНЫЕ СТАТИЧНЫЕ НОДЫ (всегда в конфиге)
# Cloudflare-based — максимально стабильные
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
# ИСТОЧНИКИ VPN-НОД (старые + новые) — ВСЕ ТВОИ
# ──────────────────────────────────────────────
VPN_NODE_SOURCES = [
    {"name": "ParadoxVPN free_config",       "url": "https://raw.githubusercontent.com/Parad1st/ParadoxVPN/main/configs/free_config.txt",                              "format": "subscription"},
    {"name": "mahdibland V2RayAggregator",   "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",                          "format": "subscription"},
    {"name": "aiboboxx v2rayfree",           "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                                                   "format": "subscription"},
    {"name": "Pawdroid Free-servers",        "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",                                               "format": "subscription"},
    {"name": "Barabama FreeNodes merge",     "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt",                                     "format": "subscription"},
    {"name": "Epodonios v2ray-configs all",  "url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",                             "format": "subscription"},
    {"name": "mheidari98 aggregated",        "url": "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",                                                   "format": "subscription"},
    {"name": "ermaozi get_subscribe main",   "url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",                               "format": "subscription"},
    {"name": "anaer/Sub nodes",              "url": "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",                                                    "format": "subscription"},
    {"name": "peasoft NoMoreWalls",          "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",                                          "format": "subscription"},
    {"name": "Leon406 SubCrawler nodes",     "url": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all",                                        "format": "subscription"},
    {"name": "free18 v2ray",                 "url": "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",                                                      "format": "subscription"},
    {"name": "go4sharing sub",               "url": "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",                                                 "format": "subscription"},
    {"name": "surfboardv2ray proxy-list",    "url": "https://raw.githubusercontent.com/surfboardv2ray/TGParse/main/configtg.txt",                                     "format": "subscription"},
    {"name": "pojiezhiyuanjun freev2",       "url": "https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/0827.txt",                                       "format": "subscription"},
    {"name": "chengaopan AutoMerge",         "url": "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",                              "format": "subscription"},
    {"name": "vxiaov free_proxies",          "url": "https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml",                           "format": "subscription"},
    {"name": "YasserDivaR v2ray-configs",    "url": "https://raw.githubusercontent.com/YasserDivaR/pr0xy/main/V2Ray.txt",                                            "format": "subscription"},
    {"name": "ssrsub v2ray",                 "url": "https://raw.githubusercontent.com/ssrsub/ssr/master/V2Ray",                                                      "format": "subscription"},
    {"name": "freefq free",                  "url": "https://raw.githubusercontent.com/freefq/free/master/v2",                                                        "format": "subscription"},
    # ── НОВЫЕ ──
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
    {"name": "resasanian Mirza sub",         "url": "https://raw.githubusercontent.com/resasanian/Mirza/main/sub",                                                    "format": "subscription"},
    {"name": "Everyday-VPN main",            "url": "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",                         "format": "subscription"},
    {"name": "ALIILAPRO v2rayNG",            "url": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",                                        "format": "subscription"},
    {"name": "soroushmirzaei mixed",         "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",                "format": "subscription"},
    {"name": "soroushmirzaei vless",         "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless",                "format": "subscription"},
    {"name": "soroushmirzaei trojan",        "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan",               "format": "subscription"},
    {"name": "roosterkid V2RAY_RAW",         "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",                                  "format": "subscription"},
    {"name": "tbbatbb v2ray config",         "url": "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",                                  "format": "subscription"},
    {"name": "LidongSub Free-Nodes",         "url": "https://raw.githubusercontent.com/LidongSub/Free-Nodes/main/sub",                                               "format": "subscription"},
    {"name": "MrPooyaX VpnsFucking",         "url": "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/Shitte.txt",                                        "format": "subscription"},
    {"name": "w1g007 free-nodes",            "url": "https://raw.githubusercontent.com/w1g007/free-v2ray-nodes/main/sub", "format": "subscription"},
    {"name": "mahdibland merged", "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt", "format": "subscription"},
    {"name": "Epodonios ALL", "url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt", "format": "subscription"},
    {"name": "Leon406 all", "url": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all", "format": "subscription"},
    {"name": "chengaopan merged", "url": "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt", "format": "subscription"},
    {"name": "soroushmirzaei mixed", "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed", "format": "subscription"},
    {"name": "awesome-vpn all", "url": "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all", "format": "subscription"},
    {"name": "barry-far ALL", "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt", "format": "subscription"},
    {"name": "barry-far vless", "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt", "format": "subscription"},
    {"name": "barry-far vmess", "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt", "format": "subscription"},
    {"name": "barry-far trojan", "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt", "format": "subscription"},
    {"name": "barry-far ss", "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt", "format": "subscription"},
    {"name": "MatinGhanbari super", "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "format": "subscription"},
    {"name": "MatinGhanbari vless", "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt", "format": "subscription"},
    {"name": "MatinGhanbari trojan", "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt", "format": "subscription"},
    {"name": "MatinGhanbari vmess", "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt", "format": "subscription"},
    {"name": "igareck vless-reality", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt", "format": "subscription"},
    {"name": "igareck general", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/General-Sub.txt", "format": "subscription"},
    {"name": "soroushmirzaei vless", "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless", "format": "subscription"},
    {"name": "soroushmirzaei trojan", "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan", "format": "subscription"},
    {"name": "soroushmirzaei vmess", "url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vmess", "format": "subscription"},
    {"name": "aiboboxx v2rayfree", "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2", "format": "subscription"},
    {"name": "Pawdroid sub", "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "format": "subscription"},
    {"name": "Barabama merged", "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt", "format": "subscription"},
    {"name": "mheidari98 all", "url": "https://raw.githubusercontent.com/mheidari98/.proxy/main/all", "format": "subscription"},
    {"name": "ermaozi v2ray", "url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", "format": "subscription"},
    {"name": "peasoft NoMoreWalls", "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", "format": "subscription"},
    {"name": "free18 v2ray", "url": "https://raw.githubusercontent.com/free18/v2ray/main/v.txt", "format": "subscription"},
    {"name": "surfboardv2ray tgparse", "url": "https://raw.githubusercontent.com/surfboardv2ray/TGParse/main/configtg.txt", "format": "subscription"},
    {"name": "YasserDivaR pr0xy", "url": "https://raw.githubusercontent.com/YasserDivaR/pr0xy/main/V2Ray.txt", "format": "subscription"},
    {"name": "ssrsub V2Ray", "url": "https://raw.githubusercontent.com/ssrsub/ssr/master/V2Ray", "format": "subscription"},
    {"name": "freefq free", "url": "https://raw.githubusercontent.com/freefq/free/master/v2", "format": "subscription"},
    {"name": "ALIILAPRO v2rayNG", "url": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt", "format": "subscription"},
    {"name": "Everyday-VPN main", "url": "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt", "format": "subscription"},
    {"name": "IranianCypherpunks", "url": "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config", "format": "subscription"},
    {"name": "resasanian Mirza", "url": "https://raw.githubusercontent.com/resasanian/Mirza/main/sub", "format": "subscription"},
    {"name": "MrPooyaX VpnsFucking", "url": "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/Shitte.txt", "format": "subscription"},
    {"name": "roosterkid V2RAY", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", "format": "subscription"},
    {"name": "tbbatbb v2ray", "url": "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt", "format": "subscription"},
    {"name": "vxiaov free_proxies", "url": "https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml", "format": "subscription"},
    {"name": "anaer Sub", "url": "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml", "format": "subscription"},
    {"name": "freev2ray sub", "url": "https://raw.githubusercontent.com/xrayfree/free-ssr-ss-v2ray-vpn-clash/main/sub/sub.txt", "format": "subscription"},
    {"name": "liasica shadowrocket", "url": "https://raw.githubusercontent.com/liasica/liasicaSSR/master/Shadowrocket", "format": "subscription"},
    {"name": "Flik91 v2rayN", "url": "https://raw.githubusercontent.com/Flik91/Xray-Sub/main/vless_vmess.txt", "format": "subscription"},
    {"name": "coldwater v2ray", "url": "https://raw.githubusercontent.com/coldwater-10/V2Hub/main/split/reality", "format": "subscription"},
    {"name": "coldwater v2hub all", "url": "https://raw.githubusercontent.com/coldwater-10/V2Hub/main/V2Hub", "format": "subscription"},
    {"name": "Renzhan v2ray", "url": "https://raw.githubusercontent.com/Renzhan/vProxy/main/merge", "format": "subscription"},
    {"name": "ts-sf clash", "url": "https://raw.githubusercontent.com/ts-sf/fly/main/v2", "format": "subscription"},
    {"name": "w1g007 nodes", "url": "https://raw.githubusercontent.com/w1g007/free-v2ray-nodes/main/sub", "format": "subscription"},
    {"name": "LidongSub nodes", "url": "https://raw.githubusercontent.com/LidongSub/Free-Nodes/main/sub", "format": "subscription"},
    {"name": "pawdroid2 sub", "url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub", "format": "subscription"},
    {"name": "vpn-configs-free", "url": "https://raw.githubusercontent.com/vpn-configs-free/free-vpn-configs/main/subscriptions/all", "format": "subscription"},
    {"name": "pojiezhiyuanjun freev2", "url": "https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/0827.txt", "format": "subscription"},
    {"name": "go4sharing sub", "url": "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml", "format": "subscription"},
    {"name": "freev2ray_links", "url": "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt", "format": "subscription"},
    {"name": "mahsanet mtn", "url": "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt", "format": "subscription"},
    {"name": "mahsanet sub2", "url": "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_2.txt", "format": "subscription"},
    {"name": "arshiacomplus configs", "url": "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix.html", "format": "subscription"},
    {"name": "yebekhe TVC", "url": "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix", "format": "subscription"},
    {"name": "yebekhe TVC plain", "url": "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix", "format": "subscription"},
    {"name": "lagzian v2ray", "url": "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS_new.txt", "format": "subscription"},
    {"name": "lagzian TG configs", "url": "https://raw.githubusercontent.com/lagzian/TG-Collector/main/protocols/mix", "format": "subscription"},
    {"name": "mfuu clash", "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml", "format": "subscription"},
    {"name": "mfuu v2ray", "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "format": "subscription"},
    {"name": "itsyebekhe meta", "url": "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix", "format": "subscription"},
    {"name": "Surfboardv2ray API", "url": "https://raw.githubusercontent.com/surfboardv2ray/Subs/main/Raw", "format": "subscription"},
    {"name": "Sub-Zero mix", "url": "https://raw.githubusercontent.com/Sub-Zero-1/V2Ray/main/Sub-Zero", "format": "subscription"},
    {"name": "zhangkaiitugithub openit", "url": "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml", "format": "subscription"}
]

# ──────────────────────────────────────────────
# ИСТОЧНИКИ HTTP/SOCKS ПРОКСИ (все твои)
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
    {"name": "barry-far ALL",          "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",                         "format": "v2ray", "proto": "v2ray"},
    {"name": "barry-far vless",        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",              "format": "v2ray", "proto": "v2ray"},
    {"name": "barry-far vmess",        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",              "format": "v2ray", "proto": "v2ray"},
    {"name": "barry-far trojan",       "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",             "format": "v2ray", "proto": "v2ray"},
    {"name": "barry-far ss",           "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt",                 "format": "v2ray", "proto": "v2ray"},
    {"name": "MatinGhanbari super",    "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",      "format": "v2ray", "proto": "v2ray"},
    {"name": "MatinGhanbari vless",    "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",  "format": "v2ray", "proto": "v2ray"},
    {"name": "MatinGhanbari vmess",    "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",  "format": "v2ray", "proto": "v2ray"},
    {"name": "MatinGhanbari trojan",   "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt", "format": "v2ray", "proto": "v2ray"},
    {"name": "Epodonios ALL",          "url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",                        "format": "v2ray", "proto": "v2ray"},
    {"name": "igareck vless-reality",  "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt", "format": "v2ray", "proto": "v2ray"},
    {"name": "igareck general",        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/General-Sub.txt",                     "format": "v2ray", "proto": "v2ray"},
    {"name": "mahdibland merged",      "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",                     "format": "v2ray", "proto": "v2ray"},
    {"name": "Leon406 all",            "url": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all",                                   "format": "v2ray", "proto": "v2ray"},
    {"name": "peasoft NoMoreWalls",    "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",                                     "format": "v2ray", "proto": "v2ray"},
    {"name": "aiboboxx v2rayfree",     "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                                              "format": "v2ray", "proto": "v2ray"},
    {"name": "Pawdroid sub",           "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",                                          "format": "v2ray", "proto": "v2ray"},
    {"name": "freefq free",            "url": "https://raw.githubusercontent.com/freefq/free/master/v2",                                                   "format": "v2ray", "proto": "v2ray"},
    {"name": "ermaozi v2ray",          "url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",                          "format": "v2ray", "proto": "v2ray"},
    {"name": "mheidari all",           "url": "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",                                              "format": "v2ray", "proto": "v2ray"},
    {"name": "chengaopan merged",      "url": "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",                        "format": "v2ray", "proto": "v2ray"},
    {"name": "ssrsub V2Ray",           "url": "https://raw.githubusercontent.com/ssrsub/ssr/master/V2Ray",                                                 "format": "v2ray", "proto": "v2ray"},
    {"name": "Barabama merged",        "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt",                                "format": "v2ray", "proto": "v2ray"},
    {"name": "free18 v2ray",           "url": "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",                                                 "format": "v2ray", "proto": "v2ray"},
    {"name": "YasserDivaR pr0xy",      "url": "https://raw.githubusercontent.com/YasserDivaR/pr0xy/main/V2Ray.txt",                                       "format": "v2ray", "proto": "v2ray"},
    {"name": "surfboardv2ray tgparse", "url": "https://raw.githubusercontent.com/surfboardv2ray/TGParse/main/configtg.txt",                                "format": "v2ray", "proto": "v2ray"},
    {"name": "ProxyScrape HTTP",   "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",  "format": "text", "proto": "http"},
    {"name": "ProxyScrape HTTPS",  "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all", "format": "text", "proto": "https"},
    {"name": "ProxyScrape SOCKS5", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=5000",        "format": "text", "proto": "socks5"},
    {"name": "ProxyScrape SOCKS4", "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=5000",        "format": "text", "proto": "socks4"},
    {"name": "GeoNode Free",       "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps%2Csocks4%2Csocks5", "format": "geonode_json", "proto": "mixed"},
    {"name": "OpenProxySpace HTTP",    "url": "https://api.openproxy.space/list/http",   "format": "openproxy_json", "proto": "http"},
    {"name": "OpenProxySpace SOCKS4",  "url": "https://api.openproxy.space/list/socks4", "format": "openproxy_json", "proto": "socks4"},
    {"name": "OpenProxySpace SOCKS5",  "url": "https://api.openproxy.space/list/socks5", "format": "openproxy_json", "proto": "socks5"},
    {"name": "Proxy-List.download HTTP",   "url": "https://www.proxy-list.download/api/v1/get?type=http",   "format": "text", "proto": "http"},
    {"name": "Proxy-List.download HTTPS",  "url": "https://www.proxy-list.download/api/v1/get?type=https",  "format": "text", "proto": "https"},
    {"name": "Proxy-List.download SOCKS4", "url": "https://www.proxy-list.download/api/v1/get?type=socks4", "format": "text", "proto": "socks4"},
    {"name": "Proxy-List.download SOCKS5", "url": "https://www.proxy-list.download/api/v1/get?type=socks5", "format": "text", "proto": "socks5"},
    {"name": "Spys.me HTTP",              "url": "https://spys.me/proxy.txt",                                                          "format": "text", "proto": "http"},
    {"name": "clarketm/proxy-list",       "url": "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",   "format": "text", "proto": "http"},
    {"name": "TheSpeedX HTTP",   "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",   "format": "text", "proto": "http"},
    {"name": "TheSpeedX SOCKS5", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "TheSpeedX SOCKS4", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "format": "text", "proto": "socks4"},
    {"name": "monosans HTTP",    "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",   "format": "text", "proto": "http"},
    {"name": "monosans HTTPS",   "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt",  "format": "text", "proto": "https"},
    {"name": "monosans SOCKS4",  "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "format": "text", "proto": "socks4"},
    {"name": "monosans SOCKS5",  "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "jetkai HTTP",   "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",   "format": "text", "proto": "http"},
    {"name": "jetkai HTTPS",  "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",  "format": "text", "proto": "https"},
    {"name": "jetkai SOCKS4", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "format": "text", "proto": "socks4"},
    {"name": "jetkai SOCKS5", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "hookzof/socks5_list",          "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",                          "format": "text", "proto": "socks5"},
    {"name": "ShiftyTR HTTP",                "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",                           "format": "text", "proto": "http"},
    {"name": "sunny9577 proxy-scraper",      "url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.json",                   "format": "sunny_json", "proto": "http"},
    {"name": "roosterkid HTTPS_RAW",  "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",  "format": "text", "proto": "https"},
    {"name": "roosterkid SOCKS4_RAW", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "format": "text", "proto": "socks4"},
    {"name": "roosterkid SOCKS5_RAW", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "format": "text", "proto": "socks5"},
    {"name": "officialputuid KANG HTTP", "url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt", "format": "text", "proto": "http"},
    # ── Новые источники прокси ──
    {"name": "proxifly HTTP",   "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",   "format": "text", "proto": "http"},
    {"name": "proxifly SOCKS5", "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt", "format": "text", "proto": "socks5"},
    {"name": "mmpx12 HTTP",    "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",   "format": "text", "proto": "http"},
    {"name": "mmpx12 SOCKS5",  "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "Anonym0usWork HTTP",  "url": "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",   "format": "text", "proto": "http"},
    {"name": "Anonym0usWork S5",    "url": "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt", "format": "text", "proto": "socks5"},
    {"name": "zloi-user SOCKS5",   "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt", "format": "text", "proto": "socks5"},
    {"name": "zloi-user HTTP",     "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",   "format": "text", "proto": "http"},
    {"name": "HyperBeats HTTP",    "url": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt", "format": "text", "proto": "http"},
]

IP_PORT_RE = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})(?!\d)")

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (все твои, без изменений) ----------
def is_valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in ip.split(".")) and ip.count(".") == 3
    except ValueError:
        return False

def parse_text(body: str, proto: str) -> List[Dict]:
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

COUNTRY_NAMES_RU = {
    "RU": "Россия", "US": "США", "DE": "Германия", "NL": "Нидерланды", "FR": "Франция",
    "GB": "Британия", "UA": "Украина", "PL": "Польша", "TR": "Турция", "CN": "Китай",
    "KR": "Корея", "JP": "Япония", "SG": "Сингапур", "IN": "Индия", "BR": "Бразилия",
    "CA": "Канада", "AU": "Австралия", "IT": "Италия", "ES": "Испания", "FI": "Финляндия",
    "SE": "Швеция", "NO": "Норвегия", "CH": "Швейцария", "AT": "Австрия", "CZ": "Чехия",
    "HU": "Венгрия", "RO": "Румыния", "BG": "Болгария", "SK": "Словакия", "LT": "Литва",
    "LV": "Латвия", "EE": "Эстония", "GR": "Греция", "HR": "Хорватия", "RS": "Сербия",
    "BA": "Босния", "MD": "Молдова", "AM": "Армения", "GE": "Грузия", "KZ": "Казахстан",
    "BY": "Беларусь", "AZ": "Азербайджан", "UZ": "Узбекистан", "TH": "Таиланд", "VN": "Вьетнам",
    "ID": "Индонезия", "MY": "Малайзия", "PH": "Филиппины", "HK": "Гонконг", "TW": "Тайвань",
    "MX": "Мексика", "AR": "Аргентина", "CL": "Чили", "CO": "Колумбия", "ZA": "ЮАР",
    "IR": "Иран", "AE": "ОАЭ", "IL": "Израиль",
}

COUNTRY_ALIASES = {
    "RUSSIA": "RU", "РОССИЯ": "RU", "RU": "RU",
    "USA": "US", "UNITED STATES": "US", "AMERICA": "US", "США": "US", "US": "US",
    "GERMANY": "DE", "DEUTSCHLAND": "DE", "ГЕРМАНИЯ": "DE", "DE": "DE",
    "NETHERLANDS": "NL", "HOLLAND": "NL", "НИДЕРЛАНДЫ": "NL", "NL": "NL",
    "FRANCE": "FR", "ФРАНЦИЯ": "FR", "FR": "FR",
    "UNITED KINGDOM": "GB", "UK": "GB", "BRITAIN": "GB", "БРИТАНИЯ": "GB", "GB": "GB",
    "UKRAINE": "UA", "УКРАИНА": "UA", "UA": "UA",
    "POLAND": "PL", "ПОЛЬША": "PL", "PL": "PL",
    "TURKEY": "TR", "ТУРЦИЯ": "TR", "TR": "TR",
    "CHINA": "CN", "КИТАЙ": "CN", "CN": "CN",
    "KOREA": "KR", "КОРЕЯ": "KR", "KR": "KR",
    "JAPAN": "JP", "ЯПОНИЯ": "JP", "JP": "JP",
    "SINGAPORE": "SG", "СИНГАПУР": "SG", "SG": "SG",
    "CANADA": "CA", "КАНАДА": "CA", "CA": "CA",
}

FLAG_TO_COUNTRY = {flag: code for code, flag in COUNTRY_EMOJI.items()}

def unquote_deep(value: str, max_rounds: int = 4) -> str:
    previous = value
    for _ in range(max_rounds):
        current = unquote(previous)
        if current == previous:
            break
        previous = current
    return previous

def normalize_label_text(value: str) -> str:
    label = unquote_deep(value or "")
    label = re.sub(r"(?i)(funvpn|fun vpn|happ|v2raytun|android|iphone|windows|pc|пк|телефон)", " ", label)
    label = re.sub(r"[|_/\\]+", " ", label)
    label = re.sub(r"\s+", " ", label).strip(" -•—:[]")
    return label

def infer_country_code(label: str) -> str:
    clean = normalize_label_text(label).upper()
    for flag, code in FLAG_TO_COUNTRY.items():
        if flag in label:
            return code
    for alias, code in COUNTRY_ALIASES.items():
        if re.search(rf"(?<![A-ZА-Я]){re.escape(alias)}(?![A-ZА-Я])", clean):
            return code
    return ""

def extract_ping(label: str) -> str:
    clean = unquote_deep(label)
    match = re.search(r"(\d{1,4})\s*ms", clean, flags=re.I)
    return f"{match.group(1)}ms" if match else ""

def make_vpn_label(original_label: str, index: int, ping_ms: Optional[int] = None) -> str:
    country = infer_country_code(original_label)
    flag = COUNTRY_EMOJI.get(country, "🌐")
    country_name = COUNTRY_NAMES_RU.get(country, "Auto")
    ping = f"{ping_ms}ms" if ping_ms is not None else extract_ping(original_label)
    suffix = f" ({ping})" if ping else ""
    return f"{flag} {country_name} {index:03d}{suffix}"

def set_node_label(uri: str, label: str) -> Optional[str]:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        payload = uri.split("://", 1)[1]
        data = decode_vmess_payload(payload)
        if not data:
            return None
        data["ps"] = label
        return f"vmess://{encode_vmess_payload(data)}"
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc or not is_public_host(parts.hostname or ""):
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, quote(label, safe="")))

def decode_vmess_payload(payload: str) -> Optional[dict]:
    compact = payload.strip()
    if not compact:
        return None
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(padded).decode("utf-8", errors="ignore")
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except Exception:
            pass
    return None

def encode_vmess_payload(data: dict) -> str:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

def is_public_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_global
    except ValueError:
        return True

def clean_node_uri(uri: str) -> Optional[str]:
    uri = uri.strip().strip('"\'`,;]}')
    if not uri.lower().startswith(SUPPORTED_NODE_SCHEMES):
        return None
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        payload = uri.split("://", 1)[1]
        return uri if decode_vmess_payload(payload) else None
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc or not is_public_host(parts.hostname or ""):
        return None
    fragment = quote(normalize_label_text(parts.fragment), safe="") if parts.fragment else ""
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, fragment))

def relabel_node_uri(uri: str, index: int, ping_ms: Optional[int] = None) -> Optional[str]:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        payload = uri.split("://", 1)[1]
        data = decode_vmess_payload(payload)
        if not data:
            return None
        label = make_vpn_label(str(data.get("ps", "")), index, ping_ms)
        data["ps"] = label
        return f"vmess://{encode_vmess_payload(data)}"
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc or not is_public_host(parts.hostname or ""):
        return None
    return set_node_label(uri, make_vpn_label(parts.fragment, index, ping_ms))

def relabel_vpn_nodes(nodes: List) -> List[str]:
    relabeled = []
    seen = set()
    for item in nodes:
        if isinstance(item, dict):
            node = str(item.get("uri", ""))
            ping_ms = item.get("ping")
        else:
            node = str(item)
            ping_ms = None
        new_node = relabel_node_uri(node, len(relabeled) + 1, ping_ms)
        if new_node and new_node not in seen:
            seen.add(new_node)
            relabeled.append(new_node)
    return relabeled

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

def parse_node_endpoint(uri: str) -> Optional[Tuple[str, int]]:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        payload = uri.split("://", 1)[1]
        data = decode_vmess_payload(payload)
        if not data:
            return None
        host = str(data.get("add", "")).strip()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            return None
        return (host, port) if host and 1 <= port <= 65535 and is_public_host(host) else None
    try:
        parts = urlsplit(uri)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if host and port and 1 <= port <= 65535 and is_public_host(host):
        return host, port
    if scheme == "ss":
        compact = uri.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
        try:
            decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="ignore")
            if "@" in decoded and ":" in decoded.rsplit("@", 1)[1]:
                host_text, port_text = decoded.rsplit("@", 1)[1].rsplit(":", 1)
                port_num = int(port_text)
                if host_text and 1 <= port_num <= 65535 and is_public_host(host_text):
                    return host_text, port_num
        except Exception:
            pass
    return None

# ---------- НОВЫЙ МОДУЛЬ АВТОПОИСКА ИСТОЧНИКОВ (добавлен) ----------
async def search_github(session: aiohttp.ClientSession, query: str) -> List[str]:
    """Ищет репозитории GitHub по ключевым словам и извлекает ссылки на конфиги."""
    urls = []
    search_url = f"https://api.github.com/search/repositories?q={quote(query)}+extension:txt+OR+path:README.md&sort=updated&order=desc&per_page=8"
    headers = {"Accept": "application/vnd.github.v3+json"}
    try:
        async with session.get(search_url, headers=headers, timeout=15) as resp:
            if resp.status == 200:
                data = await resp.json()
                for repo in data.get("items", []):
                    repo_full = repo["full_name"]
                    # ссылка на README
                    raw_readme = f"https://raw.githubusercontent.com/{repo_full}/main/README.md"
                    urls.append(raw_readme)
                    # пробуем найти любые .txt файлы в корне
                    contents_url = f"https://api.github.com/repos/{repo_full}/contents/"
                    try:
                        async with session.get(contents_url, headers=headers, timeout=10) as cont_resp:
                            if cont_resp.status == 200:
                                for file in await cont_resp.json():
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
    """Собирает динамические источники (GitHub, Telegram) и возвращает список словарей с name/url/type."""
    dynamic = []
    print("🔎 Поиск новых источников на GitHub...")
    github_tasks = [search_github(session, q) for q in GITHUB_SEARCH_QUERIES]
    github_results = await asyncio.gather(*github_tasks, return_exceptions=True)
    for res in github_results:
        if isinstance(res, list):
            for url in res:
                dynamic.append({"name": f"GitHub-Auto-{len(dynamic)}", "url": url, "format": "subscription"})
    print("✈️ Парсинг Telegram каналов...")
    tg_tasks = [parse_telegram_channel(session, ch) for ch in TELEGRAM_CHANNELS]
    tg_results = await asyncio.gather(*tg_tasks, return_exceptions=True)
    for res in tg_results:
        if isinstance(res, list):
            for url in res:
                dynamic.append({"name": f"Telegram-Auto-{len(dynamic)}", "url": url, "format": "subscription"})
    print(f"✅ Найдено динамических источников: {len(dynamic)}")
    return dynamic

async def fetch_vpn_node_from_source(session: aiohttp.ClientSession, src: dict) -> List[str]:
    """Универсальная загрузка конфигов из источника (с поддержкой вложенных ссылок)."""
    content = await fetch_text(session, src)
    if not content:
        return []
    # Извлекаем ссылки на конфиги
    config_links = extract_subscription_links(content)
    nodes = []
    for link in config_links:
        if link.endswith(('.txt', '.config')):
            sub_content = await fetch_text(session, {"url": link, "name": src["name"]})
            if sub_content:
                nodes.extend(parse_subscription_nodes(sub_content))
        else:
            node = clean_node_uri(link)
            if node:
                nodes.append(node)
    print(f"  [OK] {src['name']} -> {len(nodes)} нод")
    return nodes

# ---------- ФУНКЦИИ ЗАГРУЗКИ (оставлены твои, но расширены) ----------
async def fetch_text(session: aiohttp.ClientSession, src: dict) -> Optional[str]:
    try:
        async with session.get(
            src["url"],
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "Mozilla/5.0 FunVPN-Robot/3.0"},
        ) as resp:
            if resp.status != 200:
                print(f"  [SKIP] {src['name']} → HTTP {resp.status}")
                return None
            return await resp.text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"  [ERR]  {src['name']} → {type(e).__name__}: {e}")
        return None

async def fetch_source(session: aiohttp.ClientSession, src: dict) -> List[Dict]:
    body = await fetch_text(session, src)
    if body is None:
        return []
    proxies = parse_source(body, src["format"], src["proto"])
    print(f"  [OK]   {src['name']} → {len(proxies)} прокси")
    return proxies

async def collect_vpn_nodes(dynamic_sources: List[Dict]) -> List[str]:
    """Собирает ноды из статических и динамических источников."""
    all_sources = VPN_NODE_SOURCES + dynamic_sources
    print(f"\n🧩 Загружаем VPN-ноды из {len(all_sources)} источников (статик + динамик)...")
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *(fetch_vpn_node_from_source(session, s) for s in all_sources),
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
        elif isinstance(result, Exception):
            print(f"  [WARN] Источник упал: {result}")
    print(f"\n✅ Собрано уникальных VPN-нод: {len(nodes)}")
    return nodes

async def check_vpn_node(semaphore: asyncio.Semaphore, node: str) -> Optional[Dict]:
    endpoint = parse_node_endpoint(node)
    if not endpoint:
        return None
    host, port = endpoint
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
                return {"uri": node, "host": host, "port": port, "ping": ping}
        except Exception:
            pass
    return None

async def check_all_vpn_nodes(nodes: List[str]) -> List[Dict]:
    print(f"\n🔌 Проверяем {len(nodes)} VPN-нод TCP-connect (параллельно {VPN_CONCURRENT_CHECKS})...")
    if not nodes:
        return []
    semaphore = asyncio.Semaphore(VPN_CONCURRENT_CHECKS)
    tasks = [check_vpn_node(semaphore, node) for node in nodes]
    alive = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        done += 1
        if result:
            alive.append(result)
        if done % 1000 == 0 or done == len(tasks):
            pct = done * 100 // len(tasks)
            print(f"  [{pct:3d}%] TCP проверено {done}/{len(tasks)}, живых VPN: {len(alive)}")
    alive.sort(key=lambda x: x["ping"])
    print(f"\n🟢 Живых TCP-доступных VPN-нод: {len(alive)}")
    return alive

async def collect_proxies() -> List[Dict]:
    print("\n📡 Загружаем источники HTTP/SOCKS-прокси...")
    connector = aiohttp.TCPConnector(limit=40, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, s) for s in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    all_proxies: List[Dict] = []
    for r in results:
        if isinstance(r, list):
            all_proxies.extend(r)
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

async def check_proxy(semaphore: asyncio.Semaphore,
                      session: aiohttp.ClientSession,
                      proxy: Dict) -> Optional[Dict]:
    ip, port, proto = proxy["ip"], proxy["port"], proxy.get("proto", "http")
    proxy_url = f"http://{ip}:{port}"
    async with semaphore:
        t0 = time.monotonic()
        try:
            async with session.get(
                TEST_URL, proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="ignore")
                    if "origin" not in body and ip not in body:
                        return None
                    ping = int((time.monotonic() - t0) * 1000)
                    if ping <= MAX_PING_MS:
                        return {**proxy, "proto": proto, "ping": ping}
        except Exception:
            pass
    return None

async def check_all_proxies(proxies: List[Dict]) -> List[Dict]:
    http_proxies = [p for p in proxies if p.get("proto", "http") in ("http", "https")]
    print(f"\n🔍 Проверяем {len(http_proxies)} HTTP/HTTPS-прокси из {len(proxies)} собранных (параллельно {MAX_CONCURRENT_CHECKS})...")
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
            if done % 500 == 0 or done == len(tasks):
                pct = done * 100 // len(tasks)
                print(f"  [{pct:3d}%] проверено {done}/{len(tasks)}, живых HTTP: {len(alive)}")
    alive.sort(key=lambda x: x["ping"])
    print(f"\n🟢 Живых HTTP/HTTPS-прокси: {len(alive)}")
    return alive

async def enrich_countries(session: aiohttp.ClientSession, proxies: List[Dict]) -> List[Dict]:
    need = [p for p in proxies if not p.get("country")]
    if not need:
        return proxies
    for i in range(0, min(len(need), MAX_PROXIES_IN_CONFIG), 100):
        batch = need[i:i + 100]
        try:
            payload = json.dumps([{"query": p["ip"]} for p in batch])
            async with session.post(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                data=payload, timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ip_to_cc = {r.get("query", ""): r.get("countryCode", "") for r in data if r.get("status") == "success"}
                    for p in batch:
                        p["country"] = ip_to_cc.get(p["ip"], p.get("country", ""))
        except Exception:
            pass
    return proxies

# ---------- ИСПРАВЛЕННЫЙ УНИВЕРСАЛЬНЫЙ УЗЕЛ (выбирает самую быструю ноду) ----------
def make_universal_node(alive_vpn_nodes: List[Dict]) -> Optional[str]:
    """
    Создаёт универсальную ноду: самую быструю живую ноду.
    Приоритет отдаётся ParadoxVPN (если есть хотя бы одна живая нода из ParadoxVPN).
    """
    if not alive_vpn_nodes:
        return None
    # Сначала ищем среди живых нод те, у которых в URI есть "paradox" (без учёта регистра)
    paradox_alive = [n for n in alive_vpn_nodes if "paradox" in n.get("uri", "").lower()]
    if paradox_alive:
        best = min(paradox_alive, key=lambda x: x["ping"])
    else:
        best = min(alive_vpn_nodes, key=lambda x: x["ping"])
    uri = best["uri"]
    ping = best["ping"]
    label = f"🌐 Универсальный (авто выбор) — {ping}ms"
    labeled = set_node_label(uri, label)
    return labeled if labeled else uri

# ---------- ИСПРАВЛЕННАЯ ГЕНЕРАЦИЯ КОНФИГА (200 ГБ, сброс 1-го числа) ----------
def next_month_timestamp() -> int:
    """Unix-время начала следующего месяца (сброс трафика)."""
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    else:
        next_month = datetime(now.year, now.month + 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return int(next_month.timestamp())

def build_config(proxies: List[Dict], vpn_nodes: List[str] = None, top_n: int = MAX_PROXIES_IN_CONFIG) -> str:
    vpn_nodes = vpn_nodes or []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_bytes = 200 * 1024 ** 3   # 200 ГБ
    expire_ts = next_month_timestamp()
    lines = [
        "#profile-title: base64:" + base64.b64encode("🎮 FunVPN".encode()).decode(),
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
        lines.append("# 🌐  VPN-НОДЫ (проверены TCP-connect, по пингу)")
        lines.append("# ═══════════════════════════════════════════════════")
        # Универсальный узел (самая быстрая нода) – уже не случайный
        # Но make_universal_node требует alive_vpn_nodes, а здесь у нас уже relabeled строки.
        # Поэтому просто берём первую строку (она самая быстрая, потому что relabel_vpn_nodes сортирует по пингу)
        fastest = vpn_nodes[0]
        # извлекаем пинг из метки для красоты
        import re
        ping_match = re.search(r"\((\d+)ms\)", fastest)
        ping_str = f" — {ping_match.group(1)}ms" if ping_match else ""
        universal_label = f"🌐 Универсальный (авто выбор){ping_str}"
        universal_node = set_node_label(fastest, universal_label)
        lines.append(universal_node if universal_node else fastest)
        node_count += 1
        # остальные ноды
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

def build_json_report(proxies: List[Dict], vpn_nodes: List[str] = None) -> str:
    now = datetime.now(timezone.utc).isoformat()
    vpn_nodes = vpn_nodes or []
    # универсальный узел в JSON можно не менять, но для информации возьмём первую строку
    universal = vpn_nodes[0] if vpn_nodes else None
    return json.dumps({
        "updated_at": now,
        "universal_node": universal,
        "vpn_nodes_total": len(vpn_nodes),
        "vpn_nodes_in_config": min(len(vpn_nodes), MAX_VPN_NODES_IN_CONFIG),
        "reserve_nodes": len(RESERVE_STATIC_NODES),
        "http_proxies_total": len(proxies),
        "http_proxies_in_config": min(len(proxies), MAX_PROXIES_IN_CONFIG),
        "vpn_nodes": vpn_nodes[:MAX_VPN_NODES_IN_CONFIG],
        "proxies": proxies[:MAX_PROXIES_IN_CONFIG],
        "proxy_sources": len(SOURCES),
        "vpn_node_sources": len(VPN_NODE_SOURCES) + 1,  # +1 за динамические
        "credits": "FunVPN — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co",
    }, ensure_ascii=False, indent=2)

def build_log(collected: int, alive: int, vpn_nodes: int, elapsed: float) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"=== FunVPN Proxy Robot v3.0 (Self-Healing) — {now} ===\n"
        f"VPN-нод собрано:       {vpn_nodes}\n"
        f"VPN-нод в конфиге:     {min(vpn_nodes, MAX_VPN_NODES_IN_CONFIG)}\n"
        f"Резервных нод:         {len(RESERVE_STATIC_NODES)}\n"
        f"Прокси собрано:        {collected}\n"
        f"HTTP живых:            {alive}\n"
        f"HTTP в конфиге:        {min(alive, MAX_PROXIES_IN_CONFIG)}\n"
        f"Источников VPN (статик): {len(VPN_NODE_SOURCES)}\n"
        f"Источников прокси:     {len(SOURCES)}\n"
        f"Время:                 {elapsed:.1f} сек\n"
        f"FUN RUSSIA CRMP | TOO Oink Tech Ltd Co\n"
    )

# ---------- MAIN (обновлён) ----------
async def main():
    t_start = time.monotonic()
    print("=" * 55)
    print("🤖  FunVPN Proxy/VPN Robot v3.0 (Self-Healing)")
    print("    FUN RUSSIA CRMP | TOO Oink Tech Ltd Co")
    print("=" * 55)
    print(f"📋 Статических источников VPN: {len(VPN_NODE_SOURCES)}")
    print(f"📋 Источников прокси: {len(SOURCES)}")
    print(f"🛡️  Резервных статичных нод: {len(RESERVE_STATIC_NODES)}")

    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 1. Сбор динамических источников (GitHub, Telegram)
        dynamic_sources = await collect_dynamic_sources(session)
        # 2. Сбор VPN-нод (статик + динамик)
        raw_vpn_nodes = await collect_vpn_nodes(dynamic_sources)
        # 3. Проверка нод
        alive_vpn_nodes = await check_all_vpn_nodes(raw_vpn_nodes)
        vpn_nodes = relabel_vpn_nodes(alive_vpn_nodes)

        # 4. Прокси (без изменений)
        raw_proxies = await collect_proxies()
        alive_proxies = await check_all_proxies(raw_proxies)

        # 5. Обогащение стран
        alive_proxies = await enrich_countries(session, alive_proxies)

    os.makedirs("configs", exist_ok=True)

    config = build_config(alive_proxies, vpn_nodes)
    with open(OUTPUT_CONFIG, "w", encoding="utf-8") as f:
        f.write(config)
    print(f"\n💾 Конфиг сохранён: {OUTPUT_CONFIG}")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        f.write(build_json_report(alive_proxies, vpn_nodes))
    print(f"💾 JSON отчёт: {OUTPUT_JSON}")

    elapsed = time.monotonic() - t_start
    log_text = build_log(len(raw_proxies), len(alive_proxies), len(vpn_nodes), elapsed)
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        f.write(log_text)
    print("\n" + log_text)
    print(f"✅ Готово за {elapsed:.1f} сек.")

if __name__ == "__main__":
    asyncio.run(main())
