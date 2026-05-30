# 🤖 FunVPN Proxy Robot — GitHub Actions

**Собирает готовые VPN-ноды для Happ/v2rayTun и проверенные HTTP-прокси, затем обновляет подписку**
Разработчики: **FUN RUSSIA CRMP** | **TOO Oink Tech Ltd Co**

---

## 📁 Структура файлов

```
FunVPN/
├── .github/
│   └── workflows/
│       └── proxy_robot.yml      ← GitHub Actions workflow
├── scripts/
│   └── collect_proxies.py       ← Скрипт-робот
├── configs/
│   ├── free_config.txt          ← Конфиг (обновляется роботом)
│   ├── proxies.json             ← JSON с полным списком прокси
│   └── last_update.log          ← Лог последнего запуска
├── requirements.txt
└── README.md
```

---

## 🚀 Установка (5 шагов)

### 1. Загрузите файлы в ваш репозиторий
Просто скопируйте структуру выше в ваш GitHub-репо.

### 2. Включите GitHub Actions
В репозитории перейдите в **Settings → Actions → General**  
→ выберите **"Allow all actions"** → сохраните.

### 3. Дайте роботу права на запись
**Settings → Actions → General → Workflow permissions**  
→ выберите **"Read and write permissions"** → сохраните.

### 4. Обновите ссылку в Connect.html
```js
const GITHUB_CONFIGS = [
  'https://raw.githubusercontent.com/ВАШ_ЛОГИН/FunVPN/main/configs/free_config.txt',
];
```

### 5. Запустите вручную для проверки
**Actions → 🤖 FunVPN Proxy Robot → Run workflow → Run**

---

## ⏰ Расписание

| Событие | Время |
|---------|-------|
| Автозапуск | каждый день в **06:00 МСК** (03:00 UTC) |
| Ручной запуск | вкладка **Actions → Run workflow** |

---

## 📡 Источники (VPN + 20+ прокси API/листов)

| Тип | Источники | Что используется |
|-----|-----------|------------------|
| VPN-ноды | ParadoxVPN, V2RayAggregator, v2rayfree, Pawdroid Free-servers | `vless://`, `trojan://`, `ss://`, `vmess://` для Happ/v2rayTun/Hiddify |
| Прокси API | ProxyScrape, GeoNode, OpenProxySpace, Proxy-List.download | HTTP/HTTPS/SOCKS списки |
| GitHub-листы | TheSpeedX, monosans, jetkai, hookzof, clarketm, ShiftyTR, sunny9577, roosterkid, KangProxy | 20+ разных HTTP/SOCKS источников |
| Проверка | `http://httpbin.org/ip` через прокси | В конфиг попадают только реально ответившие HTTP/HTTPS-прокси |

---

## 📊 Что делает робот

1. **Загружает** готовые VPN-ноды (`vless://`, `trojan://`, `ss://`, `vmess://`) из открытых подписок
2. **Загружает** HTTP/SOCKS-прокси из 20+ разных API и GitHub-листов
3. **Дедуплицирует** — убирает повторяющиеся `proto://IP:PORT`
4. **Проверяет** HTTP/HTTPS-прокси реальным подключением через `httpbin.org/ip`, а не добавляет «от балды»
5. **Обогащает** HTTP-прокси данными о стране через ip-api.com
6. **Сохраняет** сначала VPN-ноды для Happ/v2rayTun, ниже — топ-200 самых быстрых HTTP-прокси
7. **Коммитит** изменения обратно в репозиторий

---

## ⚙️ Настройки (scripts/collect_proxies.py)

```python
MAX_CONCURRENT_CHECKS   = 80   # параллельных проверок HTTP-прокси
CHECK_TIMEOUT          = 6    # секунд на один HTTP-прокси
MAX_PING_MS            = 5000 # максимальный пинг
MAX_PROXIES_IN_CONFIG  = 200  # лимит HTTP-прокси в конфиге
MAX_VPN_NODES_IN_CONFIG = 250 # лимит VPN-нод в конфиге
```

---

## 📋 Пример лога

```
=== FunVPN Proxy Robot — 2026-05-30 03:01:44 UTC ===
VPN-нод:   180
Прокси собрано:   4821
HTTP живых:       347
В конфиге VPN:    180
В конфиге HTTP:   200
Источников прокси:32
Время:            142.3 сек
FUN RUSSIA CRMP | TOO Oink Tech Ltd Co
```

---

*FunVPN © 2026 — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co*
