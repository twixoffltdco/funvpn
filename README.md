# 🤖 FunVPN Proxy Robot — GitHub Actions

**Ежедневно собирает публичные прокси и обновляет конфиг**  
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

## 📡 Источники прокси (16 источников)

| Источник | Протоколы |
|----------|-----------|
| ProxyScrape API | HTTP, SOCKS4, SOCKS5 |
| GeoNode Free | HTTP, HTTPS, SOCKS |
| TheSpeedX/PROXY-List | HTTP, SOCKS4, SOCKS5 |
| monosans/proxy-list | HTTP, SOCKS5 |
| jetkai/proxy-list | HTTP, SOCKS5 |
| hookzof/socks5_list | SOCKS5 |
| clarketm/proxy-list | HTTP |
| ShiftyTR/Proxy-List | HTTP |
| sunny9577/proxy-scraper | HTTP |
| Spys.me | HTTP |

---

## 📊 Что делает робот

1. **Загружает** свежие списки из 16 источников
2. **Дедуплицирует** — убирает повторяющиеся IP:PORT
3. **Проверяет** каждый прокси (реальное подключение через тест-URL)
4. **Обогащает** данными о стране через ip-api.com
5. **Сохраняет** топ-200 самых быстрых в `free_config.txt`
6. **Коммитит** изменения обратно в репозиторий

---

## ⚙️ Настройки (scripts/collect_proxies.py)

```python
MAX_CONCURRENT_CHECKS = 80    # параллельных проверок
CHECK_TIMEOUT         = 6     # секунд на один прокси
MAX_PING_MS           = 5000  # максимальный пинг
MAX_PROXIES_IN_CONFIG = 200   # лимит в конфиге
```

---

## 📋 Пример лога

```
=== FunVPN Proxy Robot — 2026-05-30 03:01:44 UTC ===
Собрано:   4821
Живых:     347
В конфиге: 200
Время:     142.3 сек
FUN RUSSIA CRMP | TOO Oink Tech Ltd Co
```

---

*FunVPN © 2026 — FUN RUSSIA CRMP | TOO Oink Tech Ltd Co*
