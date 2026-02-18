# flexibleFlow

Каскадный VPN-менеджер для Ubuntu на базе **VLESS Reality** с моделью:
- `RU` сервер: входной bridge
- `Foreign` сервер: выходной proxy

По умолчанию весь трафик идет через `Foreign`, а российские домены/подсети идут напрямую через `RU`.

## Возможности

- Настройка `Foreign` и `RU` узлов через меню
- Опциональная установка `3x-ui` (только по подтверждению)
- Генерация клиентской ссылки и QR-кода
- Редактируемые маршруты в JSON: `/etc/vless-cascade/routes.json`
- Автодобавление default-политики, если ее нет:
  - `geosite:category-ru`
  - `.ru`, `.su`, `.рф` (через `xn--p1ai`)
  - `geoip:ru`, `geoip:private`
- Валидация входной VLESS-ссылки (UUID/SNI/pbk/sid/port)
- Проверка `xray -test` перед применением RU-конфига и перед откатом
- Бэкап `xrayConfig` + откат из меню
- Safe mode: `--safe` или `VLESS_CASCADE_SAFE_MODE=1`
- Статусы выполнения пунктов меню в консоли: `START / DONE / FAILED`
- Логирование ошибок и действий в файл: `/var/log/vless-cascade.log`

## Архитектура

```text
Client -> RU Bridge -> Foreign Exit -> Internet
          | direct for RU domains/IP |
```

## Быстрый старт (чистая Ubuntu)

```bash
sudo apt update
sudo apt install -y git python3

git clone https://github.com/itmaxk/flexibleFlow.git
cd flexibleFlow
sudo python3 vless_cascade.py
```

## Повторный старт

```bash
git pull
sudo python3 vless_cascade.py
```

Safe mode (без автоустановки зависимостей):

```bash
cd flexibleFlow
sudo python3 vless_cascade.py --safe
```

## Базовый сценарий

1. На Foreign-сервере выберите пункт `1` и получите VLESS-ссылку.
2. На RU-сервере выберите пункт `2` и вставьте ссылку Foreign.
3. Получите клиентскую ссылку/QR и импортируйте в клиент.

## Меню

- `1` Настроить Foreign
- `2` Настроить RU bridge
- `3` Перегенерировать клиентскую ссылку/QR
- `4` Изменить клиентские параметры (порт/SNI)
- `5` Редактировать маршруты JSON
- `6` Применить готовый профиль маршрутов
- `7` Откатить `xrayConfig` из бэкапа
- `8` Просмотр лога
- `9` Выход

## Маршруты

Файл: `/etc/vless-cascade/routes.json`

Поля:
- `direct_domains`
- `direct_ips`
- `proxy_domains`
- `proxy_ips`

Fallback-правило всегда сохраняется: весь остальной `tcp,udp` идет через proxy.

### Готовые профили

- `RU only direct (recommended)`
- `Mixed (RU + Telegram direct)`
- `Full proxy (only private direct)`

## Бэкапы и откат

Перед изменением `xrayConfig` скрипт сохраняет бэкап:
- каталог: `/etc/vless-cascade/backups`
- формат: `xrayConfig-XXXXXXXX.json`

Откат из меню:
- восстановить последний бэкап
- или выбрать конкретный из списка

## Логи и диагностика

- Файл логов: `/var/log/vless-cascade.log`
- Для каждого пункта меню пишутся события `START/DONE/FAILED`
- Ошибки команд и traceback (при неожиданных исключениях) сохраняются в лог

## Безопасность

- Запускайте скрипт только под `root`
- Ограничьте доступ к `3x-ui` (IP allowlist, сложный пароль, 2FA)
- Держите серверы и `3x-ui` обновленными
- Проверьте синхронизацию времени (`timedatectl`, NTP)
- Не публикуйте UUID/ссылки/ключи в открытых источниках
- На production используйте `--safe`, если автоустановка недопустима

## Производительность

- Выбирайте VPS с хорошим peering между RU и Foreign
- Избегайте перегруженных/oversold хостов
- Используйте `reality + vision` как базовый профиль

## Клиенты

- Android: `v2rayNG`, `NekoBox`, `Hiddify Next`
- iOS: `Streisand`, `FoXray`, `V2Box`
- Windows: `v2rayN`, `Nekoray`, `Hiddify Next`
- macOS: `FoXray`, `V2Box`
