# MikroTik bootstrap (RouterOS 7.21.3)

Все файлы, связанные с MikroTik, находятся только в этой папке.

## Файлы

- `mikrotik_bootstrap_v7213.rsc` - основной zero-touch bootstrap для чистого роутера.
- `mikrotik_singbox_config.template.json` - шаблон конфигурации sing-box.
- `mikrotik_ui_panel_assets.html` - HTML-шаблон панели мониторинга.
- `mikrotik_ui_metrics_script.rsc` - референсный скрипт метрик RouterOS.
- `mikrotik_bootstrap_variables.md` - описание переменных bootstrap-скрипта.

## Быстрый старт

1. Откройте `mikrotik_bootstrap_v7213.rsc` и заполните параметры VLESS:
   - `VLESS_SERVER`, `UUID`, `SNI`, `PBK`, `SID`
2. Загрузите файл на MikroTik через `Files`.
3. Выполните:

```routeros
/import file-name=mikrotik_bootstrap_v7213.rsc
```

4. Скрипт спросит путь к USB-хранилищу для контейнера.
   - Если оставить пустым, будет использован `usb1-part1`.

## Что настраивает bootstrap

- контейнер sing-box на USB-хранилище
- full-tunnel policy routing в таблицу `to_vless`
- список обхода локальных сетей `LOCAL_BYPASS`
- DNS anti-leak правила (блок прямого `tcp/udp 53` в WAN)
- fail-closed через blackhole fallback в `to_vless`
- локальную UI-панель + JSON-метрики + scheduler

## URL панели

После успешного запуска RouterOS выводит URL панели в лог.

Формат:

- `http://<router-lan-ip>:<UI_PORT>/<usb-path>/vless-ct/ui/ff_dashboard.html`

По умолчанию `UI_PORT=8089`.

## Примечания

- Скрипт рассчитан на чистый RouterOS `7.21.3` с включенной поддержкой контейнеров.
- Повторный импорт удаляет предыдущие объекты `ff_*` и пересобирает конфигурацию.
- Перед использованием в продакшене протестируйте на отдельном роутере.
