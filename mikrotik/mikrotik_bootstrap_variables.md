# Переменные в mikrotik_bootstrap_v7213.rsc

## Обязательные

- `VLESSSERVER`: домен или IP выходного VLESS-узла
- `VLESSPORT`: порт VLESS (обычно `443`)
- `UUID`: UUID клиента
- `SNI`: `serverName` для TLS/Reality
- `PBK`: публичный ключ Reality
- `SID`: short id Reality

## Сеть

- `WANIF`: WAN-интерфейс (по умолчанию `ether1`)
- `LANIF`: LAN bridge (по умолчанию `bridge`)
- `LANCIDR`: LAN-подсеть (по умолчанию `192.168.88.0/24`)
- `VETHHOSTIP`, `VETHCTIP`: адреса линка роутер-контейнер
- `ROUTETABLE`: таблица policy routing (по умолчанию `to_vless`)

## USB и контейнер

- `USBCONTAINERROOT`: запрашивается при запуске, по умолчанию `usb1-part1`
- `USBCONTAINERSUBDIR`: подпапка контейнера (`vless-ct`)
- `CTNAME`, `VETHNAME`: имена объектов

## UI

- `UIPORT`: порт встроенной web-панели (по умолчанию `8089`)
- `UIREFRESHSEC`: интервал обновления панели (по умолчанию `5`)

## DNS

- `DNSREMOTE1`, `DNSREMOTE2`: upstream DNS для резолвера роутера
