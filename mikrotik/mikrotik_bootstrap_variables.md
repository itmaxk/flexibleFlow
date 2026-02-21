# Переменные в mikrotik_bootstrap_v7213.rsc

## Обязательные

- `VLESS_SERVER`: домен или IP выходного VLESS-узла
- `VLESS_PORT`: порт VLESS (обычно `443`)
- `UUID`: UUID клиента
- `SNI`: `serverName` для TLS/Reality
- `PBK`: публичный ключ Reality
- `SID`: short id Reality

## Сеть

- `WAN_IF`: WAN-интерфейс (по умолчанию `ether1`)
- `LAN_IF`: LAN bridge (по умолчанию `bridge`)
- `LAN_CIDR`: LAN-подсеть (по умолчанию `192.168.88.0/24`)
- `VETH_HOST_IP`, `VETH_CT_IP`: адреса линка роутер-контейнер
- `ROUTE_TABLE`: таблица policy routing (по умолчанию `to_vless`)

## USB и контейнер

- `USB_CONTAINER_ROOT`: запрашивается при запуске, по умолчанию `usb1-part1`
- `USB_CONTAINER_SUBDIR`: подпапка контейнера (`vless-ct`)
- `CT_NAME`, `VETH_NAME`: имена объектов

## UI

- `UI_PORT`: порт встроенной web-панели (по умолчанию `8089`)
- `UI_REFRESH_SEC`: интервал обновления панели (по умолчанию `5`)

## DNS

- `DNS_REMOTE_1`, `DNS_REMOTE_2`: upstream DNS для резолвера роутера
