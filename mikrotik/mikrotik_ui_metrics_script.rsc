# RouterOS script source generated into /system script name=ff_ui_metrics by bootstrap.
# This file is a readable reference only.

:local vethName "veth-ff"
:local jsonPath "usb1-part1/vless-ct/ui/ff_metrics.json"
:local rx [/interface get [find where name=$vethName] rx-byte]
:local tx [/interface get [find where name=$vethName] tx-byte]
:local now [/system clock get time]
:local cst "stopped"
:if ([:len [/container find where comment="ff_container" status="running"]] > 0) do={ :set cst "running" }
:local mbytes [/ip firewall mangle get [find where comment="ff_mangle_conn"] bytes]
:local ac [:len [/ip firewall connection find where connection-mark=ff_vless_conn]]
:local payload ("{\"container_status\":\"" . $cst . "\",\"rx_bps\":" . $rx . ",\"tx_bps\":" . $tx . ",\"active_connections\":" . $ac . ",\"marked_bytes\":" . $mbytes . ",\"updated\":\"" . $now . "\",\"top_clients\":[]}")
/file set $jsonPath contents=$payload
