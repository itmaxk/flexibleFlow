# flexibleFlow MikroTik bootstrap for RouterOS 7.21.3
# Import on a clean router: /import file-name=mikrotik_bootstrap_v7213.rsc
#
# The script asks for USB root folder for container storage.
# If empty or prompt is unavailable, default is usb1-part1.
#
# Required values below (edit before import).
:local WANIF "ether1"
:local LANIF "bridge"
:local LANCIDR "192.168.88.0/24"

:local CTNAME "ff-singbox"
:local VETHNAME "veth-ff"
:local VETHHOSTIP "172.31.255.1/30"
:local VETHCTIP "172.31.255.2/30"
:local ROUTETABLE "to_vless"

:local USBCONTAINERROOT ""
:local USBCONTAINERSUBDIR "vless-ct"

:local VLESSSERVER "REPLACE_SERVER"
:local VLESSPORT 443
:local UUID "REPLACE_UUID"
:local SNI "REPLACE_SNI"
:local PBK "REPLACE_REALITY_PBK"
:local SID "REPLACE_REALITY_SID"
:local FP "chrome"
:local SPX "/"

:local DNSREMOTE1 "1.1.1.1"
:local DNSREMOTE2 "9.9.9.9"
:local UIPORT 8089
:local UIREFRESHSEC 5

:local TAG "ff_vless"

:log info "[$TAG] bootstrap started"

# Version check (strict as requested).
:local rosVer [/system resource get version]
:if ([:find $rosVer "7.21.3"] = nil) do={
  :error ("[$TAG] RouterOS 7.21.3 required, found: " . $rosVer)
}

# Container package check.
:do { /container print count-only } on-error={
  :error "[$TAG] container package/device-mode is not enabled"
}

# Ask for USB folder, fallback to usb1-part1.
:local usbInput ""
:do {
  :set usbInput [/terminal/ask prompt="Container root path [usb1-part1]:"]
} on-error={
  :set usbInput ""
}
:if ([:len $usbInput] = 0) do={
  :set USBCONTAINERROOT "usb1-part1"
} else={
  :set USBCONTAINERROOT $usbInput
}

# Validate storage root exists.
:if ([:len [/file find where name=$USBCONTAINERROOT]] = 0) do={
  :error ("[$TAG] storage path not found: " . $USBCONTAINERROOT)
}

:local CTBASEPATH ($USBCONTAINERROOT . "/" . $USBCONTAINERSUBDIR)
:local CTROOTFSPATH ($CTBASEPATH . "/rootfs")
:local CTCONFPATH ($CTBASEPATH . "/config")
:local UIPATH ($CTBASEPATH . "/ui")

# Ensure folders exist.
:if ([:len [/file find where name=$CTBASEPATH]] = 0) do={ /file make-directory $CTBASEPATH }
:if ([:len [/file find where name=$CTROOTFSPATH]] = 0) do={ /file make-directory $CTROOTFSPATH }
:if ([:len [/file find where name=$CTCONFPATH]] = 0) do={ /file make-directory $CTCONFPATH }
:if ([:len [/file find where name=$UIPATH]] = 0) do={ /file make-directory $UIPATH }

# Remove existing ff_* objects for idempotent run.
:foreach i in=[/ip firewall mangle find where comment~"^ff_"] do={ /ip firewall mangle remove $i }
:foreach i in=[/ip firewall filter find where comment~"^ff_"] do={ /ip firewall filter remove $i }
:foreach i in=[/ip firewall nat find where comment~"^ff_"] do={ /ip firewall nat remove $i }
:foreach i in=[/ip route find where comment~"^ff_"] do={ /ip route remove $i }
:foreach i in=[/routing table find where comment~"^ff_"] do={ /routing table remove $i }
:foreach i in=[/ip firewall address-list find where comment~"^ff_"] do={ /ip firewall address-list remove $i }
:foreach i in=[/tool graphing interface find where comment~"^ff_"] do={ /tool graphing interface remove $i }
:foreach i in=[/system scheduler find where comment~"^ff_"] do={ /system scheduler remove $i }
:foreach i in=[/system script find where name="ff_ui_metrics"] do={ /system script remove $i }
:foreach i in=[/container mounts find where name="ff_mount_conf"] do={ /container mounts remove $i }
:foreach i in=[/container envs find where name="ff_env"] do={ /container envs remove $i }
:foreach i in=[/container find where comment="ff_container"] do={ /container remove $i }
:foreach i in=[/interface veth find where comment="ff_container"] do={ /interface veth remove $i }
:foreach i in=[/ip address find where comment="ff_container"] do={ /ip address remove $i }

# Build base bridge/LAN only if missing (clean-router friendly).
:if ([:len [/interface bridge find where name=$LANIF]] = 0) do={
  /interface bridge add name=$LANIF comment="ff_bridge"
}
:if ([:len [/ip address find where interface=$LANIF]] = 0) do={
  /ip address add address="192.168.88.1/24" interface=$LANIF comment="ff_lan_ip"
}
:if ([:len [/ip dhcp-client find where interface=$WANIF]] = 0) do={
  /ip dhcp-client add interface=$WANIF add-default-route=yes use-peer-dns=no comment="ff_wan_dhcp"
}
:if ([:len [/ip pool find where name="ff_pool"]] = 0) do={
  /ip pool add name="ff_pool" ranges="192.168.88.10-192.168.88.250"
}
:if ([:len [/ip dhcp-server find where name="ff_dhcp"]] = 0) do={
  /ip dhcp-server add name="ff_dhcp" interface=$LANIF address-pool="ff_pool" disabled=no
}
:if ([:len [/ip dhcp-server network find where address="192.168.88.0/24"]] = 0) do={
  /ip dhcp-server network add address="192.168.88.0/24" gateway="192.168.88.1" dns-server="192.168.88.1"
}

# DNS on router for clients; upstream forced through tunnel by routing mark.
/ip dns set allow-remote-requests=yes servers=($DNSREMOTE1 . "," . $DNSREMOTE2) cache-size=4096KiB

# Container networking.
/interface veth add name=$VETHNAME address=$VETHCTIP gateway="172.31.255.1" comment="ff_container"
/ip address add address=$VETHHOSTIP interface=$VETHNAME comment="ff_container"

# Prepare sing-box config on USB.
:local confFile ($CTCONFPATH . "/config.json")
:if ([:len [/file find where name=$confFile]] = 0) do={
  /file add name=$confFile type=file
}
:local singboxJson ("{\"log\":{\"level\":\"warn\"},\"inbounds\":[{\"type\":\"tun\",\"tag\":\"tun-in\",\"interface_name\":\"sb-tun\",\"inet4_address\":\"172.29.0.1/30\",\"mtu\":1500,\"auto_route\":true,\"strict_route\":false}],\"outbounds\":[{\"type\":\"vless\",\"tag\":\"vless-out\",\"server\":\"" . $VLESSSERVER . "\",\"server_port\":" . $VLESSPORT . ",\"uuid\":\"" . $UUID . "\",\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"" . $SNI . "\",\"utls\":{\"enabled\":true,\"fingerprint\":\"" . $FP . "\"},\"reality\":{\"enabled\":true,\"public_key\":\"" . $PBK . "\",\"short_id\":\"" . $SID . "\"}}},{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"auto_detect_interface\":false,\"final\":\"vless-out\"}}")
/file set $confFile contents=$singboxJson

# Container config.
/container config set ram-high=256MiB registry-url="https://registry-1.docker.io" tmpdir=$CTBASEPATH
/container mounts add name="ff_mount_conf" src=$CTCONFPATH dst="/etc/sing-box"
/container envs add name="ff_env" key="TZ" value="UTC"

/container add remote-image="ghcr.io/sagernet/sing-box:latest" interface=$VETHNAME root-dir=$CTROOTFSPATH mounts="ff_mount_conf" envlist="ff_env" start-on-boot=yes logging=yes cmd="run -c /etc/sing-box/config.json" comment="ff_container"
/container start [find where comment="ff_container"]

# Routing table + rules for full tunnel (except local/service nets).
/routing table add fib name=$ROUTETABLE comment="ff_routing"

/ip firewall address-list add list="LOCAL_BYPASS" address="127.0.0.0/8" comment="ff_local"
/ip firewall address-list add list="LOCAL_BYPASS" address="10.0.0.0/8" comment="ff_local"
/ip firewall address-list add list="LOCAL_BYPASS" address="172.16.0.0/12" comment="ff_local"
/ip firewall address-list add list="LOCAL_BYPASS" address="192.168.0.0/16" comment="ff_local"
/ip firewall address-list add list="LOCAL_BYPASS" address="169.254.0.0/16" comment="ff_local"
/ip firewall address-list add list="LOCAL_BYPASS" address="224.0.0.0/4" comment="ff_local"
/ip firewall address-list add list="LOCAL_BYPASS" address=$LANCIDR comment="ff_local"

# Keep tunnel endpoint reachable via main table.
:local endpointIp $VLESSSERVER
:do { :set endpointIp [:resolve $VLESSSERVER] } on-error={ :set endpointIp $VLESSSERVER }
/ip firewall mangle add chain=prerouting dst-address=$endpointIp action=accept comment="ff_mangle_endpoint"
/ip firewall mangle add chain=prerouting in-interface=$LANIF dst-address-list=LOCAL_BYPASS action=accept comment="ff_mangle_bypass"
/ip firewall mangle add chain=prerouting in-interface=$LANIF dst-address-list=!LOCAL_BYPASS action=mark-connection new-connection-mark=ff_vless_conn passthrough=yes comment="ff_mangle_conn"
/ip firewall mangle add chain=prerouting connection-mark=ff_vless_conn action=mark-routing new-routing-mark=$ROUTETABLE passthrough=no comment="ff_mangle_route"

/ip route add dst-address=0.0.0.0/0 gateway="172.31.255.2" routing-table=$ROUTETABLE check-gateway=ping distance=1 comment="ff_route_tunnel"
/ip route add dst-address=0.0.0.0/0 type=blackhole routing-table=$ROUTETABLE distance=250 comment="ff_route_failclosed"

# NAT: LAN to tunnel gateway; also keep WAN masquerade for router services.
/ip firewall nat add chain=srcnat out-interface=$VETHNAME action=masquerade comment="ff_nat_tunnel"
/ip firewall nat add chain=srcnat out-interface=$WANIF action=masquerade comment="ff_nat_wan"

# DNS leak protection: block client direct DNS to WAN.
/ip firewall filter add chain=forward in-interface=$LANIF out-interface=$WANIF protocol=udp dst-port=53 action=drop comment="ff_dns_drop_udp"
/ip firewall filter add chain=forward in-interface=$LANIF out-interface=$WANIF protocol=tcp dst-port=53 action=drop comment="ff_dns_drop_tcp"

# Fail-closed: drop marked traffic if it tries to leave via WAN.
/ip firewall filter add chain=forward routing-mark=$ROUTETABLE out-interface=$WANIF action=drop comment="ff_fail_closed"

# Web UI exposure for LAN only.
/ip service set www port=$UIPORT disabled=no
/ip firewall filter add chain=input in-interface=$WANIF protocol=tcp dst-port=$UIPORT action=drop comment="ff_ui_block_wan"

# Built-in graphing panel for quick visual UI.
/tool graphing interface add interface=$VETHNAME store-on-disk=yes allow-address=$LANCIDR comment="ff_graph"
/tool graphing resource add store-on-disk=yes allow-address=$LANCIDR

# UI files.
:local uiJsonFile ($UIPATH . "/ff_metrics.json")
:if ([:len [/file find where name=$uiJsonFile]] = 0) do={ /file add name=$uiJsonFile type=file }
/file set $uiJsonFile contents="{\"status\":\"initializing\"}"

:local uiHtmlFile ($UIPATH . "/ff_dashboard.html")
:if ([:len [/file find where name=$uiHtmlFile]] = 0) do={ /file add name=$uiHtmlFile type=file }
:local uiHtml ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>flexibleFlow MikroTik</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f8;color:#111;margin:0;padding:18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}.card{background:#fff;border:1px solid #d8dde3;border-radius:10px;padding:12px}h1{margin:0 0 12px 0;font-size:20px}.k{font-size:12px;color:#5a6470}.v{font-size:18px;font-weight:600}pre{white-space:pre-wrap;margin:0}</style></head><body><h1>flexibleFlow Dashboard</h1><div class='grid'><div class='card'><div class='k'>Container</div><div class='v' id='s'>-</div></div><div class='card'><div class='k'>RX bps</div><div class='v' id='rx'>-</div></div><div class='card'><div class='k'>TX bps</div><div class='v' id='tx'>-</div></div><div class='card'><div class='k'>Active conns</div><div class='v' id='ac'>-</div></div><div class='card'><div class='k'>Marked bytes</div><div class='v' id='mb'>-</div></div><div class='card'><div class='k'>Updated</div><div class='v' id='ts'>-</div></div></div><div class='card' style='margin-top:10px'><div class='k'>Top clients (active conns)</div><pre id='top'>-</pre></div><div class='card' style='margin-top:10px'><a href='/graphs/'>Open RouterOS Graphs</a></div><script>const f=(n)=>{if(n>1e9)return(n/1e9).toFixed(2)+'G';if(n>1e6)return(n/1e6).toFixed(2)+'M';if(n>1e3)return(n/1e3).toFixed(2)+'K';return String(n)};async function tick(){try{const r=await fetch('/" . $uiJsonFile . "?t='+Date.now());const j=await r.json();s.textContent=j.container_status;rx.textContent=f(j.rx_bps||0);tx.textContent=f(j.tx_bps||0);ac.textContent=j.active_connections||0;mb.textContent=f(j.marked_bytes||0);ts.textContent=j.updated||'-';top.textContent=(j.top_clients||[]).map(x=>x.client+'  '+x.connections).join('\\n')||'-'}catch(e){s.textContent='error'}setTimeout(tick," . ($UIREFRESHSEC * 1000) . ")};tick();</script></body></html>")
/file set $uiHtmlFile contents=$uiHtml

# Metrics script (updates JSON every 5s).
:local metricsSource (":global ffprevrx;:global ffprevtx;:local vethName \"" . $VETHNAME . "\";:local jsonPath \"" . $uiJsonFile . "\";:local interval " . $UIREFRESHSEC . ";:local rx [/interface get [find where name=$vethName] rx-byte];:local tx [/interface get [find where name=$vethName] tx-byte];:if ([:typeof $ffprevrx] = \"nothing\") do={:set ffprevrx $rx};:if ([:typeof $ffprevtx] = \"nothing\") do={:set ffprevtx $tx};:local dRx ($rx - $ffprevrx);:local dTx ($tx - $ffprevtx);:if ($dRx < 0) do={:set dRx 0};:if ($dTx < 0) do={:set dTx 0};:local rxBps (($dRx * 8) / $interval);:local txBps (($dTx * 8) / $interval);:set ffprevrx $rx;:set ffprevtx $tx;:local now [/system clock get time];:local cst \"stopped\";:if ([:len [/container find where comment=\"ff_container\" status=\"running\"]] > 0) do={:set cst \"running\"};:local mbytes [/ip firewall mangle get [find where comment=\"ff_mangle_conn\"] bytes];:local ac [:len [/ip firewall connection find where connection-mark=ff_vless_conn]];:local topText \"\";:local n 0;:foreach cid in=[/ip firewall connection find where connection-mark=ff_vless_conn] do={:local src [/ip firewall connection get $cid src-address];:set topText ($topText . \"{\\\"client\\\":\\\"\" . $src . \"\\\",\\\"connections\\\":1},\");:set n ($n+1);:if ($n>9) do={:break}};:if ([:len $topText] > 0) do={:set topText [:pick $topText 0 ([:len $topText]-1)]};:local payload (\"{\\\"container_status\\\":\\\"\" . $cst . \"\\\",\\\"rx_bps\\\":\" . $rxBps . \",\\\"tx_bps\\\":\" . $txBps . \",\\\"active_connections\\\":\" . $ac . \",\\\"marked_bytes\\\":\" . $mbytes . \",\\\"updated\\\":\\\"\" . $now . \"\\\",\\\"top_clients\\\":[\" . $topText . \"]}\");/file set $jsonPath contents=$payload;")
/system script add name="ff_ui_metrics" source=$metricsSource comment="ff_ui"
:local schedInterval "00:00:05"
:if ($UIREFRESHSEC = 10) do={ :set schedInterval "00:00:10" }
/system scheduler add name="ff_ui_sched" interval=$schedInterval on-event="/system script run ff_ui_metrics" start-time=startup comment="ff_ui"
/system script run ff_ui_metrics

:log warning ("[$TAG] done. dashboard: http://" . [/ip address get [find where interface=$LANIF] address] . ":" . $UIPORT . "/" . $uiHtmlFile)


