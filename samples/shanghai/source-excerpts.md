# 上海样本：源码节选

行号对应包内 Lua 文本。分隔行 `-- <...>` 表示不连续的源码行。

## `topo`

```lua
-- L28303
send_period = 86400,
send_active_period = 3600,
-- <...>
-- L28434
add_value(gw_info, "2g_ssid", wifi_info["2g_ssid"], "")
-- <...>
-- L28447
add_value(gw_info, "pppoe", pppoe.pppoe, "")
add_value(gw_info, "loid", poninfo.loid, "")
-- <...>
-- L28450
add_value(gw_info, "wan_ip", netinfo.wan_ip, "")
-- <...>
-- L28858
info.hostname = laninfo.hostname
-- <...>
-- L28861
info.ip = laninfo.ip
```

## `http_imei`

```lua
-- L7701
keywords = {"imei"},
-- <...>
-- L7703
attr = {"url", "cookie"},
```

## `sigcollect`

```lua
-- L22470
enable = true,
-- <...>
-- L22473
newdev_period = 600,
-- <...>
-- L22480
coll_type = {"term_http","hostname","elink","mdns","upnp","vendor","dhcp_hostname","imei","mac","devname","term_pkt","term_domain"},
```

## `domain_dip`

```lua
-- L6623
upperiod = 14400,
-- <...>
-- L6716
add_sig(mac, domainip, time, false)  -- add other sig within 10 seconds
```

## `http`

```lua
-- L7517
help = "get http from kernel and send to server",
period = 0,
```

## `https`

```lua
-- L9344
period = 0,
-- <...>
-- L9349
help = "get https from kernel and send to server"
```

## `rawpkt`

```lua
-- L21519
help = "get rawpkt from kernel and send to server",
-- <...>
-- L21522
conn_limit_pkts = 16,
```

## `pcap_dump`

```lua
-- L16563
help = "read/write/stat/replay pcap",
```

## `hredirect`

```lua
-- L7376
help = "redirect http from server",
-- <...>
-- L7380
enable = false,
rules = {},
```

## `pktpolicy`

```lua
-- L16787
help = "set pktpolicy and send info to server",
-- <...>
-- L16800
enable = true,
```

## `appctrl`

```lua
-- L777
help = "set appctrl and send info to server",
```

## `appmlp`

```lua
-- L1063
help = "set appmlp and real time send info to server",
```

## `pscan`

```lua
-- L18070
help = "parse n01 result and send to oper_data"
```

## `shell`

```lua
-- L22306
help = "run shell cmd and return result",
```

## `hotpatch`

```lua
-- L7222
help = "hot fixbug, and hot add more function",
```

## `upgrade`

```lua
-- L29719
help = "upgrade for plugin/lua/sig",
```

## `xid`

```lua
-- L30842
upload_mode = "svrdata",
-- <...>
-- L30845
period = 1800,
-- <...>
-- L30855
attr = {"url", "ref", "cookie"},
```

## `coll_domain`

```lua
-- L4003
help = "collect domain/stock data and send to svrdata",
-- <...>
-- L4010
upload_period = 0,
session_period = 1800,
-- <...>
-- L4015
["<STOCK_SITE_1>"] = {url = {"[?&]code=%u*(%d+)&?"}},
["<STOCK_SITE_2>"] = {url = {"[?&]code=%u*(%d+)&?"}},
["<STOCK_SITE_3>"] = {url = {"[?&]q=%u*(%d+)&?"}},
-- <...>
-- L4019
["<STOCK_SITE_4>"] = {url = {"[^/]/%u*(%d+)/?"}},
["<STOCK_SITE_5>"] = {url = {"[^/]/%u*(%d+)/?"}},
-- <...>
-- L4022
["<STOCK_SITE_6>"] = {ref = {"[^/]/%a*(%d+).html"}},
["<STOCK_SITE_7>"] = {ref = {"[^/]/%a*(%d+).html"}},
-- <...>
-- L4076
tt.stock_code = dtype_value or ""
```

## `crawler`

```lua
-- L4388
enable = false,
-- <...>
-- L4390
max_crawl_cnt = 30,
```

## `onvif`

```lua
-- L14848
help = "support to collect sig of onvif",
period = 0,
```

## `termact`

```lua
-- L27896
help = "collect termact to server",
-- <...>
-- L27899
enable = false,
-- <...>
-- L27901
-- Samba, tcp dst port 445, "4,FE534D42", "16,01002100"
```

## `xapp`

```lua
-- L30255
help = "send appinfo to server",
-- <...>
-- L30259
flow_enable = false,
tag_enable = false,
```

## `quic`

```lua
-- L20825
help = "get quic from PCAP and send to server",
-- <...>
-- L20828
upload_mode = "none",
```

## `httpdns`

```lua
-- L8858
help="http dns parse",
-- <...>
-- L8860
enable = true,
-- <...>
-- L8863
upload_enable = false,
```

## `qrcstats`

```lua
-- L19853
help = "get root cause stats",
-- <...>
-- L19855
collect_period = 0,
```

## `sec_camera`

```lua
-- L22025
help = "set sec_camera conf",
enable = false,
```

## `sec_data`

```lua
-- L22091
help = "filter secdata and send to server",
-- <...>
-- L22094
enable = false,
```
