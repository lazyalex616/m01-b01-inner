# 浙江样本：源码节选

行号对应包内 Lua 文本。分隔行 `-- <...>` 表示不连续的源码行。

## `topo`

```lua
-- L17652
send_period = 86400,
send_active_period = 3600,
-- <...>
-- L17902
add_value(gw_info, "2g_ssid", wifi_info["2g_ssid"], "")
-- <...>
-- L17915
add_value(gw_info, "pppoe", pppoe.pppoe, "")
add_value(gw_info, "loid", poninfo.loid, "")
-- <...>
-- L17918
add_value(gw_info, "wan_ip", netinfo.wan_ip, "")
```

## `http_imei`

```lua
-- L4593
keywords = {"imei"},
-- <...>
-- L4595
attr = {"url", "cookie"},
```

## `sigcollect`

```lua
-- L12862
enable = true,
-- <...>
-- L12865
newdev_period = 600,
-- <...>
-- L12872
coll_type = {"term_ua","term_uri","hostname","elink","mdns","upnp","vendor","dhcp_hostname","imei","mac","devname"},
```

## `domain_dip`

```lua
-- L3734
upperiod = 14400,
-- <...>
-- L3827
add_sig(mac, domainip, time, false)  -- add other sig within 10 seconds
```

## `http`

```lua
-- L4428
help = "get dns from kernel and send to server",
period = 0,
```

## `https`

```lua
-- L5739
period = 0,
-- <...>
-- L5744
help = "get https from kernel and send to server"
```

## `rawpkt`

```lua
-- L11988
help = "get rawpkt from kernel and send to server",
-- <...>
-- L11991
conn_limit_pkts = 16,
```

## `pcap_dump`

```lua
-- L10326
help = "read/write/stat pcap",
```

## `hredirect`

```lua
-- L4297
help = "redirect http from server",
-- <...>
-- L4301
enable = false,
rules = {},
```

## `pktpolicy`

```lua
-- L10360
help = "set pktpolicy and send info to server",
-- <...>
-- L10372
enable = true,
```

## `appctrl`

```lua
-- L20
help = "set appctrl and send info to server",
```

## `appmlp`

```lua
-- L747
help = "set appmlp and real time send info to server",
```

## `pscan`

```lua
-- L11598
help = "parse n01 result and send to oper_data"
```

## `shell`

```lua
-- L12698
help = "run shell cmd and return result",
```

## `hotpatch`

```lua
-- L4150
help = "hot fixbug, and hot add more function",
```

## `upgrade`

```lua
-- L19012
help = "upgrade for plugin/lua/sig",
```

## `sec_camera`

```lua
-- L12417
help = "set sec_camera conf",
enable = false,
```

## `sec_data`

```lua
-- L12483
help = "filter secdata and send to server",
-- <...>
-- L12486
enable = false,
```
