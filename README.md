<p align="right"><b>简体中文</b> | <a href="README.en.md">English</a></p>

![电信光猫预装插件样本分析：m01-b01-inner](assets/banner.png)

# `m01-b01-inner`：上海、浙江电信光猫插件样本

这是电信光猫里预装的一个插件，能收集家里设备的清单和部分上网记录并上报，还能执行远程下发的命令。本仓库收录两地的 `init.bin` 原件、完整 Lua 源码和模块索引。

上海电信和浙江电信的两台光猫搭载了不同版本的 `m01-b01-inner`。两版均以 `init.bin` 分发 Lua 源码，采用 zlib 压缩、AES-128-ECB 加密。

| 样本 | `init.bin` 大小 | Lua 源码大小 | 模块数（含基础库） |
|---|---:|---:|---:|
| 上海 | 244,440 字节 | 1,151,589 字节 | 119 |
| 浙江 | 141,160 字节 | 661,590 字节 | 90 |

## 样本来源与收录范围

两份样本均于 2026 年 11 月取自在用的电信光猫，各自的 `init.bin` 原件解密解压后，与插件运行时内存中的 Lua 文本逐字节一致。

| 内容 | 是否收录 |
|---|---|
| 设备原件 `init.bin`、完整 Lua 文本 `init.lua` | 收录，保持原始字节。SHA-256 见 [FORMAT.md](FORMAT.md) |
| 单页节选 `init.public.lua` | 保留。完整源码见同目录 `init.lua` |
| 源码节选、模块索引 | 收录。行号均对应设备原件中的 Lua 文本 |

## 文件结构

`init.bin` 由 24 字节包头和密文正文组成：

```text
偏移 0    4 字节   固定值 20 18 04 12
偏移 4    4 字节   整个文件的字节数
偏移 8    4 字节   压缩流的字节数
偏移 12   4 字节   Lua 文本的字节数（大端）
偏移 16   4 字节   全零
偏移 20   4 字节   Lua 文本的字节数（小端，与偏移 12 相同）
偏移 24   至文件尾  AES-128-ECB 密文
```

正文解密后，按偏移 8 声明的长度截取 zlib 压缩流，解压即得 Lua 文本。两份样本的压缩流与 zlib 级别 9 的输出逐字节一致。各字段的取值和原件指纹见 [FORMAT.md](FORMAT.md)。

## 共有功能

| 模块 | 行为及默认配置 |
|---|---|
| `topo` | 设备清单关联宽带账号、光猫入网标识（LOID）、序列号、Wi-Fi 名称及内外网 IP。终端字段包括 MAC、主机名、品牌型号、系统、在线时长和收发流量。默认每日上报完整清单，每小时上报在线设备。 |
| `http_imei`、`sigcollect` | 默认从明文 HTTP 网址和 Cookie 中匹配名为 `imei` 的 15 位值，纳入终端特征上报。 |
| `domain_dip` | 设备访问指定智能家居服务后，记录该设备随后 10 秒内访问的其他域名及对应 IP。默认开启，每 4 小时上报。 |
| `http`、`https`、`rawpkt`、`pcap_dump` | 解析明文 HTTP 请求中的网址、来源页、客户端标识和 Cookie，识别 HTTPS 连接中可见的域名。支持按规则采集、记录和回放报文。浙江版 `http` 的说明文字写作 `get dns`，代码解析的字段与上海版相同。 |
| `hredirect` | 按域名和路径重定向明文 HTTP 请求。默认关闭，规则表为空。 |
| `pktpolicy`、`appctrl`、`appmlp` | 按设备、应用和时段丢包、中止连接或调整流量优先级。 |
| `pscan` | 下载改名为 `n01` 的 nmap 扫描局域网，参数含 `-sV`（服务版本识别）。上报设备地址、开放端口、服务名称及版本；扫描脚本输出的结果以 `dev_vuln` 类型上报。默认周期为零。 |
| `shell`、`hotpatch`、`upgrade` | 在插件权限内执行远端下发的系统命令并返回结果；运行时加载 Lua 模块；更新脚本、识别规则和插件。 |

以下为各模块的关键源码。摘要行给出模块在完整源码中的位置；代码块里的行号对应上海样本 `init.lua`，另有标注的除外。

<details>
<summary><code>topo</code> · 上海 <a href="samples/shanghai/init.lua#L28283-L29513">L28283-L29513</a> · 浙江 <a href="samples/zhejiang/init.lua#L17635-L18826">L17635-L18826</a></summary>

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

</details>

<details>
<summary><code>http_imei</code> · 上海 <a href="samples/shanghai/init.lua#L7670-L7866">L7670-L7866</a> · 浙江 <a href="samples/zhejiang/init.lua#L4562-L4758">L4562-L4758</a></summary>

```lua
-- L7701
keywords = {"imei"},
-- <...>
-- L7703
attr = {"url", "cookie"},
```

</details>

<details>
<summary><code>sigcollect</code> · 上海 <a href="samples/shanghai/init.lua#L22455-L22916">L22455-L22916</a> · 浙江 <a href="samples/zhejiang/init.lua#L12847-L13258">L12847-L13258</a></summary>

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

</details>

<details>
<summary><code>domain_dip</code> · 上海 <a href="samples/shanghai/init.lua#L6606-L6818">L6606-L6818</a> · 浙江 <a href="samples/zhejiang/init.lua#L3717-L3929">L3717-L3929</a></summary>

```lua
-- L6623
upperiod = 14400,
-- <...>
-- L6716
add_sig(mac, domainip, time, false)  -- add other sig within 10 seconds
```

</details>

<details>
<summary><code>http</code> · 上海 <a href="samples/shanghai/init.lua#L7506-L7668">L7506-L7668</a> · 浙江 <a href="samples/zhejiang/init.lua#L4417-L4560">L4417-L4560</a></summary>

上海样本：

```lua
-- L7517
help = "get http from kernel and send to server",
period = 0,
-- <...>
-- L7538
http_table.url, next_pos = string.unpack(string.format("c%d", url_len), sbytes, next_pos)
-- <...>
-- L7541
http_table.ref, next_pos = string.unpack(string.format("c%d", ref_len), sbytes, next_pos)
-- <...>
-- L7544
http_table.ua, next_pos = string.unpack(string.format("c%d", ua_len), sbytes, next_pos)
-- <...>
-- L7547
http_table.cookie, next_pos = string.unpack(string.format("c%d", cookie_len), sbytes, next_pos)
```

浙江样本：

```lua
-- L4428
help = "get dns from kernel and send to server",
-- <...>
-- L4448
http_table.url, next_pos = string.unpack(string.format("c%d", url_len), sbytes, next_pos)
-- <...>
-- L4451
http_table.ref, next_pos = string.unpack(string.format("c%d", ref_len), sbytes, next_pos)
-- <...>
-- L4454
http_table.ua, next_pos = string.unpack(string.format("c%d", ua_len), sbytes, next_pos)
-- <...>
-- L4457
http_table.cookie, next_pos = string.unpack(string.format("c%d", cookie_len), sbytes, next_pos)
```

</details>

<details>
<summary><code>https</code> · 上海 <a href="samples/shanghai/init.lua#L9335-L9426">L9335-L9426</a> · 浙江 <a href="samples/zhejiang/init.lua#L5730-L5816">L5730-L5816</a></summary>

```lua
-- L9349
help = "get https from kernel and send to server"
-- <...>
-- L9361
type = "https_domain",
-- <...>
-- L9369
domain = svrname,
```

</details>

<details>
<summary><code>rawpkt</code> · 上海 <a href="samples/shanghai/init.lua#L21501-L21947">L21501-L21947</a> · 浙江 <a href="samples/zhejiang/init.lua#L11970-L12407">L11970-L12407</a></summary>

```lua
-- L21519
help = "get rawpkt from kernel and send to server",
-- <...>
-- L21522
conn_limit_pkts = 16, -- max pkts in one conn(tuple), 0 means no limit
```

</details>

<details>
<summary><code>pcap_dump</code> · 上海 <a href="samples/shanghai/init.lua#L16553-L16676">L16553-L16676</a> · 浙江 <a href="samples/zhejiang/init.lua#L10318-L10339">L10318-L10339</a></summary>

```lua
-- L16563
help = "read/write/stat/replay pcap",
```

</details>

<details>
<summary><code>hredirect</code> · 上海 <a href="samples/shanghai/init.lua#L7365-L7504">L7365-L7504</a> · 浙江 <a href="samples/zhejiang/init.lua#L4286-L4415">L4286-L4415</a></summary>

```lua
-- L7376
help = "redirect http from server",
-- <...>
-- L7380
enable = false,
rules = {},
```

</details>

<details>
<summary><code>pktpolicy</code> · 上海 <a href="samples/shanghai/init.lua#L16770-L17284">L16770-L17284</a> · 浙江 <a href="samples/zhejiang/init.lua#L10341-L10822">L10341-L10822</a></summary>

```lua
-- L16787
help = "set pktpolicy and send info to server",
-- <...>
-- L16800
enable = true,
```

</details>

<details>
<summary><code>appctrl</code> · 上海 <a href="samples/shanghai/init.lua#L761-L1046">L761-L1046</a> · 浙江 <a href="samples/zhejiang/init.lua#L3-L272">L3-L272</a></summary>

```lua
-- L777
help = "set appctrl and send info to server",
```

</details>

<details>
<summary><code>appmlp</code> · 上海 <a href="samples/shanghai/init.lua#L1048-L1350">L1048-L1350</a> · 浙江 <a href="samples/zhejiang/init.lua#L730-L1032">L730-L1032</a></summary>

```lua
-- L1063
help = "set appmlp and real time send info to server",
```

</details>

<details>
<summary><code>pscan</code> · 上海 <a href="samples/shanghai/init.lua#L18040-L18443">L18040-L18443</a> · 浙江 <a href="samples/zhejiang/init.lua#L11568-L11968">L11568-L11968</a></summary>

```lua
-- L18055
period = 0,
-- <...>
-- L18058
argv = ' --max-rate 10 -sV -oX ',
prog = 'n01',
-- <...>
-- L18070
help = "parse n01 result and send to oper_data"
-- <...>
-- L18129
local one = {type = "dev_vuln", mac = mac, ip = ip, script_name = script.id or "", vuln_info = cjson.encode(info)}
-- <...>
-- L18145
service = get_attr(v.kids, "service", {name = true, version = true, product = true})
-- <...>
-- L18149
local one = {type = "pscan_v1", mac = mac, ip = ip, port = portid, proto = port.protocol or "", status = state.state or "", svr = service.name or "", version = service.version or "", product = service.product or ""}
-- <...>
-- L18334
-- download nmap tarball to tmp path
```

</details>

<details>
<summary><code>shell</code> · 上海 <a href="samples/shanghai/init.lua#L22300-L22337">L22300-L22337</a> · 浙江 <a href="samples/zhejiang/init.lua#L12692-L12729">L12692-L12729</a></summary>

```lua
-- L22306
help = "run shell cmd and return result",
```

</details>

<details>
<summary><code>hotpatch</code> · 上海 <a href="samples/shanghai/init.lua#L7212-L7363">L7212-L7363</a> · 浙江 <a href="samples/zhejiang/init.lua#L4142-L4284">L4142-L4284</a></summary>

```lua
-- L7222
help = "hot fixbug, and hot add more function",
```

</details>

<details>
<summary><code>upgrade</code> · 上海 <a href="samples/shanghai/init.lua#L29710-L29818">L29710-L29818</a> · 浙江 <a href="samples/zhejiang/init.lua#L19003-L19111">L19003-L19111</a></summary>

```lua
-- L29719
help = "upgrade for plugin/lua/sig",
```

</details>

## 仅见于上海样本的模块

| 模块 | 行为及默认配置 |
|---|---|
| `xid` | 从明文 HTTP 网址、来源页和 Cookie 中匹配手机号、IMEI、IMSI（移动用户识别码）、广告标识及经纬度字段，与设备和域名关联。默认每 30 分钟上报。 |
| `coll_domain` | 按设备统计域名访问次数、时长和来源页。内置东方财富、同花顺、问财、雪球的网址匹配规则，用于提取股票代码。默认上报周期为零。 |
| `crawler` | 每批接收最多 30 个网址，经用户宽带出口访问，将网页内容返回平台。默认关闭。 |
| `onvif` | 发现局域网摄像头，查询型号、序列号和固件版本，使用平台配置的账号列表尝试认证。默认采集周期为零。 |
| `termact` | 匹配发往 445 端口的特定 SMB2 文件共享报文，将应用层内容与设备地址一并交给上报模块。规则还涉及 DHCPv6、mDNS、部分 IPTV 和小米设备流量，以及组播报文。默认关闭。 |
| `xapp`、`quic`、`httpdns` | `xapp` 可记录网址、Cookie、来源页和部分报文内容，相关流量上报默认关闭。`quic` 识别部分 HTTP/3 连接中的域名；`httpdns` 记录特定域名解析服务返回的结果。 |
| `qrcstats` | 扫描附近的 Wi-Fi 网络。默认采集周期为零。 |

<details>
<summary><code>xid</code> · 上海 <a href="samples/shanghai/init.lua#L30826-L31050">L30826-L31050</a></summary>

```lua
-- L30842
upload_mode = "svrdata",   -- "none", "svrdata", "operdata", "all"
-- <...>
-- L30845
period = 1800,
-- <...>
-- L30855
attr = {"url", "ref", "cookie"},
```

</details>

<details>
<summary><code>coll_domain</code> · 上海 <a href="samples/shanghai/init.lua#L3989-L4255">L3989-L4255</a></summary>

```lua
-- L4003
help = "collect domain/stock data and send to svrdata",
-- <...>
-- L4010
upload_period = 0,  -- default disable
session_period = 1800,
-- <...>
-- L4015
["gbapi.eastmoney.com"] = {url = {"[?&]code=%u*(%d+)&?"}},
["ai.10jqka.com.cn"] = {url = {"[?&]code=%u*(%d+)&?"}},
["www.iwencai.com"] = {url = {"[?&]q=%u*(%d+)&?"}},
-- <...>
-- L4019
["stockpage.10jqka.com.cn"] = {url = {"[^/]/%u*(%d+)/?"}},
["xueqiu.com"] = {url = {"[^/]/%u*(%d+)/?"}},
-- <...>
-- L4022
["quote.eastmoney.com"] = {ref = {"[^/]/%a*(%d+).html"}},
["myfavor.eastmoney.com"] = {ref = {"[^/]/%a*(%d+).html"}},
-- <...>
-- L4076
tt.stock_code = dtype_value or ""
```

</details>

<details>
<summary><code>crawler</code> · 上海 <a href="samples/shanghai/init.lua#L4363-L4696">L4363-L4696</a></summary>

```lua
-- L4388
enable = false,         -- default is disable
-- <...>
-- L4390
max_crawl_cnt = 30,     -- maximum number of climbs
```

</details>

<details>
<summary><code>onvif</code> · 上海 <a href="samples/shanghai/init.lua#L14832-L15356">L14832-L15356</a></summary>

```lua
-- L14848
help = "support to collect sig of onvif",
period = 0, -- default close
```

</details>

<details>
<summary><code>termact</code> · 上海 <a href="samples/shanghai/init.lua#L27881-L28148">L27881-L28148</a></summary>

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

</details>

<details>
<summary><code>xapp</code> · 上海 <a href="samples/shanghai/init.lua#L30239-L30824">L30239-L30824</a></summary>

```lua
-- L30255
help = "send appinfo to server",
-- <...>
-- L30259
flow_enable = false,        -- 是否采集流特征数据，默认关闭
tag_enable = false,         -- 是否采集标签特征数据，默认关闭
```

</details>

<details>
<summary><code>quic</code> · 上海 <a href="samples/shanghai/init.lua#L20814-L21499">L20814-L21499</a></summary>

```lua
-- L20825
help = "get quic from PCAP and send to server",
-- <...>
-- L20828
upload_mode = "none", -- "none", "svrdata", "operdata", "all"
```

</details>

<details>
<summary><code>httpdns</code> · 上海 <a href="samples/shanghai/init.lua#L8844-L9333">L8844-L9333</a></summary>

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

</details>

<details>
<summary><code>qrcstats</code> · 上海 <a href="samples/shanghai/init.lua#L19840-L20476">L19840-L20476</a></summary>

```lua
-- L19853
help = "get root cause stats",
-- <...>
-- L19855
collect_period = 0,
```

</details>

## 外部线索核对

| 线索 | 核对结果 |
|---|---|
| 临时下发 `capvip`，不在设备上保存，采集哔哩哔哩大会员等流媒体会员状态 | 两份随包源码均未见该模块，无下发样本可供核对。 |
| HTTP 302 跳转 | 两份样本均有 HTTP 重定向规则；实际响应码未核实。 |
| DNS 应答改写 | 上海样本的 `HijackConfRW` 定义含“域名 → IP”和“网址 → 跳转地址”字段。Lua 中未见 DNS 应答改写实现。浙江样本未见同名定义。 |
| 跳转功能与 `dcm`、`nsxp30` 木马投放有关 | 现有材料中未见关联代码、投放记录或终端感染证据。 |
| SMB 握手数据的用途 | 上海样本将匹配报文交给设备特征模块。服务端用途未知。 |
| 按地区下发不同策略 | 缺少同版本的跨地区下发记录。新疆、西藏暂无可供核对的样本。 |

## 文件

| 样本 | 完整 Lua 源码 | `init.bin` 原件 | 模块与原行号 | 源码节选 |
|---|---|---|---|---|
| 上海 | [init.lua](samples/shanghai/init.lua) | [init.bin](samples/shanghai/init.bin) | [119 个模块](samples/shanghai/module-index.tsv) | [27 个功能模块](samples/shanghai/source-excerpts.md) |
| 浙江 | [init.lua](samples/zhejiang/init.lua) | [init.bin](samples/zhejiang/init.bin) | [90 个模块](samples/zhejiang/module-index.tsv) | [18 个功能模块](samples/zhejiang/source-excerpts.md) |

[文件格式、加密参数与原件指纹](FORMAT.md) · [外部线索的逐项证据](MODULE-NOTES.md)

## 许可

本仓库以 [MIT 许可证](LICENSE) 发布。
