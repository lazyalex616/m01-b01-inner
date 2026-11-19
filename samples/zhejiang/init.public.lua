-- m01-b01-inner | zhejiang | public source edition v1
-- <...> marks omitted implementation. Original line numbers refer to the device sample.

-- [appctrl] | original L3-L272
-- L20
-- help = "set appctrl and send info to server",
-- <...>

-- [appinfo] | original L274-L728
-- L287
-- period = 1800,
-- L288
-- help = "send appinfo to server",
-- L295
-- enable = true,
-- <...>

-- [appmlp] | original L730-L1032
-- L747
-- help = "set appmlp and real time send info to server",
-- <...>

-- [apprule] | original L1034-L1206
-- L1047
-- help = "app rule configure",
-- L1048
-- period = 5,
-- <...>

-- [appsig_bin] | original L1208-L1685
-- L1221
-- help = "load appsig",
-- L1222
-- period = 86400,
-- <...>

-- [appuse] | original L1687-L1946
-- L1704
-- help = "set appuse and send info to server",
-- <...>

-- [arch] | original L1948-L2082
-- L1959
-- help = "arch var, SN, mac, oui, version, sigversion, etc...",
-- <...>

-- [capi] | original L2084-L2149
-- L2092
-- help = "get info from capi"
-- <...>

-- [cliclient] | original L2151-L2283
-- <...>

-- [cliserver] | original L2285-L2417
-- <...>

-- [config_service] | original L2419-L2422
package.preload[ "config_service" ] = assert( (loadstring or load)(
"return {\"arch\",\"dns\",\"tuple\",\"sys\",\"svroper\",\"shell\",\"operdata\",\"svrdata\",\"sig\",\"dmpapp\",\"ct\",\"osinfo\",\"sigcollect\",\"http\",\"upgrade\",\"dpinfo\",\"http_rule\",\"devinfo\",\"lanhost\",\"lanhoststats\",\"wanstats\",\"diagnose\",\"hredirect\",\"capi\",\"pscan\",\"rawpkt\",\"hotpatch\",\"topo\",\"mdns\",\"upnp\",\"pktpolicy\",\"wandns\",\"pcap_dump\",\"dhcp\",\"oscloud\",\"pqprobe\",\"dumh\",\"https\",\"postmsg\",\"sec_data\",\"domain_dip\",\"sec_camera\",\"appsig_bin\",\"apprule\",\"appinfo\",\"http_imei\",\"appctrl\",\"appuse\",\"appmlp\"}\
"
, '@'.."./config_service.lua" ) )

-- [ct] | original L2424-L2604
-- L2436
-- help = "deal ct ipfilter cthttp topo, send to server",
-- L2443
-- period = 300,
-- <...>

-- [ct.cthttp] | original L2606-L2657
-- <...>

-- [ct.ipfilter] | original L2659-L2735
-- <...>

-- [ct.osgi] | original L2737-L2892
-- <...>

-- [ct.policy] | original L2894-L3041
-- <...>

-- [devinfo] | original L3043-L3161
package.preload[ "devinfo" ] = assert( (loadstring or load)(
"local mystring = require\"mystring\"\
local actor = require\"luactor\"\
\
local devinfo = {\
    type = \"__dev_info\", \
    subtype = \"__dev_info\", \
    help = \"send cpu/mem info to server\", \
\
    period = 0, \
\
    -- last cpu\
    last_use = 0, \
    last_all = 0, \
\
    -- stat\
    all_count = 0,\
    all_len = 0,\
}\
\
local function getmem()\
    local total, available, memfree, buffers, cached = 0, 0, 0, 0, 0\
    local available_flag = false\
    local used = 0\
    for line in io.lines(\"/proc/meminfo\") do\
        local attr, size = mystring.split(line, \" \\t\")\
        size = tonumber(size)\
        if attr == \"MemTotal:\" then\
            total = size\
        elseif attr == \"MemAvailable:\" then\
            available_flag = true\
            available = size\
        elseif attr == \"MemFree:\" then\
            memfree = size\
        elseif attr == \"Buffers:\" then\
            buffers = size\
        elseif attr == \"Cached:\" then\
            cached = size\
        end\
    end\
\
    if available_flag then\
        used = total - available\
    else\
        used = total - memfree - buffers - cached\
    end\
\
    if total <= 0 or used < 0 or used > total then\
        return 0, 0\
    else\
        return used, total - used\
    end\
end\
\
\
local function getcpu()\
    local data = io.lines(\"/proc/stat\")()\
    local _, u, n, s, i, w, x, y, z = mystring.split(data, \" \\t\")\
    if type(z) ~= \"string\" then\
        return 0, 0\
    end\
\
    local use_tic = u + n + s + w + x + y + z\
    return use_tic, use_tic + i\
end\
\
local function calccpu(last_use, last_all, now_use, now_all)\
    local all_tics, use_tics = now_all - last_all, now_use - last_use\
\
    if all_tics <= 0 or use_tics <= 0 or all_tics < use_tics then\
        return 0\
    end\
\
    return math.floor(use_tics * 100 / all_tics)\
end\
\
local function senddmp()\
    local cpu_use, cpu_all = getcpu()\
    local cpu_ratio = calccpu(devinfo.last_use, devinfo.last_all, cpu_use, cpu_all)\
    devinfo.last_use = cpu_use\
    devinfo.last_all = cpu_all\
\
    local mem_use, mem_free = getmem()\
    log.info(\"will send dmp devinfo\", cpu_ratio, mem_use, mem_free)\
\
    local sbytes = string.pack(\">IIIII\", cpu_ratio, mem_use, mem_free, 0, 0)\
\
    lcmd_run{subtype = \"__svr_data\", action = \"add\", sbytes = sbytes, \
             pkttype = CENUM.COMM_BUSINESS_DMP_DEVICE, count = 1}\
\
    devinfo.all_count = devinfo.all_count + 1\
    devinfo.all_len = devinfo.all_len + string.len(sbytes)\
end\
\
function devinfo.postinit()\
    devinfo.last_use, devinfo.last_all = getcpu()\
end\
\
actor.action_set(devinfo.subtype, \"read\", \
                 function() \
                     return {period = devinfo.period, last_use = devinfo.last_use, last_all = devinfo.last_all} \
                 end, \"read period and last cpu\")\
actor.action_set(devinfo.subtype, \"write\", \
                 function(t) \
                     if type(t.period) == \"number\" and t.period ~= devinfo.period then\
                         local timer = require\"timer\"\
                         devinfo.period = t.period\
                         timer.mod(\"devinfo\", t.period, 0, function() senddmp() end)\
                     end\
                 end, \
                 \"change period, {period = xx}\")\
                 \
actor.action_set(devinfo.subtype, \"stat\",\
                function ()\
                    return {all_count = devinfo.all_count, all_len = devinfo.all_len }\
                end, \"read stat\")\
return devinfo\
"
, '@'.."./service/devinfo.lua" ) )

-- [dhcp] | original L3163-L3262
-- L3173
-- help = "parse dhcp and send to server",
-- <...>

-- [diagnose] | original L3264-L3296
-- L3272
-- help = "diagnose",
-- <...>

-- [dmpapp] | original L3298-L3431
-- L3308
-- help = "get app from kernel, send to server",
-- L3309
-- period = 0,
-- <...>

-- [dns] | original L3433-L3558
-- L3441
-- help = "get dns from pcap",
-- L3443
-- period = 0,
-- <...>

-- [dnscache] | original L3560-L3715
-- <...>

-- [domain_dip] | original L3717-L3929
-- L3734
-- upperiod = 14400,
-- <...>
-- L3827
-- add_sig(mac, domainip, time, false)  -- add other sig within 10 seconds
-- <...>

-- [dpinfo] | original L3931-L4001
-- L3942
-- help = "show some base info, only read",
-- <...>

-- [dumh] | original L4003-L4140
-- L4016
-- help = "dumh",
-- <...>

-- [hotpatch] | original L4142-L4284
-- L4150
-- help = "hot fixbug, and hot add more function",
-- <...>

-- [hredirect] | original L4286-L4415
-- L4297
-- help = "redirect http from server",
-- <...>
-- L4301
-- enable = false,
-- rules = {},
-- <...>

-- [http] | original L4417-L4560
-- L4428
-- help = "get dns from kernel and send to server",
-- period = 0,
-- <...>

-- [http_imei] | original L4562-L4758
-- L4593
-- keywords = {"imei"},
-- <...>
-- L4595
-- attr = {"url", "cookie"},
-- <...>

-- [http_rule] | original L4760-L4792
-- L4769
-- help = "http rule configure",
-- <...>

-- [httpclient] | original L4794-L4922
-- <...>

-- [httpclient.luasocket_driver] | original L4924-L5097
-- <...>

-- [httpclient.neturl] | original L5099-L5543
-- <...>

-- [httpclient.ngx_driver] | original L5545-L5699
-- <...>

-- [httpclient.utils] | original L5701-L5728
package.preload[ "httpclient.utils" ] = assert( (loadstring or load)(
"local inspect = require('inspect')\
local function deep_copy(t)\
  if type(t) ~= \"table\" then return t end\
  local meta = getmetatable(t)\
  local target = {}\
  for k, v in pairs(t) do\
    if type(v) == \"table\" then\
        target[k] = cloneTable(v)\
    else\
        target[k] = v\
    end\
  end\
  setmetatable(target, meta)\
  return target\
end\
\
local function print_table(t)\
  return inspect(t)\
end\
\
utils = {\
  print_table = print_table,\
  deep_copy = deep_copy\
}\
return utils\
"
, '@'.."./lualib/httpclient/utils.lua" ) )

-- [https] | original L5730-L5816
-- L5739
-- period = 0,
-- <...>
-- L5744
-- help = "get https from kernel and send to server"
-- <...>

-- [inspect] | original L5818-L6162
-- <...>

-- [kengine] | original L6164-L6500
-- L6178
-- enable = false,
-- <...>

-- [lanhost] | original L6502-L6608
-- L6511
-- help = "get lan host for ct",
-- <...>

-- [lanhoststats] | original L6610-L6795
package.preload[ "lanhoststats" ] = assert( (loadstring or load)(
"\
local actor = require(\"luactor\") \
local cjson = require(\"cjson\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local cct = require(\"c.ct\")\
local timer = require(\"timer\")\
\
\
local lanHostStats = {\
    type = \"lanhost_stats\",\
    subtype = \"lanhost_stats\",  -- for timer use\
    help = \"get lanstats from capi, send to server\",\
\
    timer_name = \"lanhost_stats_get\",\
    period = 0,\
\
    upload_mode = \"svrdata\", -- \"none\", \"svrdata\", \"operdata\", \"all\"\
\
    hosts = {},\
    lasttime_get = 0,\
\
    all_count = 0,\
    all_len = 0,\
    data_uploaded = {},\
}\
\
local function lanhosts_get()\
    local lanhosts = cct.getlanhost()\
    local hosts = {}\
    \
    if lanhosts == nil then\
        return nil\
    end\
\
    for mac, v in pairs(lanhosts) do\
        assert(v.userdata)\
        local host = cct.showlan(v.userdata)\
        if host then\
            if host.rxbytes == nil or host.txbytes == nil then\
                -- ignore, maybe api version doesn't support yet\
                return nil\
            end\
\
            local macstring = string.upper(myip.mac_ntoa(mac))\
            hosts[macstring] = host\
        end\
    end\
\
    return hosts\
end\
\
local function lanhost_stats_init()\
    lanHostStats.hosts = lanhosts_get()\
    lanHostStats.lasttime_get = os.time()\
end\
\
local function lanhost_stats_get()\
    local now = os.time()\
    local stats = { }\
    local hosts = lanhosts_get()\
\
    if hosts == nil then\
        return\
    end\
\
    for macstring, host in pairs(hosts) do\
        local host_old = nil\
        local rx_bytes = 0 tx_bytes = 0\
\
        if lanHostStats.hosts then\
            host_old = lanHostStats.hosts[macstring]\
        end\
\
        local rx_old, tx_old = host_old and host_old.rxbytes or 0, host_old and host_old.txbytes or 0\
        if rx_old < 0 or tx_old < 0 or host.rxbytes < 0 or host.txbytes < 0 then\
            goto continue\
        end\
        if host_old then\
            if host_old.rxbytes <= host.rxbytes then\
                rx_bytes = host.rxbytes - host_old.rxbytes\
            else\
                rx_bytes = host.rxbytes\
            end\
            if host_old.txbytes <= host.txbytes then\
                tx_bytes = host.txbytes - host_old.txbytes\
            else\
                tx_bytes = host.txbytes\
            end\
        else\
            rx_bytes = host.rxbytes\
            tx_bytes = host.txbytes\
        end\
\
        if rx_bytes > 0 or tx_bytes > 0 then\
            local stat = {}\
            stat.mac = macstring\
            stat.ip = host.ip\
            stat.rx_bytes = tostring(rx_bytes)\
            stat.tx_bytes = tostring(tx_bytes)\
            table.insert(stats, stat)\
        end\
\
        ::continue::\
    end\
\
    if #stats > 0 then\
        lanHostStats.data_uploaded = { type = \"lan_stats\", data = stats, period = lanHostStats.period, timestamp = tostring(now) }\
\
        if lanHostStats.upload_mode ~= \"none\" then\
\
            if lanHostStats.upload_mode == \"operdata\" or lanHostStats.upload_mode  == \"all\" then\
                lcmd_run({subtype = \"__oper_data\", action = \"add\", data = lanHostStats.data_uploaded})\
            end\
\
            if lanHostStats.upload_mode == \"svrdata\" or lanHostStats.upload_mode == \"all\" then\
                lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = lanHostStats.data_uploaded})\
            end\
\
            lanHostStats.all_count = lanHostStats.all_count + 1\
            lanHostStats.all_len = lanHostStats.all_len + string.len(cjson.encode(lanHostStats.data_uploaded))\
        end\
    end\
\
    lanHostStats.hosts = hosts\
    lanHostStats.lasttime_get = now\
end\
\
local function lanhoststats_set_period(msg)\
    if msg.period and tonumber(msg.period) ~= lanHostStats.period then\
        lanHostStats.period = tonumber(msg.period)\
        timer.mod(lanHostStats.timer_name, lanHostStats.period, 0, lanhost_stats_get)\
        if lanHostStats.period > 0 then\
            lanhost_stats_init()\
        end\
    end\
end\
\
local function lanhoststats_set_upload_mode(msg)\
    if type(msg.upload_mode) == \"string\" and msg.upload_mode ~= lanHostStats.upload_mode then\
        if msg.upload_mode == \"none\" or msg.upload_mode == \"svrdata\" or msg.upload_mode == \"operdata\" or msg.upload_mode == \"all\" then\
            lanHostStats.upload_mode = msg.upload_mode\
        end\
    end\
end\
\
local function lanhoststats_show_history(msg)\
    local history = {}\
    history.time = os.date(\"%Y-%m-%d %H:%M:%S\", lanHostStats.lasttime_get)\
    history.hosts = lanHostStats.hosts\
    return history\
end\
\
local function lanhoststats_show_current(msg)\
    local current = {}\
    current.time = os.date(\"%Y-%m-%d %H:%M:%S\")\
    current.hosts = lanhosts_get()\
    return current\
end\
\
local function lanhoststats_show_lastupload(msg)\
    return lanHostStats.data_uploaded\
end\
\
local function lanhoststats_read_stat(msg)\
    return { period = lanHostStats.period, upload_mode = lanHostStats.upload_mode, all_count = lanHostStats.all_count, all_len = lanHostStats.all_len }\
end\
\
function lanHostStats.postinit()\
    timer.mod(lanHostStats.timer_name, lanHostStats.period, 0,lanhost_stats_get)\
end\
\
actor.action_set(lanHostStats.subtype, \"lanhoststats_set_upload_mode\", lanhoststats_set_upload_mode, [[set upload_mode to send lanhoststats flow msg]])\
actor.action_set(lanHostStats.subtype, \"lanhoststats_set_period\", lanhoststats_set_period, [[set period to send lanhosts flow msg,{period = number}]])\
actor.action_set(lanHostStats.subtype, \"lanhoststats_show_history\", lanhoststats_show_history, \"show lancollect msg last time\")\
actor.action_set(lanHostStats.subtype, \"lanhoststats_show_current\", lanhoststats_show_current, \"show lancollect msg current\")\
actor.action_set(lanHostStats.subtype, \"lanhoststats_show_lastupload\", lanhoststats_show_lastupload, \"show lancollect msg last upload\")\
actor.action_set(lanHostStats.subtype, \"lanhoststats_read_stat\", lanhoststats_read_stat, \"read lancollect period,all_count and all_len\")\
actor.action_set(lanHostStats.subtype, \"read\", function () return {period = lanHostStats.period, upload_mode = lanHostStats.upload_mode} end, \"read lancollect period and upload_mode\")\
actor.action_set(lanHostStats.subtype, \"stat\", function () return {all_count = lanHostStats.all_count, all_len = lanHostStats.all_len} end, \"read lancollect all_count and all_len\")\
\
return lanHostStats\
\
"
, '@'.."./service/lanhoststats.lua" ) )

-- [log] | original L6797-L6916
-- <...>

-- [ltn12] | original L6918-L7229
-- <...>

-- [luactor] | original L7231-L7583
-- L7247
-- enable = true,
-- <...>

-- [mdns] | original L7585-L7773
-- L7597
-- help = "mdns find host",
-- <...>

-- [mime] | original L7775-L7866
-- <...>

-- [msocket] | original L7868-L8167
-- <...>

-- [myfile] | original L8169-L8276
-- <...>

-- [myip] | original L8278-L8573
-- <...>

-- [mystring] | original L8575-L8631
package.preload[ "mystring" ] = assert( (loadstring or load)(
"local mystring = {}\
\
function mystring.same_table(t1, t2)\
    if type(t1) ~= \"table\" or type(t2) ~= \"table\" then\
        return false\
    end\
\
    for k,v in pairs(t1) do\
        if not t2[k] then\
            return false\
        elseif v ~= t2[k] then\
            return false\
        end\
    end\
\
    for k,v in pairs(t2) do\
        if not t1[k] then\
            return false\
        elseif v ~= t1[k] then\
            return false\
        end\
    end\
\
    return true\
end\
\
function mystring.split(str, delim)\
    local sub_str_tab = {}\
    string.gsub(str,'[^'..delim..']+',function ( w )\
        table.insert(sub_str_tab, w)\
    end)\
    return table.unpack(sub_str_tab)\
end\
\
function mystring.trim(str)\
    return (string.gsub(str, \"^%s*(.-)%s*$\", \"%1\"))\
end\
\
function mystring.data2hex(data, delim)\
    local tt = {}\
    data:gsub(\"(.)\", function (byte) table.insert(tt, string.format(\"%02X\", byte:byte())) end)\
    return table.concat(tt, delim)\
end\
\
function mystring.hex2data(hexstr, delim)\
    if delim then\
        pattern = string.format(\"(%%x%%x)[%s]?\", delim)\
    else\
        pattern = \"(%x%x)\"\
    end\
    return (hexstr:gsub(pattern, function (word) return string.char(tonumber(word, 16)) end))\
end\
\
return mystring\
"
, '@'.."./lualib/mystring.lua" ) )

-- [myutil] | original L8633-L8738
-- <...>

-- [nselib] | original L8740-L8742
-- <...>

-- [nselib.slaxml] | original L8744-L9207
-- <...>

-- [operdata] | original L9209-L9473
-- L9223
-- help = "oper data server communication",
-- <...>

-- [oscloud] | original L9475-L9600
-- L9485
-- help = "receive cloud dev desc",
-- <...>

-- [osinfo] | original L9602-L10298
-- L9615
-- help = "get osinfo from kernel, send to server",
-- L9618
-- period = 0,
-- <...>

-- [pbmsg] | original L10300-L10316
-- <...>

-- [pcap_dump] | original L10318-L10339
-- L10326
-- help = "read/write/stat pcap",
-- <...>

-- [pktpolicy] | original L10341-L10822
-- L10360
-- help = "set pktpolicy and send info to server",
-- <...>
-- L10372
-- enable = true,
-- <...>

-- [postmsg] | original L10824-L10903
-- L10829
-- help = "DBUS postmsg run lua command",
-- <...>

-- [pqprobe] | original L10905-L11566
-- L10918
-- help = "time delay detection(tcp, udp, dns)",
-- L10945
-- period = 3600,
-- <...>

-- [pscan] | original L11568-L11968
-- L11598
-- help = "parse n01 result and send to oper_data"
-- <...>

-- [rawpkt] | original L11970-L12407
-- L11988
-- help = "get rawpkt from kernel and send to server",
-- <...>
-- L11991
-- conn_limit_pkts = 16,
-- <...>

-- [sec_camera] | original L12409-L12468
-- L12417
-- help = "set sec_camera conf",
-- enable = false,
-- <...>

-- [sec_data] | original L12470-L12690
-- L12483
-- help = "filter secdata and send to server",
-- <...>
-- L12486
-- enable = false,
-- <...>

-- [shell] | original L12692-L12729
-- L12698
-- help = "run shell cmd and return result",
-- <...>

-- [sig] | original L12731-L12845
-- <...>

-- [sigcollect] | original L12847-L13258
-- L12862
-- enable = true,
-- <...>
-- L12865
-- newdev_period = 600,
-- <...>
-- L12872
-- coll_type = {"term_ua","term_uri","hostname","elink","mdns","upnp","vendor","dhcp_hostname","imei","mac","devname"},
-- <...>

-- [socket] | original L13260-L13411
-- <...>

-- [socket.headers] | original L13413-L13518
-- <...>

-- [socket.http] | original L13520-L13904
-- <...>

-- [socket.url] | original L13906-L14217
-- <...>

-- [ssl] | original L14219-L14485
-- <...>

-- [ssl.https] | original L14487-L14634
-- <...>

-- [svrcomm] | original L14636-L15083
-- <...>

-- [svrcomm.ckey] | original L15085-L15368
-- L15099
-- period = 60,
-- <...>

-- [svrcomm.dpi] | original L15370-L16096
-- <...>

-- [svrcomm.pack] | original L16098-L16280
-- <...>

-- [svrcomm.packpb] | original L16282-L16437
-- <...>

-- [svrcomm.pth] | original L16439-L16731
-- <...>

-- [svrdata] | original L16733-L16925
-- L16747
-- help = "DMP server communication, only send to, no reply",
-- L16750
-- period = 0,
-- <...>

-- [svroper] | original L16927-L17186
-- L16944
-- help = "oper server, send heart/init/result to server",
-- <...>

-- [sys] | original L17188-L17504
-- L17202
-- help = "sys module, configure/save, also including bypass/engine/timer etc.",
-- <...>

-- [timer] | original L17506-L17610
package.preload[ "timer" ] = assert( (loadstring or load)(
"log = require\"log\"\
\
local timer = {\
-- {\
--     name, \
--     cycle, \
--     once, \
--     func, \
--     args, \
--     maydisable, if true and enable is false, then this timer will not be triggerred\
--\
--     next, nexttime for runing\
-- }\
\
    timers = {}, \
    enable = false\
}\
\
function timer.read()\
    local t = {}\
    t.enable = timer.enable\
    t.timers = {}\
    for k, v in pairs(timer.timers) do\
        t.timers[k] = {cycle = v.cycle, once = v.once, maydisable = v.maydisable}\
    end\
\
    return t\
end\
\
local function tmod_all(name, cycle, once, maydisable, func, ...)\
    local timers = timer.timers\
\
    if timers[name] == nil then\
        timers[name] = {}\
    end\
    -- configures\
    timers[name].name = name\
    timers[name].cycle = cycle\
    if type(once) == \"number\" then\
        timers[name].once = once\
    end\
    timers[name].maydisable = maydisable\
\
    if type(func) == \"function\" then\
        timers[name].func = func\
        timers[name].args = {...}\
    end\
\
    -- runnings variables\
    timers[name].next = cycle + os.time()\
    -- log.info(\"mod timer \"..timers[name].name, \"cycle is \"..cycle)\
end\
\
function timer.mod_notdisable(name, cycle, once, func, ...)\
    tmod_all(name, cycle, once, false, func, ...)\
end\
\
function timer.mod(name, cycle, once, func, ...)\
    tmod_all(name, cycle, once, true, func, ...)\
end\
\
function timer.del(name)\
    if timer.timers[name] then\
        timer.timers[name] = nil\
    end\
end\
\
function timer.timer_enable(enable)\
    if enable then\
        timer.enable = true\
    else\
        timer.enable = false\
    end\
end\
\
local function timer_ready(v, now)\
    if v.cycle > 0 and (timer.enable or not v.maydisable) and (now >= v.next or now + v.cycle < v.next) then\
        return true\
    else\
        return false\
    end\
end\
\
function timer.run_now(now)\
    local running = {}\
    for _, v in pairs(timer.timers) do\
        if timer_ready(v, now) then\
            table.insert(running, v)\
        end\
    end\
\
    for _, v in ipairs(running) do\
        if v.once == 1 then\
            timer.del(v.name)\
        end\
        -- log.trace(\"trigger timer \"..v.name..\" with func \", v.func)\
        v.func(table.unpack(v.args))\
        v.next = v.cycle + now\
    end\
end\
\
return timer\
"
, '@'.."./lualib/timer.lua" ) )

-- [tlv] | original L17612-L17633
-- <...>

-- [topo] | original L17635-L18826
-- L17652
-- send_period = 86400,
-- send_active_period = 3600,
-- <...>
-- L17902
-- add_value(gw_info, "2g_ssid", wifi_info["2g_ssid"], "")
-- <...>
-- L17915
-- add_value(gw_info, "pppoe", pppoe.pppoe, "")
-- add_value(gw_info, "loid", poninfo.loid, "")
-- <...>
-- L17918
-- add_value(gw_info, "wan_ip", netinfo.wan_ip, "")
-- <...>

-- [tuple] | original L18828-L19001
-- L18844
-- period = 5,
-- L18847
-- help = "get tuple from kernel, send to server"
-- <...>

-- [upgrade] | original L19003-L19111
-- L19012
-- help = "upgrade for plugin/lua/sig",
-- <...>

-- [upnp] | original L19113-L19235
-- L19125
-- help = "upnp find host",
-- <...>

-- [wandns] | original L19237-L19324
-- L19249
-- help = "get dns server info from capi and send to server",
-- L19251
-- period = 3600,
-- L19252
-- send_period = 86400,
-- <...>

-- [wanstats] | original L19326-L19530
package.preload[ "wanstats" ] = assert( (loadstring or load)(
"\
local actor = require(\"luactor\") \
local cjson = require(\"cjson\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local cct = require(\"c.ct\") \
local timer = require(\"timer\")\
\
\
local wanstats = {\
    type = \"wan_stats\",\
    subtype = \"wan_stats\",  -- for timer use\
    help = \"get wanstats from capi, send to server\",\
\
    timer_name = \"wan_stats_get\",\
\
    upload_mode = \"svrdata\", -- \"none\", \"svrdata\", \"operdata\", \"all\"\
\
    wans = {},\
    lasttime_get = 0,\
\
    period = 0,\
    all_count = 0,\
    all_len = 0,\
    data_uploaded = {}, \
\
    stats = {},\
}\
\
local function wans_get()\
    local allwans = cct.getwans()\
    local wans = {}\
\
    if allwans == nil then\
        return nil\
    end\
\
    for index, v in pairs(allwans) do\
        assert(v.userdata)\
        local wan = cct.showwan(v.userdata)\
        if wan then\
            if wan.rxbytes == nil or wan.txbytes == nil then\
                -- ignore, maybe api version doesn't support yet\
                return nil\
            end\
            if wan.servicelist:len() > 0 then \
                if wans[wan.servicelist] == nil then\
                    wans[wan.servicelist] = {}\
                end\
                table.insert(wans[wan.servicelist], wan)\
            end\
        end\
    end\
\
    return wans\
end\
\
local function wan_stats_init()\
    wanstats.wans = wans_get()\
    wanstats.lasttime_get = os.time()\
end\
\
local function get_last_stats(servicename, wanname)\
    local rx_bytes = -1 tx_bytes = -1\
\
    if wanstats.wans and wanstats.wans[servicename] then\
        for _, wan in ipairs(wanstats.wans[servicename]) do\
            if wan.wanname == wanname then\
                rx_bytes = wan.rxbytes\
                tx_bytes = wan.txbytes\
                break\
            end\
        end\
    end\
\
    return rx_bytes, tx_bytes\
end\
\
local function wan_stats_get()\
    local now = os.time()\
    local wans = wans_get()\
    local upload_stats = {}\
\
    if wans == nil then\
        return\
    end\
\
    for servicename, wantab in pairs(wans) do\
        local rx_bytes_total = 0 tx_bytes_total = 0\
\
        for _, wan in ipairs(wantab) do\
            local rx_bytes = 0 tx_bytes = 0\
            local rx_bytes_old, tx_bytes_old = get_last_stats(servicename, wan.wanname)\
\
            if rx_bytes_old >= 0 and tx_bytes_old >= 0 and wan.rxbytes >= 0 and wan.txbytes >= 0 then\
                if rx_bytes_old <= wan.rxbytes then\
                    rx_bytes = wan.rxbytes - rx_bytes_old\
                else\
                    rx_bytes = wan.rxbytes\
                end\
                if tx_bytes_old <= wan.txbytes then\
                    tx_bytes = wan.txbytes - tx_bytes_old\
                else\
                    tx_bytes = wan.txbytes\
                end \
\
                rx_bytes_total = rx_bytes_total + rx_bytes\
                tx_bytes_total = tx_bytes_total + tx_bytes\
            end\
        end\
\
        if wanstats.wans and wanstats.wans[servicename] then\
            wanstats.stats[servicename] = {rx_bytes = rx_bytes_total, tx_bytes = tx_bytes_total}\
        end\
    end\
    \
    for servicename, stat in pairs(wanstats.stats) do\
        local upload_stat = {}\
        upload_stat.wan_type = servicename\
        upload_stat.rx_bytes = tostring(stat.rx_bytes)\
        upload_stat.tx_bytes = tostring(stat.tx_bytes)\
        table.insert(upload_stats, upload_stat)\
    end\
\
    if #upload_stats > 0 then\
        wanstats.data_uploaded = { type = \"wan_stats\", data = upload_stats, period = wanstats.period, timestamp = tostring(now) }\
\
        if wanstats.upload_mode ~= \"none\" then\
\
            if wanstats.upload_mode == \"operdata\" or wanstats.upload_mode  == \"all\" then\
                lcmd_run({subtype = \"__oper_data\", action = \"add\", data = wanstats.data_uploaded})\
            end\
\
            if wanstats.upload_mode == \"svrdata\" or wanstats.upload_mode == \"all\" then\
                lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = wanstats.data_uploaded})\
            end\
\
            wanstats.all_count = wanstats.all_count + 1\
            wanstats.all_len = wanstats.all_len + string.len(cjson.encode(wanstats.data_uploaded))\
        end\
    end\
\
    wanstats.stats = {}\
    wanstats.wans = wans\
    wanstats.lasttime_get = now\
end\
\
local function wanstats_set_period(msg)\
    if msg.period and tonumber(msg.period) ~= wanstats.period then\
        wanstats.period = tonumber(msg.period)\
        timer.mod(wanstats.timer_name, wanstats.period, 0, wan_stats_get)\
        if wanstats.period > 0 then\
            wan_stats_init()\
        end\
    end\
end\
\
local function wanstats_set_upload_mode(msg)\
    if type(msg.upload_mode) == \"string\" and msg.upload_mode ~= wanstats.upload_mode then\
        if msg.upload_mode == \"none\" or msg.upload_mode == \"svrdata\" or msg.upload_mode == \"operdata\" or msg.upload_mode == \"all\" then\
            wanstats.upload_mode = msg.upload_mode\
        end\
    end\
end\
\
local function wanstats_show_history(msg)\
    local history = {}\
    history.time = os.date(\"%Y-%m-%d %H:%M:%S\", wanstats.lasttime_get)\
    history.wans = wanstats.wans\
    return history\
end\
\
local function wanstats_show_current(msg)\
    local current = {}\
    current.time = os.date(\"%Y-%m-%d %H:%M:%S\")\
    current.wans = wans_get()\
    return current\
end\
\
local function wanstats_show_lastupload(msg)\
    return wanstats.data_uploaded\
end\
\
local function wanstats_read_stat(msg)\
    return { period = wanstats.period,upload_mode = wanstats.upload_mode,all_count = wanstats.all_count,all_len = wanstats.all_len }\
end\
\
function wanstats.postinit()\
    timer.mod(wanstats.timer_name, wanstats.period, 0,wan_stats_get)\
end\
\
actor.action_set(wanstats.subtype, \"wanstats_set_upload_mode\", wanstats_set_upload_mode, [[set upload_mode to send wan flow msg]])\
actor.action_set(wanstats.subtype, \"wanstats_set_period\", wanstats_set_period, [[set period and addr to send wan flow msg,[period = number}]])\
actor.action_set(wanstats.subtype, \"wanstats_show_history\", wanstats_show_history, \"show wancollect msg last time\") \
actor.action_set(wanstats.subtype, \"wanstats_show_current\", wanstats_show_current, \"show wancollect msg current\") \
actor.action_set(wanstats.subtype, \"wanstats_show_lastupload\", wanstats_show_lastupload, \"show wancollect msg last upload\") \
actor.action_set(wanstats.subtype, \"wanstats_read_stat\", wanstats_read_stat, \"read wancollect period, all_count and all_len\") \
actor.action_set(wanstats.subtype, \"read\", function () return {period = wanstats.period,upload_mode = wanstats.upload_mode} end, \"read wancollect period and upload_mode\")\
actor.action_set(wanstats.subtype, \"stat\", function () return {all_count = wanstats.all_count,all_len = wanstats.all_len} end, \"read wancollect all_count and all_len\")\
\
return wanstats\
\
"
, '@'.."./service/wanstats.lua" ) )

