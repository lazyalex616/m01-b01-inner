do

package.preload[ "appctrl" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local ctime = require(\"c.time\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local myutil = require(\"myutil\")\
local policy_com = require(\"ct.policy\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local pktpolicy = require(\"pktpolicy\")\
local is_numeric = policy_com.is_numeric\
\
local appctrl = {\
    subtype = \"appctrl\",\
    timer_name = 'appctrl_upload',\
    help = \"set appctrl and send info to server\",\
    pcnt = 0,\
    max_pcnt = 20,\
    max_appid_cnt = 100,\
    addr = \"message.189cube.com:9890\",\
    policies = { -- index\
        -- index, string\
        -- mac\
        -- appid, appid list\
        -- once\
        -- scnt\
        -- time\
            -- {weekdays = \"1,2,3,4,5\", time = \"00:00-19:00,21:00-24:00\"}\
        -- action_type, string \"0xff12\"\
        -- times\
            -- {weekdays = {[1] = true, [2] = true}, time = {{start_hour = 0, end_hour = 0}}, windex = 0, tindex = 0, lasttime = 0}\
    },\
    all_len = 0,\
    all_cnt = 0,\
    disable = {}, -- policy index, when hit and once is true, {\"1\" = true, \"2\" = true}\
}\
\
local function appconf_del(msg)\
    local indexes = msg.index or {}\
    if type(indexes) ~= \"table\" then\
        return {msg = \"invalid index\"}\
    end\
    local _, err_info = lcmd_run({subtype = \"pktpolicy\", action = \"del\", index = indexes, ftype = appctrl.subtype})\
    if err_info then return err_info end\
    for _, index in pairs(indexes) do\
        if appctrl.policies[index] and is_numeric(index) then\
            appctrl.policies[index] = nil\
            appctrl.pcnt = appctrl.pcnt - 1\
        else\
            log.warn(\"No such index to delete\")\
        end\
    end\
end\
\
local function appconf_add(t)\
    local msg, need_save = nil, false\
    if type(t.policies) ~= \"table\" then\
        log.error(\"must add table for appctrl conf\")\
        return\
    end\
    for _, policy in pairs(t.policies) do\
        local once, index, push_period = true, policy.index, 0\
        if not is_numeric(index) then\
            log.warn(index .. \"(index) not is effective string\")\
            return {err = \"invalid index type\"}\
        end\
        if not is_numeric(policy.action_type) then\
            return {err = \"invalid action_type\"}\
        end\
\
        if not pktpolicy.check_index(index, appctrl.subtype) then\
            return {err = \"index is used in other policy\"}\
        end\
\
        if not appctrl.policies[index] and appctrl.pcnt >= appctrl.max_pcnt then\
            return {err = \"can not exceed the limit count \"..tostring(appctrl.max_pcnt)}\
        end\
\
        local appid = policy.appid or {}\
        if type(appid) ~= \"table\"  then return end\
        if #appid <= 0 or #appid > appctrl.max_appid_cnt then return end\
\
        if type(policy.once) == \"boolean\" then once = policy.once end\
        -- default 0 seconds\
        if type(policy.push_period) == \"number\" and policy.push_period > 0 then push_period = policy.push_period end\
\
        local s = {\
            index = index,\
            appid = appid,\
            mac = policy.mac or \"\",\
            time = policy.time or {weekdays = \"1,2,3,4,5,6,7\", time = \"00:00-24:00\"},\
            once = once,\
            scnt = 0,\
            push_period = push_period,\
            action_type = policy.action_type,\
        }\
\
        local ok, times = policy_com.parse_time(s.time)\
        if not ok then\
            return {err = \"time parse failed!\"}\
        end\
        need_save = true\
        appconf_del({index = {index}})\
        s.times = times\
        -- count ++\
        appctrl.pcnt = appctrl.pcnt + 1\
        appctrl.policies[index] = s\
        _, msg = lcmd_run({\
            subtype = \"pktpolicy\",\
            action = \"add\",\
            policies = {\
                {\
                    index = policy.index,\
                    appid = policy.appid,\
                    mac = policy.mac,\
                    time = policy.time,\
                    action = policy.action,\
                    dscp_value = policy.dscp_value,\
                    ip_port = policy.ip_port,\
                    ports = policy.ports,\
                    direct = policy.direct,\
                    type = appctrl.subtype,\
                }\
            }\
        })\
    end\
    if need_save then\
        lcmd_run {type = \"sys\", action = \"save_conf_change\"}\
    end\
    return msg or {msg = \"add success\"}\
end\
\
local function stat()\
    local res = {}\
    for k, v in pairs(appctrl.policies) do\
        res[k] = {\
            index = v.index,\
            appid = v.appid,\
            mac = v.mac,\
            time = v.time,\
            -- times = v.times,            -- time after parsing\
            once = v.once,\
            push_period = v.push_period,\
            action_type = v.action_type,\
        }\
    end\
    return res\
end\
\
local function app_getinfo(one, mac, appid, date, wday, timenum)\
    -- check mac\
    if type(one) ~= \"table\" or (one.mac ~= \"\" and one.mac ~= mac) then\
        return\
    end\
    -- check appid\
    if not myutil.inarr(appid, one.appid) then\
        return\
    end\
    local ok, tindex = policy_com.check_time(date, wday, one.times)\
    if not ok then\
        return\
    end\
    local conf = one.times\
    -- 周或时间段有更新需要上报\
    if wday ~= conf.windex or tindex ~= conf.tindex then\
        conf.windex, conf.tindex, conf.lasttime = wday, tindex, timenum\
        return true\
    elseif timenum and (conf.lasttime + one.push_period <= timenum) then\
        conf.lasttime = timenum\
        return true\
    end\
end\
\
local function appctrl_get(msg)\
    if type(msg) ~= \"table\" or type(msg.data) ~= \"table\" then\
        return\
    end\
    local index = msg.data.index\
    local one = appctrl.policies[index]\
\
    if not index or not one then\
        return\
    end\
\
    if one.once and one.scnt > 0 then\
        return\
    end\
\
    local data = {}\
    for key, value in pairs(msg.data) do\
        data[key] = value\
    end\
    local date, wday = policy_com.date_fmt()\
    local macstr, appid, timenum = myip.mac_fmt(data.mac), data.appid, tonumber(data.time)\
    local ok = app_getinfo(one, macstr, appid, date, wday, timenum)\
    if ok then\
        local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
        local osid, dev_name = 0, \"\"\
        if oss[data.mac] then\
            osid, dev_name = oss[data.mac].decide_osid or oss[data.mac].cloud_osid or 0, oss[data.mac].devname or \"\"\
        end\
        if one.once then\
            appctrl.disable[tostring(index)] = true\
        end\
        one.scnt = one.scnt + 1\
        data.type, data.osid, data.dev_name = appctrl.subtype, osid, dev_name\
        data.value, data.action_type = data.dscp_value or 0, one.action_type\
        data.push_period = one.push_period\
\
        local one_len = policy_com.send_uniform(\"appctrl\", appctrl.addr, data.action_type, {data})\
        appctrl.all_len = appctrl.all_len + one_len\
        appctrl.all_cnt = appctrl.all_cnt + 1\
    end\
end\
\
local function write(t)\
    if type(t.addr) == \"string\" and t.addr ~= appctrl.addr then\
        appctrl.addr = t.addr\
    end\
    if type(t.policies) == \"table\" then\
        local add_format = {policies = t.policies}\
        appconf_add(add_format)\
    end\
end\
\
local function read()\
    return {\
        addr = appctrl.addr,\
        stat = {\
            pcnt = appctrl.pcnt,\
            max_pcnt = appctrl.max_pcnt,\
            max_appid_cnt = appctrl.max_appid_cnt,\
            all_len = appctrl.all_len,\
            all_cnt = appctrl.all_cnt,\
        },\
    }\
end\
\
local function appconf_clean()\
    if not next(appctrl.disable) then\
        return\
    end\
    for index, _ in pairs(appctrl.disable) do\
        appconf_del({index = {index}})\
    end\
    appctrl.disable = {}\
end\
\
function appctrl.postinit()\
    appctrl.index = actor.subscribe(\"PKTPOLICY\", appctrl_get)\
    timer.mod(\"appctrl_policy_clean\", 60, 0, appconf_clean)\
end\
\
function appctrl.finish()\
    if appctrl.index then actor.unsubscribe(\"PKTPOLICY\", appctrl.index) end\
end\
\
actor.action_set(appctrl.subtype, \"write\", write, [[configure appctrl, {addr = string, policies = list}]])\
actor.action_set(appctrl.subtype, \"read\", read, \"{addr, stat = {pcnt, max_pcnt, max_appid_cnt, all_len, all_cnt}}\")\
actor.action_set(appctrl.subtype, \"add\", appconf_add, \"policies = {{index = string, appid = list, mac = string, time = list, once = boolean, push_period = number, action_type = string, action = continue/fin/drop, dscp_value = number, ip_port = list, ports = list, direct = string}}\")\
actor.action_set(appctrl.subtype, \"del\", appconf_del, [[del policy, {index = [\"1\",\"2\"...]}]])\
actor.action_set(appctrl.subtype, \"stat\", stat, \"{index = string, appid = list, mac = string, time = list, once = boolean, push_period = number, action_type = string}\")\
actor.action_set(appctrl.subtype, \"flush\", function () for index, _ in pairs(appctrl.policies) do appconf_del({index = {index}}) end end, \"appctrl conf flush\")\
actor.action_set(appctrl.subtype, \"show_conf_save\", function () return {subtype = appctrl.subtype, action = \"write\", policies = appctrl.policies, addr = appctrl.addr} end, \"show appctrl save conf msg\")\
\
return appctrl\
"
, '@'.."./service/appctrl.lua" ) )

package.preload[ "appinfo" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local cjson = require(\"cjson\")\
local timer = require(\"timer\")\
local log = require(\"log\")\
local mystring = require(\"mystring\")\
local myutil = require(\"myutil\")\
local dpi = require\"svrcomm.dpi\"\
local pb = require\"pb\"\
\
local appinfo = { \
    subtype = \"appinfo\",\
    period = 1800,\
    help = \"send appinfo to server\",\
    timer_name = \"appsig_send\",\
    payload_tname = \"app_payload_send\",\
    appinfo_tname = \"appinfo_send\",\
    coll_mode = \"normal\",  --\"normal\",\"all\"\
    payload_send_period = 7200,\
    appinfo_send_period = 86400,\
    enable = true,\
    max_ip_sig_cnt = 100,\
    max_sig_cnt = 1024,\
    max_appid_cnt = 100,\
    max_base_appid = 2000,\
    payload_max_cnt = 10,\
    payload_cnt = 0,\
    sigs = {\
        -- sig\
            -- type\
            -- time\
            -- hit_cnt\
            -- send\
    },\
    payload = {\
        -- payload & len < 1k\
    },\
    ruleids = {\
        -- ruleid_appid_dip_dport_mac\
            -- time\
    },\
    ip_sig_cnt = 0,\
    sig_cnt = 0,\
    ruleid_cnt = 0,\
    all_count = 0,\
    sig_send_cnt = 0,\
    ruleid_send_cnt = 0,\
    all_len = 0,\
    sig_send_len = 0,\
    ruleid_send_len = 0,\
    addr = {\"xapp.189cube.com:7872:7871\"},\
    rules = {},\
    pstat = {}\
}\
\
local function sig_deal(addr, action, msg)\
    local ok, array = pcall(pb.decode, \".plugin.ServerMsgs\", msg)\
    if not ok then\
        log.error(\"service for protobuf err\", msg)\
        return\
    end\
\
    for _,sdata in pairs(array.data) do\
        local ok, tt = pcall(pb.decode, \".plugin.CommonHdr\", sdata)\
        local pbin, pbout, pbytes = \"\", \"\", nil\
        if not ok then\
            log.error(\"no type action for protobuf \", sdata)\
            return\
        end\
\
        pbin, pbout = actor.pb_inout(tt.type, tt.action)\
        if not pbin then\
            log.error(\"no such pbin pbout for \", tt.type, tt.action)\
            return\
        end\
\
        local ok, srctt = pcall(pb.decode, pbin, sdata)\
        if not ok then\
            log.error(\"failed to decode pbin \", pbin)\
            return\
        end\
        local ok, result = lcmd_run(srctt)\
        if ok and type(result) == \"table\" and pbout then\
            ok, pbytes = pcall(pb.encode, pbout, result)\
            if not ok then\
                log.error(\"failed to encode pbout \", pbin, pbytes, cjson.encode(result))\
                return\
            end\
            return pbytes\
        end\
    end\
\
end\
\
local function sigs_clean()\
    if appinfo.max_sig_cnt <= 0 then\
        appinfo.sigs = {}\
        return\
    end\
\
    local now, sigs = os.time(), {}\
\
    for k,v in pairs (appinfo.sigs) do\
        if now - v.time > 86400 then\
            if v.type == \"diport\" then\
                appinfo.ip_sig_cnt = appinfo.ip_sig_cnt - 1\
            end\
            appinfo.sigs[k] = nil\
            appinfo.sig_cnt = appinfo.sig_cnt - 1\
        else\
            table.insert(sigs, {key = k, time = v.time, stype = v.type})\
        end\
    end\
    table.sort(sigs, function(t1, t2) return t1.time < t2.time end)\
\
    local num = #sigs - appinfo.max_sig_cnt\
    if num > 0 then\
        for i=1,num do\
            local key = sigs[i].key\
            if sigs[i].stype == \"diport\" then\
                appinfo.ip_sig_cnt = appinfo.ip_sig_cnt - 1\
            end\
            appinfo.sigs[key] = nil\
            appinfo.sig_cnt = appinfo.sig_cnt - 1\
        end\
    end\
end\
\
local function update_info(t)\
    -- check value\
    if myip.is_localip(t.dip) or (t.stype ~= \"diport\" and myip.is_ipstring(t.value)) then\
        return\
    end\
\
    local time = os.time() or 0\
    -- 未识别\
    if not t.appid or t.appid <= appinfo.max_base_appid then\
        local key = t.value or \"\"\
\
        if appinfo.sigs[key] then\
            local info = appinfo.sigs[key]\
            info.hit_cnt = info.hit_cnt + 1\
        elseif appinfo.sig_cnt < appinfo.max_sig_cnt * 2 then\
            if t.stype == \"diport\" and appinfo.ip_sig_cnt >= appinfo.max_ip_sig_cnt then\
                return\
            end\
\
            appinfo.sigs[key] = {type = t.stype, mac = t.mac, dip = t.dip, dport = t.dport,  time = time, hit_cnt = 1, send = false}\
            appinfo.sig_cnt = appinfo.sig_cnt + 1\
            if t.stype == \"diport\" then\
                appinfo.ip_sig_cnt = appinfo.ip_sig_cnt + 1\
            end\
        end\
    -- 已识别\
    elseif t.stype == \"diport\" then\
        local key = string.format(\"%d_%d_%s_%d_%s\", t.ruleid or 0, t.appid or 0, t.dip or \"\", t.dport or 0, t.mac or \"\")\
        if not appinfo.ruleids[key] and appinfo.ruleid_cnt < appinfo.max_appid_cnt then\
            appinfo.ruleids[key] = time\
            appinfo.ruleid_cnt = appinfo.ruleid_cnt + 1\
        end\
    end\
end\
\
local function match_one(t)\
    if not t.stype or not t[t.stype]then\
        return\
    end\
    local rename = {dns = \"domain\", host = \"domain\", sni = \"domain\"}\
\
    local ruleid, appid, appdesc = nil, nil, {}\
    if not t.appid or t.appid <= appinfo.max_base_appid then\
        local stype = rename[t.stype] or t.stype\
        _, ruleid = lcmd_run({subtype = \"appsig_bin\", action = \"match\", stype = stype, value = t[t.stype]})\
        if ruleid then\
           _, appdesc = lcmd_run({subtype = \"appsig_bin\", action = \"get_desc\", ruleid = ruleid})\
           appid = appdesc.appid or 0\
           local key = (t.dip or \"\") .. \"_\" .. (t.dport or 0)\
           -- kernel read need timer to write\
           if t.stype == \"dns\" then\
                lcmd_run({subtype = \"apprule\", action = \"add\", ruleid = ruleid, appid = appid, ip = t.dip, port = t.dport})\
           else\
                appinfo.rules[key] = {subtype = \"apprule\", action = \"add\", ruleid = ruleid, appid = appid, ip = t.dip, port = t.dport}\
           end\
           appinfo.pstat[t.stype..\"_mcnt\"] = (appinfo.pstat[t.stype..\"_mcnt\"] or 0) + 1\
        end\
        appinfo.pstat[t.stype..\"_cnt\"] = (appinfo.pstat[t.stype..\"_cnt\"] or 0) + 1\
    end\
    update_info({ruleid = ruleid or t.ruleid, appid = appid or t.appid, dport = t.dport, dip = t.dip, stype = t.stype, value = t[t.stype], mac = t.mac})\
end\
\
local function pstat()\
    local rate = {}\
    local allmcnt, allcnt = 0, 0\
    for k, v in pairs(appinfo.pstat) do\
        local stype, _ = mystring.split(k,\"_\")\
        if not rate[stype] then\
            local mcnt = appinfo.pstat[stype..\"_mcnt\"] or 0\
            local cnt = appinfo.pstat[stype..\"_cnt\"] or 1\
            allmcnt = allmcnt + mcnt\
            allcnt = allcnt + cnt\
            rate[stype] = string.format(\"%d / %d = %.2f\",mcnt, cnt, mcnt/cnt*100)..\"%\"\
        end\
    end\
    rate[\"all\"] = string.format(\"%d / %d = %.2f\",allmcnt, allcnt, allmcnt/allcnt*100)..\"%\"\
    return rate\
end\
\
local function sstat()\
    local sigs_cnt = 0\
    for k,v in pairs (appinfo.sigs) do\
       sigs_cnt = sigs_cnt + 1\
    end\
    return {sigs_cnt =sigs_cnt, payload_cnt = appinfo.payload_cnt, ruleid_cnt = appinfo.ruleid_cnt}\
end\
\
local function deal_payloads(cnt)\
    local data, number = {}, 0\
    for k,v in pairs(appinfo.payload) do\
        table.insert(data, {sigvalue = v.data, sigtype = \"payload\", mac = v.mac, dip = v.ip, dport= v.port, appid = v.appid, ruleid = v.ruleid})\
    end\
    appinfo.payload = {}\
    appinfo.payload_cnt = 0\
    return data\
end\
\
local function deal_sigs(cnt)\
    local data, number = {}, 0\
    for k,v in pairs(appinfo.sigs) do\
        if not v.send then\
            v.send = true\
            table.insert(data, {sigvalue = tostring(k), sigtype = v.type, mac = v.mac, dip = v.dip or \"\", dport= v.dport or 0})\
        end\
    end\
    return data\
end\
\
\
local function appsigs_send(stype, cnt)\
    if appinfo.enable == false then\
        return\
    end\
    if stype ~= \"sigs\" and stype ~= \"payload\" then\
        return\
    end\
    local data, number = {}, 0\
    if stype == \"payload\" then\
        data = deal_payloads(cnt)\
    else\
        data = deal_sigs(cnt)\
    end\
\
    --log.error(\"#########\", cjson.encode(data))\
    if #data > 0 then\
        local info = {type = \"app_sig\", appsig = data}\
        local pbtype = actor.pbtype_get(info.type)\
        local pbsigs = pb.encode(pbtype, info)\
        for _,addr in pairs(appinfo.addr) do\
            dpi.pb_asyncall(addr, true, \"ACTION_SHORT_APP\", {pbsigs}, nil, sig_deal)\
        end\
        local len = string.len(cjson.encode(data))\
        appinfo.all_len = appinfo.all_len + len\
        appinfo.all_count = appinfo.all_count + 1\
        appinfo.ruleid_send_len = appinfo.ruleid_send_len + len\
        appinfo.ruleid_send_cnt = appinfo.ruleid_send_cnt + 1\
    end\
    if stype == \"payload\" then\
        appinfo.payload = {}\
    end\
end\
\
local function app_send()\
    if appinfo.enable == false then\
        return\
    end\
    local data = {}\
    for k,v in pairs(appinfo.ruleids) do\
        local ruleid, appid, dip, dport, mac = mystring.split(k, \"_\")\
        table.insert(data, {appid = tonumber(appid) or 0, ruleid = tonumber(ruleid) or 0, dip = dip or \"\", dport = tonumber(dport) or 0, mac = mac})\
    end\
    if #data > 0 then\
        local info = {type = \"app_info\", appinfo = data}\
        local pbtype = actor.pbtype_get(info.type)\
        local pbsiginfo = pb.encode(pbtype, info)\
        for _,addr in pairs(appinfo.addr) do\
            dpi.pb_asyncall(addr, true, \"ACTION_SHORT_APP\", {pbsiginfo})\
        end\
        local len = string.len(cjson.encode(data))\
        appinfo.all_len = appinfo.all_len + len\
        appinfo.all_count = appinfo.all_count + 1\
        appinfo.sig_send_len = appinfo.sig_send_len + len\
        appinfo.sig_send_cnt = appinfo.sig_send_cnt + 1\
    end\
    appinfo.ruleids = {}\
    appinfo.ruleid_cnt = 0\
end\
\
local function collect_dns(msg)\
    local info = msg.dnstable\
    for _, ip in pairs({mystring.split(msg.ips, \",\")}) do\
        match_one({stype = \"dns\", dip = ip, dns = info.domain, mac = info.mac})\
    end\
end\
\
local function collect_tuple(msg)\
    local info = msg.tuple_info\
    local diport = string.format(\"%s:%d\", info.dip or \"\", info.dport or 0)\
    match_one({stype = \"diport\", ruleid = info.ruleid, appid = info.appid, diport = diport, dport = info.dport, dip = info.dip, mac = info.mac})\
end\
\
local function collect_http(msg)\
    for _, info in pairs(msg.http_tables) do\
        local host = myutil.urlsplit(info.url)\
        match_one({stype = \"host\", ruleid = info.ruleid, appid = info.appid, host = host, dip = myip.inet_ntoa(info.dstip), dport = info.dport, mac = myip.mac_ntoa(info.mac)})\
    end\
end\
\
local function collect_https(msg)\
    local info = msg.https_table\
    match_one({stype = \"sni\", ruleid = info.ruleid, appid = info.appid, sni = info.domain, dip = info.dip, dport = info.dport, mac = info.mac})\
end\
\
local function collect_payload(info)\
        if info.data and #info.data > 16 then\
            local pkey = info.ip..\"_\"..info.port\
            if not appinfo.payload[pkey] then\
                appinfo.payload[pkey] = info\
                appinfo.payload[pkey].hit_cnt = 1\
                appinfo.payload_cnt = appinfo.payload_cnt + 1\
            else\
                appinfo.payload[pkey].hit_cnt = appinfo.payload[pkey].hit_cnt + 1\
            end\
        end\
end\
\
local function collect_apprule(msg)\
    local info = msg.apprule_table\
    if info.appid <= appinfo.max_base_appid and appinfo.payload_cnt < appinfo.payload_max_cnt then\
        collect_payload(info)\
    end\
end\
\
local function rule_set()\
    local rules = appinfo.rules\
    for _,v in pairs(rules) do\
        lcmd_run(v)\
    end\
    appinfo.rules = {}\
end\
\
local function appsig_update(t)\
    local simple, base = t.simple or {}, t.base or {}\
    if t.all and #simple > 0 then\
        lcmd_run({subtype = \"appsig_bin\", action = \"flush\"})    \
    end\
    if t.all and #base > 0 then\
        lcmd_run({subtype = \"appsig_bin\", action = \"base_flush\"})    \
    end\
    for k,v in pairs(simple) do\
        lcmd_run({subtype = \"appsig_bin\", action = \"add\", all = t.all, stype = v.sigtype, ruleid = v.ruleid, appid = v.appid, prio = v.prio or 0, value = v.sigvalue, name = v.name})\
    end\
    for k,v in pairs(base) do\
        lcmd_run({subtype = \"appsig_bin\", action = \"base_add\", all = t.all, stype = v.sigtype, ruleid = v.ruleid, appid = v.appid, prio = v.prio or 0, value = v.sigvalue, name = v.name})\
    end\
    if t.all then\
        lcmd_run({subtype = \"appsig_bin\", action = \"save\"})    \
    end\
end\
\
local function write(t)\
    if t.period and tonumber(t.period) ~= appinfo.period then\
        appinfo.period = tonumber(t.period)\
        timer.mod(appinfo.timer_name, appinfo.period, 0, appsigs_send, \"sigs\", appinfo.max_sig_cnt)\
    end\
    if t.payload_send_period and tonumber(t.payload_send_period) ~= appinfo.payload_send_period then\
        appinfo.payload_send_period = tonumber(t.payload_send_period)\
        timer.mod(appinfo.payload_tname, appinfo.payload_send_period, 0, appsigs_send, \"payload\", appinfo.payload_max_cnt)\
    end\
    if t.appinfo_send_period and tonumber(t.appinfo_send_period) ~= appinfo.appinfo_send_period then\
        appinfo.appinfo_send_period = tonumber(t.appinfo_send_period)\
        timer.mod(appinfo.appinfo_tname, appinfo.appinfo_send_period, 0, app_send)\
    end\
    if t.addr and type(t.addr) == \"table\" then\
        appinfo.addr = t.addr\
    end\
    if type(t.max_ip_sig_cnt) == \"number\" then\
        appinfo.max_ip_sig_cnt = t.max_ip_sig_cnt\
    end\
    if type(t.enable) == \"boolean\" and t.enable ~= appinfo.enable then\
        appinfo.enable = t.enable\
    end\
    if type(t.coll_mode) == \"string\" and t.coll_mode ~= appinfo.coll_mode then\
        if t.coll_mode == \"normal\" or t.coll_mode == \"all\" then\
            appinfo.coll_mode = t.coll_mode\
            if appinfo.coll_mode == \"all\" then\
                appinfo.payload_send_period, appinfo.period, appinfo.appinfo_send_period, appinfo.payload_max_cnt =10, 10, 10, 1024\
                timer.mod(appinfo.timer_name, appinfo.period, 0, appsigs_send, \"sigs\", appinfo.max_sig_cnt)\
                timer.mod(appinfo.payload_tname, appinfo.payload_send_period, 0, appsigs_send, \"payload\", appinfo.payload_max_cnt)\
                timer.mod(appinfo.appinfo_tname, appinfo.appinfo_send_period, 0, app_send)\
            else\
                appinfo.payload_send_period, appinfo.period, appinfo.appinfo_send_period, appinfo.payload_max_cnt =7200, 1800, 86400, 10\
                timer.mod(appinfo.timer_name, appinfo.period, 0, appsigs_send, \"sigs\", appinfo.max_sig_cnt)\
                timer.mod(appinfo.payload_tname, appinfo.payload_send_period, 0, appsigs_send, \"payload\", appinfo.payload_max_cnt)\
                timer.mod(appinfo.appinfo_tname, appinfo.appinfo_send_period, 0, app_send)\
            end\
        end\
        \
    end\
end\
\
function appinfo.postinit()\
    appinfo.dindex = actor.subscribe(\"DNS\", collect_dns)\
    appinfo.tindex = actor.subscribe(\"TUPLE\", collect_tuple)\
    appinfo.hindex = actor.subscribe(\"HTTP\", collect_http)\
    appinfo.hsindex = actor.subscribe(\"HTTPS\", collect_https)\
    appinfo.rindex = actor.subscribe(\"APPRULE\", collect_apprule)\
    timer.mod(\"appsigs_clean\", 300, 0, sigs_clean)\
    timer.mod(\"appsigs_set_rule\", 5, 0, rule_set)\
    timer.mod(appinfo.timer_name, appinfo.period, 0, appsigs_send, \"sigs\", appinfo.max_sig_cnt)\
    timer.mod(appinfo.payload_tname, appinfo.payload_send_period, 0, appsigs_send, \"payload\", appinfo.payload_max_cnt)\
    timer.mod(appinfo.appinfo_tname, appinfo.appinfo_send_period, 0, app_send)\
end\
\
function appinfo.finish()\
    if appinfo.dindex then\
        actor.unsubscribe(\"DNS\", appinfo.dindex)\
    end\
    if appinfo.tindex then\
        actor.unsubscribe(\"TUPLE\", appinfo.tindex)\
    end\
    if appinfo.hindex then\
        actor.unsubscribe(\"HTTP\", appinfo.hindex)\
    end\
    if appinfo.hsindex then\
        actor.unsubscribe(\"HTTPS\", appinfo.hsindex)\
    end\
    if appinfo.rindex then\
        actor.unsubscribe(\"APPRULE\", appinfo.rindex)\
    end\
end\
\
actor.pbtype_add(\"app_info\", \".plugin.APPInfoArr\")\
actor.pbtype_add(\"app_sig\", \".plugin.APPSigArr\")\
\
actor.action_set(appinfo.subtype, \"read\", function () return { period = appinfo.period, payload_send_period = appinfo.payload_send_period,  appinfo_send_period = appinfo.appinfo_send_period, addr = appinfo.addr, max_ip_sig_cnt = appinfo.max_ip_sig_cnt, payload_max_cnt = appinfo.payload_max_cnt, enable = appinfo.enable, coll_mode = appinfo.coll_mode} end, \"read appinfo conf\")\
actor.action_set(appinfo.subtype, \"write\", write, [[set appinfo conf, {period = number, addr = list, enable = boolean, coll_mode = normal/all}]])\
actor.action_set(appinfo.subtype,\"pstat\", pstat, \"read appsig recognition rate\")\
actor.action_set(appinfo.subtype,\"sstat\", sstat, \"read sigs/payload/ruleid count\")\
-- actor.action_set(appinfo.subtype, \"show\", function () return appinfo.rules end, [[read stat]])\
actor.action_set(appinfo.subtype, \"stat\", function () return {all_len = appinfo.all_len, all_count = appinfo.all_count, sig_send_len = appinfo.sig_send_len, sig_send_cnt = appinfo.sig_send_cnt, ruleid_send_cnt = appinfo.ruleid_send_cnt, ruleid_send_len = appinfo.ruleid_send_len} end, [[read stat]])\
actor.action_set(appinfo.subtype, \"appsig_update\", appsig_update, [[{all=boolean,app_sig={{ruleid=number,appid=number,prio=number,sig_type=string,name=string,value=string}}}]], \".plugin.APPSigRes\")\
\
return appinfo\
"
, '@'.."./service/appinfo.lua" ) )

package.preload[ "appmlp" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local myutil = require(\"myutil\")\
local policy_com = require(\"ct.policy\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local pktpolicy = require(\"pktpolicy\")\
local actint = policy_com.actint\
local is_numeric = policy_com.is_numeric\
\
local appmlp = {\
    subtype = \"appmlp\",\
    timer_name = \"appmlp_upload\",\
    help = \"set appmlp and real time send info to server\",\
    pcnt = 0,\
    max_pcnt = 20,\
    max_appid_cnt = 100,\
    period = 1800,\
    action_type = \"0xff12\",\
    addr = \"message.189cube.com:9890\",\
    policies = { -- index(string) as keyword\
        -- {\
            -- index, string\
            -- appid, appid list\
            -- mac\
            -- action, continue/fin/drop/dscp\
            -- dscp_value, dscp policies 1-36 are valid when the action is dscp\
\
            -- time\
            -- {weekdays = \"1,2,3,4,5\", time = \"00:00-19:00,21:00-24:00\"}\
\
            -- times\
            -- {weekdays ={[1]=true, [2] = true}, time = {{start_hour = 0, end_hour = 0}}, windex = 0, tindex = 0, lasttime = 0}\
        -- }\
    },\
    cache = {},\
    cache_cnt = 0,\
    max_cache_cnt = 100,\
    real_time = false,\
    all_len = 0,\
    all_cnt = 0,\
}\
\
local function appconf_del(msg)\
    local indexes = msg.index or {}\
    if type(indexes) ~= \"table\" then\
        return {msg = \"invalid index\"}\
    end\
    local _, err_info = lcmd_run({subtype = \"pktpolicy\", action = \"del\", index = indexes, ftype = appmlp.subtype})\
    if err_info then return err_info end\
    for _, index in pairs(indexes) do\
        if appmlp.policies[index] and is_numeric(index) then\
            appmlp.policies[index] = nil\
            appmlp.pcnt = appmlp.pcnt - 1\
        else\
            log.warn(\"No such index to delete\")\
        end\
    end\
end\
\
local function appconf_add(t)\
    local msg, need_save = nil, false\
    if type(t.policies) ~= \"table\" then\
        log.error(\"must add table for appmlp conf\")\
        return\
    end\
    for _, policy in pairs(t.policies) do\
        local index = policy.index\
        if not is_numeric(index) then\
            log.warn(index .. \"(index) not is effective string\")\
            return {err = \"invalid index type\"}\
        end\
        if not pktpolicy.check_index(index, appmlp.subtype) then\
            return {err = \"index is used in other policy\"}\
        end\
        if not appmlp.policies[index] and appmlp.pcnt >= appmlp.max_pcnt then\
            return {err = \"can not exceed the limit count \"..tostring(appmlp.max_pcnt)}\
        end\
\
        local appid = policy.appid or {}\
        if type(appid) ~= \"table\"  then return end\
        if #appid <= 0 or #appid > appmlp.max_appid_cnt then return end\
\
        local action, dscp_value = policy.action, nil\
        if action == \"dscp\" and type(policy.dscp_value) ~= \"number\" then\
            log.warn(\"set dscp need dscp_value\")\
            return\
        end\
        if action == \"dscp\" then dscp_value = policy.dscp_value end\
        if not action or not actint[action] then return end\
\
        local s = {\
            index = index,\
            appid = appid,\
            mac = policy.mac or \"\",\
            time = policy.time or {weekdays = \"1,2,3,4,5,6,7\", time = \"00:00-24:00\"},\
            action = action,\
            dscp_value = dscp_value,\
        }\
\
        local ok, times = policy_com.parse_time(s.time)\
        if not ok then\
            return {err = \"time parse failed!\"}\
        end\
        need_save = true\
        appconf_del({index = {index}})\
        s.times = times\
        -- count ++\
        appmlp.pcnt = appmlp.pcnt + 1\
        appmlp.policies[index] = s\
        _, msg = lcmd_run({\
            subtype = \"pktpolicy\",\
            action = \"add\",\
            policies = {\
                {\
                    index = policy.index,\
                    appid = policy.appid,\
                    mac = policy.mac,\
                    time = policy.time,\
                    action = policy.action,\
                    dscp_value = policy.dscp_value,\
                    ip_port = policy.ip_port,\
                    ports = policy.ports,\
                    direct = policy.direct,\
                    type = appmlp.subtype,\
                }\
            }\
        })\
    end\
    if need_save then\
        lcmd_run {type = \"sys\", action = \"save_conf_change\"}\
    end\
    return msg or {msg = \"add success\"}\
end\
\
local function stat()\
    local res = {}\
    for k, v in pairs(appmlp.policies) do\
        res[k] = {\
            index = v.index,\
            appid = v.appid,\
            mac = v.mac,\
            time = v.time,\
            -- times = v.times,            -- time after parsing\
            action = v.action,\
            dscp_value = v.dscp_value,\
        }\
    end\
    return res\
end\
\
local function all_send()\
    local one_len = policy_com.send_uniform(\"appmlp\", appmlp.addr, appmlp.action_type, appmlp.cache)\
    appmlp.cache = {}\
    appmlp.cache_cnt = 0\
    appmlp.all_len = appmlp.all_len + one_len\
    appmlp.all_cnt = appmlp.all_cnt + 1\
end\
\
local function upload(data)\
    -- real-time upload\
    if appmlp.real_time then\
        local one_len = policy_com.send_uniform(\"appmlp\", appmlp.addr, appmlp.action_type, {data})\
        appmlp.all_len = appmlp.all_len + one_len\
        appmlp.all_cnt = appmlp.all_cnt + 1\
        return\
    end\
    -- save data, cyclic upload\
    table.insert(appmlp.cache, data)\
    appmlp.cache_cnt = appmlp.cache_cnt + 1\
    -- if full\
    if appmlp.cache_cnt >= appmlp.max_cache_cnt then\
        all_send()\
        -- update timer\
        timer.mod(appmlp.timer_name, appmlp.period, 0, all_send)\
    end\
end\
\
local function app_getinfo(one, mac, appid, date, wday, timenum)\
    -- check mac\
    if type(one) ~= \"table\" or (one.mac ~= \"\" and one.mac ~= mac) then\
        return\
    end\
    -- check appid\
    if not myutil.inarr(appid, one.appid) then\
        return\
    end\
    local ok, tindex = policy_com.check_time(date, wday, one.times)\
    if not ok then\
        return\
    end\
    local conf = one.times\
    -- 周或时间段有更新需要上报\
    if wday ~= conf.windex or tindex ~= conf.tindex then\
        conf.windex, conf.tindex, conf.lasttime = wday, tindex, timenum\
        return true\
    elseif timenum then\
        conf.lasttime = timenum\
        return true\
    end\
end\
\
local function appmlp_get(msg)\
    if type(msg) ~= \"table\" or type(msg.data) ~= \"table\" then\
        return\
    end\
    local index = msg.data.index\
    local one = appmlp.policies[index]\
    -- close upload when period <= 0\
    if appmlp.period <=0 or not index or not one then\
        return\
    end\
\
    local data = {}\
    for key, value in pairs(msg.data) do\
        data[key] = value\
    end\
    local date, wday = policy_com.date_fmt()\
    local macstr, appid, timenum = myip.mac_fmt(data.mac), data.appid, tonumber(data.time)\
    local ok = app_getinfo(one, macstr, appid, date, wday, timenum)\
    if ok then\
        local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
        local _, appdesc = lcmd_run({subtype = \"appsig_bin\", action = \"get_desc\", ruleid = data.ruleid})\
        local osid, dev_name, host = 0, \"\", \"\"\
        if oss[data.mac] then\
            osid, dev_name = oss[data.mac].decide_osid or oss[data.mac].cloud_osid or 0, oss[data.mac].devname or \"\"\
        end\
        if appdesc then\
            host = appdesc.value or \"\"\
        end\
        data.type, data.osid, data.dev_name, data.host = appmlp.subtype, osid, dev_name, host\
\
        upload(data)\
    end\
end\
\
local function write(t)\
    if type(t.addr) == \"string\" and t.addr ~= appmlp.addr then\
        appmlp.addr = t.addr\
    end\
    if is_numeric(t.action_type) and t.action_type ~= appmlp.action_type then\
        appmlp.action_type = t.action_type\
    end\
    if type(t.period) == \"number\" and t.period ~= appmlp.period then\
        appmlp.period = t.period\
        timer.mod(appmlp.timer_name, appmlp.period, 0, all_send)\
    end\
    if type(t.real_time) == \"boolean\" and t.real_time ~= appmlp.real_time then\
        appmlp.real_time = t.real_time\
        if appmlp.real_time then\
            all_send()\
        else\
            timer.mod(appmlp.timer_name, appmlp.period, 0, all_send)\
        end\
    end\
    if type(t.policies) == \"table\" then\
        local add_format = {policies = t.policies}\
        appconf_add(add_format)\
    end\
end\
\
local function read()\
    return {\
        addr = appmlp.addr,\
        action_type = appmlp.action_type,\
        period = appmlp.period,\
        real_time = appmlp.real_time,\
        stat = {\
            pcnt = appmlp.pcnt,\
            max_pcnt = appmlp.max_pcnt,\
            max_appid_cnt = appmlp.max_appid_cnt,\
            all_len = appmlp.all_len,\
            all_cnt = appmlp.all_cnt,\
            cache_cnt = appmlp.cache_cnt,\
            max_cache_cnt = appmlp.max_cache_cnt,\
        },\
    }\
end\
\
function appmlp.postinit()\
    appmlp.index = actor.subscribe(\"PKTPOLICY\", appmlp_get)\
    timer.mod(appmlp.timer_name, appmlp.period, 0, all_send)\
end\
\
function appmlp.finish()\
    if appmlp.index then actor.unsubscribe(\"PKTPOLICY\", appmlp.index) end\
end\
\
actor.action_set(appmlp.subtype, \"write\", write, [[configure appmlp, {action_type = string, addr = string, period = number, policies = list, real_time = boolean}]])\
actor.action_set(appmlp.subtype, \"read\", read, \"{addr, action_type, period, real_time, stat = {pcnt, max_pcnt, max_appid_cnt, all_len, all_cnt, cache_cnt, max_cache_cnt}}\")\
actor.action_set(appmlp.subtype, \"add\", appconf_add, [[{policies = [{index = string, appid = list, mac = string, time = list, action = continue/fin/drop/dscp, dscp_value = number, ip_port = list, ports = list, direct = string}]}]])\
actor.action_set(appmlp.subtype, \"del\", appconf_del, [[del policy, {index = [\"1\",\"2\"...]}]])\
actor.action_set(appmlp.subtype, \"stat\", stat, \"{index:{index:string, appid:list, mac:string, time:list, action:continue/fin/drop/dscp, dscp_value:number}}\")\
actor.action_set(appmlp.subtype, \"flush\", function() for index, _ in pairs(appmlp.policies) do appconf_del({index = {index}}) end end, \"appmlp conf flush\")\
actor.action_set(appmlp.subtype, \"show_conf_save\", function () return {subtype = appmlp.subtype, action = \"write\", policies = appmlp.policies, addr = appmlp.addr, action_type = appmlp.action_type} end, \"show appmlp save conf msg\")\
\
return appmlp\
"
, '@'.."./service/appmlp.lua" ) )

package.preload[ "apprule" ] = assert( (loadstring or load)(
"local actor = require \"luactor\"\
local cjson = require \"cjson\"\
local log = require\"log\"\
local myip = require\"myip\"\
local mystring = require\"mystring\"\
local kernel = require\"c.kernel\"\
local timer = require\"timer\"\
local mime = require\"mime\"\
\
local apprule = {\
    type = \"apprule\",\
    subtype = \"apprule\",\
    help = \"app rule configure\",\
    period = 5,\
    timer_name = \"apprule_get\",\
    max_rule_cnt = 10000,\
    rule_clean_cnt = 1000,\
    rules = {\
        -- dip:dport\
            -- appid\
            -- ruleid\
            -- hit_cnt\
    },\
    rule_cnt = 0,\
    index = 0,\
}\
\
local function kernel_send(ktype, rule)\
    local ip, port, appid, ruleid = rule.ip, rule.port or 0, rule.appid, rule.ruleid\
    local port_mask = 0\
\
    if port ~= 0 then\
        port_mask = 0xffff\
    end\
    local buf = string.pack(\"=IIIc4HH\", 20, ruleid, appid, ip, port, port_mask)\
    kernel.send(ktype, buf)\
end\
\
local function del(t)\
    local key, ruleid = t.key, t.ruleid\
    local keys = {}\
    if key and apprule.rules[key] then\
        keys = {key}\
        apprule.rules[key] = nil\
    elseif ruleid then\
        for k,v in pairs(apprule.rules) do\
            if v.ruleid == ruleid then\
                apprule.rules[k] = nil\
                table.insert(keys, k)\
            end\
        end\
    end\
    for _,v in pairs(keys) do\
        apprule.rule_cnt = apprule.rule_cnt - 1 \
        local ip, port = mystring.split(v, \":\")\
        kernel_send(CENUM.MEMSHR_APP_RULE_DEL, {ip = myip.inet_aton(ip), port = tonumber(port or 0), appid = 0, ruleid = 0})\
    end\
    return\
end\
\
local function clean_rules()\
    local info = {}\
    for k,v in pairs(apprule.rules) do\
        table.insert(info, {hit_cnt = v.hit_cnt, key = k})\
    end\
    table.sort(info, function (t1,t2) return t1.hit_cnt < t2.hit_cnt end)\
    for i=1,apprule.rule_clean_cnt do\
        if info[i] then\
            local key = info[i].key\
            del({key = key})\
        end\
    end\
end\
\
local function add(t)\
    local ip, port, ruleid, appid = t.ip or \"0.0.0.0\", t.port or 0, t.ruleid or 0, t.appid or 0\
    local key = string.format(\"%s:%d\", ip, port)\
    local rule = apprule.rules[key]\
    if rule then\
        if rule.ruleid ~= ruleid or rule.appid ~= appid then\
            del({key = key})\
        else\
            return\
        end\
    else\
        if apprule.rule_cnt >= apprule.max_rule_cnt then\
            clean_rules()\
        end\
    end\
    apprule.rules[key] = {ruleid = ruleid, appid = appid, hit_cnt = 0}\
    apprule.rule_cnt = apprule.rule_cnt + 1 \
    kernel_send(CENUM.MEMSHR_APP_RULE_ADD, {ip = myip.inet_aton(ip), port = port, appid = appid, ruleid = ruleid})\
end\
\
local function flush(t)\
    apprule.rules, apprule.index, apprule.rule_cnt = {}, 0, 0\
    kernel.send(CENUM.MEMSHR_APP_RULE_FLUSH, \"\")\
end\
\
local function apprule_get_one(sbytes, pos, len)\
    local all_len, ruleid, appid, rip, ip, rport, port, mac, _, next_post = string.unpack('=IIIc4c4HHc6H', sbytes, pos)\
    local data\
    if all_len > 32 then\
        data = string.unpack('=c'.. (all_len - 32), sbytes, next_post)\
    end\
    mac = myip.mac_ntoa(mac)\
    ip = myip.inet_ntoa(ip)\
    if appid > 0 then\
        rip = myip.inet_ntoa(rip)\
        local key = string.format(\"%s:%d\", rip, rport)\
        local rule = apprule.rules[key]\
        if rule then\
            rule.hit_cnt = rule.hit_cnt + 1\
        end\
    else\
        rip = \"\"\
        data = mime.b64(data)\
    end\
\
    local appinfo_table = {\
        mac = mac,\
        ip = ip,\
        port = port,\
        appid = appid,\
        ruleid = ruleid,\
        data = data\
    }\
\
    actor.publish({msgtype = \"APPRULE\", apprule_table = appinfo_table})\
\
    return all_len\
end\
\
local function apprule_get(sbytes)\
    local len = sbytes:len() used_len = 0\
    while used_len < len do\
        local one_size = apprule_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
    end\
    assert(used_len == len)\
    return len\
end\
\
local function write(t)\
    if t.period and tonumber(t.period) ~= apprule.period then\
        apprule.period = tonumber(t.period)\
        timer.mod(apprule.timer_name, apprule.period, 0, function () kernel.call(CENUM.MEMSHR_APPINFO, \"\", apprule_get) end)\
    end\
    if type(t.max_rule_cnt) == \"number\" then\
        apprule.max_rule_cnt = t.max_rule_cnt\
    end\
    if type(t.rule_clean_cnt) == \"number\" then\
        apprule.rule_clean_cnt = t.rule_clean_cnt\
    end\
end\
\
function apprule.postinit()\
    timer.mod(apprule.timer_name, apprule.period, 0, function () kernel.call(CENUM.MEMSHR_APPINFO, \"\", apprule_get) end)\
end\
\
actor.action_set(apprule.subtype, \"stat\", function () return {rule_cnt = apprule.rule_cnt} end, \"show apprule stat\")\
actor.action_set(apprule.subtype, \"show\", function () return {rules = apprule.rules} end, \"show apprules\")\
actor.action_set(apprule.subtype, \"read\", function () return {period = apprule.period, max_rule_cnt = apprule.max_rule_cnt, rule_clean_cnt = apprule.rule_clean_cnt} end, \"read apprule conf\")\
actor.action_set(apprule.subtype, \"write\", write, \"set conf, {period = number, max_rule_cnt = number, rule_clean_cnt = number}\")\
actor.action_set(apprule.subtype, \"add\", add, \"add app rules, {ip = string/nil, port = number/nil, ruleid = number, appid = number}\")\
actor.action_set(apprule.subtype, \"del\", del, \"del app rules, {key = ip:port, ruleid = number}\")\
actor.action_set(apprule.subtype, \"flush\", flush, \"flush app rules\")\
actor.action_set(apprule.subtype, \"get_kernel\", function () kernel.call(CENUM.MEMSHR_APPINFO, \"\", apprule_get) end, \"get kernel\") \
\
return apprule\
"
, '@'.."./service/apprule.lua" ) )

package.preload[ "appsig_bin" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local cjson = require(\"cjson\")\
local timer = require(\"timer\")\
local log = require(\"log\")\
local ccrypto = require(\"c.crypto\")\
local kernel = require(\"c.kernel\")\
local mystring = require(\"mystring\")\
\
local appsig_bin = {\
    type = \"appsig_bin\",\
    subtype = \"appsig_bin\",\
    help = \"load appsig\",\
    period = 86400, \
    valid_period = 604800,  -- a week\
    timer_name = \"appsig_bin_save\",\
    filename = \"m01_sig.bin\",\
    sig_file = nil,\
    key = '\\x02\\x00\\x02\\x01\\x00\\x06\\x00\\x06\\x00\\x00\\x00\\x00',\
    magic = 0x20211115,\
    max_sig_cnt = 10000,\
    ver = \"\",\
    src_ver = \"\",\
\
    -- stat\
    sigs = {\
        domain = {\
            simple = {\
              -- value\
                -- ruleid\
                -- hit_cnt\
            }\
        },\
        diport = {\
            simple = {\
              -- value\
                -- ruleid\
                -- hit_cnt\
            }\
        },\
        port = {\
            base = {\
              -- value\
                -- ruleid\
                -- appid\
                -- name\
            }\
        },\
        payload = {\
            base = {\
              -- value\
                -- ruleid\
                -- appid\
                -- name\
            }\
        }\
    },\
    appdesc = {\
        -- ruleid\
            -- appid\
            -- prio\
            -- stype\
            -- name\
            -- value\
    },\
    ruleids = {\
        -- id\
        -- ts\
    },\
    update_sig_cnt = 0,\
    add_cnt = 0,\
    del_cnt = 0,\
}\
\
local function appsig_upstat(action, stype)\
    local key, sigtype = nil, stype or \"\"\
    if action == \"add\" then\
        appsig_bin.add_cnt = appsig_bin.add_cnt + 1\
        key = stype..\"_addcnt\"\
    elseif action == \"del\" then\
        appsig_bin.del_cnt = appsig_bin.del_cnt + 1\
        key = stype..\"_delcnt\"\
    end\
\
    if key then\
        appsig_bin[key] = (appsig_bin[key] or 0) + 1\
    end\
end\
\
local function kernel_send_port(ktype, table)\
    for port,t in pairs(table) do\
        local buf = string.pack(\"=IIIHH\", 16, t.ruleid or 0, t.appid or 0, tonumber(port) or 0, 0)\
        -- log.error(\"port add\", tonumber(port), port, mystring.data2hex(buf,\":\"))\
        kernel.send(ktype, buf)\
    end\
end\
\
local function kernel_send_payload(ktype, table)\
    for value,t in pairs(table) do\
        local len, offset, payload, nex_post = 0, 0, \"\", 0\
        if value and #value > 2 then\
            offset, nexpost = string.unpack(\">H\", value)\
            payload = string.sub(value, nexpost)\
            len = #payload\
        end\
        local buf = string.pack(\"=IIIHHc\"..len, 16 + len, t.ruleid or 0, t.appid or 0, offset, len, payload)\
        kernel.send(ktype, buf)\
    end\
end\
\
local function deal_file(filename, byte)\
    local f, str\
    if not filename then\
        return str\
    end\
    if byte then\
        f = io.open(filename, \"w\")\
        if f then\
            f:write(byte)\
            f:close()\
        end\
    else\
        f = io.open(filename, \"r\")\
        if f then\
            str = f:read(\"a\")\
            f:close()\
        end\
    end\
    return str\
end\
\
local function appsig_load_sig(sig_file)\
    local byte = deal_file(sig_file)\
    if not byte then\
        byte = deal_file(appsig_bin.filename)\
        if not byte then\
            log.error(\"read m01_sig.bin fail\")\
            return\
        end\
    end\
    local magic, alllen, zlen, len, nextpos = string.unpack(\">IIII\", byte)\
    return byte, magic, alllen, zlen, len, nextpos\
end\
\
local function appsig_load(t)\
    local now = os.time()\
    local byte, magic, alllen, zlen, len, nextpos = appsig_load_sig(t.file or appsig_bin.sig_file)\
    if magic ~= appsig_bin.magic then\
        byte, magic, alllen, zlen, len, nextpos = appsig_load_sig(appsig_bin.filename)\
    end\
    \
    local ver = myip.inet_ntoa(string.sub(byte, nextpos, nextpos + 3))\
    if t.show_ver then\
        return ver\
    end\
    appsig_bin.ver = ver\
    local key = string.pack(\">I\", len)\
    if magic ~= appsig_bin.magic or #byte ~= alllen then\
        log.error(\"load m01_sig.bin fail, alllen\", alllen, \", ziplen\", zlen, \", magic\", string.format(\"%X\", magic))\
        return\
    end\
    local cipherdata = ccrypto.decrypt(string.sub(byte, nextpos + 4, -1), appsig_bin.key .. key, \"ecb\")\
    cipherdata = string.sub(cipherdata, 1, zlen)\
    local sigstr = ccrypto.unzip(cipherdata, len)\
    if not sigstr or #sigstr ~= len then\
        log.error(\"unzip fail, len\", len, \", unziplen\", #(sigstr or \"\"))\
        return\
    end\
    local tbl = cjson.decode(sigstr)\
    if tbl and type(tbl.sigs) == \"table\" and type(tbl.appdesc) == \"table\" then\
        appsig_bin.sigs, appsig_bin.ruleids = tbl.sigs, {}\
        for k,v in pairs(tbl.appdesc) do\
            local id = tonumber(k) or 0\
            appsig_bin.appdesc[id] = v\
            table.insert(appsig_bin.ruleids, 1, {id = id, ts = now})\
        end\
    end\
    if appsig_bin.sigs and appsig_bin.sigs.diport and  appsig_bin.sigs.diport.simple then\
        local simple = appsig_bin.sigs.diport.simple\
        for k,v in pairs(simple) do\
            local desc = appsig_bin.appdesc[v.ruleid] or {}\
            local ip, port = mystring.split(k, \":\")\
            lcmd_run({subtype = \"apprule\", action = \"add\", ip = ip, port = port, ruleid = v.ruleid, appid = desc.appid or 0}) \
        end\
    end\
\
    for k,v in pairs(appsig_bin.sigs) do\
        if k == \"port\" and v.base then\
            -- log.error(\"port add\", cjson.encode(v.base))\
            kernel_send_port(CENUM.MEMSHR_APP_BASEPORT_ADD, v.base)\
        elseif k == \"payload\" and v.base then\
            kernel_send_payload(CENUM.MEMSHR_APP_BASEPAYLOAD_ADD, v.base)\
        end\
    end\
\
    return\
end\
\
local function appsig_save(t)\
    if t.timer and appsig_bin.update_sig_cnt <= 0 then\
        return\
    end\
    local sigs = {sigs = appsig_bin.sigs, appdesc = {}}\
    for k,v in pairs(appsig_bin.appdesc) do\
        local ruleid = tostring(k) or \"\"\
        sigs.appdesc[ruleid] = v\
    end\
    local str = cjson.encode(sigs)\
    local len = #str\
\
    local zstr = ccrypto.zip(str, len > 1024 and len or 1024)\
    local key = string.pack(\">I\", len)\
    local ver = os.date(\"%y.%m.%d.%H\")\
    \
    local cipherdata = ccrypto.encrypt(zstr, appsig_bin.key .. key, \"ecb\")\
    local byte = string.pack(\">IIIIc4\", appsig_bin.magic, #cipherdata + 5 * 4, #zstr, len, myip.inet_aton(ver))\
    byte = byte .. cipherdata\
    appsig_bin.update_sig_cnt = 0\
    deal_file(t.file or appsig_bin.sig_file, byte)\
end\
\
local function simple_sig_match(t)\
    local stype, value = t.stype, t.value\
    if not stype or not value then\
        return\
    end\
    value = string.lower(value)\
    if not appsig_bin.sigs[stype] then\
        return\
    end\
    local info = appsig_bin.sigs[stype]\
    local simple = info.simple or {}\
    if stype == \"domain\" then\
        local val = {mystring.split(value, \".\")}\
        for i=1,#val do\
            local v = table.concat(val, \".\", i, #val)    \
            if simple[v] then\
                simple[v].hitcnt = simple[v].hitcnt + 1\
                return simple[v].ruleid\
            end\
        end\
    elseif stype == \"diport\" then\
        if simple[value] then\
            return simple[value].ruleid\
        end\
    end\
end\
\
local function simple_sig_del(t)\
    local ruleid = t.ruleid or 0\
    local stype, desc = nil, appsig_bin.appdesc[ruleid]\
    if desc then\
        stype = desc[\"stype\"]\
        if t.index and t.index > 0 then\
            table.remove(appsig_bin.ruleids, t.index)\
        else\
            for index,rule in pairs(appsig_bin.ruleids) do\
                if ruleid == rule.id then\
                    table.remove(appsig_bin.ruleids, index)\
                    break\
                end\
            end\
        end\
\
        appsig_bin.appdesc[ruleid] = nil\
    else\
        return\
    end\
    if stype and appsig_bin.sigs[stype] then \
        local sigs = appsig_bin.sigs[stype]\
        local val = sigs.simple or {}\
        for k,v in pairs(val) do\
            if v.ruleid == ruleid then\
                val[k] = nil\
                break\
            end\
        end\
    end\
    if not t.all then\
        appsig_bin.update_sig_cnt = appsig_bin.update_sig_cnt + 1\
    end\
\
    lcmd_run({subtype = \"apprule\", action = \"del\", ruleid = ruleid})\
    appsig_upstat(\"del\", stype)\
end\
\
local function simple_sig_flush(t)\
    for k,v in pairs(appsig_bin.sigs) do\
        for _,info in pairs(v.simple or {}) do\
            simple_sig_del({all = true, ruleid = info.ruleid})\
        end\
    end\
    lcmd_run({subtype = \"apprule\", action = \"flush\"})\
end\
\
\
local function refresh_ruleids()\
    local now = os.time()\
    for i = #appsig_bin.ruleids, 1, -1 do\
        -- print(appsig_bin.ruleids[i].ts, i, now - appsig_bin.ruleids[i].ts)\
        if now - appsig_bin.ruleids[i].ts > appsig_bin.valid_period then\
            simple_sig_del({ruleid = appsig_bin.ruleids[i].id, index = i})\
        else\
            break\
        end\
    end\
end\
\
\
local function simple_sig_add(t)\
    local update = false\
    local ruleid, appid, name, stype, value, prio, all = t.ruleid, t.appid, t.name, t.stype, t.value, t.prio, t.all\
    if not ruleid or not appid or not name or not stype or not value or not prio then\
        return\
    end\
\
    if value == \"\" then\
        simple_sig_del({ruleid = ruleid})\
        return\
    end\
\
    if appsig_bin.appdesc[ruleid] then\
        update = true\
        simple_sig_del({ruleid = ruleid})\
    elseif #appsig_bin.ruleids >= appsig_bin.max_sig_cnt then\
        update = true\
        local rule = appsig_bin.ruleids[#appsig_bin.ruleids]\
        simple_sig_del({ruleid = rule.id, index = #appsig_bin.ruleids})\
    end\
\
    local now = os.time()\
    table.insert(appsig_bin.ruleids, 1, {id = ruleid, ts = now})\
    appsig_bin.appdesc[ruleid] = {appid = appid, prio = prio, stype = stype, name = name, value = value}\
    local allsigs = appsig_bin.sigs\
    if not allsigs[stype] then\
        allsigs[stype] = {simple = {}}\
    elseif not allsigs[stype].simple then\
        allsigs[stype].simple = {}\
    end\
    local val = appsig_bin.sigs[stype]\
    val.simple[value] = {ruleid = ruleid, hitcnt = 0}\
\
    if not update then\
        appsig_bin.update_sig_cnt = appsig_bin.update_sig_cnt + 1\
    end\
    if not all and appsig_bin.update_sig_cnt >= 100 then\
        appsig_save({})        \
    end\
    if stype == \"diport\" then\
        local ip, port = mystring.split(value, \":\")\
        lcmd_run({subtype = \"apprule\", action = \"add\", ip = ip, port = port, ruleid = ruleid, appid = appid}) \
    end\
    appsig_upstat(\"add\", stype)\
end\
\
local function base_sig_del(t)\
    local ruleid, delid, sigtype = t.ruleid or 0, nil, sigtype\
    for stype,info in pairs(appsig_bin.sigs) do\
        local sig = appsig_bin.sigs[stype]\
        for k,v in pairs(sig.base or {}) do\
            if v.ruleid == ruleid and (t.value == nil or t.value == k) then\
                sig.base[k], delid, sigtype = nil, ruleid, stype\
                break\
            end\
        end\
    end\
\
    if delid then\
        if sigtype == \"port\" then\
            kernel_send_port(CENUM.MEMSHR_APP_BASEPORT_DEL, {del = {ruleid = delid}})\
        elseif sigtype == \"payload\" then\
            kernel_send_payload(CENUM.MEMSHR_APP_BASEPAYLOAD_DEL, {del = {ruleid = delid}})\
        end\
    end\
end\
\
local function base_sig_flush(t)\
    for k,v in pairs(appsig_bin.sigs) do\
        local bsig = appsig_bin.sigs[k]\
        for val,info in pairs(v.base or {}) do\
            bsig.base[val] = nil\
        end\
    end\
    kernel.send(CENUM.MEMSHR_APP_BASE_FLUSH, \"\")\
end\
\
local function base_sig_add(t)\
    local ruleid, appid, name, stype, value, offset, prio, all = t.ruleid, t.appid, t.name, t.stype, t.value, t.offset or 0, t.prio, t.all\
    if not ruleid or not appid or not name or not stype or not value or not prio then\
        return\
    end\
\
    if value == \"\" then\
        base_sig_del({ruleid = ruleid})\
        return\
    end\
\
    local allsigs = appsig_bin.sigs\
    if not allsigs[stype] then\
        allsigs[stype] = {base = {}}\
    elseif not allsigs[stype].base then\
        allsigs[stype].base = {}\
    end\
\
    local val = appsig_bin.sigs[stype]\
    if stype == \"port\" then\
        val.base[value] = {ruleid = ruleid, appid = appid, name = name}\
        kernel_send_port(CENUM.MEMSHR_APP_BASEPORT_ADD, {value = {ruleid = ruleid, appid = appid, name = name}})\
    elseif stype == \"payload\" then\
        local data = mystring.hex2data(value)\
        local pkey = string.pack(\">Hc\"..#data, offset, data)\
        local psig = {}\
        val.base[pkey] = {ruleid = ruleid, appid = appid, name = name}\
        psig[pkey] = {ruleid = ruleid, appid = appid, name = name}\
        kernel_send_payload(CENUM.MEMSHR_APP_BASEPAYLOAD_ADD, psig)\
    end\
end\
\
local function get_desc(t)\
    if t.ruleid then\
        return appsig_bin.appdesc[t.ruleid]\
    end\
    return {}\
end\
\
local function sig_stat(t)\
    if not t.stype or not t.value then\
        return\
    end\
    local sigs = appsig_bin.sigs[t.stype] or {}\
    local simple = sigs.simple or {}\
    return simple[t.value]\
end\
\
local function write(t)\
    if type(t.period) == \"number\" and t.period ~= appsig_bin.period then\
        appsig_bin.period = t.period\
        timer.mod(appsig_bin.timer_name, appsig_bin.period, 0, appsig_save, {timer = true})\
    end\
\
    if type(t.valid_period) == \"number\" and t.valid_period ~= appsig_bin.valid_period then\
        appsig_bin.valid_period = t.valid_period\
    end\
\
    if type(t.max_sig_cnt) == \"number\" and t.max_sig_cnt ~= appsig_bin.max_sig_cnt then\
        appsig_bin.max_sig_cnt = t.max_sig_cnt\
    end\
end\
\
function appsig_bin.postinit()\
    appsig_bin.sig_file = lcmd_data_path(appsig_bin.filename)\
    appsig_load({})\
    appsig_bin.src_ver = appsig_load({file = appsig_bin.filename, show_ver = true}) or \"\"\
    timer.mod(appsig_bin.timer_name, appsig_bin.period, 0, appsig_save, {timer = true})\
    timer.mod(\"appsig_refresh\", 3600, 0, refresh_ruleids)\
end\
\
actor.action_set(appsig_bin.subtype, \"read\", function () return { valid_period = appsig_bin.valid_period, max_sig_cnt = appsig_bin.max_sig_cnt,  period = appsig_bin.period, src_ver = appsig_bin.src_ver, ver = appsig_bin.ver, sigcnt = #appsig_bin.ruleids } end, \"read appsig_bin conf\")\
-- actor.action_set(appsig_bin.subtype, \"show\", function () return {sigs = appsig_bin.sigs, ruleids = appsig_bin.ruleids} end, \"show appsig_bin sigs\")\
-- actor.action_set(appsig_bin.subtype, \"show_desc\", function () return {desc = appsig_bin.appdesc} end, \"show appsig_bin sigs\")\
actor.action_set(appsig_bin.subtype, \"stat\", function () return { add_cnt = appsig_bin.add_cnt, del_cnt = appsig_bin.del_cnt, domain_addcnt = appsig_bin.domain_addcnt or 0, domain_delcnt = appsig_bin.domain_delcnt or 0, diport_addcnt = appsig_bin.diport_addcnt or 0, diport_delcnt = appsig_bin.diport_delcnt or 0 } end, \"read appsig_bin conf\")\
actor.action_set(appsig_bin.subtype, \"write\", write, [[set appsig_bin conf, {period = number, valid_period = number, max_sig_cnt = number}]])\
actor.action_set(appsig_bin.subtype, \"save\", appsig_save, [[save app sig, {file = string}, default datapath + m01_sig.bin]])\
actor.action_set(appsig_bin.subtype, \"load\", appsig_load, [[load app sig, {file = string}, default m01_sig.bin]])\
actor.action_set(appsig_bin.subtype, \"match\", simple_sig_match, [[search rule_id, {stype = string, value = string}]])\
actor.action_set(appsig_bin.subtype, \"get_desc\", get_desc, [[show appsig, {ruleid = number}]])\
actor.action_set(appsig_bin.subtype, \"add\", simple_sig_add, [[add sig, {all = boolean, ruleid = number, appid = number, name = string, stype = string, value = string, prio = number}]])\
actor.action_set(appsig_bin.subtype, \"del\", simple_sig_del, [[del ruleid, {ruleid = number}]])\
actor.action_set(appsig_bin.subtype, \"flush\", simple_sig_flush, [[flush ruleid]])\
actor.action_set(appsig_bin.subtype, \"sig_stat\", sig_stat, [[read sig_stat, {stype = string, value = string}]])\
actor.action_set(appsig_bin.subtype, \"base_add\", base_sig_add, [[add sig, {all = boolean, ruleid = number, appid = number, name = string, stype = string, value = string<require hex format>, offset = number<default 0>, prio = number}]])\
actor.action_set(appsig_bin.subtype, \"base_del\", base_sig_del, [[del ruleid, {ruleid = number}]])\
actor.action_set(appsig_bin.subtype, \"base_flush\", base_sig_flush, [[flush ruleid]])\
\
return appsig_bin\
"
, '@'.."./service/appsig_bin.lua" ) )

package.preload[ "appuse" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local ctime = require(\"c.time\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local myutil = require(\"myutil\")\
local policy_com = require(\"ct.policy\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local pktpolicy = require(\"pktpolicy\")\
local is_numeric = policy_com.is_numeric\
\
local appuse = {\
    subtype = \"appuse\",\
    timer_name = 'appuse_upload',\
    help = \"set appuse and send info to server\",\
    pcnt = 0,\
    max_pcnt = 20,\
    max_appid_cnt = 100,\
    addr = \"message.189cube.com:9890\",\
    policies = { -- index\
        -- index, string\
        -- mac\
        -- appid, appid list\
        -- once\
        -- time\
            -- {weekdays = \"1,2,3,4,5\", time = \"00:00-19:00,21:00-24:00\"}\
        -- action_type, string \"0xff21\"\
        -- times\
            -- {weekdays = {[1] = true, [2] = true}, time = {{start_hour = 0, end_hour = 0}}, windex = 0, tindex = 0, lasttime = 0}\
    },\
    all_len = 0,\
    all_cnt = 0,\
    disable = {}, -- policy index, when hit and once is true, {\"1\" = true, \"2\" = true}\
}\
\
local function appconf_del(msg)\
    local indexes = msg.index or {}\
    if type(indexes) ~= \"table\" then\
        return {msg = \"invalid index\"}\
    end\
    local _, err_info = lcmd_run({subtype = \"pktpolicy\", action = \"del\", index = indexes, ftype = appuse.subtype})\
    if err_info then return err_info end\
    for _, index in pairs(indexes) do\
        if appuse.policies[index] and is_numeric(index) then\
            appuse.policies[index] = nil\
            appuse.pcnt = appuse.pcnt - 1\
        else\
            log.warn(\"No such index to delete\")\
        end\
    end\
end\
\
local function appconf_add(t)\
    local msg, need_save = nil, false\
    if type(t.policies) ~= \"table\" then\
        log.error(\"must add table for appuse conf\")\
        return\
    end\
    for _, policy in pairs(t.policies) do\
        local once, index, push_period = false, policy.index, 1200\
        if not is_numeric(index) then\
            log.warn(index .. \"(index) not is effective string\")\
            return {err = \"invalid index type\"}\
        end\
        if not is_numeric(policy.action_type) then\
            return {err = \"invalid action_type\"}\
        end\
\
        if not pktpolicy.check_index(index, appuse.subtype) then\
            return {err = \"index is used in other policy\"}\
        end\
\
        if not appuse.policies[index] and appuse.pcnt >= appuse.max_pcnt then\
            return {err = \"can not exceed the limit count \"..tostring(appuse.max_pcnt)}\
        end\
\
        local appid = policy.appid or {}\
        if type(appid) ~= \"table\"  then return end\
        if #appid <= 0 or #appid > appuse.max_appid_cnt then return end\
\
        if type(policy.once) == \"boolean\" then once = policy.once end\
        -- default 20 minute\
        if type(policy.push_period) == \"number\" and policy.push_period > 0 then push_period = policy.push_period end\
\
        local s = {\
            index = index,\
            appid = appid,\
            mac = policy.mac or \"\",\
            time = policy.time or {weekdays = \"1,2,3,4,5,6,7\", time = \"00:00-24:00\"},\
            once = once,\
            push_period = push_period,\
            action_type = policy.action_type,\
        }\
\
        local ok, times = policy_com.parse_time(s.time)\
        if not ok then\
            return {err = \"time parse failed!\"}\
        end\
        need_save = true\
        appconf_del({index = {index}})\
        s.times = times\
        -- count ++\
        appuse.pcnt = appuse.pcnt + 1\
        appuse.policies[index] = s\
        _, msg = lcmd_run({\
            subtype = \"pktpolicy\",\
            action = \"add\",\
            policies = {\
                {\
                    index = policy.index,\
                    appid = policy.appid,\
                    mac = policy.mac,\
                    time = policy.time,\
                    action = policy.action,\
                    dscp_value = policy.dscp_value,\
                    ip_port = policy.ip_port,\
                    ports = policy.ports,\
                    direct = policy.direct,\
                    type = appuse.subtype,\
                }\
            }\
        })\
    end\
    if need_save then lcmd_run\
        {type = \"sys\", action = \"save_conf_change\"}\
    end\
    return msg or {msg = \"add success\"}\
end\
\
local function stat()\
    local res = {}\
    for k, v in pairs(appuse.policies) do\
        res[k] = {\
            index = v.index,\
            appid = v.appid,\
            mac = v.mac,\
            time = v.time,\
            -- times = v.times,            -- time after parsing\
            once = v.once,\
            push_period = v.push_period,\
            action_type = v.action_type,\
        }\
    end\
    return res\
end\
\
local function app_getinfo(one, mac, appid, date, wday, timenum)\
    -- check mac\
    if type(one) ~= \"table\" or (one.mac ~= \"\" and one.mac ~= mac) then\
        return\
    end\
    -- check appid\
    if not myutil.inarr(appid, one.appid) then\
        return\
    end\
    local ok, tindex = policy_com.check_time(date, wday, one.times)\
    if not ok then\
        return\
    end\
    local conf = one.times\
    -- 周或时间段有更新需要上报\
    if wday ~= conf.windex or tindex ~= conf.tindex then\
        conf.windex, conf.tindex, conf.lasttime = wday, tindex, timenum\
        return true\
    elseif timenum and (conf.lasttime + one.push_period <= timenum) then\
        conf.lasttime = timenum\
        return true\
    end\
end\
\
local function appuse_get(msg)\
    if type(msg) ~= \"table\" or type(msg.data) ~= \"table\" then\
        return\
    end\
    local index = msg.data.index\
    local one = appuse.policies[index]\
\
    if not index or not one then\
        return\
    end\
\
    local data = {}\
    for key, value in pairs(msg.data) do\
        data[key] = value\
    end\
    local date, wday = policy_com.date_fmt()\
    local macstr, appid, timenum = myip.mac_fmt(data.mac), data.appid, tonumber(data.time)\
    local ok = app_getinfo(one, macstr, appid, date, wday, timenum)\
    if ok then\
        local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
        local osid, dev_name = 0, \"\"\
        if oss[data.mac] then\
            osid, dev_name = oss[data.mac].decide_osid or oss[data.mac].cloud_osid or 0, oss[data.mac].devname or \"\"\
        end\
        if one.once then appuse.disable[tostring(index)] = true end\
        data.type, data.osid, data.dev_name = appuse.subtype, osid, dev_name\
        data.push_period, data.action_type = one.push_period, one.action_type\
\
        local one_len = policy_com.send_uniform(\"appuse\", appuse.addr, data.action_type, {data})\
        appuse.all_len = appuse.all_len + one_len\
        appuse.all_cnt = appuse.all_cnt + 1\
    end\
end\
\
local function write(t)\
    if type(t.addr) == \"string\" and t.addr ~= appuse.addr then\
        appuse.addr = t.addr\
    end\
    if type(t.policies) == \"table\" then\
        local add_format = {policies = t.policies}\
        appconf_add(add_format)\
    end\
end\
\
local function read()\
    return {\
        addr = appuse.addr,\
        stat = {\
            pcnt = appuse.pcnt,\
            max_pcnt = appuse.max_pcnt,\
            max_appid_cnt = appuse.max_appid_cnt,\
            all_len = appuse.all_len,\
            all_cnt = appuse.all_cnt,\
        }\
    }\
end\
\
local function appconf_clean()\
    if not next(appuse.disable) then\
        return\
    end\
    for index, _ in pairs(appuse.disable) do\
        appconf_del({index = {index}})\
    end\
    appuse.disable = {}\
end\
\
function appuse.postinit()\
    appuse.index = actor.subscribe(\"PKTPOLICY\", appuse_get)\
    timer.mod(\"appuse_policy_clean\", 60, 0, appconf_clean)\
end\
\
function appuse.finish()\
    if appuse.index then actor.unsubscribe(\"PKTPOLICY\", appuse.index) end\
end\
\
actor.action_set(appuse.subtype, \"write\", write, [[configure appuse, {addr = string, policies = list}]])\
actor.action_set(appuse.subtype, \"read\", read, \"{addr, stat = {pcnt, max_pcnt, max_appid_cnt, all_len, all_cnt}}\")\
actor.action_set(appuse.subtype, \"add\", appconf_add, \"policies = {{index = string, appid = list, mac = string, time = list, once = boolean, push_period = number, action_type = string, action = continue/fin/drop, dscp_value = number, ip_port = list, ports = list, direct = string}}\")\
actor.action_set(appuse.subtype, \"del\", appconf_del, [[del policy, {index = [\"1\",\"2\"...]}]])\
actor.action_set(appuse.subtype, \"stat\", stat, \"{index = string, appid = list, mac = string, time = list, once = boolean, push_period = number, action_type = string}\")\
actor.action_set(appuse.subtype, \"flush\", function () for index, _ in pairs(appuse.policies) do appconf_del({index = {index}}) end end, \"appuse conf flush\")\
actor.action_set(appuse.subtype, \"show_conf_save\", function () return {subtype = appuse.subtype, action = \"write\", policies = appuse.policies, addr = appuse.addr} end, \"show appuse save conf msg\")\
\
return appuse\
"
, '@'.."./service/appuse.lua" ) )

package.preload[ "arch" ] = assert( (loadstring or load)(
"local carch = require\"c.arch\"\
local actor = require\"luactor\"\
local timer = require\"timer\"\
local dpi = require\"svrcomm.dpi\"\
\
local arch = {\
    type = \"arch\", \
    subtype = \"arch\", \
\
    timer_name = \"arch_timer\", \
    help = \"arch var, SN, mac, oui, version, sigversion, etc...\", \
\
    iface = \"\", \
}\
\
local function pppoe_timer(funcall)\
    local pppoe = funcall()\
    if pppoe and pppoe ~= \"\" then\
        arch.pppoe = pppoe\
        dpi.set_pppoe(pppoe)\
        timer.del(\"arch_pppoe\")\
    end\
end\
\
local function get_loid()\
    local loid\
    local ok, poninfo = lcmd_run({subtype = \"capi\", action = \"get_poninfo\"})\
    if ok and type(poninfo) == \"table\" then\
        loid = poninfo.loid\
    end\
    return loid\
end\
\
local function loid_timer()\
    local loid = get_loid()\
    if loid and loid ~= \"\" then\
        arch.loid = loid\
        dpi.set_loid(loid)\
        timer.del(\"arch_loid\")\
    end\
end\
\
local function read()\
    local log = require\"log\"\
    local csys = require\"c.sys\"\
    local myip = require\"myip\"\
    local luav = myip.inet_ntoa(csys.show_luav())\
    local _,sys_stime = lcmd_run{type = \"sys\", action = \"sys_stime\"}\
    local _,dpi_stime = lcmd_run{type = \"sys\", action = \"dpi_stime\"}\
    local ok, tt = lcmd_run{type = \"sig\", action = \"show\"}\
    local sigv\
\
    if ok and type(tt) == \"table\" then\
        sigv = tt.version \
    end\
\
    local ok, ttt = lcmd_run{type = \"capi\", action = \"get_devinfo\"}\
    local devinfo\
\
    if ok and type(ttt) == \"table\" then\
        devinfo = ttt\
    end\
\
    --[[ There is no hardware version, software version, model, manufacturer, device identification and \
         other information in the capi interface of Telecom 1.0 gateway. Set the return value to \"\". --]]\
    return {sn = arch.sn, oui = arch.oui, int_ver = arch.int_ver, pppoe = arch.pppoe, loid = arch.loid or \"\", lua_ver = luav, sig_ver = sigv, \
            src_ver = arch.src_ver, datadir = lcmd_data_path(\"\"), tmpdir = lcmd_tmp_path(\"\"),dhwver = devinfo.HDVersion or \"\",\
            dswver = devinfo.SWVersion or \"\", dmod = devinfo.ProductClass or \"\", dmfr = devinfo.Manufacturer or \"\",\
            gw_sn = devinfo.DevType or \"\", sys_stime = sys_stime or \"\", dpi_stime = dpi_stime or \"\"\
    }\
end\
\
local function set_iface(t)\
    if type(t.iface) == \"string\" then\
        arch.iface = t.iface\
    end\
end\
\
function arch.postinit()\
    local get_pppoe\
    -- init arch such as sn/pppoe..., must be OK, or will wait forever\
    while true do\
        local v = carch.init(arch.iface)\
        if not v then\
            local socket = require\"socket\"\
            log.error(\"Failed to arch init, sleep 10 seconds forever\")\
            local _, _, err = socket.select(nil, nil, 10)\
        else\
            arch.sn = v.sn\
            arch.oui = v.oui\
            arch.int_ver = v.int_ver\
            arch.src_ver = v.src_ver\
\
            arch.mac = v.mac\
            get_pppoe = v.get_pppoe\
            break\
        end\
    end\
\
    dpi.init(arch.sn, arch.oui, arch.int_ver, arch.mac)\
\
    -- init OK, \
    if type(get_pppoe) == \"function\" then\
        arch.pppoe = get_pppoe()\
        if not arch.pppoe or arch.pppoe == \"\" then\
            log.warn(\"failed to get pppoe, will retry every 60s\")\
            timer.mod(\"arch_pppoe\", 60, 0, pppoe_timer, get_pppoe)\
        else\
            dpi.set_pppoe(arch.pppoe)\
        end\
    end\
\
    local ct_enable, ct = pcall(require, \"ct\")\
    if ct_enable then\
        arch.loid = get_loid()\
        if not arch.loid or arch.loid == \"\" then\
            log.warn(\"failed to get loid, will retry every 60s\")\
            timer.mod(\"arch_loid\", 60, 0, loid_timer)\
        else\
            dpi.set_loid(arch.loid)\
        end\
    end\
end\
\
\
actor.action_set(arch.subtype, \"set_iface\", set_iface, \"set sn interface name, default is eth0\")\
actor.action_set(arch.subtype, \"set_sigver\", set_sigver, \"set sig version, {version = xxxx}\")\
actor.action_set(arch.subtype, \"read\", read, \"read arch var\")\
actor.action_set(arch.subtype, \"auth\", function () lcmd_run({subtype = \"__svr_oper\", action = \"oper_heart\"}) end, \"send heartbeat to svroper platform for authentication\")\
actor.action_set(arch.subtype, \"stat\", function () local _, t = lcmd_run({subtype = \"sys\", action = \"extperm_get\"}) return {cli_limit = t.enable} end, \"read CLI permission status\")\
\
return arch\
"
, '@'.."./service/arch.lua" ) )

package.preload[ "capi" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local cct = require\"c.ct\"\
local myip = require(\"myip\")\
\
local capi = {\
    type = \"capi\",\
    subtype = \"capi\",\
    help = \"get info from capi\"\
}\
\
local function all()\
    local capi = {\
        get_poninfo = cct.getponinfo,\
        get_devinfo = cct.getdeviceinfo,\
        get_networkinfo = cct.getnetworkinfo,\
        get_wancon = cct.getwanconnectionobjs,\
        get_wifiinfo = cct.getwifiinfo,\
        get_voipinfo = cct.getvoipinfo,\
        get_wlandevice = cct.getwlandeviceObjs,\
        get_systemcmdconfig = cct.getsystemcmdconfig,\
        get_pppoe = cct.getpppoeconfig,\
        get_dhcpserver = cct.getdhcpserver,\
        get_dnsserverconfig = cct.getdnsserverconfig,\
        get_dns6serverconfig = cct.getdns6serverconfig,\
        get_platformservice = cct.getplatformservice,\
        get_ipv6lanconfig = cct.getipv6lanconfig,\
        get_dhcpv6server = cct.getdhcpv6server,\
        get_iptvconfig = cct.getiptvconfig,\
        get_stainfoobjs = cct.getstainfoobjs,\
        get_diagservice = cct.getdiagservice,\
        get_lanhost = cct.getlanhostinfo,\
        get_lanhostext = cct.getlanhostext\
    }\
    local tt = {}\
    for k,v in pairs(capi) do\
        local _, result = pcall(v)\
            tt[k] = result\
    end\
    return tt\
end\
actor.action_set(capi.subtype, \"get_poninfo\", cct.getponinfo, \"get poninfo from CtSgwGetPONInfo\")\
actor.action_set(capi.subtype, \"get_devinfo\", cct.getdeviceinfo, \"get devinfo from CtSgwGetDeviceInfo\")\
actor.action_set(capi.subtype, \"get_networkinfo\", cct.getnetworkinfo, \"get networkinfo from CtSgwGetNetworkInfo\")\
actor.action_set(capi.subtype, \"get_wancon\", cct.getwanconnectionobjs, \"get get_wancon from CtSgwGetWANConnectionObjs\")\
actor.action_set(capi.subtype, \"get_wifiinfo\", cct.getwifiinfo, \"get wifiinfo from CtSgwGetWiFiInfo\")\
actor.action_set(capi.subtype, \"get_voipinfo\", cct.getvoipinfo, \"get voipinfo from CtSgwGetVoIPInfo\")\
actor.action_set(capi.subtype, \"get_wlandevice\", cct.getwlandeviceObjs, \"get wlandevice from CtSgwGetWLANDeviceObjs\")\
actor.action_set(capi.subtype, \"get_systemcmdconfig\", cct.getsystemcmdconfig, \"get systemcmdconfig from CtSgwGetSystemCmdConfig\")\
actor.action_set(capi.subtype, \"get_pppoe\", cct.getpppoeconfig, \"get pppoe from CtSgwGetPPPoEConfig\")\
actor.action_set(capi.subtype, \"get_dhcpserver\", cct.getdhcpserver, \"get dhcpserver from CtSgwGetDHCPServer\")\
actor.action_set(capi.subtype, \"get_dnsserverconfig\", cct.getdnsserverconfig, \"set dnsserverconfig from CtSgwSetDNSServerConfig\")\
actor.action_set(capi.subtype, \"get_dns6serverconfig\", cct.getdns6serverconfig, \"get dns6serverconfig from CtSgwGetDNS6ServerConfig\")\
actor.action_set(capi.subtype, \"get_platformservice\", cct.getplatformservice, \"get platformservice from CtSgwGetPlatformService\")\
actor.action_set(capi.subtype, \"get_ipv6lanconfig\", cct.getipv6lanconfig, \"get ipv6lanconfig from CtSgwGetIPV6LANConfig\")\
actor.action_set(capi.subtype, \"get_dhcpv6server\", cct.getdhcpv6server, \"get dhcpv6server from CtSgwGetDHCPV6Server\")\
actor.action_set(capi.subtype, \"get_iptvconfig\", cct.getiptvconfig, \"get iptvconfig from CtSgwGetIPTVConfig\")\
actor.action_set(capi.subtype, \"get_stainfoobjs\", cct.getstainfoobjs, \"get stainfoobjs from CtSgwGetSTAInfoObjs\")\
actor.action_set(capi.subtype, \"get_diagservice\", cct.getdiagservice, \"get diagservice from CtSgwGetDiagService\")\
actor.action_set(capi.subtype, \"get_lanhost\", cct.getlanhostinfo, \"get lanhost from CtSgwGetLANHostObjs\")\
actor.action_set(capi.subtype, \"get_lanhostext\", cct.getlanhostext, \"get lanhost from CtSgwGetLANHostExtObjs\")\
actor.action_set(capi.subtype, \"get_all\", all, \"get all capi info\")\
\
return capi\
"
, '@'.."./service/capi.lua" ) )

package.preload[ "cliclient" ] = assert( (loadstring or load)(
"local socket = require\"socket\"\
local unix = require\"socket.unix\"\
local cjson = require\"cjson\"\
local log = require\"log\"\
local mystring = require\"mystring\"\
\
local cliclient = {}\
\
local function usage()\
    return [[\
usage is following:\
\
1. ./CLI_client '{}'\
    all is in one json\
2. ./CLI_client help [subtype action]\
    help usage\
       only help, means all brief help\
       help and subtype, means subtype help\
       help and subtype and action, means action help for such subtype\
3. ./CLI_client subtype[:type] action ['{}']\
   args will be expanded to '{type = type, subtype = subtype, action = action, ...}'\
   last parameter can be empty if action need not any parameter\
]]\
end\
\
local function help(subtype, action)\
    if subtype == nil then\
        return '{\"action\":\"help\"}'\
    elseif action == nil then\
        return '{\"action\":\"help\", \"subtype\":\"'..subtype..'\"}'\
    else\
        return '{\"action\":\"help\", \"subtype\":\"'..subtype..'\", \"name\":\"'..action..'\"}'\
    end\
end\
\
local function cli_cmd(path, msg)\
    local t = unix.tcp()\
    _, err = t:connect(path)\
    if err then\
        return nil, \"Failed to connect path \"..path..\", err is \"..err\
    end\
\
    t:settimeout(180)\
    local len = string.pack(\"I\", #msg)\
    t:send(len)\
    -- t:send(msg:sub(1, 3))\
    -- os.execute(\"sleep 8\")\
    -- t:send(msg:sub(4, -1))\
    t:send(msg)\
    -- log.trace(\"send msg \"..msg, \"len is \"..#msg)\
    buf, err = t:receive(4)\
    if err then\
        t:close()\
        return nil, err\
    end\
    len = string.unpack(\"I\", buf)\
    if len > 0 then\
        resp, err = t:receive(len)\
    else\
        resp, err = \"\", nil\
    end\
    t:close()\
    return resp, err\
end\
\
local function cmd_prepair(stype, action, other)\
    local t = {}\
    if other then\
        local ok\
        ok, t = pcall(cjson.decode, other)\
        if not ok then\
            error(\"Failed to json decode for \"..other)\
        end\
    end\
\
    t.subtype, t.type = mystring.split(stype, \":\")\
    if not t.type then\
        t.type = t.subtype\
    end\
    t.action = action\
    return cjson.encode(t)\
end\
\
local function add_nonmainp_flag(msg)\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        error(\"Failed to json decode for \"..msg)\
    end\
    if type(t.nonmainp) ~= \"nil\" then\
        error(msg..\" should not have the key nonmainp\")\
    end\
    t.nonmainp = true\
    return cjson.encode(t)\
end\
\
function cliclient.main(ismainp, path, ...)\
    local t = {...}\
    local argc = #t\
    local err = nil msg = nil\
\
    if t[1] == \"help\" then\
        msg = help(t[2], t[3])\
    elseif argc == 1 then\
        local firstch = t[1]:sub(1, 1)\
        if firstch == \"{\" then -- json obj\
            msg = t[1]\
        elseif firstch == \"[\" then\
            return nil, usage()\
        else\
            msg = string.format([[{\"action\":\"%s\"}]], t[1])\
        end\
    elseif argc == 3 or argc == 2 then\
        msg = cmd_prepair(t[1], t[2], t[3])\
    else\
        return nil, usage()\
    end\
\
    if not ismainp then\
        msg = add_nonmainp_flag(msg)\
    end\
\
    resp, err = cli_cmd(path, msg)\
    if err then\
        return nil, err..\"\\n\"..usage()\
    else\
        return resp, nil\
    end\
end\
\
return cliclient\
"
, '@'.."./lualib/cliclient.lua" ) )

package.preload[ "cliserver" ] = assert( (loadstring or load)(
"local socket = require(\"socket\")\
local unix = require(\"socket.unix\")\
local msocket = require(\"msocket\")\
local log = require(\"log\")\
local cjson = require(\"cjson\")\
\
local cliserver = {\
}\
\
local function cli_send(s, msg)\
    local buf = string.pack(\"I\", #msg)..msg\
    local cc = coroutine.running()\
    msocket.add(cc, nil, s)\
    coroutine.yield()\
    local ret, err = msocket.polite_send(s, buf)\
    if err then\
        log.warn(\"Failed to send, err is\", err)\
    end\
    msocket.del(s, true)\
end\
\
local function cli_recv(s)\
    -- recv head\
    local buf, err = msocket.polite_receive(s, 4)\
    if err then\
        return nil, \"error for receive, err is \"..err\
    end\
\
    local len = string.unpack(\"I\", buf)\
    if len <= 0 or len > 10000000 then\
        -- actually not need check larger then 10000000 (about 9.5MB),\
        -- here just avoid some tricks or carelessness to cause fault.\
        return nil, \"error unpack len, len is \"..len\
    end\
\
\
    -- recv body\
    buf, err = msocket.polite_receive(s, len)\
    if err then\
        return nil, \"error receive body, len is \"..len.. \", err is \"..err\
    end\
\
    return buf\
end\
\
local function cli_resp(s)\
    local msg, err = cli_recv(s)\
    if err then\
        return false, err\
    end\
\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        return false, \"wrong input json msg \"..msg..\", err is \"..t\
    else\
        local ok, m = lcmd_run(t)\
        if not ok then\
            return false, string.format(\"failed run lcmd_run err(%s) for msg(%s) \", m, msg)\
        end\
        if m == nil then\
            return true, \"\"\
        end\
        local ok, reply = pcall(cjson.encode, m)\
        if not ok then\
            return false, string.format(\"failed run cjson encode err(%s)\", reply)\
        end\
        return true, reply\
    end\
end\
\
local function server_run(s)\
    s:settimeout(0)\
    local coname = \"cliclient_fd\"..s:getfd()\
    local cli = msocket.coroutine_create(coname, 10, \
        function()\
            local ok, msg = cli_resp(s)\
            msocket.del(s)\
            local t = {}\
            if not ok then\
                t.error = msg\
            else\
                t = msg\
            end\
            cli_send(s, msg)\
            s:close()\
            msocket.coroutine_exit()\
        end\
    )\
    if not cli then\
        log.warn(\"Failed to create coroutine \"..coname..\", check coroutinename err\")\
        return\
    end\
\
    msocket.add(cli, s)\
end\
\
function cliserver.init(sockname) \
    local t = unix.tcp() err = nil\
\
    os.remove(sockname)\
    _, err = t:bind(sockname)\
    if err then\
        return \"Failed to bind \"..sockname, \", err is \"..err\
    end\
\
    _, err = t:listen()\
    if err then\
        return \"Failed to listen \"..sockname, \", err is \"..err\
    end\
\
    -- coroutine init\
    co = msocket.coroutine_create(\"cliserver\", 0, \
        function (co)\
            while true do\
                local s = t:accept()\
                server_run(s)\
                --log.error(\"will yield two\")\
                coroutine.yield()\
            end\
        end\
    )\
    if not co then\
        return \"Failed to create coroutine cliserver, check coroutinename err\"\
    end\
   \
    msocket.add(co, t)\
    return nil\
end\
\
return cliserver\
"
, '@'.."./lualib/cliserver.lua" ) )

package.preload[ "config_service" ] = assert( (loadstring or load)(
"return {\"arch\",\"dns\",\"tuple\",\"sys\",\"svroper\",\"shell\",\"operdata\",\"svrdata\",\"sig\",\"dmpapp\",\"ct\",\"osinfo\",\"sigcollect\",\"http\",\"upgrade\",\"dpinfo\",\"http_rule\",\"devinfo\",\"lanhost\",\"lanhoststats\",\"wanstats\",\"diagnose\",\"hredirect\",\"capi\",\"pscan\",\"rawpkt\",\"hotpatch\",\"topo\",\"mdns\",\"upnp\",\"pktpolicy\",\"wandns\",\"pcap_dump\",\"dhcp\",\"oscloud\",\"pqprobe\",\"dumh\",\"https\",\"postmsg\",\"sec_data\",\"domain_dip\",\"sec_camera\",\"appsig_bin\",\"apprule\",\"appinfo\",\"http_imei\",\"appctrl\",\"appuse\",\"appmlp\"}\
"
, '@'.."./config_service.lua" ) )

package.preload[ "ct" ] = assert( (loadstring or load)(
"\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local cct = require(\"c.ct\")\
local ipfilter = require(\"ct.ipfilter\")\
local cthttp = require(\"ct.cthttp\")\
local osgi = require(\"ct.osgi\")\
local timer = require(\"timer\")\
\
local ct = {\
    subtype = \"ct\", \
    help = \"deal ct ipfilter cthttp topo, send to server\",\
    timer_name = \"ct_getlanhost\",\
    \
    -- used by C for get/set op\
    all_lanhost = {}, \
\
    -- time to trigger get\
    period = 300,\
\
    -- true only for debug\
    send_not_lan = false,\
\
    -- stat\
    all_len = 0, \
    all_count = 0, \
    devinfo = {},\
}\
\
local function send_osinfo(t)\
    local mac = t.mac\
    local ip = t.ip\
    local osid = t.osid\
    local hostname = t.hostname\
    local oneos = string.pack(\">c4Hc6IIII\", myip.inet_aton(ip), 0, myip.mac_aton(mac), osid, os.time(), #hostname, 0)\
\
    -- LEN + TL + ss + hostname\
    local head = string.pack(\">IHI\", #oneos + #hostname + 6, CENUM.COMM_BUSINESS_OSINFO, #oneos + #hostname)\
    local ss = head .. oneos .. hostname\
    \
    lcmd_run{subtype = \"__svr_data\", action = \"add\", pkttype=CENUM.COMM_BUSINESS_OSINFO, sbytes = ss, count = 1}\
    log.info(\"osinfo send svr data, size\", #ss)\
    ct.all_len = ct.all_len + #ss\
    ct.all_count = ct.all_count + 1\
end\
\
local function update(t)\
    local macdata = myip.mac_aton(t.mac)\
    local lanhost = ct.all_lanhost[macdata] \
    local desc = t.desc\
    local ret\
    if lanhost and desc then\
        ret = cct.setlanhost(macdata, desc.model, desc.brand, desc.devtypeint, desc.os, desc.dev_type, lanhost.userdata)\
    end\
    return ret\
end\
\
local function getdevinfo()\
    local devinfo = cct.getdeviceinfo()\
    assert(devinfo)\
\
    ct.devinfo = devinfo\
end\
\
-- timer getlanhost\
local function getlanhost()\
    local allhost = cct.getlanhost()\
    local odm = cct.odmflag()\
    assert(allhost)\
\
    for k,v in pairs(allhost) do\
        local info = cct.showlan(v.userdata) or {}\
        v.acc_port = info.port\
        v.active = info.active or 1\
        -- ct3.0\
        v.devname = info.devname or \"\"\
\
        --[[\
            CT_LAN_DEV_CONN_UNKNOWN,  //0\
            CT_LAN_DEV_CONN_WIRED,    //1\
            CT_LAN_DEV_CONN_WLAN,     //2\
        --]]\
        if odm == 1 then\
            v.acc_type = info.connectiontype + 1\
        else\
            v.acc_type = info.conntype\
        end\
    end\
\
    ct.all_lanhost = allhost\
\
end\
\
\
local function get_lan_info(t)\
    if t.all then\
        return ct.all_lanhost\
    end\
    local macdata = myip.mac_aton(t.mac)    \
    local lanhost = ct.all_lanhost[macdata]\
    if lanhost then\
        return {hname = lanhost.hostname, conntype = lanhost.conntype, port = lanhost.port}\
    end\
    return nil\
end\
\
local function set_all(t)\
    if t.send_not_lan then\
        ct.send_not_lan = true\
    elseif t.send_not_lan == false then\
        ct.send_not_lan = false\
    end\
        \
    return {}\
end\
\
local function call_api(t)\
    local result\
    local api = {\
        pppoe = cct.getpppoe,\
        dev = cct.getdevinfo,\
        pon = cct.getponinfo,\
        wlan = cct.getwandev,\
        net = cct.getnetinfo,\
        dns = cct.getdnsserver,\
        devname = cct.getlandevname,\
        lanhost = cct.topogetlanhost,\
        speed = cct.getspeedinfo,\
        accspeed = cct.getaccspeed,\
        odm = cct.odmflag,\
    }\
    if t.func and type(api[t.func]) == \"function\" then\
        result = api[t.func]()\
    end\
\
    if t.func == \"getssid\" and t.port then\
        result = cct.getwandevbyindex(t.port)\
    elseif t.func == \"elink\" then\
        result = cct.getelinkinfo(\"getAllDeviceConfig\", \"(ss)\", \"AllAP\", '[{\"name\":\"real_devinfo\"},{\"name\":\"workmode\"},{\"name\":\"wifi\"},{\"name\":\"channel\"}]')\
    end\
    return result or {}\
end\
\
local function get_stat()\
    return {all_count = ct.all_count, all_len = ct.all_len, send_not_lan = ct.send_not_lan, mintime_get = ct.mintime_get}\
end\
\
function ct.postinit()\
    cthttp.init()\
    if cct.odmflag() == 0 then\
        osgi.init()\
    end\
    getlanhost()\
    getdevinfo()\
    timer.mod(ct.timer_name, ct.period, 0, getlanhost)\
end\
\
actor.action_set(ct.subtype, \"read\", function () return {period = ct.period} end, \"read period\")\
actor.action_set(ct.subtype, \"write\", function (t) if t.period and tonumber(t.period) ~= ct.period then ct.period = tonumber(t.period) timer.mod(ct.timer_name, ct.period, 0, getlanhost) end  return  end, \"read period\")\
actor.action_set(ct.subtype, \"stat\", get_stat, \"read stat count\")\
actor.action_set(ct.subtype, \"set_all\", set_all, [[set ct send_not_lan and mintime_get, {send_not_lan = bool, mintime_get = number}]])\
actor.action_set(ct.subtype, \"get_lan_info\", get_lan_info, \"get lanhost from CAPI\")\
actor.action_set(ct.subtype, \"get_devinfo\", function () return ct.devinfo end, \"get device info from CAPI\")\
actor.action_set(ct.subtype, \"send_osinfo\", send_osinfo, [[send osinfo to DMP, {mac, ip, osid, hostname}]])\
actor.action_set(ct.subtype, \"update\", update, [[set lanhost to CAPI, {mac, osid}, setlanhost: mac modelname brandname dev_type osname devtype userdata}]])\
actor.action_set(ct.subtype, \"ipfilter_show\", ipfilter.ipfilter_show, \"read ipfilter\") \
actor.action_set(ct.subtype, \"ipfilter_add\", ipfilter.ipfilter_add, [[set ipfilter,{proto = string, iface = string, port = number, remoteip = string}, default \"tcp\" \"lan\" 0 \"\"]]) \
actor.action_set(ct.subtype, \"ipfilter_del\", ipfilter.ipfilter_del, [[del one ipfilter, {proto = string, iface = string, port = number, remoteip = string]]) \
actor.action_set(ct.subtype, \"ipfilter_flush\", ipfilter.ipfilter_flush, \"flush ipfilter\") \
actor.action_set(ct.subtype, \"call_api\", call_api, [[get info from CAPI]]) \
actor.action_set(ct.subtype, \"show_topo\", function(t) local _,topo = lcmd_run({subtype = \"topo\", action = \"show_topo\" , active = t.active, sendsig = t.sendsig, stype = t.stype}) return topo end, [[get topo info from CAPI and DBUS, {active = number,date = number}, active 1 means online, data filter last_active_time]])\
actor.action_set(ct.subtype, \"show_topo_tree\", function(t) local _,tree = lcmd_run({subtype = \"topo\", action = \"show_topo_tree\" , active = t.active}) return tree end, [[show topo info as tree struct args is same as show_topo  {active = number,date = number}, active 1 means online, data filter last_active_time]]) \
actor.action_set(ct.subtype, \"show_speed\", function(t) local _,speed = lcmd_run({subtype = \"topo\", action = \"show_speed\", stype = t.stype}) return speed end, [[get speed info from CAPI,lua will calculate]])\
actor.action_set(ct.subtype, \"topo_set\", function (t) local _,set = lcmd_run({subtype = \"topo\", action = \"write\", period = t.period, send_period=t.send_period, send_active_period=t.send_active_period}) return set end, [[change get route period,{period = number,send_period = number, send_active_period = number},default 86400 86400 3600]]) \
actor.action_set(ct.subtype, \"topo_stat\", function (t) local _,stat = lcmd_run({subtype = \"topo\", action = \"read\"}) return stat  end, \"read topo stat\")\
actor.action_set(ct.subtype, \"topo_testset\", function (t) local cjson=require\"cjson\" local _,test = lcmd_run({subtype = \"topo\", action = \"topo_testset\", lanhost = t.lanhost, elinklanhost = t.elinklanhost}) return test end, \"read topo stat\")\
\
return ct\
"
, '@'.."./service/ct/ct.lua" ) )

package.preload[ "ct.cthttp" ] = assert( (loadstring or load)(
"local lhttp = require(\"http\")\
local log = require(\"log\")\
\
local function upload_http_one(v)\
    local tt = {}\
    table.insert(tt, {type = CENUM.COMM_BUSINESS_DMP_HTTP,\
                      sbytes = string.pack(\">c4Hc6IIc4II\", v.ip, 0, v.mac, v.ts_sec, v.ts_usec, v.dstip, v.sport, v.dport)})\
    if v.url then table.insert(tt, {type = CENUM.COMM_BUSINESS_DMP_HTTP_URL, sbytes = v.url}) end\
    if v.ref then table.insert(tt, {type = CENUM.COMM_BUSINESS_DMP_HTTP_REF, sbytes = v.ref}) end\
    if v.ua then table.insert(tt, {type = CENUM.COMM_BUSINESS_DMP_HTTP_UA, sbytes = v.ua}) end\
    if v.cookie then table.insert(tt, {type = CENUM.COMM_BUSINESS_DMP_HTTP_COOKIE, sbytes = v.cookie}) end\
    table.insert(tt, {type =  CENUM.COMM_BUSINESS_DMP_HTTP_METHOD, sbytes = string.pack(\">I\", v.method)})\
\
    local sbytes = \"\"\
    for _, v in ipairs(tt) do\
        sbytes = sbytes .. string.pack(\">HI\", v.type, v.sbytes:len()) .. v.sbytes\
    end\
\
    local all = string.pack(\">I\", sbytes:len()) .. sbytes\
    return all\
end\
\
local function upload_http(http_tables)\
    local http_sbytes = {} count = 0\
    for _, v in ipairs(http_tables) do\
        table.insert(http_sbytes, upload_http_one(v))\
        count = count + 1\
    end\
\
    local send_sbytes = table.concat(http_sbytes)\
    lcmd_run{subtype = \"__svr_data\", action = \"add\", pkttype=CENUM.COMM_BUSINESS_DMP_HTTP, sbytes = send_sbytes, count = count}\
    log.info(\"http send svr data, size\", #send_sbytes)\
    lhttp.all_count = lhttp.all_count + 1\
    lhttp.all_len = lhttp.all_len + string.len(send_sbytes)\
end\
\
local function upload_init()\
    local actor = require(\"luactor\")\
    actor.subscribe(\"HTTP\",\
                    function(msg)\
                        assert(type(msg.http_tables) == \"table\")\
                        if msg.http_period > 0 then\
                            upload_http(msg.http_tables)\
                        end\
                    end\
    )\
end\
\
return {init = upload_init}\
"
, '@'.."./service/ct/cthttp.lua" ) )

package.preload[ "ct.ipfilter" ] = assert( (loadstring or load)(
"local cct = require(\"c.ct\")\
\
local ipfilter = {\
    filters = {}\
}\
\
local function parse_ipfilter(t)\
    proto = \"tcp\"\
    iface = \"lan\"\
    remoteip = \"\"\
    port = 0\
    if t.proto then\
        proto = t.proto\
    end\
    if t.iface then\
        iface = t.iface\
    end\
    if t.port then\
        port = t.port\
    end\
    if t.remoteip then\
        remoteip = t.remoteip\
    end\
\
    return remoteip, proto, port, iface\
end\
\
local function index_ipfilter(t)\
    index = 0\
    for k, v in ipairs(ipfilter.filters) do\
        if v.remoteip == t.remoteip and v.proto == t.proto and v.port == t.port and v.iface == t.iface then\
            index = k\
            break\
        end\
    end\
    return index\
end\
\
function ipfilter.ipfilter_show()\
    return ipfilter.filters\
end\
\
function ipfilter.ipfilter_add(t)\
    remoteip, proto, port, iface = parse_ipfilter(t)\
    onefilter = {remoteip = remoteip, proto = proto, port = port, iface = iface}\
    if index_ipfilter(onefilter) == 0 then\
        if cct.addipfilter(remoteip, proto, port, iface) == 0 then\
            table.insert(ipfilter.filters, onefilter)\
        end\
    end\
    return true\
end\
\
function ipfilter.ipfilter_del(t)\
    remoteip, proto, port, iface = parse_ipfilter(t)\
    onefilter = {remoteip = remoteip, proto = proto, port = port, iface = iface}\
    index = index_ipfilter(onefilter)\
    if index > 0 then\
        if cct.delipfilter(remoteip, proto, port, iface) == 0 then\
            table.remove(ipfilter.filters, index)\
        end\
    end\
    return true\
end\
\
function ipfilter.ipfilter_flush(t)\
    for _, v in ipairs(ipfilter.filters) do\
        cct.delipfilter(v.remoteip, v.proto, v.port, v.iface)\
    end\
    ipfilter.filters = {}\
    return true\
end\
\
return ipfilter\
"
, '@'.."./service/ct/ipfilter.lua" ) )

package.preload[ "ct.osgi" ] = assert( (loadstring or load)(
"local socket = require(\"socket\")\
local msocket = require(\"msocket\")\
local log = require(\"log\")\
local cjson = require(\"cjson\")\
\
local osgi = {\
}\
\
local function osgi_send(s, msg)\
    local buf = string.pack(\">I\", #msg)..msg\
    local cc = coroutine.running()\
    msocket.add(cc, nil, s)\
    coroutine.yield()\
    log.warn(\"will send msg\", buf)\
    local ret, err = msocket.polite_send(s, buf)\
    if err then\
        log.warn(\"Failed to send, err is\", err)\
    end\
    msocket.del(s, true)\
end\
\
local function osgi_recv(s)\
    -- recv head\
    local buf, err = msocket.polite_receive(s, 4)\
    if err then\
        log.warn(\"receive error,\",err)\
        return nil, \"error for receive, err is \"..err\
    end\
\
    local len = string.unpack(\">I\", buf)\
    if len <= 0 or len >= 100000 then\
        log.warn(\"error unpack len:\",len)\
        return nil, \"error unpack len, len is \"..len\
    end\
\
\
    -- recv body\
    buf, err = msocket.polite_receive(s, len)\
    if err then\
        log.warn(\"error receive body len:\",len)\
        return nil, \"error receive body, len is \"..len.. \", err is \"..err\
    end\
    log.warn(\"receive body,\", buf)\
\
    return buf\
end\
\
local function osgi_resp(s)\
    local msg, err = osgi_recv(s)\
    if err then\
        return false, err\
    end\
\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        return false, \"wrong input json msg \"..msg..\", err is \"..t\
    else\
        local m\
        if t and t.method then \
            local tt = {} \
            for k,v in pairs(t) do\
                if k == \"method\" then\
                    if v == \"gettopo\" then\
                        tt[\"type\"] = \"ct\"\
                        tt[\"action\"] = \"show_topo\"\
                    elseif v == \"getrealdata\" then\
                        tt[\"type\"] = \"ct\"\
                        tt[\"action\"] = \"show_speed\"\
                    end\
                else\
                    tt[k] = v\
                end\
            end\
            \
            log.warn(\"will lcmd_run\", cjson.encode(tt))\
            ok, m = lcmd_run(tt)\
            log.warn(\"lcmd_run return\", ok,m)\
        end\
        if not ok then\
            return false, '{\"Result\":-1}'\
        end\
        if m == nil then\
            return true, \"\"\
        end\
        log.warn(\"will cjson encode result\", m)\
        local ok, reply = pcall(cjson.encode, m)\
        log.warn(\"cjson encode result\", reply)\
        if not ok then\
            return false, '{\"Result\":-2}'\
        end\
        return true, reply\
    end\
end\
\
local function server_run(s)\
    s:settimeout(0)\
    local coname = \"osgiclient_fd\"..s:getfd()\
    local osgi = msocket.coroutine_create(coname, 10, \
        function()\
            local ok, msg = osgi_resp(s)\
            msocket.del(s)\
            local t = {}\
            if not ok then\
                t.error = msg\
            else\
                t = msg\
            end\
            osgi_send(s, msg)\
            s:close()\
            msocket.coroutine_exit()\
        end\
    )\
    if not osgi then\
        log.warn(\"Failed to create coroutine \"..coname..\", check coroutinename err\")\
        return\
    end\
    \
    msocket.add(osgi, s)\
    coroutine.yield()\
end\
\
function osgi.init() \
    local t = socket.tcp4() err = nil\
    local backlog = 5\
\
    t:setoption(\"reuseaddr\", true)\
    _, err = t:bind(\"127.0.0.1\",60000)\
    if err then\
        return \"Failed to bind 127.0.0.1:60000\", \", err is \"..err\
    end\
    _, err = t:listen(backlog)\
    if err then\
        return \"Failed to listen 127.0.0.1:60000\", \", err is \"..err\
    end\
    -- coroutine init\
    co = msocket.coroutine_create(\"osgiserver\", 0, \
        function (co)\
            while true do\
                local s = t:accept()\
                server_run(s)\
                coroutine.yield()\
            end\
        end\
    )\
    if not co then\
        return \"Failed to create coroutine osgiserver, check coroutinename err\"\
    end\
    \
    msocket.add(co, t)\
    return nil\
end\
\
return osgi\
"
, '@'.."./service/ct/osgi.lua" ) )

package.preload[ "ct.policy" ] = assert( (loadstring or load)(
"local mystring = require(\"mystring\")\
local cct = require(\"c.ct\")\
local cjson = require(\"cjson\")\
local ct_enable, ct = pcall(require, \"ct\")\
\
local policy = {}\
\
-- action int value\
policy.actint = {\
    continue = 0x00,\
    fin = 0x01,\
    drop = 0x02,\
    dscp = 0x05,\
}\
\
-- check numeric string\
function policy.is_numeric(str)\
    if type(str) == \"string\" and tonumber(str) then\
        return true\
    end\
    return false\
end\
\
-- get current specific time and day of week\
function policy.date_fmt()\
    local date = os.date([[*t]])\
    -- date.wday: Sunday 1, Monday 2, Tuesday 3, Wednesday 4, Thursday 5, Friday 6, Saturday 7\
    local wday = date.wday - 1\
    if wday == 0 then\
        wday = 7\
    end\
    return date, wday\
end\
\
-- time conflict check\
local function check_time_conflict(tbl)\
    for k, v in pairs(tbl) do\
        local stime, etime = v.start_hour, v.end_hour\
        -- 配置全天00:00-24:00不应该有其它配置\
        if stime == 0 and etime == 24 then return true end\
        for index, time in pairs(tbl) do\
            -- 开始和结束时间不在其它范围中\
            if index ~= k and ((stime >= time.start_hour and stime <= time.end_hour) or (etime >= time.start_hour and etime <= time.end_hour)) then\
                return true\
            end\
        end\
    end\
    return false\
end\
\
-- parse and check the time in the format \"00:00-24:00\"\
local function parse_check_daytime(daytime)\
    if type(daytime) ~= \"string\" then return false end\
\
    local t = {}\
    local times = {mystring.split(daytime, \",\")}\
    if #times > 3 then return false end\
    for _, vd in ipairs(times) do\
        local stime, etime = string.match(vd, \"(%d%d):00%-(%d%d):00\")\
        if not stime or not etime then return false end\
        stime = tonumber(stime)\
        etime = tonumber(etime)\
        if etime <= stime or stime < 0 or stime > 24 or etime < 0 or etime > 24 then\
            return false\
        end\
        table.insert(t, {start_hour = stime, end_hour = etime})\
    end\
    if #t > 1 and check_time_conflict(t) then return false end\
    return true, t\
end\
\
-- parse and check the week in the format \"1,2,3,4,5,6,7\"\
local function parse_weekday(weekday)\
    if weekday == \"\" then\
        return {\
            [1] = true,\
            [2] = true,\
            [3] = true,\
            [4] = true,\
            [5] = true,\
            [6] = true,\
            [7] = true\
        }\
    end\
    local t = {}\
    local wday = {mystring.split(weekday, \",\")}\
    for _, vw in ipairs(wday) do\
        local number = tonumber(vw)\
        if number and 1 <= number and number <= 7 then t[number] = true end\
    end\
    return t\
end\
\
-- verification time parameter format\
function policy.parse_time(times)\
    local res = {}\
    if type(times) ~= \"table\" then\
        return false\
    end\
    local weekdays, time = times.weekdays or \"\", times.time or \"\"\
    if time == \"\" then\
        time = \"00:00-24:00\"\
    end\
    local wday = parse_weekday(weekdays)\
    local ok, dtime = parse_check_daytime(time)\
    if not ok then\
        return false\
    end\
    res = {weekdays = wday, time = dtime, windex = 0, tindex = 0, lasttime = 0}\
\
    return true, res\
end\
\
-- check whether the current time is within the policy range\
function policy.check_time(date, wday, times)\
    local time_matched, timeindex = false, 0\
    local weekdays, time = times.weekdays, times.time\
\
    if not weekdays[wday] then\
        return time_matched, nil\
    end\
    for tindex,vd in pairs(time) do\
        if (vd.start_hour == 0 and vd.end_hour == 0) or (vd.start_hour <= date.hour and date.hour < vd.end_hour) then\
            time_matched, timeindex = true, tindex\
            break\
        end\
    end\
\
    return time_matched, timeindex\
end\
\
-- u01 upload\
function policy.send_uniform(subtype, addr, sendtype, array)\
    -- only ct support dbus\
    if not ct_enable then return end\
    if #array > 0 then\
        local send = {__u01_DMP_addr__ = addr, data = array}\
        local sendstr = cjson.encode(send)\
        log.info(\"send uniform from \"..subtype, sendstr)\
        cct.uniformsend(tonumber(sendtype), #sendstr, sendstr)\
        return #sendstr\
    end\
    return 0\
end\
\
return policy"
, '@'.."./service/ct/policy.lua" ) )

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

package.preload[ "dhcp" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local cjson = require(\"cjson\")\
local log = require(\"log\")\
local mime = require(\"mime\")\
local myip = require(\"myip\")\
\
local dhcp = {\
    type = \"dhcp\",\
    subtype = \"dhcp\",\
    help = \"parse dhcp and send to server\",\
    count = 0, \
}\
\
local function is_valid_string(str)\
    if type(str) ~= \"string\" then\
        return false\
    end\
    local bnum\
    for i = 1, #str do\
        bnum = string.byte(str, i)\
        if bnum < 32 then\
            return false\
        end\
    end\
    return true\
end\
\
local function parse_dhcp_option(all_len , sbytes, offset, mac)\
    local value\
    local option_type, next_pos = string.unpack(\"B\", sbytes, offset)\
    if option_type == 255 then  -- END\
        return all_len\
    end\
    local option_len, next_pos = string.unpack(\"B\", sbytes, next_pos)\
\
    assert(all_len >= next_pos + option_len - 1)\
\
    if option_type == 12 then  -- HOSTNAME     \
        value, next_pos = string.unpack(string.format(\"c%d\", option_len), sbytes, next_pos)\
        lcmd_run({subtype = \"osinfo\", action = \"add_sig\", key = \"dhcp_hostname\", value = value, mac = mac, from = \"repeater\"})\
    elseif option_type == 60 then   -- VENDOR\
        value, next_pos = string.unpack(string.format(\"c%d\", option_len), sbytes, next_pos)\
        if is_valid_string(value) then\
            lcmd_run({subtype = \"osinfo\", action = \"add_sig\", key = \"vendor\", value = value, mac = mac, from = \"repeater\"})\
        end\
    else\
        next_pos = next_pos + option_len\
    end\
\
    return next_pos\
end\
\
local function dhcp_get(msg)\
    local data = msg.pcap_tables\
    if type(data) ~= \"table\" or data.dport ~= 67 then\
        return\
    end\
\
    -- local sbytes, err=mime.unb64(data.data)\
    -- if err then\
    --     log.error(\"dhcp wrong base64 code, err is\", err)\
    --     return\
    -- end\
    local sbytes = data.data\
    \
    local len = sbytes:len()\
\
    --client mac  28\
    local offset = data.offset + 28\
    local cmac = string.unpack(\">c6\", sbytes, offset)\
    local fbyte = string.byte(cmac,1)\
    cmac = myip.mac_ntoa(cmac)\
\
    cmac = myip.mac_check(\"\", cmac)\
    if not cmac then\
        return\
    end\
\
    -- dhcp_header   236 + 4\
    offset = data.offset + 240\
    while offset < len do\
        offset = parse_dhcp_option(len, sbytes, offset, cmac)\
    end\
\
    dhcp.count = dhcp.count + 1\
\
    return\
end\
\
\
function dhcp.postinit()\
    actor.subscribe(\"PCAP\", dhcp_get)\
end\
\
actor.action_set(dhcp.subtype, \"stat\", function () return { count = dhcp.count } end, \"read stat\")\
\
return dhcp\
"
, '@'.."./service/dhcp.lua" ) )

package.preload[ "diagnose" ] = assert( (loadstring or load)(
"local actor = require \"luactor\"\
local dpi = require \"svrcomm.dpi\"\
local log = require \"log\"\
\
local diagnose = {\
    type = \"diagnose\",\
    subtype = \"diagnose\",\
    help = \"diagnose\",\
}\
\
local function start(t)\
    if type(t) ~= \"table\" or type(t.addr) ~= \"string\" then\
        return\
    end\
    dpi.longconn_start(t.addr, t.ssl)\
end\
\
local function stop()\
    dpi.longconn_stop()\
end\
\
local function show()\
    return dpi.longconn_show()\
end\
\
actor.action_set(diagnose.subtype, \"start\", start, 'start diagnose, {addr = \"domain:port\"}')\
actor.action_set(diagnose.subtype, \"stop\", stop, \"stop diagnose\")\
actor.action_set(diagnose.subtype, \"show\", show, \"show diagnose stat\")\
\
return diagnose\
"
, '@'.."./service/diagnose.lua" ) )

package.preload[ "dmpapp" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local timer = require\"timer\"\
local kernel = require\"c.kernel\"\
local myip = require\"myip\"\
local cjson = require\"cjson\"\
local log = require\"log\"\
local dmpapp = {\
    type = \"__dmp_app\", \
    subtype = \"__dmp_app\", \
    help = \"get app from kernel, send to server\",\
    period = 0,\
\
    -- stat\
    all_len = 0,\
    all_count = 0,\
\
    kernel_get_period = 60,\
    timer_name = \"dmpapp_upload\",\
    merge_max_cnt = 1024,\
    merge_info = {\
        -- mac_appid\
            --mac\
            --ip\
            --appid\
            --hit_cnt\
    },\
    merge_info_cnt = 0,\
}\
\
local function dmpapp_get_one(sbytes, pos, len)\
    assert(pos + 55 <= len)\
    local ip = string.sub(sbytes, pos, pos + 3)\
    local mac = string.sub(sbytes, pos + 20, pos + 25)\
    local _, appid, rule_id, baseid, _ = string.unpack(\"=HIIHH\", sbytes, pos + 26)\
\
--    if app_real ~= 0 then\
--        appid = appid | 0x80000000\
--    end\
    if appid <= 0 then\
        appid = baseid\
    end\
    return 56, ip, mac, appid, rule_id\
end\
\
local function upload_app()\
    local send = false\
    local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
    for _, tt in pairs(dmpapp.merge_info) do\
        send = true\
        tt.type = \"app_daily\"\
        tt.period = dmpapp.period\
        local osinfo = oss[tt.mac] or {}\
        tt.osid = osinfo.decide_osid or osinfo.cloud_osid or 0\
        log.info(\"app send to svr, \", cjson.encode(tt))\
        lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tt})\
        dmpapp.all_len = dmpapp.all_len + string.len(cjson.encode(tt))\
    end\
    if send then\
        dmpapp.all_count = dmpapp.all_count + 1\
    end\
    dmpapp.merge_info_cnt = 0\
    dmpapp.merge_info = {}\
end\
\
local function merge_app_info(ip, mac, appid, rule_id)\
    if dmpapp.period <= 0 then\
        return\
    end\
    local mac = myip.mac_ntoa(mac) \
    local ip = myip.inet_ntoa(ip)\
    local key = mac..\"_\"..appid\
    if not dmpapp.merge_info[key] then\
        local time = tostring(os.time())\
        dmpapp.merge_info[key] = {mac = mac, ip = ip, appid = appid, hit_cnt = 1, time = time, source = rule_id}\
        dmpapp.merge_info_cnt = dmpapp.merge_info_cnt + 1\
        if dmpapp.merge_info_cnt >= dmpapp.merge_max_cnt then\
            upload_app()\
        end\
    else\
        local one = dmpapp.merge_info[key]\
        one.hit_cnt = one.hit_cnt + 1\
    end\
end\
\
local function dmpapp_get(sbytes)\
    local len, used_len = sbytes:len(), 0\
\
    while used_len < len do\
        local one_size, ip, mac, appid, rule_id = dmpapp_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
        merge_app_info(ip, mac, appid, rule_id)\
    end\
\
    assert(used_len == len)\
    return len\
end\
\
local function write(t)\
    local timer_update = false\
    if type(t.kernel_get_period) == \"number\" and t.kernel_get_period ~= dmpapp.kernel_get_period then\
        dmpapp.kernel_get_period = t.kernel_get_period\
        timer_update = true\
    end\
    if type(t.period) == \"number\" and t.period ~= dmpapp.period then\
        dmpapp.period = t.period\
        timer.mod(dmpapp.timer_name, dmpapp.period, 0, upload_app)\
        timer_update = true\
    end\
    if timer_update then\
        if dmpapp.period > 0 then\
            kernel.set_engine(CENUM.ENGINE_TYPE_APP_STAT, 1)\
            timer.mod(\"dmpapp\", dmpapp.kernel_get_period, 0, function() kernel.call(CENUM.MEMSHR_K2U_STAT, \"\", dmpapp_get) end)\
        else\
            kernel.set_engine(CENUM.ENGINE_TYPE_APP_STAT, 0)\
            timer.mod(\"dmpapp\", 0, 0, function() kernel.call(CENUM.MEMSHR_K2U_STAT, \"\", dmpapp_get) end)\
        end\
    end\
    if type(t.merge_max_cnt) == \"number\" then\
        dmpapp.merge_max_cnt = t.merge_max_cnt\
    end\
end\
\
function dmpapp.postinit()\
    timer.mod(dmpapp.timer_name, dmpapp.period, 0, upload_app)\
end\
\
actor.action_set(dmpapp.subtype, \"write\", write, \"{period = xx}, set dmpapp period\")\
actor.action_set(dmpapp.subtype, \"read\", function() return {period = dmpapp.period, send_period = dmpapp.send_period, merge_max_cnt = dmpapp.merge_max_cnt, kernel_get_period = dmpapp.kernel_get_period} end, \"get dmpapp period\")\
actor.action_set(dmpapp.subtype, \"stat\", function() return {all_count = dmpapp.all_count,all_len = dmpapp.all_len} end, \"get dmpapp stat\")\
actor.action_set(dmpapp.subtype, \"show\", function() return dmpapp.merge_info end, \"get dmpapp merge info\")\
return dmpapp\
"
, '@'.."./service/dmpapp.lua" ) )

package.preload[ "dns" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local cjson = require(\"cjson\")\
local myip = require(\"myip\")\
\
local dns = {\
    type = \"dns\",\
    subtype = \"dns\",\
    help = \"get dns from pcap\",\
    upload_type = \"dns_info_v2\",\
    period = 0,\
    all_count = 0,\
    all_len = 0,\
    pub_cnt = 0,\
    sindex = nil,\
}\
\
local function dns_get_queries(sbytes, offset, len)\
    local tt = {}\
    local pos = 0\
    while pos < (len-offset) do\
        section = string.byte(sbytes, pos+offset)\
        if section == 0 then\
            break\
        end\
        table.insert(tt, string.sub(sbytes, pos+offset+1, pos+offset+section))\
        pos = pos + section + 1\
    end\
\
    local domain = table.concat(tt, '.')\
    local qtype, qclass = string.unpack(\">HH\", sbytes, offset+pos+1)\
    return domain, qtype, qclass, pos+5\
end\
\
local function dns_get_ips(sbytes, dnstable)\
    local ips = {}\
    for i = 1, dnstable.answersNum do\
        local _, atype, aclass, timetl, datalen = string.unpack(\">HHHc4H\", sbytes, dnstable.offset)\
        if atype == 1 and aclass == 1 and datalen == 4 then\
            local one = string.unpack(\">c4\", sbytes, dnstable.offset+12)\
            one = myip.inet_ntoa(one)\
            table.insert(ips, one)\
        end\
        dnstable.offset = dnstable.offset + 12 + datalen\
    end\
    return ips\
end\
\
local function dns_get_one(sbytes, dnstable)\
    if dnstable.flsgs>>15 ~= 1 or dnstable.flsgs&0x0f ~= 0 or dnstable.answersNum == 0 then\
        return\
    end\
\
    local ips = dns_get_ips(sbytes, dnstable)\
\
    -- add appid\
    local _, ruleid = lcmd_run({action = \"match\", subtype = \"appsig_bin\", stype = \"domain\", value = dnstable.domain})\
    local _, desc = lcmd_run({action = \"get_desc\", subtype = \"appsig_bin\", ruleid = ruleid})\
    dnstable.appid = desc.appid or 0\
    local tt = {\
        type = dns.upload_type,\
        mac = dnstable.mac,\
        user_ip = dnstable.user_ip,\
        server_ip = dnstable.server_ip,\
        domain = dnstable.domain,\
        ip = table.concat(ips, \",\")\
    }\
    actor.publish({msgtype = \"DNS\", dnstable = dnstable, ips = table.concat(ips, \",\")})\
    dns.pub_cnt = dns.pub_cnt +1\
    if dns.period > 0 then\
        lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tt})\
        dns.all_count = dns.all_count + 1\
        dns.all_len = dns.all_len + string.len(cjson.encode(tt))\
    end\
end\
\
local function dns_get(msg)\
    local pcap_tables = msg.pcap_tables\
    if type(pcap_tables) ~= \"table\" or pcap_tables.proto ~= 17 or pcap_tables.sport ~= 53 then\
        return\
    end\
    \
    local sbytes = pcap_tables.data\
    local dnsdata = {\
        mac = pcap_tables.mac,\
        user_ip = pcap_tables.dip,\
        server_ip = pcap_tables.sip,\
        offset = pcap_tables.offset,\
        sport = pcap_tables.sport,\
        dport = pcap_tables.dport,\
        timestamp = pcap_tables.timestamp,\
    }\
    local len = sbytes:len()\
    dnsdata.transActionId, dnsdata.flsgs, dnsdata.questionsNum, dnsdata.answersNum = string.unpack(\">HHHH\", sbytes, dnsdata.offset)\
    dnsdata.offset = dnsdata.offset + 12\
    dnsdata.domain, dnsdata.qtype, dnsdata.qclass, qoffset = dns_get_queries(sbytes, dnsdata.offset, len)\
    dnsdata.offset = dnsdata.offset + qoffset\
    \
    if dnsdata.questionsNum ~= 1 or dnsdata.qtype ~= 1 or dnsdata.qclass ~= 1 then\
        return\
    end\
    dns_get_one(sbytes, dnsdata)\
end\
\
local function write(t)\
    if type(t.period) == \"number\" and t.period ~= dns.period then\
        dns.period = t.period\
    end\
end\
\
function dns.postinit()\
    dns.sindex = actor.subscribe(\"PCAP\", dns_get)\
end\
\
function dns.finish()\
    if dns.sindex then\
        actor.unsubscribe(\"PCAP\", dns.sindex)\
    end\
end\
\
actor.action_set(dns.subtype, \"read\", function () return {period = dns.period} end, \"read dns configs\")\
actor.action_set(dns.subtype, \"write\", write, \"set dns period, period = 0 means close dns module\")\
actor.action_set(dns.subtype, \"stat\", function () return {all_len = dns.all_len, all_count = dns.all_count, pub_cnt = dns.pub_cnt} end, \"read dns stat \")\
return dns\
"
, '@'.."./service/dns.lua" ) )

package.preload[ "dnscache" ] = assert( (loadstring or load)(
"local timer = require\"timer\"\
\
local dnscache = {\
    tname = \"dcache_refresh\", \
}\
\
-- cacheglobal will be set by dnscache.new().\
-- here, set default value to avoid error when someone get dns before dnscache.new() run.\
local cacheglobal = { max = 10, cycle = 86400, cnt = 0, dnses = {} }\
\
-- using table(key is dns) to store all DNS, value is following:\
--\
-- ip, the first IP for dns\
-- last, the lastime of get/set for this dns\
-- refresh, the lasttime of getaddrinfo for this dns\
--\
-- getcnt, dns get count \
-- refreshcnt, refresh dns count\
\
local function dcache_random_time(now, cycle)\
    return now + math.random(cycle, cycle*2)\
end\
\
local function dcache_dec(dcache, delcnt)\
    if dcache.cnt < delcnt or delcnt <= 0 then return end\
    \
    local tt = {}\
    for k, v in pairs(dcache.dnses) do \
        table.insert(tt, {v = v, k = k})\
    end\
\
    table.sort(tt, \
               function(a, b)\
                   return a.v.last < b.v.last\
               end\
    )\
\
    for i = 1, delcnt do\
        local delkey = tt[i].k\
        dcache.dnses[delkey] = nil\
        log.info(\"del_key is \", del_key)\
    end\
    dcache.cnt = dcache.cnt - delcnt\
end\
\
local function dcache_set(dcache, dns, ip)\
    if dns == ip then\
        return                  -- no need to set for only IP\
    end\
\
    local nn = os.time()\
    if dcache.dnses[dns] then\
        dcache.dnses[dns].last = nn\
        return\
    end\
\
    -- del old item if full\
    if dcache.cnt >= dcache.max then\
        dcache_dec(dcache, dcache.cnt - dcache.max + 1)\
    end\
\
    dcache.dnses[dns] = {ip = ip, last = nn, refresh = dcache_random_time(nn, dcache.cycle), getcnt = 0, refreshcnt = 0}\
    dcache.cnt = dcache.cnt + 1\
end\
\
local function getaddr(dns)\
    local socket = require\"socket\"\
    local cc = socket.dns.getaddrinfo(dns)\
    if not cc or #cc == 0 or not cc[1].addr then\
        log.info(\"failed to find dns \", dns)\
        return nil\
    else\
        log.info(\"find dns \", dns, \"for ip, \", cc[1].addr)\
        return cc[1].addr           -- using first address\
    end\
end\
\
local function dcache_get(dcache, dns)\
    if dcache.dnses[dns] then\
        dcache.dnses[dns].last = os.time()\
        dcache.dnses[dns].getcnt = dcache.dnses[dns].getcnt + 1\
        return dcache.dnses[dns].ip\
    else\
        return getaddr(dns)\
    end\
end\
\
local function dcache_refresh(dcache)\
    local nn = os.time()\
    for k, v in pairs(dcache.dnses) do\
        if v.refresh < nn or v.refresh - nn > 86400 * 30 then\
            local ip = getaddr(k)\
            if ip then\
                v.ip = ip\
            end\
            v.refresh = dcache_random_time(nn, dcache.cycle)\
            v.refreshcnt = v.refreshcnt + 1\
        end\
    end\
end\
\
function dnscache.restart(max, cycle)\
    if type(max) == \"number\" and max ~= cacheglobal.max then\
        dcache_dec(cacheglobal, cacheglobal.cnt - max)\
        cacheglobal.max = max\
    end\
\
    if type(cycle) == \"number\" and cycle ~= cacheglobal.cycle then\
        local cinterval = cycle/10\
        if cinterval <= 0 then\
            cinterval = 1\
        end\
\
        cacheglobal.cycle = cycle\
        cacheglobal.cinterval = cinterval\
\
        dcache_dec(cacheglobal, cacheglobal.cnt) -- flush cache when cycle changed\
        timer.mod_notdisable(dnscache.tname, cinterval, 0, dcache_refresh, cacheglobal)\
    end\
end\
\
function dnscache.get_set(addr)\
    local dns, port\
    local delim_index = string.find(addr, \":\")\
    if type(delim_index) == \"number\" and delim_index > 1 then\
        dns = string.sub(addr, 1, delim_index - 1)\
        port = string.sub(addr, delim_index + 1, -1)\
    else\
        dns = addr\
    end\
    local ip = dcache_get(cacheglobal, dns)\
    if not ip then\
        return nil\
    end\
    \
    dcache_set(cacheglobal, dns, ip)\
    return ip..\":\"..port\
end\
\
function dnscache.stat()\
    return cacheglobal\
end\
\
function dnscache.new(max, cycle)\
    local cinterval = cycle/10\
    if cinterval <= 0 then\
        cinterval = 1\
    end\
    cacheglobal = {max = max, cycle = cycle, cinterval = cinterval, cnt = 0, dnses = {}}\
    timer.mod_notdisable(dnscache.tname, cinterval, 0, dcache_refresh, cacheglobal)\
end\
\
return dnscache\
"
, '@'.."./lualib/dnscache.lua" ) )

package.preload[ "domain_dip" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local myip = require\"myip\"\
local timer = require\"timer\"\
local mystring = require\"mystring\"\
local cjson = require\"cjson\"\
local log = require\"log\"\
local myutil = require\"myutil\"\
\
local domain_dip = {\
    subtype=\"domain_dip\",\
    type=\"domain_dip\",\
    help=\"send domain and dip to server\",\
\
    uptimer_name=\"domaindip_send\",\
    quptimer_name=\"domainip_send_quickly\",\
    checktimer_name=\"domainip_check\",\
    upperiod = 14400,\
    qupperiod = 10,\
\
    max_sigcnt = 512,\
    max_macnt = 100,\
    oss = {\
        -- mac\
          -- firsttime\
          -- lasttime\
          -- sigs\
          -- isnewdev\
    },\
    macs = {},\
    sindex = 0,\
    conf = {\
        domain = {\"smarthome.ctdevice.ott4china.com\",\"d.rsdznjj.com.cn\",\"l.rsdznjj.com.cn\",\"iotpaprd.angelgroup.com.cn\",\"zhy.znznz.cn\",\"post-cn-0pp1ebxgn04.mgtt.aliyuncs.com\",\"iot1.midea.com.cn\",\"beli.china.app.cloud.tenda.com.cn\",\"beli.valley.app.cloud.tenda.com.cn\"}, \
        domain_suffix = {\"tcljd.com\"},\
        dip = {\"223.255.253.3\",\"223.255.253.17\",\"223.255.253.18\",\"223.255.253.19\",\"223.255.253.20\",\"223.255.253.21\",\"223.255.253.22\",\"101.37.192.77\"}\
    },\
    data_cnt = 0,\
    data_len = 0,\
}\
\
local function sig_deal(addr, action, msg)\
    if not msg or msg == \"\" then\
        log.info(string.format(\"ignore empty msg, action 0x%x\", action))\
        return\
    end\
    log.info(string.format(\"receive %s server, action 0x%x, msg(%s)\", addr, action, msg))\
\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        log.error(string.format(\"failed json decode msg(%s), err(%s)\", msg, t))\
        return\
    end\
    if type(t) ~= \"table\" then\
        log.info(string.format(\"ignore empty json or not table for msg(%s)\", msg))\
        return\
    end\
    lcmd_run(t)\
end\
\
local function inarr(s, arr)\
    for _, v in ipairs(arr) do\
        if v == s then\
            return true\
        end\
    end\
    return false\
end\
\
local function find_suffix(s, arr)\
    for _, v in ipairs(arr) do\
        if string.match(s, v..\"$\") then\
            return true, v\
        end\
    end\
    return false\
end\
\
local function add_sig(mac, domainip, time, findsmtdev)\
    local oss = domain_dip.oss\
    if not oss[mac] and findsmtdev and domain_dip.max_macnt > 0 then  -- find smtdev need add mac\
        table.insert(domain_dip.macs, mac)\
        -- del old mac\
        if #domain_dip.macs > domain_dip.max_macnt then\
            local delmac = domain_dip.macs[1]\
            oss[delmac] = nil\
            table.remove(domain_dip.macs, 1)\
        end\
        -- add new mac\
        oss[mac] = {firsttime = time, lasttime = time, isnewdev = true, sigs = {domainip}}\
    elseif oss[mac] then\
        if findsmtdev then\
            oss[mac].lasttime = time\
        end\
        if not inarr(domainip, oss[mac].sigs) and time - oss[mac].lasttime <= domain_dip.qupperiod and #oss[mac].sigs < domain_dip.max_sigcnt then\
            table.insert(oss[mac].sigs, domainip)\
        end\
    else\
        return\
    end\
end\
\
local function add_one(domain, dip, mac, time)\
    local domainip = string.format(\"%s:%s\", domain or \"\", dip or \"\")\
    local ok, domain_suffix = find_suffix(domain, domain_dip.conf.domain_suffix)\
    if ok then\
        domainip = string.format(\"%s:%s\", domain_suffix or \"\", dip or \"\")\
    end\
    if inarr(domain, domain_dip.conf.domain) or ok or inarr(dip, domain_dip.conf.dip) then\
        add_sig(mac, domainip, time, true)   -- add smtdev sig            \
    else\
        add_sig(mac, domainip, time, false)  -- add other sig within 10 seconds \
    end\
end\
\
local function collect_http(msg)\
    local time = os.time()\
    for k,v in pairs(msg.http_tables) do\
        local mac = mystring.data2hex(v.mac, \":\")\
        local domain = myutil.urlsplit(v.url)\
        local dip = myip.inet_ntoa(v.dstip)\
        add_one(domain, dip, mac, time)\
    end\
end\
\
local function collect_https(msg)\
    local time = os.time()\
    local https = msg.https_table\
    if type(https) ~= \"table\" then\
        return\
    end\
    add_one(https.domain, https.dip, https.mac, time)\
end\
\
local function sig_upload(isnewdev)\
    local data = {}\
    local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
    local time = os.time()\
    for k,v in pairs(domain_dip.oss) do\
        if #v.sigs > 0 and (isnewdev == false or (v.isnewdev == true and time - v.firsttime >= domain_dip.qupperiod)) then\
            local info = oss[k] or {}\
            local siginfo ={mac = k, osid = info.decide_osid or info.cloud_osid or 0, iscloud = info.iscloud or 0, acc_type = info.acc_type or -1, acc_port = info.acc_port or -1, elink_type = info.cloud_elinktype or -1, sigs = {{type = \"domain_ip\", data=v.sigs}}}\
\
            -- test\
            if domain_dip.testsig then\
                table.insert(siginfo.sigs,domain_dip.testsig)\
            end\
\
            table.insert(data, siginfo)\
            local os = domain_dip.oss[k]\
            os.isnewdev = false\
            os.sigs = {}\
        end\
    end\
    if #data > 0 then\
        log.info(\"domain_dip send\",cjson.encode(data))\
        lcmd_run({subtype = \"__svr_oper\", action = \"oper_raw\", action_type = CENUM.COMM_ACTION_DEVOPS_DPI_SIGCOLLECT_UPDATE, data = data, recvcall = sig_deal})\
        domain_dip.data_cnt = domain_dip.data_cnt + 1\
        domain_dip.data_len = domain_dip.data_len + string.len(cjson.encode(data))\
    end\
end\
\
local function write(t)\
    if t.upperiod and tonumber(t.upperiod) ~= domain_dip.upperiod then\
        domain_dip.upperiod = tonumber(t.upperiod)\
        timer.mod(domain_dip.uptimer_name, domain_dip.upperiod, 0, sig_upload, false)\
    end\
    if t.qupperiod and tonumber(t.qupperiod) ~= domain_dip.qupperiod then\
        domain_dip.qupperiod = tonumber(t.qupperiod)\
        timer.mod(domain_dip.quptimer_name, domain_dip.qupperiod, 0, sig_upload, true)\
    end\
    if type(t.max_sigcnt) == \"number\" then\
        domain_dip.max_sigcnt = t.max_sigcnt\
    end\
    if type(t.max_maccnt) == \"number\" then\
        domain_dip.max_maccnt = t.max_maccnt\
    end\
    if type(t.domain) == \"table\" then\
        domain_dip.conf.domain = t.domain\
    end\
    if type(t.domain_suffix) == \"table\" then\
        domain_dip.conf.domain_suffix = t.domain_suffix\
    end\
    if type(t.dip) == \"table\" then\
        domain_dip.conf.dip = t.dip\
    end\
end\
\
function domain_dip.postinit()\
    domain_dip.httpindex = actor.subscribe(\"HTTP\", collect_http)\
    domain_dip.httpsindex = actor.subscribe(\"HTTPS\", collect_https)\
    timer.mod(domain_dip.uptimer_name, domain_dip.upperiod, 0, sig_upload, false)\
    timer.mod(domain_dip.quptimer_name, domain_dip.qupperiod, 0, sig_upload, true)\
end\
\
function domain_dip.finish()\
    if domain_dip.httpindex then\
        actor.unsubscribe(\"domain_dip\", domain_dip.httpindex)\
    end\
    if domain_dip.httpsindex then\
        actor.unsubscribe(\"domain_dip\", domain_dip.httpsindex)\
    end\
    timer.del(domain_dip.uptimer_name)\
    timer.del(domain_dip.quptimer_name)\
end\
\
actor.action_set(domain_dip.subtype, \"show\", function () return domain_dip.oss end, \"show domain_ip\")\
actor.action_set(domain_dip.subtype, \"stat\", function () return {data_cnt = domain_dip.data_cnt, data_len = domain_dip.data_len} end, \"domain_ip stat\")\
actor.action_set(domain_dip.subtype, \"flush\", function () domain_dip.oss = {} return end, \"flush domain_ip\")\
actor.action_set(domain_dip.subtype, \"read\", function () return {conf = domain_dip.conf, upperiod = domain_dip.upperiod, qupperiod = domain_dip.qupperiod, max_sigcnt = domain_dip.max_sigcnt, max_macnt = domain_dip.max_macnt} end, \"read conf\")\
actor.action_set(domain_dip.subtype, \"write\", write, \"write conf,{upperiod = number, qupperiod = number, max_sigcnt = number, max_macnt = number, domain = list, dip = list, domain_suffix = list}\")\
return domain_dip\
"
, '@'.."./service/domain_dip.lua" ) )

package.preload[ "dpinfo" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local log = require\"log\"\
local kernel = require\"c.kernel\"\
local myfile = require\"myfile\"\
local mystring = require\"mystring\"\
local sys = require\"sys\"\
\
local dpinfo = {\
    type = \"__dpi_info\", \
    subtype = \"__dpi_info\", \
    help = \"show some base info, only read\", \
\
    -- var\
    ccnt = 0, \
    pcnt = 0, \
\
    create_cnt = 0,\
    destroy_cnt = 0,\
}\
\
local function kernel_cnt_get(sbytes)\
    local len = sbytes:len()\
    local ccnt, pcnt, ctx_ccnt, ctx_dcnt, nnext = string.unpack(\"=jjjj\", sbytes)\
    if len + 1 ~= nnext then\
        log.error(\"wrong format kernel_cnt result\")\
        return len\
    end\
\
    dpinfo.ccnt = ccnt\
    dpinfo.pcnt = pcnt\
    dpinfo.create_cnt = ctx_ccnt\
    dpinfo.destroy_cnt = ctx_dcnt\
    return len\
end\
\
local function dpi_stat()\
    local _,sys_uptime = lcmd_run({type = \"sys\", action = \"sys_uptime\"})\
    local _,dpi_uptime = lcmd_run({type = \"sys\", action = \"dpi_uptime\"})\
    local _,sys_stime = lcmd_run({type = \"sys\", action = \"sys_stime\"})\
    local _,dpi_stime = lcmd_run({type = \"sys\", action = \"dpi_stime\"})\
    --local _, boottime = lcmd_run({type = \"sys\", action = \"boottime\"})\
    kernel.call(CENUM.USR_KNL_ENGINE_STAT_GET, \"\", kernel_cnt_get)\
    return {sys_uptime = tostring(sys_uptime) or \"\", dpi_uptime = tostring(dpi_uptime) or \"\",\
            sys_stime = sys_stime or \"\", dpi_stime = dpi_stime or \"\",\
            deal_ctx_count = dpinfo.ccnt, deal_pkt_count = dpinfo.pcnt,\
            ctx_create_count = dpinfo.create_cnt, ctx_destroy_count = dpinfo.destroy_cnt}\
end\
\
local function read()\
    local _, arch = lcmd_run({type = \"arch\", action = \"read\"})\
    local _, svrdata_stat = lcmd_run({type = \"__svr_data\", action = \"read_stat\"})\
    local tt = {}\
    tt.base_info = arch\
    tt.engine_info = kernel.get_engine()\
    tt.dpi_stat = dpi_stat()\
    tt.svr_data = svrdata_stat\
\
    return tt\
end\
\
actor.action_set(dpinfo.subtype, \"read\", read, \"read statistic info\")\
actor.action_set(dpinfo.subtype, \"kernel_cnt\", \
                 function () \
                     kernel.call(CENUM.USR_KNL_ENGINE_STAT_GET, \"\", kernel_cnt_get) \
                     return {ccnt = dpinfo.ccnt, pcnt = dpinfo.pcnt, ctx_create_count = dpinfo.create_cnt, ctx_destroy_count = dpinfo.destroy_cnt}\
                 end, \
                 \"get kernel cnt, ccnt(conntrack cnt), pcnt(packet cnt), create_cnt and destroy_cnt\")\
return dpinfo\
"
, '@'.."./service/dpinfo.lua" ) )

package.preload[ "dumh" ] = assert( (loadstring or load)(
"\
local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local actor = require(\"luactor\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local mystring = require(\"mystring\")\
\
\
local dumh = {\
    type = \"dumh\",\
    subtype = \"dumh\",\
    help = \"dumh\",\
\
    envp = {\
        \"PATH=/sbin:/bin:/usr/sbin:/usr/bin\",\
        \"LD_LIBRARY_PATH=/lib:/usr/lib/glib-2.0:/usr/lib\",\
    },\
\
    variables_timer_name = \"dumh_variables\",\
    variables = {\
        [\"<$OUI>\"] = \"\",\
        [\"<$SN>\"] = \"\",\
    },\
\
    laststatus = {\
        -- cmd,\
        -- ret,\
        -- ts,\
        -- usesh,\
    },\
}\
\
\
local function get_variables()\
    local _, arch = lcmd_run({type = \"arch\", action = \"read\"})\
    dumh.variables[\"<$OUI>\"] = arch.oui\
    dumh.variables[\"<$SN>\"] = arch.sn\
 \
    for _, v in pairs(dumh.variables) do\
        if #v == 0 then\
            timer.mod(dumh.variables_timer_name, 60, 1, get_variables)\
            break\
        end\
    end\
end\
\
local function replace_variable(cmd)\
    local s = cmd\
    for k, v in pairs(dumh.variables) do\
        s = string.gsub(s, k, v)\
    end\
    return s\
end\
\
--[[ local function check_sh_is_needful(cmd)\
    if string.sub(cmd, 1, 1) ~= \"/\"\
        or string.find(cmd, \">\", 1) ~= nil\
        or string.find(cmd, \";\", 1) ~= nil\
    then\
        return true\
    end\
\
    return false\
end --]]\
\
local function execve_get_result(sbytes)\
    assert(sbytes:len() >= 4)\
\
    local ret_code = string.unpack('=i', sbytes, 1)\
    dumh.laststatus.ret = ret_code\
    return sbytes:len()\
end\
\
local function execve(msg)\
    if type(msg.cmd) ~= \"string\" then\
        log.error(\"cmd is invalid\")\
        return\
    end\
\
    local str\
    local shflag\
    local cmd = replace_variable(mystring.trim(msg.cmd))\
    if type(msg.usesh) == \"boolean\" and not msg.usesh then\
        shflag = 0\
        str = cmd\
    else\
        shflag = 1\
        str = table.concat({\"/bin/sh\",\"-c\",\"if [ -f /etc/profile ]; then source /etc/profile; fi; \"..cmd}, \"\\0\")\
        --str = table.concat({\"/bin/sh\",\"-l\",\"-c\",cmd}, \"\\0\")  --  -l == --login\
    end\
\
    dumh.laststatus = { cmd = cmd , ts = os.time(), usesh = shflag ~= 0 and true or false}\
\
    local len = str:len()\
    local data = string.pack(\"=IIc\"..len, shflag, len, str)\
    data = string.pack(\"=Ic\"..data:len(), data:len() + 4, data)\
    kernel.call(CENUM.MEMSHR_DUMH_EXECVE_CMD, data, execve_get_result)\
end\
\
local function update_envp_to_kernel(envp)\
    local str = table.concat(envp, \"\\0\")\
    local len = str:len()\
    local data = string.pack(\"=Ic\"..len, len, str)\
    data = string.pack(\"=Ic\"..data:len(), data:len() + 4, data)\
    kernel.send(CENUM.MEMSHR_DUMH_SET_ENVP, data)\
end\
\
local function write(msg)\
    if type(msg.envp) == \"table\" then\
        dumh.envp = msg.envp\
        update_envp_to_kernel(dumh.envp)\
    end\
end\
\
local function read()\
    return { envp = dumh.envp }\
end\
\
local function stat()\
    return { variables = dumh.variables, laststatus = dumh.laststatus }\
end\
\
function dumh.postinit()\
    get_variables()\
    update_envp_to_kernel(dumh.envp)\
end\
\
actor.action_set(dumh.subtype, \"execve\", execve, [[run cmd, { cmd = string}]])\
actor.action_set(dumh.subtype, \"write\", write, [[set dumh, { envp = [\"\", \"\", ...]}]])\
actor.action_set(dumh.subtype, \"read\", read, \"read dumh conf\")\
actor.action_set(dumh.subtype, \"stat\", stat, \"read dumh stat\")\
\
return dumh\
\
"
, '@'.."./service/dumh.lua" ) )

package.preload[ "hotpatch" ] = assert( (loadstring or load)(
"local mylog = require(\"log\")\
local actor = require(\"luactor\")\
local mime = require(\"mime\")\
\
local hotpatch = {\
    type = \"hotpatch\",\
    subtype = \"hotpatch\",\
    help = \"hot fixbug, and hot add more function\",\
\
    seed = \"0\",\
    codes = {}, \
}\
\
local function hotpatch_save(subtype, rcode, codes)\
    if codes[subtype] then\
        log.warn(\"replace subtype \"..subtype..\" code\")\
    end\
\
    codes[subtype] = rcode\
end\
\
local function delete(subtype)\
    if type(subtype) == \"string\" then\
        log.warn(\"delete subtype \"..subtype)\
        local old_module = package.loaded[subtype]\
\
        if old_module then\
            if type(old_module.finish) == \"function\" then\
                old_module.finish()\
            end\
            actor.actor_del(subtype)\
            package.loaded[subtype] = nil\
        end\
\
        if hotpatch.codes[subtype] then\
            hotpatch.codes[subtype] = nil\
        end\
    end\
end\
\
local function reload_code(code)\
    local rcode, err = mime.unb64(code)\
    if err then\
        log.error(\"Wrong base64 code, err is\", err)\
        return nil\
    end\
    log.debug(\"rcode is \", rcode)\
\
    local ff, err = load(rcode)\
    if not ff then\
        log.error(\"failed to load, err is \", err, \"rcode is \", rcode)\
        return nil\
    end\
    local service = ff()\
    if type(service) ~= \"table\" then\
        log.error(\"Wrong type code, \", type(service))\
        return nil\
    end\
\
    if type(service.subtype) ~= \"string\" then\
        log.error(\"No subtype code\")\
        return nil\
    end\
\
    if package.loaded[service.subtype] then\
        delete(service.subtype)\
        -- if service have actor.action_set(), these actions has been deleted.\
        -- need reload\
        service = ff()\
        if type(service) ~= \"table\" or type(service.subtype) ~= \"string\" then\
            log.error(\"never happen\")\
            return nil\
        end\
    else\
        delete(service.subtype)\
    end\
    package.loaded[service.subtype] = service\
    actor.actor_add(service)\
    local err = actor.post_init()\
    if err then\
        delete(service.subtype)\
        return nil\
    end\
\
    log.info(\"reload subtype\", service.subtype)\
    return service.subtype, rcode\
end\
\
local function flush()\
    for subtype, _ in pairs(hotpatch.codes) do\
        delete(subtype)\
    end\
end\
\
local function reload(t)\
    if type(t.args) ~= \"table\" then\
        return\
    end\
    \
    if type(t.seed) == \"string\" then\
        if t.seed == hotpatch.seed then\
            log.warn(\"same seed, donnot reload code\")\
            return\
        else\
            hotpatch.seed = t.seed\
            flush()\
        end\
    end\
    \
    for k, v in pairs(t.args) do\
        if type(v) == \"string\" then\
            local status, ss, rcode = pcall(reload_code, v)\
            if not status then \
                log.error(\"failed to call, error is: \", ss)\
            elseif ss and rcode then\
                hotpatch_save(ss, rcode, hotpatch.codes)\
            end\
        end\
    end\
end\
\
local function read(t)\
    if type(t.module) ~= \"string\" then\
        return {seed = hotpatch.seed, codes = hotpatch.codes}\
    end\
\
    if type(hotpatch.codes[t.module]) == \"string\" then\
        return hotpatch.codes[t.module]\
    end\
\
    return nil\
end\
\
actor.action_set(hotpatch.subtype, \"reload\", reload, \"reload hot code, {seed = xx, args = [base64code1, base64code2...]}\")\
actor.action_set(hotpatch.subtype, \"delete\", function (msg) delete(msg.module) end, \"delete hot code, {module = key}\")\
actor.action_set(hotpatch.subtype, \"read\", read, \"read hot code, {module = xx}, nil module means all\")\
actor.action_set(hotpatch.subtype, \"show_conf_svr\", function() return {type = \"hotpatch\", subtype = \"hotpatch\", seed = hotpatch.seed} end, \
                 [[show hotpatch conf msg to oper svr]])\
\
return hotpatch\
"
, '@'.."./service/hotpatch.lua" ) )

package.preload[ "hredirect" ] = assert( (loadstring or load)(
"\
local cjson = require(\"cjson\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local kernel = require(\"c.kernel\")\
local csys = require(\"c.sys\")\
local actor = require\"luactor\"\
\
\
local hredirect = {\
    help = \"redirect http from server\", \
    type = \"hredirect\",\
    subtype = \"hredirect\",\
\
    enable = false,\
    rules = {},\
    stats = {},\
}\
\
local function rule_fill(rule)\
    local data_table = {}\
\
    if type(rule.host) ~= 'string' or type(rule.uri) ~= 'string' or type(rule.location) ~= 'string' then\
        return nil\
    end\
\
    local host_len = rule.host:len()\
    local uri_len = rule.uri:len()\
    local location_len = rule.location:len()\
\
    table.insert(data_table, string.pack('=I', host_len))\
    table.insert(data_table, string.pack('=I', uri_len))\
    table.insert(data_table, string.pack('=I', location_len))\
\
    if host_len > 0 then\
        table.insert(data_table, rule.host)\
    end\
    if uri_len > 0 then\
        table.insert(data_table, rule.uri)\
    end\
    if location_len > 0 then\
        table.insert(data_table, rule.location)\
    end\
\
    local data = table.concat(data_table)\
    local data_len = data:len()\
    return string.pack('=Ic'..data_len, data_len + 4, data)\
end\
\
local function update_rules()\
    kernel.send(CENUM.MEMSHR_U2K_HTTP_REDIRECT_FLUSH, \"\")\
\
    for i = 1, #hredirect.rules do\
        local rule_data = rule_fill(hredirect.rules[i])\
        if rule_data then\
            kernel.send(CENUM.MEMSHR_U2K_HTTP_REDIRECT_ADD, rule_data)\
        end\
    end\
end\
\
local function stat_get_one(sbytes, pos, len)\
    local stat = {}\
\
    local all_len, next_pos, err_cnt, send_cnt, host_len, uri_len, location_len = 0,0,0,0,0,0\
    all_len, stat.err_cnt, stat.send_cnt, host_len, uri_len, location_len, next_pos = string.unpack(\"=IIIIII\", sbytes, pos)\
\
    assert(all_len >= next_pos - pos + host_len + uri_len + location_len)\
\
    if host_len > 0 then\
        stat.host, next_pos = string.unpack(string.format(\"c%d\", host_len), sbytes, next_pos)\
    end\
\
    if uri_len > 0 then\
        stat.uri, next_pos = string.unpack(string.format(\"c%d\", uri_len), sbytes, next_pos)\
    end\
    if location_len > 0 then\
        stat.location, next_pos = string.unpack(string.format(\"c%d\", location_len), sbytes, next_pos)\
    end\
\
    return all_len,stat \
end\
\
\
local function get_stat(sbytes)\
    local len = sbytes:len() used_len = 0 one_size = 0\
    local stat_table = {} one = {}\
\
    while used_len < len do\
        one_size, one = stat_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
        table.insert(stat_table, one)\
    end\
    hredirect.stats = stat_table\
\
    return len\
end\
\
local function stat(msg)\
    kernel.call(CENUM.MEMSHR_K2U_HTTP_REDIRECT_STAT, \"\", get_stat) \
    return {stats=hredirect.stats}\
end\
\
function read(msg)\
    return {enable = hredirect.enable, rules = hredirect.rules}\
end\
\
local function write(msg)\
    if msg.enable ~= nil and msg.enable ~= hredirect.enable then\
        hredirect.enable = msg.enable\
        if hredirect.enable then\
            kernel.set_engine(CENUM.ENGINE_TYPE_HTTP_REDIRECT, 1)\
        else\
            kernel.set_engine(CENUM.ENGINE_TYPE_HTTP_REDIRECT, 0)\
        end\
    end\
    if msg.rules then\
        hredirect.rules = msg.rules\
        update_rules()\
    end\
end\
\
actor.action_set(hredirect.type, \"read\", read, \"read hredirect status\")\
actor.action_set(hredirect.type, \"write\", write, \"[[{host=string, uri=string, location=string}]]\")\
actor.action_set(hredirect.type, \"stat\", stat, \"get http redirect stat info\")\
\
return hredirect\
\
"
, '@'.."./service/hredirect.lua" ) )

package.preload[ "http" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local kernel = require(\"c.kernel\")\
local myip = require(\"myip\")\
local cjson = require(\"cjson\")\
local timer = require(\"timer\")\
local log = require(\"log\")\
\
local http = {\
    type = \"http\",\
    subtype = \"http\",\
    help = \"get dns from kernel and send to server\",\
    period = 0,\
    timer_name = \"http_get\",\
\
    -- stat\
    all_len = 0,\
    all_count = 0,\
    pub_cnt = 0\
}\
\
local function http_get_one(sbytes, pos, len)\
    local http_table = {}\
    local all_len, next_pos, url_len, ref_len, ua_len, cookie_len = 0, 0, 0, 0, 0, 0\
    all_len, http_table.sport, http_table.ip, http_table.mac, http_table.dport,\
    http_table.ts_sec, http_table.ts_usec, http_table.dstip, http_table.method, url_len, ref_len, ua_len, cookie_len, http_table.appid, http_table.ruleid, http_table.proto, next_pos\
        = string.unpack(\"=HHc4c6HIIc4IIIIIIIH\", sbytes, pos)\
\
    assert(all_len >= next_pos - pos + url_len + ref_len + ua_len + cookie_len)\
\
    if url_len > 0 then\
        http_table.url, next_pos = string.unpack(string.format(\"c%d\", url_len), sbytes, next_pos)\
    end\
    if ref_len > 0 then\
        http_table.ref, next_pos = string.unpack(string.format(\"c%d\", ref_len), sbytes, next_pos)\
    end\
    if ua_len > 0 then\
        http_table.ua, next_pos = string.unpack(string.format(\"c%d\", ua_len), sbytes, next_pos)\
    end\
    if cookie_len > 0 then\
        http_table.cookie, next_pos = string.unpack(string.format(\"c%d\", cookie_len), sbytes, next_pos)\
    end\
\
    return all_len, http_table\
end\
\
local function http_get(sbytes)\
    local len = sbytes:len() used_len = 0 one_size = 0\
    local http_tables = {} tt = {}\
    local info\
\
    while used_len < len do\
        one_size, tt = http_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
        table.insert(http_tables, tt)\
    end\
\
    assert(used_len == len)\
    actor.publish({msgtype = \"HTTP\", http_tables = http_tables, http_period = http.period})\
    http.pub_cnt = http.pub_cnt +1\
    for k,v in pairs(http_tables) do\
        v.mac = myip.mac_ntoa(v.mac)\
        v.ip = myip.inet_ntoa(v.ip)\
        v.dstip = myip.inet_ntoa(v.dstip)\
        v.type = \"http_data\"\
    end\
\
    return len\
end\
\
local function http_set_engine(period)\
    if period == 0 then\
        kernel.set_engine(CENUM.ENGINE_TYPE_HFILTER, 0)\
    else\
        kernel.set_engine(CENUM.ENGINE_TYPE_HFILTER, 1)\
    end\
end\
\
local function write(t)\
    kernel.set_engine(CENUM.ENGINE_TYPE_HFILTER, 1)\
    if t.period and tonumber(t.period) ~= http.period then\
        log.info(\"http period change to \", t.period, \"from \", http.period)\
        http.period = tonumber(t.period)\
        if http.period > 0 then\
            timer.mod(http.timer_name, http.period, 0, function () kernel.call(CENUM.MEMSHR_K2U_HTTP, \"\", http_get) end)\
        else                    -- default is 5s\
            timer.mod(http.timer_name, 5, 0, function () kernel.call(CENUM.MEMSHR_K2U_HTTP, \"\", http_get) end)\
        end\
    end\
end\
\
local function debug_get_one(sbytes, pos, len)\
    local all_len, url_len, code, next_pos = string.unpack(\"=III\", sbytes, pos)\
\
    local url = string.unpack(string.format(\"c%d\", url_len), sbytes, next_pos)\
    return all_len, url, code\
end\
\
local function debug_get(sbytes)\
    local len = sbytes:len() used_len = 0 one_size = 0\
    local debug_tables = {} tt = {}\
    local code_string = {[0] = \"normal\", [1] = \"black\", [2] = \"white\", [3] = \"rule\"}\
\
    while used_len < len do\
        local one_size, url, code = debug_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
        table.insert(debug_tables, {url = url, code = code_string[code]})\
    end\
    \
    http.debug = debug_tables\
    return len\
end\
\
local function http_debug(t)\
    if t.enable == true then \
        kernel.send(CENUM.MEMSHR_K2U_HTTP_DEBUG, string.pack(\"=I\", 1))\
    elseif t.enable == false then\
        kernel.send(CENUM.MEMSHR_K2U_HTTP_DEBUG, string.pack(\"=I\", 0))\
    else\
        kernel.call(CENUM.MEMSHR_K2U_HTTP_DEBUG, \"\", debug_get)\
        local tt = http.debug\
        http.debug = nil\
        return tt\
    end\
end\
\
function http.postinit()\
    kernel.set_engine(CENUM.ENGINE_TYPE_HFILTER, 1)\
    if http.period > 0 then\
        timer.mod(http.timer_name, http.period, 0, function () kernel.call(CENUM.MEMSHR_K2U_HTTP, \"\", http_get) end)\
    else                    -- default is 5s\
       timer.mod(http.timer_name, 5, 0, function () kernel.call(CENUM.MEMSHR_K2U_HTTP, \"\", http_get) end)\
    end\
end\
\
actor.action_set(http.subtype, \"read\", function () return { period = http.period} end, \"read http conf\")\
actor.action_set(http.subtype, \"stat\", function () return { all_count = http.all_count, all_len = http.all_len, pub_cnt = http.pub_cnt } end, \"read stat\")\
actor.action_set(http.subtype, \"write\", write, [[set http period and send conf, {period = number}, 0 means close engine]])\
actor.action_set(http.subtype, \"show_conf_svr\", function() return {type = \"lua_cmd\", subtype = \"http\"} end, \"show http conf msg to oper svr\")\
actor.action_set(http.subtype, \"debug\", http_debug, \"{enable = true/false}, default is dump when no enable args}\")\
\
return http\
"
, '@'.."./service/http.lua" ) )

package.preload[ "http_imei" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local timer = require(\"timer\")\
local log = require(\"log\")\
local mystring = require(\"mystring\")\
local cj = require\"cjson\"\
local ctime = require\"c.time\"\
local myip = require\"myip\"\
\
local mm = {\
    period = 0,\
    subtype = \"httpimei\",\
    type = \"httpimei\",\
    help = \"pick http key using kv pair with keywords from url/cookie\",\
    tname = \"httpimei\", \
    uptype = \"http_imei\",\
    maxmsg = 128,\
    maxsendcnt = 1024, \
    timeout = 7200,             -- every 2 hours to send httpkw\
    timeout = 7,\
\
    -- var\
    handle = 0,\
\
    sendcnt = 0,\
    lasttime = 0, \
    msg = {}, \
}\
\
local policy = {\
    --keywords = {\"mac\", \"model\"},\
    keywords = {\"imei\"},\
    othwords = {\"mac$\"},\
    attr = {\"url\", \"cookie\"},\
}\
\
local function kw_search(words, patterns)\
    kk, vv = mystring.split(words, \"=\")\
    if not kk or not vv then\
        return\
    end\
\
    kk = mystring.trim(kk)\
    vv = mystring.trim(vv)\
    for _, p in ipairs(patterns) do\
        if string.find(kk:lower(), p:lower()) then\
            return kk, vv, p\
        end\
    end\
end\
\
local function keywords_match(httpstr, attr, keywords, othwords)\
    local delim \
    if attr == \"url\" then\
        delim = \"&\"\
        httpstr = string.match(httpstr, \"?(.*)\")\
        if not httpstr or httpstr == \"\" then\
            return\
        end\
    elseif attr == \"cookie\" then\
        delim = \";\"\
    else\
        return\
    end\
\
    local var = {}\
    string.gsub(httpstr,'[^'..delim..']+',function ( w )\
        table.insert(var, w)\
    end)\
    \
    local kk, vv, result, haskey = nil, nil, {}, {}\
    result['hmac'] = ''\
    for _, words in ipairs(var) do\
        kk, vv, pattern = kw_search(words, keywords)\
        if kk and #vv==15 then\
            result['imei'] = vv\
            haskey[pattern] = true\
        end\
\
        kk, vv = kw_search(words, othwords)\
        if kk and vv then\
            result['hmac'] = vv\
        end\
    end\
\
    for _, p in ipairs(keywords) do\
        if not haskey[p] then\
            return\
        end\
    end\
\
    --log.error(\"match keywords\"..cj.encode(result))\
    return result\
end\
\
local function pick_one(v, p)\
    local value\
    for _, attr in pairs(p.attr) do\
        if v[attr] then\
            value = keywords_match(v[attr], attr, p.keywords, p.othwords)\
            --if value and type(value) == \"table\" and #mm.msg < mm.maxmsg then\
            if value and type(value) == \"table\" then\
                local myip = require(\"myip\")\
                value[\"__mac\"] = myip.mac_ntoa(v.mac)\
                value[\"type\"] = mm.uptype\
                --add to osinfo\
                if value['imei'] and myip.mac_check(\"\", value[\"__mac\"]) then\
                    lcmd_run({subtype = \"osinfo\", action = \"add_sig\", key = \"imei\", value = value['imei'], mac = value[\"__mac\"], from = \"httpimei\"})\
                end\
                --table.insert(mm.msg, value)\
            end\
        end\
    end\
end\
\
local function pick_http_kw(t)\
    for _, v in pairs(t) do\
        pick_one(v, policy)\
    end\
end\
\
--[[\
local function sendmsg(msg)\
    for _, v in ipairs(mm.msg) do\
        lcmd_run{subtype = \"__oper_data\", action = \"add\", data = v}\
        mm.sendcnt = mm.sendcnt + 1\
    end\
end\
\
local function keywords_send()\
    if #mm.msg >= mm.maxmsg then\
        sendmsg(mm.msg)\
        mm.msg = {}\
    end\
\
    local uptime = ctime.get_uptime()\
    if uptime > mm.lasttime + mm.timeout then\
        mm.lasttime = uptime\
        sendmsg(mm.msg)\
        mm.msg = {}\
    end\
end\
--]]\
\
\
local function httpkw_stat()\
    return {\
        uptype = mm.uptype,\
        maxmsg = mm.maxmsg,\
        maxsendcnt = mm.maxsendcnt,\
        timeout = mm.timeout, \
        sendcnt = mm.sendcnt, \
    }\
end\
\
local function httpkw_write(t)\
    if type(t.maxmsg) == \"number\" then\
        mm.maxmsg = t.maxmsg\
    end\
    if type(t.maxsendcnt) == \"number\" then\
        mm.maxsendcnt = t.maxsendcnt\
    end\
    if type(t.timeout) == \"number\" then\
        mm.timeout = t.timeout\
    end\
    if type(t.sendcnt) == \"number\" then\
        mm.sendcnt = t.sendcnt\
    end\
end\
\
function mm.postinit()\
    mm.handle = actor.subscribe(\"HTTP\",\
                                function(msg)\
                                    --if type(msg.http_tables) == \"table\" and mm.maxsendcnt > mm.sendcnt then\
                                    if type(msg.http_tables) == \"table\" then\
                                        pick_http_kw(msg.http_tables)\
                                    end\
                                end\
    )\
    --timer.mod(mm.tname, 10, 0, keywords_send)\
    --local uptime = ctime.get_uptime()\
    --mm.lasttime = uptime\
\
    actor.action_set(mm.subtype, \"stat\", httpkw_stat, \"show stat of httpkw.lua\")\
    actor.action_set(mm.subtype, \"write\", httpkw_write, \"write conf of httpkw.lua, {maxmsg = xx, maxsendcnt = xx, timeout = xx, sendcnt = xx}\")\
end\
\
function mm.finish()\
    timer.del(mm.tname)\
    if type(actor.unsubscribe) == \"function\" then\
        actor.unsubscribe(\"HTTP\", mm.handle)\
    end\
end\
\
return mm\
"
, '@'.."./service/http_imei.lua" ) )

package.preload[ "http_rule" ] = assert( (loadstring or load)(
"local actor = require \"luactor\"\
local chttp_header = require \"c.http_header\"\
local cjson = require \"cjson\"\
local log = require\"log\"\
\
local http_rule = {\
    type = \"__http_rule\",\
    subtype = \"__http_rule\",\
    help = \"http rule configure\",\
}\
\
local function write(t)\
    chttp_header.write(cjson.encode(t))\
    lcmd_run{subtype = \"sys\", action = \"save_conf_change\"}\
end\
\
local function read(verbose)\
    local text = chttp_header.read(verbose)\
    local ok, conf = pcall(cjson.decode, text)\
    if conf and not conf.type then\
        conf.type = http_rule.type\
    end\
    return conf\
end\
\
actor.action_set(http_rule.subtype, \"write\", write, \"write http rules\")\
actor.action_set(http_rule.subtype, \"show_conf_save\", function() return read(true) end, \"show http rules, for save conf local\")\
actor.action_set(http_rule.subtype, \"show_conf_svr\", function() return read(false) end, \"show http rules, for svroper only\")\
\
return http_rule\
"
, '@'.."./service/http_rule.lua" ) )

package.preload[ "httpclient" ] = assert( (loadstring or load)(
"local utils = require(\"httpclient.utils\")\
local urlparser = require(\"httpclient.neturl\")\
\
local HttpClient = {}\
local m = {}\
\
local DEFAULT_DRIVER = 'httpclient.luasocket_driver'\
\
function m.new(x)\
  local self = {}\
  local d = x or DEFAULT_DRIVER\
  local driver_ok, driver = pcall(require, d) \
  if not driver_ok then\
    return nil\
  end\
  self.client = driver.new()\
  self.defaults = self.client.defaults\
  setmetatable(self, {__index = HttpClient})\
  return self\
end\
\
local function merge_defaults(t1, defaults)\
  for k, v in pairs(defaults) do\
    if not t1[k] then t1[k] = v end\
  end\
  return t1\
end\
\
function HttpClient:set_default(param, value)\
  self.client:set_default(param, value)\
  self.defaults = self.client.defaults\
end\
\
function HttpClient:get_defaults()\
  return self.defaults\
end\
\
function HttpClient:urlencode(u)\
  if self.client:get_features().urlencode then\
    return self.client:urlencode(u)\
  else\
    return nil\
  end\
end\
\
function HttpClient:urldecode(u)\
  if self.client:get_features().urldecode then\
    return self.client:urldecode(u)\
  else\
    return nil\
  end\
end\
\
function HttpClient:urlparse(u)\
  return urlparser.parse(u)\
end\
\
function HttpClient:get_supported_features()\
  return self.client:get_features() or {}\
end\
\
function HttpClient:get_last_request()\
  return self.client:get_last_request() or {}\
end\
\
function HttpClient:get(url, options)\
  local opts = options or self:get_defaults()\
  local params = opts.params or nil\
  local method = \"GET\"\
\
  return self.client:request(url, params, method, opts)\
end\
\
function HttpClient:post(url, data, options)\
  local opts = options or {}\
  opts = merge_defaults(opts, self:get_defaults())\
  local params = opts.params or nil\
  if opts.content_type then\
    opts.headers = opts.headers or {}\
    opts.headers[\"Content-Type\"] = opts.content_type\
  end\
  -- post/put/patch all look similar\
  -- allow method passed in via opts to unify \"posting\" code\
  local method = opts.method or \"POST\"\
  if not data then\
    return {nil, err = \"missing data\"}\
  else\
    opts.body = data\
    opts.headers = opts.headers or {}\
    opts.headers[\"Content-Length\"] = string.len(data)\
  end\
\
  return self.client:request(url, params, method, opts)\
end\
\
function HttpClient:put(url, data, options)\
    local opts = options or {}\
    opts.method = \"PUT\"\
    return self:post(url, data, opts)\
end\
\
function HttpClient:patch(url, data, options)\
    local opts = options or {}\
    opts.method = \"PATCH\"\
    return self:post(url, data, opts)\
end\
\
function HttpClient:head(url, options)\
  local opts = options or {}\
  opts = merge_defaults(opts, self:get_defaults())\
  local params = opts.params or nil\
\
  local method = \"HEAD\"\
  return self.client:request(url, params, method, opts)\
end\
\
function HttpClient:delete(url, options)\
  local opts = options or {}\
  opts = merge_defaults(opts, self:get_defaults())\
  local params = opts.params or nil\
\
  local method = \"DELETE\"\
  return self.client:request(url, params, method, opts)\
end\
\
return m\
"
, '@'.."./lualib/httpclient.lua" ) )

package.preload[ "httpclient.luasocket_driver" ] = assert( (loadstring or load)(
"local http = require(\"socket.http\")\
local https_ok, https = pcall(_G.require, \"ssl.https\")\
local urlparser = require(\"socket.url\")\
local ltn12 = require(\"ltn12\")\
local utils = require(\"httpclient.utils\")\
\
local LuaSocketDriver = {}\
local luasocketdriver = {}\
\
local default_ssl_params = {\
  mode = \"client\",\
  protocol = \"tlsv1\",\
  verify = \"peer\",\
  options = \"all\",\
  cafile = \"/etc/ssl/certs/ca-certificates.crt\"\
}\
\
local default_timeout = 60\
\
local function get_default_opts(t)\
  local nt = utils.deep_copy(t)\
  if not nt.timeout then nt.timeout = default_timeout end\
  if not nt.ssl_opts then nt.ssl_opts = default_ssl_params end\
  return nt\
end\
\
local function merge_defaults(t1, defaults)\
  for k, v in pairs(defaults) do\
    if not t1[k] then t1[k] = v end\
  end\
  return t1\
end\
\
function luasocketdriver.new(opts)\
  local self = {}\
  self.defaults = (get_default_opts(opts or {}))\
  setmetatable(self, { __index = LuaSocketDriver })\
  return self\
end\
\
function LuaSocketDriver:set_default(param, value)\
  local t = {}\
  t[param] = value\
  self.defaults = merge_defaults(t, self.defaults)\
end\
\
function LuaSocketDriver:get_defaults()\
  return self.defaults\
end\
\
function LuaSocketDriver:urlencode(string)\
  return urlparser.escape(string)\
end\
\
function LuaSocketDriver:urldecode(string)\
  return urlparser.unescape(string)\
end\
\
function LuaSocketDriver:urlparse(u)\
  return urlparser.parse(u)\
end\
\
function LuaSocketDriver:get_features()\
  support_features = {\
    urlencode = true,\
    urldecode = true,\
    urlparse = true,\
    ssl = https_ok\
  }\
  return support_features\
end\
\
function LuaSocketDriver:set_last_request(req_t, driver)\
  local t = {}\
  t.request = req_t\
  t.driver = driver\
  self.last_request = t\
end\
\
function LuaSocketDriver:get_last_request()\
  return self.last_request\
end\
\
function LuaSocketDriver:request(url, params, method, args)\
  self.last_request = {}\
  local resp, r = {}, {}\
  local query = params or nil\
  local method = method or \"GET\"\
  local uri = url or nil\
  local http_client = http\
  local ssl_params = args.ssl_opts or self:get_defaults().ssl_opts\
  local req_t = {}\
\
  if not uri then\
    return {nil, err = \"missing url\"}\
  end\
\
  if query then\
    q = nil\
    if type(query) == \"string\" then\
      q = query\
    else\
      local qopts = {}\
      for k, v in pairs(query) do\
        table.insert(qopts, urlparser.escape(k)..\"=\"..urlparser.escape(v))\
      end\
      q = table.concat(qopts, \"&\")\
    end\
    uri = uri..\"?\"..q\
  end\
  req_t = {\
    url=uri,\
    sink=ltn12.sink.table(resp),\
    method=method,\
    redirect=true\
  }\
\
  -- Check if https\
  if uri:find(\"^https\") then\
    if not https_ok then\
      return {nil, \"https not supported. Please install luasec\"}\
    end\
    for k, v in pairs(ssl_params) do\
      req_t[k] = v\
    end \
    -- remove redirect on ssl to prevent failure\
    req_t.redirect = nil\
    http_client = https\
  end\
  \
  http_client.TIMEOUT = args.timeout or default_timeout\
  req_t.headers = args.headers or {[\"Accept\"] = \"*/*\"}\
  if args.body then req_t.source = ltn12.source.string(args.body) end\
  local results = {}\
  _ = self:set_last_request(req_t, http_client)\
  local r = {http_client.request(req_t)}\
  if #r == 2 then\
    -- the request failed\
    return {nil, err = r[2]}\
  else\
    -- we got a regular result\
    results = {\
      body = table.concat(resp),\
      code = r[2],\
      headers = r[3],\
      status_line = r[4],\
      err = nil\
    }\
  end\
  \
  if (results.code >= 400 and results.code <= 599) then\
    -- got an error of some kind\
    local e = results.body or results.status_line or \"no error\"\
    local r = results\
    r.err = e\
    return r\
  end\
\
  if (results.code == 301 or results.code == 302 or results.code == 307) then\
    local loop_control = args.loop_control or {}\
    if loop_control[results.headers.location] then\
      return {nil, err = \"redirect loop on \"..results.headers.location}\
    end\
    loop_control[results.headers.location] = true\
    local location = results.headers.location\
    return self:request(location, params, method, {loop_control = loop_control})\
  end\
  return results\
end\
\
return luasocketdriver\
"
, '@'.."./lualib/httpclient/luasocket_driver.lua" ) )

package.preload[ "httpclient.neturl" ] = assert( (loadstring or load)(
"-- neturl.lua - a robust url parser and builder\
--\
-- Bertrand Mansion, 2011-2013; License MIT\
-- @module neturl\
-- @alias\9M\
\
local M = {}\
M.version = \"0.9.0\"\
\
--- url options\
-- separator is set to `&` by default but could be anything like `&amp;amp;` or `;`\
-- @todo Add an option to limit the size of the argument table\
M.options = {\
\9separator = '&'\
}\
\
--- list of known and common scheme ports\
-- as documented in <a href=\"http://www.iana.org/assignments/uri-schemes.html\">IANA URI scheme list</a>\
M.services = {\
\9acap     = 674,\
\9cap      = 1026,\
\9dict     = 2628,\
\9ftp      = 21,\
\9gopher   = 70,\
\9http     = 80,\
\9https    = 443,\
\9iax      = 4569,\
\9icap     = 1344,\
\9imap     = 143,\
\9ipp      = 631,\
\9ldap     = 389,\
\9mtqp     = 1038,\
\9mupdate  = 3905,\
\9news     = 2009,\
\9nfs      = 2049,\
\9nntp     = 119,\
\9rtsp     = 554,\
\9sip      = 5060,\
\9snmp     = 161,\
\9telnet   = 23,\
\9tftp     = 69,\
\9vemmi    = 575,\
\9afs      = 1483,\
\9jms      = 5673,\
\9rsync    = 873,\
\9prospero = 191,\
\9videotex = 516\
}\
\
local legal = {\
\9[\"-\"] = true, [\"_\"] = true, [\".\"] = true, [\"!\"] = true,\
\9[\"~\"] = true, [\"*\"] = true, [\"'\"] = true, [\"(\"] = true,\
\9[\")\"] = true, [\":\"] = true, [\"@\"] = true, [\"&\"] = true,\
\9[\"=\"] = true, [\"+\"] = true, [\"$\"] = true, [\",\"] = true,\
\9[\";\"] = true -- can be used for parameters in path\
}\
\
local function decode(str)\
\9local str = str:gsub('+', ' ')\
\9return (str:gsub(\"%%(%x%x)\", function(c)\
\9\9\9return string.char(tonumber(c, 16))\
\9end))\
end\
\
local function encode(str)\
\9return (str:gsub(\"([^A-Za-z0-9%_%.%-%~])\", function(v)\
\9\9\9return string.upper(string.format(\"%%%02x\", string.byte(v)))\
\9end))\
end\
\
-- for query values, prefer + instead of %20 for spaces\
local function encodeValue(str)\
\9local str = encode(str)\
\9return str:gsub('%%20', '+')\
end\
\
local function encodeSegment(s)\
\9local legalEncode = function(c)\
\9\9if legal[c] then\
\9\9\9return c\
\9\9end\
\9\9return encode(c)\
\9end\
\9return s:gsub('([^a-zA-Z0-9])', legalEncode)\
end\
\
--- builds the url\
-- @return a string representing the built url\
function M:build()\
\9local url = ''\
\9if self.path then\
\9\9local path = self.path\
\9\9path:gsub(\"([^/]+)\", function (s) return encodeSegment(s) end)\
\9\9url = url .. tostring(path)\
\9end\
\9if self.query then\
\9\9local qstring = tostring(self.query)\
\9\9if qstring ~= \"\" then\
\9\9\9url = url .. '?' .. qstring\
\9\9end\
\9end\
\9if self.host then\
\9\9local authority = self.host\
\9\9if self.port and self.scheme and M.services[self.scheme] ~= self.port then\
\9\9\9authority = authority .. ':' .. self.port\
\9\9end\
\9\9local userinfo\
\9\9if self.user and self.user ~= \"\" then\
\9\9\9userinfo = self.user\
\9\9\9if self.password then\
\9\9\9\9userinfo = userinfo .. ':' .. self.password\
\9\9\9end\
\9\9end\
\9\9if userinfo and userinfo ~= \"\" then\
\9\9\9authority = userinfo .. '@' .. authority\
\9\9end\
\9\9if authority then\
\9\9\9if url ~= \"\" then\
\9\9\9\9url = '//' .. authority .. '/' .. url:gsub('^/+', '')\
\9\9\9else\
\9\9\9\9url = '//' .. authority\
\9\9\9end\
\9\9end\
\9end\
\9if self.scheme then\
\9\9url = self.scheme .. ':' .. url\
\9end\
\9if self.fragment then\
\9\9url = url .. '#' .. self.fragment\
\9end\
\9return url\
end\
\
--- builds the querystring\
-- @param tab The key/value parameters\
-- @param sep The separator to use (optional)\
-- @param key The parent key if the value is multi-dimensional (optional)\
-- @return a string representing the built querystring\
function M.buildQuery(tab, sep, key)\
\9local query = {}\
\9if not sep then\
\9\9sep = M.options.separator or '&'\
\9end\
\9local keys = {}\
\9for k in pairs(tab) do\
\9\9keys[#keys+1] = k\
\9end\
\9table.sort(keys)\
\9for _,name in ipairs(keys) do\
\9\9local value = tab[name]\
\9\9name = encode(tostring(name))\
\9\9if key then\
\9\9\9name = string.format('%s[%s]', tostring(key), tostring(name))\
\9\9end\
\9\9if type(value) == 'table' then\
\9\9\9query[#query+1] = M.buildQuery(value, sep, name)\
\9\9else\
\9\9\9local value = encodeValue(tostring(value))\
\9\9\9if value ~= \"\" then\
\9\9\9\9query[#query+1] = string.format('%s=%s', name, value)\
\9\9\9else\
\9\9\9\9query[#query+1] = name\
\9\9\9end\
\9\9end\
\9end\
\9return table.concat(query, sep)\
end\
\
--- Parses the querystring to a table\
-- This function can parse multidimensional pairs and is mostly compatible\
-- with PHP usage of brackets in key names like ?param[key]=value\
-- @param str The querystring to parse\
-- @param sep The separator between key/value pairs, defaults to `&`\
-- @todo limit the max number of parameters with M.options.max_parameters\
-- @return a table representing the query key/value pairs\
function M.parseQuery(str, sep)\
\9if not sep then\
\9\9sep = M.options.separator or '&'\
\9end\
\
\9local values = {}\
\9for key,val in str:gmatch(string.format('([^%q=]+)(=*[^%q=]*)', sep, sep)) do\
\9\9local key = decode(key)\
\9\9local keys = {}\
\9\9key = key:gsub('%[([^%]]*)%]', function(v)\
\9\9\9\9-- extract keys between balanced brackets\
\9\9\9\9if string.find(v, \"^-?%d+$\") then\
\9\9\9\9\9v = tonumber(v)\
\9\9\9\9else\
\9\9\9\9\9v = decode(v)\
\9\9\9\9end\
\9\9\9\9table.insert(keys, v)\
\9\9\9\9return \"=\"\
\9\9end)\
\9\9key = key:gsub('=+.*$', \"\")\
\9\9key = key:gsub('%s', \"_\") -- remove spaces in parameter name\
\9\9val = val:gsub('^=+', \"\")\
\
\9\9if not values[key] then\
\9\9\9values[key] = {}\
\9\9end\
\9\9if #keys > 0 and type(values[key]) ~= 'table' then\
\9\9\9values[key] = {}\
\9\9elseif #keys == 0 and type(values[key]) == 'table' then\
\9\9\9values[key] = decode(val)\
\9\9end\
\
\9\9local t = values[key]\
\9\9for i,k in ipairs(keys) do\
\9\9\9if type(t) ~= 'table' then\
\9\9\9\9t = {}\
\9\9\9end\
\9\9\9if k == \"\" then\
\9\9\9\9k = #t+1\
\9\9\9end\
\9\9\9if not t[k] then\
\9\9\9\9t[k] = {}\
\9\9\9end\
\9\9\9if i == #keys then\
\9\9\9\9t[k] = decode(val)\
\9\9\9end\
\9\9\9t = t[k]\
\9\9end\
\9end\
\9setmetatable(values, { __tostring = M.buildQuery })\
\9return values\
end\
\
--- set the url query\
-- @param query Can be a string to parse or a table of key/value pairs\
-- @return a table representing the query key/value pairs\
function M:setQuery(query)\
\9local query = query\
\9if type(query) == 'table' then\
\9\9query = M.buildQuery(query)\
\9end\
\9self.query = M.parseQuery(query)\
\9return query\
end\
\
--- set the authority part of the url\
-- The authority is parsed to find the user, password, port and host if available.\
-- @param authority The string representing the authority\
-- @return a string with what remains after the authority was parsed\
function M:setAuthority(authority)\
\9self.authority = authority\
\9self.port = nil\
\9self.host = nil\
\9self.userinfo = nil\
\9self.user = nil\
\9self.password = nil\
\
\9authority = authority:gsub('^([^@]*)@', function(v)\
\9\9self.userinfo = v\
\9\9return ''\
\9end)\
\9authority = authority:gsub(\"^%[[^%]]+%]\", function(v)\
\9\9-- ipv6\
\9\9self.host = v\
\9\9return ''\
\9end)\
\9authority = authority:gsub(':([^:]*)$', function(v)\
\9\9self.port = tonumber(v)\
\9\9return ''\
\9end)\
\9if authority ~= '' and not self.host then\
\9\9self.host = authority:lower()\
\9end\
\9if self.userinfo then\
\9\9local userinfo = self.userinfo\
\9\9userinfo = userinfo:gsub(':([^:]*)$', function(v)\
\9\9\9\9self.password = v\
\9\9\9\9return ''\
\9\9end)\
\9\9self.user = userinfo\
\9end\
\9return authority\
end\
\
--- Parse the url into the designated parts.\
-- Depending on the url, the following parts can be available:\
-- scheme, userinfo, user, password, authority, host, port, path,\
-- query, fragment\
-- @param url Url string\
-- @return a table with the different parts and a few other functions\
function M.parse(url)\
\9local comp = {}\
\9M.setAuthority(comp, \"\")\
\9M.setQuery(comp, \"\")\
\
\9local url = tostring(url or '')\
\9url = url:gsub('#(.*)$', function(v)\
\9\9comp.fragment = v\
\9\9return ''\
\9end)\
\9url =url:gsub('^([%w][%w%+%-%.]*)%:', function(v)\
\9\9comp.scheme = v:lower()\
\9\9return ''\
\9end)\
\9url = url:gsub('%?(.*)', function(v)\
\9\9M.setQuery(comp, v)\
\9\9return ''\
\9end)\
\9url = url:gsub('^//([^/]*)', function(v)\
\9\9M.setAuthority(comp, v)\
\9\9return ''\
\9end)\
\9comp.path = decode(url)\
\
\9setmetatable(comp, {\
\9\9__index = M,\
\9\9__tostring = M.build}\
\9)\
\9return comp\
end\
\
--- removes dots and slashes in urls when possible\
-- This function will also remove multiple slashes\
-- @param path The string representing the path to clean\
-- @return a string of the path without unnecessary dots and segments\
function M.removeDotSegments(path)\
\9local fields = {}\
\9if string.len(path) == 0 then\
\9\9return \"\"\
\9end\
\9local startslash = false\
\9local endslash = false\
\9if string.sub(path, 1, 1) == \"/\" then\
\9\9startslash = true\
\9end\
\9if (string.len(path) > 1 or startslash == false) and string.sub(path, -1) == \"/\" then\
\9\9endslash = true\
\9end\
\
\9path:gsub('[^/]+', function(c) table.insert(fields, c) end)\
\
\9local new = {}\
\9local j = 0\
\
\9for i,c in ipairs(fields) do\
\9\9if c == '..' then\
\9\9\9if j > 0 then\
\9\9\9\9j = j - 1\
\9\9\9end\
\9\9elseif c ~= \".\" then\
\9\9\9j = j + 1\
\9\9\9new[j] = c\
\9\9end\
\9end\
\9local ret = \"\"\
\9if #new > 0 and j > 0 then\
\9\9ret = table.concat(new, '/', 1, j)\
\9else\
\9\9ret = \"\"\
\9end\
\9if startslash then\
\9\9ret = '/'..ret\
\9end\
\9if endslash then\
\9\9ret = ret..'/'\
\9end\
\9return ret\
end\
\
local function absolutePath(base_path, relative_path)\
\9if string.sub(relative_path, 1, 1) == \"/\" then\
\9\9return '/' .. string.gsub(relative_path, '^[%./]+', '')\
\9end\
\9local path = base_path\
\9if relative_path ~= \"\" then\
\9\9path = '/'..path:gsub(\"[^/]*$\", \"\")\
\9end\
\9path = path .. relative_path\
\9path = path:gsub(\"([^/]*%./)\", function (s)\
\9\9if s ~= \"./\" then return s else return \"\" end\
\9end)\
\9path = string.gsub(path, \"/%.$\", \"/\")\
\9local reduced\
\9while reduced ~= path do\
\9\9reduced = path\
\9\9path = string.gsub(reduced, \"([^/]*/%.%./)\", function (s)\
\9\9\9if s ~= \"../../\" then return \"\" else return s end\
\9\9end)\
\9end\
\9path = string.gsub(path, \"([^/]*/%.%.?)$\", function (s)\
\9\9if s ~= \"../..\" then return \"\" else return s end\
\9end)\
\9local reduced\
\9while reduced ~= path do\
\9\9reduced = path\
\9\9path = string.gsub(reduced, '^/?%.%./', '')\
\9end\
\9return '/' .. path\
end\
\
--- builds a new url by using the one given as parameter and resolving paths\
-- @param other A string or a table representing a url\
-- @return a new url table\
function M:resolve(other)\
\9if type(self) == \"string\" then\
\9\9self = M.parse(self)\
\9end\
\9if type(other) == \"string\" then\
\9\9other = M.parse(other)\
\9end\
\9if other.scheme then\
\9\9return other\
\9else\
\9\9other.scheme = self.scheme\
\9\9if not other.authority or other.authority == \"\" then\
\9\9\9other:setAuthority(self.authority)\
\9\9\9if not other.path or other.path == \"\" then\
\9\9\9\9other.path = self.path\
\9\9\9\9local query = other.query\
\9\9\9\9if not query or not next(query) then\
\9\9\9\9\9other.query = self.query\
\9\9\9\9end\
\9\9\9else\
\9\9\9\9other.path = absolutePath(self.path, other.path)\
\9\9\9end\
\9\9end\
\9\9return other\
\9end\
end\
\
--- normalize a url path following some common normalization rules\
-- described on <a href=\"http://en.wikipedia.org/wiki/URL_normalization\">The URL normalization page of Wikipedia</a>\
-- @return the normalized path\
function M:normalize()\
\9if type(self) == 'string' then\
\9\9self = M.parse(self)\
\9end\
\9if self.path then\
\9\9local path = self.path\
\9\9path = absolutePath(path, \"\")\
\9\9-- normalize multiple slashes\
\9\9path = string.gsub(path, \"//+\", \"/\")\
\9\9self.path = path\
\9end\
\9return self\
end\
\
return M"
, '@'.."./lualib/httpclient/neturl.lua" ) )

package.preload[ "httpclient.ngx_driver" ] = assert( (loadstring or load)(
"local utils = require(\"httpclient.utils\")\
\
local NgxDriver = {}\
local ngxdriver = {}\
\
local default_opts = {\
  capture_url = '/capture',\
  capture_variable = \"url\"\
}\
\
local function get_default_opts(t)\
  local nt = utils.deep_copy(t)\
  if not nt.capture_url then nt.capture_url = default_opts.capture_url end\
  if not nt.capture_variable then nt.capture_variable = default_opts.capture_variable end\
  return nt\
end\
\
local function merge_defaults(t1, defaults)\
  for k,v in pairs(defaults) do\
    if not t1[k] then t1[k] = v end\
  end\
  return t1\
end\
\
function ngxdriver.new(opts)\
  local self = {}\
  self.defaults = (get_default_opts(opts or {}))\
  setmetatable(self, { __index = NgxDriver })\
  return self\
end\
\
function NgxDriver:set_default(param, value)\
  local t = {}\
  t[param] = value\
  self.defaults = merge_default(t, self.defaults)\
end\
\
function NgxDriver:get_defaults()\
  return self.defaults\
end\
\
function NgxDriver:urlencode(string)\
  return ngx.escape_uri(string)\
end\
\
function NgxDriver:urldecode(string)\
  return ngx.unescape_uri(string)\
end\
\
function NgxDriver:urlparse(u)\
  return nil\
  --return urlparser.parse(u)\
end\
\
function NgxDriver:get_features()\
  support_features = {\
    urlencode = true,\
    urldecode = true,\
    urlparse = false,\
    ssl = true\
  }\
  return support_features\
end\
\
function NgxDriver:set_last_request(req_t, driver)\
  local t = {}\
  t.request = req_t\
  t.driver = driver\
  self.last_request = t\
end\
\
function NgxDriver:get_last_request()\
  return self.last_request\
end\
\
-- http://wiki.nginx.org/HttpLuaModule#HTTP_method_constants\
-- additionnal: OPTIONS MKCOL COPY MOVE PROPFIND PROPPATCH\
--              LOCK UNLOCK PATCH TRACE should be supported\
local methods = {\
\9GET=true, PUT=true, POST=true, DELETE=true, PATCH=true, HEAD=true,\
\9OPTIONS=true, MKCOL=true, COPY=true, MOVE=true, PROPFIND=true,\
\9PROPPATCH=true, LOCK=true, UNLOCK=true, PATCH=true, TRACE=true,\
}\
\
function NgxDriver:request(url, params, method, args)\
  self.last_request = {}\
  local query = params or nil\
  local method = method or \"GET\"\
  local uri = url or nil\
  --local http_client = ngx.location.capture\
  local capture_url = args.capture_url or self:get_defaults().capture_url\
  local capture_variable = args.capture_variable or self:get_defaults().capture_variable\
  local req_t = {}\
  \
  if ( method == \"GET\" ) then new_method = ngx.HTTP_GET end\
  if ( method == \"PUT\" ) then new_method = ngx.HTTP_PUT end\
  if ( method == \"POST\" ) then new_method = ngx.HTTP_POST end\
  if ( method == \"DELETE\" ) then new_method = ngx.HTTP_DELETE end\
  if ( method == \"HEAD\" ) then new_method = ngx.HTTP_HEAD end\
  if ( methods[method] and ngx[\"HTTP_\"..method] ) then new_method = ngx[\"HTTP_\"..method] end\
\
  if not uri then\
    return {nil, err = \"missing url\"}\
  end\
\
  if query then\
    q = nil\
    if type(query) == \"string\" then\
      q = query\
    else\
      q = ngx.encode_args(query)\
    end\
    uri = uri..\"?\"..q\
  end\
  req_t = {\
    args    = {[capture_variable] = uri},\
    method  = new_method\
  }\
\
  -- clear all browser headers\
  local bh = ngx.req.get_headers()\
  for k, v in pairs(bh) do\
    ngx.req.clear_header(k)\
  end\
  local h = args.headers or {[\"Accept\"] = \"*/*\"}\
  for k,v in pairs(h) do\
    ngx.req.set_header(k, v)\
  end\
  if args.body then req_t.body = args.body end\
  local results = {}\
  _ = self:set_last_request(req_t, ngx.req)\
  local r = ngx.location.capture(capture_url, req_t)\
  results = {\
    body = r.body,\
    code = r.status,\
    headers = r.header,\
    status_line = tostring(r.status),\
    err = nil\
  }\
  \
  if (results.code >= 400 and results.code <= 599) then\
    -- got an error of some kind\
    local e = results.body or results.status_line or \"no error\"\
    local r = results\
    r.err = e\
    return r\
  end\
\
  return results\
end\
\
return ngxdriver\
"
, '@'.."./lualib/httpclient/ngx_driver.lua" ) )

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

package.preload[ "https" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local https = {\
    subtype = \"https\",\
    period = 0,\
    timer_name = 'https_get',\
    all_count = 0,\
    all_len = 0,\
    pub_cnt = 0,\
    help = \"get https from kernel and send to server\"\
}\
\
local function https_get_one(sbytes, pos, len, now)\
    local all_len, appid = string.unpack('=II', sbytes, pos)\
    local sip = string.sub(sbytes, pos + 8, pos + 11)\
    local dip = string.sub(sbytes, pos + 12, pos + 15)\
    local sport, dport, ruleid, mac, svrname_len, next_post = string.unpack('=HHIc6H', sbytes, pos + 16)\
    local svrname = string.unpack('c'..svrname_len, sbytes, next_post)\
\
    assert(pos + all_len - 1 <= len and all_len >= svrname_len + 32)\
    local https_table = {\
        type = \"https_domain\",\
        mac = myip.mac_ntoa(mac),\
        sip = myip.inet_ntoa(sip),\
        dip = myip.inet_ntoa(dip),\
        sport = sport,\
        dport = dport,\
        appid = appid,\
        ruleid = ruleid,\
        domain = svrname,\
        timestamp = tostring(now)\
    }\
\
    -- log.info(\"recv one https_table from kernel, \", cjson.encode(https_table))\
    actor.publish({msgtype = \"HTTPS\", https_table = https_table})\
    https.pub_cnt = https.pub_cnt +1\
    if https.period > 0 then\
        lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = https_table})\
        https.all_count = https.all_count + 1\
        https.all_len = https.all_len + string.len(cjson.encode(https_table))\
    end\
    return all_len\
end\
\
local function https_get(sbytes)\
    local len = sbytes:len() used_len = 0\
    local now = os.time()\
    while used_len < len do\
        local one_size = https_get_one(sbytes, used_len + 1, len, now)\
        used_len = used_len + one_size\
    end\
    assert(used_len == len)\
    return len\
end\
\
local function write(msg)\
    log.info(\"https period change to\", msg.period, \"from \", https.period)\
    if msg.period and msg.period ~= https.period then\
        https.period = msg.period\
        if https.period > 0 then\
            timer.mod(https.timer_name, https.period, 0, function () kernel.call(CENUM.MEMSHR_K2U_SSL_SVRNAME, \"\", https_get) end)\
        else\
            timer.mod(https.timer_name, 5, 0, function () kernel.call(CENUM.MEMSHR_K2U_SSL_SVRNAME, \"\", https_get) end)\
        end\
    end\
end\
\
function https.postinit()\
    timer.mod(https.timer_name, 5, 0, function () kernel.call(CENUM.MEMSHR_K2U_SSL_SVRNAME, \"\", https_get) end)\
end\
\
actor.action_set(https.subtype, \"get_kernel\", function () kernel.call(CENUM.MEMSHR_K2U_SSL_SVRNAME, \"\", https_get) end, \
                 \"get https from kernel manualy\")\
actor.action_set(https.subtype, \"read\", function () return {period = https.period} end, \"read https conf\")\
actor.action_set(https.subtype, \"write\", write, [[set https period, {period = number}, 0 means close engine]])\
actor.action_set(https.subtype, \"stat\", function () return {all_len = https.all_len, all_count = https.all_count, pub_cnt =https.pub_cnt} end, \"read https stat\")\
actor.action_set(https.subtype, \"show_conf_svr\", function() return {type = \"lua_cmd\", subtype = \"https\"} end, \
                 [[show https conf msg to oper svr]])\
\
return https\
"
, '@'.."./service/https.lua" ) )

package.preload[ "inspect" ] = assert( (loadstring or load)(
"local inspect ={\
  _VERSION = 'inspect.lua 3.1.0',\
  _URL     = 'http://github.com/kikito/inspect.lua',\
  _DESCRIPTION = 'human-readable representations of tables',\
  _LICENSE = [[\
    MIT LICENSE\
\
    Copyright (c) 2013 Enrique García Cota\
\
    Permission is hereby granted, free of charge, to any person obtaining a\
    copy of this software and associated documentation files (the\
    \"Software\"), to deal in the Software without restriction, including\
    without limitation the rights to use, copy, modify, merge, publish,\
    distribute, sublicense, and/or sell copies of the Software, and to\
    permit persons to whom the Software is furnished to do so, subject to\
    the following conditions:\
\
    The above copyright notice and this permission notice shall be included\
    in all copies or substantial portions of the Software.\
\
    THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS\
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY\
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,\
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE\
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\
  ]]\
}\
\
local tostring = tostring\
\
inspect.KEY       = setmetatable({}, {__tostring = function() return 'inspect.KEY' end})\
inspect.METATABLE = setmetatable({}, {__tostring = function() return 'inspect.METATABLE' end})\
\
-- Apostrophizes the string if it has quotes, but not aphostrophes\
-- Otherwise, it returns a regular quoted string\
local function smartQuote(str)\
  if str:match('\"') and not str:match(\"'\") then\
    return \"'\" .. str .. \"'\"\
  end\
  return '\"' .. str:gsub('\"', '\\\\\"') .. '\"'\
end\
\
-- \\a => '\\\\a', \\0 => '\\\\0', 31 => '\\31'\
local shortControlCharEscapes = {\
  [\"\\a\"] = \"\\\\a\",  [\"\\b\"] = \"\\\\b\", [\"\\f\"] = \"\\\\f\", [\"\\n\"] = \"\\\\n\",\
  [\"\\r\"] = \"\\\\r\",  [\"\\t\"] = \"\\\\t\", [\"\\v\"] = \"\\\\v\"\
}\
local longControlCharEscapes = {} -- \\a => nil, \\0 => \\000, 31 => \\031\
for i=0, 31 do\
  local ch = string.char(i)\
  if not shortControlCharEscapes[ch] then\
    shortControlCharEscapes[ch] = \"\\\\\"..i\
    longControlCharEscapes[ch]  = string.format(\"\\\\%03d\", i)\
  end\
end\
\
local function escape(str)\
  return (str:gsub(\"\\\\\", \"\\\\\\\\\")\
             :gsub(\"(%c)%f[0-9]\", longControlCharEscapes)\
             :gsub(\"%c\", shortControlCharEscapes))\
end\
\
local function isIdentifier(str)\
  return type(str) == 'string' and str:match( \"^[_%a][_%a%d]*$\" )\
end\
\
local function isSequenceKey(k, sequenceLength)\
  return type(k) == 'number'\
     and 1 <= k\
     and k <= sequenceLength\
     and math.floor(k) == k\
end\
\
local defaultTypeOrders = {\
  ['number']   = 1, ['boolean']  = 2, ['string'] = 3, ['table'] = 4,\
  ['function'] = 5, ['userdata'] = 6, ['thread'] = 7\
}\
\
local function sortKeys(a, b)\
  local ta, tb = type(a), type(b)\
\
  -- strings and numbers are sorted numerically/alphabetically\
  if ta == tb and (ta == 'string' or ta == 'number') then return a < b end\
\
  local dta, dtb = defaultTypeOrders[ta], defaultTypeOrders[tb]\
  -- Two default types are compared according to the defaultTypeOrders table\
  if dta and dtb then return defaultTypeOrders[ta] < defaultTypeOrders[tb]\
  elseif dta     then return true  -- default types before custom ones\
  elseif dtb     then return false -- custom types after default ones\
  end\
\
  -- custom types are sorted out alphabetically\
  return ta < tb\
end\
\
-- For implementation reasons, the behavior of rawlen & # is \"undefined\" when\
-- tables aren't pure sequences. So we implement our own # operator.\
local function getSequenceLength(t)\
  local len = 1\
  local v = rawget(t,len)\
  while v ~= nil do\
    len = len + 1\
    v = rawget(t,len)\
  end\
  return len - 1\
end\
\
local function getNonSequentialKeys(t)\
  local keys = {}\
  local sequenceLength = getSequenceLength(t)\
  for k,_ in pairs(t) do\
    if not isSequenceKey(k, sequenceLength) then table.insert(keys, k) end\
  end\
  table.sort(keys, sortKeys)\
  return keys, sequenceLength\
end\
\
local function getToStringResultSafely(t, mt)\
  local __tostring = type(mt) == 'table' and rawget(mt, '__tostring')\
  local str, ok\
  if type(__tostring) == 'function' then\
    ok, str = pcall(__tostring, t)\
    str = ok and str or 'error: ' .. tostring(str)\
  end\
  if type(str) == 'string' and #str > 0 then return str end\
end\
\
local function countTableAppearances(t, tableAppearances)\
  tableAppearances = tableAppearances or {}\
\
  if type(t) == 'table' then\
    if not tableAppearances[t] then\
      tableAppearances[t] = 1\
      for k,v in pairs(t) do\
        countTableAppearances(k, tableAppearances)\
        countTableAppearances(v, tableAppearances)\
      end\
      countTableAppearances(getmetatable(t), tableAppearances)\
    else\
      tableAppearances[t] = tableAppearances[t] + 1\
    end\
  end\
\
  return tableAppearances\
end\
\
local copySequence = function(s)\
  local copy, len = {}, #s\
  for i=1, len do copy[i] = s[i] end\
  return copy, len\
end\
\
local function makePath(path, ...)\
  local keys = {...}\
  local newPath, len = copySequence(path)\
  for i=1, #keys do\
    newPath[len + i] = keys[i]\
  end\
  return newPath\
end\
\
local function processRecursive(process, item, path, visited)\
\
    if item == nil then return nil end\
    if visited[item] then return visited[item] end\
\
    local processed = process(item, path)\
    if type(processed) == 'table' then\
      local processedCopy = {}\
      visited[item] = processedCopy\
      local processedKey\
\
      for k,v in pairs(processed) do\
        processedKey = processRecursive(process, k, makePath(path, k, inspect.KEY), visited)\
        if processedKey ~= nil then\
          processedCopy[processedKey] = processRecursive(process, v, makePath(path, processedKey), visited)\
        end\
      end\
\
      local mt  = processRecursive(process, getmetatable(processed), makePath(path, inspect.METATABLE), visited)\
      setmetatable(processedCopy, mt)\
      processed = processedCopy\
    end\
    return processed\
end\
\
\
\
-------------------------------------------------------------------\
\
local Inspector = {}\
local Inspector_mt = {__index = Inspector}\
\
function Inspector:puts(...)\
  local args   = {...}\
  local buffer = self.buffer\
  local len    = #buffer\
  for i=1, #args do\
    len = len + 1\
    buffer[len] = args[i]\
  end\
end\
\
function Inspector:down(f)\
  self.level = self.level + 1\
  f()\
  self.level = self.level - 1\
end\
\
function Inspector:tabify()\
  self:puts(self.newline, string.rep(self.indent, self.level))\
end\
\
function Inspector:alreadyVisited(v)\
  return self.ids[v] ~= nil\
end\
\
function Inspector:getId(v)\
  local id = self.ids[v]\
  if not id then\
    local tv = type(v)\
    id              = (self.maxIds[tv] or 0) + 1\
    self.maxIds[tv] = id\
    self.ids[v]     = id\
  end\
  return tostring(id)\
end\
\
function Inspector:putKey(k)\
  if isIdentifier(k) then return self:puts(k) end\
  self:puts(\"[\")\
  self:putValue(k)\
  self:puts(\"]\")\
end\
\
function Inspector:putTable(t)\
  if t == inspect.KEY or t == inspect.METATABLE then\
    self:puts(tostring(t))\
  elseif self:alreadyVisited(t) then\
    self:puts('<table ', self:getId(t), '>')\
  elseif self.level >= self.depth then\
    self:puts('{...}')\
  else\
    if self.tableAppearances[t] > 1 then self:puts('<', self:getId(t), '>') end\
\
    local nonSequentialKeys, sequenceLength = getNonSequentialKeys(t)\
    local mt                = getmetatable(t)\
    local toStringResult    = getToStringResultSafely(t, mt)\
\
    self:puts('{')\
    self:down(function()\
      if toStringResult then\
        self:puts(' -- ', escape(toStringResult))\
        if sequenceLength >= 1 then self:tabify() end\
      end\
\
      local count = 0\
      for i=1, sequenceLength do\
        if count > 0 then self:puts(',') end\
        self:puts(' ')\
        self:putValue(t[i])\
        count = count + 1\
      end\
\
      for _,k in ipairs(nonSequentialKeys) do\
        if count > 0 then self:puts(',') end\
        self:tabify()\
        self:putKey(k)\
        self:puts(' = ')\
        self:putValue(t[k])\
        count = count + 1\
      end\
\
      if mt then\
        if count > 0 then self:puts(',') end\
        self:tabify()\
        self:puts('<metatable> = ')\
        self:putValue(mt)\
      end\
    end)\
\
    if #nonSequentialKeys > 0 or mt then -- result is multi-lined. Justify closing }\
      self:tabify()\
    elseif sequenceLength > 0 then -- array tables have one extra space before closing }\
      self:puts(' ')\
    end\
\
    self:puts('}')\
  end\
end\
\
function Inspector:putValue(v)\
  local tv = type(v)\
\
  if tv == 'string' then\
    self:puts(smartQuote(escape(v)))\
  elseif tv == 'number' or tv == 'boolean' or tv == 'nil' or\
         tv == 'cdata' or tv == 'ctype' then\
    self:puts(tostring(v))\
  elseif tv == 'table' then\
    self:putTable(v)\
  else\
    self:puts('<',tv,' ',self:getId(v),'>')\
  end\
end\
\
-------------------------------------------------------------------\
\
function inspect.inspect(root, options)\
  options       = options or {}\
\
  local depth   = options.depth   or math.huge\
  local newline = options.newline or '\\n'\
  local indent  = options.indent  or '  '\
  local process = options.process\
\
  if process then\
    root = processRecursive(process, root, {}, {})\
  end\
\
  local inspector = setmetatable({\
    depth            = depth,\
    level            = 0,\
    buffer           = {},\
    ids              = {},\
    maxIds           = {},\
    newline          = newline,\
    indent           = indent,\
    tableAppearances = countTableAppearances(root)\
  }, Inspector_mt)\
\
  inspector:putValue(root)\
\
  return table.concat(inspector.buffer)\
end\
\
setmetatable(inspect, { __call = function(_, ...) return inspect.inspect(...) end })\
\
return inspect\
\
"
, '@'.."./lualib/inspect.lua" ) )

package.preload[ "kengine" ] = assert( (loadstring or load)(
"local pcap = require\"pcap\"\
local csys = require\"c.sys\"\
local ctime = require\"c.time\"\
local timer = require(\"timer\")\
local log = require(\"log\")\
local actor = require(\"luactor\")\
local mystring = require(\"mystring\")\
local myip = require(\"myip\")\
local msocket = require(\"msocket\")\
\
local kengine = {\
    iface = \"\",\
    filter = \"\",\
    enable = false,\
    timeout = 300,              -- 5 minutes for session clean\
\
    co = nil,                   -- coroutine for read pcap\
\
    -- stat\
    failed_cnt = 0, \
    pub_cnt = 0, \
    msg = \"\", \
    iface_mac = \"\", \
    pp = nil,                   -- pcap object\
    status = \"\",                -- disable/initial/ok/failed\
    pkts = 0,\
    sess_all = 0,\
    sess_cnt = 0, \
    -- key: {sip, dip, sport, dport, proto, smac}\
    sess = {}\
}\
\
------------------------------------------------------------------\
-- session parse\
------------------------------------------------------------------\
local function session_key(one, out)\
    if out then\
        return one.sip .. \"_\" .. one.sport .. \"_\" .. one.proto .. \"_\" .. one.dip .. \"_\" .. one.dport\
    else\
        return one.dip .. \"_\" .. one.dport .. \"_\" .. one.proto .. \"_\" .. one.sip .. \"_\" .. one.sport\
    end\
end\
\
local function find_session(one, sess)\
    local key = session_key(one, true)\
    if sess[key] then\
        return sess[key], true\
    else\
        key = session_key(one, false) \
        if sess[key] then\
            return sess[key], false\
        end\
    end\
    return nil\
end\
\
local function timeout_session(sess, timenow)\
    local cnt = 0\
    for k, v in pairs(sess) do\
        if v.lasttime + kengine.timeout <= timenow then\
            sess[k] = nil\
            cnt = cnt + 1\
        end\
    end\
    return cnt\
end\
\
local function parse_session(one, sess)\
    local s, output = find_session(one, sess)\
    if s then\
        if dir then\
            s.outpkts = s.outpkts + 1\
            s.outbytes = s.outbytes + one.data:len()\
        else\
            s.inpkts = s.inpkts + 1\
            s.inbytes = s.inbytes + one.data:len()\
        end\
        return s, 0\
    else\
        if one.out then\
            local key = session_key(one, true)\
            sess[key] = {\
                tuple = {one.sip, one.sport, one.proto, one.dip, one.dport}, \
                inpkts = 0, outpkts = 0, inbytes = 0, outbytes = 0, \
            }\
            s = sess[key]\
        else\
            local key = session_key(one, false)\
            sess[key] = {\
                tuple = {one.dip, one.dport, one.proto, one.sip, one.sport}, \
                inpkts = 0, outpkts = 0, inbytes = 0, outbytes = 0, \
            }\
            s = sess[key]\
        end\
        return s, 1\
    end\
end\
\
\
------------------------------------------------------------------\
-- pkt parse\
------------------------------------------------------------------\
local function parse_pcap(data, timestamp)\
    -- ethhdr = \"c6c6H\", iphdr = \"BBHHHBBHc4c4\", tcphdr = \"HHc4c4HHHH\", udphdr = \"HHHH\", icmphdr = \"BBHc4\"\
    local offset = 1\
    local one = {dip = \"\", dport = 0, offset = 0, data = \"\"} -- smac/dmac, sip/dip, sport/dport, proto\
\
    local len = #data\
    if len < 34 then\
        return nil, \"too small len \"..len\
    end\
    local dmac, smac, h_proto = string.unpack(\">c6c6H\", data, offset)\
    offset = offset + 14\
    if h_proto ~= 0x0800 then -- ETH_P_IP\
        return nil, \"unknown ether type \"..h_proto..\" \"..mystring.data2hex(data)\
    end\
    one.smac = myip.mac_ntoa(smac)\
    one.dmac = myip.mac_ntoa(dmac)\
\
    one.iphdr_ihl = string.unpack(\">B\", data, offset)\
    one.ip_header_length = (one.iphdr_ihl & 0x0f) * 4\
    one.ip_total_length = string.unpack(\">H\", data, offset + 2)\
    one.proto, _, one.sip, one.dip = string.unpack(\">BHc4c4\", data, offset + 9)\
    one.sip = myip.inet_ntoa(one.sip)\
    one.dip = myip.inet_ntoa(one.dip)\
    offset = offset + one.ip_header_length\
\
    if one.proto == 1 and len >= offset + 8 then -- IPPROTO_ICMP\
        one.offset = offset + 8\
    elseif one.proto == 6 and len >= offset + 20 - 1 then -- IPPROTO_TCP  --the init value of offset is 1\
        one.sport, one.dport, _, _, one.tcphdr_doff = string.unpack(\">HHc4c4H\", data, offset)\
        one.l4_len = (one.tcphdr_doff >> 12) * 4\
        one.offset = offset + one.l4_len\
    elseif one.proto == 17 and len >= offset + 8 then -- IPPROTO_UDP\
        one.sport, one.dport, one.len = string.unpack(\">HHH\", data, offset)\
        one.l4_len = 8\
        one.offset = offset + one.l4_len\
    else\
        return nil, \"unknow proto \"..one.proto\
    end\
\
    if dmac == kengine.iface_mac then\
        one.out = true\
    elseif smac == kengine.iface_mac then\
        one.out = false\
    elseif dmac == \"\\xff\\xff\\xff\\xff\\xff\\xff\" then\
        one.out = true\
    else\
        --return nil, \"unknown smac, dmac\"\
        one.out = true\
    end\
    if type(one.l4_len) == \"number\" then\
        -- ethernet packet may have padding when packet length is small ( < 60 bytes), such as TCP ACK packet.\
        one.l7_len = one.ip_total_length - one.ip_header_length - one.l4_len\
    else\
        one.l7_len = -1\
    end\
    one.timestamp = timestamp\
    return one, nil\
end\
\
------------------------------------------------------------------\
-- main part\
------------------------------------------------------------------\
local function run_pcap(iface, filter, timeout_ms)\
    -- local ok, cap, open_err = pcall(pcap.open_live_immediate, iface, 0, true, timeout_ms)\
    local ok, cap, open_err = pcall(pcap.open_live_immediate, iface, 0, true, timeout_ms)\
    if not ok then\
        return nil, \"[ERROR] pcall open_live, \".. cap\
    end\
    if type(open_err) == \"string\" then\
        return nil, \"[ERROR] open_live:\" .. open_err\
    end\
\
    local ok, ret, set_err = pcall(cap.set_filter, cap, filter)\
    if not ok then\
        pcall(cap.close, cap)\
        return nil, \"[ERROR] pcall set_filter, \".. (ret or \"\")\
    end\
    if type(set_err) == \"string\" then\
        pcall(cap.close, cap)\
        return nil, \"[ERROR] set_filter, \".. set_err\
    end\
    return cap, nil\
end\
\
local function pcap_init()\
    -- delete old pp\
    if kengine.pp then\
        msocket.del(kengine.pp)\
        pcall(kengine.pp.close, kengine.pp)\
        kengine.pp = nil\
    end\
\
    kengine.status = \"initial\"\
    if kengine.enable and kengine.iface:len() > 0 then\
        kengine.pp, err = run_pcap(kengine.iface, kengine.filter, 100)\
        if err then\
            kengine.status = \"failed\"\
            kengine.failed_cnt = kengine.failed_cnt + 1\
            kengine.msg = err\
            return\
        else\
            kengine.status = \"ok\"\
            kengine.msg = \"\"\
            msocket.add(kengine.co, kengine.pp)\
        end\
    else\
        kengine.status = \"disable\"\
        kengine.msg = \"\"\
    end\
end\
\
local function guess_iface()\
    return \"eth0\"               -- TODO, guess lan iface\
end\
\
function kengine.write(t)\
    local reload = false\
\
    if type(t.iface) == \"string\" and t.iface ~= kengine.iface then\
        if t.iface == \"*\" then\
            kengine.iface = guess_iface()\
        else\
            kengine.iface = t.iface\
        end\
        local mac = csys.get_mac(kengine.iface)\
        if mac then\
            kengine.iface_mac = mac\
        end\
        reload = true\
    end\
\
    if type(t.enable) == \"boolean\" and t.enable ~= kengine.enable then\
        reload = true\
        kengine.enable = t.enable\
    end\
\
    if type(t.filter) == \"string\" and t.filter ~= kengine.filter then\
        reload = true\
        kengine.filter = t.filter\
    end\
\
    if reload then\
        pcap_init()\
    end\
end\
\
local function kengine_onepcap(capdata, time, wirelen)\
    kengine.pkts = kengine.pkts + 1\
    local one, err = parse_pcap(capdata, time)\
    if one then\
        -- local sess, cnt = parse_session(one, kengine.sess, time)\
        -- sess_cnt = sess_cnt + cnt\
        -- sess_all = sess_all + cnt\
        --actor.publish({msgtype = \"PCAP\", pcap_tables = {tuple = sess.tuple, out = one.out, pkt = one.data, offset = one.offset}})\
        actor.publish({msgtype = \"PCAP\",\
                       pcap_tables = {\
                           mac = one.out and one.smac or one.dmac,\
                           sip = one.sip,\
                           dip = one.dip, \
                           sport = one.sport or 0, \
                           dport = one.dport or 0, \
                           proto = one.proto, \
                           out = one.out,\
                           l7_len = one.l7_len,\
                           offset = one.offset, \
                           data = capdata, \
                           timestamp = one.timestamp, \
                       }\
        })\
        kengine.pub_cnt = kengine.pub_cnt + 1\
    else\
        --log.error(\"failed, \", err)\
    end\
end\
\
function kengine.stat()\
    return {enable = kengine.enable, iface = kengine.iface, filter = kengine.filter,\
            status = kengine.status, pkts = kengine.pkts, sess_all = kengine.sess_all, sess_cnt = kengine.sess_cnt, \
            iface_mac = mystring.data2hex(kengine.iface_mac), msg = kengine.msg,\
            failed_cnt = kengine.failed_cnt, pub_cnt = kengine.pub_cnt, pp = (kengine.pp and \"ud\") or \"nil\", \
    }\
end\
\
function kengine.read()\
    return {enable = kengine.enable, iface = kengine.iface, filter = kengine.filter}\
end\
\
local function pcap_coroutine()\
    while true do\
        if kengine.status == \"ok\" and kengine.pp ~= nil then\
            while true do\
                local ok, capdata, timestamp, wirelen = pcall(kengine.pp.next, kengine.pp)\
                if ok and capdata then\
                    pcall(kengine_onepcap, capdata, timestamp, wirelen)\
                elseif timestamp == \"timeout\" then\
                    break\
                else\
                    log.warn(\"failed to read pcap, \", ok, capdata, timestamp)\
                    kengine.status = \"failed\"\
                    kengine.failed_cnt = kengine.failed_cnt + 1\
                    kengine.msg = timestamp  -- timestamp is errmsg\
                    pcap_init()\
                    break\
                end\
            end\
        end\
        coroutine.yield()\
    end\
end\
\
function kengine.setdefault_ifneeded(t)\
    if not kengine.enable or kengine.iface == \"\" then\
        -- means no config\
        kengine.write(t)\
    end\
end\
\
function kengine.kengine_init()\
    -- 2 minutes for clean timeout session\
    timer.mod(\"kengine_clean\", 120, 0, function () timeout_session(kengine.sess, ctime.get_uptime()) end)\
    timer.mod(\"kengine_restart\", 120, 0,\
              function () \
                  if kengine.status == \"failed\" then\
                      pcap_init()\
                  end\
              end\
    )\
    kengine.co = msocket.coroutine_create(\"kengine_co\", 0, pcap_coroutine)\
    msocket.coroutine_resume(kengine.co)\
end\
\
return kengine\
"
, '@'.."./lualib/kengine/kengine.lua" ) )

package.preload[ "lanhost" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local log = require\"log\"\
local cct = require\"c.ct\"\
local socket = require \"socket\"\
\
local lanhost = {\
    type = \"__get_lan_host\", \
    subtype = \"__get_lan_host\", \
    help = \"get lan host for ct\", \
}\
\
local function get_lanhost()\
    local hosts = cct.getlanhost()\
    local tt = {}\
\
    for m, v in pairs(hosts) do\
        local info = cct.showlan(v.userdata)\
        table.insert(tt, info)\
    end\
    return tt\
end\
\
local function check_lanhost()\
    local hosts = cct.getlanhost()\
\
    assert(hosts)\
    local tt, original, update_test, update_original = {}, {}, {}, {}\
    local saved = {}\
    -- original\
    for m, v in pairs(hosts) do\
        local info = cct.showlan(v.userdata)\
        table.insert(original, info)\
        saved[m] = {brand = info.brand, model = info.model, devtype = info.devtype, os = info.os, devtypeint = info.devtypeint}\
    end\
    -- update test\
    for m, v in pairs(hosts) do\
        cct.setlanhost(m, \"测试model\", \"测试brand\", 0, \"测试OS\", \"phone\", v.userdata)\
    end\
    update_test = get_lanhost()\
    -- update original\
    hosts = cct.getlanhost()\
    for m, v in pairs(hosts) do\
        if saved[m] then\
            cct.setlanhost(m, saved[m].model, saved[m].brand, saved[m].devtypeint, saved[m].os, saved[m].devtype, v.userdata)\
        end\
    end\
    update_original = get_lanhost()\
\
    tt.original_host = original\
    tt.update_test_host = update_test\
    tt.update_original_host = update_original\
\
    return tt\
end\
\
local function check_list()\
    local tt = check_lanhost()\
    local _, arch = lcmd_run{subtype = \"arch\", action = \"read\"}\
    local pppoe = cct.getpppoe()\
    tt.get_pppoe = {return_code = 0, val = pppoe}\
\
    return tt\
end\
\
local function read_lanhost()\
    local hosts = cct.getlanhost()\
\
    assert(hosts)\
    local tt = {}\
    for _, v in pairs(hosts) do\
        local info = cct.showlan(v.userdata)\
        info.mac = info.macstring\
        table.insert(tt, info)\
    end\
\
    return {get_lan_host = {return_code = 0, host_num = #tt, hosts = tt}}\
end\
\
local function read_wan()\
    local wans = cct.getwans()\
    assert(wans)\
\
    local tt = {}\
    for _, v in pairs(wans) do \
        table.insert(tt, cct.showwan(v.userdata))\
    end\
    return tt\
end\
\
local function get_wlan(t)\
    local start = socket.gettime()\
    local wlan = cct.getwandevbyindex(t.index)\
    local stop = socket.gettime()\
    assert(wlan)\
    wlan[\"call_time\"] = stop - start\
    return wlan\
end\
\
actor.action_set(lanhost.subtype, \"read\", read_lanhost, \"get lan host for ct\")\
actor.action_set(\"__get_wan\", \"read\", read_wan, \"get waninfo for ct\")\
actor.action_set(\"__check_list\", \"read\", check_list, \"get waninfo for ct\")\
actor.action_set(lanhost.subtype, \"get_wlan\", get_wlan, \"get wlaninfo for ct,{index = int}, -1 means getall\")\
\
return lanhost\
"
, '@'.."./service/lanhost.lua" ) )

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

package.preload[ "log" ] = assert( (loadstring or load)(
"--\
-- log.lua\
--\
-- Copyright (c) 2016 rxi\
--\
-- This library is free software; you can redistribute it and/or modify it\
-- under the terms of the MIT license. See LICENSE for details.\
--\
local myfile = require\"myfile\"\
\
local log = { \
    _version = \"0.1.0\",\
    usecolor = true,\
    outfile = nil,\
    lineinfo = false,\
    level = \"error\",\
    write_cnt = 0,\
    max_log_len = 200000,\
    tag = \"\",\
}\
\
\
local modes = {\
  { name = \"trace\", color = \"\\27[1;34m\", },\
  { name = \"debug\", color = \"\\27[36m\", },\
  { name = \"info\",  color = \"\\27[32m\", },\
  { name = \"warn\",  color = \"\\27[33m\", },\
  { name = \"error\", color = \"\\27[31m\", },\
  { name = \"fatal\", color = \"\\27[35m\", },\
}\
\
\
local levels = {}\
for i, v in ipairs(modes) do\
  levels[v.name] = i\
end\
\
\
local round = function(x, increment)\
  increment = increment or 1\
  x = x / increment\
  return (x > 0 and math.floor(x + .5) or math.ceil(x - .5)) * increment\
end\
\
\
\
local _tostring = tostring\
\
local tostring = function(...)\
  local t = {}\
  for i = 1, select('#', ...) do\
    local x = select(i, ...)\
    if type(x) == \"number\" then\
      x = round(x, .01)\
    end\
    t[#t + 1] = _tostring(x)\
  end\
  return table.concat(t, \" \")\
end\
\
\
for i, x in ipairs(modes) do\
  local nameupper = x.name:upper()\
  log[x.name] = function(...)\
    \
    -- Return early if we're below the log level\
    if i < levels[log.level] then\
      return\
    end\
\
    local msg = tostring(...)\
    local info = debug.getinfo(2, \"Sl\")\
    local lineinfo = \"\"\
\
    if log.lineinfo then\
       lineinfo = info.short_src .. \":\" .. info.currentline\
    end\
\
    -- Output to console\
    print(string.format(\"%s[%-6s%s]%s %s%s: %s\",\
                        log.usecolor and x.color or \"\",\
                        nameupper,\
                        os.date(\"%Y-%m-%d %H:%M:%S\"),\
                        log.usecolor and \"\\27[0m\" or \"\",\
                        log.tag,\
                        lineinfo,\
                        msg))\
\
    -- Output to log file\
    if log.outfile then\
        local str = string.format(\"[%-6s%s] %s%s: %s\\n\",\
                                nameupper, os.date(\"%Y-%m-%d %H:%M:%S\"), log.tag, lineinfo, msg)\
\
        local mode = 'a'\
        if log.write_cnt > 100 then\
            local log_len = myfile.length_of_file(log.outfile)\
            if log_len > log.max_log_len then\
                myfile.copy(log.outfile , log.outfile .. \".old\")\
                mode = 'w'\
            end\
\
            log.write_cnt = 0\
        end\
\
        local fp = io.open(log.outfile, mode)\
        if fp then\
            fp:write(str)\
            fp:close()\
\
            log.write_cnt = log.write_cnt + 1\
        end\
    end\
  end\
end\
\
return log\
\
"
, '@'.."./lualib/log.lua" ) )

package.preload[ "ltn12" ] = assert( (loadstring or load)(
"-----------------------------------------------------------------------------\
-- LTN12 - Filters, sources, sinks and pumps.\
-- LuaSocket toolkit.\
-- Author: Diego Nehab\
-----------------------------------------------------------------------------\
\
-----------------------------------------------------------------------------\
-- Declare module\
-----------------------------------------------------------------------------\
local string = require(\"string\")\
local table = require(\"table\")\
local unpack = unpack or table.unpack\
local base = _G\
local _M = {}\
if module then -- heuristic for exporting a global package table\
    ltn12 = _M\
end\
local filter,source,sink,pump = {},{},{},{}\
\
_M.filter = filter\
_M.source = source\
_M.sink = sink\
_M.pump = pump\
\
local unpack = unpack or table.unpack\
local select = base.select\
\
-- 2048 seems to be better in windows...\
_M.BLOCKSIZE = 2048\
_M._VERSION = \"LTN12 1.0.3\"\
\
-----------------------------------------------------------------------------\
-- Filter stuff\
-----------------------------------------------------------------------------\
-- returns a high level filter that cycles a low-level filter\
function filter.cycle(low, ctx, extra)\
    base.assert(low)\
    return function(chunk)\
        local ret\
        ret, ctx = low(ctx, chunk, extra)\
        return ret\
    end\
end\
\
-- chains a bunch of filters together\
-- (thanks to Wim Couwenberg)\
function filter.chain(...)\
    local arg = {...}\
    local n = base.select('#',...)\
    local top, index = 1, 1\
    local retry = \"\"\
    return function(chunk)\
        retry = chunk and retry\
        while true do\
            if index == top then\
                chunk = arg[index](chunk)\
                if chunk == \"\" or top == n then return chunk\
                elseif chunk then index = index + 1\
                else\
                    top = top+1\
                    index = top\
                end\
            else\
                chunk = arg[index](chunk or \"\")\
                if chunk == \"\" then\
                    index = index - 1\
                    chunk = retry\
                elseif chunk then\
                    if index == n then return chunk\
                    else index = index + 1 end\
                else base.error(\"filter returned inappropriate nil\") end\
            end\
        end\
    end\
end\
\
-----------------------------------------------------------------------------\
-- Source stuff\
-----------------------------------------------------------------------------\
-- create an empty source\
local function empty()\
    return nil\
end\
\
function source.empty()\
    return empty\
end\
\
-- returns a source that just outputs an error\
function source.error(err)\
    return function()\
        return nil, err\
    end\
end\
\
-- creates a file source\
function source.file(handle, io_err)\
    if handle then\
        return function()\
            local chunk = handle:read(_M.BLOCKSIZE)\
            if not chunk then handle:close() end\
            return chunk\
        end\
    else return source.error(io_err or \"unable to open file\") end\
end\
\
-- turns a fancy source into a simple source\
function source.simplify(src)\
    base.assert(src)\
    return function()\
        local chunk, err_or_new = src()\
        src = err_or_new or src\
        if not chunk then return nil, err_or_new\
        else return chunk end\
    end\
end\
\
-- creates string source\
function source.string(s)\
    if s then\
        local i = 1\
        return function()\
            local chunk = string.sub(s, i, i+_M.BLOCKSIZE-1)\
            i = i + _M.BLOCKSIZE\
            if chunk ~= \"\" then return chunk\
            else return nil end\
        end\
    else return source.empty() end\
end\
\
-- creates rewindable source\
function source.rewind(src)\
    base.assert(src)\
    local t = {}\
    return function(chunk)\
        if not chunk then\
            chunk = table.remove(t)\
            if not chunk then return src()\
            else return chunk end\
        else\
            table.insert(t, chunk)\
        end\
    end\
end\
\
-- chains a source with one or several filter(s)\
function source.chain(src, f, ...)\
    if ... then f=filter.chain(f, ...) end\
    base.assert(src and f)\
    local last_in, last_out = \"\", \"\"\
    local state = \"feeding\"\
    local err\
    return function()\
        if not last_out then\
            base.error('source is empty!', 2)\
        end\
        while true do\
            if state == \"feeding\" then\
                last_in, err = src()\
                if err then return nil, err end\
                last_out = f(last_in)\
                if not last_out then\
                    if last_in then\
                        base.error('filter returned inappropriate nil')\
                    else\
                        return nil\
                    end\
                elseif last_out ~= \"\" then\
                    state = \"eating\"\
                    if last_in then last_in = \"\" end\
                    return last_out\
                end\
            else\
                last_out = f(last_in)\
                if last_out == \"\" then\
                    if last_in == \"\" then\
                        state = \"feeding\"\
                    else\
                        base.error('filter returned \"\"')\
                    end\
                elseif not last_out then\
                    if last_in then\
                        base.error('filter returned inappropriate nil')\
                    else\
                        return nil\
                    end\
                else\
                    return last_out\
                end\
            end\
        end\
    end\
end\
\
-- creates a source that produces contents of several sources, one after the\
-- other, as if they were concatenated\
-- (thanks to Wim Couwenberg)\
function source.cat(...)\
    local arg = {...}\
    local src = table.remove(arg, 1)\
    return function()\
        while src do\
            local chunk, err = src()\
            if chunk then return chunk end\
            if err then return nil, err end\
            src = table.remove(arg, 1)\
        end\
    end\
end\
\
-----------------------------------------------------------------------------\
-- Sink stuff\
-----------------------------------------------------------------------------\
-- creates a sink that stores into a table\
function sink.table(t)\
    t = t or {}\
    local f = function(chunk, err)\
        if chunk then table.insert(t, chunk) end\
        return 1\
    end\
    return f, t\
end\
\
-- turns a fancy sink into a simple sink\
function sink.simplify(snk)\
    base.assert(snk)\
    return function(chunk, err)\
        local ret, err_or_new = snk(chunk, err)\
        if not ret then return nil, err_or_new end\
        snk = err_or_new or snk\
        return 1\
    end\
end\
\
-- creates a file sink\
function sink.file(handle, io_err)\
    if handle then\
        return function(chunk, err)\
            if not chunk then\
                handle:close()\
                return 1\
            else return handle:write(chunk) end\
        end\
    else return sink.error(io_err or \"unable to open file\") end\
end\
\
-- creates a sink that discards data\
local function null()\
    return 1\
end\
\
function sink.null()\
    return null\
end\
\
-- creates a sink that just returns an error\
function sink.error(err)\
    return function()\
        return nil, err\
    end\
end\
\
-- chains a sink with one or several filter(s)\
function sink.chain(f, snk, ...)\
    if ... then\
        local args = { f, snk, ... }\
        snk = table.remove(args, #args)\
        f = filter.chain(unpack(args))\
    end\
    base.assert(f and snk)\
    return function(chunk, err)\
        if chunk ~= \"\" then\
            local filtered = f(chunk)\
            local done = chunk and \"\"\
            while true do\
                local ret, snkerr = snk(filtered, err)\
                if not ret then return nil, snkerr end\
                if filtered == done then return 1 end\
                filtered = f(done)\
            end\
        else return 1 end\
    end\
end\
\
-----------------------------------------------------------------------------\
-- Pump stuff\
-----------------------------------------------------------------------------\
-- pumps one chunk from the source to the sink\
function pump.step(src, snk)\
    local chunk, src_err = src()\
    local ret, snk_err = snk(chunk, src_err)\
    if chunk and ret then return 1\
    else return nil, src_err or snk_err end\
end\
\
-- pumps all data from a source to a sink, using a step function\
function pump.all(src, snk, step)\
    base.assert(src and snk)\
    step = step or pump.step\
    while true do\
        local ret, err = step(src, snk)\
        if not ret then\
            if err then return nil, err\
            else return 1 end\
        end\
    end\
end\
\
return _M\
"
, '@'.."./lualib/ltn12.lua" ) )

package.preload[ "luactor" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local cj = require\"cjson\"\
local pb = require\"pb\"\
\
local actor = {\
    action = {},                -- all actions store here, using subtype as key\
    help = {},                  -- subtype helps\
    mysubscribe = {},           -- subscribe/publish \
    sindex = 0,                 -- subscribe index for unsubscribe\
    postinit = {}, \
    pbtype = {},               -- protobuf type\
    pbcnt = {},                 -- publish count\
\
    extperm = {                 -- external call permission control\
    --[[\
        enable = true,\
        whitelist = {\
            sys = {},           -- empty table {} means that all actions of this subtype are permitted\
            arch = {\
                read = true,\
            },\
        },\
    ]]--\
    },\
}\
\
-- upload type\
-- pbtype \
function actor.pbtype_add(uploadtype, pbtype)\
    if uploadtype == nil or pbtype == nil then\
        return \"Empty pbtype and subtype, add failed\"\
    end\
    actor.pbtype[uploadtype] = pbtype\
end\
\
function actor.pbtype_get(uploadtype)\
    return actor.pbtype[uploadtype] \
end\
\
function actor.publish(msg)\
    assert(msg.msgtype)\
    if type(actor.mysubscribe[msg.msgtype]) == \"table\" then\
        actor.pbcnt[msg.msgtype] = actor.pbcnt[msg.msgtype] + 1\
        for _, v in pairs(actor.mysubscribe[msg.msgtype]) do\
            v(msg)\
        end\
    end\
end\
\
function actor.subscribe(msgtype, func)\
    assert(msgtype and func)\
    if not actor.mysubscribe[msgtype] then\
        actor.pbcnt[msgtype] = 0\
        actor.mysubscribe[msgtype] = {}\
    end\
    actor.sindex = actor.sindex + 1\
    actor.mysubscribe[msgtype][actor.sindex] = func\
    return actor.sindex\
end\
\
function actor.unsubscribe(msgtype, index)\
    assert(msgtype and index)\
    if actor.mysubscribe[msgtype] and actor.mysubscribe[msgtype][index] then\
        actor.mysubscribe[msgtype][index] = nil\
    end\
end\
\
function actor.actor_add(service)\
    if type(service.help) ~= \"string\" or service.help == \"\" then\
        return \"Empty help string, Must not allowed\"\
    end\
\
    if service.type == nil and service.subtype == nil then\
        return \"Empty type and subtype, at least only one type\"\
    end\
\
    if service.type == nil then service.type = \"lua_cmd\" end\
    if service.subtype == nil then service.subtype = service.type end\
\
    if actor.help[service.subtype] then\
        return \"Duplicate subtype \"..subtype\
    end\
\
    if type(service.postinit) == \"function\" then\
        table.insert(actor.postinit, service.postinit)\
    end\
\
    actor.help[service.subtype] = {help = service.help, type = service.type}\
end\
\
function actor.actor_del(subtype)\
    if type(subtype) == \"string\" then\
        actor.help[subtype] = nil\
        actor.action[subtype] = nil\
    end\
end\
\
local function actor_help_subtype(types, subtype)\
    local msg = {}\
    if subtype == nil and types == nil then\
        log.info(\"will get all help\")\
        for k, v in pairs(actor.help) do \
            table.insert(msg, {type = v.type, subtype = k, help = v.help})\
        end\
        return msg\
    elseif subtype == nil and types ==\"lua_cmd\" then\
        log.info(\"will get lua_cmd all subtype help\")\
        for k, v in pairs(actor.help) do \
            if v.type == types then\
                table.insert(msg, {type = v.type, subtype = k, help = v.help})\
            end\
        end\
        return msg\
    elseif subtype == nil then \
        subtype = types\
    end\
\
    local v = actor.help[subtype] \
    log.info(\"will get \"..subtype..\" help\")\
    if v then\
        msg = {type = v.type, subtype = subtype, help = v.help, actions = {}}\
        if actor.action[subtype] then\
            for k, _ in pairs(actor.action[subtype]) do\
                table.insert(msg.actions, k)\
            end\
        end\
    end\
\
    return msg\
end\
\
local function actor_help_action(types, subtype, name)\
    if name == nil then\
        return actor_help_subtype(types, subtype)\
    end\
\
    if subtype == nil then\
        subtype = types\
    end\
\
    log.info(\"will get action '\"..name..\"' help with subtype \"..subtype)\
    local v = actor.action[subtype]\
    if v and v[name] then\
        return v[name].desc\
    end\
\
    return {}\
end\
\
local function action_get(subtype, name)\
    local t = actor.action[subtype]\
    if t and t[name] and type(t[name].func) == \"function\" then\
        return t[name].func, nil\
    end\
\
    return nil, \"No such action for subtype '\"..subtype..\"' action '\"..name..\"', failed to deal reply\"\
end\
\
local function set_all_luacmd(t)\
    for _, v in pairs(t) do\
        if v.subtype then\
            local func, err = action_get(v.subtype, \"write\")\
            -- log.error(string.format(\"will write %s with %s\", v.subtype, cj.encode(v)))\
            if err then\
                log.warn(err)\
            else\
                func(v)\
            end\
        end\
    end\
end\
\
local function traversal_service(t)\
    if type(t.action) ~= \"string\" then\
        log.error(\"traversal service error: action \", type(t.action), cj.encode(t))\
        return\
    end\
    log.info(\"Empty type and subtype, will traversal all service with action \"..t.action)\
    local tt = {}\
    for k, v in pairs(actor.action) do\
        if v[t.action] and type(v[t.action].func) == \"function\" then\
            local result = v[t.action].func(t)\
            if type(result) == \"table\" then\
                table.insert(tt, result)\
            end\
        end\
    end\
\
    return tt\
end\
\
local function extperm_permitted(t, extperm)\
    if not extperm.enable then\
        return true\
    end\
    if t.subtype == nil or t.action == nil then\
        return false\
    end\
    local pinfo = extperm.whitelist[t.subtype]\
    if pinfo == nil then\
        return false\
    end\
    if not next(pinfo) then\
        -- empty table {} means that all actions of this subtype are permitted\
        return true\
    end\
    if pinfo[t.action] then\
        return true\
    end\
    return false\
end\
\
function actor.extperm_set(t)\
    if type(t.enable) == \"boolean\" then\
        actor.extperm.enable = t.enable\
    end\
    if type(t.whitelist) == \"table\" then\
        local whitelist = {}\
        for subtype, v in pairs(t.whitelist) do\
            if type(v) == \"table\" then\
                whitelist[subtype] = {}\
                for _, action in ipairs(v) do\
                    whitelist[subtype][action] = true\
                end\
            end\
        end\
        actor.extperm.whitelist = whitelist\
    end\
end\
\
function actor.extperm_get()\
    local t = {\
        enable = actor.extperm.enable and true or false,\
        whitelist = {},\
    }\
    if actor.extperm.whitelist then\
        for subtype, v in pairs(actor.extperm.whitelist) do\
            t.whitelist[subtype] = {}\
            for action, _ in pairs(v) do\
                table.insert(t.whitelist[subtype], action)\
            end\
        end\
    end\
    return t\
end\
\
function actor.deal_reply(t)\
    -- non-main_process, need check permission\
    if t.nonmainp and not extperm_permitted(t, actor.extperm) then\
        return\
    end\
\
    -- log.info(cj.encode(t)), MUST NOT PRINT, for t will has function\
    if t.action == \"help\" then\
        if t.name == nil then\
            return actor_help_subtype(t.type, t.subtype)\
        else\
            return actor_help_action(t.type, t.subtype, t.name)\
        end\
    end\
\
    if t.type == nil and t.subtype == nil then\
        return traversal_service(t)\
    end\
\
    if t.subtype == nil then\
        if t.type == \"lua_cmd\" and type(t.all_conf) == \"table\" then\
            set_all_luacmd(t.all_conf)\
            return\
        else\
            t.subtype = t.type\
        end\
    end\
\
    if t.action == nil then\
        if t.need_return == 1 then\
            t.action = 'read'\
        else\
            t.action = 'write'\
        end\
    end\
    local func, err = action_get(t.subtype, t.action)\
    if err then\
        log.warn(err)\
    else\
        local ok, r = pcall(func, t)\
        if not ok then\
            log.error(\"failed to deal subtype action \", t.subtype, t.action, \"error is \", r)\
        end\
        return r\
    end\
end\
\
function actor.action_set(subtype, name, func, desc, pb_in, pb_out)\
    if desc == nil or desc == \"\" then\
        return \"Empty desc, Must not allowed\"\
    end\
\
    local t = actor.action[subtype] -- using subtype as key\
    if t and t[name] then\
        return \"Duplicate action \" .. name\
    end\
\
    if t == nil then\
        actor.action[subtype] = {}\
        t = actor.action[subtype]\
    end\
\
    t[name] = {type = \"lua_cmd\", func = func, desc = desc, name = name, pbin = pb_in, pbout = pb_out}\
end\
\
function actor.pb_inout(subtype, action)\
    local t = actor.action[subtype]\
    if t and t[action] and type(t[action].func) == \"function\" then\
        return t[action].pbin, t[action].pbout\
    end\
end\
\
function actor.pb_init()\
    local ok, pbmsg = pcall(require, \"pbmsg\")\
    if not ok then\
        log.error(\"No pbmsg for protobuf, \", pbmsg)\
        return\
    end\
    local mystring = require\"mystring\"\
    for k, v in pairs(pbmsg) do\
        local data = mystring.hex2data(v)\
        ok, msg = pb.load(data)\
        if not ok then\
            log.error(\"Failed to pb.load, \", k, ok, msg)\
        else\
            log.info(\"OK to pb.load, \", k)\
        end\
    end\
end\
\
function actor.post_init()\
    local err\
    for _, v in pairs(actor.postinit) do \
        local ok, r = pcall(v)\
        if not ok then\
            err = \"failed to do postinit, error is \"..r\
            log.error(err)\
        end\
    end\
    actor.postinit = {}\
    return err\
end\
\
return actor\
"
, '@'.."./lualib/luactor.lua" ) )

package.preload[ "mdns" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local cjson = require(\"cjson\")\
local timer = require(\"timer\")\
local log = require(\"log\")\
local socket = require(\"socket\")\
local mystring = require(\"mystring\")\
\
local mdns = {\
    type = \"mdns\",\
    subtype = \"mdns\",\
    help = \"mdns find host\",\
    error_count = 0,\
    ip = \"\",\
    iface = \"br0\"\
}\
\
local function mdns_query(service)\
    local data = '\\000\\000'..'\\000\\000'..'\\000\\001'..'\\000\\000'..'\\000\\000'..'\\000\\000'\
    for n in service:gmatch('([^\\\\.]+)') do\
        data = data..string.char(#n)..n\
    end\
    return data..string.char(0)..'\\000\\012'..'\\000\\001'\
end\
\
\
local function mdns_parse(service, data, answers)\
    local function parse_name(data, offset)\
        local n,d,l = '', '', data:byte(offset)\
        while (l > 0) do\
            if (l >= 192) then -- pointer\
                local p = (l % 192) * 256 + data:byte(offset + 1)\
                return n..d..parse_name(data, p + 1), offset + 2\
            end\
            n = n..d..data:sub(offset + 1, offset + l)\
            offset = offset + l + 1\
            l = data:byte(offset)\
            d = '.'\
        end\
        return n, offset + 1\
    end\
\
    local function bit_set(val, mask)\
        return val % (mask + mask) >= mask\
    end\
\
    if (not data) then\
        return nil, 'no data'\
    end\
    local len = #data\
    if (len < 12) then\
        return nil, 'truncated'\
    end\
\
    local header = {\
        id = data:byte(1) * 256 + data:byte(2),\
        flags = data:byte(3) * 256 + data:byte(4),\
        qdcount = data:byte(5) * 256 + data:byte(6),\
        ancount = data:byte(7) * 256 + data:byte(8),\
        nscount = data:byte(9) * 256 + data:byte(10),\
        arcount = data:byte(11) * 256 + data:byte(12),\
    }\
    if (not bit_set(header.flags, 0x8000)) then\
        return nil, 'not a reply'\
    end\
    if (bit_set(header.flags, 0x0200)) then\
        return nil, 'TC bit is set'\
    end\
    if (header.ancount == 0) then\
        return nil, 'no answer records'\
    end\
\
    local name\
    local offset = 13\
    if (header.qdcount > 0) then\
        for i=1, header.qdcount do\
            if (offset > len) then\
                return nil, 'truncated'\
            end\
            name, offset = parse_name(data, offset)\
            offset = offset + 4\
        end\
    end\
\
    for i=1, header.ancount do\
        if (offset > len) then\
            return nil, 'truncated'\
        end\
\
        name, offset = parse_name(data, offset)\
        local type = data:byte(offset + 0) * 256 + data:byte(offset + 1)\
        local rdlength = data:byte(offset + 8) * 256 + data:byte(offset + 9)\
        local rdoffset = offset + 10\
\
        if (type == 12) then\
            local target = parse_name(data, rdoffset)\
            table.insert(answers, target)\
        end\
\
        -- next answer record\
        offset = offset + 10 + rdlength\
    end\
\
    return answers\
end\
\
function get_mdns(t)\
    local service = '_services._dns-sd._udp.local'\
    local timeout = 2\
    local ip, port, udp = '224.0.0.251', 5353, socket.udp4()\
    local info = {}\
    local ipaddr = mdns.ip\
    if not ipaddr or ipaddr == \"\" then\
        ok, ipaddr = myip.getip(mdns.iface)\
        if not ok then\
            return info\
        end\
        mdns.ip = ipaddr\
    end\
\
    assert(udp:setoption('ip-multicast-if', ipaddr))\
    assert(udp:setoption('reuseaddr', true))\
    assert(udp:setsockname(ip, port))\
    assert(udp:setoption('ip-add-membership', {interface = ipaddr, multiaddr = ip }))\
    assert(udp:settimeout(0.1))\
    assert(udp:sendto(mdns_query(service), ip, port))\
\
    local mdns_type = {}\
    local start = os.time()\
    while (os.time() - start < timeout) do\
        local data, peeraddr, peerport = udp:receivefrom()\
        if data and (peerport == port) then\
            local _, err = mdns_parse(service, data, mdns_type)\
            if err and err ~= \"not a reply\" then\
                mdns.error_count = mdns.error_count + 1\
            end\
        end\
    end\
\
    for _, ptr in ipairs(mdns_type) do\
        assert(udp:sendto(mdns_query(ptr), ip, port))\
    end\
    start = os.time()\
    while (os.time() - start < timeout) do\
        local data, peeraddr, peerport = udp:receivefrom()\
        if data and (peerport == port) then\
            local answers = {}\
            local _,err = mdns_parse(service, data, answers)\
            if err and err ~= \"not a reply\" then\
                mdns.error_count = mdns.error_count + 1\
            end\
            if peeraddr then\
                if #answers > 0 then\
                    info[peeraddr] = answers\
                end\
            end\
        end\
    end\
    assert(udp:setoption(\"ip-drop-membership\", { interface = ipaddr, multiaddr = ip }))\
    assert(udp:close())\
    udp = nil\
    \
    local tt = {}\
    local arp = myip.getarp()\
    for ip,dev_info in pairs(info) do\
        local mac = arp[ip] --arp中的IP对应的mac给mac\
        mac = myip.mac_check(\"\", mac)\
        if mac then\
            tt[mac] = dev_info --{[mac] = devinfo}\
        end\
    end\
    return tt\
\
end\
\
local function write(msg)\
    if msg.iface then\
        mdns.iface = msg.iface\
        mdns.ip = \"\"\
    end\
end\
\
actor.action_set(mdns.subtype, \"read\", function () return {period = mdns.period, iface = mdns.iface} end, \"read period and stat\")\
actor.action_set(mdns.subtype, \"write\", write, [[set iface, {iface = string}]])\
actor.action_set(mdns.subtype, \"get_mdns\", get_mdns, [[show mdns info]])\
return mdns\
"
, '@'.."./service/mdns.lua" ) )

package.preload[ "mime" ] = assert( (loadstring or load)(
"-----------------------------------------------------------------------------\
-- MIME support for the Lua language.\
-- Author: Diego Nehab\
-- Conforming to RFCs 2045-2049\
-----------------------------------------------------------------------------\
\
-----------------------------------------------------------------------------\
-- Declare module and import dependencies\
-----------------------------------------------------------------------------\
local base = _G\
local ltn12 = require(\"ltn12\")\
local mime = require(\"mime.core\")\
local io = require(\"io\")\
local string = require(\"string\")\
local _M = mime\
\
-- encode, decode and wrap algorithm tables\
local encodet, decodet, wrapt = {},{},{}\
\
_M.encodet = encodet\
_M.decodet = decodet\
_M.wrapt   = wrapt  \
\
-- creates a function that chooses a filter by name from a given table\
local function choose(table)\
    return function(name, opt1, opt2)\
        if base.type(name) ~= \"string\" then\
            name, opt1, opt2 = \"default\", name, opt1\
        end\
        local f = table[name or \"nil\"]\
        if not f then \
            base.error(\"unknown key (\" .. base.tostring(name) .. \")\", 3)\
        else return f(opt1, opt2) end\
    end\
end\
\
-- define the encoding filters\
encodet['base64'] = function()\
    return ltn12.filter.cycle(_M.b64, \"\")\
end\
\
encodet['quoted-printable'] = function(mode)\
    return ltn12.filter.cycle(_M.qp, \"\",\
        (mode == \"binary\") and \"=0D=0A\" or \"\\r\\n\")\
end\
\
-- define the decoding filters\
decodet['base64'] = function()\
    return ltn12.filter.cycle(_M.unb64, \"\")\
end\
\
decodet['quoted-printable'] = function()\
    return ltn12.filter.cycle(_M.unqp, \"\")\
end\
\
local function format(chunk)\
    if chunk then\
        if chunk == \"\" then return \"''\"\
        else return string.len(chunk) end\
    else return \"nil\" end\
end\
\
-- define the line-wrap filters\
wrapt['text'] = function(length)\
    length = length or 76\
    return ltn12.filter.cycle(_M.wrp, length, length)\
end\
wrapt['base64'] = wrapt['text']\
wrapt['default'] = wrapt['text']\
\
wrapt['quoted-printable'] = function()\
    return ltn12.filter.cycle(_M.qpwrp, 76, 76)\
end\
\
-- function that choose the encoding, decoding or wrap algorithm\
_M.encode = choose(encodet)\
_M.decode = choose(decodet)\
_M.wrap = choose(wrapt)\
\
-- define the end-of-line normalization filter\
function _M.normalize(marker)\
    return ltn12.filter.cycle(_M.eol, 0, marker)\
end\
\
-- high level stuffing filter\
function _M.stuff()\
    return ltn12.filter.cycle(_M.dot, 2)\
end\
\
return _M"
, '@'.."./lualib/mime.lua" ) )

package.preload[ "msocket" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local socket = require\"socket\"\
local timer = require\"timer\"\
\
-- multi concurrent socket\
local msocket = {\
    maxcount = 3,                 -- check coroutine name\
    mapco = {},                   -- map for socket to coroutine\
    rd = {},                      -- read socket for select\
    wd = {},                      -- write socket for select\
    co = {},                      -- all coroutine store here\
}\
\
function msocket.read()\
    local cocnt, rdcnt, wdcnt, mapcocnt = 0, 0, 0, 0\
    for _, _ in pairs(msocket.mapco) do\
        mapcocnt = mapcocnt + 1\
    end\
\
    local costat = {}\
    for k, v in pairs(msocket.co) do\
        cocnt = cocnt + 1\
        table.insert(costat, {status = coroutine.status(k), fdcnt = v.fdcnt, name = v.name, timeout = v.timeout})\
    end\
    return {mapcocnt = mapcocnt, rdcnt = #msocket.rd, wdcnt = #msocket.wd, cocnt = cocnt, costat = costat, maxcount = msocket.maxcount}\
end\
\
function msocket.write(t)\
    if type(t.maxcount) == \"number\" and t.maxcount ~= msocket.maxcount then\
        msocket.maxcount = t.maxcount\
    end\
end\
\
function msocket.polite_receive(s, len)\
    local buf = \"\" err = nil\
    while true do\
        local data, err, part = s:receive(len)\
        log.trace(\"polite receive, len \"..len, \"#data \", (data and #data) or 0, \"#part \", (part and #part) or 0, \", err is \", err)\
        if not err then\
            return buf..data, nil\
        elseif err ~= \"timeout\" and err ~= \"wantread\" then\
            return nil, err\
        else                    -- timeout\
            if part then\
                buf = buf..part\
                len = len - #part\
            end\
            local exit = coroutine.yield()\
            if exit then\
                return nil, \"exit op received\"\
            end\
        end\
    end\
end\
\
function msocket.polite_send(s, buf)\
    local start = 1\
    local send, ret, err\
    while true do\
        ret, err, sent = s:send(buf, start)\
        if not err then\
            return nil\
        elseif err ~= \"timeout\" and err ~= \"wantwrite\" then\
            return err\
        else                    -- timeout\
            start = start + sent\
            local exit = coroutine.yield()\
            if exit then\
                return \"exit op received\"\
            end\
        end\
    end\
end\
\
function msocket.svr_receive(co, sock, addr, funcall, ...)\
    msocket.add(co, sock)\
    local reply, err = funcall(sock, addr, ...)\
    msocket.del(sock)\
\
    return reply, err\
end\
\
function msocket.svr_send(co, sock, data)\
    msocket.add(co, nil, sock)\
    local err = msocket.polite_send(sock, data)\
    msocket.del(sock, true)\
    return err\
end\
\
local function ssconnect(sock, addr, port)\
    local err, peer\
    _, err = sock:connect(addr, port)\
    if err == \"timeout\" then\
        local exit = coroutine.yield()\
        if exit then \
            return \"exit connect\"\
        end\
        \
        err = sock:getoption(\"error\")\
        if err then\
            return err\
        end\
\
        peer = sock:getpeername()\
        if not peer then\
            return \"no suck peer\"\
        end\
        return nil\
    end\
    return err\
end\
\
function msocket.svr_connect(co, sock, addr, port)\
    local err\
    msocket.add(co, nil, sock)\
    err = ssconnect(sock, addr, port)\
    msocket.del(sock, true)\
    return err\
end\
\
function msocket.add(co, rd, wd)\
    if type(co) ~= \"thread\" then\
        log.error(\"Wrong format, first arg must be coroutine, bug get \"..type(co))\
        return\
    end\
    if rd then\
        table.insert(msocket.rd, rd)\
        msocket.mapco[rd] = co\
    end\
    if wd then\
        table.insert(msocket.wd, wd)\
        msocket.mapco[wd] = co\
    end\
    if not msocket.co[co] then\
        msocket.co[co] = {fdcnt = 1}\
    else\
        msocket.co[co].fdcnt = (msocket.co[co].fdcnt or 0) + 1\
    end\
    msocket.co[co].last = os.time()\
end\
\
function msocket.del(fd, write)\
    local t = {}\
    if not write then\
        t = msocket.rd\
    else\
        t = msocket.wd\
    end\
\
    for k, v in ipairs(t) do \
        if v == fd then\
            table.remove(t, k)\
            break\
        end\
    end\
    if msocket.mapco[fd] then\
        local co = msocket.mapco[fd]\
        if msocket.co[co] then\
            msocket.co[co].fdcnt = msocket.co[co].fdcnt - 1\
        end\
\
        msocket.mapco[fd] = nil\
    end\
end\
\
\
function msocket.coroutine_create(name, timeout, func, ...)\
    --check coroutine name\
    local count = 0\
    for k,v in pairs(msocket.co) do\
        if v.name == name then\
            count = count + 1\
        end\
    end\
\
    if count >= msocket.maxcount then\
        return nil\
    end\
\
    local co = coroutine.create(func)\
    if not timeout then timeout = 0 end\
    msocket.co[co] = {name = name, timeout = timeout}\
    return co\
end\
\
local function clean_fd(fds, clean_fd)\
    local i = 1\
    while i <= #fds do\
        if clean_fd[fds[i]] then\
            table.remove(fds, i)\
        else\
            i = i + 1\
        end\
    end\
end\
\
local function co_cleanup(co)\
    local delfds = {}\
    for k, v in pairs(msocket.mapco) do\
        if v == co then\
            delfds[k] = true\
            log.warn(\"close orphan socket \", k)\
            k:close()\
        end\
    end\
\
    -- clean mapco\
    for k, _ in pairs(delfds) do\
        msocket.mapco[k] = nil\
    end\
\
    -- clean rd && wd\
    clean_fd(msocket.rd, delfds)\
    clean_fd(msocket.wd, delfds)\
\
    msocket.co[co] = nil\
end\
\
function msocket.coroutine_exit(co)\
    log.trace(\"coroutine exit with co \", co)\
    if co == nil or co == coroutine.running() then\
        co_cleanup(coroutine.running())\
        return\
    end\
\
    -- other coroutine, must wait for dead\
    if coroutine.status(co) ~= \"dead\" then\
        while true do\
            coroutine.resume(co, true)\
            log.warn(\"wait for co dead\", co)\
            if coroutine.status(co) == \"dead\" then\
                break\
            end\
        end\
        log.warn(\"wait for co dead......Done\")\
    end\
    co_cleanup(co)\
end\
\
function msocket.coroutine_resume(co, ...)\
    local ok, err = coroutine.resume(co, ...)\
    if not ok then\
        return \"coroutine resume error \"..err\
    end\
\
    if coroutine.status(co) == \"dead\" then\
        log.trace(\"coroutine dead, will do some cleanup\")\
        co_cleanup(co)\
    else\
        log.trace(\"coroutine resume, will reset \", os.time(), \"from \", msocket.co[co].last)\
        msocket.co[co].last = os.time()\
    end\
\
    return nil\
end\
\
function msocket.coroutine_yield()\
    return coroutine.yield()\
end\
\
function msocket.run(timeout_ms)\
    local rd, wd, err = socket.select(msocket.rd, msocket.wd, timeout_ms/1000)\
    if err == \"timeout\" then\
        -- log.trace(\"select for msocket, rd len is \"..#msocket.rd..\", wd len is \"..#msocket.wd)\
    else\
        -- read fd\
        local co\
        for _, input in ipairs(rd) do\
            co = msocket.mapco[input]\
            log.trace(\"select one fd for read\", input, \", with co status \", coroutine.status(msocket.mapco[input]))\
            msocket.coroutine_resume(co)\
        end\
        \
        -- write fd\
        for _, output in ipairs(wd) do\
            co = msocket.mapco[output]\
            log.trace(\"select one fd for write\", output)\
            msocket.coroutine_resume(co)\
        end\
    end\
end\
\
local function co_timeout()\
    local now = os.time()\
    local time_cos = {}\
    for k, v in pairs(msocket.co) do\
        log.trace(\"delta is \"..(now - v.last)..\" , v.timeout is \"..v.timeout..\", v.last is \"..v.last)\
        if v.timeout > 0 and now > v.last + v.timeout then\
            log.warn(\"this co should be timeout, for it has no packet for \"..(now - v.last)..\" seconds long\")\
            msocket.coroutine_exit(k)\
        end\
    end\
end\
\
timer.mod_notdisable(\"msocket_clean\", 60, 0, co_timeout) -- every 60 seconds to check if co is blocked for too many seconds\
\
return msocket\
"
, '@'.."./lualib/msocket.lua" ) )

package.preload[ "myfile" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
\
local myfile = {}\
\
function myfile.existed(src)\
    local fin = io.open(src, \"r\")\
    if fin == nil then\
        return nil\
    end\
    fin:close()\
    return \"existed\"\
end\
\
function myfile.copy(src, dst)\
    local fin = io.open(src, \"r\")\
    local fout = io.open(dst, \"w\")\
    if fin == nil or fout == nil then\
        if fin then fin:close() end\
        if fout then fout:close() end\
        return \"failed to copy\"\
    end\
    fout:write(fin:read(\"a\"))\
    fout:close()\
    fin:close()\
    return nil\
end\
\
function myfile.read(fname)\
    local f = io.open(fname, \"r\")\
    if f == nil then\
        return \"failed to read file \"..fname\
    end\
    local data = f:read(\"a\")\
    f:close()\
    return data\
end\
\
function myfile.write(body, fname)\
    local f = io.open(fname, \"w\")\
    if f == nil then\
        return \"failed to write file \" .. fname\
    end\
    f:write(body)\
    f:close()\
    return nil\
end\
\
function myfile.store_json(t, fname)\
    local io = require\"io\"\
    local ok, msg = pcall(cjson.encode, t)\
    if not ok then\
        return msg\
    end\
\
    local f = io.open(fname, \"w\")\
    if f == nil then\
        return \"failed to write file \" .. fname\
    end\
\
    f:write(msg)\
    f:close()\
    return nil\
end\
\
function myfile.load_json(fname)\
    local io = require\"io\"\
\
    local f = io.open(fname, \"r\")\
    if f == nil then\
        return nil, \"failed to read file \" .. fname\
    end\
\
    local content = f:read(\"a\")\
    f:close()\
    if content == nil then\
        return nil, \"Empty read file \" .. fname\
    end\
    \
    local ok, t = pcall(cjson.decode, content)\
    if ok then\
        return t\
    else\
        return nil, \"cjson decode error\" .. t\
    end\
end\
\
function myfile.length_of_file(fname)\
    local io = require\"io\"\
\
    local f = io.open(fname, \"r\")\
    if f == nil then\
        return 0\
    end\
\
    local len = f:seek(\"end\")\
    f:close()\
\
    if len and len > 0 then\
        return len\
    end\
    return 0\
end\
\
\
return myfile\
"
, '@'.."./lualib/myfile.lua" ) )

package.preload[ "myip" ] = assert( (loadstring or load)(
"\
local myip = {}\
local mystring = require\"mystring\"\
local log = require(\"log\")\
\
function myip.ip_cmp(addr1_bytes, addr2_bytes)\
    local ip1_h = string.unpack(\">I\", addr1_bytes)\
    local ip2_h = string.unpack(\">I\", addr2_bytes)\
    if ip1_h > ip2_h then\
        return 1\
    elseif ip1_h < ip2_h then\
        return -1\
    end\
    return 0\
end\
\
function myip.inet_ntoa(sbytes)\
    local a1, a2, a3, a4 = string.unpack(\"BBBB\", sbytes)\
    assert(a1 and a2 and a3 and a4)\
    t = {a1, a2, a3, a4}\
    return table.concat(t, '.')\
end\
\
function myip.is_ipstring(ipstring)\
    local t = {}\
\
    if (type(ipstring) == \"string\") then\
        for l in string.gmatch(ipstring, \"%d+\") do\
            local nn = tonumber(l)\
            if nn < 0 or nn > 255 then\
                return false\
            end\
            table.insert(t, tonumber(l))\
        end\
    end\
\
    if #t ~= 4 then\
        return false\
    end\
\
    return true, t\
end\
\
function myip.inet_aton(ipstring, maskbit, ret_subnetip)\
    local t = {} b = false mask = 0xffffffff\
    b, t = myip.is_ipstring(ipstring)\
    assert(b == true)\
    if maskbit and maskbit < 32 then\
        local ipaddr = (t[1] << 24) | (t[2] << 16) | (t[3] << 8) | t[4]\
        if ret_subnetip then\
            -- such as, 192.168.60.5/24, will return 192.168.60.0\
            return string.pack(\">I\", ipaddr & (~((1 << (32-maskbit)) - 1) & 0xffffffff))\
        end\
        return string.pack(\">I\", ipaddr)\
    else\
        return string.pack(\"BBBB\", t[1], t[2], t[3], t[4])\
    end\
end\
\
function myip.ipmask(ipstring, ret_subnetip)\
    local ss, ee = string.find(ipstring, '/')\
\
    if ss and ee and ss == ee then\
        local mask = tonumber(string.sub(ipstring, ss + 1))\
        return true, myip.inet_aton(string.sub(ipstring, 1, ss - 1), mask, ret_subnetip), mask\
    else\
        local t = {} b = false\
        b, t = myip.is_ipstring(ipstring)\
        if b then\
            return true, string.pack(\"BBBB\", t[1], t[2], t[3], t[4]), 32\
        else\
            return false, ipstring\
        end\
    end\
end\
\
function myip.is_localip(ipstring)\
        ok, t = myip.is_ipstring(ipstring)\
        if not ok then\
            return false, 0\
        end\
\
        local ipaddr = (t[1] << 24) | (t[2] << 16) | (t[3] << 8) | t[4]\
        -- 192.168.0.0/16,172.16.0.0-172.31.255.255,10.0.0.0/8\
        if (ipaddr >= 3232235520 and ipaddr <= 3232301055) or (ipaddr >= 2886729728 and ipaddr <= 2887778303) or (ipaddr >= 167772160 and ipaddr <= 184549375) then\
            return true, ipaddr\
        end\
        return false, ipaddr\
end\
\
function myip.subnet_iprange(ipstring, maskbit)\
    assert(maskbit and maskbit > 0 and maskbit <= 32)\
\
    local ip_addr_ns = myip.inet_aton(ipstring)\
    local mask_addr_ns = string.pack(\">I\", (~((1 << (32-maskbit)) - 1) & 0xffffffff))\
    local mask_revert_addr_ns = string.pack(\">I\", (((1 << (32-maskbit)) - 1) & 0xffffffff))\
\
    local ip_addr_ni = string.unpack(\"=I\", ip_addr_ns)\
    local mask_addr_ni = string.unpack(\"=I\", mask_addr_ns)\
    local mask_revert_addr_ni = string.unpack(\"=I\", mask_revert_addr_ns)\
\
    local start_addr = string.pack(\"=I\", (ip_addr_ni & mask_addr_ni))\
    local end_addr = string.pack(\"=I\", (ip_addr_ni | mask_revert_addr_ni))\
    return start_addr, end_addr\
end\
\
function myip.mask_bton(maskbit)\
    assert(maskbit and maskbit > 0 and maskbit <= 32)\
    return string.pack(\">I\", (~((1 << (32-maskbit)) - 1) & 0xffffffff))\
end\
\
function myip.mask_atob(maskstring)\
    local mask = myip.inet_aton(maskstring)\
    local i = string.unpack(\">I\", mask)\
    local c = 0\
    local seen_one = false\
    while i > 0 do\
        if i & 1 > 0 then\
            seen_one = true\
            c = c + 1\
        else\
            if seen_one then\
                return nil, \"invalid netmask\"\
            end\
        end\
        i = i >> 1\
    end\
    return c\
end\
\
function myip.mask_atob_fast(maskstring)\
    local maps = { [128] = 1, [192] = 2, [224] = 3, [240] = 4, [248] = 5, [252] = 6, [254] = 7, [255] = 8 }\
    local ok , nums = myip.is_ipstring(maskstring)\
    if not ok then\
        return nil, \"invalid netmask\"\
    end\
    local c = 0\
    for _, num in ipairs(nums) do\
        if maps[num] then\
            c = c + maps[num]\
        end\
        if num == 0 or num < 255 then\
            break\
        end\
    end\
    return c\
end\
\
function myip.split_ipdomain(ipdomain_set)\
    local ips = {} domain = {} masklist = {} t = {}\
\
    if not ipdomain_set then\
        return ips, domain, masklist\
    end\
    for _, v in ipairs(ipdomain_set) do\
        local b = false ipaddr = '' mask = 0\
        b, ipaddr, mask = myip.ipmask(v)\
        if b then\
            local insert = true           \
            table.insert(ips, {ip = ipaddr, mask = mask})\
            for _, mm in ipairs(masklist) do\
                if mm == mask then\
                    insert = false\
                end\
            end\
            if insert then\
                table.insert(masklist, mask)\
            end\
        else\
            table.insert(domain, v)\
        end\
    end\
\
    return ips, domain, masklist\
end\
\
function myip.time_strtotime(timeString)\
    if not timeString then\
        return 0\
    end\
    if type(timeString) ~= 'string' then error('string2time: timeString is not a string') return 0 end\
    local fun = string.gmatch( timeString, \"%d+\")\
    local y = fun() or 0\
    if y == 0 then  return 0 end\
    local m = fun() or 0\
    if m == 0 then  return 0 end\
    local d = fun() or 0\
    if d == 0 then  return 0 end\
    local H = fun() or 0\
    if H == 0 then  return 0 end\
    local M = fun() or 0\
    if M == 0 then  return 0 end\
    local S = fun() or 0\
    if S == 0 then  return 0 end\
    return os.time({year=y, month=m, day=d, hour=H,min=M,sec=S})\
end\
\
function myip.mac_ntoa(mac)\
    assert(mac:len() == 6)\
    return mystring.data2hex(mac, ':')\
end\
\
function myip.mac_aton(mac_string)\
    return mystring.hex2data(mac_string, \":\")\
end\
\
function myip.mac_fmt(mac, delim)\
    if mac then\
        mac = string.upper(mac)\
        if delim then\
            local pattern = string.format(\"(%%x%%x)[%s]?\", delim)\
            return (mac:gsub(pattern, function (word) return string.format(\"%s%s\", word, delim) end, 5))\
        else\
            return (mac:gsub(\":\",\"\"))\
        end\
    end\
    return \"\"\
end\
\
\
-- flm --> filter_local_mac\
function myip.mac_check(mac, value, flm)\
    if type(mac) ~= \"string\" or type(value) ~= \"string\" then\
        return nil\
    end\
    value = value:gsub(\":\",\"\")\
    if #value ~= 12 then\
        return nil\
    end\
\
    local hmac = string.upper(value)\
    local cmac = myip.mac_aton(hmac)\
    local fbyte = string.byte(cmac,1)\
    cmac = myip.mac_ntoa(cmac)\
    local is_broadcast = fbyte & 0x01\
\
    -- filter broadcastt mac\
    if is_broadcast == 1 then\
        --log.debug(\" mac is broadcast\")\
        return nil\
    end\
\
    -- filter local mac from http\
    if flm == true and (fbyte & 0x02 == 2) then\
        -- log.debug(\"myip debug flm success= \")\
        return nil\
    end\
\
    -- filter same mac addr\
    if string.sub(mac,1,10) == string.sub(hmac,1,10) then\
        -- log.debug(\"myip debug same mac addr\")\
        return nil\
    end\
\
    if string.find(cmac, '00:00:00$') or string.find(cmac, 'FF:FF:FF$') then\
        -- log.debug(\"error mac\")\
        return nil\
    end\
\
    return hmac\
end\
\
function myip.getip(iface)\
    local ip = \"\"\
    local t=io.popen('ifconfig '..iface..' 2>/dev/null| grep \"inet \"')\
    local s=t:read(\"a\")\
    ip = string.match(s,\"inet[^%d]+([%d.]+)\")\
    t:close()\
    if ip and ip ~= \"\" then\
        return true,ip\
    end\
    return false,\"\"\
end\
\
function myip.getarp()\
    local line =1\
    local arps = {}\
    local t=io.open('/proc/net/arp')  --读取arp缓存\
    for k,v in t:lines() do \
        if line ~= 1 then \
            local ip,_,_,mac = mystring.split(k, \" \") \
            if ip and mac then\
                arps[ip] = string.upper(mac)\
            end\
        end\
        line = line + 1\
    end\
    t:close()\
    return arps\
end\
\
\
return myip\
"
, '@'.."./lualib/myip.lua" ) )

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

package.preload[ "myutil" ] = assert( (loadstring or load)(
"\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
\
local myutil = {}\
\
\
local function value_to_printable(key, value)\
    if key == \"mac\" and value:len() == 6 then\
        return myip.mac_ntoa(value)\
    elseif (key == \"ip\" or string.match(key, \"^[ds].*ip$\")) and value:len() == 4 then\
        return myip.inet_ntoa(value)\
    else\
        return value\
    end\
end\
\
local function table_to_printable(t)\
    local tt = {}\
    for k,v in pairs(t) do\
        if type(v) == \"table\" then\
            tt[k] = table_to_printable(v)\
        elseif type(v) == \"string\" then\
            tt[k] = value_to_printable(k, v)\
        else\
            tt[k] = v\
        end\
    end\
    return tt\
end\
\
function myutil.tableprintable(t)\
    return table_to_printable(t)\
end\
\
function myutil.read_csv(filname, str, delim)\
    local pattern, f, lines, line, all = nil, nil, \"\", {}, {}\
    if delim then\
        pattern = string.format(\"([^%s\\n]+)([\\n]?)\", delim)\
    else\
        pattern = \"([^,\\n]+)([\\n]?)\"\
    end\
\
    if type(str) == \"string\" then\
        lines = str\
    elseif type(filname) == \"string\" then\
        f=io.open(filname, \"r\")\
        if f then\
            lines = f:read(\"a\")\
            f:close()\
        end\
        lines = string.gsub(lines, \"[\\r\\n]\", \"\\n\")\
    else\
        return all\
    end\
\
    lines:gsub(pattern, function(str1, str2) if str2 == \"\\n\" then table.insert(line, str1) table.insert(all, line) line = {} else table.insert(line, str1) end  end)\
\
    --all[1] header\
    local header, info = all[1] or {}, {}\
    for k,v in pairs(all) do\
        local one = {}\
        if k ~= 1 then\
            for index,name in pairs(header) do\
                one[name] = v[index]\
            end\
            table.insert(info, one)\
        end\
    end\
\
    return all, info\
end\
\
function myutil.cmdprintable(cmd, delim)\
    if type(cmd) ~= \"string\" then\
        return {}\
    end\
\
    local lines, f = \"\", nil\
    f=io.popen(cmd)\
    if f then\
        lines = f:read(\"a\")\
        f:close()\
    end\
\
    return myutil.read_csv(nil, lines, \"\\t\")\
end\
\
function myutil.urlsplit(str)\
  local host = string.match(str or \"\", \"^[^:/?]+\")\
  local url = string.match(str or \"\", \"[^/?]+(.*)\")\
  return host, url\
end\
\
function myutil.inarr(s, arr)\
    for _, v in ipairs(arr) do\
        if v == s then\
            return true\
        end\
    end\
    return false\
end\
\
return myutil"
, '@'.."./lualib/myutil.lua" ) )

package.preload[ "nselib" ] = assert( (loadstring or load)(
""
, '@'.."./lualib/nselib/nselib.lua" ) )

package.preload[ "nselib.slaxml" ] = assert( (loadstring or load)(
"---\
-- This is the NSE implementation of SLAXML.\
-- SLAXML is a pure-Lua SAX-like streaming XML parser. It is more robust\
-- than many (simpler) pattern-based parsers that exist, properly supporting\
-- code like <code><expr test=\"5 > 7\" /></code>, CDATA nodes, comments,\
-- namespaces, and processing instructions.\
-- It is currently not a truly valid XML parser, however, as it allows certain XML that is\
-- syntactically-invalid (not well-formed) to be parsed without reporting an error.\
-- The streaming parser does a simple pass through the input and reports what it sees along the way.\
-- You can optionally ignore white-space only text nodes using the <code>stripWhitespace</code> option.\
-- The library contains the parser class and the parseDOM function.\
--\
-- Basic Usage of the library:\
-- <code>\
-- local parser = parser:new()\
-- parser:parseSAX(xmlbody, {stripWhitespace=true})\
-- </code>\
-- To specify custom call backs use :\
-- <code>\
-- local call_backs = {\
--   startElement = function(name,nsURI,nsPrefix)       end, -- When \"<foo\" or <x:foo is seen\
--   attribute    = function(name,value,nsURI,nsPrefix) end, -- attribute found on current element\
--   closeElement = function(name,nsURI)                end, -- When \"</foo>\" or </x:foo> or \"/>\" is seen\
--   text         = function(text)                      end, -- text and CDATA nodes\
--   comment      = function(content)                   end, -- comments\
--   pi           = function(target,content)            end, -- processing instructions e.g. \"<?yes mon?>\"\
-- }\
-- local parser = parser:new(call_backs)\
-- parser:parseSAX(xmlbody)\
-- </code>\
-- The code also contains the <code>parseDOM</code> function.\
-- To get the dom table use the <code>parseDOM</code> method as follows.\
-- <code>\
-- parseDOM(xmlbody, options)\
-- </code>\
--\
-- DOM Table Features\
--\
-- Document - the root table returned from the parseDOM() method.\
--\
-- * <code>doc.type</code> : the string \"document\"\
-- * <code>doc.name</code> : the string \"#doc\"\
-- * <code>doc.kids</code> : an array table of child processing instructions, the root element, and comment nodes.\
-- * <code>doc.root</code> : the root element for the document\
--\
-- Element\
--\
-- * <code>someEl.type</code> : the string \"element\"\
-- * <code>someEl.name</code> : the string name of the element (without any namespace prefix)\
-- * <code>someEl.nsURI</code> : the namespace URI for this element; nil if no namespace is applied\
-- * <code>someEl.attr</code> : a table of attributes, indexed by name and index\
--\
-- <code>local value = someEl.attr['attribute-name']</code> : any namespace prefix of the attribute is not part of the name\
--\
-- <code>local someAttr = someEl.attr[1]</code> : an single attribute table (see below); useful for iterating all\
-- attributes of an element, or for disambiguating attributes with the same name in different namespaces\
--\
-- * <code>someEl.kids</code> : an array table of child elements, text nodes, comment nodes, and processing instructions\
-- * <code>someEl.el</code> : an array table of child elements only\
-- * <code>someEl.parent</code> : reference to the parent element or document table\
--\
-- Attribute\
--\
-- * <code>someAttr.type</code> : the string \"attribute\"\
-- * <code>someAttr.name</code> : the name of the attribute (without any namespace prefix)\
-- * <code>someAttr.value</code> : the string value of the attribute (with XML and numeric entities unescaped)\
-- * <code>someAttr.nsURI</code> : the namespace URI for the attribute; nil if no namespace is applied\
-- * <code>someAttr.parent</code> : reference to the owning element table\
--\
-- Text - for both CDATA and normal text nodes\
--\
-- * <code>someText.type</code> : the string \"text\"\
-- * <code>someText.name</code> : the string \"#text\"\
-- * <code>someText.value</code> : the string content of the text node (with XML and numeric entities unescaped for non-CDATA elements)\
-- * <code>someText.parent</code> : reference to the parent element table\
--\
-- Comment\
--\
-- * <code>someComment.type</code> : the string \"comment\"\
-- * <code>someComment.name</code> : the string \"#comment\"\
-- * <code>someComment.value</code> : the string content of the attribute\
-- * <code>someComment.parent</code> : reference to the parent element or document table\
--\
-- Processing Instruction\
--\
-- * <code>someComment.type</code> : the string \"pi\"\
-- * <code>someComment.name</code> : the string name of the PI, e.g. <?foo …?> has a name of \"foo\"\
-- * <code>someComment.value</code> : the string content of the PI, i.e. everything but the name\
-- * <code>someComment.parent</code> : reference to the parent element or document table\
--\
-- @args slaxml.debug Debug level at which default callbacks will print detailed\
--                    parsing info. Default: 3\
--\
-- @author Gavin Kistner <original pure lua implemetation>\
-- @author Gyanendra Mishra <NSE specific implementation>\
\
--[=====================================================================[\
v0.7 Copyright © 2013-2014 Gavin Kistner <!@phrogz.net>; MIT Licensed\
See http://github.com/Phrogz/SLAXML for details.\
--]=====================================================================]\
\
local log = require \"log\"\
local xml = {}\
\
\
local utf8markers = { {0x7FF,192}, {0xFFFF,224}, {0x1FFFFF,240} }\
local function utf8(decimal) -- convert unicode code point to utf-8 encoded character string\
    if decimal<128 then return string.char(decimal) end\
    local charbytes = {}\
    for bytes,vals in ipairs(utf8markers) do\
        if decimal<=vals[1] then\
            for b=bytes+1,2,-1 do\
                local mod = decimal%64\
                decimal = (decimal-mod)/64\
                charbytes[b] = char(128+mod)\
            end\
            charbytes[1] = char(vals[2]+decimal)\
            return concat(charbytes)\
        end\
    end\
end\
\
\
-- A table containing the default call backs to be used\
-- This really floods the script output, you will mostly be\
-- using custom call backs.\
-- Set the debugging level required for the default call backs. Defaults to 3.\
local DEFAULT_CALLBACKS = {\
    --- A call back for processing instructions.\
    -- To use define pi = function(<target>, <content>) <function body> end in parser._call table.\
    -- Executes whenever a processing instruction is found.\
    -- @param target the PI target\
    -- @param content any value not containing the sequence  '?>'\
    pi = function(target,content)\
      log.warn(debugging_level, string.format(\"<?%s %s?>\",target,content))\
    end,\
    --- A call back for comments.\
    -- To use define comment = function(<content>) <function body> end in parser._call table.\
    -- Executes whenever a comment is encountered.\
    -- @param content The comment body itself.\
    comment = function(content)\
      log.warn(debugging_level, debugging_level, string.format(\"<!-- %s -->\",content))\
    end,\
    --- A call back for the start of elements.\
    -- To use define startElement = function(<name>, <nsURI>, <nsPrefix>) <function body> end in parser._call table.\
    -- Executes whenever an element starts.\
    -- @param name The name of the element.\
    -- @param nsURI The name space URI.\
    -- @param nsPrefix The name space prefix.\
    startElement = function(name,nsURI,nsPrefix)\
      local output = \"<\"\
      if nsPrefix then output = output .. nsPrefix .. \":\" end\
      output = output .. name\
      if nsURI    then output = output .. \" (ns='\" .. nsURI .. \"')\" end\
      output = output .. \">\"\
      log.warn(debugging_level, output)\
    end,\
    --- A call back for attributes.\
    -- To use define attribute = function(<name>, <attribtute>, <nsURI>, <nsPrefix>) <function body> end in parser._call table.\
    -- Executes whenever an attribute is found.\
    -- @param name The name of the attribute.\
    -- @param value The value of the attribute.\
    -- @param nsURI The name space URI.\
    -- @param nsPrefix The name space prefix.\
    attribute = function(name,value,nsURI,nsPrefix)\
      local output = '  '\
      if nsPrefix then output = output .. nsPrefix .. \":\"  end\
      output = output .. name .. '=' .. string.format('%q',value)\
      if nsURI then output = output .. (\" (ns='\" .. nsURI .. \"')\") end\
      log.warn(debugging_level, output)\
    end,\
    --- A call back for text content.\
    -- To use define text = function(<text>) <function body> end in parser._call table.\
    -- Executes whenever pure text is found.\
    -- @param text The actual text.\
    text = function(text)\
      log.warn(debugging_level, string.format(\"  text: %q\",text))\
    end,\
    --- A call back for the end of elements.\
    -- To use define closeElement = function(<name>, <nsURI>, <nsPrefix>) <function body> end in parser._call table.\
    -- Executes whenever an element closes.\
    -- @param name The name of the element.\
    -- @param nsURI The name space URI.\
    -- @param nsPrefix The name space prefix.\
    closeElement = function(name,nsURI,nsPrefix)\
      log.warn(debugging_level, string.format(\"</%s>\",name))\
    end,\
  }\
\
local entityMap  = { [\"lt\"]=\"<\", [\"gt\"]=\">\", [\"amp\"]=\"&\", [\"quot\"]='\"', [\"apos\"]=\"'\" }\
local entitySwap = function(orig,n,s) return entityMap[s] or n==\"#\" and utf8(tonumber('0'..s)) or orig end\
\
parser = {\
\
  new = function(self, callbacks)\
    local o = {\
    _call = callbacks or DEFAULT_CALLBACKS\
    }\
    setmetatable(o, self)\
    self.__index = self\
    return o\
  end,\
\
  unescape = function(str) return string.gsub( str, '(&(#?)([%d%a]+);)', entitySwap ) end,\
\
  --- Parses the xml in sax like manner.\
  -- @self The parser object.\
  -- @param xml The xml body to be parsed.\
  -- @param options Options if any specified.\
  parseSAX = function(self, xml, options)\
    if not options then options = { stripWhitespace=false } end\
\
    -- Cache references for maximum speed\
    local find, sub, gsub, char, push, pop, concat = string.find, string.sub, string.gsub, string.char, table.insert, table.remove, table.concat\
    local first, last, match1, match2, match3, pos2, nsURI\
    local unpack = table.unpack\
    local pos = 1\
    local state = \"text\"\
    local textStart = 1\
    local currentElement={}\
    local currentAttributes={}\
    local currentAttributeCt -- manually track length since the table is re-used\
    local nsStack = {}\
    local anyElement = false\
\
    local function finishText()\
      if first>textStart and self._call.text then\
        local text = sub(xml,textStart,first-1)\
        if options.stripWhitespace then\
          text = gsub(text,'^%s+','')\
          text = gsub(text,'%s+$','')\
          if #text==0 then text=nil end\
        end\
        if text then self._call.text(parser.unescape(text)) end\
      end\
    end\
\
    local function findPI()\
      first, last, match1, match2 = find( xml, '^<%?([:%a_][:%w_.-]*) ?(.-)%?>', pos )\
      if first then\
        finishText()\
        if self._call.pi then self._call.pi(match1,match2) end\
        pos = last+1\
        textStart = pos\
        return true\
      end\
    end\
\
    local function findComment()\
      first, last, match1 = find( xml, '^<!%-%-(.-)%-%->', pos )\
      if first then\
        finishText()\
        if self._call.comment then self._call.comment(match1) end\
        pos = last+1\
        textStart = pos\
        return true\
      end\
    end\
\
    local function nsForPrefix(prefix)\
      if prefix=='xml' then return 'http://www.w3.org/XML/1998/namespace' end -- http://www.w3.org/TR/xml-names/#ns-decl\
      for i=#nsStack,1,-1 do if nsStack[i][prefix] then return nsStack[i][prefix] end end\
      log.warn((\"Cannot find namespace for prefix %s\"):format(prefix))\
      return\
    end\
\
    local function startElement()\
      anyElement = true\
      first, last, match1 = find( xml, '^<([%a_][%w_.-]*)', pos )\
      if first then\
        currentElement[2] = nil -- reset the nsURI, since this table is re-used\
        currentElement[3] = nil -- reset the nsPrefix, since this table is re-used\
        finishText()\
        pos = last+1\
        first,last,match2 = find(xml, '^:([%a_][%w_.-]*)', pos )\
        if first then\
          currentElement[1] = match2\
          currentElement[3] = match1 -- Save the prefix for later resolution\
          match1 = match2\
          pos = last+1\
        else\
          currentElement[1] = match1\
          for i=#nsStack,1,-1 do if nsStack[i]['!'] then currentElement[2] = nsStack[i]['!']; break end end\
        end\
        currentAttributeCt = 0\
        push(nsStack,{})\
        return true\
      end\
    end\
\
    local function findAttribute()\
      first, last, match1 = find( xml, '^%s+([:%a_][:%w_.-]*)%s*=%s*', pos )\
      if first then\
        pos2 = last+1\
        first, last, match2 = find( xml, '^\"([^<\"]*)\"', pos2 ) -- FIXME: disallow non-entity ampersands\
        if first then\
          pos = last+1\
          match2 = parser.unescape(match2)\
        else\
          first, last, match2 = find( xml, \"^'([^<']*)'\", pos2 ) -- FIXME: disallow non-entity ampersands\
          if first then\
            pos = last+1\
            match2 = parser.unescape(match2)\
          end\
        end\
      end\
      if match1 and match2 then\
        local currentAttribute = {match1,match2}\
        local prefix,name = string.match(match1,'^([^:]+):([^:]+)$')\
        if prefix then\
          if prefix=='xmlns' then\
            nsStack[#nsStack][name] = match2\
          else\
            currentAttribute[1] = name\
            currentAttribute[4] = prefix\
          end\
        else\
          if match1=='xmlns' then\
            nsStack[#nsStack]['!'] = match2\
            currentElement[2]      = match2\
          end\
        end\
        currentAttributeCt = currentAttributeCt + 1\
        currentAttributes[currentAttributeCt] = currentAttribute\
        return true\
      end\
    end\
\
    local function findCDATA()\
      first, last, match1 = find( xml, '^<!%[CDATA%[(.-)%]%]>', pos )\
      if first then\
        finishText()\
        if self._call.text then self._call.text(match1) end\
        pos = last+1\
        textStart = pos\
        return true\
      end\
    end\
\
    local function closeElement()\
      first, last, match1 = find( xml, '^%s*(/?)>', pos )\
      if first then\
        state = \"text\"\
        pos = last+1\
        textStart = pos\
\
        -- Resolve namespace prefixes AFTER all new/redefined prefixes have been parsed\
        if currentElement[3] then currentElement[2] = nsForPrefix(currentElement[3])    end\
        if self._call.startElement then self._call.startElement(unpack(currentElement)) end\
        if self._call.attribute then\
          for i=1,currentAttributeCt do\
            if currentAttributes[i][4] then currentAttributes[i][3] = nsForPrefix(currentAttributes[i][4]) end\
            self._call.attribute(unpack(currentAttributes[i]))\
          end\
        end\
\
        if match1==\"/\" then\
          pop(nsStack)\
          if self._call.closeElement then self._call.closeElement(unpack(currentElement)) end\
        end\
        return true\
      end\
    end\
\
    local function findElementClose()\
      first, last, match1, match2 = find( xml, '^</([%a_][%w_.-]*)%s*>', pos )\
      if first then\
        nsURI = nil\
        for i=#nsStack,1,-1 do if nsStack[i]['!'] then nsURI = nsStack[i]['!']; break end end\
      else\
        first, last, match2, match1 = find( xml, '^</([%a_][%w_.-]*):([%a_][%w_.-]*)%s*>', pos )\
        if first then nsURI = nsForPrefix(match2) end\
      end\
      if first then\
        finishText()\
        if self._call.closeElement then self._call.closeElement(match1,nsURI) end\
        pos = last+1\
        textStart = pos\
        pop(nsStack)\
        return true\
      end\
    end\
\
    while pos<#xml do\
      if state==\"text\" then\
        if not (findPI() or findComment() or findCDATA() or findElementClose()) then\
          if startElement() then\
            state = \"attributes\"\
          else\
            first, last = find( xml, '^[^<]+', pos )\
            pos = (first and last or pos) + 1\
          end\
        end\
      elseif state==\"attributes\" then\
        if not findAttribute() then\
          if not closeElement() then\
            log.warn(\"Was in an element and couldn't find attributes or the close.\")\
            return\
          end\
        end\
      end\
    end\
\
    if not anyElement then log.warn(\"Parsing did not discover any elements\") end\
    if #nsStack > 0 then log.warn(\"Parsing ended with unclosed elements\") end\
  end,\
\
}\
\
--- Parses xml and outputs a  dom table.\
-- @param xml the xml body to be parsed.\
-- @param options if any to use. Supports <code>stripWhitespaces</code> currently.\
function xml.parseDOM (xml, options)\
  if not options then options={} end\
  local rich = not options.simple\
  local push, pop = table.insert, table.remove\
  local stack = {}\
  local doc = { type=\"document\", name=\"#doc\", kids={} }\
  local current = doc\
  local builder = parser:new{\
    startElement = function(name,nsURI)\
      local el = { type=\"element\", name=name, kids={}, el=rich and {} or nil, attr={}, nsURI=nsURI, parent=rich and current or nil }\
      if current==doc then\
        if doc.root then log.warn((\"Encountered element '%s' when the document already has a root '%s' element\"):format(name,doc.root.name)) return end\
        doc.root = el\
      end\
      push(current.kids,el)\
      if current.el then push(current.el,el) end\
      current = el\
      push(stack,el)\
    end,\
    attribute = function(name,value,nsURI)\
      if not current or current.type~=\"element\" then log.warn((\"Encountered an attribute %s=%s but I wasn't inside an element\"):format(name,value)) return end\
      local attr = {type='attribute',name=name,nsURI=nsURI,value=value,parent=rich and current or nil}\
      if rich then current.attr[name] = value end\
      push(current.attr,attr)\
    end,\
    closeElement = function(name)\
      if current.name~=name or current.type~=\"element\" then log.warn((\"Received a close element notification for '%s' but was inside a '%s' %s\"):format(name,current.name,current.type)) return end\
      pop(stack)\
      current = stack[#stack]\
    end,\
    text = function(value)\
      if current.type~='document' then\
        if current.type~=\"element\" then log.warn((\"Received a text notification '%s' but was inside a %s\"):format(value,current.type)) return end\
        push(current.kids,{type='text',name='#text',value=value,parent=rich and current or nil})\
      end\
    end,\
    comment = function(value)\
      push(current.kids,{type='comment',name='#comment',value=value,parent=rich and current or nil})\
    end,\
    pi = function(name,value)\
      push(current.kids,{type='pi',name=name,value=value,parent=rich and current or nil})\
    end\
  }\
  builder:parseSAX  (xml,options)\
  return doc\
end\
\
return xml;\
\
"
, '@'.."./lualib/nselib/slaxml.lua" ) )

package.preload[ "operdata" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local actor = require\"luactor\"\
local dpi = require\"svrcomm.dpi\"\
local cjson = require\"cjson\"\
local timer = require\"timer\"\
local mime = require\"mime\"\
local csys = require\"c.sys\"\
local ctime = require\"c.time\"\
\
\
local operdata = {\
    type = \"__oper_data\",\
    subtype = \"__oper_data\",\
    help = \"oper data server communication\",\
\
    autoid = 1,\
\
    rules = {\
        --{\
        --    addr = \"domain.domain.domain:port\",\
        --    filter = {\"tuple_info_v1\",\"pscan\"}  or  \"base64(chunk string)\"\
        --    uselconn = false,  -- default is false\
        --    period = 600,      -- default is 600\
        --    maxcnt = 100,      -- default is 100\
\
        --    -- followed not config\
        --    tname = \"\", -- timer name, also used as rule unique id\
        --    stat = {\
        --        okbyte = 0,\
        --        errbyte = 0,\
        --    },\
        --    msgarray = {},    -- valid when uselconn is false\
        --    lconn = nil,      -- point long connection object when uselconn is true\
        --    finicall = nil,   -- generate when configure\
        --    filtercall = nil, -- generate when configure\
        --},\
    },\
}\
\
\
local function get_autoid()\
    local id = operdata.autoid\
    operdata.autoid = operdata.autoid + 1\
    return id\
end\
\
local function operdata_send(rule)\
    if #rule.msgarray > 0 then\
        log.info(string.format(\"operdata %s send msgcnt(%d)\", rule.addr, #rule.msgarray))\
        local msg = cjson.encode(rule.msgarray)\
        dpi.async_call(rule.addr, CENUM.COMM_ACTION_DEVOPS_DPI_DATA, msg, rule.finicall)\
        rule.msgarray = {}\
    end\
end\
\
local function stat()\
    local t = {}\
\
    for _, rule in ipairs(operdata.rules) do\
        local item = {\
            addr = rule.addr,\
            filter = rule.filter,\
            uselconn = rule.uselconn,\
            period = rule.period,\
            maxcnt = rule.maxcnt,\
            msgcnt = #rule.msgarray,\
            okbyte = rule.stat.okbyte,\
            errbyte = rule.stat.errbyte,\
            tname = rule.tname,\
        }\
        if rule.lconn then\
            item.lconn = dpi.datalongconn_show(rule.lconn)\
        end\
        table.insert(t, item)\
    end\
\
    return t\
end\
\
local function read()\
    local t = {}\
    \
    for _, rule in ipairs(operdata.rules) do\
        local item = {\
            addr = rule.addr,\
            filter = rule.filter,\
            uselconn = rule.uselconn,\
            period = rule.period,\
            maxcnt = rule.maxcnt,\
        }\
        table.insert(t, item)\
    end\
\
    return t\
end\
\
local function rule_fini(rule)\
    if rule.uselconn then\
        dpi.datalongconn_stop(rule.lconn)\
        rule.lconn = nil\
    else\
        timer.del(rule.tname)\
        rule.msgarray = {}\
    end\
    rule.finicall = nil\
    rule.filtercall = nil\
end\
\
local function rule_del(t)\
    if type(t.tname) == \"string\" then\
        for pos, rule in ipairs(operdata.rules) do\
            if t.tname == rule.tname then\
                rule_fini(rule)\
                table.remove(operdata.rules, pos)\
                return\
            end\
        end\
    end\
end\
\
local function rule_flush()\
    for _, rule in ipairs(operdata.rules) do\
        rule_fini(rule)\
    end\
    operdata.rules = {}\
end\
\
local function load_chunk(chunk)\
    local func, err = load(chunk)\
    if not func then\
        log.error(\"load failed\")\
        return nil\
    end\
\
    local ff\
    local lua_signature = csys.get_lua_signature() \
    if string.byte(chunk) == string.byte(lua_signature) then\
        -- binary string\
        ff = func\
    else\
        -- text string\
        ff = func()\
        if type(ff) ~= \"function\" then\
            log.error(\"Error, it must return function\")\
            ff = nil\
        end\
    end\
    return ff\
end\
\
local function rule_add(t)\
    local rule = {}\
\
    if type(t.addr) ~= \"string\" then\
        return\
    end\
    rule.addr = t.addr\
\
    if type(t.filter) == \"string\" then\
        local ff = load_chunk(mime.unb64(t.filter))\
        if type(ff) ~= \"function\" then\
            return\
        end\
        rule.filtercall = ff\
    elseif type(t.filter) == \"table\" then\
        for _, v in ipairs(t.filter) do\
            if type(v) ~= \"string\" then\
                return\
            end\
        end\
        rule.filtercall = function (msg)\
            local dtypes = t.filter\
            for _, dt in ipairs(dtypes) do\
                if dt == \"all\" or (type(msg.type) == \"string\" and msg.type == dt) then\
                    return true\
                end\
            end\
            return false\
        end\
    else\
        return\
    end\
    rule.filter = t.filter\
\
    local uptime = ctime.get_uptime()\
    rule.tname = string.format(\"operdata_%d_%d\", get_autoid(), uptime)\
    rule.msgarray = {}\
    rule.stat = { okbyte = 0, errbyte = 0 }\
    rule.finicall = function (err, data)\
        local stat = rule.stat\
        if err then\
            log.info(\"operdata \", rule.addr, \" finicall err, \", err)\
            stat.errbyte = stat.errbyte + #data\
        else\
            stat.okbyte = stat.okbyte + #data\
        end\
    end\
\
    rule.period = (type(t.period) == \"number\") and t.period or 600\
    rule.maxcnt = (type(t.maxcnt) == \"number\") and t.maxcnt or 100\
    if type(t.uselconn) == \"boolean\" then\
        rule.uselconn = t.uselconn\
    else\
        rule.uselconn = false\
    end\
    if rule.uselconn then\
        rule.lconn = dpi.datalongconn_start(rule.addr, CENUM.COMM_ACTION_DEVOPS_DPI_DATA, rule.maxcnt, true, rule.finicall)\
    else\
        timer.mod(rule.tname, rule.period, 0, operdata_send, rule)\
    end\
\
    table.insert(operdata.rules, rule)\
    return rule.tname\
end\
\
local function write(t)\
    if type(t.rules) == \"table\" and #t.rules > 0 then\
        rule_flush()\
        for _, rule in ipairs(t.rules) do\
            rule_add(rule)\
        end\
    end\
end\
\
local function add(msg)\
    if type(msg.data) ~= \"table\" then\
        log.error(\"must add table for oper data\")\
        return\
    end\
\
    log.info(\"operdata add , \", cjson.encode(msg.data))\
\
    for _, rule in pairs(operdata.rules) do\
        local ok, result = pcall(rule.filtercall, msg.data)\
        if not ok then\
            log.error(\"failed to do filtercall, error is \"..result)\
            -- immediate break and ignore other rules, to expose this error asap\
            break\
        end\
        if result == true then\
            if rule.uselconn then\
                dpi.datalongconn_send(rule.lconn, msg.data)\
            else\
                table.insert(rule.msgarray, msg.data)\
                if #rule.msgarray >= rule.maxcnt then\
                    operdata_send(rule)\
                    timer.mod(rule.tname, rule.period, 0, operdata_send, rule)\
                end\
            end\
        end\
    end\
end\
\
actor.action_set(operdata.subtype, \"rule_add\", rule_add, 'add one rule, { \"addr\":\"string\",\"filter\":[\"\",...],... }')\
actor.action_set(operdata.subtype, \"rule_del\", rule_del, 'del one rule, { \"tname\":\"string\" }')\
actor.action_set(operdata.subtype, \"rule_flush\", rule_flush, \"flush rules\")\
actor.action_set(operdata.subtype, \"stat\", stat, \"read operdata stat\")\
actor.action_set(operdata.subtype, \"read\", read, \"read operdata conf\")\
actor.action_set(operdata.subtype, \"write\", write, 'write operdata, {\"rules\":[{}, ]}')\
actor.action_set(operdata.subtype, \"add\", add, \"add data for send, {data = TABLE}\")\
\
return operdata\
"
, '@'.."./service/operdata.lua" ) )

package.preload[ "oscloud" ] = assert( (loadstring or load)(
"\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local cjson = require(\"cjson\")\
local mystring = require(\"mystring\")\
\
local oscloud = {\
    type = \"oscloud\",\
    subtype = \"oscloud\",\
    help = \"receive cloud dev desc\",\
    count = 0,\
    max_count = 64,\
    oss = {},\
}              -- use mac as key\
\
local function flush()\
    oscloud.oss = {}\
    oscloud.count = 0\
end\
\
local function del_oscloud_old()\
    local oldtime = os.time()\
    local mac\
\
    for k,v in pairs(oscloud.oss) do\
        if v.time and oldtime >= v.time then\
            oldtime = v.time\
            mac = k\
        end\
    end\
\
    oscloud.oss[mac] = nil\
    oscloud.count = oscloud.count -1\
end\
\
local function pdev_update(t)\
    local update = {need_save = false, macdesc = {}, rt_dev = {}}\
\
    if t.flush then\
        flush()                 -- only flush\
        return update\
    end\
\
    if t.replace then\
        flush()\
    end\
\
    if not t.devices or type(t.devices) ~= \"table\" then\
        return update\
    end\
\
    for k,v in pairs(t.devices) do\
        v.desc.id = v.osid\
        local seam_mac = 0\
        for m,n in pairs(oscloud.oss) do\
            if m == v.mac then\
                seam_mac = 1\
                if v.desc.elinktype ~= n.desc.elinktype and n.desc.elinktype == 1 then\
                    t.devices[k] = nil\
                elseif v.osid ~= n.osid or not mystring.same_table(v.desc, n.desc) then\
                    update.need_save = true\
                end\
            end\
        end\
        if seam_mac ~= 1 then\
            update.need_save = true\
        end\
    end\
    \
    for _, v in pairs(t.devices) do\
        if v.mac then\
            local mac = v.mac\
            local oss = oscloud.oss\
            if v.osid == 0 then\
                if oss[mac] then\
                    oscloud.count = oscloud.count - 1\
                end\
                oss[mac] = nil -- delete this oscloud\
            else\
                if not oss[mac] then\
                    oscloud.count = oscloud.count + 1\
                end\
                oss[mac] = {osid = v.osid, desc = v.desc or {}, time = os.time()}\
                \
                local desc = oss[mac].desc\
                local routedev = v.rt_dev\
                desc.id = v.osid\
                if oscloud.count > oscloud.max_count then\
                    del_oscloud_old()  -- delete old oscloud\
                end\
                if oss[mac] and type(desc) == \"table\" then  \
                    local id, ostype, brand, model, devtype, groupid, elinktype, os, dev_type, devtypeint = desc.id, desc.ostype, desc.brand, desc.model, desc.devtype, desc.groupid, desc.elinktype, desc.os, desc.dev_type, desc.devtypeint\
                    update.macdesc[mac] = {id = id, model = model, brand = brand, devtype = devtype, ostype = ostype, os = os, dev_type = dev_type, elinktype = elinktype, devtypeint = devtypeint} \
                    update.rt_dev[mac] = routedev\
                    if id and ostype and brand and model and devtype and groupid then\
                        lcmd_run {subtype = \"sig\", action = \"write\", osid = id, ostype = ostype, brand = brand, model = model, devtype = devtype, groupid = groupid}\
                        log.info(\"update osinfo , \", cjson.encode(desc))   -- update to sig desc\
                    end\
                end\
            end\
        end\
    end\
    return update\
end\
\
local function pdev_show()\
    return oscloud.oss\
end\
\
local function pdev_getosid(t)\
    local oss = oscloud.oss\
    if type(t.mac) == \"string\" and oss[t.mac] then\
        return oss[t.mac].osid\
    else\
        return nil\
    end\
end\
\
actor.action_set(oscloud.subtype, \"pdev_update\", pdev_update, \"update cloud dev desc, {devices=table},eg:[{mac=string,osid=number,desc={ostype=number,brand=string,model=string,devtype=number,groupid=number}}]\")\
actor.action_set(oscloud.subtype, \"pdev_show\", pdev_show, \"show cloud put msg\")\
actor.action_set(oscloud.subtype, \"pdev_getosid\", pdev_getosid, \"get cloud osid, {mac=string}\")\
\
return oscloud\
"
, '@'.."./service/oscloud.lua" ) )

package.preload[ "osinfo" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local mystring = require(\"mystring\")\
local ct_enable, ct = pcall(require, \"ct\")\
\
local osinfo = {\
    type = \"osinfo\",\
    subtype = \"osinfo\",\
    help = \"get osinfo from kernel, send to server\",\
\
    period_kernel = 5,\
    period = 0,\
    update_period = 300,\
    timer_name = 'osinfo_get',\
    uptimer_name = 'osinfo_update',\
    chktimer_name = 'ossnum_check',\
    count = 0,\
    oss = {\
        -- mac, key\
          -- ip\
          -- lasttime, firsttime\
          -- hostname, opt60\
          -- osids, table for all osid\
          -- decide_osid\
    },\
    send_time = 0,\
    alive_time = 86400,\
    ctinfo_max = 512,\
    maclevel = {\
        other = -1,\
        repeater = 1,\
        url_cookie = 2,\
        mesh = 3,\
        brctl = 4,\
        lanhost = 5,\
    },\
}\
\
local mac_info_add\
\
local function full_osid_unpack(osid_full) -- osid, ruleid, prio\
    return (osid_full & 0xffff), (osid_full & 0xff0000) >> 16, (osid_full & 0x7000000) >> 24\
end\
\
local function osinfo_publish(one, changed)\
    local tt = {}\
    tt.mac = one.mac\
    tt.ip = one.ip\
    tt.hostname = one.hostname or \"\"\
    tt.osid_pushed = one.decide_osid\
    tt.firsttime = one.firsttime\
    \
    -- publish to other modules\
    actor.publish({msgtype = \"OSINFO\", changed = changed, oss = tt})\
end\
\
local function table_copy_value(src, dst, key, changed)\
    if dst[key] and dst[key] ~= src[key] then\
        src[key] = dst[key]\
        changed[key] = true\
    end\
end\
\
local function osid_merge(origin, new)\
    local ruleid_insert = true\
\
    -- use the max prio    \
    if new.prio > origin.prio then\
        origin.prio = new.prio\
    end\
\
    -- merge ruleid to array\
    for _, v in pairs(origin.ruleid) do\
        if v == new.ruleid then\
            ruleid_insert = false\
            break\
        end\
    end\
    if ruleid_insert then\
        table.insert(origin.ruleid, new.ruleid)\
    end\
\
    -- merge stream_cnt\
    origin.stream_cnt = origin.stream_cnt + new.stream_cnt\
end\
\
local function osinfo_decide_osid(origin)\
    local host_prio, host_rule, host_osid, max_prio, max_osid = 0, 0, 0, 0, 0\
    if origin.cloud_osid then\
        return origin.cloud_osid, 4\
    end\
\
    if origin.osid_hostname > 0 then\
        host_osid, host_rule, host_prio = full_osid_unpack(origin.osid_hostname)\
    end\
\
    for osid, v in pairs(origin.osids) do\
        if v.prio > max_prio then\
            max_osid = osid\
            max_prio = v.prio\
        end\
    end\
\
    if max_prio <= host_prio then\
        return host_osid, host_prio\
    else\
        return max_osid, max_prio\
    end\
end\
\
local function update_desc(origin, desc)\
\
    local oridesc = origin.desc or {}\
\
    local updesc = {model = desc.model_name, brand = desc.brand_name, dev_type = desc.dev_type_string, devtypeint = desc.dev_type_osgi, os = desc.os_string, elinktype = desc.elinktype or oridesc.elinktype or 0}\
\
\
    if updesc.elinktype == 1 then\
        updesc.dev_type = \"elink\"\
    end\
\
    if not mystring.same_table(updesc, oridesc) then\
        origin.set_fail = 0\
        origin.desc = updesc\
    end\
end\
\
local function save_dev_desc(t)\
    if not t.mac or not t.desc then\
        return\
    end\
    local one = {mac = t.mac, desc = t.desc}\
    local os = osinfo.oss[t.mac] or {}\
    if (not os.desc or os.desc.dev_type ~= t.desc.dev_type) or t.need_save  then\
        lcmd_run({subtype = \"osinfo\", action = \"pdev_update\", devices = {one}})\
    end\
\
end\
\
local function decide_update_save(mac, origin)\
   local ok, desc = lcmd_run({subtype = \"sig\", action = \"read\", osid = origin.decide_osid})\
   local odesc = origin.desc or {}\
   if ok and desc and odesc.elinktype ~= 1 then\
        if desc.dev_type_string == \"STB\" then\
            save_dev_desc({mac = mac, desc = {dev_type = desc.dev_type_string, os = desc.os_string, brand = desc.brand_name, model = desc.model_name, devtypeint = desc.dev_type_osgi}})\
        else\
            update_desc(origin, desc)\
        end\
   end\
end\
\
local function osinfo_update(origin, new, changed)\
    origin.lasttime = new.lasttime\
    table_copy_value(origin, new, \"hostname\", changed)\
    table_copy_value(origin, new, \"opt60\", changed)\
    table_copy_value(origin, new, \"ip\", changed)\
\
    if new.osid_hostname > 0 and new.osid_hostname ~= origin.osid_hostname then\
        origin.osid_hostname = new.osid_hostname\
    end\
\
    -- merge osid\
    for osid_full, tt in pairs(new.osids) do\
        tt.osid, tt.ruleid, tt.prio = full_osid_unpack(osid_full)\
        if not origin.osids[tt.osid] then\
            origin.osids[tt.osid] = {}\
            origin.osids[tt.osid].osid = tt.osid\
            origin.osids[tt.osid].ruleid = {tt.ruleid}\
            origin.osids[tt.osid].prio = tt.prio\
            origin.osids[tt.osid].stream_cnt = tt.stream_cnt\
            origin.osids[tt.osid].ttl = tt.ttl\
        else\
            osid_merge(origin.osids[tt.osid], tt)\
        end\
    end\
\
    local decide_osid, prio = osinfo_decide_osid(origin)\
    if decide_osid ~= origin.decide_osid then\
        origin.decide_osid = decide_osid\
        origin.decide_prio = prio\
        changed.osid = true\
        decide_update_save(origin.mac, origin)\
    end\
    return origin.decide_osid\
end\
\
local function osinfo_get_one(sbytes, pos, len)\
    local one, changed = {}, {}\
    local opt60_len, hostlen, osid_cnt, uid = 0, 0, 0, 0\
\
    local all_len = string.unpack('=H', sbytes, pos)\
    assert(all_len == 168 and pos + 167 <= len, string.format(\"all_len %d, pos %d, len %d\", all_len, pos, len))\
\
    local mac = string.sub(sbytes, pos + 2, pos + 7)\
    one.ip = string.sub(sbytes, pos + 8, pos + 11)\
    one.ip = myip.inet_ntoa(one.ip)\
    mac = myip.mac_ntoa(mac)\
    one.mac = mac\
\
    uid, one.lasttime, one.firsttime, opt60_len, hostlen, one.osid_hostname, osid_cnt = string.unpack('=IIIIIII', sbytes, pos + 12)\
    if opt60_len > 0 then\
        one.opt60 = string.sub(sbytes, pos + 104, pos + 104 + opt60_len - 1)\
    end\
    if hostlen > 0 then\
        one.hostname = string.sub(sbytes, pos + 136, pos + 136 + hostlen - 1)\
    end\
\
    one.osids = {}\
    for i = 0, osid_cnt - 1 do\
        local tt, osid_full = {}, 0\
        osid_full, tt.stream_cnt, tt.ttl = string.unpack(\"=IHB\", sbytes, pos + 40 + 8 * i)\
        one.osids[osid_full] = tt\
    end\
\
    local oss = osinfo.oss\
    if ct_enable then\
        -- if mac not in lan_host then return\
        if not oss[mac] then\
            return all_len\
        end\
        if not oss[mac].osids then\
            oss[mac].osids = {}\
            changed['all'] = true\
        end\
    else\
        if not oss[mac] then\
            mac_info_add({mac=mac, key=\"osids\", value={}})\
            changed['all'] = true\
        end\
    end\
    oss[mac].firsttime = one.firsttime\
    oss[mac].mac = one.mac\
    oss[mac].osid_hostname = one.osid_hostname\
    if one.hostname then\
        oss[mac].hostname = one.hostname\
    end\
\
    -- mysys.print(string.format(\"mac = %s, ip = %s\", mac, one.ip))\
    if ct_enable then\
        one.decide_osid = osinfo_update(oss[mac], one, changed)\
        lcmd_run({subtype = \"ct\", action = \"update\", mac = mac, ip = one.ip, id = one.decide_osid})\
    else\
        one.decide_osid = osinfo_update(oss[mac], one, changed)\
    end\
\
    oss[mac].send = true\
    osinfo_publish(one, changed)\
\
    return all_len\
end\
\
local function osinfo_hostname_walk()\
    for mac, v in pairs(osinfo.oss) do\
        if v.hostname and v.osid_hostname == 0 and not v.hostname_walk then\
            local id_string = kernel.read(CENUM.MEMSHR_DEV_HOTSNAME_WALK, 4, v.hostname:lower())\
            if id_string and #id_string == 4 then\
                v.osid_hostname = string.unpack(\"=I\", id_string);\
            end\
            v.hostname_walk = true\
            v.decide_osid, v.decide_prio = osinfo_decide_osid(v)\
            decide_update_save(mac, v)\
        end\
    end\
end\
\
local function osinfo_get(sbytes)\
    local len, used_len, one_size = sbytes:len(), 0, 0\
    while used_len < len do\
        one_size = osinfo_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
    end\
\
    assert(used_len == len)\
    return len\
end\
\
local function osinfo_period_send()\
    if osinfo.period <= 0 then\
        return                  -- do not send if period is zero\
    end\
    local now = os.time()\
    if now < osinfo.send_time + osinfo.period then\
        return                  -- send must after period\
    end\
\
    for mac, v in pairs(osinfo.oss) do\
        if v.send then\
            local tt = {}\
            tt.mac = mac\
            tt.ip = v.ip\
            tt.hostname = v.hostname or \"\"\
            tt.osid_pushed = v.decide_osid\
            tt.firsttime = v.firsttime\
\
            tt.type = \"data_osinfo\"\
            lcmd_run{subtype = \"__oper_data\", action = \"add\", data = tt}\
            log.info(\"send osinfo , \", cjson.encode(tt))\
            osinfo.count = osinfo.count + 1\
\
            if ct_enable then\
                lcmd_run{subtype = \"ct\", action = \"send_osinfo\", mac = mac, ip = v.ip, osid = v.decide_osid, hostname = v.hostname or \"\"} -- send DMP\
            end\
            v.send = false\
        end\
    end\
    \
    osinfo.send_time = now\
end\
\
local function get_kernel()\
    kernel.call(CENUM.MEMSHR_K2U_OSINFO, \"\", osinfo_get)\
    osinfo_hostname_walk()\
    osinfo_period_send()\
    return {}\
end\
\
local function merge_sig(origin, key, value)\
    local old = origin[key]\
    if not old or type(old) ~= \"table\" then\
        origin[key] = {value}\
        return\
    end\
\
    for k,v in pairs(old) do\
        if v == value then\
            return\
        end\
    end\
    table.insert(old, value)\
end\
\
local function add_mac_from(from, fromnew)\
    local macfrom = from\
    local new = fromnew or \"other\"\
    if not osinfo.maclevel[macfrom] then\
        macfrom = \"other\"\
    elseif from ~= new and osinfo.maclevel[new] and osinfo.maclevel[from] < osinfo.maclevel[new] then\
        macfrom = new\
    end\
    return macfrom\
end\
\
local function add_sig(t)\
    local mac, key, value, table = myip.mac_fmt(t.mac, \":\"), t.key, t.value, t.table\
    local oss = osinfo.oss\
    if not mac or not key or not value then\
        return\
    end\
    if not oss[mac] then\
        oss[mac] = {sigs = {}, firsttime = os.time()}\
    elseif not oss[mac][\"sigs\"] then\
        oss[mac][\"sigs\"] = {}\
    end\
    oss[mac][\"lasttime\"] = os.time()\
    local origin = oss[mac][\"sigs\"] \
\
    if table then\
        origin[key] = value    \
        return\
    end\
    oss[mac].macfrom = add_mac_from(oss[mac].macfrom or \"other\", t.from)\
    merge_sig(origin, key, value)\
end\
\
function mac_info_add(t)\
    local mac, key, value = myip.mac_fmt(t.mac, \":\"), t.key, t.value\
    local oss = osinfo.oss\
    if mac and key and value then\
        if not oss[mac] then\
            oss[mac] = {[key] = value, firsttime = os.time(), lasttime = os.time()}\
        else\
            oss[mac][key] = value\
        end\
\
        if oss[mac]['active'] == 1 or not oss[mac]['active'] then\
            oss[mac][\"lasttime\"] = os.time()\
        end\
\
        oss[mac].macfrom = add_mac_from(oss[mac].macfrom or \"other\", t.from)\
    end\
end\
\
local function mac_info_del(t)\
    local mac, key = myip.mac_fmt(t.mac, \":\"), t.key\
    local oss = osinfo.oss\
    if mac and key then\
        local one = oss[mac]\
        if not one or not one[key] then\
            return\
        end\
        one[key] = nil\
    end\
end\
\
local function del_sig(t)\
    local mac, key = myip.mac_fmt(t.mac, \":\"), t.key\
    local oss = osinfo.oss\
    if mac and key and oss[mac] then\
        local sig = oss[mac][\"sigs\"]\
        if type(sig) == \"table\" then\
            sig[key] = nil\
        end\
    end\
end\
\
local function pdev_update(t)\
    local ok, result = lcmd_run({subtype = \"oscloud\", action = \"pdev_update\", devices = t.devices, flush = t.flush})\
    if not ok then\
        return\
    end\
    local need_save, oss, rt_dev = result.need_save, result.macdesc, result.rt_dev\
\
    for mac,info in pairs(oss) do\
        local _,desc = lcmd_run({subtype = \"sig\", action = \"read_string\", ostype = info.ostype, devtype = info.devtype})\
        desc = desc or {}\
        local macdesc = {model_name = info.model, brand_name = info.brand, dev_type_string = info.dev_type or desc.dev_type, os_string = info.os or desc.os, dev_type_osgi = info.devtypeint or desc.devtypeint, elinktype = info.elinktype or 0}\
        if info.id then\
            mac_info_add({mac=mac, key=\"cloud_osid\", value=info.id})\
            mac_info_add({mac=mac, key=\"iscloud\", value=1})\
            mac_info_add({mac=mac, key=\"cloud_elinktype\", value=info.elinktype or 0})\
        end\
        if not osinfo.oss[mac] then\
            mac_info_add({mac=mac, key=\"lasttime\", value=os.time()})\
        end\
        update_desc(osinfo.oss[mac], macdesc)\
    end\
    \
    for mac,info in pairs(rt_dev) do\
        mac_info_add({mac=mac, key=\"rt_dev\", value=info})\
    end\
\
    if need_save then\
        lcmd_run{type = \"sys\", action = \"save_conf_change\"}\
    end\
end\
\
local function ct_update(not_ct_update)\
    local _, allhost = lcmd_run({subtype = \"ct\", action = \"get_lan_info\", all=1})\
    for k,v in pairs(allhost) do\
        mac_info_add({subtype = \"osinfo\", action = \"add\", mac=v.macstring, key=\"hostname\", value=v.hostname, from = \"lanhost\"})\
        mac_info_add({subtype = \"osinfo\", action = \"add\", mac=v.macstring, key=\"acc_type\", value=v.acc_type, from = \"lanhost\"})\
        mac_info_add({subtype = \"osinfo\", action = \"add\", mac=v.macstring, key=\"acc_port\", value=v.acc_port, from = \"lanhost\"})\
        mac_info_add({subtype = \"osinfo\", action = \"add\", mac=v.macstring, key=\"active\", value=v.active, from = \"lanhost\"})\
        mac_info_add({subtype = \"osinfo\", action = \"add\", mac=v.macstring, key=\"devname\", value=v.devname, from = \"lanhost\"})\
    end\
\
    local _, devname = lcmd_run{subtype = \"ct\", action = \"call_api\", func = \"devname\"} \
    for k,v in pairs(devname) do\
        local mac = myip.mac_check(\"\", v.mac)\
        if mac then\
            mac_info_add({subtype = \"osinfo\", action = \"add\", mac=mac, key=\"devname\", value=v.devname, from = \"devname\"})\
        end\
    end\
    if not_ct_update then\
        return\
    end\
\
    for k,v in pairs(osinfo.oss) do\
        if not v.set_fail or v.set_fail < 3 then\
            local ok, ret = lcmd_run({subtype = \"ct\", action = \"update\", mac = k, desc = v.desc})\
            if ret and ret ~= 0 then\
                v.set_fail = (v.set_fail or 0) + 1\
            end\
        end\
    end\
end\
\
local function write(msg)\
    if msg.period and msg.period ~= osinfo.period then\
        log.info(\"osinfo period change to \", msg.period, \"from \", osinfo.period)\
        osinfo.period = tonumber(msg.period)\
    end\
\
    if msg.period_kernel and osinfo.period_kernel ~= msg.period_kernel then\
        local tt = tonumber(msg.period_kernel)\
        if tt > 0 then\
            osinfo.period_kernel = tt\
            timer.mod(osinfo.timer_name, osinfo.period_kernel, 0, get_kernel)\
        end\
    end\
\
    if msg.update_period and osinfo.update_period ~= msg.update_period then\
        local tt = tonumber(msg.update_period)\
        osinfo.update_period = tt\
        if ct_enable then\
            timer.mod(osinfo.uptimer_name, osinfo.update_period, 0, ct_update)\
        end\
    end\
        \
    if msg.pdev_conf then\
        pdev_update(msg.pdev_conf)\
    end \
    if msg.ct_max_count and msg.ct_max_count ~= osinfo.ct_max_count then\
        osinfo.ct_max_count = tonumber(msg.ct_max_count) \
    end\
\
    if type(msg.alive_time) == \"number\" and msg.alive_time ~= osinfo.alive_time then\
        osinfo.alive_time = msg.alive_time\
    end\
\
    if type(msg.ctinfo_max) == \"number\" and msg.ctinfo_max ~= osinfo.ctinfo_max then\
        osinfo.ctinfo_max = msg.ctinfo_max\
    end\
    if type(msg.maclevel) == \"table\" then\
        osinfo.maclevel = msg.maclevel\
        if not osinfo.maclevel[\"other\"] then\
            osinfo.maclevel[\"other\"] = -1\
        end\
    end\
end\
\
local function osinfo_save()\
    local r = {}\
    osinfo.pdev_conf = {}\
\
    r.action = \"write\"\
    r.type = \"lua_cmd\"\
    r.subtype = osinfo.subtype\
    r.period = osinfo.period\
    \
    local _, pdev_info = lcmd_run({subtype = \"oscloud\", action = \"pdev_show\"})\
    osinfo.pdev_conf.devices = {}\
    for k,v in pairs(pdev_info) do\
        if type(v) == \"table\" and v.desc then\
            table.insert(osinfo.pdev_conf.devices,{mac = k, osid = v.osid, desc = v.desc})\
        end\
    end\
    \
    r.pdev_conf = osinfo.pdev_conf\
    return r\
end\
\
local function get_oss_tree()\
    local tree = \"\"\
    if osinfo.oss then\
        for mac,info in pairs(osinfo.oss) do\
            local one_osinfo = string.format(\"|--- mac(%s) macfrom(%s) active(%s) firsttime(%s) lasttime(%s) iscloud(%s) cloud_osid(%s) hostname(%s) cloud_elinktype(%s) \",mac, info.macfrom, info.active, os.date(\"%Y-%m-%d %H:%M:%S\",info.firsttime), os.date(\"%Y-%m-%d %H:%M:%S\",info.lasttime), tostring(info.iscloud), tostring(info.cloud_osid), info.hostname, tostring(info.cloud_elinktype))\
            if info.desc then\
                local desc = string.format(\"elinktype(%s) model(%s) os(%s) brand(%s) dev_type(%s) devtypeint(%s)\",tostring(info.desc.elinktype), info.desc.model, info.desc.os, info.desc.brand, info.desc.dev_type, tostring(info.desc.elinktype), tostring(info.desc.devtypeint))\
                one_osinfo = one_osinfo .. desc .. \"\\n\"\
            else\
                one_osinfo = one_osinfo .. \"\\n\"\
            end\
            tree = tree .. one_osinfo\
        end\
    end\
    return tree\
end\
\
local function get_oss(t)\
    if t.mac then\
        return osinfo.oss[t.mac] or {}\
    end\
    return osinfo.oss\
end\
\
local function flush_oss()\
    osinfo.oss = {}\
    kernel.send(CENUM.MEMSHR_U2K_DEV_FLUSH, '')\
    return {}\
end\
\
local function pdev_show(t)\
    local _, pdevinfo = lcmd_run({subtype = \"oscloud\", action = \"pdev_show\"})\
    if t.mac then\
        return pdevinfo[t.mac] or {}\
    end\
    return pdevinfo\
end\
\
local function sig_desc(t)\
    local _,msg = lcmd_run({subtype=\"sig\", action = \"read\", osid = t.osid})\
    for m,n in pairs(tt) do\
        if n.desc and n.desc.ostype and n.desc.devtype then\
            local _,msg = lcmd_run({subtype=\"sig\", action = \"read_string\", ostype = n.desc.ostype, devtype = n.desc.devtype})\
            n.desc.os_str = msg.os or \"\"\
            n.desc.devtype_str = msg.devtype or \"\"\
        end\
    end\
    return tt\
end\
\
local function update_term_info()\
    local devinfo = {}\
    local now = os.time()\
    for kmac, info in pairs(osinfo.oss) do\
        if info.par_mac and type(info.desc) == \"table\" and info.lasttime + osinfo.alive_time >= now then\
            local tt  = {\
                mac = myip.mac_fmt(kmac),\
                par_mac = info.par_mac,\
                model = info.desc.model,\
                brand = info.desc.brand,\
                dev_type = info.desc.dev_type,\
                os = info.desc.os,\
            }\
            pmac = myip.mac_fmt(info.par_mac,\":\")\
            if not devinfo[pmac] then\
                devinfo[pmac] = {}\
            end\
            table.insert(devinfo[pmac], tt)\
        end\
    end\
    return devinfo\
end\
\
local function get_rtdev(t)\
    local rtdev = {}\
    local devinfos = update_term_info()\
    for k,v in pairs(osinfo.oss) do\
        local mac = myip.mac_fmt(k)\
        if type(v.rt_dev) == \"table\" and v.desc and v.desc.dev_type == \"ROUTER\" then\
            local hosts = {}\
            for _,info in pairs(v.rt_dev) do\
                local model = info.model or \"\"\
                hosts[model] = {par_mac = mac, model = info.model, os = info.os, brand = info.brand, dev_type = info.devtype}\
            end\
\
            if type(devinfos[k]) == \"table\" then\
                for _, info in pairs(devinfos[k]) do\
                    local model = info.model\
                    if hosts[model] then\
                        hosts[model] = nil\
                    end\
                    local tt = {mac = info.mac, par_mac = info.par_mac, model = info.model, os = info.os, brand = info.brand, dev_type = info.dev_type}\
                    table.insert(rtdev, tt)\
                end\
            end\
            for k,v in pairs(hosts) do\
                table.insert(rtdev, v)\
            end\
        end\
    end\
\
    return rtdev\
end\
\
local function ossnum_check(ossnum_check_accordingto_lasttime)\
    local now, osschk = os.time(), {}\
    for k, v in pairs(osinfo.oss) do\
        local tt = {lasttime = v.lasttime, mac = k}\
        table.insert(osschk, tt)\
    end\
\
    if #osschk > osinfo.ctinfo_max then\
        table.sort(osschk, function(t1, t2) return t1.lasttime < t2.lasttime end)\
        for j = 1, #osschk - osinfo.ctinfo_max do\
            local mac = osschk[j].mac\
            osinfo.oss[mac] = nil\
            osschk[j] = nil\
        end\
    end\
\
    for k, v in pairs(osschk) do\
        local info = osinfo.oss[v.mac]\
        if info.par_mac and info.lasttime + osinfo.alive_time < now then\
            osinfo.oss[v.mac] = nil\
        end\
    end\
end\
\
function osinfo.postinit()\
    kernel.set_engine(CENUM.ENGINE_TYPE_OS_OTHER, 1)\
    kernel.set_engine(CENUM.ENGINE_TYPE_OS_HTTP, 1)\
    timer.mod(osinfo.timer_name, osinfo.period_kernel, 0, get_kernel)\
    timer.mod(osinfo.chktimer_name, 300, 0, ossnum_check)\
    if ct_enable then\
        ct_update(true)\
        timer.mod(osinfo.uptimer_name, osinfo.update_period, 0, ct_update)\
    end\
end\
\
actor.action_set(osinfo.subtype, \"get_kernel\", get_kernel, \"get osinfo from kernel manualy\")\
actor.action_set(osinfo.subtype, \"write\", write, [[set osinfo period,{period=number,period_kernel=number,pdev_conf=table,ct_max_count=number}, period 0 will not set]])\
actor.action_set(osinfo.subtype, \"read\", function () return {update_period = osinfo.update_period, period = osinfo.period, period_kernel = osinfo.period_kernel, count = osinfo.count, alive_time = osinfo.alive_time, ctinfo_max = osinfo.ctinfo_max} end, \"read conf\")\
actor.action_set(osinfo.subtype, \"show_maclevel\", function () return  osinfo.maclevel end, \"read conf\")\
actor.action_set(osinfo.subtype, \"get_oss\", get_oss, \"get osinfo msg\")\
actor.action_set(osinfo.subtype, \"flush_oss\", flush_oss, \"clean osinfo msg\")\
actor.action_set(osinfo.subtype, \"pdev_update\", pdev_update, 'update cloud dev desc, {devices=table},eg:[{mac=string,osid=number,desc={ostype=number,brand=string,model=string,devtype=number,groupid=number}}]')\
actor.action_set(osinfo.subtype, \"pdev_show\", pdev_show, \"show cloud put msg\")\
actor.action_set(osinfo.subtype, \"show_conf_svr\", function() return {type = \"lua_cmd\", subtype = \"osinfo\"} end, \"show osinfo conf msg to oper svr\")\
actor.action_set(osinfo.subtype, \"show_conf_save\", osinfo_save, \"show osinfo save conf msg\")\
actor.action_set(osinfo.subtype, \"stat\", function() local _,info =  lcmd_run({subtype=\"ct\",action=\"stat\"})  if info then return {all_len=info.all_len,all_count=info.all_count} end end, \"get osinfo stat\")\
actor.action_set(osinfo.subtype, \"add\", mac_info_add, \"[[oss add key value, {mac=string,value=string or table, from=string}]]\")\
actor.action_set(osinfo.subtype, \"add_sig\", add_sig, \"[[oss add sigs, {mac=string,key=string,value=string}]]\")\
actor.action_set(osinfo.subtype, \"del_sig\", del_sig, \"[[oss del sigs, {mac=string,key=string}]]\")\
actor.action_set(osinfo.subtype, \"del\", mac_info_del, \"[[oss del key, {mac=string,key=string}]]\")\
actor.action_set(osinfo.subtype, \"get_rtdev\", get_rtdev, \"[[get route dev from plt]]\")\
actor.action_set(osinfo.subtype, \"save_dev_desc\", save_dev_desc, \"[[save to oscloud, {mac=string,desc=table}]]\")\
actor.action_set(osinfo.subtype, \"get_oss_tree\", get_oss_tree, \"[[show osinfo in tree]]\")\
return osinfo\
"
, '@'.."./service/osinfo.lua" ) )

package.preload[ "pbmsg" ] = assert( (loadstring or load)(
"local pbmsg = {\
\
clientserver = \"0AD007422A5A286769742E6D61786E65747379732E636F6D2E636E2F72642F706C61742F677270632F706C7567696E1206706C7567696E620670726F746F330A2F2F686F6D652F7A6A612F6769746C61622F677270632F706C7567696E2F636C69656E747365727665722E70726F746F22751A250A04486F7374120B180120010A036D616328091210180220010A08686F73746E616D6528090A10436C69656E744F6E6C696E6552656164120C180120010A04747970652809122C321D2E706C7567696E2E436C69656E744F6E6C696E65526561642E486F7374180220030A05686F737473280B223D0A0F5365727665724C6F6E675772697465120C180120010A04747970652809120E180220010A06616374696F6E2809120C180320030A0461646472280922280A0A436C69656E7453656564120C180120010A04747970652809120C180220010A04736565642809226D0A0E436C69656E744C6F6E6753686F77120C180120010A04747970652809120B180220010A0373736C28081210180320010A086C6F6E67736F636B2808120C180420010A04616464722809120E180520010A0673746174757328091210180620010A08636F7374617475732809223F0A135365727665725075626C696349505772697465120C180120010A04747970652809120E180220010A06616374696F6E2809120A180320010A0269702809222C0A0E436C69656E7452756C6553656564120C180120010A04747970652809120C180220010A0473656564280922E101221C0A0654617267657412080A044E4F4E45100012080A0444524F5010011A2D0A0952756C6554696D6572120F180120030A0764617974696D652809120F180220030A077765656B646179280D0A0752756C654F6E65120B180120010A036D61632809120F180220030A07646F6D61696E732809120B180320030A036970732809122632162E706C7567696E2E52756C654F6E652E546172676574180420010A06746172676574280E120D180520010A0572616464722809122732192E706C7567696E2E52756C654F6E652E52756C6554696D6572180620030A0474696D65280B226E0A0F436C69656E7452756C655772697465120C180120010A04747970652809120E180220010A06616374696F6E2809120C180320010A04736565642809120F180420010A0764697361626C652808121E320F2E706C7567696E2E52756C654F6E65180520030A0572756C6573280B224F0A1153657276657257616E446E735772697465120C180120010A04747970652809120E180220010A06616374696F6E2809120C180320010A04736565642809120E180420010A0677616E646E732809\",\
\
plugin = \"0AFB07422A5A286769742E6D61786E65747379732E636F6D2E636E2F72642F706C61742F677270632F706C7567696E1206706C7567696E620670726F746F332AF5020A0C506C7567696E416374696F6E12080A044E4F4E45100012160A10414354494F4E5F4C4F4E475F434F4E461081E00712160A10414354494F4E5F4C4F4E475F444154411082E00712170A11414354494F4E5F53484F52545F434F4E461091E00712170A11414354494F4E5F53484F52545F444154411092E00712190A13414354494F4E5F53484F52545F524553554C541093E00712170A11414354494F4E5F53484F52545F5445524D1094E00712160A10414354494F4E5F53484F52545F4150501095E00712160A10414354494F4E5F5345525645525F4F4B1081E20712190A13414354494F4E5F5345525645525F4552524F521082E20712180A12414354494F4E5F5345525645525F434F4E461083E20712150A0F414354494F4E5F434B45595F4745541081E40712170A11414354494F4E5F434B45595F4552524F521082E40712150A0F414354494F4E5F434B45595F5345541083E40712190A13414354494F4E5F434F4D4D4F4E5F48454152541081FE070A292F686F6D652F7A6A612F6769746C61622F677270632F706C7567696E2F706C7567696E2E70726F746F22290A09436F6D6D6F6E486472120C180120010A04747970652809120E180220010A06616374696F6E2809221D0A0D436F6D6D6F6E44617461486472120C180120010A0474797065280922790A0A436C69656E744D736773120C180120030A0464617461280C120A180220010A02736E2809120B180320010A036F75692809120F180420010A07696E745F7665722809120A180520010A0261642809120C180620010A04686569642809120C180720010A04697076342809120B180820010A03646E73280922170A074D656748656164120C180120010A04747970652809222B0A0B436C69656E744865617274120C180120010A04747970652809120E180220010A06757074696D65280D22300A04436B6579120C180120010A04747970652809120B180220010A036B65792809120D180320010A056C65617365280D221A0A0A5365727665724D736773120C180120030A0464617461280C221E0A0E53686F72745365727665724D7367120C180120010A0464617461280C22A0010A09506C7567696E506B741213180120010A0B756E6369706865726C656E280D120D180220010A05736E6D6435280C120B180320010A036B6579280C120C180420010A0474696D652804120F180520010A0776657273696F6E280D122432142E706C7567696E2E506C7567696E416374696F6E180620010A06616374696F6E280E1210180720010A08756E7A69706C656E280D120B180820010A036D7367280C\",\
\
upload = \"0ADF07422A5A286769742E6D61786E65747379732E636F6D2E636E2F72642F706C61742F677270632F706C7567696E1206706C7567696E620670726F746F330A292F686F6D652F7A6A612F6769746C61622F677270632F706C7567696E2F75706C6F61642E70726F746F22720A07444E5344617461120C180120010A04747970652809120C180220010A0474696D652804120B180320010A036D61632809120F180420010A07757365725F697028091211180520010A097365727665725F69702809120E180620010A06646F6D61696E2809120A180720010A026970280922C5010A084854545044617461120C180120010A04747970652809120B180220010A036D61632809120A180320010A0269702809120D180420010A0564737469702809120D180520010A0573706F7274280D120D180620010A0564706F7274280D120E180720010A0674735F7365632804120F180820010A0774735F757365632804120E180920010A066D6574686F64280D120B180A20010A0375726C2809120A180B20010A0275612809120E180C20010A06636F6F6B69652809120B180D20010A037265662809228C010A09485454505344617461120C180120010A04747970652809120C180220010A0474696D652804120B180320010A036D61632809120B180420010A037369702809120B180520010A036469702809120D180620010A0573706F7274280D120D180720010A0564706F7274280D120E180820010A066170705F6964280D120E180920010A06646F6D61696E280922B7020A095475706C6544617461120C180120010A04747970652809120B180220010A036D61632809120B180320010A037369702809120D180420010A0573706F7274280D120D180520010A0570726F746F280D120B180620010A036469702809120D180720010A0564706F7274280D1212180820010A0A73746172745F74696D6528041210180920010A08656E645F74696D652804120F180A20010A07706B74735F696E28041210180B20010A08706B74735F6F757428041210180C20010A0862797465735F696E28041211180D20010A0962797465735F6F75742804120E180E20010A066170705F6964280D1212180F20010A0A6C61745F7374617475732809120C181020010A046C617431280D120C181120010A046C617432280D120C181220010A046C617433280D120C181320010A046C617434280D22710A0A526177706B7444617461120C180120010A04747970652809120C180220010A0474696D652804120C180320010A04756D61632809120C180420010A04646174612809120F180520010A07706B745F6C656E280D120C180620010A046E6F6C322808120C180720010A046E616D652809\",\
\
weibu = \"0AA204422A5A286769742E6D61786E65747379732E636F6D2E636E2F72642F706C61742F677270632F706C7567696E1206706C7567696E620670726F746F3332510A0D4465766963655365727669636512401A132E706C7567696E2E417069526573706F6E7365121B2E706C7567696E2E446576696365497053796E63526571756573740A0C73796E635075626C6963497032510A0D446E734D73675365727669636512402801121E2E706C7567696E2E5765696275446E734D736753656E64526571756573740A0773656E644D73671A132E706C7567696E2E417069526573706F6E73650A282F686F6D652F7A6A612F6769746C61622F677270632F706C7567696E2F77656962752E70726F746F22700A0B5765696275446E734D73671211180120010A0974696D657374616D702804120E180220010A06646F6D61696E2809120D180320010A05715479706528091210180420010A087075626C6963497028091211180520010A097072697661746549702809120A180620010A02736E280922490A165765696275446E734D736753656E6452657175657374120C180120010A04747970652809122132132E706C7567696E2E5765696275446E734D7367180220030A046C697374280B22280A0B417069526573706F6E7365120C180120010A04636F64652805120B180220010A036D73672809222D0A13446576696365497053796E6352657175657374120A180120010A02736E2809120A180220010A0269702809\",\
\
xapp_plugin = \"0A9705422A5A286769742E6D61786E65747379732E636F6D2E636E2F72642F706C61742F677270632F706C7567696E1206706C7567696E620670726F746F330A2E2F686F6D652F7A6A612F6769746C61622F677270632F706C7567696E2F786170705F706C7567696E2E70726F746F22390A09415050536967417272120C180120010A04747970652809121E320E2E706C7567696E2E415050536967180220030A06617070736967280B223C0A0A415050496E666F417272120C180120010A047479706528091220320F2E706C7567696E2E415050496E666F180220030A07617070696E666F280B22730A06415050536967120F180120010A077369677479706528091210180220010A0873696776616C75652809120B180320010A036D61632809120B180420010A036469702809120D180520010A0564706F7274280D120D180620010A056170706964280D120E180720010A0672756C656964280D22510A07415050496E666F120B180120010A036D61632809120D180220010A056170706964280D120E180320010A0672756C656964280D120B180420010A036469702809120D180520010A0564706F7274280D227C0A09415050536967526573120C180120010A04747970652809120E180220010A06616374696F6E2809120B180320010A03616C6C2808122232122E706C7567696E2E415050536967496E666F180420030A0673696D706C65280B122032122E706C7567696E2E415050536967496E666F180520030A0462617365280B226A0A0A415050536967496E666F120E180120010A0672756C656964280D120D180220010A056170706964280D120C180320010A047072696F280D120C180420010A046E616D652809120F180520010A077369677479706528091210180620010A0873696776616C75652809\",\
\
}\
return pbmsg\
"
, '@'.."./lualib/pbmsg.lua" ) )

package.preload[ "pcap_dump" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local kengine = require\"kengine\"\
local log = require\"log\"\
\
local pcap_dump = {\
    type = \"pcap_dump\",\
    subtype = \"pcap_dump\",\
    help = \"read/write/stat pcap\",\
}\
\
function pcap_dump.postinit()\
    kengine.setdefault_ifneeded({filter = \"udp port 53 or udp port 67\", iface = \"br0\", enable = true})\
end\
\
actor.action_set(pcap_dump.subtype, \"stat\", kengine.stat, \"read pcap stat\")\
actor.action_set(pcap_dump.subtype, \"read\", kengine.read, \"read pcap parameter\")\
actor.action_set(pcap_dump.subtype, \"write\", function(t) kengine.write(t) end, \"{filter=string, iface=string, enable=bool}, write pcap\")\
\
return pcap_dump\
"
, '@'.."./service/pcap_dump.lua" ) )

package.preload[ "pktpolicy" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local ctime = require(\"c.time\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local myutil = require(\"myutil\")\
local policy_com = require(\"ct.policy\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local actint = policy_com.actint\
local is_numeric = policy_com.is_numeric\
\
local pktpolicy = {\
    subtype = \"pktpolicy\",\
    timer_name = 'pktpolicy_get',\
    check_tname = \"pktpolicy_check\",\
    merge_tname = \"pktpolicy_merge\",\
    help = \"set pktpolicy and send info to server\",\
    policy_max_cnt = 128,\
    list_max_cnt = 5000,\
    policy_cnt = 0,\
    policy_id = 1,\
    period = 10,\
    merge_period = 1800,\
    merge_info = {},\
    merge_info_cnt = 0,\
    merge_max_cnt = 1024,\
    all_cnt = 0,\
    all_len = 0,\
    enable = true,\
    seed = \"\",\
    kapi_ver = nil,\
    policies = {           -- use index as key\
        -- index, string\
        -- ip_port, ip or ip:port list\
        -- ports, port list\
        -- appid, appid list\
        -- mac\
        -- direct\
        -- action, continue/fin/drop\
        -- dscp_value, 1-36\
        -- info_count\
        -- time\
           -- {weekdays = \"1,2,3,4,5\", time = \"00:00-19:00,21:00-24:00\"}\
        -- enable\
\
        -- times\
           -- {weekdays ={[1]=true, [2] = true}, time = {{start_hour = 0, end_hour = 0}}}\
    },\
}\
\
-- check index uniqueness\
function pktpolicy.check_index(index, subtype)\
    if pktpolicy.policies[index] and pktpolicy.policies[index].type ~= subtype then\
        return false\
    end\
    return true\
end\
\
local function get_kapiver()\
    local kver = 0\
    local ver_string = kernel.read(CENUM.MEMSHR_KAPI_VER, 4, \"\")\
    if ver_string and #ver_string == 4 then\
        kver = string.unpack(\"=I\", ver_string);\
    end\
    -- 初始化前获取接口\
    pktpolicy.kapi_ver = kver\
    return kver\
end\
\
local function kernel_send(ktype, policy)\
    local id, pkts, action, ipport, fmt, dir\
    local ip_count, ip_list, port_list, appid_list, mac, care_mac = 0, {}, {}, {}, \"\\x00\\x00\\x00\\x00\\x00\\x00\", 0\
\
    id = policy.id\
    action = actint[policy.action]\
    if policy.dscp_value then\
        action = policy.dscp_value << 8 | action\
    end\
\
    if policy.direct == \"out\" then\
        dir = 0\
    elseif policy.direct == \"in\" then\
        dir = 1\
    else\
        dir = 2\
    end\
\
    if policy.mac ~= \"\" then\
        care_mac = 1\
        mac = mystring.hex2data(policy.mac)\
    end\
    for k,v in pairs(policy.ip_port) do\
        local ip, port = mystring.split(v, \":\")\
        if ip then\
           local port_str = string.pack(\"=H\", port or 0)\
           local ip_str = myip.inet_aton(ip)\
           table.insert(ip_list, ip_str..port_str)\
           ip_count = ip_count + 1\
        end\
    end\
\
    local buf = string.pack(\"=IIIIIIIc6H\", ip_count, #policy.ports, #policy.appid, id, action, dir, care_mac, mac, policy.enable and 1 or 0)\
    local data = buf..table.concat(ip_list)\
    for k,v in pairs(policy.ports) do\
        table.insert(port_list, string.pack(\"=H\", v))\
    end\
    data = data..table.concat(port_list)\
\
    for k,v in pairs(policy.appid) do\
        table.insert(appid_list, string.pack(\"=I\", v))\
    end\
    data = data..table.concat(appid_list)\
    data = string.pack(\"=Ic\"..data:len(), data:len() + 4, data)\
    kernel.send(ktype, data)\
end\
\
local function update_stat(id, policies)\
    local action, dscp_value\
    for k,v in pairs(policies) do\
        if v.id == id then\
            action, dscp_value = v.action, v.dscp_value\
            v.info_count = v.info_count + 1\
            break\
        end\
    end\
    return action, dscp_value\
end\
\
local function pktpolicy_get_one(sbytes, pos, len, oss)\
\9local info = {}\
\
    local all_len, id, time, dport, sport, dip, sip, mac, proto, action, appid, ruleid = string.unpack('=IIIHHc4c4c6HIII', sbytes, pos)\
    assert(pos + all_len - 1 <= len)\
    local action, dscp_value = update_stat(id, pktpolicy.policies)\
    local index = tostring(id)\
    mac, time = mystring.data2hex(mac, \":\"), tostring(time)\
    if action then\
        info.index = index\
        info.mac = mac    -- mac format: \"F6:63:6A:0A:6B:5F\"\
        info.type = \"pktpolicy\"\
        info.time = time\
        info.dip = myip.inet_ntoa(dip)\
        info.dport = dport\
        info.sip = myip.inet_ntoa(sip)\
        info.sport = sport\
        info.proto = proto\
        info.action = action\
        info.value = dscp_value\
        info.appid = appid\
        info.ruleid = ruleid\
\
        actor.publish({msgtype = \"PKTPOLICY\", data = info})\
    end\
\
    local data, osid, dev_name, hit_cnt = nil, 0, \"\", 0\
    if oss[mac] then\
        osid, dev_name = oss[mac].decide_osid or oss[mac].cloud_osid or 0, oss[mac].devname or \"\"\
    end\
    if pktpolicy.policies[index] then\
        hit_cnt = pktpolicy.policies[index].info_count\
    end\
    data = {index = index, time = time, ip = info.sip, mac2 = mac, appid = appid, dip = info.dip, action = action, value = dscp_value or 0, osid = osid, hit_cnt = hit_cnt}\
\
    return all_len, data\
end\
\
local function upload_merge()\
    local send = false\
    for _, tt in pairs(pktpolicy.merge_info) do\
        send = true\
        tt.type = pktpolicy.subtype\
        tt.period = pktpolicy.merge_period\
        log.info(\"policy merge send to svr, \", cjson.encode(tt))\
        lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tt})\
        pktpolicy.all_len = pktpolicy.all_len + string.len(cjson.encode(tt))\
    end\
    if send then\
        pktpolicy.all_cnt = pktpolicy.all_cnt + 1\
    end\
    pktpolicy.merge_info_cnt = 0\
    pktpolicy.merge_info = {}\
end\
\
local function merge_policy_info(data)\
    if pktpolicy.merge_period <= 0 then\
        return\
    end\
    local key = data.mac2..\"-\"..data.index..\"_\"..data.appid..\"_\"..data.dip\
    if not pktpolicy.merge_info[key] then\
        pktpolicy.merge_info[key] = {index = data.index, time = data.time, ip = data.ip, mac2 = data.mac2, appid = data.appid, dip = data.dip, action = data.action, value = data.value, osid = data.osid, hit_cnt = 1}\
        pktpolicy.merge_info_cnt = pktpolicy.merge_info_cnt + 1\
        if pktpolicy.merge_info_cnt >= pktpolicy.merge_max_cnt then\
            upload_merge()\
            timer.mod(pktpolicy.merge_tname, pktpolicy.merge_period, 0, upload_merge)\
        end\
    else\
        local one = pktpolicy.merge_info[key]\
        one.hit_cnt = one.hit_cnt + 1\
    end\
end\
\
local function pktpolicy_get(sbytes)\
    local len, used_len = sbytes:len(), 0\
    local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
\
    while used_len < len do\
        local one_size, data = pktpolicy_get_one(sbytes, used_len + 1, len, oss)\
        used_len = used_len + one_size\
        merge_policy_info(data)\
    end\
\
    assert(used_len == len)\
    return len\
end\
\
local function pktpolicy_del(msg)\
    local indexes, subtype = msg.index or {}, msg.ftype\
    if type(indexes) ~= \"table\" then\
        log.warn(\"invalid index\")\
        return {msg = \"invalid index\"}\
    end\
    for _, index in pairs(indexes) do\
        if not pktpolicy.check_index(index, subtype) then\
            return {msg = \"reject delete, the index \"..tostring(index)..\" belongs to \"..(pktpolicy.policies[index].type or pktpolicy.subtype)}\
        end\
    end\
    for _, index in pairs(indexes) do\
        if is_numeric(index) and pktpolicy.policies[index] then\
            local policy = {\
                id = tonumber(index),\
                ip_port = {},\
                ports = {},\
                appid = {},\
                direct = \"\",\
                mac = \"\",\
                action = \"continue\"\
            }\
            kernel_send(CENUM.MEMSHR_PKT_POLICY_DEL, policy)\
            pktpolicy.policies[index] = nil\
            pktpolicy.policy_cnt = pktpolicy.policy_cnt - 1\
        else\
            log.warn(\"No such index to delete\")\
        end\
    end\
end\
\
local function pktpolicy_add(conf)\
    local need_save = false\
    if type(conf.policies) ~= \"table\" then\
        log.warn(\"invalid policies\")\
        return\
    end\
    local date, wday = policy_com.date_fmt()\
    for _, msg in pairs(conf.policies) do\
        -- continue/fin不需要校验内核版本\
        -- 不对kver校验，来自吴芳的需求\
        -- if msg.action ~= \"continue\" and msg.action ~= \"fin\" and pktpolicy.kapi_ver ~= 1 then\
        --     log.warn(\"kernel don't support\")\
        --     goto continue\
        -- end\
\
        -- 输入参数为string格式的数值\
        if not is_numeric(msg.index) then\
            return {msg = \"invalid index type\"}\
        end\
\
        -- update policy\
        if not pktpolicy.check_index(msg.index, msg.type) then\
            return {err = \"reject update! index \"..msg.index..\" already exists, this policy belongs to \"..(pktpolicy.policies[msg.index].type or pktpolicy.subtype)}\
        end\
\
        -- add new policy\
        if not pktpolicy.policies[msg.index] and pktpolicy.policy_cnt >= pktpolicy.policy_max_cnt then\
            return {err = \"can not exceed the limit count \"..tostring(pktpolicy.policy_max_cnt)}\
        end\
\
        if msg.action == \"dscp\" and type(msg.dscp_value) ~= \"number\" then\
            log.warn(\"set dscp need dscp_value\")\
            return\
        end\
        local dscp_value\
        if msg.action == \"dscp\" then\
            dscp_value = msg.dscp_value\
        end\
\
        if not msg.action or not actint[msg.action]  then\
            return {msg = \"invalid action type\"}\
        end\
\
        local ipport, ports, appids = msg.ip_port or {}, msg.ports or {}, msg.appid or {}\
        if type(ipport) ~= \"table\" or type(ports) ~= \"table\" or type(appids) ~= \"table\"  then\
            return {msg = \"invalid appids or iports\"}\
        end\
        if #ipport > pktpolicy.list_max_cnt or #ports > pktpolicy.list_max_cnt or #appids > pktpolicy.list_max_cnt then\
            return\
        end\
\
        local policy = {\
            id = tonumber(msg.index),\
            appid = msg.appid or {},\
            mac = msg.mac or \"\",\
            time = msg.time or {weekdays = \"1,2,3,4,5,6,7\", time = \"00:00-24:00\"},\
            action = msg.action,\
            dscp_value = dscp_value,\
            ip_port = msg.ip_port or {},\
            ports = msg.ports or {},\
            direct = msg.direct or \"\",\
            info_count = 0,\
        }\
        local ok, times = policy_com.parse_time(policy.time)\
        if ok then\
            pktpolicy_del({index = {msg.index}})\
            policy.enable = policy_com.check_time(date, wday, times)\
            policy.times = times\
            need_save = true\
            kernel_send(CENUM.MEMSHR_PKT_POLICY_ADD, policy)\
            policy.type = msg.type\
            pktpolicy.policies[msg.index] = policy\
            pktpolicy.policy_cnt = pktpolicy.policy_cnt + 1\
        end\
        ::continue::\
    end\
    if need_save then\
        lcmd_run{type = \"sys\", action = \"save_conf_change\"}\
    end\
    return {msg = \"add success in pktpolicy\"}\
end\
\
local function pktpolicy_update(msg)\
    local index, enable\
    if msg.index then\
        index = msg.index\
    end\
    if msg.enable then\
        enable = true\
    else\
        enable = false\
    end\
    if pktpolicy.policies[index] then\
        local one = pktpolicy.policies[index]\
        local id = one.id\
        if id and type(id) == \"number\" and one.enable ~= enable then\
            one.enable = enable\
            kernel.send(CENUM.MEMSHR_PKT_POLICY_UPDATE, string.pack(\"=HHI\", 8, enable and 1 or 0, id))\
        end\
    else\
        log.warn(\"No such index to update\")\
    end\
end\
\
local function stat()\
    local res = {}\
    for k,v in pairs(pktpolicy.policies) do\
        res[k] = {\
            id = v.id,\
            type = v.type,\
            ip_port = v.ip_port,\
            ports = v.ports,\
            appid = v.appid,\
            mac = v.mac,\
            direct = v.direct,\
            action = v.action,\
            dscp_value = v.dscp_value,\
            time = v.time,\
            -- times = v.times,         -- time after parsing\
            info_count = v.info_count,\
            enable = v.enable,\
        }\
    end\
    return res\
end\
\
local function write(msg)\
    if type(msg.period) == \"number\" and msg.period ~= pktpolicy.period then\
        pktpolicy.period = msg.period\
        if pktpolicy.period > 0 then\
            timer.mod(pktpolicy.timer_name, pktpolicy.period, 0, function () kernel.call(CENUM.MEMSHR_PKTPOLICY_MATCHINFO, \"\", pktpolicy_get) end)\
        else                    -- default is 10s\
            timer.mod(pktpolicy.timer_name, 10, 0, function () kernel.call(CENUM.MEMSHR_PKTPOLICY_MATCHINFO, \"\", pktpolicy_get) end)\
        end\
    end\
\
    if type(msg.merge_period) == \"number\" and msg.merge_period ~= pktpolicy.merge_period then\
        pktpolicy.merge_period = msg.merge_period\
        timer.mod(pktpolicy.merge_tname, pktpolicy.merge_period, 0, upload_merge)\
    end\
\
    if type(msg.policy_max_cnt) == \"number\" and msg.policy_max_cnt ~= pktpolicy.policy_max_cnt then\
        pktpolicy.policy_max_cnt = msg.policy_max_cnt\
    end\
\
    if type(msg.list_max_cnt) == \"number\" and msg.list_max_cnt ~= pktpolicy.list_max_cnt then\
        pktpolicy.list_max_cnt = msg.list_max_cnt\
    end\
\
    if type(msg.enable) == \"boolean\" then\
        pktpolicy.enable = msg.enable\
        if pktpolicy.enable then\
            kernel.set_engine(CENUM.ENGINE_TYPE_PKT_POLICY, 1)\
        else\
            kernel.set_engine(CENUM.ENGINE_TYPE_PKT_POLICY, 0)\
        end\
    end\
\
    if type(msg.seed) == \"string\" then\
        pktpolicy.seed = msg.seed\
    end\
\
    if type(msg.policies) == \"table\" then\
        local conf = {policies = msg.policies}\
        pktpolicy_add(conf)\
    end\
end\
\
local function read()\
    return {\
        period = pktpolicy.period,\
        merge_period = pktpolicy.merge_period,\
        policy_max_cnt = pktpolicy.policy_max_cnt,\
        list_max_cnt = pktpolicy.list_max_cnt,\
        enable = pktpolicy.enable,\
        seed = pktpolicy.seed,\
        stat = {\
            policy_cnt = pktpolicy.policy_cnt,\
            kapi_ver = pktpolicy.kapi_ver,\
            all_len = pktpolicy.all_len,\
            all_cnt = pktpolicy.all_cnt,\
            merge_info_cnt = pktpolicy.merge_info_cnt,\
            merge_max_cnt = pktpolicy.merge_max_cnt,\
        },\
    }\
end\
\
local function check_policy()\
    if pktpolicy.policy_cnt <= 0 then\
        return\
    end\
\
    local date, wday = policy_com.date_fmt()\
\
    for key, conf in pairs(pktpolicy.policies) do\
        if policy_com.check_time(date, wday, conf.times) then\
            pktpolicy_update({index = key, enable = true})\
        else\
            pktpolicy_update({index = key, enable = false})\
        end\
    end\
end\
\
function pktpolicy.postinit()\
    timer.mod(pktpolicy.timer_name, pktpolicy.period, 0, function () kernel.call(CENUM.MEMSHR_PKTPOLICY_MATCHINFO, \"\", pktpolicy_get) end)\
    timer.mod(pktpolicy.check_tname, 60, 0, check_policy)\
    timer.mod(pktpolicy.merge_tname, pktpolicy.merge_period, 0, upload_merge)\
    if pktpolicy.enable then\
        kernel.set_engine(CENUM.ENGINE_TYPE_PKT_POLICY, 1)\
    end\
end\
\
actor.action_set(pktpolicy.subtype, \"del\", pktpolicy_del, [[del policy, {index = [\"1\",\"2\"...]}]])\
actor.action_set(pktpolicy.subtype, \"add\", pktpolicy_add, \"policies = {{index = string, ip_port = list, ports = list, appid = list, mac = string, direct = string, action = continue/fin/drop, dscp_value = number, time = list}}\")\
actor.action_set(pktpolicy.subtype, \"update\", pktpolicy_update, [[update policy, {index = string, enable = boolean}]])\
actor.action_set(pktpolicy.subtype, \"stat\", stat, \"read policy\")\
actor.action_set(pktpolicy.subtype, \"flush\", function() for index, _ in pairs(pktpolicy.policies) do pktpolicy_del({index = {index}}) end end, \"flush all pktpolicy policy\")\
actor.action_set(pktpolicy.subtype, \"flush_all\", function()\
    lcmd_run({subtype = \"appctrl\", action = \"flush\"})\
    lcmd_run({subtype = \"appuse\", action = \"flush\"})\
    lcmd_run({subtype = \"appmlp\", action = \"flush\"})\
    lcmd_run({subtype = \"pktpolicy\", action = \"flush\"})\
end, \"flush all policy, include policies in appctrl appuse appmlp\")\
actor.action_set(pktpolicy.subtype, \"write\", write, \"set pktpolicy period, {period = number, merge_period = number, enable = boolean, seed = string, policies = list}, engine default open, period default 10s\")\
actor.action_set(pktpolicy.subtype, \"read\", read, \"read conf\")\
actor.action_set(pktpolicy.subtype, \"get_kapiver\", get_kapiver, \"get kernel api version\")\
actor.action_set(pktpolicy.subtype, \"read_seed\", function () return {seed = pktpolicy.seed} end, \"read seed\")\
actor.action_set(pktpolicy.subtype, \"get_kernel\", function () kernel.call(CENUM.MEMSHR_PKTPOLICY_MATCHINFO, \"\", pktpolicy_get) end, \"get info from kernel\")\
actor.action_set(pktpolicy.subtype, \"show_conf_save\", function () return {subtype = pktpolicy.subtype, action = \"write\", policies = pktpolicy.policies} end, \"show pktpolicy save conf msg\")\
\
return pktpolicy\
"
, '@'.."./service/pktpolicy.lua" ) )

package.preload[ "postmsg" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local log = require(\"log\")\
\
local postmsg = {\
    help = \"DBUS postmsg run lua command\",\
    subtype = \"postmsg\",\
    conf_enable = {\
        -- type_action = true,\
        -- type_*      = true,\
        -- *_action    = true,\
        -- *_*         = true,\
        [\"pktpolicy_*\"]    = true,\
        [\"sec_data_*\"]    = true,\
        [\"sec_camera_*\"] = true,\
        [\"appctrl_*\"] = true,\
        [\"appuse_*\"] = true,\
        [\"appmlp_*\"] = true,\
    },\
    write = {},\
    cnt = 0,\
}\
\
local function deal_one(msg)\
    if type(msg.subtype) ~= \"string\" or type(msg.action) ~= \"string\" then\
        return ret\
    end\
    local ret, allconf, tconf, aconf, taconf = nil, postmsg.conf_enable[\"*_*\"], postmsg.conf_enable[msg.subtype..\"_*\"], postmsg.conf_enable[\"*_\"..msg.action], postmsg.conf_enable[msg.subtype..\"_\"..msg.action]\
\
    if allconf == false or tconf == false or aconf == false or taconf == false then\
        return ret\
    end\
\
    if allconf or tconf or aconf or taconf then\
        local subtype, action = msg.subtype, msg.action\
\
        if action == \"write\" then   --need save\
            postmsg.write[subtype] = msg\
            lcmd_run{type = \"sys\", action = \"save_conf_change\"}\
        end\
\
        local ok, r = lcmd_run(msg)\
        if ok then\
            postmsg.cnt = postmsg.cnt + 1\
            ret = r or {}\
        end\
    end\
    return ret\
end\
\
local function write(msg)\
    local ret\
    if type(msg.type_action) == \"table\" and #msg.type_action >= 0 and not msg.stype then\
        for k,v in pairs(msg.type_action) do\
            postmsg.conf_enable[k] = v\
        end\
    end\
    if type(msg.write) == \"table\" then\
       for k,v in pairs(msg.write) do\
            deal_one(v)\
       end\
    end\
    if type(msg.conf) == \"table\" then\
        ret = deal_one(msg.conf)\
    end\
    return ret\
end\
\
local function postmsg_save()\
    return { subtype = postmsg.subtype, action = \"write\", write = postmsg.write}\
end\
\
actor.action_set(postmsg.subtype, \"read\", function () return postmsg.conf_enable end, \"read period\")\
actor.action_set(postmsg.subtype, \"stat\", function () return {count = postmsg.cnt} end, \"read stat count and len\")\
actor.action_set(postmsg.subtype, \"write\", write, [[set conf, {type_action = {type_action/type_*/*_action/*_* = boolean}}]])\
actor.action_set(postmsg.subtype, \"show_conf_save\", postmsg_save, \"show postmsg save conf msg\")\
\
return postmsg\
"
, '@'.."./service/postmsg.lua" ) )

package.preload[ "pqprobe" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local cjson = require(\"cjson\")\
local log = require(\"log\")\
local mime = require(\"mime\")\
local myip = require(\"myip\")\
local timer = require(\"timer\")\
local mystring = require(\"mystring\")\
local myutil = require(\"myutil\")\
\
local pqprobe = {\
    type = \"pqprobe\",\
    subtype = \"pqprobe\",\
    help = \"time delay detection(tcp, udp, dns)\",\
    timer_name = \"pqprobe_dnstimeout\",\
    upload_name = \"pqprobe_upload\",\
    upload_mode = \"svrdata\", -- \"none\", \"svrdata\", \"operdata\", \"all\"\
\
    -- conf\
    tlenable = false,\
    tlmode = \"all\",\
    tllist = {},\
    tllistmax = 1000,\
    tl_sindex = nil,\
    dnsenable = false,\
    dnsmode = \"all\",\
    dnslist = {},\
    dnslistmax = 1000,\
    dnstimeout = 30,\
    dns_sindex = nil,\
\
    dnsmsg = {},\
    dnsmsgmax = 2048,\
    dnsmsgnum = 0,\
\
    -- stat\
    dns_stat = {count = 0,len = 0,ok_count = 0,namerror_count = 0, othererror_count = 0,fail_count = 0,lat_count = 0},\
    tl_stat = {count = 0,len = 0,ok_count = 0,namerror_count = 0, othererror_count = 0,fail_count = 0,lat1_count = 0,lat2_count = 0,lat3_count = 0,lat4_count = 0},\
\
    merge = true,\
    period = 3600,\
    max_merge_count = 2048,\
    merge_info = {\
        -- mac_dsip_dport_app_id_proto_lat_status\
        -- mac_domain_lat_status\
    },\
    merge_info_cnt = 0,\
    thres = {\
        tcpin_thres = 13000,\
        tcpout_thres = 55000,\
        udpin_thres = 0,\
        udpout_thres = 0,\
        dns_thres = 200000,\
    },\
    invalid_lat_count = 0,\
}\
\
local function stat(status, lats)\
    if status.name ~= \"dns_stat\" and status.name ~= \"tl_stat\" then\
        return\
    end\
\
    if type(status.lat_status) == \"string\" then\
        if status.lat_status == \"ok\" then\
            pqprobe[status.name].ok_count = pqprobe[status.name].ok_count + 1\
        elseif status.lat_status == \"namerror\" then\
            pqprobe[status.name].namerror_count = pqprobe[status.name].namerror_count + 1\
        elseif status.lat_status == \"fail\" then\
            pqprobe[status.name].fail_count = pqprobe[status.name].fail_count + 1\
        else\
            pqprobe[status.name].othererror_count = pqprobe[status.name].othererror_count + 1\
        end\
    end\
\
    if type(lats) == \"table\" then\
        for k,v in pairs(lats) do\
            local latx = tostring(k)\
            -- dns lat and tl lat1~lat4 is string\
            local v_number = tonumber(v)\
            if pqprobe[status.name][latx] and type(v_number) == \"number\" and v_number > 0 then\
                pqprobe[status.name][latx] = pqprobe[status.name][latx] + v_number\
            end\
        end\
    end\
end\
\
local function report_pqprobe()\
    if pqprobe.upload_mode ~= \"none\" then\
        for key,tt in pairs(pqprobe.merge_info) do\
            if tt.lat_count then\
                local lats = {lat_count = tt.lat_count}\
\
                pqprobe.dns_stat.count = pqprobe.dns_stat.count + 1\
                pqprobe.dns_stat.len = pqprobe.dns_stat.len + string.len(cjson.encode(tt))\
                keys = {mystring.split(key, \"_\")}\
                tt.mac, tt.lat_status, tt.type, tt.lat_count, tt.period = keys[1], keys[#keys], \"pqprobe_dns_data_merge\", nil, pqprobe.period\
                tt.ext = mime.b64(cjson.encode(tt.ext))\
                if #keys > 3 then\
                    tt.domain = table.concat(keys, \"_\", 2, #keys - 1)\
                else\
                    tt.domain = keys[2]\
                end\
                tt.lat_avg, tt.lat_largest = tostring(tt.lat_avg // tt.count), tostring(tt.lat_largest)\
                local dns_status = {lat_status = tt.lat_status, name = \"dns_stat\"}\
                stat(dns_status,lats)\
            else\
                local lats = {lat1_count = tt.lat1_count, lat2_count = tt.lat2_count, lat3_count = tt.lat3_count, lat4_count = tt.lat4_count}\
\
                pqprobe.tl_stat.count = pqprobe.tl_stat.count + 1\
                pqprobe.tl_stat.len = pqprobe.tl_stat.len + string.len(cjson.encode(tt))\
                tt.mac, tt.dip, tt.dport, tt.app_id, tt.proto, tt.lat_status = mystring.split(key, \"_\")\
                tt.dport, tt.app_id, tt.proto = tonumber(tt.dport), tonumber(tt.app_id), tonumber(tt.proto)\
                tt.type, tt.lat1_count, tt.lat2_count, tt.lat3_count, tt.lat4_count, tt.period = \"pqprobe_data_merge\", nil, nil, nil, nil, pqprobe.period\
                tt.ext = mime.b64(cjson.encode(tt.ext))\
                tt.lat_inner_avg, tt.lat_outer_avg, tt.lat_inner_largest, tt.lat_outer_largest = tostring(tt.lat_inner_avg // tt.count), tostring(tt.lat_outer_avg // tt.count), tostring(tt.lat_inner_largest), tostring(tt.lat_outer_largest)\
                local tl_status = {lat_status = tt.lat_status, name = \"tl_stat\"}\
                stat(tl_status, lats)\
            end\
            if pqprobe.upload_mode == \"operdata\" or pqprobe.upload_mode == \"all\" then\
                lcmd_run({subtype = \"__oper_data\", action = \"add\", data = tt})\
                lcmd_run({subtype = \"__oper_data\", action = \"add\", data = {type = \"pqprobe_invalid_lat\", period = pqprobe.period, invalid_count = pqprobe.invalid_lat_count}})\
            end\
            if pqprobe.upload_mode == \"svrdata\" or pqprobe.upload_mode == \"all\" then\
                lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tt})\
                lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = {type = \"pqprobe_invalid_lat\", period = pqprobe.period, invalid_count = pqprobe.invalid_lat_count}})\
            end\
\
        end\
    end\
    pqprobe.merge_info = {}\
    pqprobe.merge_info_cnt = 0\
    pqprobe.invalid_lat_count = 0\
end\
\
local function is_invalid_lat(lat)\
    lat_ = tonumber(lat)\
    if type(lat_) ~= \"number\" or lat_ <= 0 or lat_ >= 5000000 then\
        pqprobe.invalid_lat_count = pqprobe.invalid_lat_count + 1\
        return true\
    end\
    return false\
end\
\
local function filter_pqprobe(typ, msg)\
    if typ ~= \"dns\" and myip.is_localip(msg.dip) then\
        return false\
    end\
\
    if msg.proto and msg.proto ~= 6 and msg.proto ~= 17 then\
        return false\
    end\
\
    local lat, lat_in, lat_out = msg.lat, msg.lat2, msg.lat1\
    if typ == \"dns\" then\
        if is_invalid_lat(msg.lat) then\
            return false\
        end\
    else\
        if msg.proto == 17 then\
            if msg.lat3 > 0 then\
                lat_out = (msg.lat1 + msg.lat3) / 2\
            end\
            if msg.lat4 > 0 then\
                lat_in = (msg.lat2 + msg.lat4) / 2\
            end\
        end\
        if is_invalid_lat(lat_in) then\
            return false\
        end\
        if is_invalid_lat(lat_out) then\
            return false\
        end\
    end\
    return true, lat, lat_in, lat_out\
end\
\
local function add_one(msg, typ, lat, lat_in, lat_out, thres, thres_in, thres_out)\
    local tt\
    if typ == \"dns\" then\
        tt = {dip = msg.dip, dport = msg.dport, qtype = msg.qtype, qclass = msg.qclass, timestamp = msg.timestamp, ips = msg.ips, count = 0, lat_largest = lat, lat_avg = lat, ext = {thres = thres, lat_abnormal_count = 0}, lat_count = 0}\
    else\
        tt = {qtype = msg.qtype, qclass = msg.qclass, timestamp = msg.timestamp, count = 0, lat_inner_largest = lat_in, lat_inner_avg = lat_in, lat_outer_largest = lat_out, lat_outer_avg = lat_out, ext = {innerthres = thres_in, lat_inner_abnormal_count = 0,outerthres = thres_out, lat_outer_abnormal_count= 0}, lat1_count = 0, lat2_count = 0, lat3_count = 0, lat4_count = 0}\
    end\
    return tt\
end\
\
local function merge_info_add(key, typ, msg)\
    local ok, lat, lat_in, lat_out = filter_pqprobe(typ, msg)\
    if not ok then\
        return\
    end\
    local thres, thres_in, thres_out = pqprobe.thres.dns_thres, pqprobe.thres.tcpin_thres, pqprobe.thres.tcpout_thres\
    if typ == \"tl\" and msg.proto == 17 then\
        thres_in, thres_out = pqprobe.thres.udpin_thres, pqprobe.thres.udpout_thres\
    end\
\
    if not pqprobe.merge_info[key] then\
        pqprobe.merge_info[key] = add_one(msg, typ, lat, lat_in, lat_out, thres, thres_in, thres_out)\
        pqprobe.merge_info_cnt = pqprobe.merge_info_cnt + 1\
    end\
    local one = pqprobe.merge_info[key]\
    one.count = one.count + 1\
    if lat then\
        one.lat_largest = lat > one.lat_largest and lat or one.lat_largest\
        one.lat_avg = one.lat_avg + lat\
        if lat >= one.ext.thres and one.ext.thres > 0 then\
            one.ext.lat_abnormal_count = one.ext.lat_abnormal_count + 1\
        end\
        one.lat_count = one.lat_count + 1\
    else\
        one.lat_inner_largest = lat_in > one.lat_inner_largest and lat_in or one.lat_inner_largest\
        one.lat_outer_largest = lat_out > one.lat_outer_largest and lat_out or one.lat_outer_largest\
        one.lat_inner_avg = one.lat_inner_avg + lat_in\
        one.lat_outer_avg = one.lat_outer_avg + lat_out\
        if lat_in >= one.ext.innerthres and one.ext.innerthres > 0 then\
            one.ext.lat_inner_abnormal_count = one.ext.lat_inner_abnormal_count + 1\
        end\
        if lat_out >= one.ext.outerthres and one.ext.outerthres >0 then\
            one.ext.lat_outer_abnormal_count = one.ext.lat_outer_abnormal_count + 1\
        end\
        for i=1,4 do\
            latx = string.format(\"lat%d\",i)\
            if msg[latx] and msg[latx] > 0 then\
                one[latx..\"_count\"] = one[latx..\"_count\"] + 1\
            end\
        end\
    end\
    if pqprobe.merge_info_cnt >= pqprobe.max_merge_count then\
        report_pqprobe()\
    end\
end\
\
local function get_dns_queries(bytes, offset, len)\
    local tt = {}\
    local pos = 0\
    while pos < (len-offset) do\
        section = string.byte(bytes, pos+offset)\
        if section == 0 then\
            break\
        end\
        table.insert(tt, string.sub(bytes, pos+offset+1, pos+offset+section))\
        pos = pos + section + 1\
    end\
\
    local domain = table.concat(tt, '.')\
    local qtype, qclass = string.unpack(\">HH\", bytes, offset+pos+1)\
    return domain, qtype, qclass, pos+5\
end\
\
local function get_answers_addr(bytes, datatables)\
    local ips = {}\
    for i = 1, datatables.answersNum do\
        local _, atype, aclass, timetl, datalen = string.unpack(\">HHHc4H\", bytes, datatables.offset)\
        if atype == 1 and aclass == 1 and datalen == 4 then\
            local one = string.unpack(\">c4\", bytes, datatables.offset+12)\
            one = myip.inet_ntoa(one)\
            table.insert(ips, one)\
        end\
        datatables.offset = datatables.offset + 12 + datalen\
    end\
    return table.concat(ips, \",\")\
end\
\
local function send_one(tt, lats, lat_stat)\
    if pqprobe.upload_mode ~= \"none\" then\
        if pqprobe.upload_mode == \"operdata\" or pqprobe.upload_mode == \"all\" then\
            lcmd_run({subtype = \"__oper_data\", action = \"add\", data = tt})\
        end\
        if pqprobe.upload_mode == \"svrdata\" or pqprobe.upload_mode == \"all\" then\
            lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tt})\
        end\
\
        stat(lat_stat,lats)\
\
        if lats.lat_count then\
            pqprobe.dns_stat.count = pqprobe.dns_stat.count + 1\
            pqprobe.dns_stat.len = pqprobe.dns_stat.len + string.len(cjson.encode(tt))\
        else\
            pqprobe.tl_stat.count = pqprobe.tl_stat.count + 1\
            pqprobe.tl_stat.len = pqprobe.tl_stat.len + string.len(cjson.encode(tt))\
        end\
    end\
end\
\
local function merge_dns(dnstable, lat_status, lat, ips)\
\9local tt = {\
        type = \"pqprobe_dns_data\",\
        mac = dnstable.mac,\
        sip = dnstable.sip,\
        sport = dnstable.sport,\
        dip = dnstable.dip,\
        dport = dnstable.dport,\
        domain = dnstable.domain,\
        qtype = dnstable.type,\
        qclass = dnstable.class,\
        timestamp = dnstable.timestamp,\
        lat_status = lat_status,\
        lat = tonumber(lat) or 0,\
        ips = ips or \"\",\
    }\
    local merge_key = string.format(\"%s_%s_%s\", tt.mac, tt.domain, tt.lat_status)\
    if pqprobe.merge then\
        merge_info_add(merge_key, \"dns\", tt)\
    else\
        local lats = {lat_count = tt.lat > 0 and 1 or 0}\
        local dns_status = {lat_status = tt.lat_status, name = \"dns_stat\"}\
        tt.lat = tostring(tt.lat)\
        send_one(tt, lats, dns_status)\
    end\
end\
\
local function calc_dns_latency(bytes, dnsdata, dnstable)\
    local lat_status\
    local ips\
    local lat = math.modf((dnsdata.timestamp - dnstable.timestamp)*1000000)\
    if dnsdata.flags&0x0f == 3 then\
        lat_status = \"namerror\"\
    elseif dnsdata.flags&0x0f ~= 0 or dnsdata.answersNum == 0 then\
        lat_status = \"othererror\"\
    else\
        lat_status = \"ok\"\
        ips = get_answers_addr(bytes, dnsdata)\
    end\
\
    merge_dns(dnstable, lat_status, lat, ips)\
end\
\
local function dns_matched(dnslist, domain)\
    if dnslist[domain] then\
        return true\
    end\
    return false\
end\
\
local function check_dns_matched(dnsDomain)\
    if pqprobe.dnsmode == \"all\" then\
        return true\
    else\
        local matched = dns_matched(pqprobe.dnslist, dnsDomain)\
        if pqprobe.dnsmode == \"whitelist\" and matched then\
            return true\
        elseif pqprobe.dnsmode == \"blacklist\" and not matched then\
            return true\
        end\
    end\
    return false\
end\
\
local function oper_dns_queries(bytes, dnsdatas)\
    local dns_key = string.format(\"%s:%d_%s_%d\", dnsdatas.sip, dnsdatas.sport, dnsdatas.dip, dnsdatas.transActionId)\
    if check_dns_matched(dnsdatas.domain) and type(pqprobe.dnsmsg[dns_key]) ~= \"table\" and pqprobe.dnsmsgnum < pqprobe.dnsmsgmax then\
        pqprobe.dnsmsg[dns_key] = dnsdatas\
        pqprobe.dnsmsgnum = pqprobe.dnsmsgnum + 1\
    end\
end\
\
local function oper_dns_answers(bytes, dnsdatas)\
    local dns_key = string.format(\"%s:%d_%s_%d\", dnsdatas.dip, dnsdatas.dport, dnsdatas.sip, dnsdatas.transActionId)    \
    if pqprobe.dnsmsg[dns_key] then\
        calc_dns_latency(bytes, dnsdatas, pqprobe.dnsmsg[dns_key])\
        pqprobe.dnsmsg[dns_key] = nil\
        pqprobe.dnsmsgnum = pqprobe.dnsmsgnum - 1\
    end\
end\
\
local function dns_filter(msg)\
    if pqprobe.dnsenable == false then\
        return\
    end\
\
    local data = msg.pcap_tables\
    if type(data) ~= \"table\" or data.proto ~= 17 or (data.dport ~= 53 and data.sport ~= 53) then\
        return\
    end\
\9\
    local sbytes = data.data\
    -- local sbytes, err = mime.unb64(data.data)\
    -- if err then\
    --     log.error(\"pqprobe wrong base64 code, err is\", err)\
    --     return\
    -- end\
\
    local dnsdata = {\
        mac = data.mac,\
        sip = data.sip,\
        sport = data.sport,\
        dip = data.dip,\
        dport = data.dport,\
        timestamp = data.timestamp,\
        offset = data.offset,\
    }\
    local len = sbytes:len()\
    dnsdata.transActionId, dnsdata.flags, dnsdata.questionsNum, dnsdata.answersNum = string.unpack(\">HHHH\", sbytes, dnsdata.offset)\
    dnsdata.offset = dnsdata.offset + 12\
    dnsdata.domain, dnsdata.type, dnsdata.class, qoffset = get_dns_queries(sbytes, dnsdata.offset, len)\
    dnsdata.offset = dnsdata.offset + qoffset\
\9\
    if dnsdata.questionsNum ~= 1 or dnsdata.type ~= 1 or dnsdata.class ~= 1 then\
        return\
    end\
\
    if (dnsdata.flags>>15) == 0 then\
        oper_dns_queries(sbytes, dnsdata)\
    elseif (dnsdata.flags>>15) == 1 then\
        oper_dns_answers(sbytes, dnsdata)\
    end\
end\
\
local function tuple_matched(tllist, tuple_info)\
    if tllist[tuple_info.sip..\":\"] or tllist[\":\"..tuple_info.sport] or tllist[tuple_info.sip..\":\"..tuple_info.sport] then\
        return true\
    elseif tllist[tuple_info.dip..\":\"] or tllist[\":\"..tuple_info.dport] or tllist[tuple_info.dip..\":\"..tuple_info.dport] then\
        return true\
    end\
    return false\9\
end\
\
local function check_tuple_matched(tuple_info)\
    if pqprobe.tlmode == \"all\" then\
        return true\
    else\
        local matched = tuple_matched(pqprobe.tllist, tuple_info)\
        if pqprobe.tlmode == \"whitelist\" and matched then\
            return true\
        elseif pqprobe.tlmode == \"blacklist\" and not matched then\
            return true\
        end\
    end\
    return false\
end\
\
local function tuple_filter(msg)\
    if pqprobe.tlenable == false then\
        return\
    end\
\
    local tuple_info = msg.tuple_info\
    if check_tuple_matched(tuple_info) then\
        local tt = {\
            type = \"pqprobe_data\",\
            mac = tuple_info.mac,\
            sip = tuple_info.sip,\
            sport = tuple_info.sport,\
            dip = tuple_info.dip,\
            dport = tuple_info.dport,\
            proto = tuple_info.proto,\
            app_id = tuple_info.app_id,\
            timestamp = tostring(tuple_info.start_time),\
            endtime = tuple_info.end_time,\
            lat_status = tuple_info.lat_status,\
            lat1 = tuple_info.lat1 or 0,\
            lat2 = tuple_info.lat2 or 0,\
            lat3 = tuple_info.lat3 or 0,\
            lat4 = tuple_info.lat4 or 0,\
        }\
        local merge_key = string.format(\"%s_%s_%d_%d_%d_%s\", tt.mac, tt.dip, tt.dport, tt.app_id, tt.proto, tt.lat_status)\
    if pqprobe.merge then\
        merge_info_add(merge_key, \"tl\", tt)\
    else\
        local lats = {lat1_count = tt.lat1 > 0 and 1 or 0, lat2_count = tt.lat2 > 0 and 1 or 0, lat3_count = tt.lat3 > 0 and 1 or 0, lat4_count = tt.lat4 > 0 and 1 or 0}\
        local tl_status = {lat_status = tt.lat_status, name = \"tl_stat\"}\
        tt.lat1, tt.lat2, tt.lat3, tt.lat4 = tostring(tt.lat1), tostring(tt.lat2), tostring(tt.lat3), tostring(tt.lat4)\
        send_one(tt, lats, tl_status)\
    end\
    end\
end\
\
local function check_queries_timeout(msgNumheck_queries_timeout)\
    local now = os.time()\
    for k, v in pairs(pqprobe.dnsmsg) do\
        if (now - v.timestamp) >= pqprobe.dnstimeout then\
            merge_dns(v, \"fail\")\
            pqprobe.dnsmsg[k] = nil\
            pqprobe.dnsmsgnum = pqprobe.dnsmsgnum - 1\
        end\
    end\
end\
\
local function read(t)\
    local tl = {}\
    for k, v in pairs(pqprobe.tllist) do\
        table.insert(tl, k)\
    end\
\9\
    local dns = {}\
    for k, v in pairs(pqprobe.dnslist) do\
        table.insert(dns, k)\
    end\
\9\
    return {tlenable = pqprobe.tlenable, tlmode = pqprobe.tlmode, tllist = tl, tllistmax = pqprobe.tllistmax, \
            dnsenable = pqprobe.dnsenable, dnsmode = pqprobe.dnsmode, dnslist = dns, dnslistmax = pqprobe.dnslistmax, dnstimeout = pqprobe.dnstimeout, dnsmsgmax = pqprobe.dnsmsgmax,\
            upload_mode = pqprobe.upload_mode, period = pqprobe.period, max_merge_count = pqprobe.max_merge_count, thres = pqprobe.thres, merge = pqprobe.merge}\
end\
\
local function get_configs(list, cntmax)\
    local tt = {}\
    local max = #list\
    if max > cntmax then\
        max = cntmax\
    end\
    for i = 1, max do\
        tt[list[i]] = true\
    end\
    return tt\
end\
\
local function flush_mergeinfo()\
    pqprobe.merge_info = {}\
    pqprobe.merge_info_cnt = 0\
    pqprobe.invalid_lat_count = 0\
end\
\
local function whitelist_add(typ, filename)\
    if (typ ~= \"dns\" or typ ~= \"tl\") and type(filename) ~= \"string\" then\
        return\
    end\
    local lines = myutil.read_csv(filename)\
    local tt = {}\
    for _,v in pairs(lines) do\
        table.insert(tt, v[1])\
    end\
    if typ == \"dns\" then\
        pqprobe.dnslist = get_configs(tt, pqprobe.dnslistmax)\
    else\
        pqprobe.tllist = get_configs(tt, pqprobe.tllistmax)\
    end\
end\
\
local function set_mergeconf(t)\
    local uploadtimer_need_upload = false\
    if type(t.merge) == \"boolean\" and pqprobe.merge ~= t.merge then\
        flush_mergeinfo()\
        pqprobe.merge = t.merge\
        uploadtimer_need_upload = true\
    end\
    if type(t.period) == \"number\" and t.period ~= pqprobe.period then\
        pqprobe.period = t.period\
        uploadtimer_need_upload = true\
    end\
    if uploadtimer_need_upload then\
        if pqprobe.merge then\
            timer.mod(pqprobe.upload_name, pqprobe.period, 0, report_pqprobe)\
        else\
            timer.mod(pqprobe.upload_name, 0, 0, report_pqprobe)\
        end\
    end\
    if type(t.max_merge_count) == \"number\" then\
        pqprobe.max_merge_count = t.max_merge_count\
    end\
    if type(t.tcpin_thres) == \"number\" then\
        pqprobe.thres.tcpin_thres = t.tcpin_thres\
    end\
    if type(t.tcpout_thres) == \"number\" then\
        pqprobe.thres.tcpout_thres = t.tcpout_thres\
    end\
    if type(t.udpin_thres) == \"number\" then\
        pqprobe.thres.udpin_thres = t.udpin_thres\
    end\
    if type(t.udpout_thres) == \"number\" then\
        pqprobe.thres.udpout_thres = t.udpout_thres\
    end\
    if type(t.dns_thres) == \"number\" then\
        pqprobe.thres.dns_thres = t.dns_thres\
    end\
end\
\
\
local function write(t)\
    local dnstimer_need_update = false\
    if type(t.tlenable) == \"boolean\" and t.tlenable ~= pqprobe.tlenable then\
        pqprobe.tlenable = t.tlenable\
    end\
\
    if t.tlmode and t.tlmode ~= pqprobe.tlmode and (t.tlmode == \"all\" or t.tlmode == \"whitelist\" or t.tlmode == \"blacklist\") then\
        pqprobe.tlmode = t.tlmode\
    end\
\
    if type(t.tllistmax) == \"number\" and t.tllistmax ~= pqprobe.tllistmax then\
        pqprobe.tllistmax = t.tllistmax\
    end\9\
\
    if type(t.tllist) == \"table\" then\
        pqprobe.tllist = get_configs(t.tllist, pqprobe.tllistmax)\
    end\
\
    if type(t.dnsenable) == \"boolean\" and t.dnsenable ~= pqprobe.dnsenable then\
        pqprobe.dnsenable = t.dnsenable\
        dnstimer_need_update = true\
    end\
\
    if t.dnsmode and t.dnsmode ~= pqprobe.dnsmode and (t.dnsmode == \"all\" or t.dnsmode == \"whitelist\" or t.dnsmode == \"blacklist\") then\
        pqprobe.dnsmode = t.dnsmode\
    end\
\
    if type(t.dnslistmax) == \"number\" and t.dnslistmax ~=  pqprobe.dnslistmax then\
        pqprobe.dnslistmax = t.dnslistmax\
    end\9\
\
    if type(t.dnslist) == \"table\" then\
        pqprobe.dnslist = get_configs(t.dnslist, pqprobe.dnslistmax)\
    end\
\
    if type(t.dnsmsgmax) == \"number\" and t.dnsmsgmax ~= pqprobe.dnsmsgmax then\
        pqprobe.dnsmsgmax = t.dnsmsgmax\
    end\
\
    if type(t.dnstimeout) == \"number\" and t.dnstimeout ~= pqprobe.dnstimeout then\
        pqprobe.dnstimeout = t.dnstimeout\
        dnstimer_need_update = true\
    end\
\
    if dnstimer_need_update then\
        if pqprobe.dnsenable then\
            timer.mod(pqprobe.timer_name, pqprobe.dnstimeout/2, 0, check_queries_timeout)\
        else\
            timer.mod(pqprobe.timer_name, 0, 0, check_queries_timeout)\
        end\
    end\
\
    if type(t.upload_mode) == \"string\" and t.upload_mode ~= pqprobe.upload_mode then\
        if t.upload_mode == \"none\" or t.upload_mode == \"svrdata\" or t.upload_mode == \"operdata\" or t.upload_mode == \"all\" then\
            pqprobe.upload_mode = t.upload_mode\
        end\
    end\
    if type(t.dnslistfile) == \"string\" then\
        whitelist_add(\"dns\", t.dnslistfile)\
    end\
    if type(t.tllistfile) == \"string\" then\
        whitelist_add(\"tl\", t.tllistfile)\
    end\
    set_mergeconf(t)\
end\
\
function pqprobe.postinit()\
    pqprobe.tl_sindex = actor.subscribe(\"TUPLE\", tuple_filter)\
    pqprobe.dns_sindex = actor.subscribe(\"PCAP\",  dns_filter)\
    if pqprobe.dnsenable then\
        timer.mod(pqprobe.timer_name, pqprobe.dnstimeout/2, 0, check_queries_timeout)\
    end\
    timer.mod(pqprobe.upload_name, pqprobe.period, 0, report_pqprobe)\
    whitelist_add(\"dns\", \"pqprobe_dns_whitelist\")\
end\
\
function pqprobe.finish()\
    if pqprobe.tl_sindex then\
        actor.unsubscribe(\"TUPLE\", pqprobe.tl_sindex)\
    end\
    if pqprobe.dns_sindex then\
        actor.unsubscribe(\"PCAP\", pqprobe.dns_sindex)\
    end\
end\
\
actor.action_set(pqprobe.subtype, \"stat\", function () return {dns_stat = pqprobe.dns_stat,tl_stat = pqprobe.tl_stat} end, \"read stat\")\
actor.action_set(pqprobe.subtype, \"read\", read, \"read pqprobe configs\")\
actor.action_set(pqprobe.subtype, \"write\", write, \"write pqprobe configs, {period/max_merge_count/tcpin_thres/tcpout_thres/udpin_thres/udpout_thres/dns_thres = number, merge = bool}\")\
actor.action_set(pqprobe.subtype, \"show_dns\", function () return pqprobe.dnsmsg end, \"dns cache data presentation\")\
actor.action_set(pqprobe.subtype, \"show\", function () return pqprobe.merge_info end, \"dns merge_info\")\
actor.action_set(pqprobe.subtype, \"flush_mergeinfo\", flush_mergeinfo, \"flush mergeinfo\")\
\
return pqprobe\
"
, '@'.."./service/pqprobe.lua" ) )

package.preload[ "pscan" ] = assert( (loadstring or load)(
"\
local cjson = require(\"cjson\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local mystring= require(\"mystring\")\
local myfile = require(\"myfile\")\
local cthread = require\"c.thread\"\
local slaxml = require\"nselib.slaxml\"\
local cct_enable, cct = pcall(require, \"c.ct\")\
\
local pscan = {\
    subtype = \"pscan\",\
    period = 0,\
    timer_name = 'pscan_timer', \
    repo = 'http://101.89.180.237:7890/repo_n01/n780/',\
    argv = ' --max-rate 10 -sV -oX ',\
    prog = 'n01',\
    isrunning = false,\
    dst= \"192.168.1.0/24\",\
    oui = \"\",\
    iface = \"br0\",\
\
    -- stat\
    count = 0, \
    run_cnt = 0, \
    all_len = 0,\
\
    help = \"parse n01 result and send to oper_data\"\
}\
\
local function get_element(t, filter)\
    local element = {}\
\
    if type(t) ~= \"table\" then\
        return element\
    end\
    for k,v in pairs(t) do\
        local name = v.name or \"\"\
        local flname = filter[name]\
        if flname and v.type == \"element\" then\
            if not element[name] then\
                element[name] = {} \
            end\
            table.insert(element[name], v[flname])\
        end\
    end\
    for k,v in pairs(filter) do\
        if not element[k] then\
            element[k] = {}\
        end\
    end\
\
    return element\
end\
\
local function get_attr(info, name, filter)\
    local attr = {}\
    if type(info) ~= \"table\" then\
        return attr\
    end\
    for _, v in pairs(info) do\
        if v.name == name and v.type == \"element\" then\
            for _, att in pairs(v.attr) do\
                if att.name and filter[att.name] then\
                    attr[att.name] = att.value\
                end\
            end\
        end\
    end\
    return attr\
end\
\
local function parse_hostscript(ip, mac, hostscripts)\
    local script_info = {}\
    if type(hostscripts) ~= \"table\" then\
        return script_info\
    end\
    for _, v in pairs(hostscripts) do\
        local script = get_attr({v}, \"script\", {id = true})\
        local info = {}\
        for k,v in pairs(v.kids) do\
            if v.name == \"table\" then\
                table.insert(info, v)\
            end\
        end\
        if #info > 0 then\
            local one = {type = \"dev_vuln\", mac = mac, ip = ip, script_name = script.id or \"\", vuln_info = cjson.encode(info)}\
            table.insert(script_info, one)\
        end\
    end\
    return script_info\
end\
\
local function parse_ports(ip, mac, ports)\
    local port_info = {}\
    if type(ports) ~= \"table\" then\
        return port_info\
    end\
    for _, v in pairs(ports) do\
        local port, state, service = {}, {}, {}\
        port = get_attr({v}, \"port\", {protocol = true, portid = true})\
        state = get_attr(v.kids, \"state\", {state = true})\
        service = get_attr(v.kids, \"service\", {name = true, version = true, product = true})\
\
        local portid = tonumber(port.portid)\
        if portid then\
            local one = {type = \"pscan_v1\", mac = mac, ip = ip, port = portid, proto = port.protocol or \"\", status = state.state or \"\", svr = service.name or \"\", version = service.version or \"\", product = service.product or \"\"}\
            table.insert(port_info, one)\
        end\
    end\
    return port_info\
end\
\
local function parse_addr(address)\
    local ip, mac, addr = nil, nil ,{}\
    for k,v in pairs(address) do\
        if type(v) == \"table\" and #v == 2 then\
            local key, value\
            key = v[2].value\
            value = v[1].value\
            addr[key] = value\
        end\
    end\
    return addr[\"ipv4\"] or \"\", addr[\"mac\"] or \"\"\
end\
\
local function add_one(all, info)\
    for k,v in pairs(info) do\
        table.insert(all, v)\
    end\
end\
\
local function file_parse(file)\
    local all, info, nmaprun, hosts = {}, nil, nil, nil\
    local data = myfile.read(file)\
    log.debug(\"read data \" , data)\
\
    info = slaxml.parseDOM(data, { stripWhitespace=true,simple=true })\
    if info and info.kids then\
        nmaprun = get_element(info.kids, {nmaprun = \"kids\"})\
        hosts = get_element(nmaprun.nmaprun[1], {host = \"kids\"})\
    end\
    for k,v in pairs(hosts.host) do\
        local one, ip, mac, ports, hostscript\
        one = get_element(v, {address = \"attr\", ports = \"kids\", hostscript = \"kids\"})\
        ip, mac = parse_addr(one.address)\
        ports = parse_ports(ip, mac, one.ports[1])\
        hostscript = parse_hostscript(ip, mac, one.hostscript[1])\
        \
        add_one(all, ports)\
        add_one(all, hostscript)\
    end\
\
    return all\
end\
\
--t.file\
local function parse(msg)\
    local res = file_parse(msg.file)\
    log.info(\"parse file:\", cjson.encode(res), \"file name:\", msg.file)\
    for k, v in pairs(res) do\
        local str = cjson.encode(v)\
        if v.ip == \"\" or v.mac == \"\" then\
            log.info(\"scan ignore one \", str)\
        else\
            log.info(\"scan send one \", str)\
            lcmd_run({subtype = \"__oper_data\", action = \"add\", data = v})\
            pscan.count = pscan.count + 1\
            pscan.all_len = pscan.all_len + string.len(str)\
        end\
    end\
end\
\
-- t.url\
-- t.save_file\
local function do_download(t)\
    if t.save_file == nil then\
        log.warn(\"save file is nil\")\
        return false\
    end\
\
    local http = require\"socket.http\"\
    local body, code = http.request(t.url)\
    if code ~= 200 then\
        log.error(string.format(\"failed to download (%s), code (%s)\", t.url, code))\
        return false\
    end\
\
    myfile.write(body, t.save_file)\
    return true\
end\
\
-- t.cmd\
local function run_cmd(t)\
    return  t.cmd, os.execute(t.cmd)\
end\
\
-- t.zfile\
-- t.extra_dir\
local function do_extra(t)\
    local cmd = string.format(\"mkdir -p %s && cd %s  && tar zxf %s\", t.extra_dir, t.extra_dir, t.zfile)\
    return run_cmd({cmd=cmd})\
end\
\
local function get_route()\
    local net_dst =  {}\
    local rt_regex = \"((.*)/%w+) (%w+) (%w+)\"\
    local f = io.popen(\"ip route | grep src\")\
    for line in f:lines() do\
        local net, _, _, dev_name = string.match(line, rt_regex)\
        if net then\
            net_dst[dev_name] = net\
        end\
    end\
    f:close()\
    return net_dst\
end\
\
local function get_lan_info()\
    if cct_enable then\
        local netinfo = cct.getnetinfo()\
        local netmask = cct.getdhcpserver() or {}\
        local lan_ip = netinfo.lan_ip\
        local subnetmask = netmask.SubnetMask\
        if lan_ip and #lan_ip > 0 and subnetmask then\
            local mask, err = myip.mask_atob_fast(subnetmask)\
            if not err then\
                local ip = lan_ip .. '/' .. tostring(mask)\
                return ip\
            end\
        end\
    end\
    local net_dst = get_route()\
    for m,n in pairs(net_dst) do\
        if m == pscan.iface then\
            return n\
        end\
    end\
    return \"192.168.1.0/24\"\
end\
\
--t.ret_code\
--t.ret_msg\
--t.file\
local function do_finish(t)\
    if not t.ret_code and not t.ret_msg then\
        log.error(\"invalid do finish , need ret_code and ret_msg\")\
        return\
    end\
\
    if t.ret_code == 0 and t.file  then\
        -- parse result\
        parse({file = t.file})\
    else\
        log.error(string.format(\"finish error ret_code(%d), ret_msg(%s)\", t.ret_code, t.ret_msg))\
    end\
\
    pscan.isrunning = false\
end\
\
\
--t.ret_code\
--t.ret_msg\
--t.file\
local function post_finish(t)\
    local args = \"\"\
    if t.ret_code ~= 0 then\
        args = string.format([[{\"subtype\":\"pscan\", \"action\":\"finish\", \"ret_code\":%d, \"ret_msg\":\"%s\"}]], \
                                    t.ret_code, t.ret_msg)\
    else\
        args = string.format([[{\"subtype\":\"pscan\", \"action\":\"finish\", \"file\":\"%s\",\"ret_code\":%d, \"ret_msg\":\"%s\"}]], \
                                    t.file, t.ret_code, t.ret_msg)\
    end\
    log.info(args)\
    lcmd_client(true, lcmd_tmp_path(\"\"), args)\
end\
\
-- t.prog\
-- t.dst\
-- t.repo\
-- t.oui\
-- this func must run in thread\
local function pscan_proc(t)\
    local n01_dir = lcmd_tmp_path(\".\"..t.prog)\
    local tgz_file = lcmd_tmp_path(t.prog..\".tgz\")\
    local n01_file = n01_dir..\"/\"..t.prog\
    local n01_result = n01_file..\".xml\"\
    --\
    -- download nmap tarball to tmp path\
    local pkg_existed = myfile.existed(tgz_file)\
    if not pkg_existed then\
        local dl_url = string.format(\"%s/%s/n01.tgz\",t.repo , t.oui)\
        local succ = do_download({url = dl_url, save_file = tgz_file})\
        if not succ then\
            post_finish({ret_msg=string.format(\"download n01 failed, url(%s)\", dl_url), ret_code = -1 })\
            return\
        end\
    end\
\
    -- extra nmap tarball to tmp_path\
    local n01_existed = myfile.existed(n01_file)\
    if not n01_existed then\
        local cmd, succ, ret_code, ret_msg = do_extra({zfile= tgz_file, extra_dir=n01_dir})\
        if not succ then\
            post_finish({ret_msg=string.format(\"do extra failedi cmd(%s), ret_msg(%s), ret_code(%d)\",\
                                                cmd, ret_msg, ret_code), ret_code = -1})\
            return\
        end\
    end\
\
    -- check n01 existed\
    local existed_n01 =  myfile.existed(n01_file)\
    if not existed_n01 then\
        post_finish({ret_msg=\"do scan failed, n01 not found !\", ret_code = -1})\
        return\
    end\
\
    -- do scan\
    local scan_cmd = string.format(\"cd %s &&  %s %s %s %s\", n01_dir, n01_file, t.argv, n01_result, t.dst)\
    local cmd, succ, ret_msg, ret_code = run_cmd({cmd = scan_cmd})\
    if not succ then\
        post_finish({ret_msg=string.format(\"do scan failedi cmd(%s), ret_msg(%s), ret_code(%d)\", \
                                            cmd, ret_msg, ret_code), ret_code = -1})\
        return\
    end\
    post_finish({ret_msg=\"parse n01 result file\", ret_code = 0, file = n01_result})\
end\
\
function pscan.postinit()\
    local _, arch = lcmd_run({type = \"arch\", action = \"read\"})\
    pscan.oui = arch.oui\
end\
\
local function get_dst()\
    local dst = get_lan_info()\
    if dst ~= \"\" then\
        pscan.dst = dst\
    end\
end\
\
local function pscan_process(msg)\
    if pscan.isrunning  then\
        log.info(\"pscan is running\")\
        return {info=\"scan service is running\"}\
    end\
    pscan.isrunning = true\
    pscan.run_cnt = pscan.run_cnt + 1\
\
    get_dst()\
\
    if pscan.dst == \"\" or pscan.oui == \"\"  then\
        log.error(\"please check pscan.dst or pscan.oui is correct\")\
    end\
\
    local args = string.format([[{\"subtype\":\"pscan\", \"action\":\"proc\",\"prog\":\"%s\",\"dst\":\"%s\",\"repo\":\"%s\",\"oui\":\"%s\",\"argv\":\"%s\"}]],\
                                pscan.prog, pscan.dst, pscan.repo, pscan.oui, pscan.argv)\
    log.info(\"run thread =\" , args)\
    cthread.run(args)\
    return {info=\"starting scan service\"}\
end\
\
local function write(msg)\
    if msg.period and msg.period ~= pscan.period then\
        log.info(\"period change to\", msg.period, \"from \", pscan.period)\
        pscan.period = msg.period\
        timer.mod(pscan.timer_name, pscan.period, 0, pscan_process)\
    end\
\
    if msg.argv and msg.argv ~= pscan.argv then\
        pscan.argv = msg.argv\
        log.info(\"argv change to \",msg.argv,\" from \",pscan.argv)\
    end\
\
    if msg.iface and msg.iface ~= pscan.iface then\
        pscan.iface = msg.iface\
        log.info(\"iface change to \",msg.argv,\" from \",pscan.iface)\
    end\
\
    if msg.repo and msg.repo ~= pscan.repo then\
        pscan.repo = msg.repo\
    end\
\
    if msg.dst and msg.dst ~= pscan.dst then\
        pscan.dst = msg.dst\
    end\
end\
\
actor.action_set(pscan.subtype, \"read\", function () return {period = pscan.period, dst = pscan.dst, repo=pscan.repo, argv = pscan.argv, iface = pscan.iface} end, \"read pscan conf\")\
actor.action_set(pscan.subtype, \"write\", write, [[ set pscan period and argv, {period = number,argv = string}, period = 0 means close model,argv = nil means use default argv,argv can be changed by yourself]])\
actor.action_set(pscan.subtype, \"stat\", function () return {oui = pscan.oui, len = pscan.all_len, isrunning=pscan.isrunning, data_cnt = pscan.count, run_cnt = pscan.run_cnt} end, \"read pscan stat\")\
actor.action_set(pscan.subtype, \"parse\", parse, [[file = scan.txt parse pscan result file]])\
actor.action_set(pscan.subtype, \"proc\", pscan_proc, [[need 4 args {prog,dst,repo,oui} to start scan service]])\
actor.action_set(pscan.subtype, \"start\", pscan_process, [[start pscan and upload data]])\
actor.action_set(pscan.subtype, \"finish\", do_finish, [[report finish stat]])\
\
return pscan\
"
, '@'.."./service/pscan.lua" ) )

package.preload[ "rawpkt" ] = assert( (loadstring or load)(
"\
local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local ctime = require(\"c.time\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local mystring = require(\"mystring\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local mime = require(\"mime\")\
\
local rawpkt = {\
    count = 0, \
    all_len = 0,\
    subtype = \"rawpkt\",\
    period = 0,\
    timer_name = 'rawpkt_get', \
    help = \"get rawpkt from kernel and send to server\", \
\
    cap_all = 0, -- whether need capture all packets (means include L7_len == 0)\
    conn_limit_pkts = 16, -- max pkts in one conn(tuple), 0 means no limit\
\
    -- filter policy\
    policy_max_cnt = 16,\
    policy_cnt = 0,\
    policy_id = 1,  \
    policies = {           -- use name as key\
        -- name, used by server\
        -- id, used by kernel\
        -- ipa, ip/mask\
        -- ipb, ip/mask\
        -- porta, port\
        -- portb, port\
        -- proto, \
        -- mac,\
        -- limit_total, max total pkts\
        -- limit_bytes, max bytes \
        -- duration, seconds\
        -- disable\
\
        -- stats\
            -- pkts = 0, \
            -- bytes = 0, \
            -- b64len = 0, \
    },\
    policy_duration_timer_name = \"rawpkt_policy_duration\",\
\
    pfmt = \"=IIIIc6BBc4c4c4c4HHHHHHII\", \
}\
\
local function getid()\
    pid = rawpkt.policy_id\
    rawpkt.policy_id = pid + 1\
    return pid\
end\
\
local function getname_stats_from_id(id, policies)\
    for name, policy in pairs(policies) do\
        if policy.id == id then\
            return name, policy.stats\
        end\
    end\
    return \"unknown\", nil\
end\
\
local function rawpkt_update_stat(stat, pkts, bytes, b64len)\
    stat.pkts = stat.pkts + pkts\
    stat.bytes = stat.bytes + bytes\
    stat.b64len = stat.b64len + b64len\
end\
\
local function rawpkt_get_one(sbytes, pos, len)\
\9local rawpkt_info = {} stats = nil\
\
    local all_len, pkt_len, id, time, utime, user_mac, no_l2, dir, next_pos = string.unpack('=HHIIIc6BB', sbytes, pos)\
    local pkt_data = string.unpack(string.format(\"c%d\", pkt_len), sbytes, next_pos)\
\
    assert(pos + all_len - 1 <= len)\
\
    rawpkt_info.pkt_len = pkt_len\
    rawpkt_info.time = tostring(time)\
    rawpkt_info.umac = mystring.data2hex(user_mac)\
    rawpkt_info.nol2 = false\
    if no_l2 ~= 0 then\
        rawpkt_info.nol2 = true\
    end\
    rawpkt_info.name, stats = getname_stats_from_id(id, rawpkt.policies)\
    rawpkt_info.data = mime.b64(pkt_data)\
    rawpkt_info.type = \"rawpkt\"\
\
    log.info(\"will send rawpkt to oper, \", cjson.encode(rawpkt_info), \", len\", rawpkt_info.data:len())\
    lcmd_run{subtype = \"__oper_data\", action = \"add\", data = rawpkt_info}\
\
    if stats then\
        rawpkt_update_stat(stats, 1, pkt_data:len(), rawpkt_info.data:len())\
    end\
\
    return all_len\
end\
\
local function rawpkt_get(sbytes)\
    local len = sbytes:len() used_len = 0\
\
    while used_len < len do\
        one_size = rawpkt_get_one(sbytes, used_len + 1, len)\
        used_len = used_len + one_size\
    end\
\
    assert(used_len == len)\
\
    return len\
end\
\
local function policy_duration_check()\
    local uptime = ctime.get_uptime()\
\
    for name, policy in pairs(rawpkt.policies) do\
        if policy.duration > 0 then\
            if uptime >= policy.duration_end then\
                kernel.send(CENUM.MEMSHR_RAWPKT_DISABLE, string.pack(\"=I\", policy.id))\
            end\
        end\
    end\
end\
\
local function write(msg)\
    log.info(\"rawpkt period change to\", msg.period, \"from \", rawpkt.period)\
    if type(msg.period) == \"number\" and msg.period ~= rawpkt.period then\
        rawpkt.period = msg.period\
        timer.mod(rawpkt.timer_name, rawpkt.period, 0, function () kernel.call(CENUM.MEMSHR_K2U_RAWPKT, \"\", rawpkt_get) end)\
        if rawpkt.period > 0 then\
            kernel.set_engine(CENUM.ENGINE_TYPE_RAWPKT, 1)\
            timer.mod(rawpkt.policy_duration_timer_name, 60, 0, policy_duration_check)\
        else\
            kernel.set_engine(CENUM.ENGINE_TYPE_RAWPKT, 0)\
            timer.mod(rawpkt.policy_duration_timer_name, 0, 0, policy_duration_check)\
            kernel.call(CENUM.MEMSHR_K2U_RAWPKT, \"\", rawpkt_get) -- when set period 0, need get kernel saved pkts once\
        end\
    end\
    if type(msg.policy_max_cnt) == \"number\" and msg.policy_max_cnt ~= rawpkt.policy_max_cnt then\
        rawpkt.policy_max_cnt = msg.policy_max_cnt\
    end\
    if type(msg.conn_limit_pkts) == \"number\" and msg.conn_limit_pkts ~= rawpkt.conn_limit_pkts then\
        rawpkt.conn_limit_pkts = msg.conn_limit_pkts\
        kernel.send(CENUM.MEMSHR_RAWPKT_CONN_LIMIT_PKTS_SET, string.pack(\"=I\", rawpkt.conn_limit_pkts))\
    end\
    if type(msg.cap_all) == \"number\" and msg.cap_all ~= rawpkt.cap_all then\
        rawpkt.cap_all = msg.cap_all\
        kernel.send(CENUM.MEMSHR_RAWPKT_CAP_ALL_SET, string.pack(\"=I\", rawpkt.cap_all))\
    end\
end\
\
local function rawpkt_stat()\
    return {policy_cnt=rawpkt.policy_cnt, policies=rawpkt.policies}\
end\
\
local function rawpkt_kernel_send(ktype, policy)\
    local id = 0 dir = 2 lmit_total = 0 limitbytes = 0\
    local mac = \"\\x00\\x00\\x00\\x00\\x00\\x00\" care_mac = 0 disable = 0\
    local ipa = \"\\x00\\x00\\x00\\x00\" ipb = \"\\x00\\x00\\x00\\x00\" ipa_mask = \"\\x00\\x00\\x00\\x00\" ipb_mask = \"\\x00\\x00\\x00\\x00\"\
    local ipa_maskbit = 0 ipb_maskbit = 0 porta = 0 porta_mask = 0 portb = 0 portb_mask = 0 proto = 0\
\
    id = policy.id\
    if policy.dir == \"out\" then\
        dir = 0\
    elseif policy.dir == \"in\" then\
        dir = 1\
    else\
        dir = 2\
    end\
\
    limit_total = policy.limit_total\
    limit_bytes = policy.limit_bytes\
    if policy.mac ~= \"\" then\
        care_mac = 1\
        mac = mystring.hex2data(policy.mac)\
    end\
    if policy.disable then\
        disable = 1\
    else\
        disable = 0\
    end\
\
    if policy.ipa ~= \"\" then\
        local status\
        status, ipa, ipa_maskbit = myip.ipmask(policy.ipa, true)\
        ipa_mask = myip.mask_bton(ipa_maskbit)\
    end\
\
    if policy.ipb ~= \"\" then\
        local status\
        status, ipb, ipb_maskbit = myip.ipmask(policy.ipb, true)\
        ipb_mask = myip.mask_bton(ipb_maskbit)\
    end\
\
    if policy.porta ~= \"\" then\
        porta = tonumber(policy.porta)\
        porta_mask = 0xffff\
    end\
\
    if policy.portb ~= \"\" then\
        portb = tonumber(policy.portb)\
        portb_mask = 0xffff\
    end\
\
    if policy.proto == \"tcp\" then\
        proto = 6\
    elseif policy.proto == \"udp\" then\
        proto = 17\
    else\
        proto = 0\
    end\
\
    buf = string.pack(rawpkt.pfmt, id, dir, limit_total, limit_bytes, mac, care_mac, disable,\
                      ipa, ipa_mask, ipb, ipb_mask, porta, porta_mask, portb, portb_mask, proto, 0, 0, 0)\
    kernel.send(ktype, buf)\
end\
\
local function rawpkt_del(msg)\
    if type(msg.name) ~= \"string\" or msg.name == \"\" then\
        log.warn(\"Must set name for del\")\
        return\
    end\
    \
    if rawpkt.policies[msg.name] then\
        id = rawpkt.policies[msg.name]['id']\
        if id and type(id) == \"number\" then\
            policy = {\
                id = id,\
                ipa = \"\",\
                ipb = \"\",\
                porta = \"\",\
                portb = \"\",\
                proto = \"\",\
                mac = \"\",\
                limit_total = 0,\
                limit_bytes = 0,\
                dir = \"\", \
                disable = false, \
            }\
            rawpkt_kernel_send(CENUM.MEMSHR_RAWPKT_DEL, policy)\
            rawpkt.policies[msg.name] = nil\
            rawpkt.policy_cnt = rawpkt.policy_cnt - 1\
        end\
    else\
        log.warn(\"No such name to delete\")\
    end\
end\
\
local function rawpkt_add(msg)\
    if type(msg.name) ~= \"string\" or msg.name == \"\" then\
        log.warn(\"Must set name for add\")\
        return\
    end\
    \
    rawpkt_del(msg)\
\
    if rawpkt.policy_cnt >= rawpkt.policy_max_cnt then\
        return {err = \"Can not exceed the limit count \"..tostring(rawpkt.policy_max_cnt)}\
    end\
\
    policy = {\
        id = getid(),\
        ipa = \"\",\
        ipb = \"\",\
        porta = \"\",\
        portb = \"\",\
        proto = \"\",\
        mac = \"\",\
        dir = \"\", \
        limit_total = 1024,\
        limit_bytes = 1024000,\
        duration = 0,\
        disable = false,\
\
        stats = {\
            pkts = 0,\
            bytes = 0,\
            b64len = 0, \
        }, \
    }\
\
    for k, v in pairs(msg) do\
        if k == \"ipa\" then\
            policy.ipa = tostring(v)\
        end\
        if k == \"ipb\" then\
            policy.ipb = tostring(v)\
        end\
        if k == \"porta\" then\
            policy.porta = tostring(v)\
        end\
        if k == \"portb\" then\
            policy.portb = tostring(v)\
        end\
        if k == \"proto\" then\
            policy.proto = tostring(v)\
        end\
        if k == \"mac\" then\
            policy.mac = tostring(v)\
        end\
        if k == \"dir\" then\
            policy.dir = tostring(v)\
        end\
\
        if k == \"limit_total\" then\
            policy.limit_total = v\
        end\
        if k == \"limit_bytes\" then\
            policy.limit_bytes = v\
        end\
        if k == \"duration\" then\
            policy.duration = tonumber(v)\
            if policy.duration > 0 then\
                local uptime = ctime.get_uptime()\
                policy.duration_begin = uptime\
                policy.duration_end = uptime + policy.duration\
            end\
        end\
\
        if k == \"disable\" then\
            if v then \
                policy.disable = true\
            else\
                policy.disable = false\
            end\
        end\
    end\
    rawpkt_kernel_send(CENUM.MEMSHR_RAWPKT_ADD, policy)\
    rawpkt.policies[msg.name] = policy\
    rawpkt.policy_cnt = rawpkt.policy_cnt + 1\
end\
\
local function kernel_read(sbytes)\
    local id = 0 dir = 2 lmit_total = 0 limitbytes = 0\
    local mac = \"\\x00\\x00\\x00\\x00\\x00\\x00\" care_mac = 0 disable = 0\
    local ipa = 0 ipa_mask = 0 ipb = 0 ipb_mask = 0 porta = 0 porta_mask = 0 portb = 0 portb_mask = 0 proto = 0\
    local total_bytes = 0 total_pkts = 0\
\
    local len = sbytes:len() used_len = 0 pos = 1 next_pos = 1\
\
    while pos < len do\
        id, dir, limit_total, limit_bytes, mac, care_mac, disable,\
        ipa, ipa_mask, ipb, ipb_mask, porta, porta_mask, portb, portb_mask, proto,\
        _, total_bytes, total_pkts, next_pos = string.unpack(rawpkt.pfmt, sbytes, pos)\
        table.insert(rawpkt.kps, {\
                         id = id,\
                         dir = dir,\
                         mac = mystring.data2hex(mac),\
                         care_mac = care_mac,\
                         disable = disable,\
                         ipa = myip.inet_ntoa(ipa),\
                         ipa_mask = myip.inet_ntoa(ipa_mask),\
                         ipb = myip.inet_ntoa(ipb),\
                         ipb_mask = myip.inet_ntoa(ipb_mask),\
                         porta = porta,\
                         porta_mask = porta_mask,\
                         portb = portb,\
                         portb_mask = portb_mask,\
                         proto = proto,\
                         limit_bytes = limit_bytes,\
                         limit_total = limit_total,\
                         \
                         total_bytes = total_bytes, \
                         total_pkts = total_pkts, \
        })\
\
        pos = next_pos\
    end\
\
    return pos - 1\
end\
\
local function kernel_get_conn_limit_pkts(sbytes)\
    local cnt = -1\
    local len = sbytes:len()\
    if len >= 4 then\
        cnt = string.unpack(\"=I\", sbytes)\
    end\
    rawpkt.kernel_conn_limit_pkts = cnt\
    return len\
end\
\
local function kernel_get_cap_all(sbytes)\
    local v = -1\
    local len = sbytes:len()\
    if len >= 4 then\
        v = string.unpack(\"=I\", sbytes)\
    end\
    rawpkt.kernel_cap_all = v\
    return len\
end\
\
actor.action_set(rawpkt.subtype, \"get_kernel\", function () kernel.call(CENUM.MEMSHR_K2U_RAWPKT, \"\", rawpkt_get) end, \
                 \"get pkt upload from kernel manualy\")\
actor.action_set(rawpkt.subtype, \"read\", function () return {period = rawpkt.period, policy_max_cnt = rawpkt.policy_max_cnt, conn_limit_pkts = rawpkt.conn_limit_pkts, cap_all = rawpkt.cap_all } end, \"read rawpkt period\")\
\
actor.action_set(rawpkt.subtype, \"kernel_read\",\
                 function ()\
                     rawpkt.kps = {}\
                     kernel.call(CENUM.MEMSHR_RAWPKT_READ, \"\", kernel_read)\
                     kernel.call(CENUM.MEMSHR_RAWPKT_CONN_LIMIT_PKTS_GET, \"\", kernel_get_conn_limit_pkts)\
                     kernel.call(CENUM.MEMSHR_RAWPKT_CAP_ALL_GET, \"\", kernel_get_cap_all)\
                     return {policies=rawpkt.kps, conn_limit_pkts=rawpkt.kernel_conn_limit_pkts, cap_all=rawpkt.kernel_cap_all}\
                 end,\
                 \"read rawpkt kernel policy\")\
\
actor.action_set(rawpkt.subtype, \"write\", write, \"set rawpkt period, {period = number}, 0 means close engine\")\
actor.action_set(rawpkt.subtype, \"stat\", rawpkt_stat, \"read rawpkt policy stat\")\
actor.action_set(rawpkt.subtype, \"add\", rawpkt_add, [[\
add rawpkt policy, {\
\"name\":,  key MUST set\
\"ipa\",\"ipb\", optional, using ipaddr/mask\
\"porta\", \"portb\",  optional, using port\
\"proto\",  optional, tcp, udp, default is ignore\
\"mac\",    optional,\
\"dir\",    optional, out, in, default is ignore\
\"limit_total\",  optional, max total pkts to upload for this policy, default is 1024\
\"limit_bytes\",  optional, max total bytes to upload for this policy, default is 1024000\
\"duration\", optional, valid time for this policy, unit is seconds, default is 0 (means no limit)\
\"disable\",  optional, default is false\
}\
]])\
\
actor.action_set(rawpkt.subtype, \"del\", rawpkt_del, [[del one rawpkt policy, {\"name\":}]])\
actor.action_set(rawpkt.subtype, \"flush\", \
                function() \
                    kernel.send(CENUM.MEMSHR_RAWPKT_FLUSH, \"\")\
                    rawpkt.kps = {} -- must reset\
                    rawpkt.policies = {}\
                    rawpkt.policy_cnt = 0\
                end, \
                \"flush all rawpkt policy\")\
\
return rawpkt\
"
, '@'.."./service/rawpkt.lua" ) )

package.preload[ "sec_camera" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local cjson = require(\"cjson\")\
local log = require(\"log\")\
\
local sec_camera = {\
    type = \"sec_camera\",\
    subtype = \"sec_camera\",\
    help = \"set sec_camera conf\",\
    enable = false,\
    oper_tname = \"\",\
    addr = \"mk-collect.189smarthome.com:7890\",\
    period = 120,\
    lanstats_period = 120,\
    longconn = false,\
}\
\
local function write(t)\
    local timer_need_update = false\
    if type(t.period) == \"number\" and t.period ~= sec_camera.period then\
        timer_need_update = true\
        sec_camera.period = t.period\
    end\
    if type(t.addr) == \"string\" and t.addr ~= sec_camera.addr then\
        timer_need_update = true\
        sec_camera.addr = t.addr\
    end\
    if type(t.lanstats_period) == \"number\" and t.lanstats_period ~= sec_camera.lanstats_period then\
        timer_need_update = true\
        sec_camera.lanstats_period = t.lanstats_period\
    end\
    if type(t.enable) == \"boolean\" and t.enable ~= sec_camera.enable then\
        timer_need_update = true\
        sec_camera.enable = t.enable\
    end\
    if type(t.longconn) == \"boolean\" and t.longconn ~= sec_camera.longconn then\
        timer_need_update = true\
        sec_camera.longconn = t.longconn\
    end\
    if timer_need_update then\
        if sec_camera.enable then\
            lcmd_run({subtype = \"lanhost_stats\", action = \"lanhoststats_set_upload_mode\", upload_mode = \"all\"})\
            lcmd_run({subtype = \"lanhost_stats\", action = \"lanhoststats_set_period\",period = sec_camera.lanstats_period})\
            lcmd_run({subtype = \"tuple\", action = \"write\", upload_mode = \"operdata\"})\
            lcmd_run({subtype = \"__oper_data\", action = \"rule_del\", tname = sec_camera.oper_tname})\
            _,sec_camera.oper_tname = lcmd_run({subtype = \"__oper_data\", action = \"rule_add\", addr = sec_camera.addr, uselconn = sec_camera.longconn, period = sec_camera.period, filter = {\"tuple_info_v1\", \"lan_stats\"}})\
        else\
            lcmd_run({subtype = \"lanhost_stats\", action = \"lanhoststats_set_upload_mode\", upload_mode = \"svrdata\"})\
            lcmd_run({subtype = \"lanhost_stats\", action = \"lanhoststats_set_period\",period = 600})\
            lcmd_run({subtype = \"tuple\", action = \"write\", upload_mode = \"none\"})\
            lcmd_run({subtype = \"__oper_data\", action = \"rule_del\", tname = sec_camera.oper_tname})\
        end\
    end\
end\
\
actor.action_set(sec_camera.subtype, \"read\", function () return {enable = sec_camera.enable, period = sec_camera.period, addr = sec_camera.addr, lanstats_period = sec_camera.lanstats_period, longconn = sec_camera.longconn} end, \"read sec_camera conf\")\
actor.action_set(sec_camera.subtype, \"write\", write, [[set sec_camera period and send conf, {period = number}, 0 means close engine]])\
return sec_camera\
"
, '@'.."./service/sec_camera.lua" ) )

package.preload[ "sec_data" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local cjson = require\"cjson\"\
local timer = require\"timer\"\
local log = require\"log\"\
local myutil = require\"myutil\"\
local dpi = require\"svrcomm.dpi\"\
local myip = require\"myip\"\
local mystring = require\"mystring\"\
\
local sec_data = {\
    type = \"sec_data\",\
    subtype = \"sec_data\",\
    help = \"filter secdata and send to server\",\
    timer_name = \"secdata_send\",\
    send_period = 120,\
    enable = false,\
    svr_addr = \"xapp.189cube.com:7870\",\
    filter_mode = \"white_list\",  -- none/white_list\
    msg_max_cnt = 1000,\
    white_list = {\
        -- domain = true,\
    },\
    stat = {\
        domain_cnt  = 0,\
        filter_cnt  = 0,\
        up_succ_cnt = 0,\
        up_succ_len = 0,\
        up_fail_cnt = 0,\
        up_fail_len = 0,\
    },\
    msgarray = {},\
    domain_range_min = 0,\
    domain_range_max = 0,\
}\
\
local function set_stat(err, data, status)\
    local stat = sec_data.stat\
    if status == \"filter\" then\
        stat.filter_cnt = stat.filter_cnt + 1\
    elseif status == \"ok\" then\
        stat.domain_cnt = stat.domain_cnt + 1\
    elseif err then\
        stat.up_fail_cnt = stat.up_fail_cnt + 1\
        stat.up_fail_len = stat.up_fail_len + #data\
    else\
        stat.up_succ_cnt = stat.up_succ_cnt + 1\
        stat.up_succ_len = stat.up_succ_len + #data\
    end\
end\
\
local function finicall(err, data)\
    set_stat(err, data, nil)\
end\
\
local function domain_slice(tbl, len, min, max)\
    local sliced = {}\
    local domain_str = {}\
\
    local exp = len - max + 1\
    if exp < 1 then\
        exp = 1\
    end\
\
    for i = len, exp, -1 do\
        local msg = tbl[i]\
        if msg then\
            table.insert(sliced, 1, msg)\
            if #sliced >= min and #sliced <= max then\
                table.insert(domain_str, table.concat(sliced, \".\"))\
            end\
        end\
    end\
\
    return domain_str\
end\
\
local function secdata_send()\
    local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
\
    for _,v in pairs(sec_data.msgarray) do\
        local osinfo = oss[v.mac] or {}\
        local desc = osinfo.desc or {}\
        v.dev_type, v.model, v.brand, v.os = desc.dev_type or \"\", desc.model or \"\", desc.brand or \"\", desc.os or \"\"\
    end\
    if #sec_data.msgarray > 0 and sec_data.enable then\
        local msg = cjson.encode(sec_data.msgarray)\
        log.info(string.format(\"secdata send msgcnt(%d) msg(%s)\", string.len(msg), msg))\
        dpi.async_call(sec_data.svr_addr, CENUM.COMM_ACTION_DEVOPS_DPI_DATA, msg, finicall)\
    end\
    sec_data.msgarray = {}\
end\
\
local function check_domain(module, domain, appid)\
    if sec_data.filter_mode == \"white_list\" then\
        if appid == 0 and module ~= \"dns\" then\
            local _, ruleid = lcmd_run({action = \"match\", subtype = \"appsig_bin\", stype = \"domain\", value = domain})\
            local _, desc = lcmd_run({action = \"get_desc\", subtype = \"appsig_bin\", ruleid = ruleid})\
            appid = desc.appid or 0\
        end\
        if appid > 0 then\
            set_stat(nil, \"\", \"filter\")\
            return false\
        end\
    end\
    set_stat(nil, \"\", \"ok\")\
    return true\
end\
\
local function msgarray_add(info)\
    if #sec_data.msgarray >= sec_data.msg_max_cnt then\
        secdata_send()\
        timer.mod(sec_data.timer_name, sec_data.send_period, 0, secdata_send)\
    end\
    table.insert(sec_data.msgarray, info)\
end\
\
local function dns_filter(msg)\
    local dnsdata = msg.dnstable\
    if not sec_data.enable or type(dnsdata) ~= \"table\" then\
        return\
    end\
    if not check_domain(\"dns\", dnsdata.domain, dnsdata.appid) then\
        return\
    end\
    local info = {\
        type = \"sec_dns\",\
        time = dnsdata.timestamp,\
        sip = dnsdata.server_ip,\
        dip = dnsdata.user_ip,\
        sport = dnsdata.sport,\
        dport = dnsdata.dport,\
        proto = \"udp\",\
        domain = dnsdata.domain,\
        ips = msg.ips or \"\",\
        dnstype = \"A\",\
        mac = dnsdata.mac\
    }\
    msgarray_add(info)\
end\
\
local function http_filter(msg)\
    local htttables = msg.http_tables\
    if not sec_data.enable or type(htttables) ~= \"table\" then\
        return\
    end\
    for _, httpdata in pairs(htttables) do\
        local domain, url = myutil.urlsplit(httpdata[\"url\"])\
        if not check_domain(\"http\", domain, httpdata.appid) then\
            goto continue\
        end\
        local proto = \"tcp\"\
        if httpdata.proto == 17 then\
            proto = \"udp\"\
        end\
\
        local info = {\
            type = \"sec_http\",\
            time = tostring(httpdata.ts_sec),\
            sip = myip.inet_ntoa(httpdata.ip),\
            dip = myip.inet_ntoa(httpdata.dstip),\
            sport = httpdata.sport,\
            dport = httpdata.dport,\
            proto = proto,\
            domain = domain,\
            url = url,\
            mac = myip.mac_ntoa(httpdata.mac),\
        }\
        msgarray_add(info)\
        ::continue::\
    end\
end\
\
local function write(t)\
    local timer_update = false\
    if type(t.enable) == \"boolean\" and t.enable ~= sec_data.enable then\
        sec_data.enable = t.enable\
        timer_update = true\
    end\
    if t.send_period and tonumber(t.send_period) ~= sec_data.send_period then\
        sec_data.send_period = tonumber(t.send_period)\
        timer_update = true\
    end\
    if timer_update and sec_data.enable then\
        timer.mod(sec_data.timer_name, sec_data.send_period, 0, secdata_send)\
    end\
    if type(t.svr_addr) == \"string\" then\
        sec_data.svr_addr = t.svr_addr\
    end\
    if type(t.filter_mode) == \"string\" and (t.filter_mode == \"white_list\" or t.filter_mode == \"none\") then\
        sec_data.filter_mode = t.filter_mode\
    end\
    if type(t.msg_max_cnt) == \"number\" then\
        sec_data.msg_max_cnt = t.msg_max_cnt\
    end\
end\
\
function sec_data.postinit()\
    sec_data.hindex = actor.subscribe(\"HTTP\", http_filter)\
    sec_data.dindex = actor.subscribe(\"DNS\", dns_filter)\
    if sec_data.enable then\
        timer.mod(sec_data.timer_name, sec_data.send_period, 0, secdata_send)\
    end\
end\
\
function sec_data.finish()\
    if sec_data.hindex then\
        actor.unsubscribe(\"HTTP\", sec_data.hindex)\
    end\
    if sec_data.dindex then\
        actor.unsubscribe(\"DNS\", sec_data.dindex)\
    end\
end\
\
actor.action_set(sec_data.subtype, \"read\", function () return {send_period = sec_data.send_period, enable = sec_data.enable, filter_mode = sec_data.filter_mode, svr_addr = sec_data.svr_addr} end, \"read sec_data conf\")\
actor.action_set(sec_data.subtype, \"stat\", function () return sec_data.stat end, \"read stat\")\
actor.action_set(sec_data.subtype, \"write\", write, [[set sec_data period and send conf {send_period = number, enable = boolean, filter_mode = string, svr_addr = string}, 0 means close engine]])\
\
return sec_data\
"
, '@'.."./service/sec_data.lua" ) )

package.preload[ "shell" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
\
local shell = {\
    type = \"shell\", \
    subtype = \"shell\", \
    help = \"run shell cmd and return result\", \
}\
\
local function shell_run(t)\
    local cmd = \"\"\
    if type(t.args) == \"table\" and #t.args > 0 then\
        for _, v in ipairs(t.args) do\
            cmd = cmd .. \" \" .. v\
        end\
    elseif type(t.args) == \"string\" then\
        cmd = t.args\
    else\
        return nil\
    end\
\
    if t.action == \"read\" then\
        local p = io.popen(cmd, \"r\")\
        local result = p:read(\"a\")\
        p:close()\
        return result\
    else\
        os.execute(cmd)\
    end\
    return nil\
end\
\
actor.action_set(shell.subtype, \"write\", shell_run, 'run shell with no result, input is {args = {\"x1\", \"x2\", ...}}')\
actor.action_set(shell.subtype, \"read\", shell_run, 'run shell with result return, input is {args = {\"x1\", \"x2\", ...}}')\
\
return shell\
"
, '@'.."./service/shell.lua" ) )

package.preload[ "sig" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local csig = require\"c.sig\"\
local log = require\"log\"\
\
local sig = {\
\9type = \"sig\",\
\9subtype = \"sig\",\
    ud = nil,                   -- userdata for sig\
\9help = \"sigature operations\"\
}\
\
local function sig_load(t)\
\9local x = csig.load()\
    if not x then\
        log.error(\"failed to load sig, will exit after 10 secs\")\
        local socket = require\"socket\"\
        socket.select(nil, nil, 10)\
        os.exit(128)\
    else\
        log.info(\"OK load sig\")\
        sig.ud = x\
    end\
end\
\
local os_string = {\
    [0] = \"other\", \
    [1] = \"android\", \
    [2] = \"ios\", \
    [3] = \"windows\", \
    [4] = \"linux\", \
}\
\
local dev_type_string = {\
    [0] = \"OTHER\", \
    [1] = \"phone\", \
    [2] = \"Pad\", \
    [4] = \"STB\", \
    [5] = \"ROUTER\", \
    [7] = \"PC\", \
    [8] = \"SMTDEV\", \
}\
\
-- /* LAN device type */\
-- typedef enum {\
--     CT_LAN_DEV_UNKNOWN,\
--     CT_LAN_DEV_PHONE,\
--     CT_LAN_DEV_PAD,\
--     CT_LAN_DEV_PC,\
--     CT_LAN_DEV_STB,\
--     CT_LAN_DEV_ROUTER,\
--     CT_LAN_DEV_SMTDEV,\
--     CT_LAN_DEV_AP,\
--     CT_LAN_DEV_PLC,\
--     CT_LAN_DEV_OTHER\
-- } CtLanDevType;\
local dev_type_osgi = {\
    [0] = 0, \
    [1] = 1, \
    [2] = 2, \
    [4] = 4, \
    [5] = 5, \
    [7] = 3, \
    [8] = 6, \
}\
\
local function read(t)\
    if not t.osid then\
        return nil\
    end\
\9local x = csig.dump_dev(sig.ud, t.osid)\
    if not x then\
        return nil\
    end\
\
\9local y = csig.dump_devgrp(sig.ud, x.group_id)\
    if not y then\
        return nil\
    end\
\
    local dtype_osgi = dev_type_osgi[x.dev_type] or dev_type_osgi[0]\
    local dtype_string = dev_type_string[x.dev_type] or dev_type_string[0]\
    local osname_string = os_string[x.os_type] or os_string[0]\
    return {id = t.osid, os_type = x.os_type, dev_type = x.dev_type, brand_name = y.name_cn, model_name = x.name_cn, \
            dev_type_string = dtype_string, os_string = osname_string, dev_type_osgi = dtype_osgi}\
end\
\
local function write(t)\
    csig.write_devgrp(sig.ud, t.groupid, t.brand)\
    csig.write_dev(sig.ud, t.osid, t.model, t.ostype, t.devtype, t.groupid)\
end\
\
local function sig_show()\
    return csig.dump(sig.ud)\
end\
\
actor.action_set(sig.subtype, \"load\",sig_load,\"sig init\")\
actor.action_set(sig.subtype, \"show\",sig_show,\"show version and count\")\
actor.action_set(sig.subtype, \"show_dev\",\
                 function(t) \
                     return csig.dump_dev(sig.ud, t.id, t.name, t.exact) \
                 end,\
                 \"{id = xx, name = xx, exact = true/false}, id first then name, exact only for name\")\
actor.action_set(sig.subtype, \"show_devgrp\",\
                 function(t) \
                     return csig.dump_devgrp(sig.ud, t.id, t.name, t.exact) \
                 end,\
                 \"{id = xx, name = xx, exact = true/false}, id first then name, exact only for name\")\
actor.action_set(sig.subtype, \"read\",read,\"input osid as int\")\
actor.action_set(sig.subtype, \"write\",write,\"input osid,ostype,devtype,groupid as int and model,brand as string\")\
actor.action_set(sig.subtype, \"read_string\", function(t) if t.ostype and t.devtype  then return {dev_type=dev_type_string[t.devtype] or dev_type_string[0], os = os_string[t.ostype] or os_string[0], devtypeint = dev_type_osgi[t.devtype] or dev_type_osgi[0]} end end,\"{ostype=number,devtype=number},type number to string\")\
\
return sig\
"
, '@'.."./service/sig.lua" ) )

package.preload[ "sigcollect" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local actor = require(\"luactor\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local mystring = require(\"mystring\")\
local myip = require(\"myip\")\
local myutil = require(\"myutil\")\
local cregex = require(\"c.regex\")\
local sigcollect = {\
   type = \"sigcollect\",\
   subtype = \"sigcollect\",\
   timer_name = \"collect_upload\", \
   help=\"get collect msg from osinfo/http and send to server\",\
   period = 0,\
   enable = true,\
   -- mdns/upnp\
   other_period = 86400,\
   newdev_period = 600,\
   brmacs_period = 600,\
   briface = \"br0\",\
   send_brshowerr = false,\
   other_name = \"collect_other\",\
   send_newdev_name = \"collect_newdev\",\
   brmacs_name = \"brmacs_name\",\
   coll_type = {\"term_ua\",\"term_uri\",\"hostname\",\"elink\",\"mdns\",\"upnp\",\"vendor\",\"dhcp_hostname\",\"imei\",\"mac\",\"devname\"},\
   all_count = 0,\
   all_len = 0,\
   max_count = 1000,\
   sindex = nil,\
   addr = {\"term.189cube.com:7870\"},\
   maconf = {key= {\"url\",\"cookie\"},rules = {\"mac%s?=%s?([%x][%x])[:-]?([%x][%x])[:-]?([%x][%x])[:-]?([%x][%x])[:-]?([%x][%x])[:-]?([%x][%x])\",\"mac%s?=%s?([%x][%x])[%%]3A([%x][%x])[%%]3A([%x][%x])[%%]3A([%x][%x])[%%]3A([%x][%x])[%%]3A([%x][%x])\"}},\
   conf = {ua = {{type = \"term_ua\",val = {\"[;(][ ]?(Windows[^);]+)\",\"[;(][ ]?([^);/]+) Build\",\"iPhone[1-9][0-9]?,[0-9][0-9]?\",\"iPad[1-9][0-9]?,[0-9][0-9]?\"},max = 128}},url = {{type = \"term_uri\",val = {\"model=([^?&$]+)\",\"stbType=([^?&$]+)\",\"ua_model=([^?&$]+)\",\"device_type=([^?&$]+)\"},max = 128}}},\
   backlist = \"^((windows[ ]((98)|(nt)))|(empty)|(unknown)|(anonymous)|(mi[ ]4w))$\"\
}\
\
local function sig_deal(addr, action, msg, ...)\
    if not msg or msg == \"\" then\
        log.info(string.format(\"ignore empty msg, action 0x%x\", action))\
        return\
    end\
    log.info(string.format(\"receive %s server, action 0x%x, msg(%s)\", addr, action, msg))\
\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        log.error(string.format(\"failed json decode msg(%s), err(%s)\", msg, t))\
        return\
    end\
    if type(t) ~= \"table\" then\
        log.info(string.format(\"ignore empty json or not table for msg(%s)\", msg))\
        return\
    end\
    lcmd_run(t)\
\
    local args = {...}\
    local coll_type = args[1] or {}\
    local macs = args[2] or {}\
\
    for _, mac in pairs(macs) do\
        for k,v in pairs(coll_type) do\
            if v then\
                lcmd_run({subtype = \"osinfo\", action = \"del_sig\", key = k, mac = mac})\
            end\
        end\
    end\
\
end\
\
local function sigcollect_send(data, coll_type, macs)\
    if sigcollect.enable == false then\
        return\
    end\
    if #data > 0 then\
        local addr = sigcollect.addr\
        if not addr or #addr == 0 then\
            addr = nil\
        end\
        lcmd_run({subtype = \"__svr_oper\", action = \"oper_raw\", action_type = CENUM.COMM_ACTION_DEVOPS_DPI_SIGCOLLECT_UPDATE, data = data, addr = addr ,recvcall = sig_deal, recvargs = {coll_type, macs}})\
        sigcollect.all_len = sigcollect.all_len + string.len(cjson.encode(data))\
        sigcollect.all_count = sigcollect.all_count + 1\
    end\
end\
\
local function get_termac(mac, info)\
    if type(info) ~= \"table\" or type(sigcollect.maconf) ~= \"table\" then\
        return nil\
    end\
\
    for _, v in pairs(sigcollect.maconf.key) do\
        if info[v] then\
            for _, rule in pairs(sigcollect.maconf.rules) do\
                local m1, m2, m3, m4, m5, m6 = string.match(info[v], rule)\
                if m1 and m2 and m3 and m4 and m5 and m6 then\
                    local value = string.format(\"%s%s%s%s%s%s\", m1, m2, m3, m4, m5, m6)\
                    local hmac = myip.mac_check(mac, value, true)\
                    if hmac then\
                        lcmd_run({subtype = \"osinfo\", action = \"add\", key = \"par_mac\", value = myip.mac_fmt(mac), mac = hmac, from = \"url_cookie\"})\
                        return hmac\
                    end\
                end\
            end\
        end\
    end\
    return nil\
end\
\
local function deal_one_filter(hmac, mac, info, sigconf)\
    if type(sigconf) ~= \"table\" then\
       return \
    end\
\
    for _,conf in pairs(sigconf) do\
        if type(conf) ~= \"table\" or type(conf.val) ~= \"table\" then\
            return\
        end\
        for k,v in pairs(conf.val) do\
            value = string.match(info, v)\
            local max = conf.max or #info + 1\
            if value and #value < max and #value >= 2 then\
                mac = myip.mac_fmt(mac)\
                lcmd_run({subtype = \"osinfo\", action = \"add_sig\", key = conf.type, value = value, mac = mac, from = \"http\"})\
                if hmac then\
                    lcmd_run({subtype = \"osinfo\", action = \"add_sig\", key = conf.type, value = value, mac = hmac, from = \"url_cookie\"})\
                end\
            end\
        end\
    end\
end\
\
local function collect_http(msg)\
    for k,v in pairs(msg.http_tables) do\
        local mac = mystring.data2hex(v.mac, nil)\
        if not myip.mac_check(\"\", mac) then\
            log.info(\"invalid http mac\", mac)\
            goto continue\
        end\
        local hmac = get_termac(mac, v)\
        for sigtype, sigconf in pairs(sigcollect.conf) do\
            if v[sigtype] then\
                deal_one_filter(hmac, mac, v[sigtype], sigconf)\
            end\
        end\
        ::continue::\
    end\
end\
\
local function filter_blacklist(value)\
    if string.len(value) < 3 then\
        return false\
    end\
\
    if cregex.match(value:lower(),sigcollect.backlist) then\
        return false\
    end\
\
    return true\
end\
\
local function mergeinfo(oss, types, maxcnt)\
    local mm, macs = {}, {}\
    local count = 0\
    for mac, info in pairs(oss) do\
        if info.macfrom ~= \"lanhost\" and info.firsttime == info.lasttime then\
            goto continue\
        end\
        local tt ={mac = mac, macfrom = info.macfrom or {}, osid = info.decide_osid or info.cloud_osid or 0, iscloud = info.iscloud or 0, acc_type = info.acc_type or -1, acc_port = info.acc_port or -1, elink_type = info.cloud_elinktype or -1, sigs = {}}\
        for k,v in pairs(types) do\
            local sigs = info.sigs or {}\
            local value\
            if sigs[k] and v then\
                value = sigs[k]\
            elseif info[k] and v then\
                value = info[k]\
            end\
            if type(value) == \"table\" and #value > 0 then\
                local data = {}\
                for _,vv in pairs (value) do\
                    if filter_blacklist(vv) then\
                        table.insert(data,vv)\
                    end\
                end\
                if #data > 0 then\
                    table.insert(tt.sigs, {type = k, data = data})\
                    count = count + #data\
                end\
            elseif type(value) == \"string\" then\
                if filter_blacklist(value) then\
                    table.insert(tt.sigs, {type = k, data = {value}})\
                    count = count + 1\
                end\
            end\
        end\
\
        if #tt.sigs == 0 then\
            goto continue\
        end\
\
        --check collect count\
        if count >= maxcnt then\
            break\
        end\
\
        table.insert(mm, tt)\
        table.insert(macs, mac)\
        ::continue::\
    end\
    return mm, macs\
end\
\
local function sigcollect_upload(t)\
    -- hot_patch\
    local ok, data = lcmd_run({subtype = \"hot_sigcollect\", action = \"sigcollect_get\", coll_type = sigcollect.coll_type})\
    if ok and type(data) == \"table\" then\
        sigcollect_send(data.data, data.coll_type, data.macs)\
        return\
    end\
\
    local mm, macs, coll_type = {}, {}, {}\
    local ok, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
    for k,v in pairs(sigcollect.coll_type) do\
        coll_type[v] = true\
    end\
\
    if ok then\
        mm, macs = mergeinfo(oss, coll_type, sigcollect.max_count)\
    end\
\
    sigcollect_send(mm, coll_type, macs)\
\
    return\
end\
\
local function sigcollect_other()\
    local _, mdns = lcmd_run({subtype = \"mdns\", action = \"get_mdns\"})\
    local _, upnp = lcmd_run({subtype = \"upnp\", action = \"get_upnp\"})\
    if type(mdns) == \"table\" then\
        for k,v in pairs(mdns) do\
            lcmd_run({subtype = \"osinfo\", action = \"add_sig\", table=true, key = \"mdns\", value = v, mac = k, from = \"mdns\"})\
        end\
    end\
    if type(upnp) == \"table\" then\
        for k,v in pairs(upnp) do\
            lcmd_run({subtype = \"osinfo\", action = \"add_sig\", table=true, key = \"upnp\", value = v, mac = k, from = \"upnp\"})\
        end\
    end\
end\
\
local function sigcollect_new_dev()\
    local _, oss = lcmd_run({subtype = \"osinfo\", action = \"get_oss\"})\
    local coll_type = {}\
    for k,v in pairs(sigcollect.coll_type) do\
        coll_type[v] = true\
    end\
    if type(oss) == \"table\" then\
        local tt = {}\
        local time = os.time() or 0\
        for k,v in pairs(oss) do\
            local firsttime = v.firsttime or 0\
            if not v.cloud_osid and v.active ~= 0 and firsttime < time and firsttime >= time - sigcollect.newdev_period then\
                tt[k] = v\
            end\
        end\
        local mm, macs = mergeinfo(tt, coll_type, sigcollect.max_count)\
        sigcollect_send(mm, coll_type, macs)\
    end\
end\
\
local function send_gwinfo()\
    local _, devinfo = lcmd_run({type = \"capi\", action = \"get_devinfo\"})\
    if type(devinfo) ~= \"table\" then\
        devinfo = {}\
    end\
\
    local info = {\
        type = \"showmacs_error\",\
        dmfr = devinfo.Manufacturer or \"\",\
        dswver = devinfo.SWVersion or \"\",\
        dhwver = devinfo.HDVersion or \"\",\
        dmod = devinfo.ProductClass or \"\",\
        cpuclass = devinfo.CPUClass or \"\",\
        devtype = devinfo.DevType or \"\",\
    }\
    log.info(\"send brctl showmacs error, \", cjson.encode(info))\
    lcmd_run{subtype = \"__oper_data\", action = \"add\", data = info}\
end\
\
local function brctl_showmacs(t)\
    local res = myutil.cmdprintable(\"brctl showmacs \"..(t.iface or sigcollect.briface))\
    -- head {[\"port no\"] = 1, [\"mac addr\"] = 2, [\"is local?\"] = 3, [\"ageing time\"] = 4}\
    local head = {[\"port no\"] = 0, [\"mac addr\"] = 0, [\"is local?\"] = 0, [\"ageing timer\"] = 0}\
    local all = {}\
    if not res[1] then\
        return nil\
    else\
        for k,v in pairs(res[1]) do\
            if head[v] then\
                head[v] = k\
            end\
        end\
    end\
    -- must have port,no mac,addr is local?,ageing timer\
    if head[\"port no\"] == 0 or head[\"mac addr\"] == 0 or head[\"is local?\"] == 0 or head[\"ageing timer\"] == 0 then\
        return nil\
    end\
    for k,v in pairs(res) do\
        local islocal =  v[head[\"is local?\"]]\
        local mac = myip.mac_fmt(v[head[\"mac addr\"]])\
        mac = myip.mac_check(\"\", mac)\
        if k ~= 1 and #v >= 4 and string.match(islocal, \"no\") and mac then\
            table.insert(all, {port = v[head[\"port no\"]], mac = mac, islocal = islocal, ageingtime = v[head[\"ageing timer\"]]})\
        end\
    end\
    return all\
end\
\
local function sigcollect_brmacs(msg)\
    local res = brctl_showmacs({})\
    if not res then\
        if not sigcollect.send_brshowerr  then\
            send_gwinfo()\
            sigcollect.send_brshowerr = true\
            lcmd_run{type = \"sys\", action = \"save_conf_change\"}\
        end\
        timer.del(sigcollect.brmacs_name)\
        return\
    end\
    for k,v in pairs(res) do\
        lcmd_run({subtype = \"osinfo\", action = \"add\", key = \"mac\", value = v.mac, mac = v.mac, from = \"brctl\"})\
    end\
end\
\
local function write(t)\
    if t.period and tonumber(t.period) ~= sigcollect.period then\
        sigcollect.period = tonumber(t.period)\
        timer.mod(sigcollect.timer_name, sigcollect.period, 0, sigcollect_upload)\
    end\
\
    if t.coll_type and type(t.coll_type) == \"table\" then\
        sigcollect.coll_type = t.coll_type\
    end\
\
    if t.max_count and t.max_count ~= sigcollect.max_count then\
        sigcollect.max_count = t.max_count\
    end\
\
    if t.conf and type(t.conf) == \"table\" then\
        sigcollect.conf = t.conf\
    end\
\
    if t.maconf and type(t.maconf) == \"table\" then\
        sigcollect.maconf = t.maconf\
    end\
\
    if t.other_period and tonumber(t.other_period) ~= sigcollect.other_period then\
        sigcollect.other_period = tonumber(t.other_period)\
        timer.mod(sigcollect.other_name, sigcollect.other_period, 0, sigcollect_other)\
    end\
\
    if t.newdev_period and tonumber(t.newdev_period) ~= sigcollect.newdev_period then\
        sigcollect.newdev_period = tonumber(t.newdev_period)\
        timer.mod(sigcollect.send_newdev_name, sigcollect.newdev_period, 0, sigcollect_new_dev)\
    end\
\
    if t.addr and type(t.addr) == \"table\" then\
        sigcollect.addr = t.addr\
    end\
\
    if type(t.briface) == \"string\" then\
        sigcollect.briface = t.briface\
    end\
\
    if t.brmacs_period and tonumber(t.brmacs_period) ~= sigcollect.brmacs_period then\
        sigcollect.brmacs_period = tonumber(t.brmacs_period)\
        timer.mod(sigcollect.brmacs_name, sigcollect.brmacs_period, 0, sigcollect_brmacs)\
    end\
\
    if type(t.send_brshowerr) == \"boolean\" and t.send_brshowerr ~= sigcollect.send_brshowerr then\
        sigcollect.send_brshowerr = t.send_brshowerr\
    end\
\
    if type(t.enable) == \"boolean\" and t.enable ~= sigcollect.enable then\
        sigcollect.enable = t.enable\
    end\
end\
\
function collect_conf_save()\
    return { type = sigcollect.subtype, action = \"write\", send_brshowerr = sigcollect.send_brshowerr}\
end\
\
function sigcollect.postinit()\
    sigcollect.sindex = actor.subscribe(\"HTTP\", collect_http)\
    timer.mod(sigcollect.other_name, sigcollect.other_period, 0, sigcollect_other)\
    timer.mod(sigcollect.send_newdev_name, sigcollect.newdev_period, 0, sigcollect_new_dev)\
    timer.mod(sigcollect.brmacs_name, sigcollect.brmacs_period, 0, sigcollect_brmacs)\
end\
\
function sigcollect.finish()\
    if sigcollect.sindex then\
        actor.unsubscribe(\"HTTP\", sigcollect.sindex)\
    end\
end\
\
actor.action_set(sigcollect.subtype, \"read\", function () return {period = sigcollect.period, max_count = sigcollect.max_count, conf = sigcollect.conf, other_period = sigcollect.other_period, newdev_period = sigcollect.newdev_period, addr = sigcollect.addr, maconf = sigcollect.maconf, briface = sigcollect.briface, brmacs_period = sigcollect.brmacs_period, send_brshowerr = sigcollect.send_brshowerr, enable = sigcollect.enable} end, \"read period and other conf\")\
actor.action_set(sigcollect.subtype, \"stat\", function () return {all_count = sigcollect.all_count, all_len = sigcollect.all_len} end, \"read stat count\")\
actor.action_set(sigcollect.subtype, \"write\", write, 'set collect coll_type, coll_type default {\"term_ua\",\"term_uri\",\"hostname\",\"elink\",\"mdns\",\"upnp\"}')\
actor.action_set(sigcollect.subtype, \"send\", sigcollect_upload, \"send msg to server\")\
actor.action_set(sigcollect.subtype, \"brctl_showmacs\", brctl_showmacs, \"brctl showmacs, iface default br0 {iface = string}\")\
actor.action_set(sigcollect.subtype, \"show_conf_save\", collect_conf_save, \"save collect conf to local file\")\
\
return sigcollect\
"
, '@'.."./service/sigcollect.lua" ) )

package.preload[ "socket" ] = assert( (loadstring or load)(
"-----------------------------------------------------------------------------\
-- LuaSocket helper module\
-- Author: Diego Nehab\
-----------------------------------------------------------------------------\
\
-----------------------------------------------------------------------------\
-- Declare module and import dependencies\
-----------------------------------------------------------------------------\
local base = _G\
local string = require(\"string\")\
local math = require(\"math\")\
local socket = require(\"socket.core\")\
\
local _M = socket\
\
-----------------------------------------------------------------------------\
-- Exported auxiliar functions\
-----------------------------------------------------------------------------\
function _M.connect4(address, port, laddress, lport)\
    return socket.connect(address, port, laddress, lport, \"inet\")\
end\
\
function _M.connect6(address, port, laddress, lport)\
    return socket.connect(address, port, laddress, lport, \"inet6\")\
end\
\
function _M.bind(host, port, backlog)\
    if host == \"*\" then host = \"0.0.0.0\" end\
    local addrinfo, err = socket.dns.getaddrinfo(host);\
    if not addrinfo then return nil, err end\
    local sock, res\
    err = \"no info on address\"\
    for i, alt in base.ipairs(addrinfo) do\
        if alt.family == \"inet\" then\
            sock, err = socket.tcp4()\
        else\
            sock, err = socket.tcp6()\
        end\
        if not sock then return nil, err end\
        sock:setoption(\"reuseaddr\", true)\
        res, err = sock:bind(alt.addr, port)\
        if not res then\
            sock:close()\
        else\
            res, err = sock:listen(backlog)\
            if not res then\
                sock:close()\
            else\
                return sock\
            end\
        end\
    end\
    return nil, err\
end\
\
_M.try = _M.newtry()\
\
function _M.choose(table)\
    return function(name, opt1, opt2)\
        if base.type(name) ~= \"string\" then\
            name, opt1, opt2 = \"default\", name, opt1\
        end\
        local f = table[name or \"nil\"]\
        if not f then base.error(\"unknown key (\".. base.tostring(name) ..\")\", 3)\
        else return f(opt1, opt2) end\
    end\
end\
\
-----------------------------------------------------------------------------\
-- Socket sources and sinks, conforming to LTN12\
-----------------------------------------------------------------------------\
-- create namespaces inside LuaSocket namespace\
local sourcet, sinkt = {}, {}\
_M.sourcet = sourcet\
_M.sinkt = sinkt\
\
_M.BLOCKSIZE = 2048\
\
sinkt[\"close-when-done\"] = function(sock)\
    return base.setmetatable({\
        getfd = function() return sock:getfd() end,\
        dirty = function() return sock:dirty() end\
    }, {\
        __call = function(self, chunk, err)\
            if not chunk then\
                sock:close()\
                return 1\
            else return sock:send(chunk) end\
        end\
    })\
end\
\
sinkt[\"keep-open\"] = function(sock)\
    return base.setmetatable({\
        getfd = function() return sock:getfd() end,\
        dirty = function() return sock:dirty() end\
    }, {\
        __call = function(self, chunk, err)\
            if chunk then return sock:send(chunk)\
            else return 1 end\
        end\
    })\
end\
\
sinkt[\"default\"] = sinkt[\"keep-open\"]\
\
_M.sink = _M.choose(sinkt)\
\
sourcet[\"by-length\"] = function(sock, length)\
    return base.setmetatable({\
        getfd = function() return sock:getfd() end,\
        dirty = function() return sock:dirty() end\
    }, {\
        __call = function()\
            if length <= 0 then return nil end\
            local size = math.min(socket.BLOCKSIZE, length)\
            local chunk, err = sock:receive(size)\
            if err then return nil, err end\
            length = length - string.len(chunk)\
            return chunk\
        end\
    })\
end\
\
sourcet[\"until-closed\"] = function(sock)\
    local done\
    return base.setmetatable({\
        getfd = function() return sock:getfd() end,\
        dirty = function() return sock:dirty() end\
    }, {\
        __call = function()\
            if done then return nil end\
            local chunk, err, partial = sock:receive(socket.BLOCKSIZE)\
            if not err then return chunk\
            elseif err == \"closed\" then\
                sock:close()\
                done = 1\
                return partial\
            else return nil, err end\
        end\
    })\
end\
\
\
sourcet[\"default\"] = sourcet[\"until-closed\"]\
\
_M.source = _M.choose(sourcet)\
\
return _M\
"
, '@'.."./lualib/socket/socket.lua" ) )

package.preload[ "socket.headers" ] = assert( (loadstring or load)(
"-----------------------------------------------------------------------------\
-- Canonic header field capitalization\
-- LuaSocket toolkit.\
-- Author: Diego Nehab\
-----------------------------------------------------------------------------\
local socket = require(\"socket\")\
socket.headers = {}\
local _M = socket.headers\
\
_M.canonic = {\
    [\"accept\"] = \"Accept\",\
    [\"accept-charset\"] = \"Accept-Charset\",\
    [\"accept-encoding\"] = \"Accept-Encoding\",\
    [\"accept-language\"] = \"Accept-Language\",\
    [\"accept-ranges\"] = \"Accept-Ranges\",\
    [\"action\"] = \"Action\",\
    [\"alternate-recipient\"] = \"Alternate-Recipient\",\
    [\"age\"] = \"Age\",\
    [\"allow\"] = \"Allow\",\
    [\"arrival-date\"] = \"Arrival-Date\",\
    [\"authorization\"] = \"Authorization\",\
    [\"bcc\"] = \"Bcc\",\
    [\"cache-control\"] = \"Cache-Control\",\
    [\"cc\"] = \"Cc\",\
    [\"comments\"] = \"Comments\",\
    [\"connection\"] = \"Connection\",\
    [\"content-description\"] = \"Content-Description\",\
    [\"content-disposition\"] = \"Content-Disposition\",\
    [\"content-encoding\"] = \"Content-Encoding\",\
    [\"content-id\"] = \"Content-ID\",\
    [\"content-language\"] = \"Content-Language\",\
    [\"content-length\"] = \"Content-Length\",\
    [\"content-location\"] = \"Content-Location\",\
    [\"content-md5\"] = \"Content-MD5\",\
    [\"content-range\"] = \"Content-Range\",\
    [\"content-transfer-encoding\"] = \"Content-Transfer-Encoding\",\
    [\"content-type\"] = \"Content-Type\",\
    [\"cookie\"] = \"Cookie\",\
    [\"date\"] = \"Date\",\
    [\"diagnostic-code\"] = \"Diagnostic-Code\",\
    [\"dsn-gateway\"] = \"DSN-Gateway\",\
    [\"etag\"] = \"ETag\",\
    [\"expect\"] = \"Expect\",\
    [\"expires\"] = \"Expires\",\
    [\"final-log-id\"] = \"Final-Log-ID\",\
    [\"final-recipient\"] = \"Final-Recipient\",\
    [\"from\"] = \"From\",\
    [\"host\"] = \"Host\",\
    [\"if-match\"] = \"If-Match\",\
    [\"if-modified-since\"] = \"If-Modified-Since\",\
    [\"if-none-match\"] = \"If-None-Match\",\
    [\"if-range\"] = \"If-Range\",\
    [\"if-unmodified-since\"] = \"If-Unmodified-Since\",\
    [\"in-reply-to\"] = \"In-Reply-To\",\
    [\"keywords\"] = \"Keywords\",\
    [\"last-attempt-date\"] = \"Last-Attempt-Date\",\
    [\"last-modified\"] = \"Last-Modified\",\
    [\"location\"] = \"Location\",\
    [\"max-forwards\"] = \"Max-Forwards\",\
    [\"message-id\"] = \"Message-ID\",\
    [\"mime-version\"] = \"MIME-Version\",\
    [\"original-envelope-id\"] = \"Original-Envelope-ID\",\
    [\"original-recipient\"] = \"Original-Recipient\",\
    [\"pragma\"] = \"Pragma\",\
    [\"proxy-authenticate\"] = \"Proxy-Authenticate\",\
    [\"proxy-authorization\"] = \"Proxy-Authorization\",\
    [\"range\"] = \"Range\",\
    [\"received\"] = \"Received\",\
    [\"received-from-mta\"] = \"Received-From-MTA\",\
    [\"references\"] = \"References\",\
    [\"referer\"] = \"Referer\",\
    [\"remote-mta\"] = \"Remote-MTA\",\
    [\"reply-to\"] = \"Reply-To\",\
    [\"reporting-mta\"] = \"Reporting-MTA\",\
    [\"resent-bcc\"] = \"Resent-Bcc\",\
    [\"resent-cc\"] = \"Resent-Cc\",\
    [\"resent-date\"] = \"Resent-Date\",\
    [\"resent-from\"] = \"Resent-From\",\
    [\"resent-message-id\"] = \"Resent-Message-ID\",\
    [\"resent-reply-to\"] = \"Resent-Reply-To\",\
    [\"resent-sender\"] = \"Resent-Sender\",\
    [\"resent-to\"] = \"Resent-To\",\
    [\"retry-after\"] = \"Retry-After\",\
    [\"return-path\"] = \"Return-Path\",\
    [\"sender\"] = \"Sender\",\
    [\"server\"] = \"Server\",\
    [\"smtp-remote-recipient\"] = \"SMTP-Remote-Recipient\",\
    [\"status\"] = \"Status\",\
    [\"subject\"] = \"Subject\",\
    [\"te\"] = \"TE\",\
    [\"to\"] = \"To\",\
    [\"trailer\"] = \"Trailer\",\
    [\"transfer-encoding\"] = \"Transfer-Encoding\",\
    [\"upgrade\"] = \"Upgrade\",\
    [\"user-agent\"] = \"User-Agent\",\
    [\"vary\"] = \"Vary\",\
    [\"via\"] = \"Via\",\
    [\"warning\"] = \"Warning\",\
    [\"will-retry-until\"] = \"Will-Retry-Until\",\
    [\"www-authenticate\"] = \"WWW-Authenticate\",\
    [\"x-mailer\"] = \"X-Mailer\",\
}\
\
return _M"
, '@'.."./lualib/socket/headers.lua" ) )

package.preload[ "socket.http" ] = assert( (loadstring or load)(
"-----------------------------------------------------------------------------\
-- HTTP/1.1 client support for the Lua language.\
-- LuaSocket toolkit.\
-- Author: Diego Nehab\
-----------------------------------------------------------------------------\
\
-----------------------------------------------------------------------------\
-- Declare module and import dependencies\
-------------------------------------------------------------------------------\
local socket = require(\"socket\")\
local url = require(\"socket.url\")\
local ltn12 = require(\"ltn12\")\
local mime = require(\"mime\")\
local string = require(\"string\")\
local headers = require(\"socket.headers\")\
local base = _G\
local table = require(\"table\")\
socket.http = {}\
local _M = socket.http\
\
-----------------------------------------------------------------------------\
-- Program constants\
-----------------------------------------------------------------------------\
-- connection timeout in seconds\
_M.TIMEOUT = 60\
-- user agent field sent in request\
_M.USERAGENT = socket._VERSION\
\
-- supported schemes\
local SCHEMES = { [\"http\"] = true }\
-- default port for document retrieval\
local PORT = 80\
\
-----------------------------------------------------------------------------\
-- Reads MIME headers from a connection, unfolding where needed\
-----------------------------------------------------------------------------\
local function receiveheaders(sock, headers)\
    local line, name, value, err\
    headers = headers or {}\
    -- get first line\
    line, err = sock:receive()\
    if err then return nil, err end\
    -- headers go until a blank line is found\
    while line ~= \"\" do\
        -- get field-name and value\
        name, value = socket.skip(2, string.find(line, \"^(.-):%s*(.*)\"))\
        if not (name and value) then return nil, \"malformed reponse headers\" end\
        name = string.lower(name)\
        -- get next line (value might be folded)\
        line, err  = sock:receive()\
        if err then return nil, err end\
        -- unfold any folded values\
        while string.find(line, \"^%s\") do\
            value = value .. line\
            line = sock:receive()\
            if err then return nil, err end\
        end\
        -- save pair in table\
        if headers[name] then headers[name] = headers[name] .. \", \" .. value\
        else headers[name] = value end\
    end\
    return headers\
end\
\
-----------------------------------------------------------------------------\
-- Extra sources and sinks\
-----------------------------------------------------------------------------\
socket.sourcet[\"http-chunked\"] = function(sock, headers)\
    return base.setmetatable({\
        getfd = function() return sock:getfd() end,\
        dirty = function() return sock:dirty() end\
    }, {\
        __call = function()\
            -- get chunk size, skip extention\
            local line, err = sock:receive()\
            if err then return nil, err end\
            local size = base.tonumber(string.gsub(line, \";.*\", \"\"), 16)\
            if not size then return nil, \"invalid chunk size\" end\
            -- was it the last chunk?\
            if size > 0 then\
                -- if not, get chunk and skip terminating CRLF\
                local chunk, err, part = sock:receive(size)\
                if chunk then sock:receive() end\
                return chunk, err\
            else\
                -- if it was, read trailers into headers table\
                headers, err = receiveheaders(sock, headers)\
                if not headers then return nil, err end\
            end\
        end\
    })\
end\
\
socket.sinkt[\"http-chunked\"] = function(sock)\
    return base.setmetatable({\
        getfd = function() return sock:getfd() end,\
        dirty = function() return sock:dirty() end\
    }, {\
        __call = function(self, chunk, err)\
            if not chunk then return sock:send(\"0\\r\\n\\r\\n\") end\
            local size = string.format(\"%X\\r\\n\", string.len(chunk))\
            return sock:send(size ..  chunk .. \"\\r\\n\")\
        end\
    })\
end\
\
-----------------------------------------------------------------------------\
-- Low level HTTP API\
-----------------------------------------------------------------------------\
local metat = { __index = {} }\
\
function _M.open(host, port, create)\
    -- create socket with user connect function, or with default\
    local c = socket.try((create or socket.tcp)())\
    local h = base.setmetatable({ c = c }, metat)\
    -- create finalized try\
    h.try = socket.newtry(function() h:close() end)\
    -- set timeout before connecting\
    h.try(c:settimeout(_M.TIMEOUT))\
    h.try(c:connect(host, port or PORT))\
    -- here everything worked\
    return h\
end\
\
function metat.__index:sendrequestline(method, uri)\
    local reqline = string.format(\"%s %s HTTP/1.1\\r\\n\", method or \"GET\", uri)\
    return self.try(self.c:send(reqline))\
end\
\
function metat.__index:sendheaders(tosend)\
    local canonic = headers.canonic\
    local h = \"\\r\\n\"\
    for f, v in base.pairs(tosend) do\
        h = (canonic[f] or f) .. \": \" .. v .. \"\\r\\n\" .. h\
    end\
    self.try(self.c:send(h))\
    return 1\
end\
\
function metat.__index:sendbody(headers, source, step)\
    source = source or ltn12.source.empty()\
    step = step or ltn12.pump.step\
    -- if we don't know the size in advance, send chunked and hope for the best\
    local mode = \"http-chunked\"\
    if headers[\"content-length\"] then mode = \"keep-open\" end\
    return self.try(ltn12.pump.all(source, socket.sink(mode, self.c), step))\
end\
\
function metat.__index:receivestatusline()\
    local status = self.try(self.c:receive(5))\
    -- identify HTTP/0.9 responses, which do not contain a status line\
    -- this is just a heuristic, but is what the RFC recommends\
    if status ~= \"HTTP/\" then return nil, status end\
    -- otherwise proceed reading a status line\
    status = self.try(self.c:receive(\"*l\", status))\
    local code = socket.skip(2, string.find(status, \"HTTP/%d*%.%d* (%d%d%d)\"))\
    return self.try(base.tonumber(code), status)\
end\
\
function metat.__index:receiveheaders()\
    return self.try(receiveheaders(self.c))\
end\
\
function metat.__index:receivebody(headers, sink, step)\
    sink = sink or ltn12.sink.null()\
    step = step or ltn12.pump.step\
    local length = base.tonumber(headers[\"content-length\"])\
    local t = headers[\"transfer-encoding\"] -- shortcut\
    local mode = \"default\" -- connection close\
    if t and t ~= \"identity\" then mode = \"http-chunked\"\
    elseif base.tonumber(headers[\"content-length\"]) then mode = \"by-length\" end\
    return self.try(ltn12.pump.all(socket.source(mode, self.c, length),\
        sink, step))\
end\
\
function metat.__index:receive09body(status, sink, step)\
    local source = ltn12.source.rewind(socket.source(\"until-closed\", self.c))\
    source(status)\
    return self.try(ltn12.pump.all(source, sink, step))\
end\
\
function metat.__index:close()\
    return self.c:close()\
end\
\
-----------------------------------------------------------------------------\
-- High level HTTP API\
-----------------------------------------------------------------------------\
local function adjusturi(reqt)\
    local u = reqt\
    -- if there is a proxy, we need the full url. otherwise, just a part.\
    if not reqt.proxy and not _M.PROXY then\
        u = {\
           path = socket.try(reqt.path, \"invalid path 'nil'\"),\
           params = reqt.params,\
           query = reqt.query,\
           fragment = reqt.fragment\
        }\
    end\
    return url.build(u)\
end\
\
local function adjustproxy(reqt)\
    local proxy = reqt.proxy or _M.PROXY\
    if proxy then\
        proxy = url.parse(proxy)\
        return proxy.host, proxy.port or 3128\
    else\
        return reqt.host, reqt.port\
    end\
end\
\
local function adjustheaders(reqt)\
    -- default headers\
    local host = string.gsub(reqt.authority, \"^.-@\", \"\")\
    local lower = {\
        [\"user-agent\"] = _M.USERAGENT,\
        [\"host\"] = host,\
        [\"connection\"] = \"close, TE\",\
        [\"te\"] = \"trailers\"\
    }\
    -- if we have authentication information, pass it along\
    if reqt.user and reqt.password then\
        lower[\"authorization\"] =\
            \"Basic \" ..  (mime.b64(reqt.user .. \":\" ..\
\9\9url.unescape(reqt.password)))\
    end\
    -- if we have proxy authentication information, pass it along\
    local proxy = reqt.proxy or _M.PROXY\
    if proxy then\
        proxy = url.parse(proxy)\
        if proxy.user and proxy.password then\
            lower[\"proxy-authorization\"] =\
                \"Basic \" ..  (mime.b64(proxy.user .. \":\" .. proxy.password))\
        end\
    end\
    -- override with user headers\
    for i,v in base.pairs(reqt.headers or lower) do\
        lower[string.lower(i)] = v\
    end\
    return lower\
end\
\
-- default url parts\
local default = {\
    host = \"\",\
    port = PORT,\
    path =\"/\",\
    scheme = \"http\"\
}\
\
local function adjustrequest(reqt)\
    -- parse url if provided\
    local nreqt = reqt.url and url.parse(reqt.url, default) or {}\
    -- explicit components override url\
    for i,v in base.pairs(reqt) do nreqt[i] = v end\
    if nreqt.port == \"\" then nreqt.port = PORT end\
    if not (nreqt.host and nreqt.host ~= \"\") then\
        socket.try(nil, \"invalid host '\" .. base.tostring(nreqt.host) .. \"'\")\
    end\
    -- compute uri if user hasn't overriden\
    nreqt.uri = reqt.uri or adjusturi(nreqt)\
    -- adjust headers in request\
    nreqt.headers = adjustheaders(nreqt)\
    -- ajust host and port if there is a proxy\
    nreqt.host, nreqt.port = adjustproxy(nreqt)\
    return nreqt\
end\
\
local function shouldredirect(reqt, code, headers)\
    local location = headers.location\
    if not location then return false end\
    location = string.gsub(location, \"%s\", \"\")\
    if location == \"\" then return false end\
    local scheme = string.match(location, \"^([%w][%w%+%-%.]*)%:\")\
    if scheme and not SCHEMES[scheme] then return false end\
    return (reqt.redirect ~= false) and\
           (code == 301 or code == 302 or code == 303 or code == 307) and\
           (not reqt.method or reqt.method == \"GET\" or reqt.method == \"HEAD\")\
           and (not reqt.nredirects or reqt.nredirects < 5)\
end\
\
local function shouldreceivebody(reqt, code)\
    if reqt.method == \"HEAD\" then return nil end\
    if code == 204 or code == 304 then return nil end\
    if code >= 100 and code < 200 then return nil end\
    return 1\
end\
\
-- forward declarations\
local trequest, tredirect\
\
--[[local]] function tredirect(reqt, location)\
    local result, code, headers, status = trequest {\
        -- the RFC says the redirect URL has to be absolute, but some\
        -- servers do not respect that\
        url = url.absolute(reqt.url, location),\
        source = reqt.source,\
        sink = reqt.sink,\
        headers = reqt.headers,\
        proxy = reqt.proxy,\
        nredirects = (reqt.nredirects or 0) + 1,\
        create = reqt.create\
    }\
    -- pass location header back as a hint we redirected\
    headers = headers or {}\
    headers.location = headers.location or location\
    return result, code, headers, status\
end\
\
--[[local]] function trequest(reqt)\
    -- we loop until we get what we want, or\
    -- until we are sure there is no way to get it\
    local nreqt = adjustrequest(reqt)\
    local h = _M.open(nreqt.host, nreqt.port, nreqt.create)\
    -- send request line and headers\
    h:sendrequestline(nreqt.method, nreqt.uri)\
    h:sendheaders(nreqt.headers)\
    -- if there is a body, send it\
    if nreqt.source then\
        h:sendbody(nreqt.headers, nreqt.source, nreqt.step)\
    end\
    local code, status = h:receivestatusline()\
    -- if it is an HTTP/0.9 server, simply get the body and we are done\
    if not code then\
        h:receive09body(status, nreqt.sink, nreqt.step)\
        return 1, 200\
    end\
    local headers\
    -- ignore any 100-continue messages\
    while code == 100 do\
        headers = h:receiveheaders()\
        code, status = h:receivestatusline()\
    end\
    headers = h:receiveheaders()\
    -- at this point we should have a honest reply from the server\
    -- we can't redirect if we already used the source, so we report the error\
    if shouldredirect(nreqt, code, headers) and not nreqt.source then\
        h:close()\
        return tredirect(reqt, headers.location)\
    end\
    -- here we are finally done\
    if shouldreceivebody(nreqt, code) then\
        h:receivebody(headers, nreqt.sink, nreqt.step)\
    end\
    h:close()\
    return 1, code, headers, status\
end\
\
-- turns an url and a body into a generic request\
local function genericform(u, b)\
    local t = {}\
    local reqt = {\
        url = u,\
        sink = ltn12.sink.table(t),\
        target = t\
    }\
    if b then\
        reqt.source = ltn12.source.string(b)\
        reqt.headers = {\
            [\"content-length\"] = string.len(b),\
            [\"content-type\"] = \"application/x-www-form-urlencoded\"\
        }\
        reqt.method = \"POST\"\
    end\
    return reqt\
end\
\
_M.genericform = genericform\
\
local function srequest(u, b)\
    local reqt = genericform(u, b)\
    local _, code, headers, status = trequest(reqt)\
    return table.concat(reqt.target), code, headers, status\
end\
\
_M.request = socket.protect(function(reqt, body)\
    if base.type(reqt) == \"string\" then return srequest(reqt, body)\
    else return trequest(reqt) end\
end)\
\
return _M\
"
, '@'.."./lualib/socket/http.lua" ) )

package.preload[ "socket.url" ] = assert( (loadstring or load)(
"-----------------------------------------------------------------------------\
-- URI parsing, composition and relative URL resolution\
-- LuaSocket toolkit.\
-- Author: Diego Nehab\
-----------------------------------------------------------------------------\
\
-----------------------------------------------------------------------------\
-- Declare module\
-----------------------------------------------------------------------------\
local string = require(\"string\")\
local base = _G\
local table = require(\"table\")\
local socket = require(\"socket\")\
\
socket.url = {}\
local _M = socket.url\
\
-----------------------------------------------------------------------------\
-- Module version\
-----------------------------------------------------------------------------\
_M._VERSION = \"URL 1.0.3\"\
\
-----------------------------------------------------------------------------\
-- Encodes a string into its escaped hexadecimal representation\
-- Input\
--   s: binary string to be encoded\
-- Returns\
--   escaped representation of string binary\
-----------------------------------------------------------------------------\
function _M.escape(s)\
    return (string.gsub(s, \"([^A-Za-z0-9_])\", function(c)\
        return string.format(\"%%%02x\", string.byte(c))\
    end))\
end\
\
-----------------------------------------------------------------------------\
-- Protects a path segment, to prevent it from interfering with the\
-- url parsing.\
-- Input\
--   s: binary string to be encoded\
-- Returns\
--   escaped representation of string binary\
-----------------------------------------------------------------------------\
local function make_set(t)\
    local s = {}\
    for i,v in base.ipairs(t) do\
        s[t[i]] = 1\
    end\
    return s\
end\
\
-- these are allowed within a path segment, along with alphanum\
-- other characters must be escaped\
local segment_set = make_set {\
    \"-\", \"_\", \".\", \"!\", \"~\", \"*\", \"'\", \"(\",\
    \")\", \":\", \"@\", \"&\", \"=\", \"+\", \"$\", \",\",\
}\
\
local function protect_segment(s)\
    return string.gsub(s, \"([^A-Za-z0-9_])\", function (c)\
        if segment_set[c] then return c\
        else return string.format(\"%%%02X\", string.byte(c)) end\
    end)\
end\
\
-----------------------------------------------------------------------------\
-- Unencodes a escaped hexadecimal string into its binary representation\
-- Input\
--   s: escaped hexadecimal string to be unencoded\
-- Returns\
--   unescaped binary representation of escaped hexadecimal  binary\
-----------------------------------------------------------------------------\
function _M.unescape(s)\
    return (string.gsub(s, \"%%(%x%x)\", function(hex)\
        return string.char(base.tonumber(hex, 16))\
    end))\
end\
\
-----------------------------------------------------------------------------\
-- Builds a path from a base path and a relative path\
-- Input\
--   base_path\
--   relative_path\
-- Returns\
--   corresponding absolute path\
-----------------------------------------------------------------------------\
local function absolute_path(base_path, relative_path)\
    if string.sub(relative_path, 1, 1) == \"/\" then return relative_path end\
    local path = string.gsub(base_path, \"[^/]*$\", \"\")\
    path = path .. relative_path\
    path = string.gsub(path, \"([^/]*%./)\", function (s)\
        if s ~= \"./\" then return s else return \"\" end\
    end)\
    path = string.gsub(path, \"/%.$\", \"/\")\
    local reduced\
    while reduced ~= path do\
        reduced = path\
        path = string.gsub(reduced, \"([^/]*/%.%./)\", function (s)\
            if s ~= \"../../\" then return \"\" else return s end\
        end)\
    end\
    path = string.gsub(reduced, \"([^/]*/%.%.)$\", function (s)\
        if s ~= \"../..\" then return \"\" else return s end\
    end)\
    return path\
end\
\
-----------------------------------------------------------------------------\
-- Parses a url and returns a table with all its parts according to RFC 2396\
-- The following grammar describes the names given to the URL parts\
-- <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>\
-- <authority> ::= <userinfo>@<host>:<port>\
-- <userinfo> ::= <user>[:<password>]\
-- <path> :: = {<segment>/}<segment>\
-- Input\
--   url: uniform resource locator of request\
--   default: table with default values for each field\
-- Returns\
--   table with the following fields, where RFC naming conventions have\
--   been preserved:\
--     scheme, authority, userinfo, user, password, host, port,\
--     path, params, query, fragment\
-- Obs:\
--   the leading '/' in {/<path>} is considered part of <path>\
-----------------------------------------------------------------------------\
function _M.parse(url, default)\
    -- initialize default parameters\
    local parsed = {}\
    for i,v in base.pairs(default or parsed) do parsed[i] = v end\
    -- empty url is parsed to nil\
    if not url or url == \"\" then return nil, \"invalid url\" end\
    -- remove whitespace\
    -- url = string.gsub(url, \"%s\", \"\")\
    -- get scheme\
    url = string.gsub(url, \"^([%w][%w%+%-%.]*)%:\",\
        function(s) parsed.scheme = s; return \"\" end)\
    -- get authority\
    url = string.gsub(url, \"^//([^/]*)\", function(n)\
        parsed.authority = n\
        return \"\"\
    end)\
    -- get fragment\
    url = string.gsub(url, \"#(.*)$\", function(f)\
        parsed.fragment = f\
        return \"\"\
    end)\
    -- get query string\
    url = string.gsub(url, \"%?(.*)\", function(q)\
        parsed.query = q\
        return \"\"\
    end)\
    -- get params\
    url = string.gsub(url, \"%;(.*)\", function(p)\
        parsed.params = p\
        return \"\"\
    end)\
    -- path is whatever was left\
    if url ~= \"\" then parsed.path = url end\
    local authority = parsed.authority\
    if not authority then return parsed end\
    authority = string.gsub(authority,\"^([^@]*)@\",\
        function(u) parsed.userinfo = u; return \"\" end)\
    authority = string.gsub(authority, \":([^:%]]*)$\",\
        function(p) parsed.port = p; return \"\" end)\
    if authority ~= \"\" then \
        -- IPv6?\
        parsed.host = string.match(authority, \"^%[(.+)%]$\") or authority \
    end\
    local userinfo = parsed.userinfo\
    if not userinfo then return parsed end\
    userinfo = string.gsub(userinfo, \":([^:]*)$\",\
        function(p) parsed.password = p; return \"\" end)\
    parsed.user = userinfo\
    return parsed\
end\
\
-----------------------------------------------------------------------------\
-- Rebuilds a parsed URL from its components.\
-- Components are protected if any reserved or unallowed characters are found\
-- Input\
--   parsed: parsed URL, as returned by parse\
-- Returns\
--   a stringing with the corresponding URL\
-----------------------------------------------------------------------------\
function _M.build(parsed)\
    --local ppath = _M.parse_path(parsed.path or \"\")\
    --local url = _M.build_path(ppath)\
    local url = parsed.path or \"\"\
    if parsed.params then url = url .. \";\" .. parsed.params end\
    if parsed.query then url = url .. \"?\" .. parsed.query end\
    local authority = parsed.authority\
    if parsed.host then\
        authority = parsed.host\
        if string.find(authority, \":\") then -- IPv6?\
            authority = \"[\" .. authority .. \"]\"\
        end\
        if parsed.port then authority = authority .. \":\" .. base.tostring(parsed.port) end\
        local userinfo = parsed.userinfo\
        if parsed.user then\
            userinfo = parsed.user\
            if parsed.password then\
                userinfo = userinfo .. \":\" .. parsed.password\
            end\
        end\
        if userinfo then authority = userinfo .. \"@\" .. authority end\
    end\
    if authority then url = \"//\" .. authority .. url end\
    if parsed.scheme then url = parsed.scheme .. \":\" .. url end\
    if parsed.fragment then url = url .. \"#\" .. parsed.fragment end\
    -- url = string.gsub(url, \"%s\", \"\")\
    return url\
end\
\
-----------------------------------------------------------------------------\
-- Builds a absolute URL from a base and a relative URL according to RFC 2396\
-- Input\
--   base_url\
--   relative_url\
-- Returns\
--   corresponding absolute url\
-----------------------------------------------------------------------------\
function _M.absolute(base_url, relative_url)\
    local base_parsed\
    if base.type(base_url) == \"table\" then\
        base_parsed = base_url\
        base_url = _M.build(base_parsed)\
    else\
        base_parsed = _M.parse(base_url)\
    end\
    local relative_parsed = _M.parse(relative_url)\
    if not base_parsed then return relative_url\
    elseif not relative_parsed then return base_url\
    elseif relative_parsed.scheme then return relative_url\
    else\
        relative_parsed.scheme = base_parsed.scheme\
        if not relative_parsed.authority then\
            relative_parsed.authority = base_parsed.authority\
            if not relative_parsed.path then\
                relative_parsed.path = base_parsed.path\
                if not relative_parsed.params then\
                    relative_parsed.params = base_parsed.params\
                    if not relative_parsed.query then\
                        relative_parsed.query = base_parsed.query\
                    end\
                end\
            else    \
                relative_parsed.path = absolute_path(base_parsed.path or \"\",\
                    relative_parsed.path)\
            end\
        end\
        return _M.build(relative_parsed)\
    end\
end\
\
-----------------------------------------------------------------------------\
-- Breaks a path into its segments, unescaping the segments\
-- Input\
--   path\
-- Returns\
--   segment: a table with one entry per segment\
-----------------------------------------------------------------------------\
function _M.parse_path(path)\
    local parsed = {}\
    path = path or \"\"\
    --path = string.gsub(path, \"%s\", \"\")\
    string.gsub(path, \"([^/]+)\", function (s) table.insert(parsed, s) end)\
    for i = 1, #parsed do\
        parsed[i] = _M.unescape(parsed[i])\
    end\
    if string.sub(path, 1, 1) == \"/\" then parsed.is_absolute = 1 end\
    if string.sub(path, -1, -1) == \"/\" then parsed.is_directory = 1 end\
    return parsed\
end\
\
-----------------------------------------------------------------------------\
-- Builds a path component from its segments, escaping protected characters.\
-- Input\
--   parsed: path segments\
--   unsafe: if true, segments are not protected before path is built\
-- Returns\
--   path: corresponding path stringing\
-----------------------------------------------------------------------------\
function _M.build_path(parsed, unsafe)\
    local path = \"\"\
    local n = #parsed\
    if unsafe then\
        for i = 1, n-1 do\
            path = path .. parsed[i]\
            path = path .. \"/\"\
        end\
        if n > 0 then\
            path = path .. parsed[n]\
            if parsed.is_directory then path = path .. \"/\" end\
        end\
    else\
        for i = 1, n-1 do\
            path = path .. protect_segment(parsed[i])\
            path = path .. \"/\"\
        end\
        if n > 0 then\
            path = path .. protect_segment(parsed[n])\
            if parsed.is_directory then path = path .. \"/\" end\
        end\
    end\
    if parsed.is_absolute then path = \"/\" .. path end\
    return path\
end\
\
return _M\
"
, '@'.."./lualib/socket/url.lua" ) )

package.preload[ "ssl" ] = assert( (loadstring or load)(
"------------------------------------------------------------------------------\
-- LuaSec 0.7\
--\
-- Copyright (C) 2006-2018 Bruno Silvestre\
--\
------------------------------------------------------------------------------\
\
local core    = require(\"ssl.core\")\
local context = require(\"ssl.context\")\
local x509    = require(\"ssl.x509\")\
local config  = require(\"ssl.config\")\
\
local unpack  = table.unpack or unpack\
\
-- We must prevent the contexts to be collected before the connections,\
-- otherwise the C registry will be cleared.\
local registry = setmetatable({}, {__mode=\"k\"})\
\
--\
--\
--\
local function optexec(func, param, ctx)\
  if param then\
    if type(param) == \"table\" then\
      return func(ctx, unpack(param))\
    else\
      return func(ctx, param)\
    end\
  end\
  return true\
end\
\
--\
-- Convert an array of strings to wire-format\
--\
local function array2wireformat(array)\
   local str = \"\"\
   for k, v in ipairs(array) do\
      if type(v) ~= \"string\" then return nil end\
      local len = #v\
      if len == 0 then\
        return nil, \"invalid ALPN name (empty string)\"\
      elseif len > 255 then\
        return nil, \"invalid ALPN name (length > 255)\"\
      end\
      str = str .. string.char(len) .. v\
   end\
   if str == \"\" then return nil, \"invalid ALPN list (empty)\" end\
   return str\
end\
\
--\
-- Convert wire-string format to array\
--\
local function wireformat2array(str)\
   local i = 1\
   local array = {}\
   while i < #str do\
      local len = str:byte(i)\
      array[#array + 1] = str:sub(i + 1, i + len)\
      i = i + len + 1\
   end\
   return array\
end\
\
--\
--\
--\
local function newcontext(cfg)\
   local succ, msg, ctx\
   -- Create the context\
   ctx, msg = context.create(cfg.protocol)\
   if not ctx then return nil, msg end\
   -- Mode\
   succ, msg = context.setmode(ctx, cfg.mode)\
   if not succ then return nil, msg end\
   -- Load the key\
   if cfg.key then\
      if cfg.password and\
         type(cfg.password) ~= \"function\" and\
         type(cfg.password) ~= \"string\"\
      then\
         return nil, \"invalid password type\"\
      end\
      succ, msg = context.loadkey(ctx, cfg.key, cfg.password)\
      if not succ then return nil, msg end\
   end\
   -- Load the certificate\
   if cfg.certificate then\
     succ, msg = context.loadcert(ctx, cfg.certificate)\
     if not succ then return nil, msg end\
     if cfg.key and context.checkkey then\
       succ = context.checkkey(ctx)\
       if not succ then return nil, \"private key does not match public key\" end\
     end\
   end\
   -- Load the CA certificates\
   if cfg.cafile or cfg.capath then\
      succ, msg = context.locations(ctx, cfg.cafile, cfg.capath)\
      if not succ then return nil, msg end\
   end\
   -- Set SSL ciphers\
   if cfg.ciphers then\
      succ, msg = context.setcipher(ctx, cfg.ciphers)\
      if not succ then return nil, msg end\
   end\
   -- Set the verification options\
   succ, msg = optexec(context.setverify, cfg.verify, ctx)\
   if not succ then return nil, msg end\
   -- Set SSL options\
   succ, msg = optexec(context.setoptions, cfg.options, ctx)\
   if not succ then return nil, msg end\
   -- Set the depth for certificate verification\
   if cfg.depth then\
      succ, msg = context.setdepth(ctx, cfg.depth)\
      if not succ then return nil, msg end\
   end\
\
   -- NOTE: Setting DH parameters and elliptic curves needs to come after\
   -- setoptions(), in case the user has specified the single_{dh,ecdh}_use\
   -- options.\
\
   -- Set DH parameters\
   if cfg.dhparam then\
      if type(cfg.dhparam) ~= \"function\" then\
         return nil, \"invalid DH parameter type\"\
      end\
      context.setdhparam(ctx, cfg.dhparam)\
   end\
   \
   -- Set elliptic curves\
   if (not config.algorithms.ec) and (cfg.curve or cfg.curveslist) then\
     return false, \"elliptic curves not supported\"\
   end\
   if config.capabilities.curves_list and cfg.curveslist then\
     succ, msg = context.setcurveslist(ctx, cfg.curveslist)\
     if not succ then return nil, msg end\
   elseif cfg.curve then\
     succ, msg = context.setcurve(ctx, cfg.curve)\
     if not succ then return nil, msg end\
   end\
\
   -- Set extra verification options\
   if cfg.verifyext and ctx.setverifyext then\
      succ, msg = optexec(ctx.setverifyext, cfg.verifyext, ctx)\
      if not succ then return nil, msg end\
   end\
\
   -- ALPN\
   if cfg.mode == \"server\" and cfg.alpn then\
      if type(cfg.alpn) == \"function\" then\
         local alpncb = cfg.alpn\
         -- This callback function has to return one value only\
         succ, msg = context.setalpncb(ctx, function(str)\
            local protocols = alpncb(wireformat2array(str))\
            if type(protocols) == \"string\" then\
               protocols = { protocols }\
            elseif type(protocols) ~= \"table\" then\
               return nil\
            end\
            return (array2wireformat(protocols))    -- use \"()\" to drop error message\
         end)\
         if not succ then return nil, msg end\
      elseif type(cfg.alpn) == \"table\" then\
         local protocols = cfg.alpn\
         -- check if array is valid before use it\
         succ, msg = array2wireformat(protocols)\
         if not succ then return nil, msg end\
         -- This callback function has to return one value only\
         succ, msg = context.setalpncb(ctx, function()\
            return (array2wireformat(protocols))    -- use \"()\" to drop error message\
         end)\
         if not succ then return nil, msg end\
      else\
         return nil, \"invalid ALPN parameter\"\
      end\
   elseif cfg.mode == \"client\" and cfg.alpn then\
      local alpn\
      if type(cfg.alpn) == \"string\" then\
         alpn, msg = array2wireformat({ cfg.alpn })\
      elseif type(cfg.alpn) == \"table\" then\
         alpn, msg = array2wireformat(cfg.alpn)\
      else\
         return nil, \"invalid ALPN parameter\"\
      end\
      if not alpn then return nil, msg end\
      succ, msg = context.setalpn(ctx, alpn)\
      if not succ then return nil, msg end\
   end\
\
   return ctx\
end\
\
--\
--\
--\
local function wrap(sock, cfg)\
   local ctx, msg\
   if type(cfg) == \"table\" then\
      ctx, msg = newcontext(cfg)\
      if not ctx then return nil, msg end\
   else\
      ctx = cfg\
   end\
   local s, msg = core.create(ctx)\
   if s then\
      core.setfd(s, sock:getfd())\
      sock:setfd(core.SOCKET_INVALID)\
      registry[s] = ctx\
      return s\
   end\
   return nil, msg \
end\
\
--\
-- Extract connection information.\
--\
local function info(ssl, field)\
  local str, comp, err, protocol\
  comp, err = core.compression(ssl)\
  if err then\
    return comp, err\
  end\
  -- Avoid parser\
  if field == \"compression\" then\
    return comp\
  end\
  local info = {compression = comp}\
  str, info.bits, info.algbits, protocol = core.info(ssl)\
  if str then\
    info.cipher, info.protocol, info.key,\
    info.authentication, info.encryption, info.mac =\
        string.match(str, \
          \"^(%S+)%s+(%S+)%s+Kx=(%S+)%s+Au=(%S+)%s+Enc=(%S+)%s+Mac=(%S+)\")\
    info.export = (string.match(str, \"%sexport%s*$\") ~= nil)\
  end\
  if protocol then\
    info.protocol = protocol\
  end\
  if field then\
    return info[field]\
  end\
  -- Empty?\
  return ( (next(info)) and info )\
end\
\
--\
-- Set method for SSL connections.\
--\
core.setmethod(\"info\", info)\
\
--------------------------------------------------------------------------------\
-- Export module\
--\
\
local _M = {\
  _VERSION        = \"0.7\",\
  _COPYRIGHT      = core.copyright(),\
  loadcertificate = x509.load,\
  newcontext      = newcontext,\
  wrap            = wrap,\
}\
\
return _M\
"
, '@'.."./lualib/ssl/ssl.lua" ) )

package.preload[ "ssl.https" ] = assert( (loadstring or load)(
"----------------------------------------------------------------------------\
-- LuaSec 0.7\
-- Copyright (C) 2009-2018 PUC-Rio\
--\
-- Author: Pablo Musa\
-- Author: Tomas Guisasola\
---------------------------------------------------------------------------\
\
local socket = require(\"socket\")\
local ssl    = require(\"ssl\")\
local ltn12  = require(\"ltn12\")\
local http   = require(\"socket.http\")\
local url    = require(\"socket.url\")\
\
local try    = socket.try\
\
--\
-- Module\
--\
local _M = {\
  _VERSION   = \"0.7\",\
  _COPYRIGHT = \"LuaSec 0.7 - Copyright (C) 2009-2018 PUC-Rio\",\
  PORT       = 443,\
  TIMEOUT    = 60\
}\
\
-- TLS configuration\
local cfg = {\
  protocol = \"any\",\
  options  = {\"all\", \"no_sslv2\", \"no_sslv3\", \"no_tlsv1\"},\
  verify   = \"none\",\
}\
\
--------------------------------------------------------------------\
-- Auxiliar Functions\
--------------------------------------------------------------------\
\
-- Insert default HTTPS port.\
local function default_https_port(u)\
   return url.build(url.parse(u, {port = _M.PORT}))\
end\
\
-- Convert an URL to a table according to Luasocket needs.\
local function urlstring_totable(url, body, result_table)\
   url = {\
      url = default_https_port(url),\
      method = body and \"POST\" or \"GET\",\
      sink = ltn12.sink.table(result_table)\
   }\
   if body then\
      url.source = ltn12.source.string(body)\
      url.headers = {\
         [\"content-length\"] = #body,\
         [\"content-type\"] = \"application/x-www-form-urlencoded\",\
      }\
   end\
   return url\
end\
\
-- Forward calls to the real connection object.\
local function reg(conn)\
   local mt = getmetatable(conn.sock).__index\
   for name, method in pairs(mt) do\
      if type(method) == \"function\" then\
         conn[name] = function (self, ...)\
                         return method(self.sock, ...)\
                      end\
      end\
   end\
end\
\
-- Return a function which performs the SSL/TLS connection.\
local function tcp(params)\
   params = params or {}\
   -- Default settings\
   for k, v in pairs(cfg) do \
      params[k] = params[k] or v\
   end\
   -- Force client mode\
   params.mode = \"client\"\
   -- 'create' function for LuaSocket\
   return function ()\
      local conn = {}\
      conn.sock = try(socket.tcp())\
      local st = getmetatable(conn.sock).__index.settimeout\
      function conn:settimeout(...)\
         return st(self.sock, _M.TIMEOUT)\
      end\
      -- Replace TCP's connection function\
      function conn:connect(host, port)\
         try(self.sock:connect(host, port))\
         self.sock = try(ssl.wrap(self.sock, params))\
         self.sock:sni(host)\
         self.sock:settimeout(_M.TIMEOUT)\
         try(self.sock:dohandshake())\
         reg(self, getmetatable(self.sock))\
         return 1\
      end\
      return conn\
  end\
end\
\
--------------------------------------------------------------------\
-- Main Function\
--------------------------------------------------------------------\
\
-- Make a HTTP request over secure connection.  This function receives\
--  the same parameters of LuaSocket's HTTP module (except 'proxy' and\
--  'redirect') plus LuaSec parameters.\
--\
-- @param url mandatory (string or table)\
-- @param body optional (string)\
-- @return (string if url == string or 1), code, headers, status\
--\
local function request(url, body)\
  local result_table = {}\
  local stringrequest = type(url) == \"string\"\
  if stringrequest then\
    url = urlstring_totable(url, body, result_table)\
  else\
    url.url = default_https_port(url.url)\
  end\
  if http.PROXY or url.proxy then\
    return nil, \"proxy not supported\"\
  elseif url.redirect then\
    return nil, \"redirect not supported\"\
  elseif url.create then\
    return nil, \"create function not permitted\"\
  end\
  -- New 'create' function to establish a secure connection\
  url.create = tcp(url)\
  local res, code, headers, status = http.request(url)\
  if res and stringrequest then\
    return table.concat(result_table), code, headers, status\
  end\
  return res, code, headers, status\
end\
\
--------------------------------------------------------------------------------\
-- Export module\
--\
\
_M.request = request\
\
return _M\
"
, '@'.."./lualib/ssl/https.lua" ) )

package.preload[ "svrcomm" ] = assert( (loadstring or load)(
"local cjson = require \"cjson\"\
local log = require \"log\"\
local msocket = require \"msocket\"\
local mystring = require \"mystring\"\
local socket = require \"socket\"\
local cssl_enable, cssl = pcall(require, \"c.ssl\")\
\
local svrcomm = {\
    localaddr = \"\", \
}\
\
-- TLS/SSL client parameters\
local sslparams = {\
    mode = \"client\",\
    protocol = \"tlsv1_2\",\
    verify = \"none\",\
    options = \"all\",\
}\
\
\
local function ssl_wrap_conn(svr, issync, timeout)\
    local addr = svr.addr or \"\"\
\
    local conn, err\
    if cssl_enable then\
        conn, err = cssl.wrap(svr.sock:getfd())  -- do not support sslparams now\
        if conn then\
            svr.sock:setfd(-1)\
        end\
    else\
        local ssl_enable, ssl = pcall(require, \"ssl\")  -- luasec\
        if not ssl_enable then\
            return \"luasec ssl not enable\"\
        end\
        conn, err = ssl.wrap(svr.sock, sslparams)\
    end\
    if not conn then\
        log.error(addr..\" ssl wrap failed, error is \"..err)\
        return err\
    end\
    svr.sock = conn\
\
    if type(timeout) == \"number\" then\
        conn:settimeout(timeout)\
    else\
        conn:settimeout(2)\
    end\
    local ok, err = conn:dohandshake()\
    if not ok then\
        log.error(addr..\" dohandshake failed, error is \"..err)\
        return err\
    end\
\
    if not issync then\
        conn:settimeout(0)\
    end\
    return nil\
end\
\
-- data long conn, just use ssl\
--\
\
local function datalong_sock_run(svr, recvcall, ...)\
    local sock = svr.sock\
    sock:settimeout(0)\
    local addr, port = mystring.split(svr.addr, \":\")\
    svr.status = \"connecting\"\
    local err = msocket.svr_connect(svr.co, sock, addr, port)\
    if err then \
        log.error(\"datalong \"..svr.addr..\" connect failed, error is \"..err)\
        return\
    end\
    svr.status = \"connected\"\
\
    if svr.sslflag then\
        svr.status = \"ssl_handshake_doing\"\
        local err = ssl_wrap_conn(svr)\
        if err then\
            return\
        end\
        svr.status = \"ssl_handshake_done\"\
        sock = svr.sock\
    end\
\
    while true do\
        svr.status = \"waiting\"\
        exit, data = msocket.coroutine_yield()\
        if exit then\
            break\
        end\
\
        svr.status = \"sending\"\
        err = msocket.svr_send(svr.co, sock, data)\
        if err then\
            log.error(\"datalong \"..svr.addr..\" send data failed, error is \"..err)\
            break\
        end\
\
        svr.status = \"recving\"\
        _, err = msocket.svr_receive(svr.co, sock, svr.addr, recvcall, data, ...)\
        if err then\
            log.error(\"datalong \"..svr.addr..\" recv data failed, error is \"..err)\
            break\
        end\
    end\
    svr.status = \"closed\"\
end\
\
local function coroutine_datalong_run(svr, recvcall, ...)\
    log.warn(\"will start datalong sock with addr \", svr.addr)\
    svr.sock = socket.tcp()\
    local ok, r = pcall(datalong_sock_run, svr, recvcall, ...)\
    if not ok then\
        log.error(r)\
    end\
    svr.sock:close()\
    log.warn(\"will exit datalong sock with addr \", svr.addr)\
    msocket.coroutine_exit()\
end\
\
-- server running structures\
-- running var\
--   co\
--   addr\
--\
--   long sock running\
--   status, connecting/connected/listening/replying/closed\
\
local function long_sock_run(svr, init_data, recvcall, key)\
    local sock = svr.sock\
    sock:settimeout(0)\
    local addr, port = mystring.split(svr.addr, \":\")\
    svr.status = \"connecting\"\
    local err = msocket.svr_connect(svr.co, sock, addr, port)\
    if err then \
        log.error(\"long \"..svr.addr..\" connect failed, error is \"..err)\
        return\
    end\
    svr.status = \"connected\"\
\
    if svr.sslflag then\
        svr.status = \"ssl_handshake_doing\"\
        local err = ssl_wrap_conn(svr)\
        if err then\
            return\
        end\
        svr.status = \"ssl_handshake_done\"\
        sock = svr.sock\
    end\
\
    -- send hello\
    local err = msocket.svr_send(svr.co, sock, init_data)\
    if err then\
        log.error(err)\
        return\
    end\
\
    while true do\
        svr.status = \"listening\"\
        result_data, err = msocket.svr_receive(svr.co, sock, svr.addr, recvcall, key)\
        if err then\
            log.error(\"long \"..svr.addr..\" recv data failed, error is \"..err)\
            break\
        end\
\
        svr.status = \"replying\"\
        err = msocket.svr_send(svr.co, sock, result_data)\
        if err then\
            log.error(\"long \"..svr.addr..\" send data failed, error is \"..err)\
            break\
        end\
    end\
    svr.status = \"closed\"\
end\
\
local function coroutine_long_run(svr, init_data, recvcall, key)\
    log.warn(\"will start long sock with addr \", svr.addr)\
    svr.sock = socket.tcp()\
    local ok, r = pcall(long_sock_run, svr, init_data, recvcall, key)\
    if not ok then\
        log.error(r)\
    end\
    svr.sock:close()\
    log.warn(\"will exit long sock with addr \", svr.addr)\
end\
\
local function short_sock_run(co, svr, data, funcall, ...)\
    -- connect\
    local addrport = svr.addr\
    local sock = svr.sock\
    sock:settimeout(0)\
    local addr, port = mystring.split(addrport, \":\")\
    local err = msocket.svr_connect(co, sock, addr, port)\
    log.trace(\"connect addr \"..addrport, \", err is \", err)\
    if err then \
        return \"failed to connect svr sock, err is \"..err\
    end\
    local localaddr = sock:getsockname()\
    if localaddr and localaddr ~= svrcomm.localaddr then\
        log.warn(\"reset sockname to \", localaddr, \", old localaddr, \", svrcomm.localaddr)\
        svrcomm.localaddr = localaddr\
    end\
\
    if svr.sslflag then\
        local err = ssl_wrap_conn(svr)\
        if err then\
            return\
        end\
        sock = svr.sock\
    end\
\
    -- send\
    local err = msocket.svr_send(co, sock, data)\
    if err then\
        return \"failed to send svr sock, err is \"..err\
    end\
\
    -- recv\
    if type(funcall) == \"function\" then\
        reply, err = msocket.svr_receive(co, sock, addrport, funcall, ...)\
        log.trace(\"recv addr \"..addrport, \", err is \", err)\
    end\
    return err\
end\
\
local function coroutine_short_run(svr, data, finicall, recvcall, ...)\
    log.info(\"svr coroutine start \"..svr.addr)\
    local co = coroutine.running()\
    svr.sock = socket.tcp()\
    local ok, err = pcall(short_sock_run, co, svr, data, recvcall, ...)\
    svr.sock:close()\
    if type(finicall) == \"function\" then\
        finicall(err, data)\
    end\
    log.info(\"svr coroutine finish \"..svr.addr, \", ok is \", ok, \", err is \", err)\
    msocket.coroutine_exit(co)\
end\
\
local function index_svr_call(svr, data, finicall, recvcall, ...)\
    if type(svr.addr) ~= \"string\" then\
        if type(finicall) == \"function\" then\
            finicall(\"failed find IP for dns\", data)\
        end\
        return\
    end\
    local coname = string.format(\"svr_%s\", svr.addr)\
    if type(svr.action) == \"number\" then\
        coname = string.format(\"%s_%02x\", coname, svr.action)\
    end\
    svr.co = msocket.coroutine_create(coname, 300, coroutine_short_run) -- at most 300 seconds for block\
    if not svr.co then\
        log.warn(\"Failed to create coroutine \"..coname..\", check coroutinename err\")\
        if type(finicall) == \"function\" then\
            finicall(\"check coroutine name err\", data)\
        end\
        return\
    end\
    msocket.coroutine_resume(svr.co, svr, data, finicall, recvcall, ...)\
end\
\
local function index_svr_init(svr, addr, action, sslflag)\
    if type(addr) ~= \"string\" then\
        log.error(\"wrong format svr addr \"..type(addr))\
        return\
    end\
\
    svr.addr = addr\
    svr.action = action\
    svr.sslflag = sslflag\
    log.trace(\"init all co with addr \" .. addr)\
end\
\
local function index_svr_init_long(svr, addr, init_data, recvcall, key)\
    if type(addr) ~= \"string\" then\
        log.error(\"wrong format svr addr \"..type(addr))\
        return\
    end\
\
    local coname = \"longconn_\"..addr\
    svr.addr = addr\
    if not key then\
        svr.sslflag = true\
    end\
    svr.co = msocket.coroutine_create(coname, 300, coroutine_long_run)\
    if not svr.co then\
        log.warn(\"Failed to create coroutine \"..coname..\", check coroutinename err\")\
        return\
    end\
    svr.long = true\
    msocket.coroutine_resume(svr.co, svr, init_data, recvcall, key)\
end\
\
local function index_svr_init_datalong(svr, addr, recvcall, ...)\
    if type(addr) ~= \"string\" then\
        log.error(\"wrong format svr addr \"..type(addr))\
        return\
    end\
\
    local coname = \"datalongconn_\"..addr\
    svr.addr = addr\
    svr.co = msocket.coroutine_create(coname, 300, coroutine_datalong_run)\
    if not svr.co then\
        log.warn(\"Failed to create coroutine \"..coname..\", check coroutinename err\")\
        return\
    end\
    svr.sslflag = true\
    svr.long = true\
    msocket.coroutine_resume(svr.co, svr, recvcall, ...)\
end\
\
local function index_svr_datalong_send(svr, data)\
    return msocket.coroutine_resume(svr.co, false, data)\
end\
\
local function index_svr_show(svr)\
    return {addr = svr.addr, longsock = svr.long or false, ssl = svr.sslflag or false, status = svr.status, costatus = coroutine.status(svr.co)}\
    -- return {addr = svr.addr, longsock = svr.long or false, status = svr.status}\
end\
\
local function index_svr_free(svr)\
    msocket.coroutine_exit(svr.co)\
end\
\
local function index_svr_wait(svr)\
    if coroutine.status(svr.co) ~= \"suspended\" then\
        return false\
    end\
    \
    socket.select(nil, nil, 1)  -- sleep 1 second\
    coroutine.resume(svr.co)\
    return true\
end\
\
local function index_svr_running(svr)\
    if coroutine.status(svr.co) == \"dead\" then\
        return false\
    else\
        return true\
    end\
end\
\
local function index_svr_getstatus(svr)\
    if type(svr.status) == \"string\" then\
        return svr.status\
    end\
    return \"\"\
end\
\
local function syncall_run(svr, data, recvcall, ...)\
    -- connect\
    local addrport = svr.addr\
    local timeout = svr.timeout\
    local sip = svr.sip\
    local sock = svr.sock\
    local addr, port = mystring.split(addrport, \":\")\
    sock:settimeout(30)\
    local _, err = sock:connect(addr, port)\
    if err then\
        return err\
    end\
\
    sock:settimeout(timeout)\
    local localaddr = sock:getsockname()\
    if localaddr and localaddr ~= svrcomm.localaddr then\
        --log.warn(\"reset sockname to \", localaddr, \", old localaddr, \", svrcomm.localaddr)\
        svrcomm.localaddr = localaddr\
    end\
\
    if svr.sslflag then\
        local err = ssl_wrap_conn(svr, true, timeout)\
        if err then\
            return\
        end\
        sock = svr.sock\
    end\
\
    -- send\
    if type(sip) == \"string\" and sip ~= \"\" then\
        local ret, err, send = sock:send(string.format(\"PROXY TCP4 %s 0.0.0.0 0 0\\r\\n\", sip))\
        if err then\
            return err\
        end\
    end\
\
    local ret, err, sent = sock:send(data)\
    if err then\
        return err\
    end\
\
    if type(recvcall) == \"function\" then\
        err = recvcall(sock, addrport, ...)\
        if err then\
            return err\
        end\
    end\
\
    return nil\
end\
\
local function index_svr_syncall(svr, addr, timeout, data, sip, sslflag, recvcall, ...)\
    if type(addr) ~= \"string\" then\
        return \"failed find IP for dns\"\
    end\
    svr.addr = addr\
    svr.timeout = timeout\
    svr.sip = sip\
    svr.sslflag = sslflag\
    svr.sock = socket.tcp()\
    local ok, err = pcall(syncall_run, svr, data, recvcall, ...)\
    svr.sock:close()\
    return err\
end\
\
function svrcomm.new()\
    local svr = {}\
    return setmetatable(\
        svr, \
        {__index = {\
             free = index_svr_free, \
             init = index_svr_init, \
             init_long = index_svr_init_long, \
             init_datalong = index_svr_init_datalong, \
             datalong_send = index_svr_datalong_send,\
             call = index_svr_call, \
             syncall = index_svr_syncall, \
             wait = index_svr_wait, \
             show = index_svr_show, \
             running = index_svr_running,\
             getstatus = index_svr_getstatus,\
        }}\
    ), svrcomm.localaddr\
end\
\
function svrcomm.get_localaddr()\
    return svrcomm.localaddr\
end\
\
function svrcomm.set_localaddr(localaddr)\
    if localaddr and #localaddr > 0 and localaddr ~= svrcomm.localaddr then\
        log.warn(\"reset sockname to \", localaddr, \", old localaddr, \", svrcomm.localaddr)\
        svrcomm.localaddr = localaddr\
    end\
end\
\
return svrcomm\
"
, '@'.."./lualib/svrcomm/svrcomm.lua" ) )

package.preload[ "svrcomm.ckey" ] = assert( (loadstring or load)(
"local timer = require\"timer\"\
local cjson = require\"cjson\"\
local ctime = require\"c.time\"\
local mystring = require\"mystring\"\
local svrcomm = require\"svrcomm\"\
local pack = require\"svrcomm.pack\"\
local packpb = require\"svrcomm.packpb\"\
local tlv = require\"tlv\"\
--local pbmsg = require\"pbmsg\"\
local pb = require\"pb\"\
\
local ckey = {\
    tname = \"ckey_refresh\",\
    period = 60,\
    proto = \"pb\"\
}\
\
local cacheglobal = {\
    keys = {\
        -- using table(key is addr) to store all keys, value is following table:\
        --\
        -- key, the key from platform\
        -- lease, lease time\
        -- lastget, the last time of getting this key\
        -- lastupdate, the last time of updating this key\
        -- refresh, the next time of requesting for this key\
        -- valid, key maybe invalid for some reasons\
        -- totalcnt, total update cnt\
        -- pcnt, passive update cnt in thread\
    },\
    cnt = 0,\
    max = 16,\
}\
\
local cachetmp = {\
    -- thread use, when get key from server in thread, it will do two things:\
    --   1. update key to master.\
    --   2. save it in this thread.\
    --      using getkey() to get key in the thread, not using lcmd_client to get key,\
    --      it can decrease the communications with master.\
    -- addr = key\
}\
\
local function kcache_dec(kcache, delcnt)\
    if kcache.cnt < delcnt or delcnt <= 0 then return end\
\
    local tt = {}\
    for k, v in pairs(kcache.keys) do \
        table.insert(tt, {v = v, k = k})\
    end\
\
    table.sort(tt, \
    function(a, b)\
        return a.v.lastupdate < b.v.lastupdate\
    end\
    )\
\
    for i = 1, delcnt do\
        local delkey = tt[i].k\
        kcache.keys[delkey] = nil\
        log.info(\"del_key is \", delkey)\
    end\
    kcache.cnt = kcache.cnt - delcnt\
end\
\
local function update_ckey(isthread, org_addr, item)\
    if isthread then\
        local args = string.format([[{\"subtype\":\"ckey\", \"action\":\"write\", \"isthread\":true, \"addr\":\"%s\", \"key\":\"%s\", \"lease\":%d}]], org_addr, item.key, item.lease)\
        log.info(\"update key\", args)\
        lcmd_client(true, lcmd_tmp_path(\"\"), args)\
        cachetmp[org_addr] = item.key\
    else\
        item[\"addr\"] = org_addr\
        lcmd_run(item)\
    end\
end\
\
local function parse_ckey_json(sock, addr, issync)\
    local action, msg, err = pack.dpi_recv(sock, addr, nil, issync)\
    if err then\
        return err\
    end\
    log.info(\"action = \",action, \"msg=\",msg)\
\
    if action ~= CENUM.COMM_ACTION_RESULT_OK then\
        return \"result not ok\"\
    end\
    if not msg or msg == \"\" then\
        return \"result ok, but response empty msg\"\
    end\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        return \"failed json decode msg, \"..msg..\", err is \"..t\
    end\
    if type(t) ~= \"table\" or #t == 0 then\
        return \"ignore empty json or not table for msg, \"..msg\
    end\
    log.info(string.format(\"receive %s server, action 0x%x, msg(%s)\", addr, action, msg))\
\
    for _, item in ipairs(t) do\
        if item.type and item.type == \"ckey\" and type(item.key) == \"string\" and type(item.lease) == \"number\" then\
           return item\
        end\
    end\
 \
end \
\
local function parse_ckey_pb(sock, addr, issync)\
    local action, msg, err = packpb.dpi_recv(sock, addr, nil, issync)\
    if action == \"ACTION_CKEY_SET\" then\
        local ok, t = pcall(pb.decode, \".plugin.Ckey\", msg)\
        if ok then\
            return t\
        end\
        log.error(\"failed pb decode ckey msg, \", msg, \", err is \", t)\
    end\
    return nil\
end \
\
local function ckey_recvcall(sock, addr, issync, isthread, org_addr)\
    local item = nil\
    if ckey.proto == \"pb\" then\
        item = parse_ckey_pb(sock, addr, issync)\
    else\
        item = parse_ckey_json(sock, addr, issync)\
    end\
    if item then\
        update_ckey(isthread, org_addr, item)\
    end\
   \
    return nil\
end\
\
local function get_ckey_request_addr(addr)\
    local raddr = addr\
    local host, port, sslport = mystring.split(raddr, \":\")\
    if sslport then\
        raddr = host..\":\"..sslport\
    end\
    return raddr\
end\
\
function ckey.sync_request(addr, isthread, packconf)\
    local pconf = packconf or ckey.packconf\
    log.trace(\"ckey.sync_request \"..addr)\
    local buf = \"\"\
    if ckey.proto == \"pb\" then\
        local action = pb.enum(\".plugin.PluginAction\", \"ACTION_CKEY_GET\")\
        buf = packpb.client_pack(pconf, action, \"\", \"\")\
    else\
        buf = pack.client_pack_key(pconf, tlv.write(CENUM.COMM_ACTION_CKEY_GET, \"\"))\
    end\
    local svr, _ = svrcomm.new()\
    local err = svr:syncall(get_ckey_request_addr(addr), 20, buf, nil, true, ckey_recvcall, true, isthread, addr)\
    if err then\
        log.error(addr, \"ckey sync_request failed, \", err)\
    end\
    local key = ckey.getkey(addr, isthread)\
    return key\
end\
\
function ckey.async_request(addr, isthread)\
    log.trace(\"ckey.async_request \"..addr)\
    local action, buf = \"\",\"\"\
    if ckey.proto == \"pb\" then\
        action = pb.enum(\".plugin.PluginAction\", \"ACTION_CKEY_GET\")\
        buf = packpb.client_pack(ckey.packconf, action, \"\", \"\")\
    else\
        action = CENUM.COMM_ACTION_CKEY_GET\
        buf = pack.client_pack_key(ckey.packconf, tlv.write(action, \"\"))\
    end\
\
    local svr, _ = svrcomm.new()\
    svr:init(get_ckey_request_addr(addr), action, true)\
    svr:call(buf, nil, ckey_recvcall, false, isthread, addr)\
end\
\
local function ckey_refresh(kcache)\
    local uptime = ctime.get_uptime()\
    for addr, item in pairs(kcache.keys) do\
        if item.refresh <= uptime then\
            log.trace(\"do ckey.async_request\", addr, cjson.encode(item))\
            item.refresh = item.refresh + math.ceil(item.lease / 2)\
            ckey.async_request(addr)\
        end\
        if item.valid and item.lastupdate + item.lease <= uptime then\
            item.valid = false\
        end\
    end\
end\
\
function ckey.write(t)\
    if type(t.period) == \"number\" and t.period ~= ckey.period then\
        ckey.period = t.period\
        timer.mod(ckey.tname, ckey.period, 0, ckey_refresh, cacheglobal)\
    end\
    if type(t.max) == \"number\" and t.max ~= cacheglobal.max then\
        kcache_dec(cacheglobal, cacheglobal.cnt - t.max)\
        cacheglobal.max = t.max\
    end\
    if type(t.addr) == \"string\" and type(t.key) == \"string\" and type(t.lease) == \"number\" then\
        if not cacheglobal.keys[t.addr] then\
            if cacheglobal.cnt >= cacheglobal.max then\
                kcache_dec(cacheglobal, cacheglobal.cnt - cacheglobal.max + 1)\
            end\
            cacheglobal.keys[t.addr] = { totalcnt = 0, pcnt = 0 }\
            cacheglobal.cnt = cacheglobal.cnt + 1\
        end\
        cacheglobal.keys[t.addr].key = t.key\
        cacheglobal.keys[t.addr].lease = t.lease\
        cacheglobal.keys[t.addr].valid = true\
        local uptime = ctime.get_uptime()\
        cacheglobal.keys[t.addr].lastupdate = uptime\
        cacheglobal.keys[t.addr].refresh = cacheglobal.keys[t.addr].lastupdate + math.ceil(cacheglobal.keys[t.addr].lease / 2)\
        cacheglobal.keys[t.addr].totalcnt = cacheglobal.keys[t.addr].totalcnt + 1\
        if t.isthread then\
            cacheglobal.keys[t.addr].pcnt = cacheglobal.keys[t.addr].pcnt + 1\
        end\
        log.trace(\"ckey write \"..t.addr..\" (\"..t.key..\") \"..tostring(t.lease))\
    end\
end\
\
function ckey.read(t)\
    return { period = ckey.period, cache = cacheglobal }\
end\
\
function ckey.del(t)\
    if type(t.addr) == \"string\" then\
        if cacheglobal.keys[t.addr] then\
            log.trace(\"ckey del \"..t.addr)\
            cacheglobal.keys[t.addr] = nil\
            cacheglobal.cnt = cacheglobal.cnt - 1\
        end\
    end\
end\
\
function ckey.flush(t)\
    cacheglobal.keys = {}\
    cacheglobal.cnt = 0\
    log.warn(\"ckey flush\")\
end\
\
function ckey.request(t)\
    if type(t.addr) == \"string\" then\
        ckey.async_request(t.addr)\
    end\
end\
\
function ckey.getkey(addr, isthread)\
    log.trace(\"ckey.getkey \"..addr..\" ,isthread \"..tostring(isthread))\
    if not isthread then\
        if cacheglobal.keys[addr] and cacheglobal.keys[addr].valid then\
            local uptime = ctime.get_uptime()\
            cacheglobal.keys[addr].lastget = uptime\
            return cacheglobal.keys[addr].key\
        end\
    else\
        if cachetmp[addr] then\
            return cachetmp[addr]\
        end\
    end\
    return nil\
end\
\
function ckey.restart(timer_enable)\
    if timer_enable then\
        timer.mod(ckey.tname, ckey.period, 0, ckey_refresh, cacheglobal)\
    else\
        timer.mod(ckey.tname, 0, 0, ckey_refresh, cacheglobal)\
    end\
end\
\
function ckey.init(enable, packconf, proto)\
    if enable then\
        timer.mod(ckey.tname, ckey.period, 0, ckey_refresh, cacheglobal)\
    end\
    ckey.packconf = packconf\
    ckey.proto = proto\
end\
\
return ckey\
"
, '@'.."./lualib/svrcomm/ckey.lua" ) )

package.preload[ "svrcomm.dpi" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local svrcomm = require\"svrcomm\"\
local packpb = require\"svrcomm.packpb\"\
local pack = require\"svrcomm.pack\"\
local pb = require\"pb\"\
local ckey = require\"svrcomm.ckey\"\
local pth = require\"svrcomm.pth\"\
local cjson = require\"cjson\"\
local ccrypto = require\"c.crypto\"\
local ctime = require\"c.time\"\
local cthread = require\"c.thread\"\
local tlv = require\"tlv\"\
local myip = require\"myip\"\
local mystring = require\"mystring\"\
local timer = require\"timer\"\
local dnscache = require\"dnscache\"\
local mime = require\"mime\"\
local cct_enable, cct = pcall(require, \"c.ct\")\
\
local dpi = {\
    sn = \"\", \
    oui = \"\", \
    int_ver = \"\", \
    snmd5 = \"\",\
    pppoe = nil, \
    loid = \"\",\
    longconn = nil,\
    tname = \"dpilongsock\", \
    dtlc_autoid = 1, -- datalongconn autoid\
\
    use_seconn = false,\
    callcache = {},\
    ccache_tname = \"dpicallcache\",\
    pthtimeout = 300, -- timeout for pthread\
    pthlimit = 3, -- limit pthread for same addr_action\
}\
\
local defpack = {\
    -- used for short-conn and long-conn-ctrl in old version\
    nocipher = false,\
    ziplen = 1024,\
    secmode = false,\
}\
\
local secpack = {\
    -- used for short-conn (except ckey request) in sec mode\
    nocipher = false,\
    ziplen = 1024,\
    secmode = true,\
}\
\
local sslpack = {\
    -- used for ckey request (short-conn) and long-conn-ctrl in sec mode\
    -- used for long-conn-data-upload\
    nocipher = true,\
    ziplen = 1024,\
    secmode = true,\
}\
\
-----------------------------------------------------------------------------\
-- long sock part\
-----------------------------------------------------------------------------\
local function diagnose_deal_reply(addr, action, msg)\
    if not msg or msg == \"\" then\
        log.info(string.format(\"ignore empty msg, action 0x%x\", action))\
        return nil\
    end\
    log.info(string.format(\"receive %s server, action 0x%x, msg(%s)\", addr, action, msg))\
\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        log.error(\"failed json decode msg, \", msg, \", err is \", t)\
        return nil\
    end\
    -- multiple commands ?\
    if type(t) ~= \"table\" or #t ~= 0 then\
        log.info(string.format(\"ignore empty json or not table for msg(%s)\", msg))\
        return nil\
    end\
    local ok, result = lcmd_run(t)\
    return result\
end\
\
local function diagnose_recv(sock, addr, key)\
    local action, msg, err = pack.dpi_recv(sock, addr, key)\
    if err then\
        return nil, err\
    end\
\
    local ok, reply\
    if action == CENUM.COMM_ACTION_DEVOPS_DPI_HEART then\
        reply = \"\"\
    else\
        ok, reply = pcall(diagnose_deal_reply, addr, action, msg)\
        if not ok then\
            log.error(reply)\
        end\
    end\
    local result = {sn = dpi.sn, oui = dpi.oui, int_ver = dpi.int_ver, data = cjson.encode(reply)}\
    local data\
    if not key then\
        data = pack.client_pack_key(sslpack, tlv.write(action, cjson.encode(result)))\
    else\
        data = pack.client_pack_key(defpack, tlv.write(action, cjson.encode(result)), key.key)\
    end\
    return data, err\
end\
\
local function client_recv(sock, addr, key, funcall, ...)\
    if type(funcall) ~= \"function\" then\
        return nil, nil\
    end\
\
    local action, msg, err = pack.dpi_recv(sock, addr, key)\
    if err then\
        return nil, err\
    end\
\
    -- trigger inner module dealing\
    local ok, reply = pcall(funcall, addr, action, msg, ...)\
    if not ok then\
        log.error(reply)\
    end\
    return data, err\
end\
\
local function dtlclient_recv(sock, addr, datasent, finicall, ...)\
    if type(finicall) ~= \"function\" then\
        return nil, nil\
    end\
\
    local action, msg, err = pack.dpi_recv(sock, addr)\
    if err then\
        -- recv failed, maybe connection is closed by remote.\
        -- here, it can not distinguish that it is recving data_response and heart_response.\
        -- so this err will always be processed by finicall.\
        local ok, result = pcall(finicall, err, datasent, ...)\
        if not ok then\
            log.error(result)\
        end\
        return nil, err\
    end\
\
    if action == CENUM.COMM_ACTION_COMMON_HEART then\
        return nil, nil\
    end\
    \
    local errmsg = nil\
    if action ~= CENUM.COMM_ACTION_RESULT_OK then\
        errmsg = \"svr inform data error\"\
    end\
    local ok, err = pcall(finicall, errmsg, datasent, ...)\
    if not ok then\
        log.error(err)\
    end\
    return nil, nil\
end\
\
local function get_dns_str()\
    local str = \"\"\
\
    if cct_enable then\
        local t = cct.getdnsserver()\
        if t.dns then\
            str = t.dns\
        end\
        if t.dns2 and #t.dns2 > 0 then\
            str = str..\",\"..t.dns2\
        end\
    end\
\
    return str\
end\
\
local function pthcall_client_recv(sock, addr, key, id, has_recvcall)\
    local action, msg, err = pack.dpi_recv(sock, addr, key, true)\
    if err then\
        return err\
    end\
    if action ~= CENUM.COMM_ACTION_RESULT_OK then\
        if action == CENUM.COMM_ACTION_RESULT_CKEY_ERROR then\
            return \"RESULT_CKEY_ERROR\"\
        end\
        return \"RESULT_NOT_OK\"\
    end\
\
    if has_recvcall then\
        local resmsg = msg or \"\"\
        if #resmsg > 0 then\
            resmsg = mime.b64(resmsg)\
        end\
        local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pth_recvcall\",\"id\":\"%s\",\"addr\":\"%s\",\"comm_action\":%d,\"msg\":\"%s\"}]],\
                        id, addr, action, resmsg)\
        log.trace(args)\
        lcmd_client(true, lcmd_tmp_path(\"\"), args)\
    end\
\
    return nil\
end\
\
function dpi.pthcall(t)\
    local snmd5 = mime.unb64(t.snmd5)\
    local addr = t.addr\
    local action = t.comm_action\
    local key = t.key\
    local id = t.id\
    local msg = mime.unb64(t.msg)\
    local has_recvcall = t.recvcall == \"function\"\
\
    pack.init(snmd5)\
\
    if not key or #key == 0 then\
        key = nil\
    end\
    local keyreq_cnt = 0\
    local err\
    while true do\
        if not key then\
            if keyreq_cnt >= 1 then\
                err = \"request ckey over limit\"\
                break\
            end\
            key = ckey.sync_request(addr, true, sslpack)\
            keyreq_cnt = keyreq_cnt + 1\
        end\
\
        if key then\
            local buf, realkey = pack.client_pack(secpack, tlv.write(action, msg), key)\
            local svr = svrcomm.new()\
            err = svr:syncall(addr, 10, buf, nil, false, pthcall_client_recv, realkey, id, has_recvcall)\
            if err and err == \"RESULT_CKEY_ERROR\" then\
                log.error(addr..\" ckey(\"..key..\") error\")\
                key = nil\
            else\
                break\
            end\
        end\
    end\
\
    local localaddr = svrcomm.get_localaddr()\
    local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pth_finicall\",\"localaddr\":\"%s\",\"id\":\"%s\",\"err\":\"%s\"}]],\
                localaddr, id, err or \"\")\
    log.trace(args)\
    lcmd_client(true, lcmd_tmp_path(\"\"), args)\
\
    return\
end\
\
function dpi.pth_recvcall(t)\
    local id = t.id\
\
    if dpi.callcache[id] and dpi.callcache[id].recvcall then\
        local addr = t.addr\
        local action = t.comm_action\
        local msg = t.msg\
        if #msg > 0 then\
            msg = mime.unb64(msg)\
        end\
        local ok, reply = pcall(dpi.callcache[id].recvcall, addr, action, msg, table.unpack(dpi.callcache[id].recvargs))\
        if not ok then\
            log.error(reply)\
        end\
    end\
end\
\
function dpi.pth_finicall(t)\
    local localaddr = t.localaddr\
    if localaddr and #localaddr > 0 then\
        svrcomm.set_localaddr(localaddr)\
    end\
\
    local id = t.id\
    if dpi.callcache[id] and dpi.callcache[id].finicall then\
        local err = t.err\
        if #err == 0 then\
            err = nil\
        end\
        local ok, reply = pcall(dpi.callcache[id].finicall, err, dpi.callcache[id].data)\
        if not ok then\
            log.error(reply)\
        end\
    end\
\
    dpi.callcache[id] = nil -- need clean\
end\
\
function dpi.pthcallcache_stat()\
    local stat = {}\
    for id, item in pairs(dpi.callcache) do\
        stat[id] = {}\
        for k, v in pairs(item) do\
            if type(v) == \"table\" then\
                stat[id][k] = {}\
                for i, e in pairs(v) do\
                    stat[id][k][i] = tostring(e)\
                end\
            elseif type(v) == \"string\" then\
                stat[id][k..\"len\"] = tostring(#v)\
            else\
                stat[id][k] = tostring(v)\
            end\
        end\
    end\
    return stat\
end\
\
local function callcache_timeout()\
    local uptime = ctime.get_uptime()\
\
    for id, _ in pairs(dpi.callcache) do\
        if dpi.callcache[id].btime + dpi.pthtimeout <= uptime then\
            log.error(id..\" call timeout\")\
            if dpi.callcache[id].finicall then\
                dpi.callcache[id].finicall(\"call timeout\", dpi.callcache[id].data)\
            end\
            dpi.callcache[id] = nil\
        end\
    end\
end\
\
local function pthrun(addr, action, data, finicall, recvcall, ...)\
    local addrport = dnscache.get_set(addr)\
    if type(addrport) ~= \"string\" then\
        if type(finicall) == \"function\" then\
            finicall(\"failed find IP for dns\", data)\
        end\
        return\
    end\
\
    local idpre = addr..\"_\"..string.format(\"%02x\",action)..\"_\"\
    local scount = 0\
    for k, _ in pairs(dpi.callcache) do\
        if #idpre <= #k then\
            local pre = string.sub(k, 1, #idpre)\
            if pre == idpre then\
                scount = scount + 1\
            end\
        end\
    end\
    if scount >= dpi.pthlimit then\
        if type(finicall) == \"function\" then\
            finicall(\"same addr_action over limit\", data)\
            log.error(idpre..\" has \"..tostring(dpi.pthlimit)..\" running pth\")\
        end\
        return \
    end\
\
    local uptime, uptimens = ctime.get_uptime()\
    local id = idpre..tostring(uptime)..\"_\"..tostring(uptimens)\
    dpi.callcache[id] = { btime = uptime, data = data, finicall = finicall, recvcall = recvcall, recvargs = {...} }\
    local key = ckey.getkey(addrport)\
    local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pthcall\",\"snmd5\":\"%s\",\"id\":\"%s\",\"addr\":\"%s\",\"comm_action\":%d,\"key\":\"%s\",\"recvcall\":\"%s\",\"msg\":\"%s\"}]], \
                    mime.b64(dpi.snmd5), id, addrport, action, key or \"\", type(recvcall), mime.b64(data))\
    log.trace(args)\
    cthread.run(args)\
end\
\
-- TODO protobuf recv 平台下发配置需要实现\
function dpi.pb_asyncall(addr, use_seconn, action, data, finicall, recvcall, ...)\
    -- get localaddr\
    local svr, localaddr = svrcomm.new()\
    local pb_action = pb.enum(\".plugin.PluginAction\", action)\
    local mmsg = {sn = dpi.sn, oui = dpi.oui, int_ver = dpi.int_ver, ad = dpi.pppoe, loid = dpi.loid, ipv4 = localaddr, data = data}\
    local pb_data = pb.encode(\".plugin.ClientMsgs\", mmsg)\
\
    log.info(string.format(\"will send to %s with buf len %d\", addr, #pb_data))\
\
    if use_seconn then\
        pth.pb_pthrun(addr, pb_action, pb_data, finicall, recvcall, ...)\
        return\
    end\
\
    local buf, realkey = packpb.client_pack(secpack, pb_action, pb_data)\
\
    svr:init(dnscache.get_set(addr), pb_action)\
    svr:call(buf, finicall, pb_client_recv, key, recvcall, ...)\
\
end\
\
function dpi.async_call(addr, action, data, finicall, recvcall, ...)\
    local svr, localaddr = svrcomm.new()\
    local msg = string.format('{\"data\":%s,\"sn\":\"%s\",\"oui\":\"%s\",\"int_ver\":\"%s\",\"ad\":\"%s\", \"ipv4\":\"%s\", \"loid\":\"%s\"}',\
                              data, dpi.sn, dpi.oui, dpi.int_ver, dpi.pppoe, localaddr, dpi.loid)\
    if dpi.use_seconn then\
        pthrun(addr, action, msg, finicall, recvcall, ...)\
        return\
    end\
\
    local buf, key = pack.client_pack(defpack, tlv.write(action, msg))\
\
    svr:init(dnscache.get_set(addr), action)\
    log.info(string.format(\"will send to %s with buf len %d\", addr, #buf))\
    svr:call(buf, finicall, client_recv, key, recvcall, ...)\
    -- svr:free(), MUST NOT FREE HERE\
end\
\
function dpi.async_dmp_send(addr, msg, finicall, ...)\
    local svr, localaddr = svrcomm.new()\
\
    -- prepair buf to send\
    local sbytes = \"\" ipbyte = \"\"\
    if localaddr ~= \"\" then\
        ipbyte = myip.inet_aton(localaddr)\
    else\
        ipbyte = string.rep(\"\\x00\", 4)\
    end\
    sbytes = tlv.write(CENUM.COMM_BUSINESS_SN, dpi.sn)..tlv.write(CENUM.COMM_BUSINESS_OUI, dpi.oui)..tlv.write(CENUM.COMM_BUSINESS_IPv4_MAC, ipbyte..\"\\x00\\x00\"..dpi.mac)\
    if dpi.pppoe then\
        sbytes = sbytes..tlv.write(CENUM.COMM_BUSINESS_PPPOE_ACCOUNT, dpi.pppoe)\
    end\
    \
    if dpi.use_seconn then\
        pthrun(addr, CENUM.COMM_ACTION_UPLOAD, sbytes..msg, finicall)\
        return\
    end\
\
    local buf = pack.client_pack(defpack, tlv.write(CENUM.COMM_ACTION_UPLOAD, sbytes..msg))\
\
    svr:init(dnscache.get_set(addr), CENUM.COMM_ACTION_UPLOAD)\
    svr:call(buf, finicall)\
end\
\
function dpi.async_dmp_send_json(addr, action, data, finicall)\
    local svr, localaddr = svrcomm.new()\
    local msg = string.format('{\"customer\":\"%s\",\"mac\":\"%s\", \"ipv4\":\"%s\", \"ad\":\"%s\", \"loid\":\"%s\",\"dns\":\"%s\",\"v\":%s}',\
                                dpi.oui, mystring.data2hex(dpi.mac,\":\"), localaddr, dpi.pppoe or \"\", dpi.loid, get_dns_str(), data)\
    \
    if dpi.use_seconn then\
        pthrun(addr, action, msg, finicall)\
        return\
    end\
\
    local buf, key = pack.client_pack(defpack, tlv.write(action, msg))\
\
    svr:init(dnscache.get_set(addr), action)\
    log.info(string.format(\"will send json to %s with buf len %d\", addr, #buf))\
    svr:call(buf, finicall)\
    -- svr:free(), MUST NOT FREE HERE\
    return svr\
end\
\
function dpi.syncall(addr, action, data)\
    local svr, localaddr = svrcomm.new()\
    local msg = string.format('{\"customer\":\"%s\",\"mac\":\"%s\", \"ipv4\":\"%s\", \"ad\":\"%s\", \"loid\":\"%s\", \"v\":%s, \"time\":\"%d\"}',\
                              dpi.oui, mystring.data2hex(dpi.mac,\":\"), localaddr, dpi.pppoe or \"\", dpi.loid, data, os.time())\
    \
    if dpi.use_seconn then\
        pthrun(addr, action, msg)\
        return\
    end\
\
    local buf, key = pack.client_pack(defpack, tlv.write(action, msg))\
\
    log.info(string.format(\"sync send json to %s with buf len %d\", addr, #buf))\
    return svr:syncall(dnscache.get_set(addr), 180, buf) -- default timeout is 180s\
    --svr:syncall(addr, 30, buf, finicall, sip)\
end\
\
local function longconn_timer(svr, addr, data, key)\
    if not svr:running() then\
        log.warn(\"will reconnect long sock, addr is \", addr)\
        svr:init_long(dnscache.get_set(addr), data, diagnose_recv, key)\
    end\
end\
\
function dpi.longconn_start(addr, sslflag)\
    if dpi.longconn then\
        log.info(\"long connection already started\")\
        return\
    end\
\
    local svr, localaddr = svrcomm.new()\
    local action = CENUM.COMM_ACTION_DEVOPS_DPI_INIT\
    local msg = string.format('{\"data\":[],\"sn\":\"%s\",\"oui\":\"%s\",\"int_ver\":\"%s\", \"ipv4\":\"%s\"}', \
                              dpi.sn, dpi.oui, dpi.int_ver, localaddr)\
    local hello_data, key\
    if sslflag then\
        hello_data = pack.client_pack(sslpack, tlv.write(action, msg))\
    else\
        hello_data, key = pack.client_pack(defpack, tlv.write(action, msg))\
    end\
\
    svr:init_long(dnscache.get_set(addr), hello_data, diagnose_recv, key)\
    dpi.longconn = { svr = svr, addr = addr, sslflag = sslflag }\
    -- using 10 secs to reconnect long sock\
    timer.mod_notdisable(dpi.tname, 10, 0, longconn_timer, svr, addr, hello_data, key)\
end\
\
function dpi.longconn_show()\
    local svr\
    if dpi.longconn then\
        svr = dpi.longconn.svr\
    end\
    if svr then\
        return svr:show()\
    else\
        return {enable = false}\
    end\
end\
\
function dpi.longconn_stop()\
    log.warn(\"long connection stopped\", dpi.longconn)\
    timer.del(dpi.tname)\
    if dpi.longconn then\
        dpi.longconn.svr:free()\
        dpi.longconn = nil\
    end\
end\
\
local function datalongconn_pack_store(dtlc)\
    local msg\
    if dtlc.isjson then\
        -- notice: format not in common use\
        local datastr = cjson.encode(dtlc.data)\
        msg = string.format('{\"data\":%s,\"sn\":\"%s\",\"oui\":\"%s\",\"int_ver\":\"%s\",\"ad\":\"%s\",\"loid\":\"%s\",\"ipv4\":\"%s\"}',\
        datastr, dpi.sn, dpi.oui, dpi.int_ver, dpi.pppoe, dpi.loid, dtlc.localaddr)\
    else\
        -- notice: not test\
        local sbytes = \"\" ipbyte = \"\"\
        if dtlc.localaddr ~= \"\" then\
            ipbyte = myip.inet_aton(dtlc.localaddr)\
        else\
            ipbyte = string.rep(\"\\x00\", 4)\
        end\
        sbytes = tlv.write(CENUM.COMM_BUSINESS_SN, dpi.sn)..tlv.write(CENUM.COMM_BUSINESS_OUI, dpi.oui)..tlv.write(CENUM.COMM_BUSINESS_IPv4_MAC, ipbyte..\"\\x00\\x00\"..dpi.mac)\
        if dpi.pppoe then\
            sbytes = sbytes..tlv.write(CENUM.COMM_BUSINESS_PPPOE_ACCOUNT, dpi.pppoe)\
        end\
        msg = sbytes..dtlc.data\
    end\
    local buf = pack.client_pack(sslpack, tlv.write(dtlc.action, msg))\
    return buf\
end\
\
local function datalongconn_reset_store(dtlc)\
    dtlc.datalen = 0\
    if dtlc.isjson then\
        dtlc.data = {}\
    else\
        dtlc.data = \"\"\
    end\
end\
\
local function datalongconn_timer(dtlc)\
    local need_reconn = false\
    local uptime = ctime.get_uptime()\
\
    if not dtlc.svr:running() then\
        need_reconn = true\
    elseif dtlc.svr:getstatus() ~= \"waiting\" then\
        if dtlc.lastsendtime + 30 < uptime then\
            log.warn(\"datalong has not be ready for a long time, addr is \"..dtlc.addr)\
            need_reconn = true\
        end\
    end\
\
    if need_reconn then\
        log.warn(\"will reconnect datalong sock, addr is \"..dtlc.addr)\
        dtlc.svr:free()\
        local svr, localaddr = svrcomm.new()\
        svr:init_datalong(dnscache.get_set(dtlc.addr), dtlclient_recv, dtlc.finicall)\
        dtlc.svr = svr\
        dtlc.localaddr = localaddr\
    elseif dtlc.svr:getstatus() == \"waiting\" then\
        local buf = \"\"\
        if dtlc.datalen > 0 then\
            buf = datalongconn_pack_store(dtlc)\
            datalongconn_reset_store(dtlc)\
        elseif dtlc.lastsendtime + 120 < uptime then\
            buf = pack.client_pack(sslpack, tlv.write(CENUM.COMM_ACTION_COMMON_HEART, \"\"))\
        end\
        if #buf > 0 then\
            dtlc.lastsendtime = uptime\
            local err = dtlc.svr:datalong_send(buf)\
            if err then\
                dtlc.finicall(\"send failed\", buf)\
            end\
        end\
    end\
end\
\
local function datalongconn_get_autoid()\
    local pid = dpi.dtlc_autoid\
    dpi.dtlc_autoid = dpi.dtlc_autoid + 1\
    return pid\
end\
\
function dpi.datalongconn_start(addr, action, limit, isjson, finicall)\
    if type(finicall) ~= \"function\" then\
        return nil, \"no finicall\"\
    end\
\
    local dtlc = {\
        addr = addr,\
        action = action,\
        limit = limit,\
        isjson = isjson,\
        finicall = finicall,\
        lastsendtime = 0,\
    }\
    datalongconn_reset_store(dtlc)\
\
    local svr, localaddr = svrcomm.new()\
    svr:init_datalong(dnscache.get_set(dtlc.addr), dtlclient_recv, dtlc.finicall)\
    dtlc.svr = svr\
    dtlc.localaddr = localaddr\
\
    local uptime = ctime.get_uptime()\
    dtlc.tname = string.format(\"datalong_%s_%02x_%d_%d\", dtlc.addr, action, datalongconn_get_autoid(), uptime)\
    timer.mod_notdisable(dtlc.tname, 10, 0, datalongconn_timer, dtlc)\
\
    return dtlc, nil\
end\
\
function dpi.datalongconn_send(dtlc, data)\
    local send_not_ready = false\
\
    if not dtlc.svr:running() or dtlc.svr:getstatus() ~= \"waiting\" then\
        send_not_ready = true\
        if dtlc.datalen >= dtlc.limit then\
            local strdata = dtlc.isjson and cjson.encode(data) or data\
            dtlc.finicall(\"cache buf full\", strdata)\
            return\
        end\
    end\
\
    if dtlc.isjson then\
        table.insert(dtlc.data, data)\
        dtlc.datalen = dtlc.datalen + 1\
    else\
        dtlc.data = dtlc.data .. data\
        dtlc.datalen = dtlc.datalen + #data\
    end\
\
    if send_not_ready then\
        return\
    end\
\
    local buf = datalongconn_pack_store(dtlc)\
    datalongconn_reset_store(dtlc)\
    dtlc.lastsendtime = ctime.get_uptime()\
    local err = dtlc.svr:datalong_send(buf)\
    if err then\
        dtlc.finicall(\"send failed\", buf)\
        return\
    end\
end\
\
function dpi.datalongconn_show(dtlc)\
    local stat = {\
        addr = dtlc.addr, \
        action = dtlc.action, \
        limit = dtlc.limit, \
        isjson = dtlc.isjson,\
        storelen = dtlc.datalen,\
        lastsendtime = dtlc.lastsendtime,\
        tname = dtlc.tname,\
        svr = dtlc.svr:show(),\
    }\
    return stat\
end\
\
function dpi.datalongconn_stop(dtlc)\
    log.warn(\"datalong connection stopped \"..dtlc.tname)\
    timer.del(dtlc.tname)\
    if dtlc.svr then\
        dtlc.svr:free()\
        dtlc.svr = nil\
    end\
end\
\
function dpi.set_pppoe(pppoe)\
    dpi.pppoe = pppoe\
end\
\
function dpi.set_loid(loid)\
    dpi.loid = loid\
end\
\
function dpi.init(sn, oui, int_ver, mac)\
    dpi.sn = sn\
    dpi.oui = oui\
    dpi.int_ver = int_ver\
    dpi.mac = mac\
    dpi.snmd5 = ccrypto.md5(dpi.sn)\
\
    math.randomseed(os.time())\
\
    pack.init(dpi.snmd5)\
    pth.init(dpi.snmd5)\
    packpb.init(dpi.snmd5)\
    ckey.init(dpi.use_seconn, sslpack)\
    dnscache.new(10, 86400)\
    log.warn(\"init with dcache\")\
\
    timer.mod_notdisable(dpi.ccache_tname, 60, 0, callcache_timeout)\
end\
\
function dpi.dcache_stat()\
    return dnscache.stat()\
end\
\
function dpi.dcache_restart(t)\
    dnscache.restart(t.max, t.cycle)\
end\
\
function dpi.write(t)\
    if type(t.use_seconn) == \"boolean\" and t.use_seconn ~= dpi.use_seconn then\
        dpi.use_seconn = t.use_seconn\
        ckey.restart(dpi.use_seconn)\
    end\
    if type(t.pthlimit) == \"number\" and t.pthlimit ~= dpi.pthlimit then\
        dpi.pthlimit = t.pthlimit\
    end\
    if type(t.pthtimeout) == \"number\" and t.pthtimeout ~= dpi.pthtimeout then\
        dpi.pthtimeout = t.pthtimeout\
    end\
end\
\
function dpi.read(t)\
    return { use_seconn = dpi.use_seconn, pthlimit = dpi.pthlimit, pthtimeout = dpi.pthtimeout }\
end\
\
return dpi\
"
, '@'.."./lualib/svrcomm/dpi.lua" ) )

package.preload[ "svrcomm.pack" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local ccrypto = require\"c.crypto\"\
local tlv = require\"tlv\"\
local msocket = require\"msocket\"\
\
\
local pack = {\
    snmd5 = \"\"\
}\
\
local dpi_type = {\
\9typeCipher  = 0x01, \
\9typeSNMD5   = 0x02, \
\9typeKey     = 0x03, \
\9typePlain   = 0x04, \
\9typeTime    = 0x05, \
\9typeVersion = 0x06, \
}\
\
function pack.client_pack_key(packconf, msg, key, ckey)\
    -- try zip\
    if packconf.ziplen > 0 and #msg > packconf.ziplen then\
        local zipdata = ccrypto.zip(msg, #msg)\
        if zipdata then\
            log.info(string.format(\"using gzip ziplen(%d), origlen(%d)\", #zipdata, #msg))\
            msg = tlv.write(CENUM.COMM_ACTION_GZIP_ACTION, string.pack(\">I\", #msg)..zipdata)\
        else\
            log.error(string.format(\"failed to zip, origlen(%d)\", #msg))\
        end\
    end\
\
    local buf = tlv.write(dpi_type.typeSNMD5, pack.snmd5)\
    local encinfo\
    if packconf.secmode then\
        buf = buf..tlv.write_uint32(dpi_type.typeVersion, 0x02020309)\
    else\
        buf = buf..tlv.write_uint32(dpi_type.typeVersion, 0x01020309)\
    end\
    buf = buf..tlv.write_uint32(dpi_type.typeTime, os.time())\
\
    if not packconf.nocipher then\
        if ckey then\
            encinfo = { key = ckey, needmd5 = false, mode = \"cbc\" } \
        else\
            encinfo = { key = key, needmd5 = true, mode = \"ecb\" } \
        end\
        local cipherkey = encinfo.key\
        if encinfo.needmd5 then\
            cipherkey = ccrypto.md5(cipherkey)\
        end\
        local cipherdata = ccrypto.encrypt(msg, cipherkey, encinfo.mode)\
        buf = buf..tlv.write(dpi_type.typeCipher, cipherdata)\
        buf = buf..tlv.write(dpi_type.typeKey, key)\
    else\
        buf = buf..tlv.write(dpi_type.typePlain, msg)\
    end\
    local alllen = #buf + 8\
    buf = string.pack(\">II\", 0x20141028, alllen)..buf\
    return buf, encinfo\
end\
\
function pack.client_pack(packconf, msg, ckey)\
    local key\
    if not packconf.nocipher then\
        local v = math.random(2^31 - 1)\
        key = string.pack(\">IIII\", v, v, v, v)\
    end\
    return pack.client_pack_key(packconf, msg, key, ckey)\
end\
\
local function dpi_extract_gzip(value)\
    if #value <= 4 then\
        return 0, nil\
    end\
\
    local max, nextpos = string.unpack(\">I\", value)\
    local data = ccrypto.unzip(string.sub(value, nextpos, -1), max)\
    if not data then \
        return 0, nil\
    end\
\
    local action, msg = tlv.read(data)\
    log.info(string.format(\"action is 0x%X, msg is %s\", action, msg))\
    return action, msg\
end\
\
local function dpi_extract(buf, encinfo)\
    local map = {} nnext = 1 len = #buf\
    while nnext < len do\
        local ttype, value, nn = tlv.read(buf, nnext)\
        map[ttype] = value\
        nnext = nnext + nn\
    end\
\
    if nnext ~= len + 1 then\
        return nil, nil, string.format(\"wrong format nnext(%d), len(%d)\", nnext, len)\
    end\
\
    local plain = map[dpi_type.typePlain]\
    local cipher = map[dpi_type.typeCipher]\
    if not plain and not cipher then\
        return nil, nil, string.format(\"no cipher or plain\")\
    end\
\
    if cipher then\
        if not encinfo then\
            return nil, nil, string.format(\"should not be cipher\")\
        end\
        log.trace(\"dpi extract encinfo, key(\"..encinfo.key..\") needmd5(\"..tostring(encinfo.needmd5)..\") mode(\"..encinfo.mode..\")\")\
        local cipherkey = encinfo.key\
        if encinfo.needmd5 then\
            cipherkey = ccrypto.md5(cipherkey)\
        end\
        plain = ccrypto.decrypt(cipher, cipherkey, encinfo.mode)\
    end\
    \
    local ttype, value, nn = tlv.read(plain)\
    log.trace(\"dpi extract ttype \", ttype, \", len \", #value)\
    if ttype == CENUM.COMM_ACTION_GZIP_ACTION then\
        return dpi_extract_gzip(value)\
    end\
    return ttype, value\
end\
\
function pack.dpi_recv(sock, addr, encinfo, issync)\
    -- read dpi head\
    local buf, err\
    if issync then\
        buf, err = sock:receive(8)\
    else\
        buf, err = msocket.polite_receive(sock, 8)\
    end\
    log.trace(\"dpi after read head, err is\", err)\
    if err then\
        if err == \"closed\" then\
            return nil, nil, err\
        end\
\
        local emsg = \"failed to read server dpi header, err is \"..err\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
    local magic, alllen = string.unpack(\">II\", buf)\
    if magic ~= 0x20141028 or alllen <= 0 or alllen >= 10000000 then\
        local emsg = string.format(\"wrong magic(%x) or alllen(%d) for dpi header\", magic, alllen)\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
\
    -- read dpi body\
    if issync then\
        buf, err = sock:receive(alllen - 8)\
    else\
        buf, err = msocket.polite_receive(sock, alllen - 8)\
    end\
    log.trace(\"dpi after read body, err is\", err)\
    if err then\
        local emsg = \"failed to read server dpi body, err is \"..err\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
\
    -- extract action and msg\
    local action, msg, err = dpi_extract(buf, encinfo)\
    if err then\
        local emsg = \"failed to extract server dpi body, err is \"..err\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
\
    return action, msg, nil\
end\
\
function pack.init(snmd5)\
    pack.snmd5 = snmd5\
end\
\
return pack\
\
\
"
, '@'.."./lualib/svrcomm/pack.lua" ) )

package.preload[ "svrcomm.packpb" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local ccrypto = require\"c.crypto\"\
local msocket = require\"msocket\"\
local pb = require\"pb\"\
local mystring = require\"mystring\"\
\
local MAGIC = 0x20210419\
\
local packpb = {\
    snmd5 = \"\"\
}\
\
function packpb.client_pack_key(packconf, action, msg, key, ckey)\
    local pbytes = {\
        uncipherlen = 0,\
        snmd5 = packpb.snmd5,\
        key = \"\",\
        time = os.time(),\
        version = 0x03000001,   -- new version for protobuf\
        action = action,\
        unziplen = 0, \
        msg = msg, \
    }            -- protobuf bytes\
    local data = msg\
    -- try zip\
    if packconf.ziplen > 0 and #msg > packconf.ziplen then\
        local zipdata = ccrypto.zip(msg, #msg)\
        if zipdata then\
            log.info(string.format(\"using gzip ziplen(%d), origlen(%d)\", #zipdata, #msg))\
            pbytes.unziplen = #msg\
            pbytes.msg = zipdata\
        else\
            log.error(string.format(\"failed to zip, origlen(%d)\", #msg))\
        end\
    end\
\
    if not packconf.nocipher then\
        if ckey then\
            encinfo = { key = ckey, needmd5 = false, mode = \"cbc\" }\
        else\
            encinfo = { key = key, needmd5 = true, mode = \"ecb\" }\
        end\
        local cipherkey = encinfo.key\
        if encinfo.needmd5 then\
            cipherkey = ccrypto.md5(cipherkey)\
        end\
        local cipherdata = ccrypto.encrypt(pbytes.msg, cipherkey, encinfo.mode)\
        pbytes.uncipherlen = #pbytes.msg\
        pbytes.key = key\
        pbytes.msg = cipherdata\
    end\
\
    local buf = pb.encode(\".plugin.PluginPkt\", pbytes)\
    local alllen = #buf + 8\
    return string.pack(\">II\", MAGIC, alllen)..buf, encinfo\
end\
\
function packpb.client_pack(packconf, action, msg, ckey)\
    local key\
    if not packconf.nocipher then\
        local v = math.random(2^31 - 1)\
        key = string.pack(\">IIII\", v, v, v, v)\
    end\
    return packpb.client_pack_key(packconf, action, msg, key, ckey)\
end\
\
local function dpi_extract(buf, encinfo)\
    local ok, pkt = pcall(pb.decode, \".plugin.PluginPkt\", buf)\
    if not ok then\
        return 0, nil, string.format(\"wrong format for pb decode pkt, \", pkt)\
    end\
\
    local plain = pkt.msg\
    if pkt.uncipherlen > 0 then\
        if not encinfo or pkt.uncipherlen < #plain then\
            return 0, nil, string.format(\"should not be cipher, or wrong uncipherlen %d msg len %d\", pkt.uncipherlen, #plain)\
        end\
        log.trace(\"dpi extract encinfo, key(\"..encinfo.key..\") needmd5(\"..tostring(encinfo.needmd5)..\") mode(\"..encinfo.mode..\")\")\
        local cipherkey = encinfo.key\
        if encinfo.needmd5 then\
            cipherkey = ccrypto.md5(cipherkey)\
        end\
        plain = ccrypto.decrypt(cipher, cipherkey, encinfo.mode)\
        plain = plain:sub(1, pkt.uncipherlen)\
    end\
\
    log.trace(\"dpi extract action \", pkt.action, \", len \", #pkt.msg)\
    if pkt.unziplen > 0 then\
        local data = ccrypto.unzip(pkt.msg, pkt.unziplen + 1)\
        if not data or #data ~= pkt.unziplen then \
            return 0, nil, string.format(\"failed to unzip, or mismatch unziplen %d with data %d\", unziplen, #data)\
        end\
        return pkt.action, data\
    end\
    return pkt.action, pkt.msg\
end\
\
function packpb.dpi_recv(sock, addr, encinfo, issync)\
    -- read dpi head\
    local buf, err\
    if issync then\
        buf, err = sock:receive(8)\
    else\
        buf, err = msocket.polite_receive(sock, 8)\
    end\
    log.trace(\"dpi after read head, err is\", err)\
    if err then\
        if err == \"closed\" then\
            return nil, nil, err\
        end\
\
        local emsg = \"failed to read server dpi header, err is \"..err\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
    local magic, alllen = string.unpack(\">II\", buf)\
    if magic ~= MAGIC or alllen <= 0 or alllen >= 10000000 then\
        local emsg = string.format(\"wrong magic(%x) or alllen(%d) for dpi header\", magic, alllen)\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
\
    -- read dpi body\
    if issync then\
        buf, err = sock:receive(alllen - 8)\
    else\
        buf, err = msocket.polite_receive(sock, alllen - 8)\
    end\
    log.trace(\"dpi after read body, err is\", err)\
    if err then\
        local emsg = \"failed to read server dpi body, err is \"..err\
        log.error(emsg)\
        return nil, nil, emsg\
    end\
\
    -- extract action and msg\
    local action, msg, err = dpi_extract(buf, encinfo)\
    if err then\
        local emsg = \"failed to extract server dpi body, err is \"..err\
        log.error(emsg)\
        mystring = require\"mystring\"\
        log.error(\"buf len is \", alllen, buf:len(), mystring.data2hex(buf))\
        return nil, nil, emsg\
    end\
\
    return action, msg, nil\
end\
\
function packpb.init(snmd5)\
    packpb.snmd5 = snmd5\
end\
\
return packpb\
"
, '@'.."./lualib/svrcomm/packpb.lua" ) )

package.preload[ "svrcomm.pth" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local actor = require\"luactor\"\
local svrcomm = require\"svrcomm\"\
local pack = require\"svrcomm.pack\"\
local packpb = require\"svrcomm.packpb\"\
local ckey = require\"svrcomm.ckey\"\
local ctime = require\"c.time\"\
local cthread = require\"c.thread\"\
local tlv = require\"tlv\"\
local timer = require\"timer\"\
local dnscache = require\"dnscache\"\
local mime = require\"mime\"\
\
\
local pth = {\
    snmd5 = \"\",\
    timeout = 300, \9-- timeout for pthread\
    limit = 3, \9-- limit pthread for same addr_action\
    callcache = {},\
    ccache_tname = \"pthcallcache\",\
    -- type = \"pb\"\
}\
\
local sslpack = {\
    -- used for ckey request (short-conn) and long-conn-ctrl in sec mode\
    -- used for long-conn-data-upload\
    nocipher = true,\
    ziplen = 1024,\
    secmode = true,\
}\
\
local secpack = {\
    -- used for short-conn (except ckey request) in sec mode\
    nocipher = false,\
    ziplen = 1024,\
    secmode = true,\
}\
\
function pth.init(snmd5)\
    pth.snmd5 = snmd5\
    timer.mod_notdisable(pth.ccache_tname, 60, 0, callcache_timeout)\
    --timer.mod(pth.ccache_tname, 20, 0, callcache_timeout)\
end\
\
-- protobuf\
local function pb_client_recv(sock, addr, key, id, has_recvcall)\
    local action, msg, err = packpb.dpi_recv(sock, addr, key, true)\
    if err then\
        return err\
    end\
    if action == \"ACTION_CKEY_ERROR\" then\
        return \"RESULT_CKEY_ERROR\"\
    elseif action ~= \"ACTION_SERVER_OK\" then\
        return \"RESULT_NOT_OK\"\
    end\
\
    if has_recvcall then\
        local resmsg = msg or \"\"\
        if #resmsg > 0 then\
            resmsg = mime.b64(resmsg)\
        end\
        local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pth_recvcall\",\"id\":\"%s\",\"addr\":\"%s\",\"comm_action\":\"%s\",\"msg\":\"%s\"}]],\
                        id, addr, action, resmsg)\
        log.trace(args)\
        lcmd_client(true, lcmd_tmp_path(\"\"), args)\
    end\
\
    return nil\
end\
\
local function client_recv(sock, addr, key, id, has_recvcall)\
    local action, msg, err = pack.dpi_recv(sock, addr, key, true)\
    if err then\
        return err\
    end\
    if action ~= CENUM.COMM_ACTION_RESULT_OK then\
        if action == CENUM.COMM_ACTION_RESULT_CKEY_ERROR then\
            return \"RESULT_CKEY_ERROR\"\
        end\
        return \"RESULT_NOT_OK\"\
    end\
\
    if has_recvcall then\
        local resmsg = msg or \"\"\
        if #resmsg > 0 then\
            resmsg = mime.b64(resmsg)\
        end\
        local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pth_recvcall\",\"id\":\"%s\",\"addr\":\"%s\",\"comm_action\":%d,\"msg\":\"%s\"}]],\
                        id, addr, action, resmsg)\
        log.trace(args)\
        lcmd_client(true, lcmd_tmp_path(\"\"), args)\
    end\
\
    return nil\
end\
\
function pth.call(t)\
    local snmd5 = mime.unb64(t.snmd5)\
    local addr = t.addr\
    local action = t.comm_action\
    local key = t.key\
    local id = t.id\
    local msg = mime.unb64(t.msg)\
    local has_recvcall = t.recvcall == \"function\"\
    local proto = t.proto\
\
    -- enable it just when debug\
    --log.lineinfo = true\
\
    pack.init(snmd5)\
    packpb.init(snmd5)\
\
    if not key or #key == 0 then\
        key = nil\
    end\
    local keyreq_cnt = 0\
    local err\
    local buf_len = #msg\
    while true do\
        if not key then\
            if keyreq_cnt >= 1 then\
                err = \"request ckey over limit\"\
                break\
            end\
            key = ckey.sync_request(addr, true, sslpack)\
            log.trace(\"get ckey from \",addr, \"ckey = \", key)\
            keyreq_cnt = keyreq_cnt + 1\
        end\
\
        if key then\
            local svr = svrcomm.new()\
            local buf, realkey = \"\", \"\"\
            if proto == \"pb\" then\
                buf, realkey = packpb.client_pack(secpack, action, msg, key)\
                err = svr:syncall(addr, 10, buf, nil, false, pb_client_recv, realkey, id, has_recvcall)\
            else\
                buf, realkey = pack.client_pack(secpack, tlv.write(action, msg), key)\
                err = svr:syncall(addr, 10, buf, nil, false, client_recv, realkey, id, has_recvcall)\
            end\
            buf_len = #buf\
            if err and err == \"RESULT_CKEY_ERROR\" then\
                log.error(addr..\" ckey(\"..key..\") error\")\
                key = nil\
            else\
                break\
            end\
        end\
    end\
\
    local localaddr = svrcomm.get_localaddr()\
    local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pth_finicall\",\"localaddr\":\"%s\",\"id\":\"%s\",\"err\":\"%s\",\"data_len\":%d}]],\
                localaddr, id, err or \"\", buf_len)\
    log.trace(args)\
    lcmd_client(true, lcmd_tmp_path(\"\"), args)\
\
    return\
end\
\
function callcache_timeout()\
    local uptime = ctime.get_uptime()\
\
    for id, _ in pairs(pth.callcache) do\
        if pth.callcache[id].btime + pth.timeout <= uptime then\
            if pth.callcache[id].finicall then\
                log.trace(\"do finicall\")\
                pth.callcache[id].finicall(\"call timeout\", pth.callcache[id].data)\
            end\
            pth.callcache[id] = nil\
        end\
    end\
end\
\
local function run(proto, addr, action, data, finicall, recvcall, ...)\
    local addrport = dnscache.get_set(addr)\
    if type(addrport) ~= \"string\" then\
        if type(finicall) == \"function\" then\
            finicall(\"failed find IP for dns\", data)\
        end\
        return\
    end\
\
    local idpre = addr..\"_\"..string.format(\"%02x\",action)..\"_\"\
    local scount = 0\
    for k, _ in pairs(pth.callcache) do\
        if #idpre <= #k then\
            local pre = string.sub(k, 1, #idpre)\
            if pre == idpre then\
                scount = scount + 1\
            end\
        end\
    end\
    if scount >= pth.limit then\
        if type(finicall) == \"function\" then\
            finicall(\"same addr_action over limit\", data)\
            log.error(idpre..\" has \"..tostring(pth.limit)..\" running pth\")\
        end\
        return \
    end\
\
    local uptime, uptimens = ctime.get_uptime()\
    local id = idpre..tostring(uptime)..\"_\"..tostring(uptimens)\
    pth.callcache[id] = { btime = uptime, data = data, finicall = finicall, recvcall = recvcall, recvargs = {...} }\
    local key = ckey.getkey(addrport)\
    local args = string.format([[{\"subtype\":\"sys\",\"action\":\"pthcall\",\"snmd5\":\"%s\",\"id\":\"%s\",\"addr\":\"%s\",\"comm_action\":%d,\"key\":\"%s\",\"proto\":\"%s\",\"recvcall\":\"%s\",\"msg\":\"%s\"}]], \
                    mime.b64(pth.snmd5), id, addrport, action, key or \"\", proto, type(recvcall), mime.b64(data))\
    log.trace(args)\
    cthread.run(args)\
end\
\
\
function pth.pb_pthrun(addr, action, data, finicall, recvcall, ...)\
    return run(\"pb\", addr, action, data, finicall, recvcall, ...)\
end\
\
function pth.pthrun(addr, action, data, finicall, recvcall, ...)\
    return run(\"json\", addr, action, data, finicall, recvcall, ...)\
end\
\
function pth.recvcall(t)\
    local id = t.id\
    if pth.callcache[id] and pth.callcache[id].recvcall then\
        local addr = t.addr\
        local action = t.comm_action\
        local msg = t.msg\
        if #msg > 0 then\
            msg = mime.unb64(msg)\
        end\
        local ok, reply = pcall(pth.callcache[id].recvcall, addr, action, msg, table.unpack(pth.callcache[id].recvargs))\
        if not ok then\
            log.error(reply)\
        end\
    end\
end\
\
function pth.finicall(t)\
    local localaddr = t.localaddr\
    if localaddr and #localaddr > 0 then\
        svrcomm.set_localaddr(localaddr)\
    end\
\
    local id = t.id\
    if pth.callcache[id] and pth.callcache[id].finicall then\
        local data_len = (type(t.data_len) == \"number\") and t.data_len or 0\
        local err = t.err\
        if #err == 0 then\
            err = nil\
        end\
        local ok, reply = pcall(pth.callcache[id].finicall, err, pth.callcache[id].data, data_len)\
        if not ok then\
            log.error(reply)\
        end\
    end\
\
    pth.callcache[id] = nil -- need clean\
end\
\
function pth.cache_stat()\
    local stat = {}\
    for id, item in pairs(pth.callcache) do\
        stat[id] = {}\
        for k, v in pairs(item) do\
            if type(v) == \"table\" then\
                stat[id][k] = {}\
                for i, e in pairs(v) do\
                    stat[id][k][i] = tostring(e)\
                end\
            elseif type(v) == \"string\" then\
                stat[id][k..\"len\"] = tostring(#v)\
            else\
                stat[id][k] = tostring(v)\
            end\
        end\
    end\
    return stat\
end\
\
function pth.write(t)\
    if type(t.limit) == \"number\" and t.limit ~= pth.limit then\
        pth.limit = t.limit\
    end\
    if type(t.timeout) == \"number\" and t.timeout ~= pth.timeout then\
        pth.timeout = t.timeout\
    end\
end\
\
function pth.read()\
    return { limit = pth.limit, timeout = pth.timeout }\
end\
\
return pth\
"
, '@'.."./lualib/svrcomm/pth.lua" ) )

package.preload[ "svrdata" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local actor = require\"luactor\"\
local dpi = require\"svrcomm.dpi\"\
local cjson = require\"cjson\"\
local mystring = require\"mystring\"\
local timer = require\"timer\"\
local tlv = require\"tlv\"\
\
local maxmsglen = 80000         -- 80K\
\
local svrdata = {\
    type = \"__svr_data\", \
    subtype = \"__svr_data\", \
    help = \"DMP server communication, only send to, no reply\", \
\
    -- conf\
    period = 0, \
    addr = {}, \
    seed = \"\", \
    tname = \"svrdata\", \
    tjname = \"svrdata_json\", \
\
    -- var\
    msg = \"\", \
    msg_json = {}, \
    msg_json_len = 0, \
\
    -- stat\
    stat = {\
        upload_raw_len = 0, \
        upload_succ_len = 0, \
        upload_succ_count = 0, \
        upload_fail_len = 0, \
        upload_fail_count = 0, \
    }, \
\
    -- json stat\
    json_stat = {\
        upload_raw_len = 0, \
        upload_succ_len = 0, \
        upload_succ_count = 0, \
        upload_fail_len = 0, \
        upload_fail_count = 0, \
    }\
}\
\
local function set_stat(err, data, cc)\
    if not err then\
        cc.upload_succ_count = cc.upload_succ_count + 1\
        cc.upload_succ_len = cc.upload_succ_len + #data\
    else\
        cc.upload_fail_count = cc.upload_fail_count + 1\
        cc.upload_fail_len = cc.upload_fail_len + #data\
        log.warn(\"svrdata fini: \"..err)\
    end\
end\
\
local function finicall(err, data)\
    set_stat(err, data, svrdata.stat)\
end\
\
local function finicall_json(err, data)\
    set_stat(err, data, svrdata.json_stat)\
end\
\
local function read()\
    return {period = svrdata.period, addr = svrdata.addr, msglen = #svrdata.msg, seed = svrdata.seed}\
end\
\
local function read_stat()\
    local t = svrdata.stat\
    t.datajson_peer = svrdata.json_stat\
    return t\
end\
\
local function send_json_table(msg_table)\
    local msgstring = cjson.encode(msg_table)\
    log.info(\"send json to DMP\", msgstring)\
    for _, addr in pairs(svrdata.addr) do\
        dpi.async_dmp_send_json(addr, CENUM.COMM_ACTION_UPLOAD_MULTI_JSON, msgstring, finicall_json)\
        svrdata.json_stat.upload_raw_len = svrdata.json_stat.upload_raw_len + #msgstring\
    end\
end\
\
local function svrdata_send_json()\
    if #svrdata.msg_json == 0 then\
        return\
    end\
    send_json_table(svrdata.msg_json)\
    svrdata.msg_json_len = 0\
    svrdata.msg_json = {}\
end\
\
local function svrdata_send()\
    if #svrdata.addr > 0 and #svrdata.msg > 0 then\
        log.info(\"send to DMP len \", #svrdata.msg)\
        for _, addr in pairs(svrdata.addr) do\
            svrdata.stat.upload_raw_len = svrdata.stat.upload_raw_len + #svrdata.msg\
            dpi.async_dmp_send(addr, svrdata.msg, finicall)\
        end\
    end\
    svrdata.msg = \"\"\
end\
\
local function write(t)\
    local need_save = false\
    if type(t.addr) == \"table\" then \
        if not mystring.same_table(t.addr, svrdata.addr) or not mystring.same_table(svrdata.addr, t.addr) then\
            svrdata.addr = t.addr\
            need_save = true\
        end\
    end\
\
    if type(t.period) == \"number\" and t.period ~= svrdata.period then\
        svrdata.period = t.period\
        timer.mod(svrdata.tname, svrdata.period, 0, svrdata_send)\
        timer.mod(svrdata.tjname, svrdata.period, 0, svrdata_send_json)\
        need_save = true\
    end\
    \
    if type(t.seed) == \"string\" and t.seed ~= svrdata.seed then\
        svrdata.seed = t.seed\
        need_save = true\
    end\
\
    if need_save then\
        lcmd_run{type = \"sys\", action = \"save_conf_change\"}\
    end\
end\
\
local function add(t)\
    --check period \
    if svrdata.period <= 0 then\
        --log.info(\"svrdata add err, period \", svrdata.period)\
        return\
    end\
\
    if type(t.count) ~= \"number\" or type(t.sbytes) ~= \"string\" or type(t.pkttype) ~= \"number\" then\
        log.error(\"Wrong format\", type(t.count), type(t.sbytes), type(t.pkttype))\
        return\
    end\
\
    local onemsg = tlv.write(t.pkttype, string.pack(\">II\", os.time(), t.count)..t.sbytes)\
    if #svrdata.msg + #onemsg >= maxmsglen then\
        svrdata_send(svrdata.msg..onemsg)\
        timer.mod(svrdata.tname, svrdata.period, 0, svrdata_send)\
        svrdata.msg = \"\"\
    else\
        svrdata.msg = svrdata.msg .. onemsg\
    end\
end\
\
local function add_json(msg)\
    --check period \
    if svrdata.period <= 0 then\
        --log.info(\"svrdata add_json err, period \", svrdata.period)\
        return\
    end\
\
    if type(msg.data) ~= \"table\" then\
        log.error(\"must add table for svr data\")\
        return\
    end\
    \
    local mm = cjson.encode(msg.data)\
    svrdata.msg_json_len = svrdata.msg_json_len + #mm\
    table.insert(svrdata.msg_json, msg.data)\
\
    if svrdata.msg_json_len >= maxmsglen then\
        svrdata_send_json()\
        timer.mod(svrdata.tjname, svrdata.period, 0, svrdata_send_json)\
    end\
end\
\
local function svrdata_conf_save()\
    return {type = svrdata.type, addr = svrdata.addr, seed = svrdata.seed, period = svrdata.period}\
end\
\
actor.action_set(svrdata.subtype, \"show_conf_save\", svrdata_conf_save, \"save svrdata conf to local file\")\
actor.action_set(svrdata.subtype, \"show_conf_svr\", function() return {type = svrdata.type, seed = svrdata.seed} end, \"show svrdata conf msg to oper svr\")\
actor.action_set(svrdata.subtype, \"read\", read, \"read svrdata conf\")\
actor.action_set(svrdata.subtype, \"read_stat\", read_stat, \"read svrdata stat\")\
actor.action_set(svrdata.subtype, \"stat\", read_stat, \"read svrdata stat\")\
actor.action_set(svrdata.subtype, \"write\", write, 'write svrdata, {\"period\":NN, \"addr\":[ADDR1, ADDR2, ...]}')\
actor.action_set(svrdata.subtype, \"add\", add, \"add data for svrdata send, {count = xx, pkttype = xx, sbytes = bytes}\")\
actor.action_set(svrdata.subtype, \"add_json\", add_json, \"add json data for svrdata send, {data = table}\")\
\
actor.action_set(svrdata.subtype, \"flush\", function() svrdata.msg = \"\" end, \"flush data for svrdata send, no args\")\
\
return svrdata\
"
, '@'.."./service/svrdata.lua" ) )

package.preload[ "svroper" ] = assert( (loadstring or load)(
"local log = require\"log\"\
local actor = require\"luactor\"\
local dpi = require\"svrcomm.dpi\"\
local cjson = require\"cjson\"\
local timer = require\"timer\"\
local mystring = require\"mystring\"\
local kernel = require\"c.kernel\"\
\
local ctime = require\"c.time\" \
\
local oper_init                 -- this function must be declared firstly\
local oper_heart\
\
local svroper = {\
    type = \"__svr_oper\", \
    subtype = \"__svr_oper\", \
    help = \"oper server, send heart/init/result to server\", \
    timer_name = \"svroper_heart\", \
    inittimer_name = \"svroper_init\", \
\
    -- conf\
    init_period = 1,\
    init_lasttime = 0,\
    init_doing = false, \
    \
    heart_period = 0, \
    result_period = 10, \
    addr = nil, \
\
    -- var\
    initok = false, \
    ret_code = 0, \
    replyarray = {}, \
}\
\
local function oper_result()\
    for _, v in pairs(svroper.replyarray) do\
        dpi.async_call(v.addr, CENUM.COMM_ACTION_DEVOPS_DPI_RESULT, cjson.encode(v.reply))\
    end\
    svroper.replyarray = {}\
end\
\
local function msg_reply(t, msg, addr)\
    local reply = {}\
    for _, v in pairs(t) do \
        if type(v) == \"table\" then\
            local result = actor.deal_reply(v)\
            if type(result) == \"string\" or type(result) == \"table\" then\
                table.insert(reply, {result = result, id = t.id, status = 0})\
            end\
        end\
    end\
    if #reply > 0 then\
        table.insert(svroper.replyarray, {addr = addr, reply = reply})\
    end\
end\
\
local function oper_deal_reply(addr, action, msg, initphrase)\
    if initphrase then\
        svroper.initok = true\
        lcmd_run({subtype = \"sys\", action = \"unbypass\"})\
        log.info(\"svroper init OK for addr \"..addr..\", action is \"..action)\
    end\
\
    if not msg or msg == \"\" then\
        log.info(string.format(\"ignore empty msg, action 0x%x\", action))\
        return\
    end\
    log.info(string.format(\"receive %s server, action 0x%x, msg(%s)\", addr, action, msg))\
\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok then\
        log.error(string.format(\"failed json decode msg(%s), err(%s)\", msg, t))\
        return\
    end\
    if type(t) ~= \"table\" or #t == 0 then\
        log.info(string.format(\"ignore empty json or not table for msg(%s)\", msg))\
        return\
    end\
    msg_reply(t, msg, addr)\
end\
\
local function oper_raw(t)\
    if type(t.action_type) ~= \"number\" or type(t.data) ~= \"table\" then\
        log.error(\"wrong format for oper raw, look into help\")\
        return\
    end\
\
    if not svroper.initok and not t.addr then\
        log.warn(\"Wait init ok first, just ignore this raw\")\
        return\
    end\
\
    local addrs = t.addr or svroper.addr\
    for _, addr in ipairs(addrs) do\
        dpi.async_call(addr, t.action_type, cjson.encode(t.data), t.finicall, t.recvcall, table.unpack(t.recvargs or {}))\
    end\
end\
\
local function init_fini_call(err, msg)\
    if err then\
        log.warn(\"svr oper init failed, err \", err)\
    end\
    svroper.init_doing = false\
    svroper.init_lasttime = ctime.get_uptime()\
end\
\
local function show_oper_init()\
    local ok, t = lcmd_run({action = \"show_conf_svr\"})\
    if not ok or type(t) ~= \"table\" then\
        return \
    end\
\
    local ok, arch = lcmd_run({subtype = \"arch\", action = \"read\"})\
    if not ok or type(arch) ~= \"table\" then\
        return \
    end\
\
    local ok, devinfo = lcmd_run({subtype = \"ct\", action = \"get_devinfo\"})\
    if not ok or type(devinfo) ~= \"table\" then\
         devinfo = {}\
    end\
\
    table.insert(t, {type = \"binfo_v1\", pver = arch.int_ver, sver = arch.sig_ver, ecode = svroper.ret_code, ad = arch.pppoe, dhwver = devinfo.HDVersion or \"\", dswver = devinfo.SWVersion or \"\", dmod = devinfo.ProductClass or \"\", dmfr = devinfo.Manufacturer or \"\", gw_sn = devinfo.DevType or \"\"})\
    return t\
end\
\
function oper_init()\
    if svroper.initok then\
        return \
    end\
\
    local uptime = ctime.get_uptime()\
    if svroper.init_doing then \
        if uptime > svroper.init_lasttime + 14400 then\
            log.warn(\"Wrong init msg coroutine, must init again\")\
        else\
            return\
        end\
    else\
        if uptime < svroper.init_lasttime + svroper.init_period then\
            log.trace(\"another init will be triggered after \", svroper.init_lasttime + svroper.init_period - uptime, \" secs\")\
            return\
        end\
    end\
\
    local t = show_oper_init()\
    if type(t) ~= \"table\" then\
        return \"Wait for init.....\"\
    end\
\
    svroper.init_period = svroper.init_period * 3 > 14400 and 14400 or svroper.init_period * 3\
    svroper.init_doing = true\
\
    local msg = cjson.encode(t)\
    log.info(\"will trigger init with period, \", svroper.init_period, \" msg, \", msg)\
    for _, addr in ipairs(svroper.addr) do\
        dpi.async_call(addr, CENUM.COMM_ACTION_DEVOPS_DPI_INIT, msg, init_fini_call, oper_deal_reply, true)\
    end\
end\
\
local function show_oper_heart()\
    local ok, t = lcmd_run({action = \"show_conf_svr\"})\
    if not ok or type(t) ~= \"table\" then\
        return nil\
    end\
\
    local ok, kcnt = lcmd_run({subtype = \"__dpi_info\", action = \"kernel_cnt\"})\
    if not ok or type(kcnt) ~= \"table\" then\
        return nil\
    end\
\
    local _, svrdata_stat = lcmd_run({type = \"__svr_data\", action = \"read_stat\"})\
    table.insert(t, {type = \"svrdata_stat\", v = svrdata_stat})\
    \
    local _, debuginfo = lcmd_run({type = \"topo\", action = \"show_debug\", send = true})\
    if debuginfo and #debuginfo > 0 then\
        table.insert(t, {type = \"topo_debug\", v = debuginfo})\
    end\
\
    local ok, boottime = lcmd_run({subtype = \"sys\", action = \"boottime\"})\
\
    table.insert(t, {type = \"dstat\", dpiup = os.time() - boottime, ccnt = kcnt.ccnt, pcnt = kcnt.pcnt})\
    return t\
end\
\
local function trigger_heart_timer()\
    local period = math.floor(svroper.heart_period)\
    local half = math.floor(period / 2)\
    local range_min = period - half\
    local range_max = period + half\
    local random_period =  math.random(range_min, range_max)\
    local uptime = ctime.get_uptime()\
    svroper.heart_nexttime = uptime + random_period\
    -- here it does not use once timer, in case that timer will not be added because of exception.\
    timer.mod_notdisable(svroper.timer_name, random_period, 0, oper_heart)\
end\
\
function oper_heart()\
    trigger_heart_timer()\
\
    if not svroper.initok then\
        log.warn(\"Wait init ok first, just ignore this heart\")\
        return\
    end\
    local t = show_oper_heart()\
    if type(t) ~= \"table\" then\
        return \"failed to prepair heart msg.....\"\
    end\
\
    local msg =  cjson.encode(t)\
    log.info(\"will heart oper with msg \"..msg)\
    svroper.heart_lasttime = ctime.get_uptime()\
    for _, addr in ipairs(svroper.addr) do\
        dpi.async_call(addr, CENUM.COMM_ACTION_DEVOPS_DPI_HEART, msg, nil, oper_deal_reply)\
    end\
end\
\
local function read()\
    return {heart_period = svroper.heart_period, addr = svroper.addr, \
            initok = svroper.initok, ret_code = svroper.ret_code, init_period = svroper.init_period, \
            heart_lasttime = svroper.heart_lasttime, heart_nexttime = svroper.heart_nexttime,\
            inittimer_name = svroper.inittimer_name, replycnt = #svroper.replyarray}\
end\
\
local function write(t)\
    if type(t.addr) == \"table\" then \
        if not mystring.same_table(t.addr, svroper.addr) or not mystring.same_table(svroper.addr, t.addr) then\
            svroper.addr = t.addr\
            timer.mod_notdisable(svroper.inittimer_name, 5, 0, oper_init)\
        end\
    end\
    \
    if type(t.heart_period) == \"number\" and t.heart_period ~= svroper.heart_period then\
        svroper.heart_period = t.heart_period\
        trigger_heart_timer()\
    end\
end\
\
function svroper.postinit()\
    timer.mod_notdisable(\"svroper_result\", svroper.result_period, 0, oper_result)\
    svroper.init_lasttime = ctime.get_uptime()\
end\
\
actor.action_set(svroper.subtype, \"show_oper_init\", show_oper_init, \"show init msg to oper server\")\
actor.action_set(svroper.subtype, \"show_oper_heart\", show_oper_heart, \"show heart msg to oper server\")\
actor.action_set(svroper.subtype, \"show_oper_result\", function() return cjson.encode(svroper.replyarray) end, \"show result msg to oper server\")\
\
actor.action_set(svroper.subtype, \"set_ret_code\", function(t) svroper.ret_code = t.ret_code end, 'set ret code for oper init msg')\
actor.action_set(svroper.subtype, \"read\", read, 'read svroper conf')\
actor.action_set(svroper.subtype, \"write\", write, 'write svroper, {\"heart_period\":NN, \"addr\":[ADDR1, ADDR2, ...]}')\
actor.action_set(svroper.subtype, \"oper_init\", oper_init, \"send init msg to oper server\")\
actor.action_set(svroper.subtype, \"oper_heart\", oper_heart, \"send heart msg to oper server\")\
actor.action_set(svroper.subtype, \"oper_raw\", oper_raw, \
                 [[send raw msg to oper server, {action_type = xx, data = table, addr = [\"\"], recvcall = recv_func, finicall = finish_call, recvargs = recv_args(table)}]])\
\
return svroper\
"
, '@'.."./service/svroper/svroper.lua" ) )

package.preload[ "sys" ] = assert( (loadstring or load)(
"local timer = require\"timer\"\
local actor = require\"luactor\"\
local log = require\"log\"\
local msocket = require\"msocket\"\
local myfile = require\"myfile\"\
local mystring = require\"mystring\"\
local ctime = require\"c.time\"\
local csys = require\"c.sys\"\
local pth = require\"svrcomm.pth\"\
\
local sys = {\
    type = \"sys\", \
    subtype = \"sys\", \
    help = \"sys module, configure/save, also including bypass/engine/timer etc.\", \
\
    -- local save conf file\
    now_seed = 0, \
    save_seed = 0, \
\
    -- sw_def_enabled\
    --   false: means default \"bypass\", and \"unbypass\" will be triggered when svroper init is ok.\
    sw_def_enabled = true,\
\
    -- sys\
    boottime = os.time(), \
    init_uptime = 0,\
}\
\
local function get_uptime()\
    local uptime = ctime.get_uptime()\
    return uptime\
end\
\
local function uptime_to_date(uptime)\
    local now_uptime = get_uptime()\
    local difftime = math.modf(now_uptime) - math.modf(uptime)\
    local ttime = os.time() - difftime\
    if ttime <= 0 then\
        return nil\
    end\
    return os.date(\"%Y/%m/%d %H:%M:%S\", ttime)\
end\
\
local function sysswitch(enable)\
    local ok, kernel = pcall(require, \"c.kernel\")\
    if ok then\
        if enable then\
            log.info(\"will enable timer/kernel\")\
            timer.timer_enable(true)\
            kernel.set_engine(CENUM.ENGINE_TYPE_ALL, 1)\
        else\
            log.info(\"will disable timer/kernel\")\
            timer.timer_enable(false)        \
            kernel.set_engine(CENUM.ENGINE_TYPE_ALL, 0)\
        end\
    end\
end\
\
local function read(t)\
    local resp = {}\
    local ok, kernel = pcall(require, \"c.kernel\")\
    if ok then\
        resp.kernel = kernel.get_engine()\
    end\
    resp.timer = timer.read()\
    resp.msocket = msocket.read()\
    resp.log = {file = log.outfile or \"\", level = log.level}\
    resp.conf = {now_seed = sys.now_seed, save_seed = sys.save_seed, sw_def_enabled = sys.sw_def_enabled}\
    resp.stat = {uptime = sys.init_uptime}\
    if not t or not t.module or not resp[t.module] then\
        return resp\
    else\
        return resp[t.module]\
    end\
end\
\
local function show(funcname)\
    return actor.deal_reply({action = funcname})\
end\
\
local function save()\
    local save_file = lcmd_conf_save_filename()\
    local ok, t = lcmd_run({action = \"show_conf_save\"})\
    if not ok then\
        log.error(\"failed to show conf save, \", t)\
    else\
        err = myfile.store_json(t, save_file)\
        if err then\
            log.error(err)\
        else\
            log.warn(\"save conf to local file \"..save_file)\
        end\
    end\
end\
\
local function set_log(t)\
    if type(t.level) == \"string\" then\
        local lev = {\
            trace = true, \
            debug = true, \
            info = true, \
            warn = true, \
            error = true, \
            fatal = true, \
        }\
        if lev[t.level] then\
            log.level = t.level\
        end\
    end\
\
    if type(t.file) == \"string\" or not t.file then\
        log.outfile = t.file\
    end\
\
    if t.lineinfo and t.lineinfo == true then\
        log.lineinfo = true\
    end\
\
    if type(t.tag) == \"string\" then\
        log.tag = t.tag\
    end\
\
    if not t.isthread then\
        csys.set_log(log.level, log.outfile)\
    end\
end\
\
local function save_conf_change()\
    sys.save_seed = sys.save_seed + 1\
end\
\
local function show_memory()\
    return { used = collectgarbage(\"count\")..\" K\" }\
end\
\
local function collect_memory()\
    collectgarbage(\"collect\")\
    return { used = collectgarbage(\"count\")..\" K\" }\
end\
\
local function leak_memory(t)\
    local leak_enable, cleak = pcall(require, \"c.memleak\")\
    if not leak_enable then \
        return\
    end\
\
    cleak.dump(t.file)\
end\
\
-- local function dump_memory(t)\
--     local mri = require\"MemoryReferenceInfo\"\
--     collectgarbage(\"collect\")\
--     collectgarbage(\"collect\")\
--     mri.m_cMethods.DumpMemorySnapshot(\"./\", \"All\", -1)\
-- end\
\
local function load_string_file(t)\
    if type(t.string) == \"string\" then\
        return {value = load(t.string)()}\
    elseif type(t.file) == \"file\" then\
        return {value = loadfile(t.file)()}\
    end\
end\
\
function sys.show_module(modname)\
    if type(modname) == \"string\" then\
        local t = {}\
        if package.loaded[modname] then\
            if type(package.loaded[modname]) == \"table\" then\
                for k, v in pairs(package.loaded[modname]) do\
                    if type(v) == \"boolean\" or (type(v) == \"number\" and v ~= math.huge) then\
                        -- math.huge will cause cjson.encode failed\
                        t[k] = v\
                    else\
                        t[k] = tostring(v)\
                    end\
                end\
            else\
                table.insert(t, tostring(package.loaded[modname]))\
            end\
        else\
            if package.preload[modname] then\
                t[\"error\"] = \"in preload, but not in loaded\"\
            else\
                t[\"error\"] = \"N/A\"\
            end\
        end\
        return t\
    end\
\
    -- show all\
    local all = {}\
    all[\"package.loaded\"] = {}\
    for name, mod in pairs(package.loaded) do\
        if type(mod) == \"table\" then\
            all[\"package.loaded\"][name] = {}\
            for k, v in pairs(mod) do\
                if type(v) == \"boolean\" or (type(v) == \"number\" and v ~= math.huge) then\
                    -- math.huge will cause cjson.encode failed\
                    all[\"package.loaded\"][name][k] = v\
                else\
                    all[\"package.loaded\"][name][k] = tostring(v)\
                end\
            end\
        else\
            all[\"package.loaded\"][name] = tostring(mod)\
        end\
    end\
    all[\"package.preload\"] = {}\
    all[\"package.preload_not_used\"] = {}\
    for k, v in pairs(package.preload) do\
        all[\"package.preload\"][k] = tostring(v)\
        if not package.loaded[k] then\
            table.insert(all[\"package.preload_not_used\"], k)\
        end\
    end\
    return all\
end\
\
local function write(t)\
    local need_save = false\
\
    if type(t.sw_def_enabled) == \"boolean\" and t.sw_def_enabled ~= sys.sw_def_enabled then\
        sys.sw_def_enabled = t.sw_def_enabled\
        need_save = true\
    end\
\
    if need_save then\
        lcmd_run{type = \"sys\", action = \"save_conf_change\"}\
    end\
end\
\
local function sys_conf_save()\
    return { type = sys.subtype, action = \"write\", sw_def_enabled = sys.sw_def_enabled}\
end\
\
function sys.postinit()\
    sys.now_seed = sys.save_seed -- MUST NOT trigger save conf when init\
\
    sys.init_uptime = get_uptime()\
\
    if sys.sw_def_enabled then\
        sysswitch(sys.sw_def_enabled)\
    end\
end\
\
actor.action_set(sys.subtype, \"boottime\", function() return sys.boottime end, \"return boottime of process\")\
\
actor.action_set(sys.subtype, \"dpi_uptime\", function() return get_uptime() - sys.init_uptime end, \"get dpi uptime\")\
actor.action_set(sys.subtype, \"sys_uptime\", function() return get_uptime() end, \"get sys uptime\")\
actor.action_set(sys.subtype, \"dpi_stime\", function() return os.date(\"%F %T\", os.time() - get_uptime() + sys.init_uptime) end, \"get dpi start time\")\
actor.action_set(sys.subtype, \"sys_stime\", function() return os.date(\"%F %T\", os.time() - get_uptime()) end, \"get sys start time\")\
actor.action_set(sys.subtype, \"uptime_to_date\", \
        function(msg)\
            if type(msg.uptime) ~= \"number\" then\
                return { err = \"uptime missed\" }\
            end\
            local date = uptime_to_date(msg.uptime)\
            if not date then\
                return { err = \"invalid uptime\" }\
            end\
            return { date = date }\
        end,\
        \"convert uptime to date, { uptime = number }\")\
actor.action_set(sys.subtype, \"show_endian\", function() return { endian = csys.show_endian() } end, \"show endian\")\
actor.action_set(sys.subtype, \"unbypass\", function () sysswitch(true) end, \"close bypass stat, enable engine\")\
actor.action_set(sys.subtype, \"bypass\", function () sysswitch(false) end, \"bypass engine\")\
actor.action_set(sys.subtype, \"set_log\", set_log,\
                 \"set log parameters, {level = [fatal | error | warn | info | debug | trace], file = filename}\")\
actor.action_set(sys.subtype, \"set_msocket\", msocket.write, \"{maxcount = number}, limit the number of identical name, default 3\")\
actor.action_set(sys.subtype, \"read\", read, \"read all var\")\
actor.action_set(sys.subtype, \"write\", write, \"write conf\")\
actor.action_set(sys.subtype, \"show_conf_save\", sys_conf_save, \"save sys conf to local file\")\
\
actor.action_set(sys.subtype, \"save\", save, \"save msg to local file\")\
actor.action_set(sys.subtype, \"save_conf_change\", save_conf_change, \"trigger conf save to local file, no args\")\
\
actor.action_set(sys.subtype, \"show_memory\", show_memory, \"show memory usage\")\
actor.action_set(sys.subtype, \"collect_memory\", collect_memory, \"collect garbage\")\
actor.action_set(sys.subtype, \"malloc_trim\", function () csys.malloc_trim() end, \"malloc_trim\")\
actor.action_set(sys.subtype, \"exit\", lcmd_loop_exit, \"exit lua engine, only for memory test\")\
actor.action_set(sys.subtype, \"leak\", leak_memory, \"{file = xxx}, show mem leak info into file\")\
actor.action_set(sys.subtype, \"load\", load_string_file, \"{string = xxx, file = xxx}, load string or file\")\
actor.action_set(sys.subtype, \"show_pbcnt\", function () return actor.pbcnt end, \"show all actor publish count\")\
actor.action_set(sys.subtype, \"extperm_set\", actor.extperm_set, \"perm conf set\")\
actor.action_set(sys.subtype, \"extperm_get\", actor.extperm_get, \"perm conf get\")\
\
timer.mod(\"sys_save_conf\", 60, 0, \
          function() \
              if sys.now_seed ~= sys.save_seed then\
                  save()\
                  sys.now_seed = sys.save_seed\
              end\
          end\
)\
\
local dpi = require\"svrcomm.dpi\"\
actor.action_set(sys.subtype, \"dcache_stat\", dpi.dcache_stat, \"show dcache stat\")\
actor.action_set(sys.subtype, \"dcache_restart\", dpi.dcache_restart, \"restart dcache, {max = maxdns, cycle = secs}\")\
actor.action_set(sys.subtype, \"dpiwrite\", dpi.write, \"dpi write, { use_seconn = boolean, pthlimit = number }\")\
actor.action_set(sys.subtype, \"dpiread\", dpi.read, \"dpi read\")\
actor.action_set(sys.subtype, \"pthcall\", pth.call, \"pthcall\")\
actor.action_set(sys.subtype, \"pth_recvcall\", pth.recvcall, \"pth_recvcall\")\
actor.action_set(sys.subtype, \"pth_finicall\", pth.finicall, \"pth_finicall\")\
actor.action_set(sys.subtype, \"pthcallcache_stat\", pth.cache_stat, \"pthcallcache_stat\")\
\
local ckey = require\"svrcomm.ckey\"\
actor.action_set(\"ckey\", \"write\", ckey.write, \"ckey write, { addr = string, key = string, lease = number}, { max = number }\")\
actor.action_set(\"ckey\", \"read\", ckey.read, \"ckey read\")\
actor.action_set(\"ckey\", \"del\", ckey.del, \"ckey del, { addr = string }\")\
actor.action_set(\"ckey\", \"flush\", ckey.flush, \"ckey flush\")\
actor.action_set(\"ckey\", \"request\", ckey.request, \"ckey request, { addr = string }\")\
\
return sys\
"
, '@'.."./service/sys.lua" ) )

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

package.preload[ "tlv" ] = assert( (loadstring or load)(
"local log = require\"log\"\
\
local tlv = {}\
\
function tlv.write(ttype, value)\
    local buf = string.pack(\">HI\", ttype, #value)\
    return buf..value\
end\
\
function tlv.read(data, pos) \
    local ttype, len, nn = string.unpack(\">HI\", data, pos)\
    return ttype, data:sub(nn, nn + len - 1), string.packsize(\">HI\") + len\
end\
\
function tlv.write_uint32(ttype, number)\
    return string.pack(\">HII\", ttype, 4, number)\
end\
\
return tlv\
"
, '@'.."./lualib/tlv.lua" ) )

package.preload[ "topo" ] = assert( (loadstring or load)(
"local cjson = require(\"cjson\")\
local myip = require(\"myip\")\
local actor = require(\"luactor\") \
local timer = require(\"timer\")\
local mime = require(\"mime\")\
\
local topo = {\
    subtype = \"topo\",\
    help = \"show topo\",\
    count = 0,\
    send_count = 0,\
    send_active_count = 0,\
\
    -- show log\
    log = {},\
\
    send_period = 86400,\
    send_active_period = 3600,\
    last_speed = {},\
    debug_enable = 0,\
    max_debug = 1,\
    postmsg_enable = true,\
    hang_max = 8,\
\
    brmacs_enable = true,\
    agetime = 600,\
}\
\
-- <elink digraph to tree>\
local function inarr(s, arr)\
    for _, v in ipairs(arr) do\
        if v == s then\
            return true\
        end\
    end\
    return false\
end\
\
local function dfs_vertex(es, vmain, alle, dealv)\
    local runv = {}\
\
    table.insert(runv, vmain)\
    dealv[vmain] = true\
    while #runv > 0 do\
        xx = table.remove(runv)\
        -- print(\"will find xx for v[1], v[2]\", xx)\
        for _, v in pairs(es) do\
            local key, val = v[1], v[2]\
            if key == xx and not dealv[val] then\
                table.insert(runv, val)\
                dealv[val] = true\
                -- print(\"visit and add one edge \", vmain, val)\
                table.insert(alle, {vmain, val})\
            end\
        end\
    end\
end\
\
-- del circle in DG using DFS, fmt as following:\
-- {{\"v1\", \"v2\"}, {\"v2\", \"v3\"}, {\"v3\":\"v1\"}}\
--\
-- output is real edges with only 2 layers, with example:\
-- {{\"v1\", \"v2\"}, {\"v1\", \"v3\"}}\
local function del_circle_2layer(vs, indegree, es, hprio_mac) \
    local mainv = {}\
    local alle = {}\
    local dealv, outv = {}, {}\
\
    -- find indegree 0\
    for k, v in pairs(indegree) do\
        if v == 0 then\
            table.insert(outv, k)\
        end\
    end\
\
    -- deal outv first for this vertex has childrens\
    for _, vv in pairs(outv) do\
        if not dealv[vv] then\
            table.insert(mainv, vv)\
            dfs_vertex(es, vv, alle, dealv)\
        end\
    end\
\
    -- deal high priority mac\
    for _, vv in pairs(hprio_mac) do\
        if not dealv[vv] then\
            table.insert(mainv, vv)\
            dfs_vertex(es, vv, alle, dealv)\
        end\
    end\
\
    -- deal left vertex\
    for _, vv in pairs(vs) do\
        if not dealv[vv] then          -- main vertex\
            table.insert(mainv, vv)\
            dfs_vertex(es, vv, alle, dealv)\
        end\
    end\
\
    return mainv, alle\
end\
\
local function change_edge(t, vertexs, alle)\
    local result = {}\
    local vvflag = {}\
\
    for k, v in pairs(t) do\
        local varr = {}\
        for _, vv in ipairs(v) do\
            if not inarr(vv, vertexs) then -- commain v\
                if not vvflag[vv] then\
                    table.insert(varr, vv)\
                end\
                vvflag[vv] = true\
            end\
        end\
        for _, vv in ipairs(alle) do\
            if vv[1] == k and type(vv[2]) == \"string\" then\
                if not vvflag[vv[2]] then\
                    table.insert(varr, vv[2])\
                end\
                vvflag[vv] = true\
                -- print(\"add k, vv2\", k, vv[2])\
            end\
        end\
        result[k] = varr\
    end\
\
    return result\
end\
\
-- input fmt:\
--   {{\"p1\":{\"c11\", \"c12\", \"c13\"}}, \
--   {\"p2\":{\"c21\", \"c22\", \"c23\", \"p1\"}}, \
--   {\"p3\":{\"c31\", \"c32\", \"c33\"}},\
--   .............. }\
--\
-- output, main vertexs {\"p2\", \"p3\"} and all edges\
local function dg2tree(t, hprio_mac)\
    local vertexs, indegree = {}, {}\
    local dgs = {}\
\
    for k, v in pairs(t) do\
        table.insert(vertexs, k)\
    end\
    for k, v in pairs(t) do\
        for _, vv in ipairs(v) do\
            if inarr(vv, vertexs) then\
                table.insert(dgs, {k, vv})\
                -- print(\"add dgs\", k, vv)\
                if not indegree[k] then\
                    indegree[k] = 0\
                end\
                if not indegree[vv] then\
                    indegree[vv] = 1\
                else\
                    indegree[vv] = indegree[vv] + 1\
                end\
            end\
        end\
    end\
\
    if #dgs == 0 then\
        return vertexs, t\
    end\
\
    local mainv, alle = del_circle_2layer(vertexs, indegree, dgs, hprio_mac)\
    local result = change_edge(t, vertexs, alle)\
\
    return mainv, result\
end\
-- </elink digraph to tree>\
\
local function add_value(info, key, value, default)\
    if type(info) == \"table\" and key then\
        local fmt_value = value\
        if type(fmt_value) ~= type(default) then\
            fmt_value = default\
        end\
        info[key] = fmt_value\
    end\
end\
\
local function log_add(log, func, result)\
    if type(log) == \"table\" and result then\
        table.insert(log, {func = func,etime = os.time(), ret = result})\
    end\
end\
\
local function call_api(func, log, port)\
    local _, result = lcmd_run{subtype = \"ct\", action = \"call_api\", func = func, port = port} \
    log_add(log, func, result)\
\
    return result or {} \
end\
\
local function log_set(old, max, log)\
    local len = #old - max \
    if len >= 0 then\
        if log then\
            len = len + 1\
        end\
        for i=1,len do\
            table.remove(old, 1)\
        end\
    end\
    table.insert(old, log)\
end\
\
local function get_brmacs(all_lanhost, time, test)\
    local brhost = {}\
    -- default brport 1-4 is wired\
    local conf = {[1] = 0, [2] = 0, [3] = 0, [4] = 0}\
    local ports = {}\
    local _, brmacs = lcmd_run({subtype = \"sigcollect\", action = \"brctl_showmacs\"})\
    if test and test.brmacs then\
        brmacs = test.brmacs\
    end\
    if type(brmacs) ~= \"table\" then\
        return {}\
    end\
    -- check rule port==brPort and 1-4 is wired\
    for k,v in pairs(brmacs) do\
        local one = all_lanhost[v.mac] or {}\
        local conf1, conf2 = conf[1], conf[2]\
        local brport = tonumber(v.port) or 0\
        local lanport = tonumber(one.acc_port) or 0\
\
        if one.active == 1 and lanport > 0 and lanport < 5 then\
            if brport ~= lanport or one.acc_type ~= 0 then\
                conf = {}\
            end\
        end\
    end\
\
    for k,v in pairs(brmacs) do\
        local agetime = tonumber(v.ageingtime) or -1\
        local port = tonumber(v.port) or \"\"\
        if agetime > 0 and agetime < time and conf[port] then\
            brhost[v.mac] = {mac = v.mac, port = port, connectiontype = 0, active = 1}\
        end\
    end\
    return brhost\
end\
\
local function get_gw_info(log)\
    local gw_info, wifi_info = {}, {}\
    local pppoe = call_api(\"pppoe\", log)\
    local devinfo = call_api(\"dev\", log)\
    local poninfo = call_api(\"pon\", log)\
    local wlan = call_api(\"wlan\", log)\
    local netinfo = call_api(\"net\", log)\
    local dnsinfo = call_api(\"dns\", log)\
    local odm = call_api(\"odm\", log)\
   \
    for k, v in pairs(wlan) do\
        if v.rfbrand == 0 and v.enable == 1 then\
            wifi_info[\"2g_ssid\"] = v.ssid\
            wifi_info[\"2g_channel\"] = v.channel\
        elseif v.rfbrand == 1 and v.enable == 1 then\
            wifi_info[\"5g_ssid\"] = v.ssid\
            wifi_info[\"5g_channel\"] = v.channel\
        end\
    end\
    if odm == 1 then\
        add_value(gw_info, \"sn\", devinfo.sn, \"\")\
        add_value(gw_info, \"2g_ssid\", wifi_info[\"2g_ssid\"], \"\")\
        add_value(gw_info, \"2g_channel\", wifi_info[\"2g_channel\"], -1)\
        add_value(gw_info, \"5g_ssid\", wifi_info[\"5g_ssid\"], \"\")\
        add_value(gw_info, \"5g_channel\", wifi_info[\"5g_channel\"], -1)\
        add_value(gw_info, \"vendor\", devinfo.vendor, \"\")\
        add_value(gw_info, \"model\", devinfo.model, \"\")\
        add_value(gw_info, \"online_time\", devinfo.online_time, -1)\
        add_value(gw_info, \"rx_bytes\", netinfo.rx_bytes, -1)\
        add_value(gw_info, \"tx_bytes\", netinfo.tx_bytes, -1)\
        add_value(gw_info, \"dns\", dnsinfo.dns, \"\")\
        add_value(gw_info, \"Devname\", devinfo.devname, \"\")\
    end\
    add_value(gw_info, \"mac\", myip.mac_fmt(devinfo.mac), \"\")\
    add_value(gw_info, \"pppoe\", pppoe.pppoe, \"\")\
    add_value(gw_info, \"loid\", poninfo.loid, \"\")\
    add_value(gw_info, \"lan_ip\", netinfo.lan_ip, \"\")\
    add_value(gw_info, \"wan_ip\", netinfo.wan_ip, \"\")\
\
    log_add(log, \"get_gw_info\", gw_info)\
    return gw_info\
end\
\
local function host_add_one(host, par_mac, odm)\
    local one = {}\
    add_value(one, \"par_mac\", par_mac, \"\")\
    add_value(one, \"mac\", host.mac, \"\")\
    add_value(one, \"ip\", host.ip, \"\")\
    add_value(one, \"acc_type\", host.connectiontype, -1)\
    add_value(one, \"acc_port\", tostring(host.port or \"\"), \"\")\
    add_value(one, \"gw_port\", tostring(host.port or \"\"), \"\")\
    if odm == 1 then\
        add_value(one, \"last_active_time\", host.lastactivetime, \"\")\
        add_value(one, \"last_inactive_time\", host.lastinactivetime, \"\")\
        add_value(one, \"devname\", host.devname, \"\")\
        add_value(one, \"rxbytes\", host.rxbytes, -1)\
        add_value(one, \"txbytes\", host.txbytes, -1)\
        add_value(one, \"power_level\", host.powerlevel, -1)\
        add_value(one, \"acc_speed\", host.negorate, -1)\
    end\
    add_value(one, \"active\", host.active, -1)\
    add_value(one, \"online_time\", host.onlinetime, -1)\
    add_value(one, \"hostname\", host.hostname, \"\")\
    add_value(one, \"dev_type\", host.devtype, \"\")\
    add_value(one, \"model\", host.model, \"\")\
    add_value(one, \"brand\", host.brand, \"\")\
    add_value(one, \"os\", host.os, \"\")\
    return one\
end\
\
local function fmt_wifiport(wifi, host, odm, log)\
    local port, acctype = host.port, host.connectiontype\
    if not port or not acctype or acctype == 0 then\
        return \
    end\
    \
    if host.devname then\
        if not wifi[port] then\
            local wlan = call_api(\"getssid\", log, port)\
            if wlan and wlan.SSIDAlias then\
                ssid = wlan.SSIDAlias\
                wifi[port] = ssid\
                port = ssid\
            end\
        else\
            port = wifi[port]\
        end\
    else\
        local wandev = call_api(\"getssid\", log, port)\
        if wandev.rfbrand == 0 then\
            port = \"2.4G\"\
        elseif wandev.rfbrand == 1 then\
            port = \"5G\"\
        end\
    end\
    host.port = port\
end\
\
local function get_lanhost_info(sn, log, test, brmacs_enable, agetime)\
    local lanhost = test.lanhost or call_api(\"lanhost\", log)\
    local devname = call_api(\"devname\", log)\
    local odm = call_api(\"odm\", log)\
    local all_lanhost, wifi = {}, {}\
    for mac, host in pairs(lanhost) do\
        local macstr = myip.mac_fmt(host.macstring)\
        host.mac = macstr\
\
        if odm == 1 then\
            fmt_wifiport(wifi, host, odm, log)\
        end\
        -- 用于调整天翼网关1.0 有线连接值不统一的问题\
        if odm == 0 then \
            host.connectiontype = host.connectiontype - 1\
        end\
        local one = host_add_one(host, sn, odm)    \
\
        --update devname\
        if devname[mac] then\
            add_value(one, \"devname\", devname[mac].devname, \"\")\
        end\
\
        --add level\
        if host.active ~= 1 then\
            add_value(one, \"level\", -1, -1)\
        else\
            add_value(one, \"level\", 1, 1)\
        end\
        all_lanhost[macstr]=one\
    end\
    log_add(log, \"get_lanhost_info\", all_lanhost)\
    if brmacs_enable then\
        local brinfo = get_brmacs(all_lanhost, agetime, test)\
        for k,v in pairs(brinfo) do\
            if not all_lanhost[k] then\
                all_lanhost[k] = host_add_one(v, sn, odm)\
                add_value(all_lanhost[k], \"level\", 1, 1)\
            end\
        end\
        log_add(log, \"get_brmacs\", brinfo)\
    end\
    return all_lanhost\
end\
\
\
local function str_to_table(info)\
    local ok, table = pcall(cjson.decode, info)\
    if not ok then\
        return {}\
    end\
    return table\
end\
\
local function get_ap_ssid(wifi)\
    local wifis = {}\
    if type(wifi) ~= \"table\" then\
        return wifis\
    end\
    for k,v in pairs(wifi) do\
        if not v.radio and type(v.ap) ~= \"table\" then\
            break\
        end\
        local mode = v.radio.mode or \"\"\
        for _,wifinfo in pairs(v.ap) do\
            if wifinfo.apidx == 0 then\
                wifis[mode] = wifinfo.ssid\
            end\
        end\
    end\
    return wifis\
end\
\
local function get_ext_apinfo(apinfo)\
    local info, devinfo = {}, {}\
    if type(apinfo) ~= \"table\" then\
        apinfo = {}\
    end\
    if type(apinfo.real_devinfo) == \"table\" then\
        devinfo = apinfo.real_devinfo\
    end\
    if apinfo.channel then\
        info[\"2Gchannel\"] = apinfo.channel[\"2.4G\"]        \
        info[\"5Gchannel\"] = apinfo.channel[\"5G\"]        \
    end\
    info[\"workmode\"] = apinfo.workmode\
    local ssids = {}\
    ssids = get_ap_ssid(apinfo.wifi)\
    info[\"2Gssid\"] = ssids[\"2.4G\"]\
    info[\"5Gssid\"] = ssids[\"5G\"]\
    return info, devinfo\
end\
\
local function string_to_number(str)\
    local num\
    if type(str) == \"string\" then\
        local numstr = string.match(str,\"[-%d]+\")  \
        num = tonumber(numstr)\
    else\
        return str\
    end\
    return num \
end\
\
local function get_gw_port(lanhost, par_elink, elink_info)\
    local par_info = {}\
    for _,mac in pairs(par_elink) do\
        local same_mac = {}\
        local cat_mac = string.sub(mac, 1, 10)\
        for mac2,info in pairs(lanhost) do\
            if mac2 == mac then\
                table.insert(same_mac, 1, mac2)\
            --find same mac\
            elseif string.match(mac2, \"^\"..cat_mac) and not elink_info[mac2] and not info.merge then\
                table.insert(same_mac, mac2)\
                info.merge = true\
            end\
        end\
\
        local pmac = same_mac[1] or mac\
        local host = lanhost[pmac] or elink_info[pmac]\
        par_info[mac] = {pmac, host.acc_port}\
    end\
\
    return par_info\
end\
\
local function select_filed(elink_info, lan_info, default)\
    if elink_info and elink_info ~= default then\
        return elink_info\
    end\
    return lan_info\
end\
\
--[[\
    laninfo:par_mac,mac,acc_type,acc_port,dev_type,model,brand,os,ip,last_active_time,\
    last_inactive_time,online_time,hostname,devname,rxbytes,txbytes,power_level,acc_speed,active\
    elink:par_mac,mac,dev_type,model,brand,os,active\
    elink_dev:par_mac,mac,acc_type,acc_port,online_time,hostname,power_level,acc_speed(-1),active\
\
    bridge_valid:ip,rxbytes,txbytes,last_active_time,last_inactive_time\
    elink_ext:sn,2Gchannel,5Gchannel,2Gssid,5Gssid,workmode,uploadspeed,downloadspeed\
--]]\
local function  merge_mac_info(all_lan_host, mac, elinkinfo, laninfo, uselink)\
    all_lan_host[mac] = elinkinfo\
    if laninfo then\
        add_value(all_lan_host[mac], \"devname\", laninfo.devname, \"\")\
\
        -- add primary elink node info\
        if elinkinfo.elink and uselink == nil then\
            add_value(all_lan_host[mac], \"acc_type\", laninfo.acc_type, -1)\
            add_value(all_lan_host[mac], \"acc_port\", laninfo.acc_port, \"\")\
            add_value(all_lan_host[mac], \"power_level\", laninfo.power_level, -1)\
            add_value(all_lan_host[mac], \"acc_speed\", laninfo.acc_speed, -1)\
            add_value(all_lan_host[mac], \"online_time\", laninfo.online_time, -1)\
            add_value(all_lan_host[mac], \"hostname\", laninfo.hostname, \"\")\
        end\
\
        if uselink ~= true then\
            add_value(all_lan_host[mac], \"ip\", select_filed(elinkinfo.ip, laninfo.ip, \"\"), \"\")\
            add_value(all_lan_host[mac], \"rxbytes\", select_filed(elinkinfo.rxbytes, laninfo.rxbytes, -1), -1)\
            add_value(all_lan_host[mac], \"txbytes\", select_filed(elinkinfo.txbytes, laninfo.txbytes, -1), -1)\
            add_value(all_lan_host[mac], \"last_active_time\", select_filed(elinkinfo.last_active_time, laninfo.last_active_time, \"\"), \"\")\
            add_value(all_lan_host[mac], \"last_inactive_time\", select_filed(elinkinfo.last_inactive_time, laninfo.last_inactive_time, \"\"), \"\")\
        end\
    end\
end\
\
local function merge_elink_info(elink_info, lanhost, par_info, elink_topo, sn)\
    local all_lan_host = lanhost\
\
    for pmac, info in pairs(par_info) do\
        elink_info[pmac].par_mac = sn\
        local lanmac, gw_port = info[1], info[2]\
        elink_info[pmac].gw_port = gw_port\
        merge_mac_info(all_lan_host, pmac, elink_info[pmac], lanhost[lanmac])\
        for _, mac in pairs(elink_topo[pmac]) do\
            elink_info[mac].par_mac = pmac\
            elink_info[mac].gw_port = gw_port\
            local uselink = false\
            if elink_info[pmac].workmode == \"router\" then \
                uselink = true\
            end\
            merge_mac_info(all_lan_host, mac, elink_info[mac], lanhost[mac], uselink)\
            local macs = elink_topo[mac] or {}\
            for _,mac2 in pairs(macs) do\
                elink_info[mac2].par_mac = mac\
                elink_info[mac2].gw_port = gw_port\
                if elink_info[mac].workmode == \"router\" then \
                    uselink = true\
                end\
                merge_mac_info(all_lan_host, mac2, elink_info[mac2], lanhost[mac2], uselink)\
            end\
        end\
    end\
    return all_lan_host\
end\
\
local function add_elink_host(macinfo, info, mac, parmac)\
    local one = macinfo or host_add_one({mac = mac}, parmac, 1)\
    add_value(one, \"par_mac\", parmac, \"\")\
    add_value(one, \"acc_type\", info.connecttype, -1)\
    local port \
    if info.connecttype == 0 then\
        port = \"\"\
    else\
        port = info.band\
    end\
    add_value(one, \"acc_port\", port, \"\")\
    add_value(one, \"online_time\", string_to_number(info.onlineTime), -1)\
    add_value(one, \"hostname\", info.hostname, \"\")\
    add_value(one, \"power_level\", string_to_number(info.rssi), -1)\
    add_value(one, \"uploadspeed\", info.uploadspeed, \"\")\
    add_value(one, \"downloadspeed\", info.downloadspeed, \"\")\
\
    -- update\
    add_value(one, \"active\", string_to_number(info.active), 1)\
    add_value(one, \"ip\", info.ipaddr, \"\")\
    add_value(one, \"acc_speed\", string_to_number(info.negorate), -1)\
    add_value(one, \"rxbytes\", string_to_number(info.bytesreceived), -1)\
    add_value(one, \"txbytes\", string_to_number(info.bytessent), -1)\
    add_value(one, \"last_active_time\", info.activetime, \"\")\
    add_value(one, \"last_inactive_time\", info.inactivetime, \"\")\
\
    if not one.level or one.level < 2 then\
        add_value(one, \"level\", 2, 2)\
    end\
    if myip.mac_check(\"\", mac) then\
        lcmd_run{subtype = \"osinfo\", action = \"add\", key = \"hostname\", value = one.hostname, mac = mac, from = \"mesh\"}\
    end\
    return one\
end\
\
local function comp_mac(mac1, mac2)\
    number1 = tonumber(mac1, 16)\
    number2 = tonumber(mac2, 16)\
    if type(number1) ~= \"number\" then\
        return false\
    end\
    if type(number2) ~= \"number\" then\
        return true\
    end\
    return number1 < number2\
end\
\
local function add_elink_info(lanhost, sn, test, log)\
    local elink =  test.elink or call_api(\"elink\", log)\
    local devinfo, dir_graph, elink_info, hprio_mac, get_elinkap = str_to_table(elink.elinkinfo), {}, {}, {}, false\
    for k,v in pairs(devinfo) do\
        if type(v) == \"table\" and v.Result == 0 and v.apMac and type(v.apInfo) == \"table\" then \
            get_elinkap = true\
            local mac = myip.mac_fmt(v.apMac)\
            local apInfo = v.apInfo\
            elink_info[mac] = elink_info[mac] or host_add_one({mac = mac}, sn, 1)\
            add_value(elink_info[mac], \"elink\", true, true)\
            add_value(elink_info[mac], \"model\", apInfo.DeviceType, \"\")\
            add_value(elink_info[mac], \"os\", \"\", \"\")\
            add_value(elink_info[mac], \"active\", 1, 1)\
            add_value(elink_info[mac], \"level\", 3, 3)\
            add_value(elink_info[mac], \"sn\", apInfo.sn, \"\")\
            add_value(elink_info[mac], \"brand\", apInfo.vendor, \"\")\
            add_value(elink_info[mac], \"dev_type\", \"elink\", \"\")\
\
            --add 2Gchannel 5Gchannel 2Gssid 5Gssid workmode\
            local extinfo, subdev = get_ext_apinfo(v.status)\
            add_value(elink_info[mac], \"2Gchannel\", extinfo[\"2Gchannel\"], -1)\
            add_value(elink_info[mac], \"5Gchannel\", extinfo[\"5Gchannel\"], -1)\
            add_value(elink_info[mac], \"2Gssid\", extinfo[\"2Gssid\"], \"\")\
            add_value(elink_info[mac], \"5Gssid\", extinfo[\"5Gssid\"], \"\")\
            add_value(elink_info[mac], \"workmode\", extinfo.workmode, \"\")\
            lcmd_run{subtype = \"osinfo\", action = \"add_sig\", key = \"elink\", value = {apInfo.DeviceType or \"\", apInfo.vendor or \"\"}, table = true, mac = mac, from = \"mesh\"}\
            lcmd_run{subtype = \"osinfo\", action = \"save_dev_desc\", mac = myip.mac_fmt(mac, \":\"), desc = {os = \"\", brand = apInfo.vendor or \"\", model = apInfo.DeviceType or \"\", dev_type = \"elink\", devtypeint = 5, elinktype = 1}}\
\
            --add elink host\
            dir_graph[mac] = {}\
            if lanhost[mac] then\
                table.insert(hprio_mac, mac)\
            end\
            for _, info in pairs(subdev) do \
                local mac2 = myip.mac_fmt(info.mac)\
                table.insert(dir_graph[mac], mac2)\
                elink_info[mac2] = add_elink_host(elink_info[mac2], info, mac2, mac)\
            end\
        end\
    end\
    table.sort(hprio_mac, comp_mac)\
    local par_elink, elink_topo = dg2tree(dir_graph, hprio_mac)\
    log_add(log, \"dg2tree\", {par_elink, elink_topo})\
    local par_info = get_gw_port(lanhost, par_elink, elink_info)\
    log_add(log, \"get_gw_port\", par_info)\
    local all_lanhost = merge_elink_info(elink_info, lanhost, par_info, elink_topo, sn)\
    log_add(log, \"merge_elink_info\", all_lanhost)\
    return all_lanhost, get_elinkap\
end\
\
local function comp_level(table1, table2)\
    if type(table1.level) ~= \"number\" then\
        return false\
    end\
    if type(table2.level) ~= \"number\" then\
        return true\
    end\
    return table1.level > table2.level\
end\
\
local function get_port_type(all_lanhost, sn, macs, get_elinkap)\
    local typewifi = {SMTDEV = 1, Pad = 1, phone = 1}\
    local elink, route, other = {}, {}, {}\
    for _,mac in pairs(macs) do\
        local one = all_lanhost[mac] or {}\
        if one.par_mac == sn then\
            if one.elink then\
                table.insert(elink, mac)\
            elseif one.dev_type == \"route\" then\
                table.insert(route, mac)\
            elseif one.acc_type == 0 then \
                table.insert(other, mac)\
            end\
        end\
     end\
\
     local primary_mac\
     if get_elinkap and #route > 0 then -- 调用组网成功，如有路由直连网关优先选取路由为主节点\
        primary_mac = route[1]\
     else  -- elink > route > AP\
        primary_mac = elink[1] or route[1]\
     end\
\
     if not primary_mac then\
        local mac = other[1]\
        if #other > 1 then\
            primary_mac = \"AP\"\
        elseif mac and all_lanhost[mac] and all_lanhost[mac].dev_type then\
            local dev_type = all_lanhost[mac].dev_type\
            if typewifi[dev_type] then\
                primary_mac = \"AP\"\
            end\
        end\
     end\
     return primary_mac\
end\
\
\
local function get_port_info(lanhosts)\
    local port_info = {}\
    for mac, info in pairs(lanhosts) do\
        local port = info.gw_port or \"\"\
        if not port_info[port] then \
            port_info[port] = {}\
        end\
        if not info.merge then\
            table.insert(port_info[port], mac)\
        end\
    end\
\
    -- sort the mac from small to large\
    for _,macs in pairs(port_info) do\
        table.sort(macs, comp_mac)\
    end\
    return port_info\
end\
\
local function get_same_elink(lanhost, sn, macs)\
    local cat_macs, same_info = {}, {}\
    for _, mac in pairs(macs) do\
        local cat_mac = string.sub(mac, 1, 10)\
        cat_macs[cat_mac] = cat_macs[cat_mac] or {}\
        table.insert(cat_macs[cat_mac], mac)\
    end\
\
    -- choose par_mac is sn or smallest elinkmac\
    for _,macinfo in pairs(cat_macs) do\
        local pmac, min_mac\
        for _,mac in pairs(macinfo) do\
            if lanhost[mac].elink then\
                if lanhost[mac].par_mac == sn and not pmac then\
                    pmac = mac\
                elseif not min_mac then\
                    min_mac = mac\
                end\
            end\
        end\
        pmac = pmac or min_mac\
\
        if pmac and #macinfo > 1 then\
            same_info[pmac] = {}\
            for _, mac2 in pairs(macinfo) do\
                same_info[pmac][mac2] = true\
            end\
            same_info[pmac][pmac] = nil\
        end\
    end\
    return same_info\
end\
\
local function topo_gw_port(lanhosts, sn, log, get_elinkap)\
    local suffix, same_elink = 1, {}\
    local port_info = get_port_info(lanhosts)\
    for port,macs in pairs(port_info) do\
        local same_info = get_same_elink(lanhosts, sn, macs)\
        log_add(log, \"get_same_elink\", same_info)\
        for mac, info in pairs(same_info) do\
            same_elink[mac] = info\
        end\
    end\
    for port,macs in pairs(port_info) do\
        local primary_mac = get_port_type(lanhosts, sn, macs, get_elinkap)\
        log_add(log, \"get_port_type\", primary_mac)\
        if primary_mac == \"AP\" then\
            primary_mac = primary_mac..tostring(suffix)\
            suffix = suffix + 1\
            lanhosts[primary_mac] = {par_mac = sn, mac = primary_mac, acc_type = 0, acc_port = port, active = 1, dev_type = \"AP\", level = 3}\
        end\
        for _, mac in pairs(macs) do\
            if primary_mac and primary_mac ~= mac and lanhosts[mac].par_mac == sn then\
                lanhosts[mac].par_mac = primary_mac\
                lanhosts[mac].acc_speed = -1\
                lanhosts[mac].acc_port = \"\"\
            elseif primary_mac == mac and lanhosts[primary_mac].dev_type == \"route\" and #macs > 1 then\
                lanhosts[primary_mac].workmode = \"bridge\"\
            end\
        end\
    end\
    return lanhosts, same_elink\
end\
\
local function gen_topo_info(all_lanhost, sn, test, log, get_elinkap)\
    local typewifi = {SMTDEV = 1, Pad = 1, phone = 1}\
    local dtype = {ROUTER = \"route\"}\
    local bad_hostname = {unknown = true, empty = true, anonymous = true, [\"n/a\"] = true, unknow = true}\
    local online_lanhost, offline_lanhost, lanhost, same_elink = {}, {}, {}, {}\
    -- del invalid mac\
    all_lanhost[sn], all_lanhost[\"\"] = nil, nil\
    -- add desc\
    for k,v in pairs(all_lanhost) do\
        local _, osinfo = lcmd_run({subtype = \"osinfo\", action = \"get_oss\", mac = myip.mac_fmt(v.mac, \":\")})\
        local model, brand, dev_type, os\
        v.osid, v.source = osinfo.decide_osid or osinfo.cloud_osid or 0, \"local\"\
        if osinfo.iscloud == 1 then\
            v.source = \"cloud\"\
        end\
        if osinfo and osinfo.desc and osinfo.desc.dev_type then\
            model, brand, dev_type, os = osinfo.desc.model, osinfo.desc.brand, osinfo.desc.dev_type, osinfo.desc.os\
            dev_type = dtype[dev_type] or dev_type\
        end\
        if dev_type == \"elink\" then\
            add_value(v, \"elink\", true, true)\
        end\
        if not test.lanhost then\
            add_value(v, \"model\", model, \"\")\
            add_value(v, \"brand\", brand, \"\")\
            add_value(v, \"dev_type\", dev_type, \"\")\
            add_value(v, \"os\", os, \"\")\
        end\
        \
        -- change hostname:unknown,empty,anonymous,N/A,unknow\
        if v.hostname then\
            local hname = string.lower(v.hostname)\
            if bad_hostname[hname] then\
                add_value(v, \"hostname\", v.model, \"\")\
            end\
        end\
\
        if v.active == 1 then\
            lanhost[k] = v\
        else\
            offline_lanhost[k] = v\
        end\
    end\
\
    online_lanhost, same_elink = topo_gw_port(lanhost, sn, log, get_elinkap)\
    for mac,info in pairs(online_lanhost) do\
        if info.dev_type and typewifi[info.dev_type] then\
            info.acc_type = 1\
        end\
    end\
    for mac,info in pairs(same_elink) do\
        local mesh = online_lanhost[mac]\
        local mesh_desc = {dev_type = \"elink\", brand = mesh.brand, model = mesh.model, os = mesh.os, devtypeint = 5, elinktype = 1}\
        for mac2,_ in pairs(info) do\
            local one = online_lanhost[mac2]\
            one.dev_type, one.os, one.model, one.brand = mesh_desc.dev_type, mesh_desc.os, mesh_desc.model, mesh_desc.brand\
            lcmd_run{subtype = \"osinfo\", action = \"save_dev_desc\", mac = myip.mac_fmt(mac2, \":\"), desc = mesh_desc, need_save = true}\
        end\
    end\
    return online_lanhost, offline_lanhost\
end\
\
local function show_topo_info(t, online_lanhost, offline_lanhost, sn, odm)\
    local max_count, count, route_suffix, lasttime, hang_count, topo_info, pmac = 64, 0, 1, 0, 0, {}\
    if type(t.date) == \"number\" and t.date > 0 then\
        lasttime = os.time() - t.date * 3600 * 24\
    end\
    --add online host\
    for k,v in pairs(online_lanhost) do\
        if not v.merge or (t.show_hide and v.merge) then\
            table.insert(topo_info,v)\
        end\
    end\
    --add route host\
    local _, rtdev = lcmd_run({subtype = \"osinfo\", action = \"get_rtdev\"})\
    for k,v in pairs(rtdev) do\
        if pmac ~= v.par_mac then\
            pmac = v.par_mac\
            hang_count = 0\
        end\
        local par_host = online_lanhost[v.par_mac]\
        if par_host and par_host.par_mac == sn and not par_host.workmode and hang_count < topo.hang_max then\
            v.level = 0\
            v.acc_type = 1\
            if not v.mac then\
                v.mac = \"ROUTE\"..tostring(route_suffix)\
                route_suffix = route_suffix + 1\
                table.insert(topo_info,v)\
                hang_count = hang_count + 1\
            elseif v.mac and not online_lanhost[v.mac] then\
                local one =  host_add_one({mac = v.mac, connectiontype = 1, model = v.model, brand = v.brand, os = v.os, devtype = v.dev_type}, v.par_mac, odm)\
                one.level = 0\
                table.insert(topo_info,one)\
                hang_count = hang_count + 1\
            end\
            offline_lanhost[v.mac] = nil\
        end\
    end\
    --add offline host\
    if t.active ~= 1 then\
        for k,v in pairs(offline_lanhost) do\
            v.level = -1\
            if myip.time_strtotime(v.last_active_time) >= lasttime then\
                table.insert(topo_info,v)\
            end\
        end\
    end\
    if #topo_info > max_count then\
        table.sort(topo_info,comp_level)\
        for k,v in pairs(topo_info) do\
            if k > max_count then\
                topo_info[k] = nil\
            end\
        end\
    end\
    for k,v in pairs(topo_info) do\
        v.level, v.elink, v.gw_port, v.merge = nil, nil, nil, nil\
        if v.dev_type == \"route\" then\
            v.workmode = nil\
        end\
        if not t.show_hide then\
            v.source, v.osid = nil, nil\
        end\
    end\
    return topo_info\
end\
\
local function get_speed(speedtype, all, last, time)\
    local allspeed, lastspeed = all[speedtype], last[speedtype]\
    if type(allspeed) == \"table\" and type(lastspeed) == \"table\" then\
        for k,v in pairs(allspeed) do\
            local last = lastspeed[k]\
            local tx, rx = 0, 0\
            if type(v) == \"table\" and type(last) == \"table\" then\
                tx = v.tx_bytes - last.tx_bytes or v.tx_bytes\
                rx = v.rx_bytes - last.rx_bytes or v.rx_bytes\
            end\
            if tx > 0 then\
                v.up_speed = tx//(1024 * time)\
            end\
            if rx > 0 then\
                v.down_speed = rx//(1024 * time)\
            end\
        end\
    end\
end\
\
local function deal_speed(time, last_speed, wlan, speedinfo, accspeed)\
    local list = {}\
    local all_speed = {time = time, wan = {}, lan = {}, wifi = {}}\
    local all_type = {\"wan\", \"lan\", \"wifi\"}\
    local deal_time\
\
    if wlan and not wlan.osgi then\
        for k, v in pairs(wlan) do\
            local x = v.ssid or \"\"\
            all_speed.wifi[x] = {type = \"wifi\", subtype = v.ssid or \"\", up_speed = 0, down_speed = 0, tx_bytes = v.tx or 0, rx_bytes = v.rx or 0, acc_speed = 0}\
        end\
    end\
    \
    if speedinfo and accspeed then\
        for i=1,4 do\
            local x = tostring(i)\
            all_speed.lan[x] = {type = \"lan\", subtype = x, up_speed = 0, down_speed = 0, tx_bytes = speedinfo[x..\"_tx\"] or 0, rx_bytes = speedinfo[x..\"_rx\"] or 0, acc_speed = accspeed[x..\"_speed\"] or 0}\
        end\
        all_speed.wan[1] = {type = \"wan\", subtype = \"1\", up_speed = 0, down_speed = 0, tx_bytes = speedinfo[\"wan_tx\"] or 0, rx_bytes = speedinfo[\"wan_rx\"] or 0, acc_speed = 0}\
    end\
\
    if last_speed.time and all_speed.time - last_speed.time < 180 and all_speed.time - last_speed.time > 0 then\
        deal_time = all_speed.time - last_speed.time\
        for _,v in pairs(all_type) do\
            get_speed(v, all_speed, last_speed, deal_time)\
        end\
    end\
\
    for k,v in pairs(all_speed) do\
        if type(v) == \"table\" then\
            for m,n in pairs(v) do\
                table.insert(list, n)         \
            end\
        end\
    end\
    topo.last_speed = all_speed\
    topo.last_speed.time = time\
\
    return list\
\
end\
\
local function show_speed(t)\
    -- postmsg input '{\"subtype\":\"ct\",\"stype\":\"postmsg\",\"action\":\"show_topo/show_speed\"}'\
    -- client and send_topo are not controlled\
    if not topo.postmsg_enable and t.stype then\
        return\
    end\
\
    --hot_topo\
    local ok, speeds = lcmd_run({subtype = \"hot_topo\", action = \"show_speed\"})\
    if ok and type(speeds) == \"table\" then\
        return speeds\
    end\
\
    local time = os.time()\
    local r = {list={}}\
    local wlan, speedinfo, accspeed\
    wlan = call_api(\"wlan\")\
    speedinfo = call_api(\"speed\")\
    accspeed = call_api(\"accspeed\")\
\
    local s = deal_speed(time, topo.last_speed or {}, wlan, speedinfo, accspeed)\
    if #s == 0 then\
        table.insert(r.list, {})\
    else\
        r.list = s\
    end\
\
    return r\
end\
\
local function show_topo(t)\
    if not topo.postmsg_enable and t.stype then\
        return\
    end\
    local btime, log, test = os.time(), {}, {}\
    local stype = t.stype or \"dpi\"\
    local odm = call_api(\"odm\")\
\
    if t.sendsig then\
        lcmd_run({subtype = \"sigcollect\", action = \"send\"})\
    end\
    if type(t.lanhost) == \"table\" and type(t.elinklanhost) == \"table\" then\
        test = {lanhost = t.lanhost, elink = t.elinklanhost, brmacs = t.brmacs}\
    end\
\
    local ok, arch = lcmd_run({subtype = \"arch\", action = \"read\"})\
    if not ok or type(arch) ~= \"table\" then\
        arch = {sn = \"\"}\
    end\
    local gw_info = get_gw_info(log)\
    local sn = gw_info.mac or arch.sn\
    local lanhost = get_lanhost_info(sn, log, test, topo.brmacs_enable, topo.agetime)\
    local all_lanhost, get_elinkap = add_elink_info(lanhost, sn, test, log)\
    local online_lanhost, offline_lanhost = gen_topo_info(all_lanhost, sn ,test, log, get_elinkap)\
    local topo_info = show_topo_info(t, online_lanhost, offline_lanhost, sn, odm)\
    topo.count = topo.count + 1\
    local etime = os.time()\
    local result = {Result = 0, gw_info = gw_info, topo_info = topo_info}\
    log_set(topo.log, topo.max_debug, {cmd = \"show_topo\", call = log, send = true, type = stype, res = cjson.encode(result), btime = btime, etime = etime})       \
\
    return result\
end\
\
local function gen_tree(mac, array)\
\9local tree = {}\
\9tree.mac = mac\
\9tree.nodes = {}\
\
\9for k,v in pairs(array) do \
\9\9if v.mac == mac then\
\9\9\9tree.val = v\
\9\9\9array[k] = nil\
\9\9end\
\
\9\9if v.par_mac == mac then\
\9\9\9tree.nodes[v.mac] = gen_tree(v.mac,array)\
\9\9end\
\9end\
\
\9return tree\
end\
\
local function dump_tree(tree,level)\
\9local str = \"\"\
\9local sub = \"\"\
\9if tree.val then\
\9\9local one = tree.val\
\9\9str = string.format(\"|%smac(%s) ip(%s) active(%d) acc_type(%d) model(%s) brand(%s) dev_type(%s) os(%s) hostname(%s)\",\
\9\9\9\9\9\9\9string.rep(\"-\", level*8),tree.mac, one.ip or \"\", one.active or -1, one.acc_type or -1,one.model or \"\", one.brand or \"\", one.dev_type or \"\", one.os or \"\", one.hostname or \"\") .. \" acc_port \"..tostring(one.acc_port or -1) .. \"\\n\"\
\9else\
\9\9str = string.format(\"|%s%s GW\\n\",string.rep(\"-\", level*8),tree.mac)\
\9end\
\
\9for k,v in pairs(tree.nodes) do \
\9\9sub = dump_tree(v, level+1)\
\9\9str = str..sub\
\9end\
\
\9return str\
end\
\
local function show_topo_tree(t)\
\9tinfo = show_topo(t)\
\9local tree = gen_tree(tinfo.gw_info.mac,tinfo.topo_info)\
\9return dump_tree(tree, 1)\
end\
\
local function test_tree(t)\
local list = {}\
table.insert(list, {par_mac=\"1\", mac = \"11\"})\
table.insert(list, {par_mac=\"1\", mac = \"12\"})\
table.insert(list, {par_mac=\"1\", mac = \"13\"})\
table.insert(list, {par_mac=\"11\", mac = \"111\"})\
table.insert(list, {par_mac=\"12\", mac = \"121\"})\
table.insert(list, {par_mac=\"12\", mac = \"122\"})\
table.insert(list, {par_mac=\"12\", mac = \"123\"})\
table.insert(list, {par_mac=\"12\", mac = \"124\"})\
table.insert(list, {par_mac=\"13\", mac = \"131\"})\
table.insert(list, {par_mac=\"13\", mac = \"132\"})\
table.insert(list, {par_mac=\"13\", mac = \"133\"})\
table.insert(list, {par_mac=\"133\", mac = \"1331\"})\
table.insert(list, {par_mac=\"1331\", mac = \"13311\"})\
table.insert(list, {par_mac=\"13311\", mac = \"133111\"})\
local tree = gen_tree(\"1\",list)\
return dump_tree(tree, 1)\
end\
\
local function show_debug(t)\
    local log = {}\
    if not t.send then\
        return topo.log\
    elseif topo.debug_enable == 0 then\
        return log\
    end\
    for k,v in pairs(topo.log) do\
        if v.send then\
            table.insert(log, v)\
            v.send = false\
        end\
    end\
    return log\
end\
\
local function send_topo_info()\
    local topo_info = show_topo({show_hide = 1})\
    data_uploaded = { type = \"topo_upload\", data = {topo_info}, period = topo.send_period, timestamp = tostring(os.time())}\
    lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = data_uploaded})\
    topo.send_count = topo.send_count + 1\
end\
\
local function send_topo_active_info()\
    local info = show_topo({ active = 1, disable_sync_info_with_svr = true, show_hide = 1 })\
    if #info.topo_info > 0 then\
        data_uploaded = { type = \"topo_upload\", data = {info}, period = topo.send_active_period, timestamp = tostring(os.time())}\
        lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = data_uploaded})\
        topo.send_active_count = topo.send_active_count + 1\
    end\
end\
\
local function write(msg)\
    if msg.send_period and msg.send_period ~= topo.send_period then\
        log.info(\"send_topo send_period change to \", msg.send_period, \"from \", topo.send_period)\
        topo.send_period = tonumber(msg.send_period)\
        timer.mod(\"send_topo\", topo.send_period, 0, send_topo_info)\
    end\
    if msg.send_active_period and msg.send_active_period ~= topo.send_active_period then\
        log.info(\"send_topo_active send_active_period change to \", msg.send_active_period, \"from \", topo.send_active_period)\
        topo.send_active_period = tonumber(msg.send_active_period)\
        timer.mod(\"send_topo_active\", topo.send_active_period, 0, send_topo_active_info)\
    end\
    if type(msg.postmsg_enable) == \"boolean\" then\
        topo.postmsg_enable = msg.postmsg_enable\
    end\
    if type(msg.hang_max) == \"number\" and msg.hang_max ~= topo.hang_max then\
        topo.hang_max = msg.hang_max\
    end\
    if type(msg.brmacs_enable) == \"boolean\" then\
        topo.brmacs_enable = msg.brmacs_enable\
    end\
    if type(msg.agetime) == \"number\" then\
        topo.agetime = msg.agetime\
    end\
end\
\
local function debug(t)\
    local count\
    if t.enable then\
        topo.debug_enable = tonumber(t.enable)\
    end\
    if t.max_cnt then\
        count = tonumber(t.max_cnt) or 0\
        topo.max_debug = count\
    end\
\
    if count then\
        log_set(topo.log, count)\
    end\
end\
\
function topo.postinit()\
    timer.mod(\"send_topo\", topo.send_period, 0, send_topo_info)\
    timer.mod(\"send_topo_active\", topo.send_active_period, 0, send_topo_active_info)\
end\
\
local function gen_topo_test(t) \
    local lanhost = t.lanhost or {}\
    local elinklanhost = t.elinklanhost or {}\
    local argv, info = {lanhost = lanhost, elinklanhost = {elinkinfo = cjson.encode(elinklanhost)}, show_hide = t.show_hide, brmacs = t.brmacs}\
    if t.show_topo then\
        info = show_topo(argv)\
    else\
        info = show_topo_tree(argv)\
    end\
    return info\
end\
\
local function read()\
    return {send_period = topo.send_period, send_active_period = topo.send_active_period, count = topo.count, send_count = topo.send_count, send_active_count = topo.send_active_count, enable=topo.debug_enable, postmsg_enable = topo.postmsg_enable, max_cnt=topo.max_debug, hang_max = topo.hang_max, brmacs_enable = topo.brmacs_enable, agetime = topo.agetime}\
end\
\
actor.action_set(topo.subtype, \"show_topo\", show_topo, [[get topo info from CAPI and DBUS, {active = number,date = number}, active 1 means online, data filter last_active_time]]) \
actor.action_set(topo.subtype, \"show_topo_tree\", show_topo_tree, [[show topo info as tree struct args is same as show_topo  {active = number,date = number}, active 1 means online, data filter last_active_time]]) \
actor.action_set(topo.subtype, \"test_tree\", test_tree, [[test topo tree]]) \
\
actor.action_set(topo.subtype, \"show_speed\", show_speed, [[get speed info from CAPI,lua will calculate]]) \
actor.action_set(topo.subtype, \"show_debug\", show_debug, [[show log]]) \
actor.action_set(topo.subtype, \"write\", write, [[change get route period,{send_period = number, send_active_period = number},default 86400 86400 3600]]) \
actor.action_set(topo.subtype, \"read\", read, \"read topo stat\")\
actor.action_set(topo.subtype, \"topo_testset\", gen_topo_test, [[ct topo test,{lanhost={mac={}}},elinklanhost={{},{}}}]]) \
actor.action_set(topo.subtype, \"debug\", debug, [[set topo debug, {enable=1/0, max_cnt=number}]]) \
return topo\
"
, '@'.."./service/topo.lua" ) )

package.preload[ "tuple" ] = assert( (loadstring or load)(
"\
local cjson = require(\"cjson\")\
local kernel = require(\"c.kernel\")\
local actor = require(\"luactor\")\
local myip = require(\"myip\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local mystring = require(\"mystring\")\
local myip = require(\"myip\")\
\
local tuple = {\
    all_count = 0,\
    all_len = 0,\
    subtype = \"tuple\",\
    upload_type = \"tuple_info_v1\",\
    period = 5,\
    upload_mode = \"none\", -- \"none\", \"svrdata\", \"operdata\", \"all\"\
    timer_name = 'tuple_get', \
    help = \"get tuple from kernel, send to server\"\
}\
\
local function tuple_get_one(sbytes, pos, len)\
\9local format='=IIIIIc4c4IIHHBBHc6HIIBBBBIIIIIII'\
\9local tuple_info = {}\
\
\9tuple_info.all_len, \
\9tuple_info.pkts_in, \
\9tuple_info.pkts_out, \
\9tuple_info.bytes_in, \
\9tuple_info.bytes_out, \
\9tuple_info.sip, \
\9tuple_info.dip, \
    tuple_info.appid,\
    tuple_info.ruleid,\
\9tuple_info.sport, \
\9tuple_info.dport, \
\9tuple_info.proto, \
\9tuple_info.svr_local, \
\9tuple_info.L7_len, \
\9tuple_info.mac, \
\9tuple_info.pad, \
\9tuple_info.start_time, \
\9tuple_info.end_time, \
    tuple_info.state,\
    tuple_info.latency_valid,\
    _ , tuple_info.latency_cnt,\
    tuple_info.lat1,\
    tuple_info.lat2,\
    tuple_info.lat3,\
    tuple_info.lat4,\
    _ , _ ,\
\9tuple_info.base_appid = string.unpack(format, sbytes, pos)\
\
\9tuple_info['type'] = tuple.upload_type\
\9tuple_info['is_app'] = 0\
\9tuple_info['app_id'] = tuple_info.appid\
\9tuple_info['sip'] = myip.inet_ntoa(tuple_info['sip'])\
\9tuple_info['dip'] = myip.inet_ntoa(tuple_info['dip'])\
\9tuple_info['mac'] = mystring.data2hex(tuple_info['mac'], \":\")\
\9tuple_info['pad'] = nil\
\9tuple_info['L7_len'] = nil\
\
    if tuple_info.proto == 6 then\
        if tuple_info.latency_valid > 0 then\
            if tuple_info.state == CENUM.CTX_STAT_STATE_TCP_FIN then\
                tuple_info.lat_status = \"fin\"\
            elseif tuple_info.state == CENUM.CTX_STAT_STATE_TCP_RST then\
                tuple_info.lat_status = \"rst\"\
            elseif tuple_info.latency_cnt >= 2 then\
                tuple_info.lat_status = \"ok\"\
            else\
                tuple_info.lat_status = \"fail\"\
            end\
        else\
            tuple_info.lat_status = \"abnormal\"\
        end\
    elseif tuple_info.proto == 17 then\
        if tuple_info.latency_valid > 0 then\
            if tuple_info.latency_cnt >= 1 then\
                tuple_info.lat_status = \"ok\"\
            else\
                tuple_info.lat_status = \"fail\"\
            end\
        else\
            tuple_info.lat_status = \"abnormal\"\
        end\
    else\
        tuple_info.lat_status = \"none\"\
    end\
    local all_len = tuple_info.all_len\
    tuple_info.all_len = nil\
    tuple_info.latency_cnt = nil\
    tuple_info.latency_valid = nil\
    tuple_info.state = nil\
\
    --log.info(\"get one tuple, \", cjson.encode(tuple_info))\
    actor.publish({msgtype = \"TUPLE\", tuple_info = tuple_info})\
\
    if tuple.upload_mode ~= \"none\" then\
        if tuple.upload_mode == \"operdata\" or tuple.upload_mode == \"all\" then\
            lcmd_run({subtype = \"__oper_data\", action = \"add\", data = tuple_info})\
        end\
        if tuple.upload_mode == \"svrdata\" or tuple.upload_mode == \"all\" then\
            lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tuple_info})\
        end\
        tuple.all_len = tuple.all_len + string.len(cjson.encode(tuple_info))\
        tuple.all_count = tuple.all_count + 1\
    end\
\
\9return  all_len\
end\
\
local function tuple_get(sbytes)\
    local len = sbytes:len() used_len = 0\
\
    while used_len < len do\
        one_size = tuple_get_one(sbytes, used_len + 1, len)\
        if one_size <= 0 then\
            return -1\
        end\
        used_len = used_len + one_size\
    end\
\
    if used_len ~= len then\
        return -1;\
    end\
\
    return len\
end\
\
local function tuple_engine_opt(is_enable)\
    local sbytes = \"\" enable = 0\
\9if is_enable ~= 0 then\
        enable = 1\
\9end\
\9sbytes = string.pack(\"=i\", enable)\
\9kernel.send(CENUM.MEMSHR_U2K_TUPLE_ENABLE, sbytes)\
end\
\
local function write(msg)\
    log.info(\"tuple period change to \", msg.period, \"from \", tuple.period)\
    if type(msg.period) == \"number\" and msg.period ~= tuple.period then\
        tuple.period = msg.period\
        timer.mod(tuple.timer_name, tuple.period, 0, function () kernel.call(CENUM.MEMSHR_K2U_TUPLE, \"\", tuple_get) end)\
        if tuple.period > 0 then\
\9\9\9tuple_engine_opt(1)\
        else\
\9\9\9tuple_engine_opt(0)\
        end\
    end\
    if type(msg.upload_mode) == \"string\" and msg.upload_mode ~= tuple.upload_mode then\
        if msg.upload_mode == \"none\" or msg.upload_mode == \"svrdata\" or msg.upload_mode == \"operdata\" or msg.upload_mode == \"all\" then\
            tuple.upload_mode = msg.upload_mode\
        end\
    end\
end\
\
function tuple.postinit()\
    if tuple.period > 0 then\
        tuple_engine_opt(1)\
        timer.mod(tuple.timer_name, tuple.period, 0, function () kernel.call(CENUM.MEMSHR_K2U_TUPLE, \"\", tuple_get) end)\
    end\
end\
\
actor.action_set(tuple.subtype, \"get_kernel\", function () kernel.call(CENUM.MEMSHR_K2U_TUPLE, \"\", tuple_get) end, \
                 \"get tuple from kernel manualy\")\
actor.action_set(tuple.subtype, \"read\", function () return {period = tuple.period, upload_mode = tuple.upload_mode} end, \"read period\")\
actor.action_set(tuple.subtype, \"stat\", function () return {all_count = tuple.all_count, all_len = tuple.all_len} end, \"read stat count and len\")\
actor.action_set(tuple.subtype, \"write\", write, [[set tuple period, {period = number}, 0 means close engine]])\
\
return tuple\
"
, '@'.."./service/tuple.lua" ) )

package.preload[ "upgrade" ] = assert( (loadstring or load)(
"local actor = require\"luactor\"\
local cthread = require\"c.thread\"\
local log = require\"log\"\
local myfile = require\"myfile\"\
\
local upgrade = {\
    type = \"upgrade\", \
    subtype = \"upgrade\", \
    help = \"upgrade for plugin/lua/sig\", \
    upgrading = false, \
    ufile = \"ttupgrade.tgz\", \
}\
\
-------------------------------------------------------------------\
-- New Thread to run this function, download file , write to tmppath,\
-- and trigger upgrade_post\
-------------------------------------------------------------------\
local function upgrade_http(t)\
    local http = require\"socket.http\"\
    log.warn(string.format(\"upgrade http, url(%s), module(%s)......\", t.url, t.module))\
    local body, code = http.request(t.url)\
    if code ~= 200 then\
        log.error(string.format(\"failed to load (%s), code (%d)\", t.url, code))\
        return\
    end\
\
    log.warn(string.format(\"upgrade http, url(%s), module(%s)......Done, size(%d)\", t.url, t.module, #body))\
    myfile.write(body, lcmd_tmp_path(upgrade.ufile))\
    local args = string.format([[{\"subtype\":\"upgrade\", \"action\":\"upgrade_post\", \"module\":\"%s\", \"version\":\"%s\"}]], t.module, t.version)\
    lcmd_client(true, lcmd_tmp_path(\"\"), args)\
end\
\
-------------------------------------------------------------------\
-- origin thread to run, exit code, see app_dpi_process.h\
-------------------------------------------------------------------\
-- enum {\
--     APP_RETCODE_NORMAL = 128,\
--     APP_RETCODE_ERROR = 129,\
--     APP_RETCODE_UPDATE = 130,\
--     APP_RETCODE_UPDATE_LUA = 131, \
--     APP_RETCODE_UPDATE_SIG = 132, \
\
--     APP_RETCODE_RESTORE = 160, \
-- };\
local function upgrade_post(t)\
    local ret_code = 0\
    log.warn(\"will upgrade post\", t.module)\
    if t.module ~= \"lua\" and t.module ~= \"sig\" and t.module ~= \"plugin\" then\
        log.error(\"wrong module, \", t.module)\
        return\
    end\
\
    if t.module == \"lua\" then\
        -- bootjs.luadata = 1\
        ret_code = 131\
    elseif t.module == \"sig\" then\
        -- bootjs.sigdata = 1\
        ret_code = 132\
    else\
        -- only write version here\
        local bootjs, err = myfile.load_json(lcmd_data_path(\".bootchk\"))\
        if not bootjs then\
            bootjs = {}\
            log.warn(\"first upgrade with empty bootjs\")\
        end\
        bootjs.version = t.version\
        myfile.store_json(bootjs, lcmd_data_path(\".bootchk\"))\
        ret_code = 130\
    end\
\
    -- will rename/unzip file in watch_daemon\
    -- os.remove(lcmd_tmp_path(upgrade.ufile))\
    log.warn(\"will restart program for upgrade \", t.module, t.version)\
    os.exit(ret_code)\
end\
\
local function do_upgrade(t)\
    if upgrade.upgrading then\
        log.error(\"Please wait upgrade done...\")\
        return\
    end\
\
    if type(t.url) ~= \"string\" or type(t.module) ~= \"string\" then\
        log.error(\"wrong upgrade parameter, module \", t.module)\
        return\
    end\
\
    local version = t.version or \"\"\
    local args = string.format([[{\"subtype\":\"upgrade\", \"action\":\"upgrade_http\", \"url\":\"%s\", \"module\":\"%s\", \"version\":\"%s\"}]], t.url, t.module, version)\
    cthread.run(args)\
end\
\
local function restore()\
    local bb = os.remove(lcmd_data_path(\".bootchk\"))\
    if bb then\
        os.exit(160)\
    end\
end\
\
actor.action_set(upgrade.subtype, \"read\", function () return {upgrading = upgrade.upgrading} end, \"read upgrading status\")\
actor.action_set(upgrade.subtype, \"restore\", restore, \"restore as origin plugin\")\
actor.action_set(upgrade.subtype, \"upgrade_post\", upgrade_post, \"upgrade, {module = xx}\")\
actor.action_set(upgrade.subtype, \"upgrade_http\", upgrade_http, \"upgrade, {url = xx, module = xx}\")\
actor.action_set(upgrade.subtype, \"upgrade\", do_upgrade, \"upgrade, {url = xx, module = [sig | lua | plugin]}, and version needed only for plugin\")\
\
return upgrade\
"
, '@'.."./service/upgrade.lua" ) )

package.preload[ "upnp" ] = assert( (loadstring or load)(
"local socket = require\"socket\"\
local http = require('httpclient').new()\
local myip = require(\"myip\")\
local timer = require(\"timer\")\
local actor = require(\"luactor\")\
local log = require(\"log\")\
local cjson = require(\"cjson\")\
\
local upnp = {\
    type = \"upnp\",\
    subtype = \"upnp\",\
    help = \"upnp find host\",\
    ip = \"\",\
    iface = \"br0\",\
}\
\
local function xml_parse(xml)\
  local idx_cur = 1\
  local root = {}\
  local node_cur = root\
  local nodes = {}\
\
  while true do\
    local idx_start, idx_end, end_tag, label, args, empty = string.find(xml, \"<(%/?)([%w:]+)(.-)(%/?)>\", idx_cur)\
\
    if not idx_start then break end\
\
    if end_tag == \"\" then -- start tag\
      node_cur[label] = {}\
      nodes[#nodes+1] = node_cur[label]\
      node_cur = nodes[#nodes]\
    else -- end tag\
      table.remove(nodes)\
      node_cur = nodes[#nodes]\
\
      local value = string.sub(xml, idx_cur, idx_start - 1)\
\
      if not string.find(value, \"^%s*$\") then\
\9  node_cur[label] = value\
      end\
    end\
    idx_cur = idx_end + 1\
  end\
\
  return root\
end\
\
function get_upnp(t)\
    local udp=socket.udp4()\
    local timeout = 2\
    local ipaddr = upnp.ip\
    local info = {}\
\
    if not ipaddr or ipaddr == \"\" then\
        ok, ipaddr = myip.getip(upnp.iface)\
        if not ok then\
            return info\
        end\
        upnp.ip = ipaddr\
    end\
    udp:settimeout(0.1)\
    local pkt_ssdp_discover = table.concat({\
        'M-SEARCH * HTTP/1.1\\r\\n',\
        'HOST: 239.255.255.250:1900\\r\\n',\
        'MAN: \"ssdp:discover\"\\r\\n',\
        'MX: 3\\r\\n',\
        'ST: ssdp:all\\r\\n',\
        '\\r\\n'\
    })\
\
    assert(udp:setoption('reuseaddr', true))\
    assert(udp:setsockname(ipaddr, 1900))\
    assert(udp:sendto(pkt_ssdp_discover, \"239.255.255.250\", 1900))\
    local start = os.time()\
    local anwser = {}\
    while (os.time() - start < timeout) do\
        local discover_response, ip, port = udp:receivefrom()\
        if discover_response and port == 1900 then\
            local location = string.match(discover_response,\"LOCATION:%s+(http://%S+)\")\
            anwser[ip] = location\
        end\
    end\
\
    for k,v in pairs(anwser) do\
        if v ~= \"\" then\
            local response = http:get(v)\
            if not response.err then\
                local deviceinfo = xml_parse(response.body) \
                if deviceinfo and deviceinfo.root and deviceinfo.root.device then\
                    local ss = deviceinfo.root.device.modelName\
                    info[k] = {ss}\
                end\
            end\
        end\
    end\
    assert(udp:close())\
    local tt = {}\
    local arp = myip.getarp()\
    for ip,dev_info in pairs(info) do\
        local mac = arp[ip]\
        mac = myip.mac_check(\"\", mac)\
        if mac then\
            tt[mac] = dev_info\
        end\
    end\
    return tt\
end\
\
local function write(msg) --修改参数设置\
    if msg.iface then\
        upnp.iface = msg.iface\
        upnp.ip = \"\"\
    end\
end\
\
actor.action_set(upnp.subtype, \"read\", function () return {period = upnp.period, iface = upnp.iface} end, \"read period and stat\")\
actor.action_set(upnp.subtype, \"write\", write, [[set upnp iface, {iface = string}]])\
actor.action_set(upnp.subtype, \"get_upnp\", get_upnp, [[show upnp info]])\
\
return upnp\
"
, '@'.."./service/upnp.lua" ) )

package.preload[ "wandns" ] = assert( (loadstring or load)(
"local actor = require(\"luactor\")\
local timer = require(\"timer\")\
local log = require(\"log\")\
local cjson = require(\"cjson\")\
local sys = require(\"sys\")\
local cct = require(\"c.ct\")\
local ctime = require\"c.time\"\
\
local wandns = {\
    type = \"wandns\",\
    subtype = \"wandns\",\
    help = \"get dns server info from capi and send to server\",\
    timer_name = \"wandns_get\",\
    period = 3600,\
    send_period = 86400,\
    lasttime = 0,\
    all_count = 0,\
    dns = {},\
}\
\
local function get_wan_dns()\
    local now_dns = { dns1 = \"\", dns2 = \"\" }\
    local dns_info = cct.getdnsserver()\
    \
    if dns_info then\
        if type(dns_info['dns']) == \"string\" then\
            now_dns['dns1'] = dns_info['dns']\
        end\
        if type(dns_info['dns2']) == \"string\" then\
            now_dns['dns2'] = dns_info['dns2']\
        end\
    end\
    return now_dns\
end\
\
local function check_wan_dns()\
    local now_dns = get_wan_dns() \
\
    local uptime = ctime.get_uptime()\
    local need_upload = false\
\
    if now_dns['dns1'] ~= wandns.dns['dns1'] or now_dns['dns2'] ~= wandns.dns['dns2'] then\
        need_upload = true\
        wandns.dns = now_dns\
    else\
        if wandns.lasttime + wandns.send_period <= uptime then\
            need_upload = true\
        end\
    end\
\
    if need_upload then\
        local tt = {\
            type = \"wandns\",\
            dns1 = wandns.dns['dns1'],\
            dns2 = wandns.dns['dns2'],\
        }\
        lcmd_run{subtype = \"__oper_data\", action = \"add\", data = tt}\
        wandns.all_count = wandns.all_count + 1\
        wandns.lasttime = uptime\
    end\
\
end\
\
local function write(t)\
    if t.period and tonumber(t.period) ~= wandns.period then\
        log.info(\"wandns period change to \", t.period, \"from \", wandns.period)\
        wandns.period = tonumber(t.period)\
        timer.mod(wandns.timer_name, wandns.period, 0, check_wan_dns)\
    end\
    if t.send_period and tonumber(t.send_period) ~= wandns.send_period then\
        log.info(\"wandns send_period change to \", t.send_period, \"from \", wandns.send_period)\
        wandns.send_period = tonumber(t.send_period)\
    end\
end\
\
function wandns.postinit()\
    wandns.dns = get_wan_dns()\
    wandns.lasttime = ctime.get_uptime() \
    timer.mod(wandns.timer_name, wandns.period, 0, check_wan_dns)\
end\
\
actor.action_set(wandns.subtype, \"read\", function() return {period = wandns.period, send_period = wandns.send_period, all_count = wandns.all_count} end, \"read wandns conf\")\
actor.action_set(wandns.subtype, \"write\", write, [[set get wandns period and send_period,{period=number,send_period = number}, period 0 will not set]])\
\
return wandns\
"
, '@'.."./service/wandns.lua" ) )

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

end

assert( (loadstring or load)(
"\
if not rootpath then rootpath = \".\" end\
\
local function concat_path(prefix, ...)\
    local luapath = \"\"\
    for i, v in ipairs({...}) do\
        luapath = luapath .. prefix..\"/\".. v .. \";\"\
    end\
    return luapath\
end\
\
package.path = concat_path(rootpath, \"?.lua\", \"service/?.lua\", \"service/?/?.lua\", \"lualib/?.lua\", \"lualib/?/?.lua\")\
package.cpath = concat_path(rootpath, \"luaclib/?.so\")\
\
local cjson = require(\"cjson\")\
local actor = require(\"luactor\")\
local log = require(\"log\")\
local timer = require(\"timer\")\
local myfile = require(\"myfile\")\
local sockfile = \".__scli\"\
local loop_running = true\
\
-- path def\
local g_tmppath = \"\"\
local g_datapath = \"\"\
\
cjson.encode_sparse_array(true)\
\
function __lcmd_actor()\
    return actor\
end\
\
function lcmd_loop_exit()\
    loop_running = false\
end\
\
function lcmd_run(t)\
    return pcall(actor.deal_reply, t)\
end\
\
function lcmd_tmp_path(fname)\
    return g_tmppath..\"/\"..fname\
end\
\
function lcmd_data_path(fname)\
    if not g_datapath then\
        return nil\
    end\
    return g_datapath..\"/\"..fname\
end\
\
function lcmd_conf_save_filename()\
    if not g_datapath then\
        return nil\
    end\
    return g_datapath..\"/conf_init.json\"\
end\
\
function lcmd_runmsg(msg)\
    local ok, t = pcall(cjson.decode, msg)\
    if not ok or type(t) ~= \"table\" then\
        return nil, \"failed to lcmd run msg, cjson decode err, \", err\
    end\
    local ok, result = lcmd_run(t)\
    if not ok then\
        return nil, \"failed to run\"..result\
    end\
    if type(result) == \"string\" or type(result) == \"table\" then\
        return cjson.encode(result), nil\
    end\
    return nil, nil\
end\
\
local function init_config_file(config, config_local)\
    -- init config && config_local\
    local t, err = myfile.load_json(config)\
    if t == nil then\
        return \"failed load config, err is \"..err\
    end\
    for _, v in pairs(t.__conf_init__) do \
        actor.deal_reply(v)\
    end\
    local saveconf\
    if config_local ~= nil then\
        saveconf, err = myfile.load_json(config_local)\
        if not err then\
            for _, v in pairs(saveconf) do \
                actor.deal_reply(v)\
            end\
        end\
    end\
    return nil\
end\
\
function lcmd_boot(tmppath, datapath)\
    local mystring = require\"mystring\"\
    local tmpp, fsock = mystring.split(tmppath, \":\")\
    g_tmppath = tmpp\
    g_datapath = datapath\
\
    if fsock then sockfile = fsock end\
    \
    -- load all service\
    local a = assert(require(\"config_service\"))\
    for k, v in pairs(a) do\
        local service = assert(require(v))\
        actor.actor_add(service)\
    end\
\
    -- init protobuf\
    actor.pb_init()\
end\
\
function lcmd_init(config, ...)\
    -- initmsg first\
    for _, initmsg in ipairs({...}) do\
        if type(initmsg) == \"string\" and initmsg ~= \"\" then\
            lcmd_runmsg(initmsg)\
        end\
    end\
\
    -- kengine init\
    local kengine = require(\"kengine\")\
    kengine.kengine_init()\
\
    -- init config and local\
    init_config_file(config, lcmd_conf_save_filename())\
\
    -- init unix server\
    local cli = require'cliserver'\
    err = cli.init(lcmd_tmp_path(sockfile))\
    if err then\
        log.fatal(err)\
        return err\
    end\
\
    actor.post_init()\
    return nil\
end\
\
function lcmd_loop()\
    local msocket = require(\"msocket\")\
    local last = os.time()\
    while loop_running do\
        msocket.run(1000)          -- using 1000 ms precision timer\
        now = os.time()\
        if now - last > 2 or now < last then\
            timer.run_now(now)\
            last = now\
        end\
    end\
end\
\
function lcmd_client(ismainp, tmppath, ...)\
    local mystring = require\"mystring\"\
    local cli = require(\"cliclient\")\
\
    local tmpp, fsock = mystring.split(tmppath, \":\")\
    if fsock then\
        return cli.main(ismainp, tmpp ..\"/\".. fsock, ...)\
    else\
        return cli.main(ismainp, tmpp ..\"/\".. sockfile, ...)\
    end\
end\
\
function lcmd_unittest(...)\
    package.path = concat_path(rootpath, \"?.lua\", \"service/?.lua\", \"service/?/?.lua\", \"lualib/?.lua\", \"lualib/?/?.lua\", \"unittest/?.lua\")\
\
    -- load all service\
    local a = assert(require(\"config_service\"))\
    for k, v in pairs(a) do\
        local service = assert(require(v))\
        actor.actor_add(service)\
    end\
\
\
    local lu = require\"luaunit\"\
    local p = io.popen(string.format(\"find %s/unittest -name *_test.lua\", rootpath))\
    for file in p:lines() do\
        local fmod, id = string.gsub(file, \"^.*/(.*_test).lua\",\"%1\")\
        if id == 1 then\
            log.info(\"add unittest \"..fmod)\
            require(fmod)\
        end\
    end\
    p:close()\
\
    lu.LuaUnit.run(...)\
end\
"
, '@'.."init.lua" ) )( ... )

