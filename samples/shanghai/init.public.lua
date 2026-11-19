-- m01-b01-inner | shanghai | public source edition v1
-- <...> marks omitted implementation. Original line numbers refer to the device sample.

-- [aho_corasick] | original L3-L328
package.preload[ "aho_corasick" ] = assert( (loadstring or load)(
"-- Aho-Corasick自动机模块\
-- 用于高效的多模式字符串匹配\
\
local aho_corasick = {}\
\
local byte = string.byte\
local char = string.char\
\
-- 创建一个新的节点\
local function create_node()\
    return {\
        to = {},    -- 子节点的映射,键为字符的字节值,值为对应的子节点\
        output = {}, -- 存储该节点对应的完整模式和相关信息\
        fail = nil,  -- 失败指针,指向匹配失败时应跳转的节点\
        word = false -- 标记该节点是否是某个模式的结束\
    }\
end\
\
-- 清理失败指针\
local function clear_fail_pointers(node)\
    node.fail = nil\
    for _, child in pairs(node.to) do\
        clear_fail_pointers(child)\
    end\
end\
\
-- 添加模式到Trie树\
local function add_pattern(ac, pattern, info)\
    local node = ac.root\
    for i = 1, #pattern do\
        local c = byte(pattern, i)\
        if not node.to[c] then\
            node.to[c] = create_node()\
        end\
        node = node.to[c]\
    end\
    node.word = true\
    table.insert(node.output, {pattern = pattern, info = info})\
    ac.fail_built = false\
end\
\
-- 从Trie树删除模式\
local function remove_pattern(ac, pattern, info)\
    local node = ac.root\
    local path = {}\
    for i = 1, #pattern do\
        local c = byte(pattern, i)\
        if not node.to[c] then\
            return false\
        end\
        table.insert(path, {node = node, char = c})\
        node = node.to[c]\
    end\
    if not node.word then\
        return false\
    end\
    if not info then\
        node.output = {}\
    else\
        for index, value in ipairs(node.output) do\
            if value.info == info then\
                table.remove(node.output, index)\
                ac.fail_built = false\
                break\
            end\
        end\
    end\
    if #node.output == 0 then\
        node.word = false\
        -- 清理不必要的节点\
        for i = #path, 1, -1 do\
            local parent = path[i].node\
            local c = path[i].char\
            node = parent.to[c]\
            if next(node.to) == nil and not node.word then\
                parent.to[c] = nil\
            else\
                break\
            end\
        end\
        ac.fail_built = false\
    end\
    return true\
end\
\
-- 构建失败指针\
local function build_fail(ac)\
    -- 清理旧的失败指针\
    clear_fail_pointers(ac.root)\
\
    -- 初始化队列和根节点\
    local queue = {}\
    local root = ac.root\
\
    -- 将根节点的所有子节点加入队列，并设置它们的失败指针指向根节点\
    for _, child in pairs(root.to) do\
        child.fail = root\
        table.insert(queue, child)\
    end\
\
    -- 广度优先搜索构建失败指针\
    while #queue > 0 do\
        local node = table.remove(queue, 1)\
        for c, child in pairs(node.to) do\
            -- 将当前节点的子节点加入队列\
            table.insert(queue, child)\
\
            -- 查找失败指针\
            local fail = node.fail\
            while fail ~= root and not fail.to[c] do\
                fail = fail.fail\
            end\
            child.fail = fail.to[c] or root\
        end\
    end\
    ac.fail_built = true\
end\
\
-- 在文本中匹配模式\
local function match(ac, text, all)\
    if not ac.fail_built then\
        build_fail(ac)\
    end\
\
    if all == nil then\
        all = true\
    end\
\
    local node = ac.root\
    local results = {}\
    local results_idx = 0\
\
    for i = 1, #text do\
        local c = byte(text, i)\
        while node ~= ac.root and not node.to[c] do\
            node = node.fail\
        end\
        node = node.to[c] or ac.root\
        if node.word or (node.fail and node.fail.word) then\
            for _, output in ipairs(node.output) do\
                results_idx = results_idx + 1\
                results[results_idx] = output\
                if not all then\
                    return results\
                end\
            end\
            for _, output in ipairs(node.fail.output) do\
                results_idx = results_idx + 1\
                results[results_idx] = output\
            end\
        end\
    end\
    return results\
end\
\
-- 展示当前Trie树的状态，包括失败指针\
local function display_trie(ac)\
    local node_id_map = {}\
    local id_counter = 0\
\
    -- 为每个节点分配唯一ID\
    local function assign_ids(node)\
        if node_id_map[node] then\
            return node_id_map[node]\
        end\
        id_counter = id_counter + 1\
        node_id_map[node] = id_counter\
        return id_counter\
    end\
\
    -- 获取节点到根的路径\
    local function get_path(node)\
        local path = {}\
        local current = node\
        local visited = {}\
        while current ~= ac.root and not visited[current] do\
            visited[current] = true\
            local found = false\
            for char_value, child in pairs(ac.root.to) do\
                if child == current then\
                    table.insert(path, 1, char(char_value))\
                    current = ac.root\
                    found = true\
                    break\
                end\
            end\
            if not found then\
                for parent in pairs(node_id_map) do\
                    for char_value, child in pairs(parent.to) do\
                        if child == current then\
                            table.insert(path, 1, char(char_value))\
                            current = parent\
                            found = true\
                            break\
                        end\
                    end\
                    if found then break end\
                end\
            end\
            if not found then break end\
        end\
        return table.concat(path)\
    end\
\
    -- 递归函数，将节点及其子节点转换为字符串\
    local function node_to_string(node, prefix, char_value)\
        local output = {}\
        table.insert(output, prefix)\
        if char_value then\
            table.insert(output, string.format(\"'%s' \", char(char_value)))\
        end\
        local node_id = assign_ids(node)\
        table.insert(output, string.format(\"(ID: %d) \", node_id))\
        if node.word then\
            table.insert(output, \"[词尾] \")\
        end\
        if #node.output > 0 then\
            table.insert(output, \"输出: \")\
            for _, out in ipairs(node.output) do\
                table.insert(output, string.format(\"(%s, %s) \", out.pattern, tostring(out.info)))\
            end\
        end\
        -- 添加失败指针信息\
        if node.fail then\
            local fail_id = assign_ids(node.fail)\
            local fail_path = get_path(node.fail)\
            table.insert(output, string.format(\"失败指针: ID %d ('%s') \", fail_id, fail_path))\
        end\
        table.insert(output, \"\\n\")\
\
        -- 对子节点的字符进行排序，确保输出顺序一致\
        local sorted_chars = {}\
        for c in pairs(node.to) do\
            table.insert(sorted_chars, c)\
        end\
        table.sort(sorted_chars)\
\
        -- 递归处理所有子节点\
        for _, c in ipairs(sorted_chars) do\
            table.insert(output, node_to_string(node.to[c], prefix .. \"  |-- \", c))\
        end\
\
        return table.concat(output)\
    end\
\
    -- 返回整个Trie树的字符串表示\
    return \"Trie树结构（包括失败指针）:\\n\" .. node_to_string(ac.root, \"\", nil)\
end\
\
-- 创建一个新的Aho-Corasick自动机实例\
function aho_corasick.new()\
    local ac = {\
        root = create_node(),\
        fail_built = false,\
    }\
\
    return setmetatable(\
        ac,\
        {\
            __index = {\
                add_pattern = add_pattern,\
                remove_pattern = remove_pattern,\
                build_fail = build_fail,\
                display = display_trie,\
                match = match,\
            }\
        }\
    )\
end\
\
--[[\
使用说明:\
1. 创建AC自动机实例:\
   local ac = aho_corasick.new()\
\
2. 添加模式:\
   ac:add_pattern(\"pattern\", info)\
   其中info可以是任何与该模式相关的信息\
\
3. 删除模式:\
   ac:remove_pattern(\"pattern\", info)\
   info为可选参数。如果提供，只删除匹配该info的模式\
   删除成功返回true，模式不存在返回false\
\
4. 构建失败指针:\
   ac:build_fail()\
   在添加或删除模式后，必须调用此方法来重建失败指针\
\
5. 执行匹配:\
   local results = ac:match(\"text\")\
   返回的results是一个包含所有匹配结果的表\
\
6. 显示Trie树结构:\
   local trie_structure = ac:display()\
   返回一个字符串，表示当前Trie树的结构\
\
示例:\
local ac = aho_corasick.new()\
ac:add_pattern(\"he\", \"pronoun\")\
ac:add_pattern(\"she\", \"pronoun\")\
ac:add_pattern(\"his\", \"possessive\")\
ac:add_pattern(\"hers\", \"possessive\")\
ac:build_fail()\
\
-- 删除模式\
ac:remove_pattern(\"he\", \"pronoun\")\
ac:build_fail()  -- 重建失败指针\
\
local trie_structure = ac:display()\
print(trie_structure)\
\
local results = ac:match(\"ushers\")\
for i, result in ipairs(results) do\
    print(string.format(\"匹配 %d: 模式 = %s, 信息 = %s\", i, result.pattern, tostring(result.info)))\
end\
\
注意:\
- 在调用match之前，必须先添加所有模式并调用build_fail\
- 添加或删除模式后，需要重新调用build_fail来重建失败指针\
- match方法返回的结果包含所有匹配，包括重叠匹配\
- display方法返回一个字符串，可以用于调试或可视化Trie树结构\
]]\
\
return aho_corasick"
, '@'.."./lualib/aho_corasick.lua" ) )

-- [appcidr] | original L330-L759
-- L342
-- help = "appcidr module, configure/save, also including cidr rule management",
-- <...>

-- [appctrl] | original L761-L1046
-- L777
-- help = "set appctrl and send info to server",
-- <...>

-- [appmlp] | original L1048-L1350
-- L1063
-- help = "set appmlp and real time send info to server",
-- <...>

-- [appqos] | original L1352-L1674
-- L1365
-- help = "set appqos for safeguard app",
-- L1371
-- enable = true,
-- <...>

-- [apprule] | original L1676-L1953
-- L1690
-- help = "app rule configure",
-- L1691
-- period = 5,
-- <...>

-- [appsig_bin] | original L1955-L3036
-- L1970
-- help = "load appsig",
-- L1971
-- period = 86400,
-- <...>

-- [appuse] | original L3038-L3316
-- L3054
-- help = "set appuse and send info to server",
-- <...>

-- [arch] | original L3318-L3453
-- L3330
-- help = "arch var, SN, mac, oui, version, sigversion, etc...",
-- <...>

-- [arping] | original L3455-L3657
-- L3468
-- help = "get arping time delay",
-- L3470
-- period = 0,
-- <...>

-- [capi] | original L3659-L3728
-- L3667
-- help = "get info from capi"
-- <...>

-- [cliclient] | original L3730-L3863
-- <...>

-- [cliserver] | original L3865-L3987
-- <...>

-- [coll_domain] | original L3989-L4255
-- L4003
-- help = "collect domain/stock data and send to svrdata",
-- <...>
-- L4010
-- upload_period = 0,
-- session_period = 1800,
-- <...>
-- L4015
-- ["gbapi.eastmoney.com"] = {url = {"[?&]code=%u*(%d+)&?"}},
-- ["ai.10jqka.com.cn"] = {url = {"[?&]code=%u*(%d+)&?"}},
-- ["www.iwencai.com"] = {url = {"[?&]q=%u*(%d+)&?"}},
-- <...>
-- L4019
-- ["stockpage.10jqka.com.cn"] = {url = {"[^/]/%u*(%d+)/?"}},
-- ["xueqiu.com"] = {url = {"[^/]/%u*(%d+)/?"}},
-- <...>
-- L4022
-- ["quote.eastmoney.com"] = {ref = {"[^/]/%a*(%d+).html"}},
-- ["myfavor.eastmoney.com"] = {ref = {"[^/]/%a*(%d+).html"}},
-- <...>
-- L4076
-- tt.stock_code = dtype_value or ""
-- <...>

-- [config_service] | original L4257-L4260
package.preload[ "config_service" ] = assert( (loadstring or load)(
"return {\"arch\",\"dns\",\"tuple\",\"sys\",\"svroper\",\"shell\",\"operdata\",\"svrdata\",\"sig\",\"dmpapp\",\"ct\",\"osinfo\",\"sigcollect\",\"http\",\"upgrade\",\"dpinfo\",\"http_rule\",\"devinfo\",\"lanhost\",\"lanhoststats\",\"wanstats\",\"diagnose\",\"hredirect\",\"capi\",\"pscan\",\"rawpkt\",\"hotpatch\",\"topo\",\"mdns\",\"upnp\",\"pktpolicy\",\"wandns\",\"pcap_dump\",\"dhcp\",\"oscloud\",\"pqprobe\",\"dumh\",\"https\",\"postmsg\",\"sec_data\",\"domain_dip\",\"sec_camera\",\"appsig_bin\",\"apprule\",\"xapp\",\"http_imei\",\"appctrl\",\"appuse\",\"appmlp\",\"httpdns\",\"mdns_pcap\",\"quic\",\"pcap_udp\",\"locdata\",\"d2tree\",\"crawler\",\"domcent\",\"termact\",\"coll_domain\",\"xid\",\"onvif\",\"appqos\",\"qcollect\",\"qcalc\",\"qsvr\",\"qrcstats\",\"qblstats\",\"arping\",\"mdppp\",\"immddata\",\"murl\",\"msgenl\",\"connfirst\",\"appcidr\"}\
"
, '@'.."./config_service.lua" ) )

-- [connfirst] | original L4262-L4361
-- L4273
-- help = "connfirst",
-- <...>

-- [crawler] | original L4363-L4696
-- L4388
-- enable = false,
-- <...>
-- L4390
-- max_crawl_cnt = 30,
-- <...>

-- [ct] | original L4698-L4906
-- L4713
-- help = "deal ct ipfilter cthttp topo, send to server",
-- L4720
-- period = 300,
-- <...>

-- [ct.cthttp] | original L4908-L4973
-- <...>

-- [ct.ipfilter] | original L4975-L5051
-- <...>

-- [ct.osgi] | original L5053-L5208
-- <...>

-- [ct.policy] | original L5210-L5472
-- <...>

-- [d2tree] | original L5474-L5735
package.preload[ "d2tree" ] = assert( (loadstring or load)(
"local d2tree = {\
    dd = false\
}\
\
local function PRINT_DBG(ss)\
    if d2tree.dd then\
        print(ss)\
    end\
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
local function inedges(e, edges)\
    if edges == nil then\
        return false\
    end\
    for _, v in ipairs(edges) do\
        if e[1] == v[1] and e[2] == v[2] then\
            return true\
        end\
    end\
    return false\
end\
\
local function del_indegree(node, edges, indegree) \
    if edges == nil then\
        return\
    end\
    for _, v in pairs(edges) do\
        assert(#v == 2)\
        if v[1] == node then\
            indegree[v[2]] = indegree[v[2]] - 1\
            PRINT_DBG(string.format(\"indegree[%s] = %d\", v[2], indegree[v[2]]))\
        end\
    end\
end\
\
local function tsort_one(edges, indegree, sorted, hprio_node)\
    local node, rnode, min_degree = \"\", \"\", \"\"\
    local min = 65535\
    local nodebk = {}\
    for k, v in pairs(indegree) do\
        if not sorted[k] then\
            if v == 0 then\
                if type(hprio_node) == \"table\" and hprio_node[k] then\
                    node = k\
                    break\
                else\
                    table.insert(nodebk, k)\
                end\
            else\
                if min > v or (min == v and type(hprio_node) == \"table\" and hprio_node[k] ~= nil) then\
                    min = v\
                    min_degree = k\
                end\
            end\
        end\
    end\
    if node ~= \"\" then\
        del_indegree(node, edges, indegree)\
        rnode = node\
    else\
        if #nodebk > 0 then\
            del_indegree(nodebk[1], edges, indegree)\
            rnode = nodebk[1]\
        else\
            PRINT_DBG(\"Faled to find zero indegree node, MUST cyclic graph\")\
            del_indegree(min_degree, edges, indegree)\
            rnode = min_degree\
        end\
    end\
    PRINT_DBG(string.format(\"tsort one: rnode = %s, node = %s, nodebk = %s, min_degree = %s, sorted[%s] = %s\",\
                            rnode, node, (#nodebk > 0 and nodebk[1] or \"\") , min_degree, node, tostring(sorted[rnode])))\
    sorted[rnode] = true\
    return rnode\
end\
\
\
local function merge_tree(level, root, index, edges, tsort, dfsorted, new_edges)\
    for i = index+1, #tsort do\
        if not dfsorted[i] then\
            if inedges({tsort[index], tsort[i]}, edges) then\
                table.insert(new_edges, {tsort[index], tsort[i], root, level+1})\
                PRINT_DBG(string.format(\"add one edge when merge tree: %s, %s, %s\",tsort[index], tsort[i], root))\
                dfsorted[i] = true\
                merge_tree(level+1, root, i, edges, tsort, dfsorted, new_edges)\
            end\
        end\
    end\
end\
\
local function find_root(tsort, dfsorted)\
    for k, v in ipairs(tsort) do\
        if not dfsorted[k] then\
            return k\
        end\
    end\
    return 0\
end\
\
\
local function topo_sort(count, edges, indegree, hprio_node)\
    local tsort, sorted, root = {}, {}, {}\
    local new_edges = {}\
    repeat\
        local node = tsort_one(edges, indegree, sorted, hprio_node)\
        PRINT_DBG(string.format(\"topo sort: add one node %s\", node))\
        table.insert(tsort, node)\
    until(#tsort >= count)\
\
    -- DFS traverse\
    local dfsorted = {}\
    while(true) do\
        local index = find_root(tsort, dfsorted)\
        if index <= 0 then\
            break\
        end\
        PRINT_DBG(string.format(\"Find root: tsort[%d] = %s\", index, tsort[index]))\
        dfsorted[index] = true\
        table.insert(root, tsort[index])\
        merge_tree(1, tsort[index], index, edges, tsort, dfsorted, new_edges)\
    end\
\
    return root, new_edges\
end\
\
local function fill_all_nodes(t, roots, new_edges)\
    local emap = {}\
\
    for _, v in ipairs(roots) do\
        emap[v] = {[\"parent\"] = v, [\"root\"] = v, [\"ntype\"] = \"root\", [\"level\"] = 1}\
    end\
\
    for _, v in ipairs(new_edges) do -- [parent, node, root]\
        emap[v[2]] = {[\"parent\"] = v[1], [\"root\"] = v[3], [\"ntype\"] = \"branch\", [\"level\"] = v[4]}\
        PRINT_DBG(string.format(\"Fill branch, emap[%s] = parent(%s), root(%s), level(%s)\", v[2], v[1], v[3], v[4]))\
    end\
\
    -- generate node=>[parent1, parent2, ...]\
    local nparent = {}\
    for k, v in pairs(t) do\
        for _, vv in ipairs(v) do\
            if not inarr(vv, roots) and not emap[vv] then\
                if not nparent[vv] then\
                    nparent[vv] = {k}\
                else\
                    table.insert(nparent[vv], k)\
                end\
            end\
        end\
    end\
\
    -- find max level branch as parent for other node\
    for k, v in pairs(nparent) do\
        local maxlevel = 0\
        local pp = nil\
        for _, vv in ipairs(v) do\
            if maxlevel < emap[vv][\"level\"] then\
                maxlevel = emap[vv][\"level\"]\
                pp = vv\
            end\
        end\
        if pp ~= nil then\
            emap[k] = {[\"parent\"] = pp, [\"root\"] = emap[pp][\"root\"], [\"ntype\"] = \"term\", [\"level\"] = maxlevel + 1}\
            PRINT_DBG(string.format(\"Fill leaf, emap[%s] = parent(%s), root(%s), level(%d)\",\
                                    k, pp, emap[k][\"root\"], emap[k][\"level\"]))\
        end\
    end\
\
    return emap\
end\
\
-- input fmt:\
--  t\
--   {[\"p1\"]={\"c11\",\"c12\",\"c13\",\"p2\",\"p3\",\"p4\"},[\"p2\"]={\"c21\",\"c22\",\"c23\",\"p3\",\"p4\"},[\"p3\"]={\"c31\",\"c32\",\"c33\",\"p4\"},[\"p4\"]={\"c41\", \"c11\", \"c21\"}}\
--   {[\"p1\"]={\"c11\",\"c12\",\"c13\",\"p2\",\"p3\",\"p4\"},[\"p2\"]={\"c21\",\"c22\",\"c23\",\"p3\",\"p4\"},[\"p3\"]={\"c31\",\"c32\",\"c33\"},[\"p4\"]={\"c41\", \"c11\", \"c21\"}}\
--   \
--   {[\"p1\"]={\"c11\",\"c12\",\"c13\",\"p2\",\"p3\"},[\"p2\"]={\"c21\",\"c22\",\"c23\",\"p3\"},[\"p3\"]={\"c31\",\"c32\",\"c33\"},[\"p4\"]={\"c41\", \"c11\", \"c21\"}}\
--   {[\"p1\"]={},[\"p2\"]={},[\"p3\"]={},[\"p4\"]={}}\
--\
--   {[\"p1\"] = {\"p2\"}, [\"p2\"] = {\"p3\"}, [\"p3\"] = {\"p1\"}}\
--\
--  hprio_node\
--   {[\"p1\"] = 1, [\"p2\"] = 1}\
--\
-- output:\
--   roots, vertexs {\"p2\", \"p3\"}\
--   emap, all edges(node->{parent,level...})\
--   new_edges, branch edges\
function d2tree.calc_trees(t, hprio_node)\
    local vertexs, indegree = {}, {}\
    local edges = {}\
\
    -- collect all branch nodes and reset indgree\
    for k, v in pairs(t) do\
        table.insert(vertexs, k)\
        indegree[k] = 0\
        PRINT_DBG(string.format(\"add vertex, %s\", k))\
    end\
    if #vertexs == 0 then\
        return {}, {}, {}\
    end\
    -- collect all branch node's edges and calc indegree\
    for k, v in pairs(t) do\
        for _, vv in ipairs(v) do\
            if inarr(vv, vertexs) then\
                table.insert(edges, {k, vv})\
                indegree[vv] = indegree[vv] + 1\
                PRINT_DBG(string.format(\"add edges, indegree[%s]=%d, indegree[%s] = %d\", \
                                        k, indegree[k], vv, indegree[vv]))\
            end\
        end\
    end\
\
    local roots, new_edges = topo_sort(#vertexs, edges, indegree, hprio_node)\
    local emap = fill_all_nodes(t, roots, new_edges)\
    return roots, emap, new_edges\
end\
\
local function show_node(node, emap, attrs)\
    local prefix, content = \"\", \"\"\
    prefix = string.rep(\"-\", (emap[node][\"level\"] - 1)*4)\
    content = string.format(\"node:%s,parent:%s,level:%d\",\
                            node, emap[node][\"parent\"], emap[node][\"level\"])\
    if type(attrs) == \"table\" then\
        for k, _ in pairs(attrs) do\
            content = content..string.format(\",%s:%s\", k, emap[node][k] or \"\")\
        end\
    end\
    return prefix..content..\"\\n\"\
end\
\
local function show_root_loop(node, emap, attrs)\
    local tstring = show_node(node, emap, attrs)\
    for k, v in pairs(emap) do\
        if v[\"parent\"] == node and k ~= node then\
            tstring = tstring..show_root_loop(k, emap, attrs)\
        end\
    end\
    return tstring\
end\
\
function d2tree.show_trees(roots, emap, attrs)\
    local tstring = \"\"\
    for _, rr in pairs(roots) do\
        tstring = tstring..show_root_loop(rr, emap, attrs)\
        tstring = tstring..\"\\n\"\
    end\
    return tstring\
end\
\
return d2tree\
"
, '@'.."./service/d2tree.lua" ) )

-- [devinfo] | original L5737-L5873
package.preload[ "devinfo" ] = assert( (loadstring or load)(
"local mystring = require\"mystring\"\
local actor = require\"luactor\"\
local log = require\"log\"\
local cjson = require\"cjson\"\
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
\
    uploadfmt = \"json\",\
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
    if devinfo.uploadfmt == \"json\" then\
        local tt = {\
            type = \"device_data\",\
            timestamp = tostring(os.time()),\
            cpu_usage = cpu_ratio,\
            mem_used = mem_use,\
            mem_free = mem_free,\
        }\
        lcmd_run({subtype = \"__svr_data\", action = \"add_json\", data = tt})\
        devinfo.all_count = devinfo.all_count + 1\
        devinfo.all_len = devinfo.all_len + string.len(cjson.encode(tt))\
        return\
    end\
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

-- [dhcp] | original L5875-L6024
-- L5885
-- help = "parse dhcp and send to server",
-- <...>

-- [diagnose] | original L6026-L6058
-- L6034
-- help = "diagnose",
-- <...>

-- [dmpapp] | original L6060-L6293
-- L6072
-- help = "get app from kernel, send to server",
-- L6073
-- period = 0,
-- <...>

-- [dns] | original L6295-L6437
-- L6303
-- help = "get dns from pcap",
-- L6305
-- period = 0,
-- <...>

-- [dnscache] | original L6439-L6604
-- <...>

-- [domain_dip] | original L6606-L6818
-- L6623
-- upperiod = 14400,
-- <...>
-- L6716
-- add_sig(mac, domainip, time, false)  -- add other sig within 10 seconds
-- <...>

-- [domcent] | original L6820-L6982
-- L6833
-- help = "get domain and manage",
-- L6835
-- period = 0,
-- <...>

-- [dpinfo] | original L6984-L7071
-- L6995
-- help = "show some base info, only read",
-- <...>

-- [dumh] | original L7073-L7210
-- L7086
-- help = "dumh",
-- <...>

-- [hotpatch] | original L7212-L7363
-- L7222
-- help = "hot fixbug, and hot add more function",
-- <...>

-- [hredirect] | original L7365-L7504
-- L7376
-- help = "redirect http from server",
-- <...>
-- L7380
-- enable = false,
-- rules = {},
-- <...>

-- [http] | original L7506-L7668
-- L7517
-- help = "get http from kernel and send to server",
-- period = 0,
-- <...>

-- [http_imei] | original L7670-L7866
-- L7701
-- keywords = {"imei"},
-- <...>
-- L7703
-- attr = {"url", "cookie"},
-- <...>

-- [http_rule] | original L7868-L7905
-- L7877
-- help = "http rule configure",
-- <...>

-- [httpclient] | original L7907-L8035
-- <...>

-- [httpclient.luasocket_driver] | original L8037-L8210
-- <...>

-- [httpclient.neturl] | original L8212-L8656
-- <...>

-- [httpclient.ngx_driver] | original L8658-L8813
-- <...>

-- [httpclient.utils] | original L8815-L8842
package.preload[ "httpclient.utils" ] = assert( (loadstring or load)(
"local inspect = require('inspect')\
local function deep_copy(t)\
  if type(t) ~= \"table\" then return t end\
  local meta = getmetatable(t)\
  local target = {}\
  for k, v in pairs(t) do\
    if type(v) == \"table\" then\
        target[k] = deep_copy(v)\
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
local utils = {\
  print_table = print_table,\
  deep_copy = deep_copy\
}\
return utils\
"
, '@'.."./lualib/httpclient/utils.lua" ) )

-- [httpdns] | original L8844-L9333
-- L8858
-- help="http dns parse",
-- <...>
-- L8860
-- enable = true,
-- <...>
-- L8863
-- upload_enable = false,
-- <...>

-- [https] | original L9335-L9426
-- L9344
-- period = 0,
-- <...>
-- L9349
-- help = "get https from kernel and send to server"
-- <...>

-- [immddata] | original L9428-L9677
-- L9439
-- help = "immediate data upload",
-- <...>

-- [inspect] | original L9679-L10023
-- <...>

-- [kengine] | original L10025-L10460
-- L10041
-- enable = false,
-- <...>

-- [lanhost] | original L10462-L10568
-- L10471
-- help = "get lan host for ct",
-- <...>

-- [lanhoststats] | original L10570-L10755
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
        local rx_bytes, tx_bytes = 0, 0\
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

-- [locdata] | original L10757-L10864
-- L10765
-- help = "dump send data to local dir",
-- L10769
-- enable = false,
-- <...>

-- [log] | original L10866-L10985
-- <...>

-- [ltn12] | original L10987-L11298
-- <...>

-- [luactor] | original L11300-L11776
-- L11319
-- enable = true,
-- <...>

-- [mdns] | original L11778-L11967
-- L11790
-- help = "mdns find host",
-- <...>

-- [mdns_pcap] | original L11969-L12155
-- L11975
-- help = "get mdns from pcap",
-- <...>

-- [mdppp] | original L12157-L12246
-- L12168
-- help = "pkt print policy",
-- L12178
-- enable = 1
-- <...>

-- [mhttps] | original L12248-L12402
-- <...>

-- [mime] | original L12404-L12495
-- <...>

-- [msgenl] | original L12497-L12627
-- L12509
-- help = "msgenl",
-- <...>

-- [msocket] | original L12629-L12934
-- <...>

-- [murl] | original L12936-L13171
-- L12949
-- help = "send murl data to server",
-- L12955
-- period = 0,
-- <...>

-- [myfile] | original L13173-L13341
-- <...>

-- [myip] | original L13343-L13785
-- <...>

-- [mystring] | original L13787-L13851
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
function mystring.splits(str, delim)\
    local sub_str_tab = {}\
    local last_str = string.gsub(str, '(.-)'..delim, function ( w ) table.insert(sub_str_tab, w) return \"\" end)\
    table.insert(sub_str_tab, last_str)\
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
    local pattern = \"\"\
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

-- [myutil] | original L13853-L14358
-- <...>

-- [nselib] | original L14360-L14362
-- <...>

-- [nselib.slaxml] | original L14364-L14830
-- <...>

-- [onvif] | original L14832-L15356
-- L14848
-- help = "support to collect sig of onvif",
-- period = 0,
-- <...>

-- [operdata] | original L15358-L15624
-- L15372
-- help = "oper data server communication",
-- <...>

-- [oscloud] | original L15626-L15757
-- L15637
-- help = "receive cloud dev desc",
-- <...>

-- [osinfo] | original L15759-L16529
-- L15772
-- help = "get osinfo from kernel, send to server",
-- L15775
-- period = 0,
-- <...>

-- [pbmsg] | original L16531-L16551
-- <...>

-- [pcap_dump] | original L16553-L16676
-- L16563
-- help = "read/write/stat/replay pcap",
-- <...>

-- [pcap_udp] | original L16678-L16768
-- L16686
-- help = "get broadcast and multicast and unicast from pcap",
-- L16689
-- enable = false,
-- <...>

-- [pktpolicy] | original L16770-L17284
-- L16787
-- help = "set pktpolicy and send info to server",
-- <...>
-- L16800
-- enable = true,
-- <...>

-- [postmsg] | original L17286-L17370
-- L17291
-- help = "DBUS postmsg run lua command",
-- <...>

-- [pqprobe] | original L17372-L18038
-- L17385
-- help = "time delay detection(tcp, udp, dns)",
-- L17412
-- period = 3600,
-- <...>

-- [pscan] | original L18040-L18443
-- L18070
-- help = "parse n01 result and send to oper_data"
-- <...>

-- [qblstats] | original L18445-L18803
-- L18459
-- help = "quality baseline stats",
-- <...>

-- [qcalc] | original L18805-L19545
-- L18819
-- help = "calculate and find poor network quality data through the model.",
-- L18827
-- enable = false,
-- L18832
-- period = 25200,
-- <...>

-- [qcollect] | original L19547-L19838
-- L19561
-- help = "data collection for poor network quality",
-- L19567
-- enable = false,
-- <...>

-- [qrcstats] | original L19840-L20476
-- L19853
-- help = "get root cause stats",
-- <...>
-- L19855
-- collect_period = 0,
-- <...>

-- [qsvr] | original L20478-L20812
-- L20495
-- help = "oper server, send heart/init/result/data to server",
-- L20505
-- period = 1800,
-- <...>

-- [quic] | original L20814-L21499
-- L20825
-- help = "get quic from PCAP and send to server",
-- <...>
-- L20828
-- upload_mode = "none",
-- <...>

-- [rawpkt] | original L21501-L21947
-- L21519
-- help = "get rawpkt from kernel and send to server",
-- <...>
-- L21522
-- conn_limit_pkts = 16,
-- <...>

-- [sampling] | original L21949-L22015
package.preload[ "sampling" ] = assert( (loadstring or load)(
"\
\
local sampling = {}\
\
\
local function accept(sar)\
    sar.token = sar.token + sar.ratio\
\
    local tolerance_value = 1e-6\
    -- double(float) can not just use < to judge\
    if sar.token < 1 and math.abs(1 - sar.token) > tolerance_value then\
        sar.droppedCount = sar.droppedCount + 1\
        return false\
    end\
\
    sar.acceptedCount = sar.acceptedCount + 1\
    sar.token = sar.token - 1\
    return true\
end\
\
local function show(sar)\
    return {\
        ratio = sar.ratio,\
        acceptedCount = sar.acceptedCount,\
        droppedCount = sar.droppedCount,\
    }\
end\
\
local function getRatio(sar)\
    return sar.ratio\
end\
\
\
function sampling.newAverager(ratio, stail)\
    -- if you want data sampling of 1:100, please set \"ratio\" to 0.01 .\
    -- if you want sampling the tail per segment, please set \"stail\" to true.\
\
    if ratio >= 1 then\
        return nil\
    end\
\
    local sar = {\
        ratio = ratio,\
        token = stail and 0 or (1 - ratio),\
\
        acceptedCount = 0,\
        droppedCount = 0,\
    }\
\
    return setmetatable(\
        sar,\
        {\
            __index = {\
                accept = accept,\
                show = show,\
                getRatio = getRatio,\
            }\
        }\
    )\
end\
\
\
return sampling\
\
"
, '@'.."./lualib/sampling.lua" ) )

-- [sec_camera] | original L22017-L22076
-- L22025
-- help = "set sec_camera conf",
-- enable = false,
-- <...>

-- [sec_data] | original L22078-L22298
-- L22091
-- help = "filter secdata and send to server",
-- <...>
-- L22094
-- enable = false,
-- <...>

-- [shell] | original L22300-L22337
-- L22306
-- help = "run shell cmd and return result",
-- <...>

-- [sig] | original L22339-L22453
-- <...>

-- [sigcollect] | original L22455-L22916
-- L22470
-- enable = true,
-- <...>
-- L22473
-- newdev_period = 600,
-- <...>
-- L22480
-- coll_type = {"term_http","hostname","elink","mdns","upnp","vendor","dhcp_hostname","imei","mac","devname","term_pkt","term_domain"},
-- <...>

-- [socket] | original L22918-L23069
-- <...>

-- [socket.headers] | original L23071-L23176
-- <...>

-- [socket.http] | original L23178-L23562
-- <...>

-- [socket.url] | original L23564-L23875
-- <...>

-- [ssl] | original L23877-L24143
-- <...>

-- [ssl.https] | original L24145-L24292
-- <...>

-- [stats] | original L24294-L24392
package.preload[ "stats" ] = assert( (loadstring or load)(
"-- stats.lua\
local stats = {}\
stats.__index = stats\
\
-- 初始化统计数据\
function stats:new()\
    local stat = setmetatable({}, stats)\
    stat.sum = 0\
    stat.count = 0\
    stat.max = nil\
    stat.min = nil\
    stat.sumOfSquares = 0\
    stat.sumOfDiff = 0\
    stat.lastValue = nil\
    stat.firstValue = nil\
    return stat\
end\
\
-- 重置统计数据\
function stats:reset()\
    self.sum = 0\
    self.count = 0\
    self.max = nil\
    self.min = nil\
    self.sumOfSquares = 0\
    self.sumOfDiff = 0\
    self.lastValue = nil\
    self.firstValue = nil\
end\
\
-- 更新统计数据\
function stats:update(value)\
    if type(value) ~= \"number\" then return end\
    self.count = self.count + 1\
    self.sum = self.sum + value\
    self.max = self.max and math.max(self.max, value) or value\
    self.min = self.min and math.min(self.min, value) or value\
    self.sumOfSquares = self.sumOfSquares + value * value\
    self.sumOfDiff = self.lastValue and (self.sumOfDiff + math.abs(value - self.lastValue)) or self.sumOfDiff\
    self.lastValue = value\
    self.firstValue = self.firstValue or value\
end\
\
-- 合并统计数据\
function stats:merge(stat)\
    if type(stat) ~= \"table\" then return end\
    self.sum = self.sum + stat.sum\
    self.count = self.count + stat.count\
    self.max = (self.max and stat.max) and math.max(self.max, stat.max) or (self.max or stat.max)\
    self.min = (self.min and stat.min) and math.min(self.min, stat.min) or (self.min or stat.min)\
    self.sumOfSquares = stat.sumOfSquares + self.sumOfSquares\
    self.sumOfDiff = self.lastValue and (stat.firstValue and (self.sumOfDiff + stat.sumOfDiff + math.abs(stat.firstValue - self.lastValue)) or self.sumOfDiff) or stat.sumOfDiff\
    self.lastValue = stat.lastValue or self.lastValue\
    self.firstValue = self.firstValue or stat.firstValue\
end\
\
-- 获取平均值\
function stats:getMean()\
    if self.count == 0 then return 0 end\
    return self.sum / self.count\
end\
\
-- 获取最大值\
function stats:getMax()\
    return self.max\
end\
\
-- 获取最小值\
function stats:getMin()\
    return self.min\
end\
\
-- 获取统计数据个数\
function stats:getCount()\
    return self.count\
end\
\
-- 获取总和\
function stats:getSum()\
    return self.sum\
end\
\
-- 获取标准差\
function stats:getStdDev()\
    if self.count <= 1 then return 0 end\
    local variance = (self.sumOfSquares - (self.sum * self.sum) / self.count) / (self.count - 1)\
    return math.sqrt(variance)\
end\
\
-- 获取平均抖动\
function stats:getMeanJitter()\
    if self.count <= 1 then return 0 end\
    return self.sumOfDiff / (self.count - 1)\
end\
\
return stats\
"
, '@'.."./lualib/stats.lua" ) )

-- [svrcomm] | original L24394-L24941
-- <...>

-- [svrcomm.ckey] | original L24943-L25255
-- L24958
-- period = 60,
-- <...>

-- [svrcomm.dpi] | original L25257-L26022
-- <...>

-- [svrcomm.pack] | original L26024-L26207
-- <...>

-- [svrcomm.packpb] | original L26209-L26365
-- <...>

-- [svrcomm.pth] | original L26367-L26740
-- <...>

-- [svrdata] | original L26742-L27072
-- L26755
-- help = "DMP server communication, only send to, no reply",
-- <...>

-- [svroper] | original L27074-L27333
-- L27091
-- help = "oper server, send heart/init/result to server",
-- <...>

-- [sys] | original L27335-L27879
-- L27350
-- help = "sys module, configure/save, also including bypass/engine/timer etc.",
-- <...>

-- [termact] | original L27881-L28148
-- L27896
-- help = "collect termact to server",
-- <...>
-- L27899
-- enable = false,
-- <...>
-- L27901
-- Samba, tcp dst port 445, "4,FE534D42", "16,01002100"
-- <...>

-- [timer] | original L28150-L28258
package.preload[ "timer" ] = assert( (loadstring or load)(
"local log = require\"log\"\
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
        --v.func(table.unpack(v.args))\
        local ok, err = xpcall(v.func, lcmd_errhandle, table.unpack(v.args))\
        if not ok then\
            log.error(\"failed to deal timer \", v.name, \", error is \", err)\
        end\
        v.next = v.cycle + now\
    end\
end\
\
return timer\
"
, '@'.."./lualib/timer.lua" ) )

-- [tlv] | original L28260-L28281
-- <...>

-- [topo] | original L28283-L29513
-- L28303
-- send_period = 86400,
-- send_active_period = 3600,
-- <...>
-- L28434
-- add_value(gw_info, "2g_ssid", wifi_info["2g_ssid"], "")
-- <...>
-- L28447
-- add_value(gw_info, "pppoe", pppoe.pppoe, "")
-- add_value(gw_info, "loid", poninfo.loid, "")
-- <...>
-- L28450
-- add_value(gw_info, "wan_ip", netinfo.wan_ip, "")
-- <...>
-- L28858
-- info.hostname = laninfo.hostname
-- <...>
-- L28861
-- info.ip = laninfo.ip
-- <...>

-- [tuple] | original L29515-L29708
-- L29530
-- period = 5,
-- L29533
-- help = "get tuple from kernel, send to server"
-- <...>

-- [upgrade] | original L29710-L29818
-- L29719
-- help = "upgrade for plugin/lua/sig",
-- <...>

-- [upnp] | original L29820-L29942
-- L29832
-- help = "upnp find host",
-- <...>

-- [wandns] | original L29944-L30031
-- L29956
-- help = "get dns server info from capi and send to server",
-- L29958
-- period = 3600,
-- L29959
-- send_period = 86400,
-- <...>

-- [wanstats] | original L30033-L30237
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
    local rx_bytes, tx_bytes = -1, -1\
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
        local rx_bytes_total, tx_bytes_total = 0, 0\
\
        for _, wan in ipairs(wantab) do\
            local rx_bytes, tx_bytes = 0, 0\
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

-- [xapp] | original L30239-L30824
-- L30255
-- help = "send appinfo to server",
-- <...>
-- L30259
-- flow_enable = false,
-- tag_enable = false,
-- <...>

-- [xid] | original L30826-L31050
-- L30842
-- upload_mode = "svrdata",
-- <...>
-- L30845
-- period = 1800,
-- <...>
-- L30855
-- attr = {"url", "ref", "cookie"},
-- <...>

