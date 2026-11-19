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
