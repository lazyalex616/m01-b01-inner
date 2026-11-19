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
