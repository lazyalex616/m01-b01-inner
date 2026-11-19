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
