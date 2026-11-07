-- KEYS[1] metadata; ARGV[1] proposed exact metadata, ARGV[2] dataset prefix.
local journal=get('busbar:v4:bootstrap')
local upgrade=nil
if journal then
    local ok,value=pcall(cjson.decode,journal)
    if not ok or value.version~=1 or value.stage~=6 or #value.target~=64 then return {'refused'} end
    upgrade=value
end
local existing=get(KEYS[1])
if existing then
    if #existing~=64 or string.sub(existing,1,8)~='BSP4'..string.char(1,0,0,0) then return {'refused'} end
    if upgrade then
        if existing~=string.char(unpack(upgrade.target)) then return {'refused'} end
        return {'metadata',existing}
    end
    local prefix='busbar:v4:{'..hex(string.sub(existing,9,24))..'}:'
    for _,k in ipairs(keys('busbar:*')) do
        if k~=KEYS[1] and string.sub(k,1,#prefix+2)~=prefix..'r:' and string.sub(k,1,#prefix+2)~=prefix..'o:' then return {'refused'} end
    end
    return {'metadata',existing}
end
-- A fresh name must never silently detach old or partially initialized data.
if upgrade then return {'refused'} end
local all=keys('busbar:*')
if #all~=0 then return {'refused'} end
redis.call('MSET',KEYS[1],ARGV[1])
return {'metadata',ARGV[1]}
