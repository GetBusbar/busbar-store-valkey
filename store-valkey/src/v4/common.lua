-- Every helper below is read-only. Publications happen only at the final MSET.
local zero = string.rep(string.char(0), 8)
local one = string.char(1) .. string.rep(string.char(0), 7)
local function cmp(a,b)
    for i=8,1,-1 do
        local x,y=string.byte(a,i),string.byte(b,i)
        if x<y then return -1 elseif x>y then return 1 end
    end
    return 0
end
local function inc(a)
    local t,carry={},1
    for i=1,8 do local n=string.byte(a,i)+carry; t[i]=string.char(n%256); carry=math.floor(n/256) end
    if carry~=0 then return nil end
    return table.concat(t)
end
local function dec64(s)
    if not string.match(s,'^%d+$') then return nil end
    local t={}
    for i=1,8 do
        local q,r={},0
        for j=1,#s do local n=r*10+tonumber(string.sub(s,j,j)); q[j]=tostring(math.floor(n/256)); r=n%256 end
        t[i]=string.char(r); s=string.gsub(table.concat(q),'^0+',''); if s=='' then s='0' end
    end
    if s~='0' then return nil end
    return table.concat(t)
end
local function get(k)
    local kind=redis.call('TYPE',k).ok
    if kind=='none' then return nil end
    if kind~='string' then error('V4_CORRUPT') end
    return redis.call('GET',k)
end
local function live(k)
    local v=get(k)
    if not v then return nil end
    if v==string.char(0) then return nil end
    if string.byte(v,1)~=1 then error('V4_CORRUPT') end
    return string.sub(v,2)
end
local function generation(k)
    local v=get(k)
    if not v then return nil end
    if #v~=9 or string.byte(v,1)~=1 or string.sub(v,2)==zero then error('V4_CORRUPT') end
    return string.sub(v,2)
end
local function hex(s)
    return (string.gsub(s,'.',function(c) return string.format('%02x',string.byte(c)) end))
end
local function keys(pattern)
    local out,seen,cursor={},{},'0'
    repeat
        local page=redis.call('SCAN',cursor,'MATCH',pattern,'COUNT',1000); cursor=page[1]
        for _,k in ipairs(page[2]) do if not seen[k] then seen[k]=true; out[#out+1]=k end end
    until cursor=='0'
    return out
end
local function empty(pattern)
    local cursor='0'
    repeat local page=redis.call('SCAN',cursor,'MATCH',pattern,'COUNT',1000); cursor=page[1]; if #page[2]>0 then return false end until cursor=='0'
    return true
end
local function now()
    local n=dec64(redis.call('TIME')[1]); if not n then error('V4_CORRUPT') end; return n
end
local function permits(n,lower,upper)
    return (lower=='' or cmp(n,lower)>=0) and (upper=='' or cmp(n,upper)<0)
end
local function dataset(v,id)
    return v and #v==32 and string.sub(v,1,8)=='BSD1'..string.rep(string.char(0),4)
        and string.sub(v,9,24)==id and string.sub(v,25,32)~=zero
end
local function writer(v)
    return v and #v==24 and string.sub(v,1,8)=='BSW1'..string.rep(string.char(0),4)
        and string.sub(v,17,24)~=zero and cmp(string.sub(v,9,16),string.sub(v,17,24))<=0
end
local function frame(s)
    local n=#s; local t={}
    for i=1,4 do t[i]=string.char(n%256); n=math.floor(n/256) end
    if n~=0 then error('V4_RESOURCE') end
    return table.concat(t)..s
end
