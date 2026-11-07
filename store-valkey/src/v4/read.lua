-- metadata key, exact metadata; lower, upper, then exact physical addresses.
if get(KEYS[1])~=ARGV[1] then return {'corrupt'} end
local n=now()
if not permits(n,ARGV[2],ARGV[3]) then return {'time',n} end
local out={}
for i=4,#ARGV do
    local v=live(ARGV[i])
    if string.find(ARGV[i],':r:'..hex('busbar.scan.v1'..string.char(0,0))..':',1,true) then
        v=generation(ARGV[i])
    end
    out[#out+1]=v and (string.char(1)..frame(v)) or string.char(0)
end
return {'values',n,table.concat(out)}
