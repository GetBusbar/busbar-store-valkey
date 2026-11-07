-- Separate transport maintenance: no new effects are published here. The native
-- guard rereads the durable writer fence and only removes aged, fenced receipts.
if get(KEYS[1])~=ARGV[1] then return {'corrupt'} end
local w=live(ARGV[2])
if not writer(w) then return {'corrupt'} end
if cmp(string.sub(w,9,16),ARGV[3])<0 then return {'corrupt'} end
local doomed={}
for _,k in ipairs(keys(ARGV[4]..'*')) do
    local v=get(k)
    if not v or #v<52 or string.sub(v,1,4)~='BVR1' then return {'corrupt'} end
    if cmp(string.sub(v,37,44),ARGV[3])<=0 then doomed[#doomed+1]=k end
end
-- All deletions are already permanently non-executable and older than the
-- monotonic horizon. An interrupted maintenance command can only retain extras.
for _,k in ipairs(doomed) do redis.call('DEL',k) end
return {'ok'}
