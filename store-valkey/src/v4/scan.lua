-- meta, prefix, generation address, expected generation, allow change, cursor,
-- max items, max bytes, namespace record prefix, raw prefix hex.
if get(KEYS[1])~=ARGV[1] then return {'corrupt'} end
local generation=generation(ARGV[3]) or zero
if ARGV[4]~='' and ARGV[5]~='1' and generation~=ARGV[4] then return {'stale'} end
local found=keys(ARGV[9]..ARGV[10]..'*'); table.sort(found)
local out,bytes,count,last,more={},0,0,'',false
local maxitems,maxbytes=tonumber(ARGV[7]),tonumber(ARGV[8])
for _,k in ipairs(found) do
    local h=string.sub(k,#ARGV[9]+1)
    if #h%2~=0 or not string.match(h,'^[0-9a-f]*$') then return {'corrupt'} end
    if ARGV[11]=='0' or h>ARGV[6] then
        local v=live(k)
        if v then
            local raw=(string.gsub(h,'..',function(s) return string.char(tonumber(s,16)) end))
            local size=#raw+#v
            if count>=maxitems or bytes+size>maxbytes then
                if count==0 then return {'refused'} end
                more=true; break
            end
            count=count+1; bytes=bytes+size; last=raw
            out[#out+1]=frame(raw)..frame(v)
        end
    end
end
return {'page',generation,table.concat(out),more and last or '',more and '1' or '0'}
