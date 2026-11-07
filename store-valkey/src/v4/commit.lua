-- Fixed header: metadata, prefix, dataset id, receipt key, fingerprint,
-- execution epoch, writer epoch, root address, writer address, lower, upper,
-- bootstrap-shape flag, result, control record prefix, generation record prefix.
-- Then predicate count + (physical address, expected live-tagged bytes), mutation
-- count + (kind,physical address/prefix,value or exact physical key length,namespace).
local receipt=get(ARGV[4])
if receipt then
    if #receipt<52 or string.sub(receipt,1,4)~='BVR1' then return {'corrupt'} end
    if string.sub(receipt,5,36)~=ARGV[5] then return {'opconflict',string.sub(receipt,45,52)} end
    if string.sub(receipt,37,44)~=ARGV[6] then return {'corrupt'} end
    return {'applied',string.sub(receipt,45,52),string.sub(receipt,53)}
end
if get(KEYS[1])~=ARGV[1] then return {'corrupt'} end
local root=live(ARGV[8]); local registered=live(ARGV[9])
if registered and not writer(registered) then return {'corrupt'} end
local bootstrap=false
if not root then
    if ARGV[12]=='1' and empty(ARGV[2]..'r:*') and empty(ARGV[2]..'o:*') then bootstrap=true
    else return {'expired',now()} end
else
    if not dataset(root,ARGV[3]) then return {'corrupt'} end
    if registered and not writer(registered) then return {'corrupt'} end
    if not registered or cmp(ARGV[6],string.sub(registered,9,16))<=0 or cmp(ARGV[6],string.sub(registered,17,24))>0 then return {'expired',now()} end
    if ARGV[7]~=string.sub(root,25,32) then return {'expired',now()} end
end
local n=now()
if not permits(n,ARGV[10],ARGV[11]) then return {'time',n} end
local i=16; local predicates={}; local np=tonumber(ARGV[i]); i=i+1
for p=1,np do
    local k,e=ARGV[i],ARGV[i+1]; i=i+2
    predicates[k]=e
    local old=live(k)
    if string.sub(k,1,#ARGV[15])==ARGV[15] then
        local suffix=string.sub(k,#ARGV[15]+1)
        if #suffix~=32 or not string.match(suffix,'^[0-9a-f]+$') then return {'refused'} end
        old=generation(k)
    end
    if (e==string.char(0) and old) or (e~=string.char(0) and (not old or e~=string.char(1)..old)) then return {'condition',n} end
end
local nm=tonumber(ARGV[i]); i=i+1
local writes,spaces={},{}
local function put(k,v) writes[#writes+1]=k; writes[#writes+1]=v end
for m=1,nm do
    local kind,k,v,ns=ARGV[i],ARGV[i+1],ARGV[i+2],ARGV[i+3]; i=i+4
    if string.sub(k,1,#ARGV[15])==ARGV[15] then return {'refused'} end
    if string.sub(k,1,#ARGV[14])==ARGV[14] then
        if kind~='put' or not predicates[k] then return {'refused'} end
        local suffix=string.sub(k,#ARGV[14]+1); local old=live(k)
        if suffix=='64' then
            if not dataset(v,ARGV[3]) then return {'refused'} end
            if not bootstrap then
                if not old then return {'refused'} end
                if not dataset(old,ARGV[3]) then return {'corrupt'} end
                if cmp(string.sub(v,25,32),string.sub(old,25,32))<0 then return {'refused'} end
            end
        elseif #suffix==34 and string.sub(suffix,1,2)=='77' and string.sub(suffix,3)~=string.rep('0',32) then
            if not writer(v) then return {'refused'} end
            if old then
                if not writer(old) then return {'corrupt'} end
                if cmp(string.sub(v,9,16),string.sub(old,9,16))<0 or cmp(string.sub(v,17,24),string.sub(old,17,24))<0 then return {'refused'} end
            elseif string.sub(v,9,16)~=zero or string.sub(v,17,24)~=one then return {'refused'} end
        else return {'refused'} end
    end
    if kind=='put' then
        live(k); put(k,string.char(1)..v)
    elseif kind=='delete' then
        live(k); put(k,string.char(0))
    elseif kind=='range' then
        local matches=keys(k..'*'); local exact=tonumber(v)
        for _,at in ipairs(matches) do
            local h=string.sub(at,#ARGV[2]+36)
            if #h%2~=0 or not string.match(h,'^[0-9a-f]*$') then return {'corrupt'} end
            if #at==exact then live(at); put(at,string.char(0)) end
        end
    else return {'refused'} end
    spaces[ns]=true
end
for ns,_ in pairs(spaces) do
    local k=ARGV[15]..ns; local old=generation(k)
    local next=inc(old or zero); if not next then return {'refused'} end
    put(k,string.char(1)..next)
end
put(ARGV[4],'BVR1'..ARGV[5]..ARGV[6]..n..ARGV[13])
-- No authoritative write has occurred. A native MSET prepares all replacements
-- before publishing any of them. Tail calls avoid Lua 5.1's unpack stack cap.
local function emit(i, ...)
    if i==0 then return redis.call('MSET',...) end
    if i<128 then return emit(i-2,writes[i-1],writes[i],...) end
    return emit(i-128,writes[i-127],writes[i-126],writes[i-125],writes[i-124],writes[i-123],writes[i-122],writes[i-121],writes[i-120],writes[i-119],writes[i-118],writes[i-117],writes[i-116],writes[i-115],writes[i-114],writes[i-113],writes[i-112],writes[i-111],writes[i-110],writes[i-109],writes[i-108],writes[i-107],writes[i-106],writes[i-105],writes[i-104],writes[i-103],writes[i-102],writes[i-101],writes[i-100],writes[i-99],writes[i-98],writes[i-97],writes[i-96],writes[i-95],writes[i-94],writes[i-93],writes[i-92],writes[i-91],writes[i-90],writes[i-89],writes[i-88],writes[i-87],writes[i-86],writes[i-85],writes[i-84],writes[i-83],writes[i-82],writes[i-81],writes[i-80],writes[i-79],writes[i-78],writes[i-77],writes[i-76],writes[i-75],writes[i-74],writes[i-73],writes[i-72],writes[i-71],writes[i-70],writes[i-69],writes[i-68],writes[i-67],writes[i-66],writes[i-65],writes[i-64],writes[i-63],writes[i-62],writes[i-61],writes[i-60],writes[i-59],writes[i-58],writes[i-57],writes[i-56],writes[i-55],writes[i-54],writes[i-53],writes[i-52],writes[i-51],writes[i-50],writes[i-49],writes[i-48],writes[i-47],writes[i-46],writes[i-45],writes[i-44],writes[i-43],writes[i-42],writes[i-41],writes[i-40],writes[i-39],writes[i-38],writes[i-37],writes[i-36],writes[i-35],writes[i-34],writes[i-33],writes[i-32],writes[i-31],writes[i-30],writes[i-29],writes[i-28],writes[i-27],writes[i-26],writes[i-25],writes[i-24],writes[i-23],writes[i-22],writes[i-21],writes[i-20],writes[i-19],writes[i-18],writes[i-17],writes[i-16],writes[i-15],writes[i-14],writes[i-13],writes[i-12],writes[i-11],writes[i-10],writes[i-9],writes[i-8],writes[i-7],writes[i-6],writes[i-5],writes[i-4],writes[i-3],writes[i-2],writes[i-1],writes[i-0],...)
end
emit(#writes)
return {'applied',n,ARGV[13]}
