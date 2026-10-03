-- difficulty 3
local src="\108\111\099\097\108\032\119\061\054\056\032\112\114\105\110\116\040\034\076\051\032\099\111\109\112\108\101\116\101\032\099\097\115\099\097\100\101\045\054\050\051\101\034\041\032"
local function sum(s) local a,b=1,0 for i=1,#s do a=(a+string.byte(s,i))%65521 b=(b+a)%65521 end return b*65536+a end
local function tier(s) return s end
local ok,vals=pcall(function() local f=loadstring(tier(src),'=L3') if not f then error('bad') end return f() end)
if ok==true and sum(src)==1507331673 then return vals end
