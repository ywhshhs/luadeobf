-- difficulty 4
local D="T0xAQk8DSB4UFANPTEJHUFdRSk1ECwF/EhIRfxISF38SExZ/EhITfxISFX8TFxN/ExAXfxMUFX8TFhF/ExARfxMaGn8SEhJ/EhMafxISEX8SExt/EhMSfxISFX8SExJ/ExARfxITEn8SExp/ExobfxITEn8SEhd/ExcWfxMWF38TFhR/ExYRfxMWEn8TEBd/ExcSAQoLCgMD"
local K2=35
local function un(s) local o={} local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' for i=1,#s do local c=s:sub(i,i) local p=b:find(c,1,true) if p then o[#o+1]=p-1 end end local out={} for i=1,#o,4 do local a,c,d,e=o[i],o[i+1] or 0,o[i+2] or 0,o[i+3] or 0 local n=a*262144+c*4096+d*64+e out[#out+1]=string.char(math.floor(n/65536)%256,math.floor(n/256)%256,n%256) end return table.concat(out) end
local raw=un(D)
local dec={}
for i=1,#raw do dec[#dec+1]=string.char(string.byte(raw,i)~K2) end
loadstring(table.concat(dec))()
