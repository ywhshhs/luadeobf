-- difficulty 6
local _e8faf1={(457+12*30-(809)),(77*7/7),(7+2*2-(-223)),(365-(283)),(371+(-148)),(58+(-16)),(134*3/3),(305+8*15-(216)),(188-(-61)),(36+(195)),(87+15*28-(308)),(262-(29)),(126*3/3),(217-(169)),(376+31*6-(374)),(205+38*4-(324)),(403+10*17-(428)),(358-(147)),(329+28*24-(914)),(86*2/2),(363-(358)),(171+25*13-(429)),(280+(-136))}
local function _yiln23(i) return (68+i*43+i*i*12)&0xFF end
local function _qqlp8f(x) local y=x*7+7 return y==y end
local _ik3i22={} local _9euv31=1
while true do
  if _9euv31==1 then
    if _qqlp8f(43) then _9euv31+=3 else _9euv31+=9 end
  elseif _9euv31==4 then
    for i=1,#_e8faf1 do _ik3i22[i]=string.char(string.byte(_e8faf1,i)~_yiln23(i)) end
    _9euv31+=2
    continue
  elseif _9euv31==6 then
    print(table.concat(_ik3i22)) _9euv31+=93
  elseif _9euv31==12 then
    print("\110\111\x70\101") _9euv31+=87
  elseif _9euv31>=99 then break end
end
