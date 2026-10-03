-- difficulty 5
local _39x={"\214\148\136\204\217\208\180\167\183\173\133\199",
"\255\204\202\202\196\193\181\190\179\171\148\157\146\135\157\117\111\127\100\124\071\094\087\090\038\044\044\056\060\022\005\023\019\224\230\243\236\248\212\195\203\203\188\168\160\172\164\159\132\148\154\138\106\108\104\120\075\071\084\082\076\057\058\060\040\021\013\023\010\013\253\249\247\229\199\203\207\214\213\166\184\173\171\175\131\142\128\158\112\117\118\123\107\093",
"\183"}
local _emj=147
local function _k80(t) local o={} for j=1,#t do o[j]=string.char(string.byte(t,j)~((_emj+7*j)%256)) end return table.concat(o) end
local _3w3={226,245,158,216,171,14,54995,144,180,103,174,136,249,248,149,192,133,208,184,57,73,233,39,240,85,64,200,237,157,216,176,35,38,176,220,152,239,204,68,80}
local _6kr,_syl=1,{}
local function pk(i) return (96+i*54+i*i*74)&0xFF end
local R={}
while true do
local op=_3w3[_6kr]~pk(_6kr)
local a=_3w3[_6kr+1]~pk(_6kr+1)
local b=_3w3[_6kr+2]~pk(_6kr+2)
local c=_3w3[_6kr+3]~pk(_6kr+3)
if op==1 then R[a]=_k80(_39x[b]);_6kr+=4
elseif op==2 then local w=_k80(_39x[b]); local parts={}; local s=w; local n=0; for wq in s:gmatch("[^|]+") do n=n+1; parts[n]=wq end; R[a]=parts[math.random(1,n)];_6kr+=4
elseif op==3 then R[a]=math.random(0,65535);_6kr+=4
elseif op==4 then R[a]=string.format("%04x",R[b]);_6kr+=4
elseif op==5 then R[a]=(R[b] or '')..(R[c] or '');_6kr+=4
elseif op==6 then print(R[a]);_6kr+=4
elseif op==7 then break end
end
