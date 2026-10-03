-- difficulty 8
local _9nyrvy={224, 148, 140, 207, 195, 193, 220, 192, 201, 216, 201, 140, 202, 192, 217, 212, 129, 207, 206, 200, 153}
local _y6wm69=string.pack("I2I2",4,172)
local _esd1rq=string.unpack("I2",string.pack("I2",172))
local _8two3g={} local _tyff8c=0
for i=1,#_9nyrvy do
  if (_9nyrvy[i]~_esd1rq)%2==0 then _tyff8c+=1 else _tyff8c+=0 end
  _8two3g[i]=string.char(_9nyrvy[i]~_esd1rq)
  if _tyff8c>100000 then continue end
end
local msg=table.concat(_8two3g)
local extra=if 4*5>4 then string.rep("!",0) else string.rep(" ",0)
print(`{msg}{extra}`)
