local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _cap, _log, _step = {}, {}, 0
local function _L(s) _log[#_log+1] = s end
debug.sethook(function() _step=_step+5000; if _step>2e6 then _L("STEP_LIMIT");error("__LIMIT__")end end,"",5000)
local function _capture(v) if type(v)=="string" and #v>3 then _cap[#_cap+1]=v end end
rawget=function(t,k) local v=(rawget~=nil and rawget or _G.rawget)(t,k); if type(v)=="string" and #v>3 then _capture(v)end; return v end
_G.rawget=rawget
local _orig=loadstring
loadstring=function(code,name)
    if type(code)=="function" then local p={} while true do local c=code() if not c then break end if type(c)=="string" then p[#p+1]=c end if #p>5000 then break end end code=table.concat(p) end
    if type(code)=="string" and #code>5 then _capture(code) local f=io.open(_out.."/layer_1.lua","w") if f then f:write(code) f:close() end end
    return _orig(code,name)
end
load,G.loadstring,G.load=loadstring,loadstring,loadstring
string.char=function(...) local r=(string.char~=nil and string.char or _G.string.char)(...) _capture(r) return r end
table.concat=function(t,s,i,j) local r=(table.concat~=nil and table.concat or _G.table.concat)(t,s,i,j) if #r>3 then _capture(r)end return r end
local f=io.open(_inp,"r") local code=f:read("*a") f:close()
local chunk,err=loadstring(code)
if chunk then setfenv(chunk,setmetatable({},{__index=_G})) local ok,res=pcall(chunk)
    if ok and type(res)=="function" then local bc=string.dump(res) local df=io.open(_out.."/dump.bin","wb") if df then df:write(bc) df:close() end end
end
local sf=io.open(_out.."/cap.txt","w") if sf then for _,s in ipairs(_cap) do sf:write(s:gsub("\n","\\n").."\n---SEP---\n") end sf:close() end
local df=io.open(_out.."/diag.txt","w") if df then df:write(table.concat(_log,"\n")) df:close() end
