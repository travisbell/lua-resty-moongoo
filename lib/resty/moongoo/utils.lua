local nmd5 = require "resty.nettle.md5"
local bit = require("bit")
local cbson = require("cbson")
local hasposix, posix = pcall(require, "posix")

local byte = string.byte
local gsub = string.gsub
local format = string.format

local function hex(str, spacer)
  return (gsub(str,"(.)", function (c)
    return format("%02x%s", byte(c), spacer or "")
  end))
end

local function generate_md5(string)
  local new_md5 = nmd5.new()
  new_md5:update(string)
  return new_md5:digest()
end

local machineid
if hasposix then
  machineid = posix.uname("%n")
else
  machineid = assert(io.popen("uname -n")):read("*l")
end
machineid = hex(generate_md5(machineid)):sub(1, 6)

local function uint_to_hex(num, len, be)
  local len = len or 4
  local be = be or 0
  local num = cbson.uint(num)
  local raw = cbson.uint_to_raw(num, len, be)
  local out = ''
  for i = 1, #raw do
    out = out .. format("%02x", raw:byte(i,i))
  end
  return out
end

local counter = 0

if not ngx then
  math.randomseed(os.time())
  counter = math.random(100)
else
  local resty_random = require "resty.random"
  local resty_string = require "resty.string"
  local strong_random = resty_random.bytes(4,true)
  while strong_random == nil do
    strong_random = resty_random.bytes(4,true)
  end
  counter = tonumber(resty_string.to_hex(strong_random), 16)
end

local function generate_oid()
  local pid = ngx and ngx.worker.pid() or nil
  if not pid then
    if hasposix then
      pid = posix.getpid("pid")
    else
      pid = 1
    end
  end

  pid = uint_to_hex(pid,2)
  counter = counter + 1
  local time = os.time()

  return uint_to_hex(time, 4, 1) .. machineid .. pid .. uint_to_hex(counter, 4, 1):sub(3,8)
end

local function parse_uri(url)
  -- initialize default parameters
  local parsed = {}
  -- empty url is parsed to nil
  if not url or url == "" then return nil, "invalid url" end
  -- remove whitespace
  url = gsub(url, "%s", "")
  -- get fragment
  url = gsub(url, "#(.*)$", function(f)
    parsed.fragment = f
    return ""
  end)
  -- get scheme
  url = gsub(url, "^([%w][%w%+%-%.]*)%:", function(s) parsed.scheme = s; return "" end)

  -- get authority
  local location
  url = gsub(url, "^//([^/]*)", function(n)
    location = n
    return ""
  end)

  -- get query stringing
  url = gsub(url, "%?(.*)", function(q)
    parsed.query_string = q
    return ""
  end)
  -- get params
  url = gsub(url, "%;(.*)", function(p)
    parsed.params = p
    return ""
  end)
  -- path is whatever was left
  if url ~= "" then parsed.database = gsub(url,"^/([^/]*).*","%1") end
  if not parsed.database or #parsed.database == 0 then parsed.database = "admin" end

  if not location then return parsed end

  location = gsub(location,"^([^@]*)@", function(u) parsed.userinfo = u; return "" end)

  parsed.hosts = {}
  gsub(location, "([^,]+)", function(u)
    local pr = { host = "localhost", port = 27017 }
    u = gsub(u, ":([^:]*)$",
      function(p) pr.port = p; return "" end)
    if u ~= "" then pr.host = u end
   table.insert(parsed.hosts, pr)
  end)
  if #parsed.hosts == 0 then parsed.hosts = {{ host = "localhost", port = 27017 }} end

  parsed.query = {}
  if parsed.query_string then
    gsub(parsed.query_string, "([^&]+)", function(u)
      u = gsub(u, "([^=]*)=([^=]*)$", function(k,v) parsed.query[k] = v; return "" end)
    end)
  end

  local userinfo = parsed.userinfo
  if not userinfo then return parsed end
  userinfo = gsub(userinfo, ":([^:]*)$",
    function(p) parsed.password = p; return "" end)
  parsed.user = userinfo
  return parsed
end

-- not full implementation, but oh well
local function saslprep(username)
  return gsub(gsub(username, '=', '=3D'), ',', '=2C')
end

local function pass_digest(username, password)
  return hex(generate_md5(username .. ":mongo:" .. password))
end

return {
  parse_uri = parse_uri;
  saslprep = saslprep;
  pass_digest = pass_digest;
  xor_bytestr = xor_bytestr;
  generate_oid = generate_oid;
}