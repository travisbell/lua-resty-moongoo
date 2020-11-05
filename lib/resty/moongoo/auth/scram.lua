local cbson = require("cbson")
local pbkdf2 = require "resty.nettle.pbkdf2"
local hmac = require "resty.nettle.hmac"
local sha1 = require "resty.nettle.sha1"
local base64 = require "resty.nettle.base64"
local saslprep = require("resty.moongoo.utils").saslprep
local pass_digest = require("resty.moongoo.utils").pass_digest

local char = string.char
local byte = string.byte
local gmatch = string.gmatch
local sub = string.sub
local random = math.random

local function generate_sha1(key)
  local sha1 = sha1.new()
  sha1:update(key)
  return sha1:digest()
end

local function generate_hmac_sha1(key, string)
  local hmac_sha1 = hmac.sha1.new(key)
  hmac_sha1:update(string)
  return hmac_sha1:digest()
end

local function xor_bytestr(a, b)
  local res = ""
  for i=1,#a do
    res = res .. char(bit.bxor(byte(a,i,i), byte(b, i, i)))
  end
  return res
end

local function auth(db, username, password)
  local username = saslprep(username)
  local c_nonce = base64.encode(sub(tostring(random()), 3 , 14))
  local first_bare = "n="  .. username .. ",r="  .. c_nonce
  local sasl_start_payload = base64.encode("n,," .. first_bare)

  local r, err
  r, err = db:_cmd("saslStart", {
    mechanism = "SCRAM-SHA-1" ;
    autoAuthorize = 1 ;
    payload =  cbson.binary(sasl_start_payload);
  })

  if not r then
    return nil, err
  end

  local conversationId = r['conversationId']
  local server_first = r['payload']:raw()
  local parsed_t = {}
  for k, v in gmatch(server_first, "(%w+)=([^,]*)") do
    parsed_t[k] = v
  end

  local iterations = tonumber(parsed_t['i'])
  local salt = parsed_t['s']
  local s_nonce = parsed_t['r']

  if not sub(s_nonce, 1, 12) == c_nonce then
    return nil, 'Server returned an invalid nonce.'
  end

  local without_proof = "c=biws,r=" .. s_nonce
  local salted_pass = pbkdf2.hmac_sha1(pass_digest(username, password), iterations, base64.decode(salt), 20)
  local client_key = generate_hmac_sha1(salted_pass, "Client Key")
  local auth_msg = first_bare .. ',' .. server_first .. ',' .. without_proof
  local client_sig = generate_hmac_sha1(generate_sha1(client_key), auth_msg)
  local client_key_xor_sig = xor_bytestr(client_key, client_sig)
  local client_proof = "p=" .. base64.encode(client_key_xor_sig)
  local client_final = base64.encode(without_proof .. ',' .. client_proof)
  local server_key = generate_hmac_sha1(salted_pass, "Server Key")
  local server_sig = base64.encode(generate_hmac_sha1(server_key, auth_msg))

  r, err = db:_cmd("saslContinue",{
    conversationId = conversationId ;
    payload =  cbson.binary(client_final);
  })

  if not r then
    return nil, err
  end

  local parsed_s = r['payload']:raw()
  parsed_t = {}
  for k, v in gmatch(parsed_s, "(%w+)=([^,]*)") do
    parsed_t[k] = v
  end
  if parsed_t['v'] ~= server_sig then
    return nil, "Server returned an invalid signature."
  end

  if not r['done'] then
    r, err = db:_cmd("saslContinue", {
      conversationId = conversationId ;
      payload =  ngx.encode_base64("");
    })

    if not r then
      return nil, err
    end

    if not r['done'] then
      return nil, 'SASL conversation failed to complete.'
    end

    return 1
  end

  return 1
end

return auth
