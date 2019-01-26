local ssl = require "ngx.ssl"
local resty_lock = require "resty.lock"
ssl.clear_certs()
local common_name = ssl.server_name()
if common_name == nil then
    common_name = "unknown"
end
local key_data = nil;
local f = io.open(string.format("/etc/nginx/ssl/%s-key.der", common_name), "r")
if f then
    key_data = f:read("*a")
    f:close()
end
local cert_data = nil;
local f = io.open(string.format("/etc/nginx/ssl/%s-cert.der", common_name), "r")
if f then
    cert_data = f:read("*a")
    f:close()
end
if key_data and cert_data then
    local ok, err = ssl.set_der_priv_key(key_data)
    if not ok then
        ngx.log(ngx.ERR, "failed to set DER priv key: ", err)
        return
    end
    local ok, err = ssl.set_der_cert(cert_data)
    if not ok then
        ngx.log(ngx.ERR, "failed to set DER cert: ", err)
        return
    end
    return
end
-- prevent creating same certificate twice using lock
local lock = resty_lock:new("my_locks")
local elapsed, err = lock:lock(common_name)
if not elapsed then
    return fail("failed to acquire the lock: ", err)
end
-- generate new private key
ngx.log(ngx.INFO, "generating key")
local key_data, err = ssl.rsa_generate_key(2048)
if not key_data then
    ngx.log(ngx.ERR, "failed to generate rsa key: ", err)
    return
end
-- write certificate to cache
local f = assert(io.open(string.format("/etc/nginx/ssl/%s-key.key", common_name), "w"))
f:write(key_data)
f:close()

local csr, err = ssl.generate_certificate_sign_request(key_data, {
    country = "NL",
    state = "Test",
    city = "City",
    organisation = "Organisation",
    common_name = common_name
})
if not csr then
    ngx.log(ngx.ERR, "failed to create sign request: ", err)
    return
end
ngx.log(ngx.ERR, "generated csr: ", csr, err)
-- load ca key
local f = assert(io.open("/etc/nginx/rootCA/ca.key"))
local ca = f:read("*a")
f:close()
if not ca then
    ngx.log(ngx.ERR, "failed to load cakey: ", err)
    return
end
-- create certificate using csr req
cert_data, err = ssl.sign_csr({
    ca = ca,
    csr = csr
})
if not cert_data then
    ngx.log(ngx.ERR, "failed to sign: ", err)
    return
end
-- write certificate to cache
local f = assert(io.open(string.format("/etc/nginx/ssl/%s-key.csr", common_name), "w"))
f:write(key_data)
f:close()
local ok, err = ssl.set_der_priv_key(key_data)
if not ok then
    ngx.log(ngx.ERR, "failed to set DER priv key: ", err)
    return
end
local f = assert(io.open(string.format("/etc/nginx/ssl/%s-cert.der", common_name), "w"))
f:write(cert_data)
f:close()
local ok, err = ssl.set_der_cert(cert_data)
if not ok then
    ngx.log(ngx.ERR, "failed to set DER cert: ", err)
    return
end
local ok, err = lock:unlock()
if not ok then
    return fail("failed to unlock: ", err)
end

