ngx.req.read_body()

-- ===================================================================
-- STAGE 1: REGEX CHECK AGAINST LOCAL REDIS
-- ===================================================================
local redis = require "resty.redis"
local cjson = require "cjson"

local red = redis:new()
red:set_timeout(1000)

-- Connect to local Redis
local ok, err = red:connect("127.0.0.1", 6379)
if not ok then
    ngx.log(ngx.ERR, "LUA: Failed to connect to local Redis: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- Check rules against request body
local request_body = ngx.req.get_body_data() or ""
local rules, err = red:smembers("waf:rules:regex")
if rules then
    for _, rule in ipairs(rules) do
        if ngx.re.find(request_body, rule, "ijo") then
            ngx.log(ngx.INFO, "BLOCK: Stage 1 blocked by regex rule: ", rule)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end
end
ngx.log(ngx.INFO, "PASS: Stage 1 (Regex) passed.")

-- ===================================================================
-- STAGE 2: TRANSFORMER MODEL CHECK
-- ===================================================================
local http = require "resty.http"

-- Build request_body string in the format your transformer expects
-- Combines URI args and POST body
local uri_args = ngx.req.get_uri_args()
local request_body_str = request_body

-- If there are URI arguments, format them as key=value pairs
if uri_args and next(uri_args) ~= nil then
    local args_parts = {}
    for key, val in pairs(uri_args) do
        if type(val) == "table" then
            -- Handle multiple values for same key
            for _, v in ipairs(val) do
                table.insert(args_parts, key .. "=" .. v)
            end
        else
            table.insert(args_parts, key .. "=" .. val)
        end
    end
    request_body_str = table.concat(args_parts, "&")
end

-- Format data according to transformer model's expected schema
local transformer_data = {
    method = ngx.req.get_method(),
    path = ngx.var.uri,
    protocol = ngx.var.server_protocol,  -- e.g., "HTTP/1.1"
    status = 200,  -- We don't have response status yet, default to 200
    request_body = request_body_str
}

ngx.log(ngx.INFO, "LUA: Sending to transformer: ", cjson.encode(transformer_data))

local httpc = http:new()
local res, err = httpc:request_uri("http://127.0.0.1:8000/analyze", {
    method = "POST",
    body = cjson.encode(transformer_data),
    headers = { ["Content-Type"] = "application/json" }
})

if not res then
    ngx.log(ngx.ERR, "LUA: Failed to connect to analyzer: ", err)
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

ngx.log(ngx.INFO, "LUA: Transformer response: ", res.body)

local report, err = cjson.decode(res.body)
if not report then
    ngx.log(ngx.ERR, "LUA: Failed to decode analyzer response: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

if report.allow == false then
    ngx.log(ngx.INFO, "BLOCK: Stage 2 blocked by transformer model")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

ngx.log(ngx.INFO, "PASS: Stage 2 (Transformer) passed. Proxying to backend.")
