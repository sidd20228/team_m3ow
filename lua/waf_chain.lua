local cjson = require "cjson.safe"
local http = require "resty.http"
local redis = require "resty.redis"

-- ===================================================================
-- CONFIGURATION
-- ===================================================================
-- ⚠️ FOR WINDOWS MANUAL RUN: Use "127.0.0.1" for both.
-- ⚠️ FOR DOCKER: Use service names "waf_app" and "redis".
local ML_API_HOST = "127.0.0.1" 
local REDIS_HOST = "127.0.0.1"

local ML_API_URL = "http://" .. ML_API_HOST .. ":8001/analyze"
local ML_API_TIMEOUT = 4000 -- 4 seconds

-- ===================================================================
-- INITIALIZATION
-- ===================================================================
-- Read request data (Used by ML stage)
ngx.req.read_body()
local request_body = ngx.req.get_body_data() or ""
local uri = ngx.var.uri
local args = ngx.var.args or ""
local method = ngx.req.get_method()
local protocol = ngx.var.server_protocol

-- Connect to Redis for Config (Mode Check)
local red = redis:new()
red:set_timeout(1000)
local ok, err = red:connect(REDIS_HOST, 6379)

if not ok then
    ngx.log(ngx.ERR, "WAF: Failed to connect to Redis: ", err)
    -- Fail Open if Redis is down
else
    -- ===================================================================
    -- STAGE 0: CHECK WAF MODE
    -- ===================================================================
    -- Modes: "full", "ml", "off" (Regex/Rules mode is now irrelevant)
    local mode, err = red:get("waf:mode")
    
    if not mode or mode == ngx.null then
        mode = "full" -- Default to on
    end

    -- Skip everything if turned off
    if mode == "off" then
        ngx.log(ngx.INFO, "WAF: Mode is OFF. Passing traffic.")
        red:set_keepalive(10000, 100)
        return
    end

    -- Release Redis connection to pool
    red:set_keepalive(10000, 100)
    
    -- ===================================================================
    -- STAGE 2: ML MODEL CHECK (If mode is 'full' or 'ml')
    -- ===================================================================
    if mode == "full" or mode == "ml" then
        
        -- Helper: Reconstruct query params into body string for model
        local request_body_str = request_body
        local uri_args = ngx.req.get_uri_args()
        if uri_args and next(uri_args) ~= nil then
            local args_parts = {}
            for key, val in pairs(uri_args) do
                if type(val) == "table" then
                    for _, v in ipairs(val) do table.insert(args_parts, key .. "=" .. v) end
                else
                    table.insert(args_parts, key .. "=" .. val)
                end
            end
            if request_body_str ~= "" then
                request_body_str = request_body_str .. "&" .. table.concat(args_parts, "&")
            else
                request_body_str = table.concat(args_parts, "&")
            end
        end

        local payload = {
            method = method,
            path = uri,
            protocol = protocol,
            request_body = request_body_str
        }

        -- Send to Python Brain
        local httpc = http.new()
        httpc:set_timeout(ML_API_TIMEOUT)

        local res, err = httpc:request_uri(ML_API_URL, {
            method = "POST",
            body = cjson.encode(payload),
            headers = { ["Content-Type"] = "application/json" }
        })

        if not res then
            ngx.log(ngx.ERR, "WAF: Failed to contact ML Brain: ", err)
            -- Fail Open (Allow traffic if ML is down)
            return
        end

        local response, err = cjson.decode(res.body)
        if not response then
            ngx.log(ngx.ERR, "WAF: Failed to decode JSON from ML Brain: ", err)
            return
        end

        if response.allow == false then
            ngx.log(ngx.WARN, "BLOCK: Stage 2 (ML Model). Reason: " .. (response.reason or "Unknown"))
            
            ngx.status = 403
            ngx.header.content_type = "application/json"
            ngx.say(cjson.encode({
                error = "403 Forbidden",
                message = "Request blocked by AI Security Model",
                reason = response.reason,
                block_stage = "ml"
            }))
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
        ngx.log(ngx.INFO, "PASS: Stage 2 (ML) clear.")
    else
        ngx.log(ngx.INFO, "SKIP: Stage 2 (ML) disabled by config.")
    end
end

ngx.log(ngx.INFO, "WAF: CLEAN. Request allowed.")