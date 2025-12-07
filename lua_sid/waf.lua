-- WAF Lua module for ML-based anomaly detection
-- This module handles rule-based checks and ML API integration

local _M = {}

local http = require "resty.http"
local cjson = require "cjson.safe"

-- Configuration
_M.ML_API_URL = "http://waf-ml-api:5000/score"
_M.ML_API_TIMEOUT = 10000  -- 10 seconds (ML inference can be slow on CPU)
_M.MAX_BODY_SIZE = 1048576  -- 1MB
_M.BLOCK_ON_ML_FAILURE = false  -- Don't block if ML API fails
_M.ML_LOG_ONLY = false  -- ML blocking enabled
_M.RULE_BASED_ENABLED = false  -- Disable rule-based WAF for now

-- SQLi patterns to block
local SQLI_PATTERNS = {
    "union%s+select",
    "union%s+all%s+select",
    "'%s*or%s+['\"]?%d+['\"]?%s*=%s*['\"]?%d+",
    "'%s*or%s+['\"]?1['\"]?%s*=%s*['\"]?1",
    "select%s+.*%s+from%s+",
    "insert%s+into%s+",
    "delete%s+from%s+",
    "drop%s+table",
    "drop%s+database",
    "update%s+.*%s+set%s+",
    "exec%s*%(", 
    "execute%s*%(",
    "xp_cmdshell",
    "sp_executesql",
    "benchmark%s*%(",
    "sleep%s*%(",
    "waitfor%s+delay",
    "';%s*--",
    "'%s*;%s*--",
    "1%s*=%s*1",
    "1'%s*or%s*'1'%s*=%s*'1",
}

-- XSS patterns to block
local XSS_PATTERNS = {
    "<script[^>]*>",
    "</script>",
    "javascript:",
    "on%w+%s*=",
    "expression%s*%(",
    "eval%s*%(",
    "alert%s*%(",
    "document%.cookie",
    "document%.location",
    "window%.location",
}

-- Path traversal patterns
local PATH_TRAVERSAL_PATTERNS = {
    "%.%.%/",
    "%.%.\\",
    "/etc/passwd",
    "/etc/shadow",
    "c:\\windows",
    "c:/windows",
}


-- Check string against pattern list (case-insensitive)
local function matches_patterns(str, patterns)
    if not str or str == "" then
        return false, nil
    end
    local lower_str = string.lower(str)
    for _, pattern in ipairs(patterns) do
        if string.match(lower_str, pattern) then
            return true, pattern
        end
    end
    return false, nil
end


-- Rule-based WAF check
function _M.rule_based_check()
    local uri = ngx.var.uri or ""
    local args = ngx.var.args or ""
    local request_body = ngx.var.request_body or ""
    
    -- Check for SQLi
    local blocked, pattern = matches_patterns(uri, SQLI_PATTERNS)
    if blocked then
        return true, "SQLi detected in URI", pattern
    end
    
    blocked, pattern = matches_patterns(args, SQLI_PATTERNS)
    if blocked then
        return true, "SQLi detected in query args", pattern
    end
    
    blocked, pattern = matches_patterns(request_body, SQLI_PATTERNS)
    if blocked then
        return true, "SQLi detected in body", pattern
    end
    
    -- Check for XSS
    blocked, pattern = matches_patterns(uri, XSS_PATTERNS)
    if blocked then
        return true, "XSS detected in URI", pattern
    end
    
    blocked, pattern = matches_patterns(args, XSS_PATTERNS)
    if blocked then
        return true, "XSS detected in query args", pattern
    end
    
    blocked, pattern = matches_patterns(request_body, XSS_PATTERNS)
    if blocked then
        return true, "XSS detected in body", pattern
    end
    
    -- Check for path traversal
    blocked, pattern = matches_patterns(uri, PATH_TRAVERSAL_PATTERNS)
    if blocked then
        return true, "Path traversal detected", pattern
    end
    
    -- Check body size
    local content_length = tonumber(ngx.var.content_length) or 0
    if content_length > _M.MAX_BODY_SIZE then
        return true, "Request body too large", "size: " .. content_length
    end
    
    return false, nil, nil
end


-- Call ML API for anomaly detection
function _M.ml_check()
    local method = ngx.var.request_method or ""
    local uri = ngx.var.uri or ""
    local args = ngx.var.args or ""
    local protocol = ngx.var.server_protocol or "HTTP/1.1"
    local request_body = ngx.var.request_body or ""
    local content_length = ngx.var.content_length or "0"
    
    -- Build full path with query string
    local full_path = uri
    if args and args ~= "" then
        full_path = uri .. "?" .. args
    end
    
    -- Build request payload matching ScoreRequest schema
    local payload = {
        body_bytes_sent = content_length,
        body_bytes = content_length,
        method = method,
        path = full_path,
        protocol = protocol,
        request_body = request_body,
        body = request_body
    }
    
    local json_payload, err = cjson.encode(payload)
    if not json_payload then
        ngx.log(ngx.ERR, "Failed to encode JSON payload: ", err)
        return _M.BLOCK_ON_ML_FAILURE, "JSON encode error", nil
    end
    
    -- Create HTTP client
    local httpc = http.new()
    httpc:set_timeout(_M.ML_API_TIMEOUT)
    
    -- Make request to ML API
    local res, err = httpc:request_uri(_M.ML_API_URL, {
        method = "POST",
        body = json_payload,
        headers = {
            ["Content-Type"] = "application/json",
        },
    })
    
    if not res then
        ngx.log(ngx.ERR, "ML API request failed: ", err)
        return _M.BLOCK_ON_ML_FAILURE, "ML API unavailable", nil
    end
    
    if res.status ~= 200 then
        ngx.log(ngx.ERR, "ML API returned status: ", res.status)
        return _M.BLOCK_ON_ML_FAILURE, "ML API error", nil
    end
    
    -- Parse response
    local response, err = cjson.decode(res.body)
    if not response then
        ngx.log(ngx.ERR, "Failed to parse ML API response: ", err)
        return _M.BLOCK_ON_ML_FAILURE, "ML response parse error", nil
    end
    
    -- Check decision
    if response.decision == "block" or response.category == 1 then
        return true, "ML anomaly detected", response
    end
    
    return false, nil, response
end


-- Main WAF handler
function _M.handle_request()
    -- Read request body first (required for POST inspection)
    ngx.req.read_body()
    
    local client_ip = ngx.var.remote_addr
    local uri = ngx.var.uri
    local method = ngx.var.request_method
    
    -- Step 1: Rule-based checks (if enabled)
    if _M.RULE_BASED_ENABLED then
        local blocked, reason, pattern = _M.rule_based_check()
        if blocked then
            ngx.log(ngx.WARN, string.format(
                "[WAF-RULE] BLOCKED - IP: %s, URI: %s, Method: %s, Reason: %s, Pattern: %s",
                client_ip, uri, method, reason, pattern or "N/A"
            ))
            ngx.status = 403
            ngx.header["Content-Type"] = "application/json"
            ngx.say(cjson.encode({
                error = "Forbidden",
                reason = reason,
                blocked_by = "rule"
            }))
            return ngx.exit(403)
        end
    end
    
    -- Step 2: ML-based checks
    local ml_response
    blocked, reason, ml_response = _M.ml_check()
    if blocked then
        local loss = ml_response and ml_response.reconstruction_loss or "N/A"
        local threshold = ml_response and ml_response.details and ml_response.details.threshold or "N/A"
        
        -- In log-only mode, just log but don't block
        if _M.ML_LOG_ONLY then
            ngx.log(ngx.WARN, string.format(
                "[WAF-ML] WOULD_BLOCK (log-only mode) - IP: %s, URI: %s, Method: %s, Reason: %s, Loss: %s, Threshold: %s",
                client_ip, uri, method, reason, tostring(loss), tostring(threshold)
            ))
            -- Store ML decision for logging but continue
            ngx.var.ml_decision = "would_block"
            ngx.var.ml_loss = tostring(loss)
            -- Don't block, let request through
        else
            ngx.log(ngx.WARN, string.format(
                "[WAF-ML] BLOCKED - IP: %s, URI: %s, Method: %s, Reason: %s, Loss: %s, Threshold: %s",
                client_ip, uri, method, reason, tostring(loss), tostring(threshold)
            ))
            ngx.status = 403
            ngx.header["Content-Type"] = "application/json"
            ngx.say(cjson.encode({
                error = "Forbidden",
                reason = reason,
                blocked_by = "ml",
                reconstruction_loss = ml_response and ml_response.reconstruction_loss or nil
            }))
            return ngx.exit(403)
        end
    else
        -- Request allowed - log and continue
        local loss = ml_response and ml_response.reconstruction_loss or "N/A"
        ngx.log(ngx.INFO, string.format(
            "[WAF] ALLOWED - IP: %s, URI: %s, Method: %s, Loss: %s",
            client_ip, uri, method, tostring(loss)
        ))
        
        -- Store ML decision in variable for access log
        ngx.var.ml_decision = ml_response and ml_response.decision or "unknown"
        ngx.var.ml_loss = ml_response and tostring(ml_response.reconstruction_loss) or "N/A"
    end
end


return _M
