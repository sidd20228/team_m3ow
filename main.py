import os
import redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
from transformers import pipeline
import re
import traceback
from datetime import datetime


def log_debug(message: str, level: str = "INFO"):
    """Custom logging with timestamps"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")


# --- 1. SETUP & REDIS CONNECTION ---
app = FastAPI()

log_debug("🚀 Starting FastAPI WAF Application...")

try:
    redis_url = os.environ.get("REDIS_URL") or "redis://localhost:6379"
    log_debug(f"Attempting to connect to Redis at: {redis_url}")
    
    if not redis_url:
        raise ValueError("REDIS_URL environment variable not set!")
    
    r = redis.from_url(redis_url, decode_responses=True)
    r.ping()
    log_debug("✅ Successfully connected to Redis.", "SUCCESS")
except Exception as e:
    log_debug(f"❌ ERROR: Could not connect to Redis: {e}", "ERROR")
    log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
    r = None


# --- 2. LLM SETUP FOR RULE GENERATION (LIGHTWEIGHT VERSION) ---
log_debug("Loading LLM model for rule generation...")

try:
    log_debug("Attempting to load DistilGPT2 (lightweight, ~350MB)...")
    llm_pipe = pipeline(
        "text-generation",
        model="distilgpt2",
        device=-1,  # CPU
        max_length=512,
    )
    log_debug("✅ LLM Pipeline (DistilGPT2) loaded successfully.", "SUCCESS")
except Exception as e:
    log_debug(f"❌ Failed to load LLM: {e}", "ERROR")
    log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
    llm_pipe = None


RULE_GENERATOR_PROMPT = """Generate a regex pattern for WAF to detect this malicious payload. Output ONLY the regex pattern, nothing else:

Payload: """


def generate_rule_from_payload(payload: str) -> str | None:
    """Uses an LLM to generate a regex rule from a malicious payload."""
    log_debug(f"🧠 generate_rule_from_payload() called with payload length: {len(payload) if payload else 0}")
    
    if not payload:
        log_debug("⚠️ Empty payload provided, skipping rule generation.", "WARNING")
        return None
    
    if llm_pipe is None:
        log_debug("❌ LLM pipeline not available, using fallback regex generation.", "WARNING")
        try:
            escaped = re.escape(payload[:100])
            fallback_rule = f"(?i){escaped}"
            log_debug(f"Using fallback rule: {fallback_rule}", "WARNING")
            return fallback_rule
        except Exception as e:
            log_debug(f"❌ Fallback also failed: {e}", "ERROR")
            return None
    
    try:
        log_debug(f"Sending payload to LLM: {payload[:100]}...")
        
        # Simplified prompt for DistilGPT2
        prompt = f"{RULE_GENERATOR_PROMPT}{payload[:200]}\n\nRegex pattern:"
        
        log_debug("Calling LLM pipeline...")
        outputs = llm_pipe(
            prompt,
            max_new_tokens=50,
            temperature=0.3,
            do_sample=True,
            pad_token_id=50256,  # DistilGPT2 specific
        )
        
        log_debug(f"LLM raw output: {outputs}")
        
        # Extract generated text
        generated_text = outputs[0]['generated_text']
        log_debug(f"Full generated text: {generated_text}")
        
        # Extract just the regex part (after the prompt)
        regex_part = generated_text.replace(prompt, "").strip()
        
        # Clean up common LLM artifacts
        regex_part = regex_part.split('\n')[0]  # Take first line only
        regex_part = regex_part.replace('"', '').replace("'", "").strip()
        
        log_debug(f"Extracted regex candidate: {regex_part}")
        
        # If LLM output is poor, use smart fallback
        if len(regex_part) < 3 or len(regex_part) > 200:
            log_debug("⚠️ LLM output invalid, using intelligent fallback", "WARNING")
            # Create pattern from payload keywords
            keywords = re.findall(r'\b\w+\b', payload.lower())[:5]
            if keywords:
                pattern = '|'.join(re.escape(kw) for kw in keywords)
                regex_part = f"(?i)({pattern})"
                log_debug(f"Generated keyword-based pattern: {regex_part}")
        
        # Validate regex
        try:
            re.compile(regex_part)
            log_debug(f"✅ Generated valid rule: {regex_part}", "SUCCESS")
            return regex_part
        except re.error:
            log_debug("⚠️ Invalid regex, using safe fallback", "WARNING")
            # Safe fallback: escape entire payload
            escaped = re.escape(payload[:100])
            safe_rule = f"(?i){escaped}"
            log_debug(f"Safe fallback rule: {safe_rule}")
            return safe_rule
        
    except Exception as e:
        log_debug(f"❌ Unexpected error in rule generation: {e}", "ERROR")
        log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
        
        # Final fallback
        try:
            escaped = re.escape(payload[:100])
            return f"(?i){escaped}"
        except:
            return None


# --- 3. Pydantic Models ---
class RequestData(BaseModel):
    method: str
    path: str
    protocol: str
    request_body: str  # Removed 'status' field


class Rule(BaseModel):
    rule: str


# --- 4. WAF ANALYSIS ENDPOINT (Stage 2) WITH AUTO-LEARNING ---
@app.post("/analyze")
async def analyze(request_data: RequestData):
    """
    Analyzes request and automatically generates regex rules for malicious payloads.
    """
    log_debug("=" * 60)
    log_debug("📥 /analyze endpoint called")
    log_debug(f"Request details - Method: {request_data.method}, Path: {request_data.path}")
    log_debug(f"Protocol: {request_data.protocol}")  # Removed status logging
    log_debug(f"Request body preview: {request_data.request_body[:100] if request_data.request_body else 'None'}...")
    
    # ==========================================================
    # <<< TOGGLE THIS VALUE FOR TESTING >>>
    SIMULATE_MALICIOUS = False  
    # ==========================================================
    
    log_debug(f"🔬 Analysis mode: {'MALICIOUS' if SIMULATE_MALICIOUS else 'BENIGN'}")
    
    try:
        # STEP 1: Transformer Model Analysis (currently simulated)
        # TODO: Replace this with actual transformer model call
        is_malicious = SIMULATE_MALICIOUS
        reason = "Hardcoded: Malicious payload simulated." if is_malicious else "Hardcoded: Benign request simulated."
        
        # STEP 2: If malicious, generate regex rule and add to Redis
        if is_malicious:
            log_debug("🚨 MALICIOUS request detected by transformer!")
            
            # Extract the payload to analyze (prioritize request_body, then path)
            payload_to_analyze = request_data.request_body if request_data.request_body else request_data.path
            log_debug(f"Payload to analyze: {payload_to_analyze[:200] if payload_to_analyze else 'None'}...")
            
            new_rule = None
            
            if payload_to_analyze:
                log_debug(f"📝 Initiating rule generation from payload...")
                
                # Generate regex rule using LLM
                new_rule = generate_rule_from_payload(payload_to_analyze)
                
                if new_rule:
                    log_debug(f"✅ Rule generated successfully: {new_rule}")
                    
                    if r:
                        log_debug("Adding rule to Redis...")
                        r.sadd("waf:rules:regex", new_rule)
                        log_debug(f"✅ Auto-generated rule added to Redis: {new_rule}", "SUCCESS")
                        reason += f" | Auto-generated rule: {new_rule}"
                    else:
                        log_debug("⚠️ Redis not available, cannot store rule.", "WARNING")
                else:
                    log_debug("⚠️ Failed to generate rule from payload.", "WARNING")
            else:
                log_debug("⚠️ No payload to analyze (both request_body and path are empty).", "WARNING")
            
            response = {
                "allow": False,
                "reason": reason,
                "auto_learned": new_rule
            }
            log_debug(f"📤 Returning response: {response}")
            return response
        else:
            log_debug("✅ Request classified as BENIGN, allowing.")
            response = {
                "allow": True,
                "reason": reason
            }
            log_debug(f"📤 Returning response: {response}")
            return response
            
    except Exception as e:
        log_debug(f"❌ CRITICAL ERROR in /analyze endpoint: {e}", "ERROR")
        log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# --- 5. RULE MANAGEMENT API ---
@app.get("/rules", response_model=Dict[str, List[str]])
async def get_rules():
    """Retrieve all regex rules from Redis."""
    log_debug("📥 /rules GET endpoint called")
    
    if not r:
        log_debug("❌ Redis connection not available", "ERROR")
        raise HTTPException(status_code=503, detail="Redis connection not available")
    
    try:
        log_debug("Fetching rules from Redis...")
        rules = list(r.smembers("waf:rules:regex"))
        log_debug(f"✅ Retrieved {len(rules)} rules from Redis", "SUCCESS")
        return {"rules": rules}
    except Exception as e:
        log_debug(f"❌ Error fetching rules: {e}", "ERROR")
        log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
        raise HTTPException(status_code=500, detail=f"Error fetching rules: {str(e)}")


@app.post("/rules")
async def add_rule(new_rule: Rule):
    """Manually add a new regex rule to Redis."""
    log_debug(f"📥 /rules POST endpoint called with rule: {new_rule.rule}")
    
    if not r:
        log_debug("❌ Redis connection not available", "ERROR")
        raise HTTPException(status_code=503, detail="Redis connection not available")
    
    try:
        log_debug("Adding rule to Redis...")
        r.sadd("waf:rules:regex", new_rule.rule)
        log_debug(f"✅ Rule added successfully: {new_rule.rule}", "SUCCESS")
        return {"status": "success", "message": "Rule added.", "rule": new_rule.rule}
    except Exception as e:
        log_debug(f"❌ Error adding rule: {e}", "ERROR")
        log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
        raise HTTPException(status_code=500, detail=f"Error adding rule: {str(e)}")


@app.delete("/rules")
async def delete_rule(rule_to_delete: Rule):
    """Delete a regex rule from Redis."""
    log_debug(f"📥 /rules DELETE endpoint called with rule: {rule_to_delete.rule}")
    
    if not r:
        log_debug("❌ Redis connection not available", "ERROR")
        raise HTTPException(status_code=503, detail="Redis connection not available")
    
    try:
        log_debug("Removing rule from Redis...")
        removed_count = r.srem("waf:rules:regex", rule_to_delete.rule)
        
        if removed_count > 0:
            log_debug(f"✅ Rule deleted successfully: {rule_to_delete.rule}", "SUCCESS")
            return {"status": "success", "message": "Rule deleted.", "rule": rule_to_delete.rule}
        else:
            log_debug(f"⚠️ Rule not found in Redis: {rule_to_delete.rule}", "WARNING")
            return {"status": "not_found", "message": "Rule not found in Redis."}
    except Exception as e:
        log_debug(f"❌ Error deleting rule: {e}", "ERROR")
        log_debug(f"Stack trace: {traceback.format_exc()}", "ERROR")
        raise HTTPException(status_code=500, detail=f"Error deleting rule: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint to verify services status"""
    log_debug("📥 /health endpoint called")
    
    status = {
        "redis": "connected" if r else "disconnected",
        "llm": "loaded" if llm_pipe else "not loaded",
        "status": "healthy" if (r and llm_pipe) else "degraded"
    }
    
    log_debug(f"Health status: {status}")
    return status


if __name__ == "__main__":
    import uvicorn
    log_debug("🚀 Starting Uvicorn server on 0.0.0.0:8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)
