

import os
import re
import traceback
from datetime import datetime
from typing import Dict, Any, List
import numpy as np
import redis
import torch
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import pipeline, DistilBertTokenizer, DistilBertForMaskedLM
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import json
import hashlib

# ===================================================================
# --- 0. INITIAL SETUP & ENVIRONMENT VARIABLES ---
# ===================================================================
load_dotenv()  # Load environment variables from .env file

def log_debug(message: str, level: str = "INFO"):
    """Custom logging with timestamps."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

# ===================================================================
# --- 1. SERVICE CONNECTIONS (Redis & MongoDB) ---
# ===================================================================
app = FastAPI()

# Add CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for dev simplicity, restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

log_debug("🚀 Starting FastAPI WAF Application...")

# --- Redis Connection ---
try:
    redis_url = os.environ.get("REDIS_URL") or "redis://localhost:6379"
    r = redis.from_url(redis_url, decode_responses=True)
    r.ping()
    log_debug("✅ Successfully connected to Redis.", "SUCCESS")
except Exception as e:
    log_debug(f"❌ ERROR: Could not connect to Redis: {e}", "ERROR")
    r = None

# --- MongoDB Connection ---
try:
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("MONGO_URI environment variable not set!")
    
    mongo_client = MongoClient(mongo_uri)
    db = mongo_client.get_database("waf_db")
    analysis_collection = db.get_collection("analysis_logs")
    # Quick ping to verify
    mongo_client.admin.command('ping')
    log_debug("✅ Successfully connected to MongoDB.", "SUCCESS")
except Exception as e:
    log_debug(f"❌ ERROR: Could not connect to MongoDB: {e}", "ERROR")
    mongo_client = None
    analysis_collection = None

# ===================================================================
# --- 2. ANOMALY DETECTION MODEL SETUP (SIMPLIFIED) ---
# ===================================================================
log_debug("🧠 Loading Anomaly Detection Models...")
try:
    # Primary device for the main ML model (DistilBERT). Use CUDA if available.
    device_main = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device_main.type == 'cuda':
        log_debug(f"🔌 CUDA available. Using device: {torch.cuda.get_device_name(0)}", "INFO")
    else:
        log_debug("⚠️ CUDA not available. Running on CPU.", "INFO")
    # Backwards-compatible alias used throughout the code (some helpers reference `device`)
    device = device_main
    MAX_LENGTH = 256
    
    # Path Configuration - Update these if needed!
    MODEL_PATH = './distilbert_http_mlm_epoch22' 
    TRAIN_FEATURES_PATH = 'train_features_dvwa_fix_seed.npy'

    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_PATH)
    model = DistilBertForMaskedLM.from_pretrained(MODEL_PATH)
    # Move main model to primary device (GPU when available) for low-latency inference
    model.to(device_main)
    model.eval()

    # Load Training Stats for Thresholding
    train_data = np.load(TRAIN_FEATURES_PATH, allow_pickle=True).item()
    train_errors = train_data['errors']
    
    train_stats = {
        'mean_error': train_errors.mean(),
        'std_error': train_errors.std(),
        'threshold_percentile': np.percentile(train_errors, 95)
    }

    torch.manual_seed(42)
    np.random.seed(42)
    anomaly_model_loaded = True
    log_debug(f"✅ Models loaded. Threshold (95%): {train_stats['threshold_percentile']:.4f}", "SUCCESS")

except Exception as e:
    log_debug(f"❌ CRITICAL ERROR: Failed to load Anomaly Detection models: {e}", "ERROR")
    anomaly_model_loaded = False
    train_stats = {}

# ------------------------------------------------------------------
# LLM (rule generation) pipeline - lazy load on CPU only
# We intentionally do NOT load distilgpt2 onto GPU. It runs on CPU to
# preserve GPU memory for the main model used in the fast path.
# ------------------------------------------------------------------
llm_pipe = None
llm_loaded = False

def _lazy_load_llm():
    global llm_pipe, llm_loaded
    if llm_pipe is not None:
        return
    try:
        # device=-1 forces CPU   usage for the HF pipeline
        llm_pipe = pipeline("text-generation", model="distilgpt2", device=-1)
        llm_loaded = True
        log_debug("✍️ Loaded distilgpt2 for rule generation on CPU", "INFO")
    except Exception as e:
        llm_pipe = None
        llm_loaded = False
        log_debug(f"❌ Failed to load distilgpt2 LLM on CPU: {e}", "ERROR")

# ===================================================================
# --- 3. HELPER FUNCTIONS (Matches Inference Script) ---
# ===================================================================

def build_sequence(log_data: dict) -> str:
    """Builds the sequence string for the model."""
    body_bytes = log_data.get('body_bytes_sent', '') or log_data.get('body_bytes', '')
    method = log_data.get('method', '')
    path = log_data.get('path', '')
    protocol = log_data.get('protocol', '')
    body = log_data.get('request_body', '')

    return (
        f"[CLS] <body_bytes> {body_bytes} </body_bytes> [SEP] "
        f"<request_method> {method} </request_method> [SEP] "
        f"<request_path> {path} </request_path> [SEP] "
        f"<request_protocol> {protocol} </request_protocol> [SEP] "
        f"<request_body> {body} </request_body> [SEP]"
    )

def mask_tokens(input_ids: torch.Tensor, tokenizer_inst, mask_prob=0.15):
    """Masking for MLM training/inference. Works on tensors already on `device`."""
    device_local = input_ids.device
    labels = input_ids.clone()
    probability_matrix = torch.full(labels.shape, mask_prob, device=device_local)

    # Create special tokens mask
    special_tokens_mask = torch.zeros(labels.shape, dtype=torch.bool, device=device_local)
    for special_id in tokenizer_inst.all_special_ids:
        special_tokens_mask |= (labels == special_id)
    probability_matrix.masked_fill_(special_tokens_mask, value=0.0)

    masked_indices = torch.bernoulli(probability_matrix).bool()

    # Ensure at least one token is masked
    if masked_indices.sum() == 0:
        # choose random valid index (not 0 and not last)
        seq_len = labels.shape[1]
        if seq_len > 2:
            rand_idx = torch.randint(1, seq_len - 1, (1,), device=device_local)
            masked_indices[0, rand_idx] = True
        else:
            masked_indices[0, 0] = True

    labels[~masked_indices] = -100  # only compute loss on masked tokens

    # 80% replace with [MASK]
    prob_replace = 0.8
    indices_replaced = torch.bernoulli(torch.full(labels.shape, prob_replace, device=device_local)).bool() & masked_indices
    input_ids[indices_replaced] = tokenizer_inst.mask_token_id

    # 10% replace with random token
    prob_random = 0.1
    indices_random = torch.bernoulli(torch.full(labels.shape, prob_random, device=device_local)).bool() & masked_indices & ~indices_replaced
    # Use tokenizer.vocab_size
    random_words = torch.randint(0, tokenizer_inst.vocab_size, labels.shape, dtype=torch.long, device=device_local)
    input_ids[indices_random] = random_words[indices_random]

    # remaining 10% keep original
    return input_ids, labels

def extract_features(log_text: str, tokenizer_inst, model_inst, num_runs=5):
    """Calculates reconstruction error by averaging multiple runs.
    Returns: (avg_error: float, cls_embedding: np.ndarray, approx_perplexity: float)
    """
    device_local = device  # defined globally earlier
    errors = []
    cls_embeddings = []

    for _ in range(num_runs):
        # Tokenize on CPU then move tensors explicitly to device
        encoding = tokenizer_inst(
            log_text,
            padding='max_length',
            truncation=True,
            max_length=MAX_LENGTH,
            return_tensors='pt'
        )
        input_ids = encoding["input_ids"].to(device_local)
        attention_mask = encoding["attention_mask"].to(device_local)

        with torch.no_grad():
            masked_input, labels = mask_tokens(input_ids.clone(), tokenizer_inst)
            outputs = model_inst(
                input_ids=masked_input,
                attention_mask=attention_mask,
                labels=labels,
                return_dict=True
            )

        loss_val = outputs.loss
        if loss_val is None:
            error = float(0.0)
        else:
            error = float(loss_val.item())
        errors.append(error)

        # Approximate "CLS embedding" (DistilBERT doesn't have CLS token embedding like BERT; take first token's logits mean)
        try:
            # If model outputs logits (vocab predictions), we can take the logits for the first token and average
            logits = outputs.logits  # shape: (batch, seq_len, vocab_size)
            # Move to cpu numpy, take first position (0,0,:)
            cls_emb = logits[0, 0].detach().cpu().numpy()
        except Exception:
            # fallback to zeros
            cls_emb = np.zeros((tokenizer_inst.vocab_size,), dtype=float)

        cls_embeddings.append(cls_emb)

    avg_error = float(np.mean(errors))
    # average CLS embedding across runs (may be large; downsample if necessary)
    avg_cls_emb = np.mean(np.stack(cls_embeddings, axis=0), axis=0)

    # crude "perplexity" estimate from loss: exp(loss)
    try:
        approx_perplexity = float(np.exp(avg_error))
    except Exception:
        approx_perplexity = float("nan")

    return avg_error, avg_cls_emb, approx_perplexity
 

def predict_anomaly(reconstruction_error, stats):
    """
    Predicts anomaly based on the 95th percentile threshold from training.
    Returns 1 if Anomaly, 0 if Safe.
    """
    threshold = stats['threshold_percentile']
    is_anomaly = reconstruction_error > threshold
    
    # Optional: Calculate Z-Score for reporting
    z_score = abs(reconstruction_error - stats['mean_error']) / stats['std_error']
    
    return int(is_anomaly), {
        "threshold": float(threshold),
        "z_score": float(z_score),
        "mean_error": float(stats['mean_error'])
    }


# LLM for rule generation
log_debug("✍️ Loading LLM model for rule generation...")
try:
    llm_pipe = pipeline("text-generation", model="distilgpt2", device=-1) # Run on CPU for stability
    llm_loaded = True
except Exception:
    llm_pipe = None
    llm_loaded = False


def generate_rule_from_payload(payload: str) -> str | None:
    if not payload:
        return None

    # Fallback / Simple regex generation logic
    if not llm_loaded:
         # Basic safe regex escaping
        return f"(?i){re.escape(payload[:50])}"
    
    try:
        prompt = (
            f"Generate a regex pattern for a WAF to detect this malicious payload. "
            f"Output ONLY the regex pattern, nothing else:\n\n"
            f"Payload: {payload[:200]}\n\nRegex pattern:"
        )
        outputs = llm_pipe(prompt, max_new_tokens=50, pad_token_id=50256)
        regex_part = outputs[0]['generated_text'].replace(prompt, "").strip().split('\n')[0].strip('\'"')
        # Validate regex
        re.compile(regex_part)
        return regex_part
    except Exception:
        return f"(?i){re.escape(payload[:50])}"


def background_rule_learning(payload: str, mongo_id: str | None = None):
    """Background task: generate a regex rule from payload and persist it.
    This runs asynchronously after the API has returned a decision to the user.
    """
    try:
        if not payload:
            log_debug("No payload provided for background rule learning", "INFO")
            return

        log_debug("🧠 Background rule generation started", "INFO")
        new_rule = None
        try:
            new_rule = generate_rule_from_payload(payload)
        except Exception as e:
            log_debug(f"❌ LLM rule generation failed: {e}", "ERROR")
            new_rule = f"(?i){re.escape(payload[:50])}"

        # Persist to Redis
        if new_rule and r:
            try:
                r.sadd("waf:rules:regex", new_rule)
                log_debug("✅ Background: rule added to Redis", "SUCCESS")
            except Exception as e:
                log_debug(f"❌ Background: failed to add rule to Redis: {e}", "ERROR")

        # Update MongoDB analysis document if provided
        if mongo_id and analysis_collection is not None:
            try:
                analysis_collection.update_one({"_id": ObjectId(mongo_id)}, {"$set": {"auto_learned_rule": new_rule}})
                log_debug(f"📝 Background: Mongo document {mongo_id} updated with auto_learned_rule", "INFO")
            except Exception as e:
                log_debug(f"❌ Background: failed to update Mongo for {mongo_id}: {e}", "ERROR")

        log_debug("🧠 Background rule generation finished", "INFO")
    except Exception as e:
        log_debug(f"❌ Unexpected error in background_rule_learning: {e}", "ERROR")


# ===================================================================
# --- WebSocket Connection Manager ---
# ===================================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        log_debug(f"🔌 WebSocket client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        log_debug(f"🔌 WebSocket client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)

manager = ConnectionManager()


# ===================================================================
# --- 4. PYDANTIC MODELS & API ENDPOINTS ---
# ===================================================================
class RequestData(BaseModel):
    method: str
    path: str
    protocol: str
    request_body: str
    body_bytes_sent: str = "0" # Optional, default to 0

# Cache TTL (seconds) for identical requests. Safe default keeps correctness.
CACHE_TTL = int(os.getenv("WAF_CACHE_TTL", "60"))


@app.post("/analyze")
async def analyze(request_data: RequestData, background_tasks: BackgroundTasks):
    """
    Analyzes request using reconstruction error thresholding.
    """
    if not anomaly_model_loaded:
        raise HTTPException(status_code=503, detail="Anomaly detection service unavailable")

    try:
        # --- STEP 1: Request normalization and cache check ---
        # Pydantic v2: use model_dump() instead of .dict()
        formatted_log = build_sequence(request_data.model_dump())

        # Build a deterministic cache key for identical requests
        norm = f"{request_data.method}|{request_data.path}|{request_data.request_body}".strip().lower()
        cache_key = f"waf:decision:{hashlib.sha256(norm.encode()).hexdigest()}"

        # If Redis is available and decision cached, return cached response immediately
        if r:
            try:
                cached = r.get(cache_key)
                if cached:
                    log_debug("♻️ Returning cached WAF decision", "INFO")
                    return json.loads(cached)
            except Exception as e:
                log_debug(f"❌ Redis cache read error: {e}", "ERROR")

        # Run inference (5 runs averaged). extract_features returns (rec_error, cls_emb, perplexity)
        rec_error, cls_emb, perplexity = extract_features(formatted_log, tokenizer, model, num_runs=5)
        # Ensure rec_error is a plain float for comparisons/JSON
        rec_error = float(rec_error)

        # Predict
        is_malicious_int, details = predict_anomaly(rec_error, train_stats)
        is_malicious = bool(is_malicious_int)
        
        # --- STEP 2: Logic for response and logging ---
        response, new_rule = None, None
        payload = request_data.request_body or request_data.path

        if is_malicious:
            log_debug(f"🚨 MALICIOUS! Loss: {rec_error:.4f} > {details['threshold']:.4f}", "ALERT")

            # Defer rule generation to background to keep response fast
            new_rule = None
            response = {
                "allow": False,
                "reason": f"Blocked by ML (Loss: {rec_error:.4f} > Threshold: {details['threshold']:.4f})",
                "auto_learned_rule": None,
                "reconstruction_loss": rec_error,
                "details": details
            }
        else:
            log_debug(f"✅ BENIGN. Loss: {rec_error:.4f}")
            response = {
                "allow": True, 
                "reason": "Safe",
                "reconstruction_loss": rec_error,
                "details": details
            }
            
        # --- STEP 3: Save to MongoDB ---
        if analysis_collection is not None:
            log_document = {
                "timestamp": datetime.utcnow(),
                    "request": request_data.model_dump(),
                "analysis": {
                    "is_malicious": is_malicious,
                    "reconstruction_loss": float(rec_error),
                    "threshold": details['threshold'],
                    "z_score": details['z_score']
                },
                "action_taken": "BLOCK" if is_malicious else "ALLOW",
                "auto_learned_rule": new_rule
            }
            result = analysis_collection.insert_one(log_document)
            log_document["_id"] = str(result.inserted_id)

            # If malicious, schedule background rule generation which will update Redis and Mongo
            if is_malicious:
                try:
                    background_tasks.add_task(background_rule_learning, payload, str(result.inserted_id))
                    log_debug(f"⏱️ Scheduled background rule generation for doc {result.inserted_id}", "INFO")
                except Exception as e:
                    log_debug(f"❌ Failed to schedule background task: {e}", "ERROR")

            # Cache the decision for identical requests to reduce repeated inference
            if r:
                try:
                    cache_value = json.dumps(response)
                    r.setex(cache_key, CACHE_TTL, cache_value)
                    log_debug(f"💾 Cached decision for key {cache_key} (ttl={CACHE_TTL}s)", "INFO")
                except Exception as e:
                    log_debug(f"❌ Redis cache write error: {e}", "ERROR")

            # Broadcast to WebSocket clients
            broadcast_data = {
                "_id": log_document["_id"],
                "timestamp": log_document["timestamp"].isoformat(),
                "method": request_data.method,
                "path": request_data.path,
                "request_body": request_data.request_body,
                "action_taken": log_document["action_taken"],
                "is_malicious": is_malicious,
                "reconstruction_loss": float(rec_error),
                "auto_learned_rule": new_rule
            }
            await manager.broadcast(broadcast_data)

        return response
            
    except Exception as e:
        log_debug(f"❌ CRITICAL ERROR in /analyze: {e}", "ERROR")
        # Fail Open to avoid breaking the site on internal error
        return {"allow": True, "reason": "Internal Error", "error": str(e)}


@app.get("/health")
async def health_check():
    return {
        "status": "healthy" if r and anomaly_model_loaded else "degraded",
        "redis_connected": bool(r),
        "mongodb_connected": (mongo_client is not None),
        "anomaly_model_loaded": anomaly_model_loaded,
        "model_threshold": train_stats.get('threshold_percentile', 'N/A')
    }


@app.post("/debug-analyze")
async def debug_analyze(request_data: RequestData):
    """
    Debug endpoint returning raw model diagnostics for a request.
    Useful to inspect why a request was considered malicious.
    """
    try:
        if not anomaly_model_loaded:
            raise HTTPException(status_code=503, detail="Anomaly detection service unavailable")

        # Build sequence and extract features (same pipeline as /analyze)
        # Pydantic v2: use model_dump() instead of .dict()
        formatted_log = build_sequence(request_data.model_dump())
        rec_error, cls_emb, perplexity = extract_features(formatted_log, tokenizer, model)

        # Build feature vector and attempt scaling
        features = np.column_stack([
            np.array([rec_error, perplexity]).reshape(1, -1),
            cls_emb.reshape(1, -1)
        ])

        scaler_info = None
        scaled = None
        if scaler is not None:
            try:
                scaled = scaler.transform(features)
                scaler_info = {
                    "mean_shape": getattr(scaler, 'mean_', None).shape if hasattr(scaler, 'mean_') else None,
                    "scale_shape": getattr(scaler, 'scale_', None).shape if hasattr(scaler, 'scale_') else None,
                }
            except Exception as e:
                scaler_info = {"error": str(e)}

        # IForest prediction if available
        iforest_pred = None
        try:
            if iforest is not None and scaled is not None:
                iforest_pred = int(iforest.predict(scaled)[0])
        except Exception as e:
            iforest_pred = f"error: {e}"

        # Statistical checks
        z_score = None
        percentile_threshold = None
        try:
            if train_stats is not None and train_stats.get('std_error'):
                z_score = float(abs((rec_error - train_stats['mean_error']) / (train_stats['std_error'] or 1e-9)))
            percentile_threshold = float(train_stats['threshold_percentile']) if train_stats is not None else None
        except Exception:
            z_score = None

        # Short summary of scaled features
        scaled_preview = None
        if isinstance(scaled, np.ndarray):
            scaled_preview = scaled[0][:20].tolist()

        return {
            "reconstruction_loss": float(rec_error),
            "perplexity": float(perplexity),
            "cls_embedding_length": int(cls_emb.shape[0]) if hasattr(cls_emb, 'shape') else None,
            "scaled_preview_first_20": scaled_preview,
            "scaler_info": scaler_info,
            "iforest_prediction": iforest_pred,
            "z_score": z_score,
            "percentile_threshold": percentile_threshold,
        }

    except HTTPException:
        raise
    except Exception as e:
        log_debug(f"❌ CRITICAL ERROR in /debug-analyze: {e}", "ERROR")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# ===================================================================
# --- HISTORY & RULES (Same as before) ---
# ===================================================================
@app.get("/logs")
async def get_logs(limit: int = 20):
    if analysis_collection is None:
        raise HTTPException(status_code=503, detail="MongoDB service unavailable")
    try:
        logs = list(analysis_collection.find().sort("timestamp", -1).limit(limit))
        for log in logs:
            log["_id"] = str(log["_id"])
            if "timestamp" in log: log["timestamp"] = log["timestamp"].isoformat()
        return {"logs": logs, "count": len(logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class RuleBody(BaseModel):
    rule: str

@app.get("/rules")
async def get_rules():
    if not r: raise HTTPException(status_code=503, detail="Redis unavailable")
    return {"rules": list(r.smembers("waf:rules:regex"))}

@app.post("/rules")
async def add_rule(body: RuleBody):
    if not r: raise HTTPException(status_code=503, detail="Redis unavailable")
    try:
        re.compile(body.rule) # Validate
        r.sadd("waf:rules:regex", body.rule)
        return {"status": "success", "rule": body.rule}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/rules")
async def delete_rule(body: RuleBody):
    if not r: raise HTTPException(status_code=503, detail="Redis unavailable")
    r.srem("waf:rules:regex", body.rule)
    return {"status": "success", "message": "Rule deleted"}

@app.post("/set-mode/{mode_name}")
async def set_waf_mode(mode_name: str):
    # Updated to include 'rules' and 'ml'
    valid_modes = ['off', 'fast', 'full', 'rules', 'ml'] 
    
    if mode_name not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid mode. Must be one of: {valid_modes}")
    
    if not r: 
        raise HTTPException(status_code=503, detail="Redis service unavailable")
    
    try:
        r.set("waf:mode", mode_name)
        log_debug(f"🔧 WAF mode set to: {mode_name}", "INFO")
        return {"status": "success", "mode": mode_name, "message": f"WAF mode set to {mode_name}"}
    except Exception as e:
        log_debug(f"❌ Error setting WAF mode: {e}", "ERROR")
        raise HTTPException(status_code=500, detail=f"Error setting WAF mode: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)