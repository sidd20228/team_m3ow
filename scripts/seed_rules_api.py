import requests
import redis
import time

# --- CONFIGURATION ---
API_URL = "http://localhost:8001"        # WAF Brain API
REDIS_HOST = "localhost"                 # Direct Redis Access
REDIS_PORT = 6379
HEADERS = {"Content-Type": "application/json"}

# The Standard Rule Set (PCRE Regex)
RULES = [
    # --- SQL Injection ---
    r"union\s+select",
    r"union\s+all\s+select",
    r"'\s*or\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+",
    r"'\s*or\s+[\"']?1[\"']?\s*=\s*[\"']?1",
    r"select\s+.*\s+from\s+",
    r"insert\s+into\s+",
    r"delete\s+from\s+",
    r"drop\s+table",
    r"drop\s+database",
    r"update\s+.*\s+set\s+",
    r"exec\s*\(", 
    r"execute\s*\(",
    r"xp_cmdshell",
    r"sp_executesql",
    r"benchmark\s*\(",
    r"sleep\s*\(",
    r"waitfor\s+delay",
    r"';\s*--",
    r"'\s*;\s*--",
    
    # --- XSS ---
    r"<script[^>]*>",
    r"</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"expression\s*\(",
    r"eval\s*\(",
    r"alert\s*\(",
    r"document\.cookie",
    r"document\.location",
    r"window\.location",
    
    # --- Path Traversal ---
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\windows",
    r"c:/windows",
    
    # --- Command Injection ---
    r"\|\s*whoami",
    r"\|\s*ls",
    r"\|\s*cat",
    r"&&\s*whoami",
    r"&&\s*ls",
    r"&&\s*cat"
]

def hard_reset_redis():
    """Connects directly to Redis and wipes EVERYTHING."""
    print(f"[*] Connecting to Redis at {REDIS_HOST}:{REDIS_PORT} for Hard Reset...")
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping() # Check connection
        
        # The Nuclear Option: Deletes all keys in all databases
        r.flushall() 
        
        print("[+] 💥 Redis FLUSHALL successful. Database is empty.")
        
    except redis.exceptions.ConnectionError:
        print("[-] Could not connect to Redis directly. Is port 6379 exposed?")
        print("    (You can still run this, but old data might persist).")
    except Exception as e:
        print(f"[-] Redis Reset Error: {e}")

def seed_new_rules():
    """Uploads the RULES list to the API."""
    print(f"[*] Connecting to WAF API at {API_URL} to seed rules...")
    
    # Wait a moment for API to reconnect to Redis if needed
    time.sleep(1)
    
    success_count = 0
    for rule in RULES:
        payload = {"rule": rule}
        try:
            resp = requests.post(f"{API_URL}/rules", json=payload, headers=HEADERS)
            if resp.status_code == 200:
                success_count += 1
            else:
                print(f" [-] Failed to add '{rule}': {resp.text}")
        except requests.exceptions.ConnectionError:
             print(f"[!] API Connection Failed. Is the WAF App running on port 8001?")
             return

    print(f"\n[+] SUCCESS: Seeded {success_count}/{len(RULES)} rules into the WAF.")

if __name__ == "__main__":
    # 1. Wipe Redis Clean
    hard_reset_redis()
    
    # 2. Upload Fresh Rules
    seed_new_rules()