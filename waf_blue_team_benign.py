import os
import requests
import json
import time
import csv
import random
import socket
from faker import Faker
from typing import List, Dict
from tqdm import tqdm
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

# ================= CONFIGURATION =================
# WebGoat typically runs on 8080 or via your WAF on 9090/2323
WAF_BASE_URL = "http://localhost:2323/WebGoat" 

NUM_REQUESTS = 100               # How many benign requests to send
LOG_CSV = "waf_benign_traffic_report.csv"
METRICS_IMAGE = "waf_benign_metrics.png"

# Standard headers mimicking a real browser
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Connection": "keep-alive"
}
# =============================================

fake = Faker()

class BenignTrafficAgent:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.history = []
        
        # Initialize CSV
        with open(LOG_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "ip", "method", "url", "path", 
                "protocol", "request_body", "response_status", "blocked", "latency_ms", "type"
            ])

    def generate_benign_action(self):
        """Generates a random SAFE user action."""
        action_type = random.choice(["browse", "search", "login", "register", "comment"])
        
        if action_type == "browse":
            # Just visiting a page
            endpoints = ["/login", "/registration", "/welcome.mvc", "/start.mvc"]
            path = random.choice(endpoints)
            return {
                "method": "GET",
                "url": f"{self.base_url}{path}",
                "data": {},
                "type": "Page Load"
            }
            
        elif action_type == "search":
            # Searching for safe terms
            term = fake.word() if random.random() > 0.5 else fake.city()
            return {
                "method": "GET",
                "url": f"{self.base_url}/search",
                "params": {"q": term},
                "data": {},
                "type": "Search"
            }

        elif action_type == "login":
            # Posting valid credentials
            return {
                "method": "POST",
                "url": f"{self.base_url}/login",
                "data": {
                    "username": fake.user_name(),
                    "password": fake.password(length=12)
                },
                "type": "Login Attempt"
            }

        elif action_type == "register":
            # Registering a new user
            return {
                "method": "POST",
                "url": f"{self.base_url}/register.mvc",
                "data": {
                    "username": fake.user_name(),
                    "password": fake.password(),
                    "confirmParam": "on",
                    "email": fake.email()
                },
                "type": "Registration"
            }
            
        elif action_type == "comment":
            # Submitting a safe comment
            return {
                "method": "POST",
                "url": f"{self.base_url}/comment",
                "data": {
                    "text": fake.sentence(),
                    "user_id": str(random.randint(1, 1000))
                },
                "type": "Comment"
            }

    def run_simulation(self):
        print(f"[BlueTeam] 🛡️  Generating {NUM_REQUESTS} benign requests...")
        
        try:
            target_ip = socket.gethostbyname(requests.utils.urlparse(self.base_url).hostname)
        except:
            target_ip = "127.0.0.1"

        for _ in tqdm(range(NUM_REQUESTS), desc="Simulating Users"):
            action = self.generate_benign_action()
            
            try:
                start_time = time.time()
                
                # Execute Request
                if action["method"] == "GET":
                    resp = self.session.get(action["url"], params=action.get("params"), headers=HEADERS, timeout=5)
                    req_body = json.dumps(action.get("params", ""))
                else:
                    resp = self.session.post(action["url"], data=action["data"], headers=HEADERS, timeout=5)
                    req_body = json.dumps(action["data"])
                
                latency_ms = (time.time() - start_time) * 1000

                # WAF Logic for BENIGN traffic:
                # 403/406 = WAF Blocked (FALSE POSITIVE - BAD)
                # 200/302/404 = Allowed (TRUE NEGATIVE - GOOD)
                is_blocked = resp.status_code in [403, 406]
                
                # Parse URL for logging
                parsed = requests.utils.urlparse(action["url"])

                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "ip": target_ip,
                    "method": action["method"],
                    "url": action["url"],
                    "path": parsed.path,
                    "protocol": "HTTP/1.1",
                    "request_body": req_body,
                    "response_status": resp.status_code,
                    "blocked": is_blocked,
                    "latency_ms": round(latency_ms, 2),
                    "type": action["type"]
                }
                
                self.history.append(log_entry)
                self._append_to_csv(log_entry)
                
                # Random sleep to mimic human reading time (0.1s to 0.5s)
                time.sleep(random.uniform(0.1, 0.5))

            except requests.RequestException:
                # If connection drops, treat as blocked/error
                self.history.append({
                    "timestamp": datetime.now().isoformat(),
                    "ip": target_ip,
                    "method": action["method"],
                    "url": action["url"],
                    "path": action["url"],
                    "protocol": "HTTP/1.1",
                    "request_body": "CONNECTION_ERROR",
                    "response_status": 0,
                    "blocked": True,
                    "latency_ms": 0,
                    "type": action["type"]
                })

    def _append_to_csv(self, row):
        with open(LOG_CSV, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "ip", "method", "url", "path", 
                "protocol", "request_body", "response_status", "blocked", "latency_ms", "type"
            ])
            writer.writerow(row)

    def generate_metrics(self):
        print("\n[Analysis] 📊 Generating Accuracy Metrics...")
        
        try:
            df = pd.DataFrame(self.history)
            
            if df.empty:
                print("No data.")
                return

            total = len(df)
            false_positives = df['blocked'].sum() # Benign requests that were blocked
            allowed = total - false_positives
            
            # False Positive Rate (Lower is better)
            fp_rate = (false_positives / total) * 100
            
            avg_latency = df[df['latency_ms'] > 0]['latency_ms'].mean()

            print("-" * 40)
            print(f"Total Benign Requests: {total}")
            print(f"Correctly Allowed:     {allowed}")
            print(f"False Positives:       {false_positives} (Blocked)")
            print(f"False Positive Rate:   {fp_rate:.2f}%")
            print(f"Avg Latency:           {avg_latency:.2f} ms")
            print("-" * 40)

            # --- Visualization ---
            plt.figure(figsize=(15, 5))

            # 1. Pass Rate (Pie Chart)
            plt.subplot(1, 3, 1)
            plt.pie([allowed, false_positives], labels=['Allowed (Good)', 'Blocked (Bad)'], 
                    autopct='%1.1f%%', colors=['#66b3ff', '#ff9999'], startangle=90)
            plt.title('Benign Traffic Pass Rate')

            # 2. Latency
            plt.subplot(1, 3, 2)
            plt.hist(df[df['latency_ms'] > 0]['latency_ms'], bins=10, color='lightgreen', edgecolor='black')
            plt.title('Latency Distribution (ms)')
            plt.xlabel('Time (ms)')

            # 3. Block Rate by Action Type
            plt.subplot(1, 3, 3)
            # Group by type and calculate % blocked
            if false_positives > 0:
                type_counts = df.groupby('type')['blocked'].mean() * 100
                type_counts.plot(kind='bar', color='orange', edgecolor='black')
                plt.title('False Positive Rate by Action')
                plt.ylabel('% Blocked')
                plt.ylim(0, 100)
            else:
                plt.text(0.5, 0.5, 'No False Positives!', ha='center')
                plt.title('False Positive Rate by Action')

            plt.tight_layout()
            plt.savefig(METRICS_IMAGE)
            print(f"[Analysis] ✅ Graphs saved to {METRICS_IMAGE}")

        except Exception as e:
            print(f"[Analysis] ❌ Error generating graphs: {e}")

# ================= MAIN =================
if __name__ == "__main__":
    agent = BenignTrafficAgent(WAF_BASE_URL)
    agent.run_simulation()
    agent.generate_metrics()