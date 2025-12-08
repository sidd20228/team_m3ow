import requests
import time
import random
import matplotlib.pyplot as plt
import numpy as np

API_URL = "http://localhost:8001/analyze"

# Example test cases (add more as needed)
test_cases = [
    # Benign
    {"method": "GET", "path": "/test", "protocol": "HTTP/1.1", "request_body": "hello", "body_bytes_sent": "0", "label": "benign"},
    {"method": "POST", "path": "/test", "protocol": "HTTP/1.1", "request_body": "normal input", "body_bytes_sent": "0", "label": "benign"},
    # Malicious
    {"method": "POST", "path": "/test", "protocol": "HTTP/1.1", "request_body": "1' OR '1'='1", "body_bytes_sent": "0", "label": "malicious"},
    {"method": "GET", "path": "/test", "protocol": "HTTP/1.1", "request_body": "<script>alert(1)</script>", "body_bytes_sent": "0", "label": "malicious"},
]

def send_request(payload):
    start = time.perf_counter()
    resp = requests.post(API_URL, json=payload)
    latency = (time.perf_counter() - start) * 1000
    result = resp.json()
    allowed = result.get("allow", True)
    return latency, allowed, result

def main():
    latencies = []
    labels = []
    decisions = []
    correct = []
    for case in test_cases * 25:  # 100 requests (adjust as needed)
        latency, allowed, result = send_request({k: case[k] for k in ["method", "path", "protocol", "request_body", "body_bytes_sent"]})
        latencies.append(latency)
        labels.append(case["label"])
        decisions.append("benign" if allowed else "malicious")
        correct.append((allowed and case["label"] == "benign") or (not allowed and case["label"] == "malicious"))
        print(f"{case['label']:9s} | {latency:7.1f} ms | {'ALLOWED' if allowed else 'BLOCKED'} | {result.get('reason', '')}")

    # Accuracy metrics
    accuracy = np.mean(correct)
    print(f"\nAccuracy: {accuracy:.2%}")

    # Latency graph
    plt.figure(figsize=(10, 5))
    plt.title("WAF /analyze Latency per Request")
    plt.plot(latencies, marker='o', linestyle='-', alpha=0.7)
    plt.xlabel("Request #")
    plt.ylabel("Latency (ms)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("waf_latency.png")
    plt.close()

    # Boxplot by label
    benign_lat = [lat for lat, lbl in zip(latencies, labels) if lbl == "benign"]
    malicious_lat = [lat for lat, lbl in zip(latencies, labels) if lbl == "malicious"]
    plt.boxplot([benign_lat, malicious_lat], labels=["Benign", "Malicious"])
    plt.title("Latency Distribution by Request Type")
    plt.ylabel("Latency (ms)")
    plt.tight_layout()
    plt.savefig("waf_latency_boxplot.png")
    plt.close()

    # Accuracy bar
    plt.bar(["Accuracy"], [accuracy])
    plt.ylim(0, 1)
    plt.title("WAF Classification Accuracy")
    plt.tight_layout()
    plt.savefig("waf_accuracy.png")
    plt.close()

if __name__ == "__main__":
    main()