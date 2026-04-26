import urllib.request
import json
import sys
import os

# Append project root to path for absolute DB object references
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))



def print_header(title):
    print("\n" + "="*50)
    print(f"\033[1;36m{title.center(50)}\033[0m")
    print("="*50)

def main():

    
    try:
        print("Polling Chaotic API Backend (localhost:8088)...")
        req = urllib.request.Request("http://localhost:8088/api/benchmarks")
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
        
        if not data.get("success"):
            print("\033[31m[ERROR] API returned unsuccessful attempt\033[0m")
            return
            
        stats = data.get("stats", {})
        
        print_header("REAL-TIME BENCHMARKS")
        
        # Challenge Gen Check
        lat = stats.get('avg_challenge_gen_ms', 0)
        c_lat = "\033[32m[PASS]\033[0m" if lat < 10 else "\033[31m[FAIL]\033[0m"
        print(f" > Challenge Gen (target <10ms): {lat:.2f}ms {c_lat}")
        
        # Total Auth verification
        v_lat = stats.get('avg_verification_ms', 0)
        c_v = "\033[32m[PASS]\033[0m" if v_lat < 500 else "\033[31m[FAIL]\033[0m"
        print(f" > ZKP Verification latency:     {v_lat:.2f}ms {c_v}")
        
        print(f" > Total Validated Signatures:   {int(stats.get('total_verifications', 0))}")
        print(f" > Security Integrity Score:     {int(stats.get('security_score', 0))}%\n")
        
        print_header("SECURITY AUDIT PROBE MATRIX")
        matrix = stats.get("pass_fail_matrix", {})
        
        for check, status in matrix.items():
            check_name = check.replace("_", " ").title()
            color = "\033[32m" if "PASS" in status else "\033[33m"
            print(f"  [{color}{status.center(8)}\033[0m] {check_name}")
            
    except urllib.error.URLError as e:
        print(f"\n\033[31m[CRITICAL FAILURE] Could not reach API:\n{str(e)}\033[0m")
    except Exception as e:
        print(f"\n\033[31m[CRITICAL FAILURE] Exception occurred:\n{str(e)}\033[0m")
        print("\nPlease ensure 'python patch_db.py' has run, and restart 'python backend/api_server.py'.")

if __name__ == '__main__':
    main()
