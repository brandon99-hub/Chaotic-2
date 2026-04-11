import time
import requests
import statistics
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://localhost:8088"

def measure_request(endpoint, method="GET", payload=None):
    start = time.perf_counter()
    try:
        if method == "POST":
            requests.post(f"{BASE_URL}{endpoint}", json=payload)
        else:
            requests.get(f"{BASE_URL}{endpoint}")
    except Exception as e:
        print(f"Error: {e}")
    return (time.perf_counter() - start) * 1000  # ms

def run_performance_suite():
    print("=" * 60)
    print("    CHAOTIC AUTH - PERFORMANCE BENCHMARK RUNNER")
    print("=" * 60)
    
    # 1. Warm up
    requests.get(f"{BASE_URL}/api/health")
    
    # 2. Challenge Generation Benchmark (10 iterations)
    print("\n[Benchmarking] /api/auth/challenge (10 iterations)...")
    challenge_times = []
    for _ in range(10):
        # Using a dummy device that doesn't exist just to measure generation overhead
        # or use the health check if we want baseline
        t = measure_request("/api/auth/challenge", "POST", {"user_id": "bench@test.com", "device_id": "BENCH_DEVICE"})
        challenge_times.append(t)
    
    avg_challenge = statistics.mean(challenge_times)
    print(f"  Average Latency: {avg_challenge:.2f}ms")
    print(f"  Target: < 10ms | Status: {'SUCCESS' if avg_challenge < 10 else 'NEEDS OPTIMIZATION'}")

    # 3. Verification Logic Baseline
    print("\n[Benchmarking] /api/health (Baseline Check)...")
    health_times = []
    for _ in range(10):
        t = measure_request("/api/health")
        health_times.append(t)
    
    avg_health = statistics.mean(health_times)
    print(f"  System Response Baseline: {avg_health:.2f}ms")

    # 4. Stress Test (Concurrent Challenge Requests)
    print("\n[Stress Test] 50 Concurrent Challenge Requests...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(measure_request, "/api/auth/challenge", "POST", {"user_id": "stress@test.com", "device_id": "STRESS_DEV"}) for _ in range(50)]
        stress_times = [f.result() for f in futures]
    
    print(f"  Avg Concurrent Latency: {statistics.mean(stress_times):.2f}ms")
    print(f"  Max Latency under Load: {max(stress_times):.2f}ms")

    print("\n" + "=" * 60)
    print("    BENCHMARK COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    run_performance_suite()
