"""Runtime checks against a live backend: memory, sequential vs concurrent latency, rate limit.
Usage: python run_runtime_checks.py <uvicorn pid> [base]
Waits 65 s before each block so earlier requests don't count against the 20/min limit.
"""
import json, sys, time, concurrent.futures as cf
import requests

PID = sys.argv[1]; BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8000"
TEXT = "تم إيقاف بطاقتك مؤقتاً، أدخل بياناتك على الرابط لإعادة التفعيل"


def rss_mb():
    for line in open(f"/proc/{PID}/status"):
        if line.startswith("VmRSS"):
            return round(int(line.split()[1]) / 1024)


def post(i):
    t = time.perf_counter()
    r = requests.post(f"{BASE}/analyze", json={"text": f"{TEXT} {i}"}, timeout=120)
    return r.status_code, time.perf_counter() - t


out = {"rss_mb_before": rss_mb()}
time.sleep(65)
t = time.perf_counter(); seq = [post(i) for i in range(10)]; out["sequential_10_s"] = round(time.perf_counter() - t, 2)
time.sleep(65)
t = time.perf_counter()
with cf.ThreadPoolExecutor(10) as ex:
    con = list(ex.map(post, range(10, 20)))
out["concurrent_10_s"] = round(time.perf_counter() - t, 2)
out["statuses"] = sorted({s for s, _ in seq + con})
out["rss_mb_after"] = rss_mb()
time.sleep(65)
codes = [post(100 + i)[0] for i in range(22)]
out["rate_limit_codes_22_requests"] = codes
out["first_429_at_request"] = codes.index(429) + 1 if 429 in codes else None
json.dump(out, open("results/runtime_checks.json", "w"), indent=1)
print(json.dumps(out))
