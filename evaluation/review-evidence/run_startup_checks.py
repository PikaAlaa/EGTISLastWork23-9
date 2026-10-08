"""Start the backend from cold, then measure start-up time, idle memory, first and warm scan latency.
Usage: python run_startup_checks.py   (needs ETIS_REPO, DATABASE_URL; stops any server it starts)
"""
import json, os, subprocess, sys, time
import requests

REPO = os.environ.get("ETIS_REPO", "/home/claude/etis-group")
cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"]


def rss(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS"):
            return round(int(line.split()[1]) / 1024)


def up():
    try:
        requests.get("http://127.0.0.1:8000/docs", timeout=1); return True
    except Exception:
        return False


out = {}
for run in ("first_start", "second_start"):
    t = time.perf_counter()
    p = subprocess.Popen(cmd, cwd=f"{REPO}/backend", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while not up():
        time.sleep(0.2)
    r = {"startup_s": round(time.perf_counter() - t, 1), "idle_rss_mb": rss(p.pid)}
    t = time.perf_counter(); requests.post("http://127.0.0.1:8000/analyze", json={"text": "تم تحديث باقتك بنجاح"}); r["first_text_scan_s"] = round(time.perf_counter() - t, 2)
    lat = []
    for i in range(5):
        t = time.perf_counter(); requests.post("http://127.0.0.1:8000/analyze", json={"text": f"تم تحديث باقتك بنجاح {i}"}); lat.append(time.perf_counter() - t)
    r["warm_text_scan_s_median"] = round(sorted(lat)[2], 3)
    lat = []
    for i in range(5):
        t = time.perf_counter(); requests.post("http://127.0.0.1:8000/analyze", json={"url": f"https://example.com/{i}"}); lat.append(time.perf_counter() - t)
    r["warm_url_scan_s_median"] = round(sorted(lat)[2], 3)
    r["rss_after_scans_mb"] = rss(p.pid)
    out[run] = r
    p.terminate(); p.wait()
    time.sleep(65)  # reset the rate-limit window for the next run
out["note"] = "first_start may include cold disk cache; second_start is the warm start-up figure."
json.dump(out, open("results/startup_checks.json", "w"), indent=1)
print(json.dumps(out, indent=1))
