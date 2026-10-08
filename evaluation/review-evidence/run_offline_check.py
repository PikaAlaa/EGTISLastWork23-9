"""R2: a full scan (text + URL, all three engines) with no network interface except loopback.
Run inside a new network namespace, connecting to PostgreSQL over its Unix socket:
  unshare -rn sh -c 'ip link set lo up 2>/dev/null; DATABASE_URL="postgresql://postgres:postgres@/etis?host=/tmp" python run_offline_check.py'
"""
import json, os, socket, logging, warnings
logging.disable(logging.CRITICAL); warnings.filterwarnings("ignore")
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.engines.risk_scoring import calculate_final_risk_score

try:
    socket.create_connection(("1.1.1.1", 443), timeout=3); internet = True
except OSError:
    internet = False
db = sessionmaker(bind=create_engine(os.environ["DATABASE_URL"]))()
r = calculate_final_risk_score(text="تم تحديث باقتك بنجاح", url="https://example.com/login", db=db)
out = {"internet_reachable": internet, "engines_applied": r["engines_applied"], "verdict": r["verdict"], "final_score": r["final_score"]}
json.dump(out, open("results/offline_check.json", "w"), indent=1)
print(out)
