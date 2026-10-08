"""Re-apply the pass rules in cases.py to results/api_cases.json and write results/SUMMARY.md."""
import json
from cases import API_CASES, ROBUSTNESS

a = json.load(open("results/api_cases.json"))
accept = {c[0]: c[3] for c in API_CASES} | {c[0]: c[3] for c in ROBUSTNESS}
for c in a["cases"] + a["robustness"]:
    acc = accept[c["id"]]
    c["accept"] = sorted(map(str, acc))
    c["pass"] = (c.get("verdict") if c["http_status"] == 200 else c["http_status"]) in acc
for c in a["everyday_sms"]:
    c["pass"] = c.get("verdict") == "LOW"
json.dump(a, open("results/api_cases.json", "w"), ensure_ascii=False, indent=1)

d = json.load(open("results/direct_checks.json"))
ds = json.load(open("results/dataset_checks.json"))
m = json.load(open("results/model_comparison.json"))
rt = json.load(open("results/runtime_checks.json"))
st = json.load(open("results/startup_checks.json"))
off = json.load(open("results/offline_check.json"))

L = ["# Evidence summary", "", f"Blacklisted URL used: `{a['meta']['blacklisted_url_used']}`", "",
     "## API cases", "", "| ID | Case | HTTP | Verdict | Score | Engine scores | Pass |", "| --- | --- | --- | --- | --- | --- | --- |"]
for c in a["cases"] + a["robustness"]:
    L.append(f"| {c['id']} | {c['description']} | {c['http_status']} | {c.get('verdict', '')} | {c.get('final_score', '')} | "
             f"{c.get('engine_scores', '')} | {'yes' if c['pass'] else 'no'} (accept {', '.join(c['accept'])}) |")
sms = a["everyday_sms"]
L += ["", f"Everyday SMS (E14): {sum(c['verdict'] == 'HIGH' for c in sms)} HIGH, {sum(c['verdict'] == 'MEDIUM' for c in sms)} MEDIUM, "
      f"{sum(c['verdict'] == 'LOW' for c in sms)} LOW of {len(sms)}", "",
      "## Direct and controlled", "", f"D1 parsing: {d['D1_parsing']}", ""]
for x in d["D3_controlled"]:
    L.append(f"- D3: input url={x['input']['url']}, fixed={x['fixed']}, engines={x['engine_scores']} -> {x['verdict']} {x['final_score']}")
L += ["", f"D6-D8 brand checker: {d['D6_D8_brand_checker']}", f"Boundaries: {d['boundaries']}",
      f"E10 example: {d['E10_confidence_example']}",
      "E9 committed report, wrong verdicts marked OK: " + str([x for x in d['E9_acceptance_report'] if not x['verdict_matches']]), ""]
for p in d["model_pairs"]:
    L.append(f"- Model pair {p['pair']}: with money wording {p['with_money_wording']['lstm']}, without {p['without']['lstm']}")
L += ["", "## Dataset", "", "```", json.dumps({k: v for k, v in ds.items() if k != "E12_egyptian"}, ensure_ascii=False, indent=1),
      json.dumps({k: v for k, v in ds["E12_egyptian"].items() if k != "strict_matches"}, ensure_ascii=False), "```", "",
      "## Models", "", "```", json.dumps(m, indent=1), "```", "", "## Runtime", "", "```", json.dumps(rt), json.dumps(st), json.dumps(off), "```"]
open("results/SUMMARY.md", "w").write("\n".join(L))
print("\n".join(L[:50]))
