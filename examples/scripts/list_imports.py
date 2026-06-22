import json
import os

report_path = os.environ["FYIDA_REPORT_JSON"]
with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)

imports = report["analysis"]["imports"]
print(f"{report['input']['path']}: {len(imports)} imports")
for item in imports[:16]:
    print(item["display_name"])
