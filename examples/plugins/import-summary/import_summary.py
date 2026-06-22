import json
import os

with open(os.environ["FYIDA_REPORT_JSON"], "r", encoding="utf-8") as handle:
    report = json.load(handle)

print("Import Summary")
for item in report["analysis"]["imports"][:10]:
    print(f"- {item['display_name']}")
