import re
import json
import glob
import os

# Paths
log_path = "output/logs/global_detection_log_for_sigma.txt"
rules_dir = "data/rules-sigma/windows/process_creation/"
output_path = "fine-tune-sigma/dataset/codeLLamA_detected_commands_fullrule.jsonl"

# Regex to parse log lines
log_re = re.compile(r"\[.*?\] (\S+) \[(\w+)\]: DETECTED → (.+)")

# Read all rules into a dict
rule_contents = {}
for rule_file in glob.glob(os.path.join(rules_dir, "*.yml")):
    with open(rule_file, "r", encoding="utf-8") as f:
        rule_contents[os.path.basename(rule_file)] = f.read().strip()

# Process log and generate fine-tune data
with open(log_path, "r", encoding="utf-8") as log, open(output_path, "w", encoding="utf-8") as out:
    for line in log:
        m = log_re.match(line)
        if m:
            rule_name, phase, payload = m.groups()
            payload = payload.strip()
            
            # Find matching rule file
            rule_file = None
            for rfile in rule_contents:
                if rule_name.startswith(os.path.splitext(rfile)[0]):
                    rule_file = rfile
                    break
            
            if rule_file and rule_file in rule_contents:
                entry = {
                    "instruction": "Write Sigma rule to detect payload:",
                    "input": payload,
                    "output": rule_contents[rule_file]
                }
                out.write(json.dumps(entry, ensure_ascii=False) + "\n")