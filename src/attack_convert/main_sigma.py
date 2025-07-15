# attack_convert/main.py
import os
import yaml
import json
from pathlib import Path

# Get the project root directory
PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Paths
rules_dir = PROJECT_ROOT / "data" / "rules-sigma" / "windows" / "process_creation"
evasion_list_file = PROJECT_ROOT / "data" / "all_rule_names.txt"
output_dir = PROJECT_ROOT / "src" / "attack_convert" / "Evasion-Results"
output_dir.mkdir(parents=True, exist_ok=True)

# Import after setting up paths
from src.attack_convert.utils.parser import extract_first_command_line
from src.attack_convert.utils.evasions_core import generate_all_evasions

# Load evasion rule list
with open(evasion_list_file, "r", encoding="utf-8") as f:
    evasion_rules = set(line.strip().lower() for line in f if line.strip())

# Iterate through YAML rule files
for rule_file in rules_dir.glob("*.yml"):
    rule_name = rule_file.stem.lower()
    if rule_name not in evasion_rules:
        continue

    with open(rule_file, "r", encoding="utf-8") as f:
        rule_docs = list(yaml.safe_load_all(f))

    for idx, rule_data in enumerate(rule_docs):
        if not isinstance(rule_data, dict):
            continue

        rule_filter = rule_data.get("filter", "")
        if not rule_filter and "detection" in rule_data:
            detection = rule_data["detection"]
            fragments = []
            # Recursively search for relevant keys
            def extract_fragments(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if any(x in k.lower() for x in ["commandline|contains", "image|endswith", "originalfilename", "description|contains"]):
                            if isinstance(v, list):
                                fragments.extend(str(i) for i in v)
                            else:
                                fragments.append(str(v))
                        else:
                            extract_fragments(v)
                elif isinstance(obj, list):
                    for i in obj:
                        extract_fragments(i)
            extract_fragments(detection)
            # Build a pseudo-filter string for the parser
            rule_filter = " OR ".join(f'process.command_line: "{frag}"' for frag in fragments if frag)

        original_command = extract_first_command_line(rule_filter)
        evasions = generate_all_evasions(original_command)

        result = {
            "rule_name": f"{rule_file.stem.lower()}_{idx}",
            "original_command": original_command,
            "evasions": evasions
        }

        output_path = output_dir / f"{result['rule_name']}.json"
        with open(output_path, "w", encoding="utf-8") as out_f:
            json.dump(result, out_f, indent=2, ensure_ascii=False)
