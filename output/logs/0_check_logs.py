import re
from collections import defaultdict

def is_valid_bypass(phase, command):
    """Check if a bypass is valid based on the command content."""
    # If command contains any of these markers, it's not a real bypass
    invalid_markers = [
        "#",  # Comment markers
        "#insertion",
        "#substitution",
        "# omission",
        "<recoding not applicable>",
        "<substitution not applicable>",
        "<omission not applicable>"
    ]
    
    # Check if command contains any invalid markers
    for marker in invalid_markers:
        if marker in command:
            return False
    
    return True

# File chứa log
log_file_path = "global_detection_log.txt"
# File xuất kết quả
output_file_path = "qualified_rules_output.txt"

# Regex để tách thông tin từ dòng log
pattern = re.compile(
    r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\] (\S+) \[(\w+)\]: (DETECTED|BYPASSED) → (.+)"
)

logs_by_rule = defaultdict(dict)

# Đọc file và phân tích log
with open(log_file_path, "r", encoding="utf-8") as f:
    for line in f:
        match = pattern.match(line)
        if match:
            rule_name, phase, status, command = match.groups()
            logs_by_rule[rule_name][phase] = {
                "status": status,
                "command": command.strip()
            }

qualified_rules = []

# Kiểm tra điều kiện từng rule
for rule, evasion_data in logs_by_rule.items():
    if "original" not in evasion_data:
        continue
    if evasion_data["original"]["status"] != "DETECTED":
        continue

    bypassed_found = False

    for phase, info in evasion_data.items():
        if phase == "original" or info["status"] != "BYPASSED":
            continue

        # Check if this is a valid bypass
        if is_valid_bypass(phase, info["command"]):
            bypassed_found = True
            break

    if bypassed_found:
        qualified_rules.append(rule)

# In kết quả ra màn hình và ghi vào file
with open(output_file_path, "w", encoding="utf-8") as out_file:
    print("Các rule thỏa điều kiện:")
    for rule in qualified_rules:
        rule_clean = rule.removesuffix('_0')  # Loại bỏ hậu tố _0
        out_file.write(f"{rule_clean}\n")
        print("-", rule_clean)

    print("\nTổng số rule thỏa điều kiện:", len(qualified_rules))
