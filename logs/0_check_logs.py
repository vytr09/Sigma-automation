import re
from collections import defaultdict

# File chứa log
log_file_path = "global_detection_log.txt"

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

        command = info["command"]

        # Điều kiện loại bỏ BYPASSED không hợp lệ
        if phase == "recoding" and command == "<recoding not applicable>":
            continue
        if phase == "substitution" and "#substitution" in command:
            continue
        if phase == "omission" and "# omission" in command:
            continue

        # Nếu hợp lệ
        bypassed_found = True
        break

    if bypassed_found:
        qualified_rules.append(rule)

# In kết quả
print("Các rule thỏa điều kiện:")
for rule in qualified_rules:
    print("-", rule)

print("\nTổng số rule thỏa điều kiện:", len(qualified_rules))
