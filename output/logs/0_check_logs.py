import re
from collections import defaultdict
import os

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

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# File paths relative to the script directory
log_file_path = os.path.join(SCRIPT_DIR, "global_detection_log.txt")
output_file_path = os.path.join(SCRIPT_DIR, "qualified_rules_output.txt")
evasion_stats_file = os.path.join(SCRIPT_DIR, "evasion_effectiveness.txt")
failed_rules_file = os.path.join(SCRIPT_DIR, "failed_rules.txt")

# Regex để tách thông tin từ dòng log
pattern = re.compile(
    r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\] (\S+) \[(\w+)\]: (DETECTED|BYPASSED) → (.+)"
)

logs_by_rule = defaultdict(dict)
evasion_stats = defaultdict(lambda: {
    'total_attempts': 0,
    'valid_bypasses': 0,
    'affected_rules': set()
})

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
failed_rules = []  # Rules that were bypassed by original command
all_evasion_phases = set()

# First pass: collect all possible evasion phases
for rule, evasion_data in logs_by_rule.items():
    for phase in evasion_data:
        if phase != "original":
            all_evasion_phases.add(phase)

# Kiểm tra điều kiện từng rule và cập nhật thống kê evasion
for rule, evasion_data in logs_by_rule.items():
    if "original" not in evasion_data:
        continue
        
    # Check if original command was bypassed
    if evasion_data["original"]["status"] == "BYPASSED":
        failed_rules.append(rule)
        continue
        
    if evasion_data["original"]["status"] != "DETECTED":
        continue

    bypassed_found = False
    valid_bypass_phases = set()

    for phase, info in evasion_data.items():
        if phase == "original" or info["status"] != "BYPASSED":
            continue

        # Check if this is a valid bypass
        if is_valid_bypass(phase, info["command"]):
            bypassed_found = True
            valid_bypass_phases.add(phase)

    if bypassed_found:
        qualified_rules.append(rule)
        # Update evasion statistics only for valid rules
        for phase in valid_bypass_phases:
            evasion_stats[phase]['valid_bypasses'] += 1
            evasion_stats[phase]['affected_rules'].add(rule)
        
        # Update total attempts for all possible evasion phases
        for phase in all_evasion_phases:
            evasion_stats[phase]['total_attempts'] += 1

# In kết quả ra màn hình và ghi vào file
with open(output_file_path, "w", encoding="utf-8") as out_file:
    print("Các rule thỏa điều kiện:")
    for rule in qualified_rules:
        rule_clean = rule.removesuffix('_0')  # Loại bỏ hậu tố _0
        out_file.write(f"{rule_clean}\n")
        print("-", rule_clean)

    print("\nTổng số rule thỏa điều kiện:", len(qualified_rules))

# Ghi danh sách các rule bị bypass bởi lệnh gốc
with open(failed_rules_file, "w", encoding="utf-8") as failed_file:
    failed_file.write("=== Danh sách các rule bị bypass bởi lệnh gốc ===\n\n")
    for rule in sorted(failed_rules):
        rule_clean = rule.removesuffix('_0')
        failed_file.write(f"{rule_clean}\n")
    failed_file.write(f"\nTổng số rule bị bypass: {len(failed_rules)}")

print(f"\nDanh sách các rule bị bypass đã được lưu vào file: {failed_rules_file}")

# Ghi thống kê hiệu quả của các evasion
with open(evasion_stats_file, "w", encoding="utf-8") as stats_file:
    stats_file.write("=== Thống kê hiệu quả của các kỹ thuật evasion ===\n\n")
    
    # Sắp xếp evasion theo tỷ lệ bypass thành công
    sorted_evasions = sorted(
        evasion_stats.items(),
        key=lambda x: (x[1]['valid_bypasses'] / x[1]['total_attempts'] if x[1]['total_attempts'] > 0 else 0),
        reverse=True
    )
    
    for evasion_type, stats in sorted_evasions:
        success_rate = (stats['valid_bypasses'] / stats['total_attempts'] * 100) if stats['total_attempts'] > 0 else 0
        stats_file.write(f"Evasion Type: {evasion_type}\n")
        stats_file.write(f"Tổng số lần thử: {stats['total_attempts']}\n")
        stats_file.write(f"Số lần bypass thành công: {stats['valid_bypasses']}\n")
        stats_file.write(f"Tỷ lệ thành công: {success_rate:.2f}%\n")
        stats_file.write(f"Số rule bị ảnh hưởng: {len(stats['affected_rules'])}\n")
        stats_file.write("Các rule bị ảnh hưởng:\n")
        for rule in sorted(stats['affected_rules']):
            stats_file.write(f"  - {rule}\n")
        stats_file.write("\n")

print(f"\nThống kê evasion đã được lưu vào file: {evasion_stats_file}")
