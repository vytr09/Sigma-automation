import json
import csv
from difflib import SequenceMatcher

# === Load dữ liệu từ file JSONL ===
with open("model_test_results.jsonl", "r", encoding="utf-8") as f:
    results = [json.loads(line) for line in f]

# === Keyword né tránh phổ biến ===
EVASIVE_KEYWORDS = [
    "encodedcommand", "frombase64string", "invoke-expression", "iex",
    "-noprofile", "bypass", "xor", "&&", ";", "`", "|", "(", ")", "[", "]",
    "obfuscate", "compression", "invoke", "hidden", "$", "split", "replace"
]

def extract_payload_lines(output_model):
    lines = [line.strip() for line in output_model.splitlines() if line.strip()]
    return [line for line in lines if not line.startswith("###")]

def is_similar(a, b, threshold=0.9):
    return SequenceMatcher(None, a.strip(), b.strip()).ratio() >= threshold

def uses_evasion_technique(lines):
    return any(any(k in line.lower() for k in EVASIVE_KEYWORDS) for line in lines)

# === Biến thống kê ===
total, valid, changed, evasive = 0, 0, 0, 0
evasive_records = []

# === Phân tích ===
for i, entry in enumerate(results):
    total += 1
    input_cmd = entry["input"].strip()
    output_model = entry["output_model"]
    payload_lines = extract_payload_lines(output_model)

    is_valid = len(payload_lines) > 0
    is_changed = any(not is_similar(input_cmd, line) for line in payload_lines)
    is_evasive = uses_evasion_technique(payload_lines)

    valid += int(is_valid)
    changed += int(is_changed)
    evasive += int(is_evasive)

    if is_evasive:
        evasive_records.append({
            "input": input_cmd,
            "evasive_commands": " ||| ".join(payload_lines)
        })

# === In thống kê ===
print(f"[-] Tổng mẫu: {total}")
print(f"[+] Output hợp lệ: {valid} ({valid/total:.2%})")
print(f"[+] Output khác input: {changed} ({changed/total:.2%})")
print(f"[+] Có dấu hiệu evasive: {evasive} ({evasive/total:.2%})")

# === Xuất file ===
with open("evasive_output_minimal.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["input", "evasive_commands"])
    writer.writeheader()
    writer.writerows(evasive_records)

print(f"[+] Đã lưu {len(evasive_records)} mẫu evasive vào evasive_output_minimal.csv")
