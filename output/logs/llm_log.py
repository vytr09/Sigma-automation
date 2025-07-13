import os
import yaml
import json
import re
from collections import defaultdict
from src.attack_convert.utils.evasions_core import generate_all_evasions

# --- Step 1: Load các log_id hợp lệ ---
# Mở file chứa các ID log hợp lệ và lưu chúng vào một set để dễ dàng kiểm tra.
with open("output/logs/qualified_rules_output.txt", "r", encoding="utf-8") as f:
    qualified_ids = set(line.strip() for line in f if line.strip())

# --- Step 1.1: Load danh sách rule_id cho phép recoding ---
# Mở file chứa các ID rule cho phép recoding và lưu vào một set.
with open("output/logs/recode.txt", "r", encoding="utf-8") as f:
    allowed_recoding_ids = set(line.strip() for line in f if line.strip())

# --- Step 2: Load logs từ file log detection ban đầu ---
# Mở file log detection gốc.
with open("output/logs/global_detection_log.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Định nghĩa regex pattern để phân tích cú pháp mỗi dòng log.
pattern = re.compile(r"\[(.*?)\] (.*?) \[(.*?)\]: (DETECTED|BYPASSED) → (.+)")

# Sử dụng defaultdict để nhóm các log theo ID cơ sở.
logs_by_id = defaultdict(dict)

# Duyệt qua từng dòng trong log file để trích xuất thông tin.
for line in lines:
    match = pattern.match(line.strip())
    if not match:
        continue

    # Trích xuất các nhóm từ regex match.
    _, log_id, technique, status, payload = match.groups()
    log_id_base = "_".join(log_id.split("_")[:-1])

    # Bỏ qua các log không có trong danh sách ID hợp lệ.
    if log_id_base not in qualified_ids:
        continue

    # Bỏ qua các payload chứa '#' nếu không phải là technique "original"
    if technique != "original" and "#" in payload:
        continue

    # Làm sạch payload: loại bỏ mọi thứ sau ký tự '#' đầu tiên.
    payload_cleaned = payload.strip().split("#")[0].strip()

    # Lưu trữ thông tin log vào dictionary.
    logs_by_id[log_id_base][technique] = {
        "status": status,
        "payload": payload_cleaned,
        "base_id": log_id_base,
        "full_id": log_id
    }

# --- Step 3: Tạo sample từ log detection ban đầu ---
samples = []
# Duyệt qua các log đã nhóm để tạo các mẫu huấn luyện.
for log_id_base, variants in logs_by_id.items():
    original = variants.get("original")
    # Chỉ xử lý nếu có biến thể "original" và nó bị "DETECTED".
    if not original or original["status"] != "DETECTED":
        continue

    input_payload = original["payload"]

    # Duyệt qua các biến thể (technique khác ngoài "original").
    for tech, info in variants.items():
        if tech == "original":
            continue

        # Chỉ lấy các biến thể đã "BYPASSED" (né tránh thành công).
        if info["status"] != "BYPASSED":
            continue
        
        # Đảm bảo payload của biến thể đã BYPASSED không chứa '#'
        if "#" in info["payload"]:
            continue

        # Nếu technique là "recoding", kiểm tra xem full_id có trong danh sách cho phép recoding không.
        if tech == "recoding" and info["full_id"] not in allowed_recoding_ids:
            continue

        output_payload = info["payload"]
        # Thêm mẫu vào danh sách với định dạng input đã được đơn giản hóa.
        samples.append({
            "instruction": "Modify the following attack command to evade detection.",
            "input": input_payload, # <-- THAY ĐỔI Ở ĐÂY
            "output": output_payload
        })

# --- Step 4: Trích xuất từ LOLBAS ---
lolbas_dir = "output/logs/LOLBAS-yml"
# Duyệt qua các file YAML trong thư mục LOLBAS.
for root, _, files in os.walk(lolbas_dir):
    for file in files:
        if not file.endswith(".yml"):
            continue

        with open(os.path.join(root, file), "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
                
                # Duyệt qua các lệnh trong mỗi entry LOLBAS.
                for cmd_entry in data.get("Commands", []):
                    cmd = cmd_entry.get("Command")
                    if not cmd:
                        continue

                    # Tạo tất cả các biến thể né tránh cho lệnh.
                    evasions = generate_all_evasions(cmd)
                    for tech, evasive_cmd in evasions.items():
                        # Làm sạch evasive_cmd
                        cleaned_evasive_cmd = evasive_cmd.strip().split("#")[0].strip()

                        # Chỉ thêm vào samples nếu lệnh đã làm sạch không rỗng.
                        if cleaned_evasive_cmd:
                            samples.append({
                                "instruction": "Modify the following attack command to evade detection.",
                                "input": cmd, # <-- THAY ĐỔI Ở ĐÂY
                                "output": cleaned_evasive_cmd
                            })
            except Exception as e:
                print(f"⚠️ Error in LOLBAS file {file}: {e}")

# --- Step 5: Trích xuất từ Atomic Red Team ---
atomic_dir = "output/logs/atomic-red-team/atomics"
# Duyệt qua các thư mục technique trong Atomic Red Team.
for technique in os.listdir(atomic_dir):
    tech_path = os.path.join(atomic_dir, technique)
    if not os.path.isdir(tech_path):
        continue

    yaml_file = os.path.join(tech_path, f"{technique}.yaml")
    if not os.path.isfile(yaml_file):
        continue

    try:
        with open(yaml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            tests = data.get("atomic_tests", [])
            # Duyệt qua các bài kiểm tra atomic.
            for idx, test in enumerate(tests):
                executor = test.get("executor", {})
                cmd = executor.get("command")
                if not cmd or len(cmd.strip()) < 4:
                    continue

                # Tạo tất cả các biến thể né tránh cho lệnh.
                evasions = generate_all_evasions(cmd)
                for tech, evasive_cmd in evasions.items():
                    # Làm sạch evasive_cmd
                    cleaned_evasive_cmd = evasive_cmd.strip().split("#")[0].strip()

                    # Chỉ thêm vào samples nếu lệnh đã làm sạch không rỗng.
                    if cleaned_evasive_cmd:
                        samples.append({
                            "instruction": "Modify the following attack command to evade detection.",
                            "input": cmd, # <-- THAY ĐỔI Ở ĐÂY
                            "output": cleaned_evasive_cmd
                        })
    except Exception as e:
        print(f"⚠️ Error in Atomic file {technique}.yaml: {e}")

# --- Bước 6: Loại bỏ các mẫu trùng lặp và ghi ra file tổng hợp ---
unique_samples = []
seen_samples_json = set() # Sử dụng set để lưu trữ chuỗi JSON của các mẫu đã thấy

if samples:
    for item in samples:
        # Chuyển đổi dict thành chuỗi JSON để có thể hash và thêm vào set.
        item_json = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if item_json not in seen_samples_json:
            seen_samples_json.add(item_json)
            unique_samples.append(item)

    with open("output/logs/finetune_bypass_output.jsonl", "w", encoding="utf-8") as f:
        for item in unique_samples:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"✅ Đã tạo {len(unique_samples)} mẫu tổng hợp duy nhất từ log, LOLBAS và Atomic Red Team.")
else:
    print("⚠️ Không có mẫu nào được tạo.")