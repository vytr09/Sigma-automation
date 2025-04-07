import os
import yaml

base_path = r"D:\UIT\Nam_3\DACN\Sigma-automation\data\events\windows\process_creation"
evasion_possible_rules = []

for folder_name in os.listdir(base_path):
    folder_path = os.path.join(base_path, folder_name)
    if os.path.isdir(folder_path):
        properties_file = os.path.join(folder_path, "properties.yml")
        if os.path.isfile(properties_file):
            with open(properties_file, 'r', encoding='utf-8') as f:
                try:
                    properties = yaml.safe_load(f)
                    evasion_val = properties.get("evasion_possible")
                    print(f"[DEBUG] {folder_name} - evasion_possible = {evasion_val}")
                    
                    if evasion_val in ("yes", "true", True):
                        evasion_possible_rules.append(folder_name)
                except yaml.YAMLError as e:
                    print(f"[ERROR] YAML lỗi trong {properties_file}: {e}")
                except Exception as e:
                    print(f"[ERROR] Lỗi đọc {properties_file}: {e}")

# Ghi ra file
output_file = os.path.join("evasion_possible_rules.txt")
with open(output_file, 'w', encoding='utf-8') as out_f:
    for rule in evasion_possible_rules:
        out_f.write(f"{rule}\n")

print(f"Đã xuất {len(evasion_possible_rules)} rule ra file: {output_file}")
