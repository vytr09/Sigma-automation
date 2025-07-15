import os
import yaml
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rules_dir = os.path.join(BASE_DIR, "data", "rules-sigma", "windows", "process_creation")
output_dir = os.path.join(BASE_DIR, "src", "query_convert", "sigma_to_splunk", "output_queries")

os.makedirs(output_dir, exist_ok=True)

# Updated field mappings based on Sigma rules
field_mappings = {
    # Process info
    "Image": "New_Process_Name",
    "CommandLine": "Process_Command_Line",
    "CurrentDirectory": "Current_Directory",
    "IntegrityLevel": "Process_Integrity_Level",
    "CreationUtcTime": "Process_Creation_Time",
    "ProcessId": "Process_ID",

    # Parent process
    "ParentImage": "Parent_Process_Name",
    "ParentCommandLine": "Parent_Process_Command_Line",
    "ParentProcessId": "Parent_Process_ID",
    "ParentCreationUtcTime": "Parent_Process_Creation_Time",
    "ParentIntegrityLevel": "Parent_Process_Integrity_Level",
    "ParentCurrentDirectory": "Parent_Current_Directory",

    # User info
    "User|sid": "SubjectUserSid",
    "User|name": "SubjectUserName",
    "User|domain": "SubjectDomainName",

    # PE Metadata
    "OriginalFileName": "Original_File_Name",

    # Hashes
    "Hash|md5": "Hash_MD5",
    "Hash|sha1": "Hash_SHA1",
    "Hash|sha256": "Hash_SHA256"
}

def map_field(field_expr, value):
    if "|" in field_expr:
        field, op = field_expr.split("|", 1)
    else:
        field, op = field_expr, "equals"

    field_mapped = field_mappings.get(field_expr, field_mappings.get(field, field))

    if op == "equals":
        return f'{field_mapped}="{value}"'
    elif op == "contains":
        return f'{field_mapped}="*{value}*"'
    elif op == "startswith":
        return f'{field_mapped}="{value}*"'
    elif op == "endswith":
        return f'{field_mapped}="*{value}"'
    elif op == "in" and isinstance(value, list):
        quoted_values = ', '.join([f'"{v}"' for v in value])
        return f'{field_mapped} IN ({quoted_values})'
    else:
        return f'{field_mapped}="{value}"'  # fallback

def convert_detection_to_splunk(detection_dict):
    condition = detection_dict.get("condition", "")
    selections = {k: v for k, v in detection_dict.items() if k != "condition"}
    all_clauses = []

    for sel_key, sel_body in selections.items():
        if isinstance(sel_body, list):
            sub_clauses = []
            for entry in sel_body:
                if isinstance(entry, dict):
                    sub_entry = [map_field(k, v) for k, v in entry.items()]
                    sub_clauses.append(" AND ".join(sub_entry))
            if sub_clauses:
                all_clauses.append(f"({' OR '.join(sub_clauses)})")

        elif isinstance(sel_body, dict):
            sub_clauses = []
            for field, value in sel_body.items():
                if isinstance(value, list):
                    or_clauses = [map_field(field, v) for v in value]
                    sub_clauses.append(f"({' OR '.join(or_clauses)})")
                else:
                    sub_clauses.append(map_field(field, value))
            all_clauses.append(f"({' AND '.join(sub_clauses)})")

    if "all of" in condition:
        return " | search " + " | search ".join(all_clauses)
    elif "1 of" in condition or "any of" in condition:
        return " | search " + " OR ".join(all_clauses)
    else:
        return " | search " + " | search ".join(all_clauses)  # fallback

# Main conversion logic
for filename in os.listdir(rules_dir):
    if not filename.endswith('.yml'):
        continue

    rule_file_path = os.path.join(rules_dir, filename)
    rule_folder = filename[:-4]

    with open(rule_file_path, 'r', encoding='utf-8') as f:
        try:
            docs = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"[!] Lỗi đọc rule YAML: {rule_file_path}: {e}")
            continue

    converted = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        detection = doc.get("detection")
        if not detection:
            continue

        converted_filter = convert_detection_to_splunk(detection)
        full_query = (
            'index=* sourcetype="WinEventLog:Security" EventCode=4688\n'
            f'{converted_filter}\n'
            '| table _time, New_Process_Name, Process_Command_Line'
        )

        output_path = os.path.join(output_dir, rule_folder + '.spl')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_query)

        print(f"[✓] Đã convert: {rule_file_path} → {rule_folder}.spl")
        converted = True
        break

    if not converted:
        print(f"[!] Không tìm thấy detection hợp lệ trong: {rule_file_path}")