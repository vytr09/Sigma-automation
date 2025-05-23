# File: run_attack_eval.py

import os
import json
import time
import shlex
import subprocess
import re
from typing import Optional
from datetime import datetime, timedelta

# ========== Config ==========
EVASION_RESULTS_DIR = os.path.join("src", "attack_convert", "Evasion-Results")
QUERY_DIR = os.path.join("src", "query_convert", "sigma_to_splunk","output_queries")
LOG_DIR = os.path.join("output", "logs")
GLOBAL_LOG = os.path.join(LOG_DIR, "global_detection_log.txt")

# ========== Helper Functions ==========
def load_target_rules(path=os.path.join("data", "evasion_possible_rules.txt")) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Failed to read evasion_possible_rules.txt → {e}")
        return []


def get_current_time_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat()

def run_commandline(cmd: str):
    try:
        # Nếu là lệnh đơn giản, thêm `& exit` để tránh block
        if "cmd.exe" in cmd.lower() or "powershell" in cmd.lower():
            if "exit" not in cmd.lower():
                cmd += " & exit"
        
        # Nếu là một executable không có tham số (ví dụ: "notepad"), thêm timeout
        tokens = shlex.split(cmd)
        if len(tokens) == 1:
            # ví dụ: notepad → không tham số → likely mở GUI
            cmd = f"start /B {cmd} & timeout /t 5 & taskkill /im {tokens[0]} /f"

        print(f"[RUNNING] {cmd}")
        subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE)

    except Exception as e:
        print(f"[ERROR] Failed to run: {cmd} → {e}")

def run_splunk_query(query: str, since: str, expected_cmd: str) -> bool:
    since_dt = datetime.fromisoformat(since)
    latest_dt = since_dt + timedelta(seconds=15)
    earliest_str = since_dt.strftime("%Y-%m-%dT%H:%M:%S")
    latest_str = latest_dt.strftime("%Y-%m-%dT%H:%M:%S")
    constrained_query = f'{query} earliest="{earliest_str}" latest="{latest_str}"'
    full_query = f'"{constrained_query}"'  # escape toàn bộ truy vấn

    # def is_payload_in_output(payload: str, stdout: str) -> bool:
    #     payload_parts = re.findall(r'[\w.=/-]+', payload.lower())
    #     for line in stdout.splitlines():
    #         line = line.lower()
    #         if all(part in line for part in payload_parts):
    #             return True
    #     return False

    try:
        result = subprocess.run([
            "C:\\Program Files\\Splunk\\bin\\splunk", "search",
            full_query, "-auth", "vy:22521709"
        ], capture_output=True, text=True)

        print("[DEBUG SPLUNK OUTPUT]")
        print(result.stdout)
        print(result.stderr)

        # Normalize command for loose comparison
        expected_parts = re.findall(r'[\w.]+', expected_cmd.lower())  # ['cmdkey.exe', 'list']

        for line in result.stdout.splitlines():
            if "Command Line" in line or "Process_Command_Line" in line or "New_Process_Name" in line:
                lowered = line.lower()
                if all(part in lowered for part in expected_parts):
                    return True
        return False
        # return is_payload_in_output(expected_cmd, result.stdout)

    except Exception as e:
        print(f"[ERROR] Splunk query failed → {e}")
        return False

def load_query_for_rule(rule_name: str) -> Optional[str]:
    base_name = rule_name.rsplit("_", 1)[0]  # remove _0 or similar suffix
    query_path = os.path.join(QUERY_DIR, f"{base_name}.spl")
    if not os.path.exists(query_path):
        print(f"[WARN] Query file not found for rule: {rule_name} → tried: {base_name}.spl")
        return None
    with open(query_path, "r", encoding="utf-8") as f:
        return f.read()

def log_detection(rule_name: str, phase: str, command: str, detected: bool):
    os.makedirs(LOG_DIR, exist_ok=True)
    status = "DETECTED" if detected else "BYPASSED"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Ghi log toàn cục
    with open(GLOBAL_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {rule_name} [{phase}]: {status} → {command}\n")

    # Ghi log chi tiết theo rule
    rule_log_path = os.path.join(LOG_DIR, f"{rule_name}_detection_log.jsonl")
    log_entry = {
        "timestamp": timestamp,
        "rule": rule_name,
        "phase": phase,
        "command": command,
        "status": status
    }
    with open(rule_log_path, "a", encoding="utf-8") as f:
        json.dump(log_entry, f)
        f.write("\n")

# ========== Main Execution ==========

def process_attack_file(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rule_name = data.get("rule_name")
    original_cmd = data.get("original_command")
    evasions = data.get("evasions", {})

    if not rule_name or not original_cmd:
        print(f"[SKIP] Invalid file: {file_path}")
        return

    query = load_query_for_rule(rule_name)
    if not query:
        return
    print(f"\n==== Processing Rule: {rule_name} ====")

    # --- Original Attack ---
    timestamp = get_current_time_iso()
    run_commandline(original_cmd)
    time.sleep(3)
    detected = run_splunk_query(query, timestamp, original_cmd)  # ← sửa ở đây
    log_detection(rule_name, "original", original_cmd, detected)

    # --- Evasion Attempts ---
    for evasion_type, evasion_cmd in evasions.items():
        timestamp = get_current_time_iso()
        run_commandline(evasion_cmd)
        time.sleep(3)
        detected = run_splunk_query(query, timestamp, evasion_cmd)  # ← sửa ở đây
        log_detection(rule_name, evasion_type, evasion_cmd, detected)

def run_all_attacks():
    print("[*] Starting automated attack execution...\n")
    os.makedirs(LOG_DIR, exist_ok=True)
    open(GLOBAL_LOG, "w").close()  # Clear global log

    target_rules = set(load_target_rules())

    for filename in os.listdir(EVASION_RESULTS_DIR):
        if filename.endswith(".json"):
            base_name = os.path.splitext(filename)[0].rsplit("_", 1)[0]
            if base_name in target_rules:
                full_path = os.path.join(EVASION_RESULTS_DIR, filename)
                process_attack_file(full_path)

    print("\n[✔] Done. Logs saved to:", LOG_DIR)


# ========== Entry Point ==========
if __name__ == "__main__":
    run_all_attacks()