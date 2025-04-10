# File: run_attack_eval.py

import os
import json
import time
import datetime
import subprocess

# ========== Config ==========
EVASION_RESULTS_DIR = "attack_convert/Evasion-Results"
QUERY_DIR = "query_convert/sigma_to_splunk/output_queries"
LOG_DIR = "logs"
GLOBAL_LOG = os.path.join(LOG_DIR, "global_detection_log.txt")

# ========== Helper Functions ==========

def get_current_time_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()

def run_commandline(cmd: str):
    try:
        print(f"[RUNNING] {cmd}")
        subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"[ERROR] Failed to run: {cmd} → {e}")

def run_splunk_query(query: str, since: str) -> bool:
    constrained_query = f'{query} earliest="{since}"'
    try:
        result = subprocess.run(["splunk", "search", constrained_query], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "_time" in line:
                return True
        return False
    except Exception as e:
        print(f"[ERROR] Splunk query failed → {e}")
        return False

def load_query_for_rule(rule_name: str) -> str | None:
    query_path = os.path.join(QUERY_DIR, f"{rule_name}.spl")
    if not os.path.exists(query_path):
        print(f"[WARN] Query file not found for rule: {rule_name}")
        return None
    with open(query_path, "r", encoding="utf-8") as f:
        return f.read()

def log_detection(rule_name: str, phase: str, command: str, detected: bool):
    os.makedirs(LOG_DIR, exist_ok=True)
    status = "DETECTED" if detected else "BYPASSED"
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(GLOBAL_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {rule_name} [{phase}]: {status} → {command}\n")

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

    timestamp = get_current_time_iso()
    run_commandline(original_cmd)
    time.sleep(3)
    detected = run_splunk_query(query, timestamp)
    log_detection(rule_name, "original", original_cmd, detected)

    for evasion_type, evasion_cmd in evasions.items():
        timestamp = get_current_time_iso()
        run_commandline(evasion_cmd)
        time.sleep(3)
        detected = run_splunk_query(query, timestamp)
        log_detection(rule_name, evasion_type, evasion_cmd, detected)

def run_all_attacks():
    print("[*] Starting automated attack execution...\n")
    os.makedirs(LOG_DIR, exist_ok=True)
    open(GLOBAL_LOG, "w").close()

    for filename in os.listdir(EVASION_RESULTS_DIR):
        if filename.endswith(".json"):
            full_path = os.path.join(EVASION_RESULTS_DIR, filename)
            process_attack_file(full_path)

    print("\n[✔] Done. Logs saved to:", LOG_DIR)

# ========== Entry Point ==========
if __name__ == "__main__":
    run_all_attacks()
