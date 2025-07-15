# File: run_attack_eval.py

import os
import json
import time
import subprocess
import re
from typing import Optional
from datetime import datetime, timedelta

# ========== Config ==========
EVASION_RESULTS_DIR = os.path.join("src", "attack_convert", "Evasion-Results")
QUERY_DIR = os.path.join("src", "query_convert", "sigma_to_splunk","output_queries")
LOG_DIR = os.path.join("output", "logs")
GLOBAL_LOG = os.path.join(LOG_DIR, "global_detection_log_for_sigma.txt")
COMMAND_TIMEOUT = 2  # Reduced timeout for commands

# ========== Helper Functions ==========
# def load_target_rules(path=os.path.join("data", "evasion_possible_rules.txt")) -> list[str]:
def load_target_rules(path=os.path.join("data", "all_rule_names.txt")) -> list[str]:
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
        # Convert command to PowerShell format
        if "cmd.exe" in cmd.lower() or "powershell" in cmd.lower():
            # If it's already a PowerShell command, use it directly
            ps_cmd = cmd
        else:
            # For other commands, wrap them in PowerShell
            # Escape quotes and special characters
            escaped_cmd = cmd.replace('"', '`"')
            ps_cmd = f'powershell.exe -Command "{escaped_cmd}"'

        print(f"[RUNNING] {ps_cmd}")
        
        # Use PowerShell to execute the command
        subprocess.Popen(
            ps_cmd,
            shell=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:
        print(f"[ERROR] Failed to run: {cmd} → {e}")

def run_splunk_query(query: str, since: str, expected_cmd: str) -> bool:
    since_dt = datetime.fromisoformat(since)
    latest_dt = since_dt + timedelta(seconds=15)
    earliest_str = since_dt.strftime("%Y-%m-%dT%H:%M:%S")
    latest_str = latest_dt.strftime("%Y-%m-%dT%H:%M:%S")
    constrained_query = f'{query} earliest="{earliest_str}" latest="{latest_str}"'
    full_query = f'"{constrained_query}"'  # escape toàn bộ truy vấn

    try:
        result = subprocess.run([
            "C:\\Program Files\\Splunk\\bin\\splunk", "search",
            full_query, "-auth", "Tuyen:Tuyen1630@"
        ], capture_output=True, text=True)

        # print("\n[DEBUG SPLUNK OUTPUT]")
        # print("Query:", full_query)
        print("Expected command:", expected_cmd)
        print("Output:", result.stdout)
        if result.stderr:
            print("Error:", result.stderr)

        # Check if query returned any results
        if not result.stdout.strip():
            print("[DEBUG] No results returned from Splunk")
            return False

        # Normalize command for loose comparison
        expected_parts = re.findall(r'[\w.]+', expected_cmd.lower())
        found_match = False

        for line in result.stdout.splitlines():
            if "Command Line" in line or "Process_Command_Line" in line or "New_Process_Name" in line:
                lowered = line.lower()
                if all(part in lowered for part in expected_parts):
                    found_match = True
                    print(f"[DEBUG] Found matching line: {line}")
                    break

        if not found_match:
            print("[DEBUG] No matching command found in results")
            return False

        return True

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
    print(f"Original command: {original_cmd}")

    # --- Original Attack ---
    timestamp = get_current_time_iso()
    run_commandline(original_cmd)
    time.sleep(COMMAND_TIMEOUT)
    detected = run_splunk_query(query, timestamp, original_cmd)
    log_detection(rule_name, "original", original_cmd, detected)

    # --- Evasion Attempts ---
    if detected:
        # Only run evasions if original command was detected
        for evasion_type, evasion_cmd in evasions.items():
            print(f"\nTrying evasion: {evasion_type}")
            print(f"Command: {evasion_cmd}")
            timestamp = get_current_time_iso()
            run_commandline(evasion_cmd)
            time.sleep(COMMAND_TIMEOUT)
            detected = run_splunk_query(query, timestamp, evasion_cmd)
            log_detection(rule_name, evasion_type, evasion_cmd, detected)
    else:
        # If original command bypassed, log all evasions as bypassed without running them
        print(f"[SKIP] Original command bypassed detection, skipping evasion attempts for {rule_name}")
        for evasion_type, evasion_cmd in evasions.items():
            log_detection(rule_name, evasion_type, evasion_cmd, False)

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