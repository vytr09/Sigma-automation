# src/detection/run_detect_and_decode.py

import re
from src.detection.command_inspector import is_encoded_command, extract_encoded_payload
from src.detection.decoding import decode_base64_string, guess_encoding_type
from src.detection.llm_decoder import query_ollama_llm

VALID_RULES_PATH = "src/detection/valid_rules.txt"
LOG_PATH = "output/logs/global_detection_log.txt"


def load_valid_rules(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def extract_rule_and_command(line: str) -> tuple[str, str] | None:
    """
    Trích xuất rule name và command line từ một dòng log.
    """
    match = re.search(r"\] ([^\[\]:]+) \[.*\]: .*→ (.+)$", line)
    if match:
        rule_name = match.group(1).strip()
        command = match.group(2).strip()
        return rule_name, command
    return None


def main():
    valid_rules = load_valid_rules(VALID_RULES_PATH)

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines:
        result = extract_rule_and_command(line)
        if not result:
            continue

        rule_name, command = result

        if rule_name not in valid_rules:
            continue

        if is_encoded_command(command):
            print(f"[ENCODED DETECTED] Rule: {rule_name}")
            print(f"  Original: {command}")

            encoding = guess_encoding_type(command)
            b64_string = extract_encoded_payload(command)
            decoded = decode_base64_string(b64_string, encoding) if b64_string else None

            if decoded:
                print(f"  Decoded : {decoded}")
            else:
                print("  ⚠️  Base64 decode failed or payload not found. Trying LLM...")
                decoded_llm = query_ollama_llm(command)
                print(f"  🔍 LLM Out : {decoded_llm}")

            print("-" * 50)


if __name__ == "__main__":
    main()
