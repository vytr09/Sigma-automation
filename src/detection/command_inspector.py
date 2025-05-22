# src/detection/command_inspector.py

import re

def is_encoded_command(command_line: str) -> bool:
    """
    Kiểm tra xem dòng lệnh có đang dùng kỹ thuật mã hóa (recoding) hay không.
    """
    # Dấu hiệu 1: PowerShell -EncodedCommand
    if re.search(r'(?i)-EncodedCommand\s+[a-zA-Z0-9+/=]+', command_line):
        return True

    # Dấu hiệu 2: FromBase64String() trong PowerShell
    if re.search(r'(?i)FromBase64String\s*\(\s*["\']?[a-zA-Z0-9+/=]{10,}["\']?\s*\)', command_line):
        return True

    # Dấu hiệu 3: Kết hợp Invoke-Expression + decode
    if ("Invoke-Expression" in command_line or "iex" in command_line):
        if "FromBase64String" in command_line or "GetString" in command_line:
            return True

    return False


def extract_encoded_payload(command_line: str) -> str | None:
    """
    Cố gắng trích xuất payload được mã hóa từ command line.
    """
    # Dạng: -EncodedCommand <base64>
    match = re.search(r'(?i)-EncodedCommand\s+([a-zA-Z0-9+/=]+)', command_line)
    if match:
        return match.group(1)

    # Dạng FromBase64String('base64...')
    match = re.search(r'FromBase64String\s*\(\s*[\'"]?([a-zA-Z0-9+/=]{10,})[\'"]?\s*\)', command_line)
    if match:
        return match.group(1)

    return None
