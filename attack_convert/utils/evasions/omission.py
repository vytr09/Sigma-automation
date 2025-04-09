import re

def evasive_omission(command: str) -> str:
    """
    Perform omission evasion by removing elements that are often matched by Sigma rules,
    such as `.exe`, optional switches, or partial paths.
    """
    if not command:
        return None

    original = command

    # Step 1: Remove `.exe` from executables (e.g., cscript.exe -> cscript)
    command = re.sub(r'\b(\w+)\.exe\b', r'\1', command)

    # Step 2: Remove common shell prefixes like `/c`, `-Command`, etc.
    command = re.sub(r'\s+(/c|-Command|--command)\b', '', command, flags=re.IGNORECASE)

    # Step 3: Remove redundant path segments (e.g., .\ or full path to script)
    command = re.sub(r'\.?\\?AppData\\Roaming\\', '', command, flags=re.IGNORECASE)
    command = re.sub(r'c:\\users\\[^\\]+\\', '', command, flags=re.IGNORECASE)

    # Step 4: Normalize spacing
    command = re.sub(r'\s+', ' ', command).strip()

    return command if command != original else command + " # omission"
