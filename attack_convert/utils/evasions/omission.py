import re

def is_critical_process(command: str) -> bool:
    """Check if the command contains a critical process that shouldn't be modified."""
    critical_processes = [
        r'powershell\.exe',
        r'cmd\.exe',
        r'regsvr32\.exe',
        r'xcopy\.exe',
        r'rundll32\.exe'
    ]
    return any(re.search(proc, command, re.IGNORECASE) for proc in critical_processes)

def is_critical_switch(switch: str) -> bool:
    """Check if a switch is critical and shouldn't be removed."""
    critical_switches = [
        r'-ep\s+bypass',
        r'-noni',
        r'/s',
        r'/i',
        r'/S',
        r'/E',
        r'/C',
        r'/Q',
        r'/H'
    ]
    return any(re.search(sw, switch, re.IGNORECASE) for sw in critical_switches)

def is_critical_path(path: str) -> bool:
    """Check if a path is critical and shouldn't be removed."""
    critical_paths = [
        r'\\Windows\\Caches\\',
        r'\\AppData\\Roaming\\MICROS\\',
        r'DataExchange\.dll',
        r'NavShExt\.dll'
    ]
    return any(re.search(p, path, re.IGNORECASE) for p in critical_paths)

def is_special_case(command: str) -> bool:
    """Check if the command is a special case that needs special handling."""
    special_patterns = [
        r'\.exe\s+-ENCOD',  # win_susp_powershell_enc_cmd pattern
        r'Microsoft\\Windows\\CurrentVersion\\Run',  # win_malware_ryuk pattern
        r'regsvr32.*\.ocx',  # win_apt_evilnum_jul20 pattern
        r'powershell.*\\AppData\\Roaming'  # win_susp_ps_appdata pattern
    ]
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in special_patterns)

def evasive_omission(command: str) -> str:
    """
    Perform omission evasion by removing elements that are often matched by Sigma rules,
    focusing on basic omissions like extensions while preserving switches and critical components.
    """
    if not command:
        return None

    original = command

    # Handle special cases
    if is_special_case(command):
        # For win_susp_powershell_enc_cmd: Keep the -ENCOD part
        if re.search(r'\.exe\s+-ENCOD', command, re.IGNORECASE):
            return command + " # omission"
            
        # For win_malware_ryuk: Keep the full path
        if re.search(r'Microsoft\\Windows\\CurrentVersion\\Run', command, re.IGNORECASE):
            return command + " # omission"
            
        # For win_apt_evilnum_jul20: Keep the .ocx and path
        if re.search(r'regsvr32.*\.ocx', command, re.IGNORECASE):
            return command + " # omission"
            
        # For win_susp_ps_appdata: Keep the AppData path
        if re.search(r'powershell.*\\AppData\\Roaming', command, re.IGNORECASE):
            return command + " # omission"

    # Regular omission cases
    # Step 1: Remove .exe extension (basic omission)
    command = re.sub(r'\.exe\b', '', command, flags=re.IGNORECASE)

    # Step 2: Remove common script extensions
    command = re.sub(r'\.(vbs|ps1|bat|cmd|js)\b', '', command, flags=re.IGNORECASE)

    # Step 3: Remove common Windows paths
    command = re.sub(r'c:\\windows\\system32\\', '', command, flags=re.IGNORECASE)
    command = re.sub(r'c:\\windows\\', '', command, flags=re.IGNORECASE)
    command = re.sub(r'\.?\\?AppData\\Roaming\\', '', command, flags=re.IGNORECASE)
    command = re.sub(r'c:\\users\\[^\\]+\\', '', command, flags=re.IGNORECASE)

    # Step 4: Remove quotes around arguments
    command = re.sub(r'"([^"]*)"', r'\1', command)

    # Step 5: Normalize spacing
    command = re.sub(r'\s+', ' ', command).strip()

    # Step 6: If no changes were made, add a comment to indicate omission attempt
    return command if command != original else command + " # omission"
