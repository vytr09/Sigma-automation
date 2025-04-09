import re

# ===== Step 1: Extract command_line fragments =====
def extract_raw_fragments(filter_str: str) -> list[str]:
    fragments = set()

    # Bỏ tất cả các NOT process.command_line
    filter_str = re.sub(r'NOT\s+process\.command_line:\s*"[^"]+"', '', filter_str, flags=re.IGNORECASE)

    # OR group (quoted or unquoted)
    group_blocks = re.findall(r'process\.command_line:\s*\((.*?)\)', filter_str, flags=re.DOTALL | re.IGNORECASE)
    for block in group_blocks:
        quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', block)
        if quoted:
            for q in quoted:
                fragments.add(clean_command(q))
        else:
            parts = re.split(r'\s+OR\s+', block, flags=re.IGNORECASE)
            for p in parts:
                fragments.add(clean_command(p))

    # Regular lines
    cmd_lines = re.findall(r'process\.command_line:\s*"([^"]+)"', filter_str)
    for line in cmd_lines:
        fragments.add(clean_command(line))

    return list(fragments)

# ===== Step 2: Clean command fragment =====
def clean_command(fragment: str) -> str:
    # Remove wildcards but preserve punctuation
    fragment = fragment.replace("*", " ")
    fragment = re.sub(r'\s+', ' ', fragment)
    fragment = fragment.strip()
    # Gỡ dấu nháy dư nếu không cần thiết
    if fragment.startswith('"') and not fragment.endswith('"'):
        fragment = fragment.lstrip('"')
    return fragment

# ===== Step 3: Prioritize best command =====
def prioritize_command(commands: list[str]) -> str:
    """
    From a list of commands, selects the one with highest priority.
    """
    danger_keywords = [
        "downloadstring", "downloadfile",  # ✅ Thêm ưu tiên cụ thể
        "powershell", "netsh", "reg", "cmd", "wmic", "schtasks", "rundll32",
        "mshta", "taskkill", "java", "cscript", "bypass", "encodedcommand",
        "debug", "service", "url", "remote", "exe", "dll", "start", "create"
    ]


    if not commands:
        return ""

    priority_cmds = [cmd for cmd in commands if any(kw in cmd.lower() for kw in danger_keywords)]

    if priority_cmds:
        return max(priority_cmds, key=len)  # prefer longest among danger ones
    else:
        return max(commands, key=len)


# ===== Step 4: Extract process.executable if available =====
def extract_executable(filter_str: str) -> str | None:
    """
    Extracts the executable name from process.executable, supporting single and OR-group cases.
    """
    # 1. OR-group: process.executable: ("*\\net.exe" OR "*\\net1.exe")
    group_match = re.search(r'process\.executable:\s*\((.*?)\)', filter_str, flags=re.DOTALL | re.IGNORECASE)
    if group_match:
        group_content = group_match.group(1)
        candidates = re.findall(r'"[^"]*\\([^"\\]+)"', group_content)
        if candidates:
            # Ưu tiên "net.exe" nếu có
            for exe in candidates:
                if exe.lower() == "net.exe":
                    return exe
            return candidates[0]

    # 2. Fallback: dạng đơn
    exe_match = re.search(r'process\.executable:\s*"[^"]*\\([^"\\]+)"', filter_str)
    if exe_match:
        return exe_match.group(1).strip()

    return None


# ===== Step 5: Combine if needed =====
def combine_command(exe: str | None, cmd: str) -> str:
    """
    Combine executable with command if not redundant.
    """
    if exe and not cmd.lower().startswith(exe.lower()):
        return f"{exe} {cmd}".strip()
    return cmd.strip()


# ===== Main Function =====
def extract_first_command_line(filter_str: str) -> str:
    """
    Main API function: extract the most representative command from a Sigma filter string.
    """

    raw_fragments = extract_raw_fragments(filter_str)
    cleaned_commands = [clean_command(frag) for frag in raw_fragments if frag.strip()]
    best_command = prioritize_command(cleaned_commands)
    executable = extract_executable(filter_str)
    full_command = combine_command(executable, best_command)

    return full_command if full_command else "<no command found>"
