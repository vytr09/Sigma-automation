import re

# ===== Step 1: Extract complex (exe + cmd) OR-pairs =====
def extract_raw_fragments_with_exe_pairs(filter_str: str) -> list[str]:
    pattern = r'\(\s*process\.executable:\s*"([^"]+)"\s*AND\s*process\.command_line:\s*"([^"]+)"\s*\)'
    pairs = re.findall(pattern, filter_str)
    fragments = []
    for exe, cmd in pairs:
        exe_clean = clean_command(exe)
        cmd_clean = clean_command(cmd)
        fragments.append(f"{exe_clean} {cmd_clean}")
    return fragments


# ===== Step 2: Extract all other command_line fragments =====
def extract_raw_fragments(filter_str: str) -> list[str]:
    fragments = set()

    # Remove NOT statements
    filter_str = re.sub(r'NOT\s+process\.command_line:\s*"[^"]+"', '', filter_str, flags=re.IGNORECASE)

    # 1. Complex (exe + cmd) pairs
    fragments.update(extract_raw_fragments_with_exe_pairs(filter_str))

    # 2. AND + OR combination
    and_or_combos = re.findall(
        r'process\.command_line:\s*"([^"]+)"\s+AND\s+process\.command_line:\s*\(\s*((?:"[^"]+"\s*(?:OR\s*)?)+)\)',
        filter_str,
        flags=re.IGNORECASE
    )
    for base, or_group in and_or_combos:
        or_parts = re.findall(r'"([^"]+)"', or_group)
        for p in or_parts:
            combined = f"{base} {p}"
            fragments.add(clean_command(combined))

    # 3. OR-branch processing with AND-inside
    or_branches = re.split(r'\)\s+OR\s+\(', filter_str, flags=re.IGNORECASE)
    for branch in or_branches:
        cmd_lines = re.findall(r'process\.command_line:\s*"([^"]+)"', branch)
        if cmd_lines:
            joined = " ".join(clean_command(cmd) for cmd in cmd_lines)
            fragments.add(joined)

    # 4. group (quoted OR list)
    group_blocks = re.findall(r'process\.command_line:\s*\((.*?)\)', filter_str, flags=re.DOTALL | re.IGNORECASE)
    for block in group_blocks:
        quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', block)
        parts = quoted if quoted else re.split(r'\s+OR\s+', block, flags=re.IGNORECASE)
        for part in parts:
            fragments.add(clean_command(part))

    # 5. Special case: only ANDed process.command_line
    key_matches = re.findall(r'([a-zA-Z0-9_.]+):\s*"[^"]+"', filter_str)
    if key_matches and all(k == 'process.command_line' for k in key_matches):
        all_cmds = re.findall(r'process\.command_line:\s*"([^"]+)"', filter_str)
        full_command = " ".join(clean_command(cmd) for cmd in all_cmds)
        fragments.add(full_command)

    else:
        # 6. Fallback: extract individually
        cmd_lines = re.findall(r'process\.command_line:\s*"([^"]+)"', filter_str)
        for line in cmd_lines:
            fragments.add(clean_command(line))

    return list(fragments)


# ===== Step 3: Clean fragments =====
def clean_command(fragment: str) -> str:
    fragment = fragment.replace("*", " ")
    fragment = re.sub(r'\s+', ' ', fragment).strip()
    if fragment.startswith('"') and not fragment.endswith('"'):
        fragment = fragment.lstrip('"')
    return fragment


# ===== Step 4: Prioritize =====
def prioritize_command(commands: list[str]) -> str:
    danger_keywords = [
        "add-printerport", "downloadstring", "downloadfile",
        "powershell", "netsh", "reg", "cmd", "wmic", "schtasks", "rundll32",
        "mshta", "taskkill", "java", "cscript", "bypass", "encodedcommand",
        "debug", "service", "url", "remote", "exe", "dll", "start", "create"
    ]
    if not commands:
        return ""
    priority_cmds = [cmd for cmd in commands if any(kw in cmd.lower() for kw in danger_keywords)]
    return max(priority_cmds, key=len) if priority_cmds else max(commands, key=len)


# ===== Step 5: Extract executable =====
def extract_executable(filter_str: str) -> str | None:
    group_match = re.search(r'process\.executable:\s*\((.*?)\)', filter_str, flags=re.DOTALL | re.IGNORECASE)
    if group_match:
        group_content = group_match.group(1)
        candidates = re.findall(r'"[^"]*\\([^"\\]+)"', group_content)
        if candidates:
            return candidates[0]
    exe_match = re.search(r'process\.executable:\s*"[^"]*\\([^"\\]+)"', filter_str)
    return exe_match.group(1).strip() if exe_match else None


# ===== Step 6: Combine =====
def combine_command(exe: str | None, cmd: str) -> str:
    if exe and not cmd.lower().startswith(exe.lower()):
        return f"{exe} {cmd}".strip()
    return cmd.strip()


# ===== Main API =====
def extract_first_command_line(filter_str: str) -> str:
    raw_fragments = extract_raw_fragments(filter_str)
    cleaned_commands = [clean_command(frag) for frag in raw_fragments if frag.strip()]
    best_command = prioritize_command(cleaned_commands)
    executable = extract_executable(filter_str)
    full_command = combine_command(executable, best_command)
    return full_command if full_command else "<no command found>"
