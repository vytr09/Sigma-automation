import re

def extract_first_command_line(filter_str: str) -> str:
    """
    Extracts the most representative command from a Sigma rule's filter string.
    Supports single and grouped command_line entries.
    Handles wildcards, escaped quotes, and OR expressions.
    """

    # Extract process.executable (may be a single or group)
    exe_pattern = r'process\.executable:\s*(?:"\*?\\?([^"]+)"|\((.*?)\))'
    exe_match = re.search(exe_pattern, filter_str)
    executables = []

    if exe_match:
        if exe_match.group(1):
            executables = [exe_match.group(1).strip()]
        elif exe_match.group(2):
            raw_group = exe_match.group(2)
            # Extract full filenames like net.exe or net1.exe
            executables = re.findall(r'"[^"]*\\([^"]+)"', raw_group)

    # Extract command_line (support grouped OR)
    cmd_group_match = re.search(r'process\.command_line:\s*\((.*?)\)', filter_str, re.DOTALL)
    if cmd_group_match:
        group_content = cmd_group_match.group(1)
        all_cmds = re.findall(r'"((?:[^"\\]|\\.)*)"', group_content)
        if all_cmds:
            raw_cmd = all_cmds[0]  # Just take the first for now
            try:
                unescaped = bytes(raw_cmd, "utf-8").decode("unicode_escape")
            except Exception:
                unescaped = raw_cmd
            command_line = re.sub(r'\*+', ' ', unescaped).strip()
            command_line = re.sub(r'\s+', ' ', command_line)
        else:
            command_line = ""
    else:
        # Single command_line string
        cmd_match = re.search(r'process\.command_line:\s*"([^"]+)"', filter_str)
        if cmd_match:
            raw_cmd = cmd_match.group(1)
            command_line = re.sub(r'\*+', ' ', raw_cmd).strip()
            command_line = re.sub(r'\s+', ' ', command_line)
        else:
            command_line = ""

    # Combine if possible
    if executables and command_line:
        return f"{executables[0]} {command_line}"
    elif command_line:
        return command_line
    elif executables:
        return executables[0]
    else:
        return "<no command found>"
