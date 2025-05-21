import base64

def evasive_recoding(command):
    # if not command:
    #     return None
    # if "powershell" in command.lower():
    #     encoded = base64.b64encode(command.encode("utf-16le")).decode()
    #     return f"powershell.exe -EncodedCommand {encoded}"
    # return "<recoding not applicable>"

    """
    Improved recoding that handles .dll, powershell param-only, and generic encoding.
    """
    if not command:
        return None

    command_lower = command.lower().strip()

    # If DLL is directly called, encode the whole command (often malicious pattern)
    if ".dll" in command_lower:
        encoded = base64.b64encode(command.encode("utf-16le")).decode()
        return f"powershell.exe -EncodedCommand {encoded} "

    # Infer PowerShell if no executable present but PS-like params exist
    if (
        "powershell" in command_lower or
        "-ep" in command_lower or
        "-encodedcommand" in command_lower or
        "-noni" in command_lower or
        "$" in command_lower
    ):
        if "powershell" not in command_lower:
            command = f"powershell.exe {command}"
        encoded = base64.b64encode(command.encode("utf-16le")).decode()
        return f"powershell.exe -EncodedCommand {encoded} "

    # Fallback generic encoding using PowerShell
    encoded_generic = base64.b64encode(command.encode("utf-8")).decode()
    return (
        'powershell.exe -NoProfile -Command '
        f'"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\'{encoded_generic}\')) | '
        'Invoke-Expression" '
    )
