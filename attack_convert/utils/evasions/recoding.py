import base64

def evasive_recoding(command):
    if not command:
        return None
    if "powershell" in command.lower():
        encoded = base64.b64encode(command.encode("utf-16le")).decode()
        return f"powershell.exe -EncodedCommand {encoded}"
    return "<recoding not applicable>"
