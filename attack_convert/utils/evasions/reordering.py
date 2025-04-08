def evasive_reordering(command):
    if not command:
        return None
    parts = command.split()
    if len(parts) > 2:
        reordered = parts[:1] + parts[2:3] + parts[1:2] + parts[3:]
        return " ".join(reordered)
    return command
