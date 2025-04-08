def evasive_substitution(command):
    if not command:
        return None
    return command.replace("-Command", "-c").replace("--", "-")
