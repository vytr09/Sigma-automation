import re

def evasive_omission(command):
    if not command:
        return None
    return re.sub(r'(-Command\\s+)', '', command)
