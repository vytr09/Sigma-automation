import json
import os

# Load the mapping file (only once)
mapping_file = os.path.join(os.path.dirname(__file__), "substitution_mapping.json")
with open(mapping_file, "r", encoding="utf-8") as f:
    substitution_map = json.load(f)

def evasive_substitution(command: str) -> str:
    """
    Substitute known flags or parameters with valid aliases or long forms.
    Uses external substitution_mapping.json for flexibility.
    """
    if not command:
        return None

    original = command
    substitution_found = False
    
    for cmd_name, subs in substitution_map.items():
        if cmd_name.lower() in command.lower():
            for orig_flag, replacement in subs.items():
                if orig_flag in command:
                    command = command.replace(orig_flag, replacement)
                    substitution_found = True
                    break  # Use first valid substitution found
            if substitution_found:
                break  # Stop after first substitution

    # Only mark with #substitution if no valid substitution was found
    return command if substitution_found else command + " #substitution"
