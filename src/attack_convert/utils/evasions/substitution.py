import json
import os
import re

# Load the mapping file (only once)
# This assumes 'substitution_mapping.json' is in the same directory as this script,
# or a path accessible via os.path.dirname(__file__).
# For robustness in different environments, consider passing substitution_map directly.
try:
    mapping_file = os.path.join(os.path.dirname(__file__), "substitution_mapping.json")
    with open(mapping_file, "r", encoding="utf-8") as f:
        substitution_map = json.load(f)
except FileNotFoundError:
    print("Error: substitution_mapping.json not found. Please ensure it's in the correct path.")
    # Fallback or raise error, depending on desired behavior
    substitution_map = {} # Empty map if file not found

def evasive_substitution(command: str) -> str:
    """
    Substitute known flags or parameters with valid aliases or long forms.
    Uses an external substitution map for flexibility.
    
    This function aims to replace ALL possible matching flags/keywords
    in a case-insensitive manner, prioritizing longer matches.
    """
    if not command:
        return "" # Return empty string for consistency instead of None

    modified_command = command
    substitution_occurred = False

    # First, identify the primary command (e.g., "powershell", "cmd")
    # Using shlex.split for robust tokenization might be better if the command
    # structure is complex with quotes, but for simple substitution on flags,
    # splitting by space and taking the first token is a good starting point.
    tokens = modified_command.split(maxsplit=1)
    if not tokens:
        return modified_command # No tokens, return as is

    # Normalize the executable name to match keys in substitution_map
    executable = tokens[0].lower() # e.g., "powershell.exe" or "cmd" -> "powershell", "cmd"

    # Handle .exe suffix for executables
    if executable.endswith(".exe"):
        executable = executable[:-4] # Remove .exe for matching keys like "powershell"

    # Check if a specific substitution map exists for this command
    target_subs = substitution_map.get(executable)
    if not target_subs:
        # Also check for the .exe version if we removed it (e.g. `powershell` vs `powershell.exe` key)
        if executable + ".exe" in substitution_map:
            target_subs = substitution_map.get(executable + ".exe")
        else:
            return modified_command # No specific substitutions for this command

    # Sort substitutions to prioritize longer matches.
    # This prevents "-C" from replacing part of "-Command" incorrectly.
    # The longest original flags are tried first.
    sorted_orig_flags = sorted(target_subs.keys(), key=len, reverse=True)

    for orig_flag in sorted_orig_flags:
        replacement = target_subs[orig_flag]

        # Use regex to replace the original flag with its replacement.
        # \b ensures word boundary (e.g., -f doesn't match 'file').
        # re.escape handles special characters in flags (like '$').
        # re.IGNORECASE ensures case-insensitive matching.
        # We need to consider that the replacement might contain regex special chars,
        # but re.sub handles the replacement string literally by default.

        # Create a regex pattern for the original flag
        # Handle cases where orig_flag might be a multi-word phrase like "add rule"
        # by matching it literally, but still using word boundaries if it's a simple flag.
        if re.match(r'^[/-_]?[a-zA-Z0-9.\$]+$', orig_flag): # Looks like a single flag/token
            pattern = r'\b' + re.escape(orig_flag) + r'\b'
        else: # Likely a phrase or complex keyword, match literally
            pattern = re.escape(orig_flag)
        
        # Perform replacement across the entire command
        # count=0 means replace all occurrences
        new_command = re.sub(pattern, replacement, modified_command, flags=re.IGNORECASE)
        
        if new_command != modified_command:
            modified_command = new_command
            substitution_occurred = True

    # Return the modified command. The `#substitution` comment should be handled
    # at the dataset generation level, not within this evasion function.
    return modified_command
