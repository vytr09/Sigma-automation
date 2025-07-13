import random
import re
import shlex # Import shlex for robust command parsing
from typing import List, Tuple

def parse_command(command: str) -> Tuple[str, List[str]]:
    """
    Parse command into executable and arguments using shlex for robustness.
    Handles quotes and complex command structures.
    """
    try:
        tokens = shlex.split(command)
        if not tokens:
            return "", []
        executable = tokens[0]
        args = tokens[1:]
        return executable, args
    except ValueError:
        # Fallback if shlex.split fails for some reason (e.g., unmatched quotes)
        # In such cases, we might not be able to safely reorder.
        return "", []

def is_order_dependent_arg_group(arg: str, next_arg: str = None) -> bool:
    """
    Check if an argument, especially a flag, is likely to be order-dependent
    with its subsequent argument (i.e., it's a flag that takes a value).
    Returns True if the flag likely requires the next argument as its value.
    """
    # Common flags that usually require a value (e.g., -f <file>, -output <path>)
    # This is a heuristic and might not cover all cases.
    value_requiring_flags = [
        r'^-f\b', r'^-file\b', r'^-o\b', r'^-output\b',
        r'^-path\b', r'^-arg\b', r'^-name\b', r'^-value\b',
        r'^--file\b', r'^--output\b', r'^--path\b', r'^--name\b',
        r'/f\b', r'/o\b', r'/p\b', r'/v\b', # Windows specific
        r'-c\b', r'-command\b' # Powershell specific
    ]

    # Check if the current argument is a flag that requires a value
    if any(re.match(pattern, arg, re.IGNORECASE) for pattern in value_requiring_flags):
        # If it's a value-requiring flag and there's a next argument (which is not another flag)
        if next_arg and not (next_arg.startswith('-') or next_arg.startswith('/')):
            return True # This pair should probably stay together
    return False

def is_safe_reordering(original_command: str, reordered_command: str) -> bool:
    """
    Checks if a reordering is syntactically safe and preserves basic command structure.
    This is a heuristic and doesn't guarantee functional correctness.
    """
    if not reordered_command.strip():
        return False
    
    # Unmatched quotes check (shlex.split would ideally catch this, but good to double check)
    if reordered_command.count('"') % 2 != 0:
        return False
    
    # Avoid breaking pipes, redirects, or command chaining
    if re.search(r'[<>|&]', reordered_command):
        return False

    # Check for critical components that must maintain relative positions (e.g., `cmd /c` followed by actual command)
    original_exe, original_args = parse_command(original_command)
    reordered_exe, reordered_args = parse_command(reordered_command)

    # Executable must remain first
    if original_exe and reordered_exe and original_exe.lower() != reordered_exe.lower():
        return False
    
    # If `cmd /c` is present, `/c` must be followed by content that resembles the original command
    if original_exe.lower() == 'cmd' and '/c' in original_args:
        # Find index of /c in original args
        try:
            original_c_idx = original_args.index('/c')
            # The part of the command after /c in the original must be largely intact
            # and appear after /c in the reordered command.
            original_cmd_after_c = " ".join(original_args[original_c_idx + 1:])
            
            # Find index of /c in reordered args
            reordered_c_idx = reordered_args.index('/c')
            reordered_cmd_after_c = " ".join(reordered_args[reordered_c_idx + 1:])
            
            # This is a very loose check, but we want to avoid completely scrambling the inner command.
            # A more robust check might involve comparing sets of tokens or using a parser.
            # For simplicity, ensure the reordered command still contains the original inner command.
            if original_cmd_after_c and original_cmd_after_c not in reordered_cmd_after_c:
                 return False

        except ValueError:
            # /c not found in one of them (should ideally be caught by executable check)
            pass
            
    # Check if flags that require values are kept together (heuristic)
    for i, arg in enumerate(original_args):
        next_arg = original_args[i+1] if i + 1 < len(original_args) else None
        if is_order_dependent_arg_group(arg, next_arg):
            # If (arg, next_arg) was a pair, check if they are still paired or appear in the reordered command
            # This is hard to check robustly without complex parsing, so we rely on not splitting them in generate_reorderings
            pass # We'll handle this primarily in `generate_reorderings`

    return True

def generate_reorderings(command: str) -> list[str]:
    """
    Generate multiple evasive variants using reordering techniques.
    These include reordering command parts while preserving functionality.
    """
    if not command:
        return []

    reorderings = []
    executable, args = parse_command(command)
    
    if not executable or not args: # Need at least an executable and one arg to reorder
        return []

    # Filter out arg-value pairs that should not be split
    # Create groups of arguments that should stay together
    arg_groups = []
    i = 0
    while i < len(args):
        current_arg = args[i]
        next_arg = args[i+1] if i + 1 < len(args) else None
        if is_order_dependent_arg_group(current_arg, next_arg):
            arg_groups.append([current_arg, next_arg])
            i += 2
        else:
            arg_groups.append([current_arg])
            i += 1

    # Only attempt reordering if there are at least two independent groups
    if len(arg_groups) < 2:
        return []

    # --- Strategy 1: Randomly swap two independent groups ---
    if len(arg_groups) >= 2:
        # Choose two distinct indices to swap
        idx1, idx2 = random.sample(range(len(arg_groups)), 2)
        
        reordered_groups = arg_groups[:]
        reordered_groups[idx1], reordered_groups[idx2] = reordered_groups[idx2], reordered_groups[idx1]
        
        # Flatten the list of lists back into tokens
        reordered_args = [item for sublist in reordered_groups for item in sublist]
        reordered_cmd = f"{executable} {' '.join(reordered_args)}"
        
        if is_safe_reordering(command, reordered_cmd) and reordered_cmd != command:
            reorderings.append(reordered_cmd)

    # --- Strategy 2: Rotate independent groups ---
    if len(arg_groups) > 1:
        # Rotate one position
        rotated_groups = arg_groups[1:] + [arg_groups[0]]
        reordered_args = [item for sublist in rotated_groups for item in sublist]
        reordered_cmd = f"{executable} {' '.join(reordered_args)}"
        if is_safe_reordering(command, reordered_cmd) and reordered_cmd != command:
            reorderings.append(reordered_cmd)
        
        # Rotate two positions (if enough groups)
        if len(arg_groups) > 2:
            rotated_groups = arg_groups[2:] + arg_groups[:2]
            reordered_args = [item for sublist in rotated_groups for item in sublist]
            reordered_cmd = f"{executable} {' '.join(reordered_args)}"
            if is_safe_reordering(command, reordered_cmd) and reordered_cmd != command:
                reorderings.append(reordered_cmd)

    # --- Special handling for `cmd /c` (if it's not already covered by general reordering) ---
    # This block might be redundant if `parse_command` and general reordering
    # are smart enough, but kept for explicit clarity.
    if executable.lower() == 'cmd' and '/c' in args:
        try:
            c_index = args.index('/c')
            # The part after `/c` is the "inner command" and should generally stay together
            inner_command_parts = args[c_index + 1:]
            
            # Arguments before `/c`
            pre_c_args = args[:c_index]
            
            # --- Move `/c` and inner command after some pre-c args ---
            if len(pre_c_args) > 0:
                # Try moving `/c` after the first pre-c arg
                new_pre_c_args = pre_c_args[1:] + [pre_c_args[0]] # Rotate pre-c args
                reordered_cmd_parts = new_pre_c_args + ['/c'] + inner_command_parts
                reordered_cmd = f"{executable} {' '.join(reordered_cmd_parts)}"
                if is_safe_reordering(command, reordered_cmd) and reordered_cmd != command:
                    reorderings.append(reordered_cmd)

        except ValueError:
            pass # /c not found, ignore this strategy

    return reorderings

def evasive_reordering(command: str) -> str:
    """
    Return one evasive command generated by a random reordering technique.
    """
    reorderings = generate_reorderings(command)
    # Remove duplicates before picking a random one
    reorderings = list(set(reorderings)) 
    return random.choice(reorderings) if reorderings else command
