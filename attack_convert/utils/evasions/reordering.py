import random

def evasive_reordering(command: str) -> str:
    """
    Evasion technique: Reordering command-line arguments while preserving semantics.
    The executable stays in place.
    """
    if not command:
        return None

    tokens = command.split()
    if len(tokens) <= 2:
        return command  # Nothing to reorder

    exe = tokens[0]
    args = tokens[1:]

    if len(args) == 2:
        # Swap two args
        reordered = [exe] + [args[1], args[0]]
    else:
        # Shuffle arguments
        args_shuffled = args[:]
        random.shuffle(args_shuffled)
        reordered = [exe] + args_shuffled

    return " ".join(reordered)
