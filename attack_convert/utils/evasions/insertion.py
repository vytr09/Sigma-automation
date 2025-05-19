import random
import re
import string

def generate_random_noise(length: int = 3) -> str:
    """Generate random noise characters that are safe for command insertion."""
    # Use a mix of safe characters that won't break command functionality
    safe_chars = string.ascii_letters + string.digits + "_-"
    return ''.join(random.choice(safe_chars) for _ in range(length))

def is_safe_insertion(command: str, insertion: str) -> bool:
    """Check if an insertion preserves command functionality."""
    # Check if insertion breaks command structure
    if insertion.count('"') % 2 != 0:  # Unmatched quotes
        return False
        
    # Check if insertion breaks common command patterns
    if re.search(r'[<>|&]', insertion):  # Avoid breaking pipes and redirects
        return False
        
    return True

def insert_quotes_around_word(word: str) -> str:
    """Insert quotes around a word in various ways."""
    if not word:
        return word
        
    # Strategy 1: Simple quote around word
    if len(word) > 1:
        return f'"{word}"'
        
    # Strategy 2: Quote each character
    if len(word) > 2:
        return ''.join(f'"{c}"' for c in word)
        
    # Strategy 3: Quote with escaped quotes
    if len(word) > 1:
        return f'\\"{word}\\"'
        
    return word

def insert_spaces(word: str) -> str:
    """Insert spaces in various ways."""
    if not word:
        return word
        
    # Strategy 1: Add random spaces between characters
    if len(word) > 1:
        return ' '.join(word)
        
    # Strategy 2: Add multiple spaces
    return word + ' ' * random.randint(1, 3)
    
    return word

def generate_insertions(command: str) -> list[str]:
    """
    Generate multiple evasive variants using insertion techniques.
    These include inserting quotes and escaped quotes around command parts and arguments.
    """
    if not command:
        return []

    insertions = []
    tokens = command.split()
    if len(tokens) < 1:  # Changed from 2 to 1 to handle single token commands
        return []

    # Strategy 0: Handle paths with backslashes
    for i in range(len(tokens)):
        if '\\' in tokens[i]:
            # Handle file path
            path_tokens = tokens.copy()
            # Simple quote around entire path
            path_tokens[i] = f'"{tokens[i]}"'
            path_cmd = " ".join(path_tokens)
            if is_safe_insertion(command, path_cmd):
                insertions.append(path_cmd)
            # Character-level quotes for filename part
            if '.' in tokens[i]:
                filename = tokens[i].split('\\')[-1]
                path = '\\'.join(tokens[i].split('\\')[:-1])
                # Fix nested f-string by using string concatenation
                quoted_filename = ''.join(f'"{c}"' for c in filename)
                char_quoted_path = f'{path}\\{quoted_filename}'
                path_tokens[i] = char_quoted_path
                path_cmd = " ".join(path_tokens)
                if is_safe_insertion(command, path_cmd):
                    insertions.append(path_cmd)
            # Escaped quotes
            escaped_tokens = tokens.copy()
            escaped_tokens[i] = f'\\"{tokens[i]}\\"'
            escaped_cmd = " ".join(escaped_tokens)
            if is_safe_insertion(command, escaped_cmd):
                insertions.append(escaped_cmd)

    # Strategy 1: Insert quotes around arguments
    for i in range(1, len(tokens)):
        # Handle /command -> /"command" or /"c"r"e"a"t"e"
        if tokens[i].startswith('/'):
            quoted_tokens = tokens.copy()
            cmd_part = tokens[i][1:]  # Remove the slash
            # Simple quote
            quoted_tokens[i] = f'/"{{cmd_part}}"'
            quoted_cmd = " ".join(quoted_tokens)
            if is_safe_insertion(command, quoted_cmd):
                insertions.append(quoted_cmd)
            # Character-level quotes
            char_quoted_tokens = tokens.copy()
            char_quoted_tokens[i] = '/' + ''.join(f'"{c}"' for c in cmd_part)
            char_quoted_cmd = " ".join(char_quoted_tokens)
            if is_safe_insertion(command, char_quoted_cmd):
                insertions.append(char_quoted_cmd)
        # Handle regular arguments
        else:
            # Simple quote
            quoted_tokens = tokens.copy()
            quoted_tokens[i] = f'"{tokens[i]}"'
            quoted_cmd = " ".join(quoted_tokens)
            if is_safe_insertion(command, quoted_cmd):
                insertions.append(quoted_cmd)
            # Character-level quotes
            char_quoted_tokens = tokens.copy()
            char_quoted_tokens[i] = ''.join(f'"{c}"' for c in tokens[i])
            char_quoted_cmd = " ".join(char_quoted_tokens)
            if is_safe_insertion(command, char_quoted_cmd):
                insertions.append(char_quoted_cmd)
            # Escaped quotes
            escaped_tokens = tokens.copy()
            escaped_tokens[i] = f'\\"{tokens[i]}\\"'
            escaped_cmd = " ".join(escaped_tokens)
            if is_safe_insertion(command, escaped_cmd):
                insertions.append(escaped_cmd)
            # Character-level escaped quotes
            char_escaped_tokens = tokens.copy()
            char_escaped_tokens[i] = ''.join(f'\\"{c}\\"' for c in tokens[i])
            char_escaped_cmd = " ".join(char_escaped_tokens)
            if is_safe_insertion(command, char_escaped_cmd):
                insertions.append(char_escaped_cmd)

    # Strategy 2: Insert quotes around multiple arguments
    for i in range(1, len(tokens)-1):
        quoted_tokens = tokens.copy()
        # Handle /command patterns
        if tokens[i].startswith('/') and tokens[i+1].startswith('/'):
            cmd_part1 = tokens[i][1:]  # Remove the slash
            cmd_part2 = tokens[i+1][1:]  # Remove the slash
            # Simple quotes
            quoted_tokens[i] = f'/"{{cmd_part1}}"'
            quoted_tokens[i+1] = f'/"{{cmd_part2}}"'
            quoted_cmd = " ".join(quoted_tokens)
            if is_safe_insertion(command, quoted_cmd):
                insertions.append(quoted_cmd)
            # Character-level quotes
            char_quoted_tokens = tokens.copy()
            char_quoted_tokens[i] = '/' + ''.join(f'"{c}"' for c in cmd_part1)
            char_quoted_tokens[i+1] = '/' + ''.join(f'"{c}"' for c in cmd_part2)
            char_quoted_cmd = " ".join(char_quoted_tokens)
            if is_safe_insertion(command, char_quoted_cmd):
                insertions.append(char_quoted_cmd)
        # Handle regular arguments
        else:
            # Simple quotes
            quoted_tokens[i] = f'"{tokens[i]}"'
            quoted_tokens[i+1] = f'"{tokens[i+1]}"'
            quoted_cmd = " ".join(quoted_tokens)
            if is_safe_insertion(command, quoted_cmd):
                insertions.append(quoted_cmd)
            # Escaped quotes
            escaped_tokens = tokens.copy()
            escaped_tokens[i] = f'\\"{tokens[i]}\\"'
            escaped_tokens[i+1] = f'\\"{tokens[i+1]}\\"'
            escaped_cmd = " ".join(escaped_tokens)
            if is_safe_insertion(command, escaped_cmd):
                insertions.append(escaped_cmd)

    # Strategy 3: Insert quotes around command parts
    for i in range(1, len(tokens)):
        if tokens[i].startswith('/'):
            cmd_part = tokens[i][1:]  # Remove the slash
            if len(cmd_part) > 2:
                # Quote first half
                part_quoted_tokens = tokens.copy()
                mid = len(cmd_part) // 2
                part_quoted_tokens[i] = f'/"{{cmd_part[:mid]}}"{{cmd_part[mid:]}}'
                part_quoted_cmd = " ".join(part_quoted_tokens)
                if is_safe_insertion(command, part_quoted_cmd):
                    insertions.append(part_quoted_cmd)
                # Quote second half
                part_quoted_tokens[i] = f'/{{cmd_part[:mid]}}"{{cmd_part[mid:]}}"'
                part_quoted_cmd = " ".join(part_quoted_tokens)
                if is_safe_insertion(command, part_quoted_cmd):
                    insertions.append(part_quoted_cmd)
        else:
            if len(tokens[i]) > 2:
                # Quote first half
                part_quoted_tokens = tokens.copy()
                mid = len(tokens[i]) // 2
                part_quoted_tokens[i] = f'"{tokens[i][:mid]}"{tokens[i][mid:]}'
                part_quoted_cmd = " ".join(part_quoted_tokens)
                if is_safe_insertion(command, part_quoted_cmd):
                    insertions.append(part_quoted_cmd)
                # Quote second half
                part_quoted_tokens[i] = f'{tokens[i][:mid]}"{tokens[i][mid:]}"'
                part_quoted_cmd = " ".join(part_quoted_tokens)
                if is_safe_insertion(command, part_quoted_cmd):
                    insertions.append(part_quoted_cmd)
                # Escaped quotes first half
                escaped_tokens = tokens.copy()
                escaped_tokens[i] = f'\\"{tokens[i][:mid]}\\"{tokens[i][mid:]}'
                escaped_cmd = " ".join(escaped_tokens)
                if is_safe_insertion(command, escaped_cmd):
                    insertions.append(escaped_cmd)
                # Escaped quotes second half
                escaped_tokens[i] = f'{tokens[i][:mid]}\\"{tokens[i][mid:]}\\"'
                escaped_cmd = " ".join(escaped_tokens)
                if is_safe_insertion(command, escaped_cmd):
                    insertions.append(escaped_cmd)

    return insertions

def evasive_insertion(command: str) -> str:
    """
    Return one evasive command generated by a random insertion technique.
    """
    evasions = generate_insertions(command)
    return random.choice(evasions) if evasions else command
