import base64
import re
import random
import ipaddress # For IP address obfuscation

def _obfuscate_ip_address(ip_addr_str: str) -> str:
    """
    Obfuscates an IPv4 address into various numerical formats (long decimal, hex).
    Returns a randomly chosen obfuscated format.
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip_addr_str)
        options = []

        # Long Decimal (e.g., 127.0.0.1 -> 2130706433)
        options.append(str(int(ip_obj)))

        # Hexadecimal (e.g., 127.0.0.1 -> 0x7f000001)
        options.append(hex(int(ip_obj)))
        
        # Dotted Hex (e.g., 127.0.0.1 -> 0x7f.0x00.0x00.0x01)
        options.append(".".join(f"0x{int(octet):x}" for octet in ip_addr_str.split('.')))

        return random.choice(options) if options else ip_addr_str
    except ipaddress.AddressValueError:
        # Not a valid IP address, return original string
        return ip_addr_str

def evasive_recoding(command: str) -> str:
    """
    Improved recoding that handles .dll, powershell param-only, generic encoding,
    and IP address obfuscation.
    """
    if not command:
        return "" # Return empty string for consistency

    modified_command = command.strip()
    command_lower = modified_command.lower()
    
    recoded_options = []

    # --- Strategy 1: PowerShell -EncodedCommand (Primary for PS-like commands) ---
    # This is a very common and effective recoding method for PowerShell.
    is_powershell_like = (
        "powershell" in command_lower or
        "-ep" in command_lower or
        "-encodedcommand" in command_lower or
        "-noni" in command_lower or
        "$" in command_lower or # PowerShell variables
        "cmdlet" in command_lower or # Common PowerShell term
        ".dll" in command_lower # Often executed via PowerShell reflection
    )

    if is_powershell_like:
        command_to_encode = modified_command
        # If powershell isn't the primary executable, prepend it
        if "powershell" not in command_lower.split(maxsplit=1)[0]:
            command_to_encode = f"powershell.exe {modified_command}"
        
        # Encode with UTF-16LE for PowerShell -EncodedCommand
        encoded = base64.b64encode(command_to_encode.encode("utf-16le")).decode()
        recoded_options.append(f"powershell.exe -EncodedCommand {encoded}".strip())

    # --- Strategy 2: IP Address Obfuscation (In-place substitution) ---
    # This strategy finds IP addresses and converts them to other numerical formats.
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b') # Matches IPv4 addresses
    
    # Find all IPs and store their original position and obfuscated versions
    temp_command_with_ips_obfuscated = modified_command
    ips_found = False
    for match in ip_pattern.finditer(modified_command):
        original_ip = match.group(0)
        obfuscated_ip = _obfuscate_ip_address(original_ip)
        
        if obfuscated_ip != original_ip:
            # Replace only the first occurrence found in the temp string at a time
            # to avoid issues with `re.sub` and overlapping matches if not careful.
            # However, `re.finditer` and then `re.sub` should be safe if done iteratively.
            # A simpler approach is to rebuild the command string with replaced IPs.
            temp_command_with_ips_obfuscated = temp_command_with_ips_obfuscated.replace(original_ip, obfuscated_ip, 1)
            ips_found = True
    
    if ips_found and temp_command_with_ips_obfuscated != modified_command:
        recoded_options.append(temp_command_with_ips_obfuscated)


    # --- Strategy 3: Fallback Generic Encoding (if no other specific recoding was found) ---
    # This provides a general Base64 wrapping if more specific methods weren't applicable
    # or to provide an additional option.
    if not recoded_options or (len(recoded_options) == 1 and is_powershell_like): # Only add generic if no other unique recoding or just powershell-like
        encoded_generic = base64.b64encode(modified_command.encode("utf-8")).decode()
        generic_recoded_cmd = (
            'powershell.exe -NoProfile -Command '
            f'"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\'{encoded_generic}\')) | '
            'Invoke-Expression"'
        ).strip()
        if generic_recoded_cmd != modified_command: # Ensure it's actually different
            recoded_options.append(generic_recoded_cmd)


    # --- Final Step: Return a random valid recoded command ---
    if recoded_options:
        # Remove duplicates
        unique_recoded_options = list(set(recoded_options))
        # Ensure we don't return the original command if it somehow slipped in
        if modified_command in unique_recoded_options:
            unique_recoded_options.remove(modified_command)
        
        if unique_recoded_options:
            return random.choice(unique_recoded_options)
        
    return modified_command # If no recoding options found, return original
