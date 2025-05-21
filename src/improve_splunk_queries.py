import json
import os
from pathlib import Path
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('query_improvement.log'),
        logging.StreamHandler()
    ]
)

def read_qualified_rules():
    """Read the list of qualified rules that were bypassed."""
    with open(os.path.join(BASE_DIR, "output", "logs", "qualified_rules_output.txt"), "r") as f:
        return [line.strip() for line in f if line.strip()]

def read_detection_log(rule_name):
    """Read the detection log for a specific rule."""
    log_path = os.path.join(BASE_DIR, "output", "logs", f"{rule_name}_0_detection_log.jsonl")
    if not os.path.exists(log_path):
        return None
    
    with open(log_path, "r") as f:
        return [json.loads(line) for line in f]

def find_splunk_query(rule_name):
    """Find the corresponding Splunk query for a rule."""
    # Remove _0 suffix if present
    base_name = rule_name.removesuffix('_0')
    query_path = os.path.join(BASE_DIR, "src", "query_convert", "sigma_to_splunk", "output_queries", f"{base_name}.spl")
    
    if not os.path.exists(query_path):
        return None
    
    with open(query_path, "r") as f:
        return f.read()

def is_valid_bypass(phase, command):
    """Check if a bypass is valid based on the command content."""
    # If command contains any of these markers, it's not a real bypass
    invalid_markers = [
        "#",  # Comment markers
        "#insertion",
        "#substitution",
        "# omission",
        "<recoding not applicable>",
        "<substitution not applicable>",
        "<omission not applicable>"
    ]
    
    # Check if command contains any invalid markers
    for marker in invalid_markers:
        if marker in command:
            return False
    
    return True

def analyze_bypass(log_entries):
    """Analyze how the rule was bypassed from log entries."""
    bypass_info = {
        "original_command": None,
        "bypassed_command": None,
        "bypass_technique": None,
        "valid_bypasses": []  # Track all valid bypasses
    }
    
    # First check if original is detected
    original_detected = False
    for entry in log_entries:
        if entry.get("status") == "DETECTED" and entry.get("phase") == "original":
            original_detected = True
            bypass_info["original_command"] = entry.get("command")
            break
    
    if not original_detected:
        return bypass_info
    
    # Then check for valid bypasses
    for entry in log_entries:
        if entry.get("status") == "BYPASSED":
            phase = entry.get("phase")
            command = entry.get("command")
            
            # Check if this is a valid bypass
            if is_valid_bypass(phase, command):
                bypass_info["valid_bypasses"].append({
                    "phase": phase,
                    "command": command
                })
    
    # If we have valid bypasses, use the first one for backward compatibility
    if bypass_info["valid_bypasses"]:
        first_bypass = bypass_info["valid_bypasses"][0]
        bypass_info["bypassed_command"] = first_bypass["command"]
        bypass_info["bypass_technique"] = first_bypass["phase"]
    
    return bypass_info

def improve_splunk_query(query, bypass_info):
    """Generate an improved version of the Splunk query."""
    if not query or not bypass_info["valid_bypasses"]:
        return query

    # Split the query into base and table parts
    base_query = query.split("| table")[0]
    table_part = "| table" + query.split("| table")[1] if "| table" in query else "| table _time, New_Process_Name, Process_Command_Line"
    
    # Get the search conditions
    search_parts = base_query.split("| search")
    base_part = search_parts[0]  # The index and sourcetype part
    search_conditions = search_parts[1:]  # The search conditions
    
    # Start building the improved query
    improved_query = base_part
    
    # Process each search condition
    for i, condition in enumerate(search_conditions):
        condition = condition.strip()
        
        # Skip empty conditions
        if not condition:
            continue
            
        # Add the search command
        improved_query += "| search "
        
        # For the first condition, add all valid bypasses
        if i == 0:
            # Add the original condition
            improved_query += condition
            
            # Add valid bypasses based on their type
            for bypass in bypass_info["valid_bypasses"]:
                phase = bypass["phase"]
                command = bypass["command"]
                
                # Skip invalid bypasses
                if not is_valid_bypass(phase, command):
                    continue
                
                # Handle different bypass techniques
                if phase == "substitution":
                    # For substitution, add the alternative command
                    improved_query += ' OR "' + command.replace('"', '\\"') + '"'
                elif phase == "recoding":
                    # For recoding, add the encoded version
                    if "-EncodedCommand" in command:
                        improved_query += ' OR "' + command.replace('"', '\\"') + '"'
                elif phase == "insertion":
                    # For insertion, add pattern matching
                    parts = command.split()
                    if len(parts) > 1:
                        pattern = " ".join(parts)
                        improved_query += ' OR "' + pattern.replace('"', '\\"') + '"'
                elif phase == "omission":
                    # For omission, add the command without extension
                    if ".exe" in command:
                        cmd_without_exe = command.replace(".exe", "")
                        improved_query += ' OR "' + cmd_without_exe.replace('"', '\\"') + '"'
                elif phase == "reordering":
                    # For reordering, add the reordered command
                    improved_query += ' OR "' + command.replace('"', '\\"') + '"'
        else:
            # For subsequent conditions, just add them as is
            improved_query += condition
    
    # Add the table part
    improved_query += " " + table_part
    
    return improved_query

def validate_inputs(rule_name):
    """Validate that all required files exist for a rule."""
    required_files = [
        f"logs/{rule_name}_0_detection_log.jsonl",
        f"query_convert/sigma_to_splunk/output_queries/{rule_name.removesuffix('_0')}.spl"
    ]
    return all(os.path.exists(f) for f in required_files)

def validate_improved_query(query):
    """Validate that the improved query is syntactically correct."""
    # Check for balanced parentheses
    if query.count("(") != query.count(")"):
        return False
    
    # Check for proper table command placement
    if "| table" in query and query.count("| table") > 1:
        return False
    
    return True

def main():
    # Create output directory if it doesn't exist
    output_dir = "improved_queries"
    os.makedirs(output_dir, exist_ok=True)
    
    # Read qualified rules
    qualified_rules = read_qualified_rules()
    
    # Process each rule
    for rule in qualified_rules:
        print(f"\nProcessing rule: {rule}")
        
        # Read detection log
        log_entries = read_detection_log(rule)
        if not log_entries:
            print(f"  No detection log found for {rule}")
            continue
        
        # Get original Splunk query
        original_query = find_splunk_query(rule)
        if not original_query:
            print(f"  No Splunk query found for {rule}")
            continue
        
        # Analyze bypass
        bypass_info = analyze_bypass(log_entries)
        
        # Generate improved query
        improved_query = improve_splunk_query(original_query, bypass_info)
        
        # Save improved query
        output_path = os.path.join(output_dir, f"{rule.removesuffix('_0')}.spl")
        with open(output_path, "w") as f:
            f.write(improved_query)
        
        print(f"  Improved query saved to {output_path}")
        print(f"  Bypass technique: {bypass_info['bypass_technique']}")
        print(f"  Original command: {bypass_info['original_command']}")
        print(f"  Bypassed command: {bypass_info['bypassed_command']}")

def fix_existing_queries():
    """Fix syntax errors in existing improved queries."""
    output_dir = "improved_queries"
    for filename in os.listdir(output_dir):
        if filename.endswith(".spl"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "r") as f:
                query = f.read()
            
            # Fix unbalanced parentheses
            open_count = query.count("(")
            close_count = query.count(")")
            if open_count > close_count:
                query += ")" * (open_count - close_count)
            
            # Fix OR conditions in table command
            if "| table" in query:
                base_query = query.split("| table")[0]
                table_part = "| table" + query.split("| table")[1]
                if " OR " in table_part:
                    # Move OR conditions to the search part
                    or_conditions = table_part.split(" OR ")
                    table_part = "| table " + or_conditions[0].strip()
                    base_query += " OR " + " OR ".join(or_conditions[1:])
                query = base_query + " " + table_part
            
            # Remove placeholder text
            query = query.replace("<recoding not applicable>", "")
            query = query.replace("<substitution not applicable>", "")
            query = query.replace("<omission not applicable>", "")
            
            # Write fixed query back to file
            with open(filepath, "w") as f:
                f.write(query)

if __name__ == "__main__":
    main()
    fix_existing_queries() 