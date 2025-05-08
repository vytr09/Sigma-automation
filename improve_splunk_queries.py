import json
import os
from pathlib import Path

def read_qualified_rules():
    """Read the list of qualified rules that were bypassed."""
    with open("logs/qualified_rules_output.txt", "r") as f:
        return [line.strip() for line in f if line.strip()]

def read_detection_log(rule_name):
    """Read the detection log for a specific rule."""
    log_path = f"logs/{rule_name}_0_detection_log.jsonl"
    if not os.path.exists(log_path):
        return None
    
    with open(log_path, "r") as f:
        return [json.loads(line) for line in f]

def find_splunk_query(rule_name):
    """Find the corresponding Splunk query for a rule."""
    # Remove _0 suffix if present
    base_name = rule_name.removesuffix('_0')
    query_path = f"query_convert/sigma_to_splunk/output_queries/{base_name}.spl"
    
    if not os.path.exists(query_path):
        return None
    
    with open(query_path, "r") as f:
        return f.read()

def analyze_bypass(log_entries):
    """Analyze how the rule was bypassed from log entries."""
    bypass_info = {
        "original_command": None,
        "bypassed_command": None,
        "bypass_technique": None
    }
    
    for entry in log_entries:
        if entry.get("status") == "BYPASSED":
            bypass_info["bypassed_command"] = entry.get("command")
            bypass_info["bypass_technique"] = entry.get("phase")
        elif entry.get("status") == "DETECTED":
            bypass_info["original_command"] = entry.get("command")
    
    return bypass_info

def improve_splunk_query(query, bypass_info):
    """Generate an improved version of the Splunk query."""
    if not query or not bypass_info["bypassed_command"]:
        return query

    improved_query = query
    
    # Add additional conditions based on bypass technique
    if bypass_info["bypass_technique"] == "recoding":
        # Add pattern matching for common recoding techniques
        improved_query = improved_query.replace("| search", "| search (")
        improved_query += " OR " + bypass_info["bypassed_command"].replace("\\", "\\\\")
        improved_query += ")"
    
    elif bypass_info["bypass_technique"] == "substitution":
        # Add checks for common substitution patterns
        improved_query = improved_query.replace("| search", "| search (")
        improved_query += " OR " + bypass_info["bypassed_command"].replace("\\", "\\\\")
        improved_query += ")"
    
    elif bypass_info["bypass_technique"] == "omission":
        # Add checks for partial matches
        improved_query = improved_query.replace("| search", "| search (")
        improved_query += " OR " + bypass_info["bypassed_command"].replace("\\", "\\\\")
        improved_query += ")"
    
    return improved_query

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

if __name__ == "__main__":
    main() 