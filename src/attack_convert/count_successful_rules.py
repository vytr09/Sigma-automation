import os
import json
from pathlib import Path

# Get the project root directory
PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def count_successful_rules():
    # Path to the Evasion-Results directory
    results_dir = PROJECT_ROOT / "src" / "attack_convert" / "Evasion-Results"
    
    # Initialize counters
    total_rules = 0
    successful_rules = 0
    failed_rules = []
    debug_info = {}  # Store debug information for each rule
    
    # Walk through all JSON files in the directory
    for json_file in results_dir.glob("**/*.json"):
        total_rules += 1
        rule_name = json_file.name
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Initialize debug info for this rule
            debug_info[rule_name] = {
                'original_command': data.get('original_command', ''),
                'evasion_techniques': [],
                'is_successful': False
            }
            
            # Check if the rule was parsed successfully
            is_successful = False
            
            # Check original command
            original_cmd = data.get("original_command", "")
            if original_cmd and original_cmd != "<no command found>":
                is_successful = True
                debug_info[rule_name]['is_successful'] = True
                debug_info[rule_name]['success_reason'] = 'original_command'
            
            # Check evasion techniques
            for technique in data.get("evasion_techniques", []):
                cmd = technique.get("command", "")
                debug_info[rule_name]['evasion_techniques'].append({
                    'technique': technique.get('technique', ''),
                    'command': cmd
                })
                if cmd and cmd != "<no command found>":
                    is_successful = True
                    debug_info[rule_name]['is_successful'] = True
                    debug_info[rule_name]['success_reason'] = f'evasion_technique: {technique.get("technique", "")}'
                    break
            
            if is_successful:
                successful_rules += 1
            else:
                failed_rules.append(rule_name)
                
        except Exception as e:
            print(f"Error processing {json_file}: {str(e)}")
            failed_rules.append(rule_name)
            debug_info[rule_name]['error'] = str(e)
    
    # Calculate success rate
    success_rate = (successful_rules / total_rules * 100) if total_rules > 0 else 0
    
    # Print results
    print("\n=== Rule Parsing Statistics ===")
    print(f"Total rules processed: {total_rules}")
    print(f"Successfully parsed rules: {successful_rules}")
    print(f"Failed rules: {len(failed_rules)}")
    print(f"Success rate: {success_rate:.2f}%")
    
    # Print detailed information for failed rules
    if failed_rules:
        print("\nFailed rules details:")
        for rule in failed_rules:
            print(f"\n=== {rule} ===")
            info = debug_info[rule]
            print(f"Original command: {info['original_command']}")
            print("Evasion techniques:")
            for tech in info['evasion_techniques']:
                print(f"  - {tech['technique']}: {tech['command']}")
            if 'error' in info:
                print(f"Error: {info['error']}")
            if 'success_reason' in info:
                print(f"Success reason: {info['success_reason']}")

if __name__ == "__main__":
    count_successful_rules() 