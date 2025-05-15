# Sigma Automation

## Overview
Sigma Automation is a security tool designed to enhance SIEM (Security Information and Event Management) rule detection by automatically generating and testing evasion techniques against Sigma rules. The project focuses on improving detection capabilities by identifying and addressing potential blind spots in security rules.

## Core Functionality

### 1. Attack Generation and Testing
- Automatically generates original attacks based on Sigma rules
- Creates 5 types of evasion techniques for each rule:
  - Character insertion (e.g., adding quotes or spaces)
  - Argument substitution (e.g., using alternative flags)
  - Character omission (e.g., removing file extensions)
  - Argument reordering
  - Argument recoding (e.g., using encoded commands)
- Executes both original and evasion attacks
- Logs detection results for analysis

### 2. Splunk Query Generation and Improvement
- Converts Sigma rules to Splunk queries
- Automatically improves queries based on successful evasion attempts
- Validates and fixes query syntax
- Generates enhanced detection patterns

### 3. Logging and Analysis
- Maintains detailed logs of attack execution
- Tracks detection success/failure for each attempt
- Records both original and evasion commands
- Provides analysis of bypass techniques

## Technical Details

### Attack Execution
- Supports Windows process creation events
- Integrates with Windows Event Logs
- Uses Sysmon for enhanced logging capabilities
- Executes commands in isolated environments

### Query Improvement
- Analyzes successful evasion attempts
- Enhances Splunk queries to detect evasion patterns
- Maintains backward compatibility with original rules
- Validates query syntax and structure

## Getting Started

### Prerequisites
- Windows 10 system
- Splunk Enterprise installed
- Sysmon (optional, for enhanced logging)
- Python 3.x
- Required Python packages:
  ```bash
  pip install pyyaml
  ```

### Directory Structure
- `attack_convert/`: Contains attack generation tools and results
- `improved_queries/`: Stores enhanced Splunk queries
- `logs/`: Contains execution and detection logs
- `query_convert/`: Original Sigma to Splunk query conversions
- `data/rules/windows/process_creation/`: Place your Sigma rules here

### Complete Usage Flow

1. **Prepare Input Files**
   - Place your Sigma rule files (`.yml`) in `data/rules/windows/process_creation/`
   - Create `evasion_possible_rules.txt` listing rules to process (filenames without `.yml`)

2. **Generate Attack Commands**
   ```bash
   # Set PYTHONPATH to project root
   set PYTHONPATH=D:\UIT\Nam_3\DACN\Sigma-automation
   
   # Run attack generation
   python -m attack_convert.main
   ```
   This will generate JSON files in `attack_convert/Evasion-Results/` containing:
   - Original attack commands
   - Five evasion variations for each rule

3. **Convert Sigma Rules to Splunk Queries**
   ```bash
   # Run Sigma to Splunk conversion
   python -m query_convert.sigma_to_splunk.main
   ```
   This will generate Splunk queries in `query_convert/sigma_to_splunk/output_queries/`

4. **Run Attack Evaluation**
   ```bash
   # Execute attacks and test detection
   python run_attack_eval.py
   ```
   This will:
   - Execute original and evasion attacks
   - Test detection using Splunk queries
   - Log results in the `logs/` directory

5. **Generate Improved Queries**
   ```bash
   # Create enhanced Splunk queries
   python improve_splunk_queries.py
   ```
   This will generate improved queries in `improved_queries/` based on successful evasion attempts

### Output Files
- `attack_convert/Evasion-Results/*.json`: Generated attack commands
- `query_convert/sigma_to_splunk/output_queries/*.spl`: Original Splunk queries
- `improved_queries/*.spl`: Enhanced Splunk queries
- `logs/*.jsonl`: Detailed execution logs
- `logs/global_detection_log.txt`: Summary of all detection results

## Acknowledgments
This project implements the first three parts of the research paper "Adaptive Misuse Detection for SIEM Rules" presented at the 33rd USENIX Security Symposium (2024). The paper can be found in the `paper/` directory.

Our implementation focuses on:
1. Analysis of SIEM rules for evasions
2. Automatic generation of original attacks and evasion techniques
3. Conversion and improvement of Splunk queries

The paper's full content, including additional research on adaptive misuse detection, can be found in `paper/usenixsecurity24-uetz.pdf`.

## Contributing
We welcome contributions to improve the detection capabilities and add support for additional evasion techniques.