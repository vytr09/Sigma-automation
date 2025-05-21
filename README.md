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
- Python 3.10+
- Required Python packages:
  ```bash
  pip install pyyaml
  ```

### Project Structure
```
Sigma-automation/
├── src/                           # Source code
│   ├── attack_convert/            # Attack generation
│   │   ├── main.py               # Main attack generator
│   │   ├── utils/                # Utility functions
│   │   │   ├── parser.py        # Rule parser
│   │   │   ├── evasions_core.py # Evasion controller
│   │   │   └── evasions/        # Evasion techniques
│   │   └── Evasion-Results/      # Generated attacks
│   │
│   ├── query_convert/            # Query conversion
│   │   └── sigma_to_splunk/      # Sigma to Splunk converter
│   │       ├── sigma_to_splunk.py # Main converter
│   │       └── output_queries/    # Generated queries
│   │
│   ├── tools/                    # Utility tools
│   │   ├── all_filters.py       # Extract filters from rules
│   │   └── filter_rules.py      # Filter rules by properties
│   │
│   ├── run_attack_eval.py       # Run attack evaluation
│   └── improve_splunk_queries.py # Improve Splunk queries
│
├── data/                         # Data directory
│   ├── rules/                    # Sigma rules
│   │   └── windows/
│   │       └── process_creation/ # Process creation rules
│   ├── events/                   # Event data
│   │   └── windows/
│   │       └── process_creation/ # Process creation events
│   └── evasion_possible_rules.txt # Rules to process
│
├── output/                       # Output directory
│   ├── improved_queries/         # Enhanced Splunk queries
│   ├── logs/                     # Execution logs
│   └── results/                  # Analysis results
│
├── paper/                        # Research paper
│   └── usenixsecurity24-uetz.pdf # Original paper
│
├── example_rules/                # Example Sigma rules
├── README.md                     # Project documentation
└── .gitignore                    # Git ignore file
```

### Running the Tools

1. **Prepare Input Files**
   ```bash
   # Place Sigma rules in:
   data/rules/windows/process_creation/
   
   # Place event samples in:
   data/events/windows/process_creation/
   
   # Create evasion_possible_rules.txt in data/ directory
   # List rule names (without .yml) to process
   ```

2. **Generate Attack Commands**
   ```bash
   # From project root
   set PYTHONPATH=%CD%
   python -m src.attack_convert.main
   ```
   Output: `src/attack_convert/Evasion-Results/*.json`

3. **Convert Sigma Rules to Splunk Queries**
   ```bash
   # From project root
   set PYTHONPATH=%CD%
   python -m src.query_convert.sigma_to_splunk.sigma_to_splunk
   ```
   Output: `src/query_convert/sigma_to_splunk/output_queries/*.spl`

4. **Run Attack Evaluation**
   ```bash
   # From project root
   set PYTHONPATH=%CD%
   python src/run_attack_eval.py
   ```
   Output: `output/logs/*.jsonl` and `output/logs/global_detection_log.txt`

5. **Generate Improved Queries**
   ```bash
   # From project root
   set PYTHONPATH=%CD%
   python src/improve_splunk_queries.py
   ```
   Output: `output/improved_queries/*.spl`

6. **Utility Tools**
   ```bash
   # Extract filters from rules
   python src/tools/all_filters.py
   # Output: output/results/extracted_filters.txt
   
   # Filter rules by properties
   python src/tools/filter_rules.py
   # Output: data/evasion_possible_rules.txt
   ```

### Output Files
- `src/attack_convert/Evasion-Results/*.json`: Generated attack commands
- `src/query_convert/sigma_to_splunk/output_queries/*.spl`: Original Splunk queries
- `output/improved_queries/*.spl`: Enhanced Splunk queries
- `output/logs/*.jsonl`: Detailed execution logs
- `output/logs/global_detection_log.txt`: Summary of all detection results
- `output/results/extracted_filters.txt`: Extracted filters from rules

## Acknowledgments
This project implements the first three parts of the research paper "Adaptive Misuse Detection for SIEM Rules" presented at the 33rd USENIX Security Symposium (2024). The paper can be found in the `paper/` directory.

Our implementation focuses on:
1. Analysis of SIEM rules for evasions
2. Automatic generation of original attacks and evasion techniques
3. Conversion and improvement of Splunk queries

The paper's full content, including additional research on adaptive misuse detection, can be found in `paper/usenixsecurity24-uetz.pdf`.

## Contributing
We welcome contributions to improve the detection capabilities and add support for additional evasion techniques.