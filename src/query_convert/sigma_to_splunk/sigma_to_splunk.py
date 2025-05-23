import os
import yaml
import re

# # Thư mục chứa file .yml
# input_dir = 'input_rules'
# # Thư mục để lưu truy vấn Splunk sau khi convert
# output_dir = 'output_queries'

# # Tạo thư mục output nếu chưa có
# os.makedirs(output_dir, exist_ok=True)

# Get the project root directory (go up one more level from src)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

events_dir = os.path.join(BASE_DIR, "data", "events", "windows", "process_creation")
rules_dir = os.path.join(BASE_DIR, "data", "rules", "windows", "process_creation")
output_dir = os.path.join(BASE_DIR, "src", "query_convert", "sigma_to_splunk", "output_queries")

# Debug: In ra các đường dẫn để kiểm tra
print(f"Base directory: {BASE_DIR}")
print(f"Rules directory: {rules_dir}")
print(f"Events directory: {events_dir}")
print(f"Output directory: {output_dir}")

os.makedirs(output_dir, exist_ok=True)

# Mapping tên trường trong Sigma sang Splunk
field_mappings = {
    "process.executable": "New_Process_Name",
    "process.command_line": "Process_Command_Line",
    "user.name": "user.name",
    "process.parent.executable": "Parent_Process_Name",
    "process.parent.command_line": "Parent_Process_Command_Line",
    "process.current_directory": "Current_Directory",
    "process.integrity_level": "Process_Integrity_Level",
    "process.creation_time": "Process_Creation_Time",
    "process.id": "Process_ID",
    "process.parent.id": "Parent_Process_ID",
    "process.parent.creation_time": "Parent_Process_Creation_Time",
    "process.parent.integrity_level": "Parent_Process_Integrity_Level",
    "process.parent.current_directory": "Parent_Current_Directory"
}

def enhance_netsh_pattern(value):
    if "netsh" in value and "k*=clear" in value:
        words = value.split()
        new_words = []
        for i, word in enumerate(words):
            if "*" in word:
                new_words.append(word)
            else:
                # Nếu từ sau có chứa *, thì không thêm
                if i + 1 < len(words) and "*" in words[i + 1]:
                    new_words.append(word)
                else:
                    new_words.append(f"{word}*")
        return ' '.join(new_words)
    return value

def enhance_command_line_pattern(value):
    # Handle special cases for command line patterns
    if "netsh" in value:
        return enhance_netsh_pattern(value)
    elif "powershell" in value:
        # Preserve important PowerShell patterns
        value = re.sub(r'-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)', r'-enc \1', value)
        value = re.sub(r'-e(?:c)?\s+([A-Za-z0-9+/=]+)', r'-e \1', value)
        value = re.sub(r'-w(?:indowstyle)?\s+hidden', r'-w hidden', value)
        value = re.sub(r'-nop(?:rofile)?', r'-nop', value)
        value = re.sub(r'-noni(?:nteractive)?', r'-noni', value)
        value = re.sub(r'-nologo', r'-nologo', value)
        value = re.sub(r'-ep(?:executionpolicy)?\s+bypass', r'-ep bypass', value)
    elif "cmd" in value:
        # Preserve important CMD patterns
        value = re.sub(r'/c\s+([^"]+)', r'/c \1', value)
        value = re.sub(r'/k\s+([^"]+)', r'/k \1', value)
    elif "reg" in value:
        # Preserve important REG patterns
        value = re.sub(r'add\s+([^"]+)', r'add \1', value)
        value = re.sub(r'delete\s+([^"]+)', r'delete \1', value)
        value = re.sub(r'query\s+([^"]+)', r'query \1', value)
    elif "wmic" in value:
        # Preserve important WMIC patterns
        value = re.sub(r'process\s+call\s+create', r'process call create', value)
        value = re.sub(r'product\s+where\s+name', r'product where name', value)
    elif "schtasks" in value:
        # Preserve important SCHTASKS patterns
        value = re.sub(r'/create\s+([^"]+)', r'/create \1', value)
        value = re.sub(r'/delete\s+([^"]+)', r'/delete \1', value)
        value = re.sub(r'/query\s+([^"]+)', r'/query \1', value)
    
    # Handle wildcards more intelligently
    if "*" in value:
        parts = value.split()
        new_parts = []
        for i, part in enumerate(parts):
            if "*" in part:
                new_parts.append(part)
            else:
                # Check if next part has wildcard
                has_next_wildcard = i + 1 < len(parts) and "*" in parts[i + 1]
                if not has_next_wildcard and not part.endswith("="):
                    new_parts.append(part + "*")
                else:
                    new_parts.append(part)
        value = " ".join(new_parts)
    
    return value

def convert_filter_to_splunk(filter_str):
    # Ghép chuỗi lại thành một dòng
    filter_str = filter_str.replace('\n', ' ').replace('\r', ' ')
    filter_str = re.sub(r'\s+', ' ', filter_str)  # loại bỏ khoảng trắng thừa

    # Mapping các trường
    for sigma_field, splunk_field in field_mappings.items():
        filter_str = filter_str.replace(sigma_field, splunk_field)

    # Thay AND thành | search
    filter_str = filter_str.replace("AND", "| search")

    # Bước xử lý OR trong các chuỗi có dấu ngoặc: field=(val1 OR val2)
    def convert_or_block_to_in(match):
        field = match.group(1)
        or_values = match.group(2)

        # Split values while preserving quoted strings
        values = []
        current = ""
        in_quotes = False
        for char in or_values:
            if char == '"':
                in_quotes = not in_quotes
                current += char
            elif char == ' ' and not in_quotes:
                if current.strip():
                    values.append(current.strip())
                current = ""
            else:
                current += char
        if current.strip():
            values.append(current.strip())

        # Clean up values
        values = [v.strip().strip('"') for v in values if v.strip()]
        
        # Handle special cases for command line patterns
        if field == "Process_Command_Line":
            values = [enhance_command_line_pattern(v) for v in values]
        elif field == "New_Process_Name":
            # Handle executable patterns
            values = [v.replace("*", ".*") for v in values]

        quoted_values = ', '.join([f'"{v}"' for v in values])
        return f'{field} IN ({quoted_values})'

    # Process OR blocks
    filter_str = re.sub(r'([\w\.]+):\s*\(\s*((?:.|\n)*?)\s*\)', convert_or_block_to_in, filter_str, flags=re.DOTALL)

    def replace_field_value(match):
        field = match.group(1)
        quoted_val = match.group(2)
        grouped_val = match.group(3)

        if quoted_val:
            if field == "Process_Command_Line":
                quoted_val = enhance_command_line_pattern(quoted_val)
            elif field == "New_Process_Name":
                quoted_val = quoted_val.replace("*", ".*")
            return f'{field}="{quoted_val}"'
        elif grouped_val:
            return f'{field}=({grouped_val})'
        else:
            return match.group(0)

    # Convert field: "value" → field="value"
    filter_str = re.sub(r'(\b[\w\.]+):\s*(?:"(.*?)"|\((.*?)\))', replace_field_value, filter_str)

    # Handle special command line patterns
    def process_special_command_line(s):
        pattern = re.compile(r'Process_Command_Line="([^"]+)"')

        def repl(match):
            cmd = match.group(1)
            if "*" in cmd and " " in cmd:
                parts = cmd.split()
                new_parts = []
                i = 0

                while i < len(parts):
                    part = parts[i]

                    # Nếu là phần tử có '=' thì giữ nguyên
                    if '=' in part or part.endswith('*'):
                        new_parts.append(part)
                    else:
                        # Kiểm tra các phần sau xem có phần nào bắt đầu bằng '*' không
                        has_star_soon = False
                        for j in range(i + 1, len(parts)):
                            if parts[j].startswith('*'):
                                has_star_soon = True
                                break
                        if has_star_soon:
                            new_parts.append(part)
                        else:
                            new_parts.append(part + '*')
                    i += 1

                return f'Process_Command_Line="{" ".join(new_parts)}"'
            return match.group(0)

        return pattern.sub(repl, s)
    
    filter_str = process_special_command_line(filter_str)

    # Remove blocks with only wildcard patterns
    search_blocks = filter_str.split("| search")
    new_blocks = []

    for block in search_blocks:
        block = block.strip()
        if not block:
            continue

        if "Process_Command_Line=" in block:
            values = re.findall(r'Process_Command_Line="([^"]+)"', block)
            if all(re.match(r'^\*\.[a-zA-Z0-9]+\*$', v) for v in values):
                continue

        elif "Process_Command_Line IN" in block:
            values = re.findall(r'Process_Command_Line\s*IN\s*\(([^)]+)\)', block)
            flattened_values = []
            for group in values:
                flattened_values.extend([v.strip().strip('"') for v in group.split(',')])
            if flattened_values and all(re.match(r'^\*\.[a-zA-Z0-9]+\*$', v) for v in flattened_values):
                continue

        new_blocks.append(block)

    filter_str = " | search ".join(new_blocks)

    # Escape backslash
    filter_str = re.sub(r'(?<!\\)\\(?![\\"])', r'\\\\', filter_str)

    return filter_str


# Duyệt thư mục events/windows/process_creation để tìm rule nào có evasion_possible: yes
# Tìm và convert rule
for rule_folder in os.listdir(events_dir):
    rule_path = os.path.join(events_dir, rule_folder)
    if not os.path.isdir(rule_path):
        continue

    # print(f"{rule_path}")

    properties_path = None
    for file in os.listdir(rule_path):
        # print(f"{file}")
        if file == "properties.yml":
            properties_path = os.path.join(rule_path, file)
            # print(f"{properties_path}")
            break
    if not properties_path:
        continue

    with open(properties_path, 'r', encoding='utf-8') as f:
        try:
            props = yaml.safe_load(f)
            # print(f"{props}")
        except Exception as e:
            print(f"[!] Lỗi đọc YAML: {properties_path}: {e}")
            continue

    if not isinstance(props.get("evasion_possible"), bool) or props["evasion_possible"] is not True:
        continue

    rule_file_path = os.path.join(rules_dir, rule_folder + '.yml')
    # print(f"{rule_file_path}")
    if not os.path.isfile(rule_file_path):
        continue

    # Đọc file rule (có thể là multi-document YAML)
    with open(rule_file_path, 'r', encoding='utf-8') as f:
        try:
            docs = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"[!] Lỗi đọc rule YAML: {rule_file_path}: {e}")
            continue

    converted = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        filter_str = doc.get("filter")
        if not filter_str:
            continue

        converted_filter = convert_filter_to_splunk(filter_str)
        full_query = (
            'index=* sourcetype="WinEventLog:Security" EventCode=4688\n'
            f'| search {converted_filter}\n'
            '| table _time, New_Process_Name, Process_Command_Line'
        )

        output_path = os.path.join(output_dir, rule_folder + '.spl')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_query)

        print(f"[✓] Đã convert: {rule_file_path} → {rule_folder}.spl")
        converted = True
        break

    if not converted:
        print(f"[!] Không tìm thấy filter hợp lệ trong: {rule_file_path}")
