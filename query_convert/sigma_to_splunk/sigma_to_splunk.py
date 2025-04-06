import os
import yaml
import re

# Thư mục chứa file .yml
input_dir = 'input_rules'
# Thư mục để lưu truy vấn Splunk sau khi convert
output_dir = 'output_queries'

# Tạo thư mục output nếu chưa có
os.makedirs(output_dir, exist_ok=True)

# Mapping tên trường trong Sigma sang Splunk
field_mappings = {
    "process.executable": "New_Process_Name",
    "process.command_line": "Process_Command_Line",
    "user.name": "user.name",
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


def convert_filter_to_splunk(filter_str):

    # Ghép chuỗi lại thành một dòng
    filter_str = filter_str.replace('\n', ' ').replace('\r', ' ')
    filter_str = re.sub(r'\s+', ' ', filter_str)  # loại bỏ khoảng trắng thừa

    # Mapping các trường
    field_mappings = {
        "process.executable": "New_Process_Name",
        "process.command_line": "Process_Command_Line",
        "user.name": "user.name",
    }

    for sigma_field, splunk_field in field_mappings.items():
        filter_str = filter_str.replace(sigma_field, splunk_field)

    # Thay AND thành | search
    filter_str = filter_str.replace("AND", "| search")

    # # Bước xử lý OR trong các chuỗi có dấu ngoặc: field=(val1 OR val2)
    # def convert_or_block_to_in(match):
    #     field = match.group(1)
    #     or_values = match.group(2)
    #     values = [v.strip().strip('"') for v in or_values.split("OR")]
    #     quoted_values = ', '.join([f'"{v}"' for v in values])
    #     return f'{field} IN ({quoted_values})'

    # filter_str = re.sub(r'(\b[\w\.]+)=\(([^()]+)\)', convert_or_block_to_in, filter_str)

    def replace_field_value(match):
        field = match.group(1)
        quoted_val = match.group(2)
        grouped_val = match.group(3)

        if quoted_val:
            return f'{field}="{quoted_val}"'
        elif grouped_val:
            return f'{field}=({grouped_val})'
        else:
            return match.group(0)  # fallback

    # Chuyển field: "value" → field="value"
    filter_str = re.sub(r'(\b[\w\.]+):\s*(?:"(.*?)"|\((.*?)\))', replace_field_value, filter_str)

    # # Xử lý OR và loại bỏ dấu ngoặc ()
    # def expand_or_clauses(filter_str):
    #     or_pattern = re.compile(r'(\b[\w\.]+)=\((.*?)\)')

    #     def replace_or(match):
    #         field = match.group(1)
    #         values_str = match.group(2)
    #         values = [v.strip().strip('"') for v in values_str.split("OR")]
    #         expanded = ' OR '.join([f'{field}="{v}"' for v in values])
    #         return expanded

    #     return or_pattern.sub(replace_or, filter_str)

    # filter_str = expand_or_clauses(filter_str)

    # Bước xử lý OR trong các chuỗi có dấu ngoặc: field=(val1 OR val2)
    def convert_or_block_to_in(match):
        field = match.group(1)
        or_values = match.group(2)
        values = [v.strip().strip('"') for v in or_values.split("OR")]
        quoted_values = ', '.join([f'"{v}"' for v in values])
        return f'{field} IN ({quoted_values})'

    filter_str = re.sub(r'(\b[\w\.]+)=\(([^()]+)\)', convert_or_block_to_in, filter_str)

    # Xử lý đặc biệt cho cụm như: netsh wlan s* p* k*=clear → thêm * sau mỗi từ chưa có * và không phải biểu thức gán
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

    # Bỏ điều kiện Process_Command_Line nếu chỉ chứa "*.đuôi*"
    search_blocks = filter_str.split("| search")
    new_blocks = []

    for block in search_blocks:
        block = block.strip()
        if not block:
            continue

        if "Process_Command_Line=" in block:
            values = re.findall(r'Process_Command_Line="([^"]+)"', block)
            if all(re.match(r'^\*\.[a-zA-Z0-9]+\*$', v) for v in values):
                continue  # Bỏ khối này

        elif "Process_Command_Line IN" in block:
            # Kiểm tra các giá trị trong IN
            values = re.findall(r'Process_Command_Line\s*IN\s*\(([^)]+)\)', block)
            flattened_values = []

            for group in values:
                # Tách các giá trị trong IN(...)
                flattened_values.extend([v.strip().strip('"') for v in group.split(',')])

            # Nếu TẤT CẢ các giá trị đều là "*.đuôi*", thì bỏ khối này
            if flattened_values and all(re.match(r'^\*\.[a-zA-Z0-9]+\*$', v) for v in flattened_values):
                continue

        new_blocks.append(block)

    filter_str = " | search ".join(new_blocks)

    # Escape backslash
    filter_str = re.sub(r'(?<!\\)\\(?![\\"])', r'\\\\', filter_str)

    return filter_str


# Lặp qua tất cả các file .yml trong thư mục input
for filename in os.listdir(input_dir):
    if filename.endswith(".yml"):
        yml_path = os.path.join(input_dir, filename)

        with open(yml_path, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)

        filter_str = content.get("filter", "")
        if not filter_str:
            print(f"[!] Không tìm thấy filter trong file {filename}")
            continue

        # Chuyển filter sang Splunk query
        converted_filter = convert_filter_to_splunk(filter_str)

        # Tạo truy vấn Splunk đầy đủ
        full_query = (
            'index=* sourcetype="WinEventLog:Security" EventCode=4688\n'
            f'| search {converted_filter}\n'
            '| table _time, New_Process_Name, Process_Command_Line'
        )

        # Ghi kết quả ra file .spl
        query_filename = os.path.splitext(filename)[0] + '.spl'
        output_path = os.path.join(output_dir, query_filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_query)

        print(f"[✓] Đã convert: {filename} → {query_filename}")