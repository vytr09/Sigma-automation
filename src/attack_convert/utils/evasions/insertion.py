import random
import re
import string

def generate_random_noise(length: int = 1) -> str:
    """
    Tạo các ký tự nhiễu ngẫu nhiên an toàn để chèn vào lệnh.
    Các ký tự này thường bị bỏ qua bởi cmd.exe hoặc PowerShell trong các ngữ cảnh nhất định.
    """
    # Ký tự `^` là escape character trong cmd, thường bị bỏ qua nếu không có ý nghĩa đặc biệt.
    # Ký tự `,` và `;` có thể bị bỏ qua hoặc hiểu sai trong một số ngữ cảnh đối với Sigma rules.
    # Các ký tự khoảng trắng đặc biệt như tab (\\t), null (\\x00), backspace (\\x08) cũng có thể dùng.
    safe_chars = ["^", ",", ";"] # Thêm các ký tự mà CMD thường bỏ qua
    return ''.join(random.choice(safe_chars) for _ in range(length))

def is_safe_insertion(command: str, insertion: str) -> bool:
    """
    Kiểm tra xem việc chèn có giữ nguyên chức năng của lệnh hay không.
    Kiểm tra này là heuristic và không đảm bảo 100% lệnh vẫn hoạt động.
    """
    # Không tạo ra chuỗi rỗng
    if not insertion.strip():
        return False
    # Kiểm tra dấu nháy: số lượng dấu nháy phải là chẵn
    if insertion.count('"') % 2 != 0:
        return False
    # Tránh chèn các ký tự có thể phá vỡ pipe, redirect hoặc thực thi lệnh kép
    if re.search(r'[<>|&]', insertion):
        return False
    # Tránh các chuỗi rỗng giữa các token quan trọng (trừ khi cố ý thêm khoảng trắng)
    if "  " in insertion and not " " in command: # Hạn chế khoảng trắng không mong muốn
        pass # Có thể cho phép nhiều khoảng trắng nếu đó là chiến lược

    # Thêm các kiểm tra cụ thể hơn nếu có các trường hợp lỗi thường gặp
    return True

def insert_noise_characters(word: str) -> str:
    """
    Chèn các ký tự nhiễu ngẫu nhiên giữa các ký tự của một từ.
    Ví dụ: 'net' -> 'n^e^t'
    """
    if len(word) < 2:
        return word
    result = ""
    for char in word:
        result += char
        if random.random() < 0.5: # 50% cơ hội chèn nhiễu
            result += generate_random_noise(1) # Chèn 1 ký tự nhiễu
    return result

def insert_random_spaces(word: str) -> str:
    """
    Chèn ngẫu nhiên một hoặc nhiều khoảng trắng giữa các ký tự của một từ.
    Ví dụ: 'net' -> 'n e t' hoặc 'n  e   t'
    """
    if len(word) < 2:
        return word
    result = ""
    for char in word:
        result += char
        if random.random() < 0.5: # 50% cơ hội chèn khoảng trắng
            result += " " * random.randint(1, 3) # Chèn 1-3 khoảng trắng
    return result

def generate_insertions(command: str) -> list[str]:
    """
    Tạo nhiều biến thể né tránh bằng cách chèn ký tự và sử dụng dấu nháy.
    Các kỹ thuật này bao gồm:
    1. Chèn ký tự nhiễu ngẫu nhiên.
    2. Chèn khoảng trắng ngẫu nhiên.
    3. Thêm dấu nháy kép xung quanh toàn bộ path.
    4. Thêm dấu nháy kép xung quanh từng phần tử của path (file/folder).
    5. Chèn dấu nháy thoát (escaped quotes) xung quanh path.
    6. Thêm dấu nháy kép xung quanh đối số.
    7. Thêm dấu nháy kép quanh từng ký tự của đối số (nếu hợp lệ).
    8. Chèn dấu nháy thoát quanh đối số.
    """
    if not command:
        return []

    insertions = []
    tokens = command.split()
    if not tokens:
        return []

    # Danh sách các hàm biến đổi có thể áp dụng cho từng token
    token_transforms = [
        insert_noise_characters,
        insert_random_spaces,
    ]

    # --- Chiến lược tổng quát: Áp dụng noise/spaces cho từng token ---
    for i in range(len(tokens)):
        original_token = tokens[i]
        for transform_func in token_transforms:
            temp_tokens = tokens.copy()
            transformed_token = transform_func(original_token)
            if transformed_token != original_token: # Chỉ thêm nếu có sự thay đổi
                temp_tokens[i] = transformed_token
                new_cmd = " ".join(temp_tokens)
                if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                    insertions.append(new_cmd)

    # --- Chiến lược Path (dành cho các token chứa '\') ---
    for i in range(len(tokens)):
        if '\\' in tokens[i]:
            original_path = tokens[i]

            # 1. Dấu nháy kép quanh toàn bộ path
            temp_tokens = tokens.copy()
            temp_tokens[i] = f'"{original_path}"'
            new_cmd = " ".join(temp_tokens)
            if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                insertions.append(new_cmd)

            # 2. Dấu nháy kép quanh từng phần tử của filename (nếu có dấu chấm)
            if '.' in original_path:
                parts = original_path.split('\\')
                filename = parts[-1]
                path_prefix = '\\'.join(parts[:-1])
                
                # Biến đổi filename
                quoted_filename_chars = ''.join(f'"{c}"' for c in filename)
                
                # Ghép lại path: path_prefix + '\' + quoted_filename_chars
                transformed_path = f'{path_prefix}\\{quoted_filename_chars}' if path_prefix else quoted_filename_chars
                
                temp_tokens = tokens.copy()
                temp_tokens[i] = transformed_path
                new_cmd = " ".join(temp_tokens)
                if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                    insertions.append(new_cmd)

            # 3. Dấu nháy thoát (escaped quotes) quanh toàn bộ path
            temp_tokens = tokens.copy()
            temp_tokens[i] = f'\\"{original_path}\\"'
            new_cmd = " ".join(temp_tokens)
            if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                insertions.append(new_cmd)

    # --- Chiến lược Argument/Command part (dành cho token không phải là path) ---
    for i in range(len(tokens)):
        original_arg = tokens[i]
        
        # Bỏ qua nếu là path đã xử lý ở trên
        if '\\' in original_arg:
            continue

        # 1. Dấu nháy kép quanh đối số
        temp_tokens = tokens.copy()
        temp_tokens[i] = f'"{original_arg}"'
        new_cmd = " ".join(temp_tokens)
        if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
            insertions.append(new_cmd)

        # 2. Dấu nháy kép quanh từng ký tự của đối số (chỉ nếu độ dài lớn hơn 1 để tránh "a" -> ""a"")
        if len(original_arg) > 1:
            temp_tokens = tokens.copy()
            temp_tokens[i] = ''.join(f'"{c}"' for c in original_arg)
            new_cmd = " ".join(temp_tokens)
            if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                insertions.append(new_cmd)

        # 3. Dấu nháy thoát (escaped quotes) quanh đối số
        temp_tokens = tokens.copy()
        temp_tokens[i] = f'\\"{original_arg}\\"'
        new_cmd = " ".join(temp_tokens)
        if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
            insertions.append(new_cmd)
        
        # 4. Dấu nháy thoát quanh từng ký tự của đối số (chỉ nếu độ dài lớn hơn 1)
        if len(original_arg) > 1:
            temp_tokens = tokens.copy()
            temp_tokens[i] = ''.join(f'\\"{c}\\"' for c in original_arg)
            new_cmd = " ".join(temp_tokens)
            if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                insertions.append(new_cmd)
                
        # 5. Chèn dấu nháy vào giữa từ (nếu từ đủ dài)
        if len(original_arg) > 2:
            mid = len(original_arg) // 2
            # Nháy nửa đầu
            temp_tokens = tokens.copy()
            temp_tokens[i] = f'"{original_arg[:mid]}"{original_arg[mid:]}'
            new_cmd = " ".join(temp_tokens)
            if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                insertions.append(new_cmd)
            
            # Nháy nửa sau
            temp_tokens = tokens.copy()
            temp_tokens[i] = f'{original_arg[:mid]}"{original_arg[mid:]}"'
            new_cmd = " ".join(temp_tokens)
            if is_safe_insertion(command, new_cmd) and new_cmd not in insertions:
                insertions.append(new_cmd)

    return insertions

def evasive_insertion(command: str) -> str:
    """
    Trả về một lệnh né tránh được tạo ra bằng kỹ thuật chèn ngẫu nhiên.
    """
    evasions = generate_insertions(command)
    # Loại bỏ các lệnh trùng lặp trước khi chọn ngẫu nhiên
    evasions = list(set(evasions)) 
    return random.choice(evasions) if evasions else command