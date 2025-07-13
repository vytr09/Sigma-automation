import re

def is_critical_process(command: str) -> bool:
    """Kiểm tra nếu lệnh chứa một tiến trình quan trọng không nên bị sửa đổi hậu tố .exe."""
    critical_processes = [
        r'powershell\.exe',
        r'cmd\.exe',
        r'regsvr32\.exe',
        r'xcopy\.exe',
        r'rundll32\.exe',
        r'msiexec\.exe', # Thêm msiexec
        r'schtasks\.exe' # Thêm schtasks
    ]
    return any(re.search(proc, command, re.IGNORECASE) for proc in critical_processes)

def is_critical_switch(switch: str) -> bool:
    """Kiểm tra nếu một switch là quan trọng và không nên bị loại bỏ hoàn toàn."""
    critical_switches = [
        r'-ep\s+bypass', # PowerShell ExecutionPolicy Bypass
        r'-noni',        # PowerShell NoNewItem
        r'-nop',         # PowerShell NoProfile
        r'-e(ncoded)?c(ommand)?', # PowerShell EncodedCommand
        r'/s\b',         # Switches like /s for silent, recursive, etc.
        r'/i\b',         # Interactive/install
        r'/c\b',         # CMD /C (run command and exit)
        r'/q\b',         # Quiet mode
        r'/h\b',         # Help switch (often benign but can be critical in some contexts)
        r'/?',           # Help switch (very common)
        r'/f\b',         # Force (e.g., del /f)
        r'-w\b',         # Wait (e.g., start -w)
        r'start',        # "start" command itself can act as a switch context
        r'runas'         # "runas" command
    ]
    # Sử dụng re.match để đảm bảo khớp từ đầu switch, và word boundary \b
    return any(re.match(sw, switch, re.IGNORECASE) for sw in critical_switches)

def is_critical_path(path: str) -> bool:
    """Kiểm tra nếu một đường dẫn là quan trọng và không nên bị loại bỏ."""
    critical_paths = [
        r'\\Windows\\Caches\\',
        r'\\AppData\\Roaming\\MICROS\\',
        r'DataExchange\.dll',
        r'NavShExt\.dll',
        r'C:\\ProgramData\\', # Đường dẫn ProgramData thường chứa malware
        r'\\Temp\\',          # Thư mục tạm thời
        r'\.tmp\b',           # File .tmp
        r'\\Users\\Public\\'  # Đường dẫn public user
    ]
    return any(re.search(p, path, re.IGNORECASE) for p in critical_paths)

def is_special_case(command: str) -> bool:
    """Kiểm tra nếu lệnh là một trường hợp đặc biệt cần xử lý riêng hoặc không nên bị sửa đổi."""
    special_patterns = [
        r'\.exe\s+-ENCOD',                      # win_susp_powershell_enc_cmd pattern
        r'Microsoft\\Windows\\CurrentVersion\\Run', # win_malware_ryuk pattern
        r'regsvr32.*\.ocx',                     # win_apt_evilnum_jul20 pattern
        r'powershell.*\\AppData\\Roaming',      # win_susp_ps_appdata pattern
        r'certutil\s+-urlcache\s+-f\s+http',    # certutil download
        r'bitsadmin\s+/transfer',               # bitsadmin download
        r'mshta\s+http',                        # mshta download
        r'rundll32\s+javascript:'               # rundll32 JScript execution
    ]
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in special_patterns)


def evasive_omission(command: str) -> str:
    """
    Thực hiện né tránh bằng cách loại bỏ các yếu tố thường bị Sigma rules khớp,
    tập trung vào các loại bỏ cơ bản như phần mở rộng, nhưng bảo toàn các switch và thành phần quan trọng.
    """
    if not command:
        return "" # Trả về chuỗi rỗng thay vì None cho nhất quán

    initial_command = command.strip()
    modified_command = initial_command
    changes_made = False

    # --- Bước 1: Xử lý các trường hợp đặc biệt (ưu tiên cao nhất) ---
    # Nếu là trường hợp đặc biệt, thường thì không nên bỏ qua bất cứ thứ gì để đảm bảo chức năng
    # hoặc vì bản thân nó đã là một kỹ thuật né tránh.
    if is_special_case(initial_command):
        return initial_command

    # --- Bước 2: Loại bỏ phần mở rộng .exe, .dll, .vbs, .ps1, .bat, .cmd, .js ---
    # Chỉ loại bỏ nếu phần trước .exe không phải là một tiến trình quan trọng
    match_exe = re.search(r'([\w.-_]+?)\.exe\b', modified_command, re.IGNORECASE)
    if match_exe:
        process_name = match_exe.group(1)
        # Kiểm tra xem tên tiến trình có nằm trong danh sách các tiến trình quan trọng không.
        # Nếu không quan trọng (ví dụ: myapp.exe), hoặc nếu là cmd.exe/powershell.exe nhưng ta muốn bỏ .exe
        # thì thực hiện loại bỏ. Cần cẩn thận khi bỏ .exe của các process critical
        
        # Một cách tiếp cận an toàn hơn là chỉ bỏ .exe nếu nó không làm thay đổi ngữ nghĩa quá nhiều
        # hoặc nếu nó là một phần của chuỗi không phải là tên process trực tiếp.
        
        # Đối với các tiến trình quan trọng, chúng ta có thể không bỏ `.exe` hoặc chỉ bỏ nếu biết chắc là an toàn.
        # Ví dụ: `cmd.exe` -> `cmd` là an toàn. `powershell.exe` -> `powershell` là an toàn.
        # Ta cần một logic tinh tế hơn thay vì dùng `is_critical_process` để ngăn hoàn toàn.
        
        # Nếu tên tiến trình (không có .exe) khớp với một process critical
        # thì việc bỏ .exe thường là an toàn.
        if is_critical_process(process_name + ".exe"): # Kiểm tra tên process đầy đủ
            modified_command = re.sub(r'\.exe\b', '', modified_command, flags=re.IGNORECASE, count=1)
            changes_made = True
    else: # Nếu không tìm thấy .exe, thử các extension khác
        # Loại bỏ các extension script phổ biến
        old_command = modified_command
        modified_command = re.sub(r'\.(vbs|ps1|bat|cmd|js)\b', '', modified_command, flags=re.IGNORECASE)
        if modified_command != old_command:
            changes_made = True

    # --- Bước 3: Loại bỏ đường dẫn tuyệt đối (hoặc một phần) ---
    # Cần cẩn thận khi loại bỏ đường dẫn, chỉ loại bỏ nếu nó không quan trọng
    
    # 3a. C:\Windows\System32\
    if not is_critical_path(r'c:\\windows\\system32\\') or not re.search(r'c:\\windows\\system32\\', initial_command, re.IGNORECASE):
        old_command = modified_command
        modified_command = re.sub(r'c:\\windows\\system32\\', '', modified_command, flags=re.IGNORECASE)
        if modified_command != old_command:
            changes_made = True

    # 3b. C:\Windows\
    if not is_critical_path(r'c:\\windows\\') or not re.search(r'c:\\windows\\', initial_command, re.IGNORECASE):
        old_command = modified_command
        modified_command = re.sub(r'c:\\windows\\', '', modified_command, flags=re.IGNORECASE)
        if modified_command != old_command:
            changes_made = True

    # 3c. AppData\Roaming\
    # Đặc biệt cẩn thận với AppData, nó thường là chỉ báo của malware
    # Chỉ loại bỏ nếu nó không khớp với một critical path cụ thể
    if not is_critical_path(r'\.?\\?AppData\\Roaming\\') or not re.search(r'\.?\\?AppData\\Roaming\\', initial_command, re.IGNORECASE):
        old_command = modified_command
        modified_command = re.sub(r'\.?\\?AppData\\Roaming\\', '', modified_command, flags=re.IGNORECASE)
        if modified_command != old_command:
            changes_made = True
            
    # 3d. C:\Users\[User]\ (loại bỏ đường dẫn profile người dùng)
    old_command = modified_command
    modified_command = re.sub(r'c:\\users\\[^\\]+\\', '', modified_command, flags=re.IGNORECASE)
    if modified_command != old_command:
        changes_made = True

    # --- Bước 4: Loại bỏ dấu nháy không cần thiết quanh đối số hoặc path (nếu không làm hỏng lệnh) ---
    # Thử loại bỏ dấu nháy kép nếu chúng bao quanh toàn bộ một token
    # Ví dụ: "C:\Program Files\App\file.exe" -> C:\Program Files\App\file.exe
    
    # regex để tìm các chuỗi được bao quanh bởi dấu nháy kép và sau đó loại bỏ chúng
    # (chỉ khi chúng không có khoảng trắng bên trong sau khi loại bỏ)
    # Cần regex tinh tế hơn để không loại bỏ nhầm dấu nháy quan trọng
    
    # Đây là một chiến lược rủi ro, cần cân nhắc. Thường thì dấu nháy là cần thiết nếu có khoảng trắng.
    # Chỉ bỏ dấu nháy nếu token đó không chứa khoảng trắng và không bị ảnh hưởng.
    tokens = modified_command.split()
    temp_tokens = []
    for token in tokens:
        if token.startswith('"') and token.endswith('"'):
            inner_content = token[1:-1]
            if ' ' not in inner_content: # Chỉ bỏ nháy nếu không có khoảng trắng bên trong
                temp_tokens.append(inner_content)
                changes_made = True
            else:
                temp_tokens.append(token)
        else:
            temp_tokens.append(token)
    modified_command = " ".join(temp_tokens)


    # --- Bước 5: Chuẩn hóa khoảng trắng ---
    # Nén nhiều khoảng trắng thành một và loại bỏ khoảng trắng ở đầu/cuối
    old_command = modified_command
    modified_command = re.sub(r'\s+', ' ', modified_command).strip()
    if modified_command != old_command:
        changes_made = True

    # --- Bước 6: Trả về kết quả ---
    # Nếu có bất kỳ thay đổi nào được thực hiện, trả về lệnh đã sửa đổi.
    # Nếu không có thay đổi nào được thực hiện, trả về lệnh gốc.
    return modified_command if changes_made else initial_command

# Hàm này sẽ được gọi từ `generate_all_evasions` hoặc tương tự.
# Ví dụ về cách sử dụng:
# command1 = "C:\\Windows\\System32\\cmd.exe /c dir \"C:\\Program Files\""
# print(f"Original: {command1}")
# print(f"Omission: {evasive_omission(command1)}")

# command2 = "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\user\\script.ps1"
# print(f"Original: {command2}")
# print(f"Omission: {evasive_omission(command2)}")

# command3 = "regsvr32.exe /s C:\\AppData\\Roaming\\MICROS\\malware.dll"
# print(f"Original: {command3}")
# print(f"Omission: {evasive_omission(command3)}")

# command4 = "C:\\path\\to\\myapp.exe /arg1 /arg2"
# print(f"Original: {command4}")
# print(f"Omission: {evasive_omission(command4)}")

# command5 = "cmd.exe /c echo hello"
# print(f"Original: {command5}")
# print(f"Omission: {evasive_omission(command5)}")

# command6 = "powershell.exe -EncodedCommand SomeBase64String"
# print(f"Original: {command6}")
# print(f"Omission: {evasive_omission(command6)}")

