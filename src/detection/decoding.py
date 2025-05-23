# src/detection/decoding.py

import base64

def decode_base64_string(b64_string: str, encoding_hint: str | None = None) -> str:
    """
    Giải mã chuỗi base64, theo encoding hint (utf8, utf16le, hoặc None).
    Nếu không có hint, thử tự đoán.
    """
    try:
        decoded_bytes = base64.b64decode(b64_string)

        if encoding_hint == "utf8":
            return decoded_bytes.decode("utf-8")

        if encoding_hint == "utf16le":
            return decoded_bytes.decode("utf-16le")

        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return decoded_bytes.decode("utf-16le")

    except Exception as e:
        return f"[DecodeError] Cannot decode: {e}"


def guess_encoding_type(command_line: str) -> str:
    """
    Dự đoán encoding dùng trong dòng lệnh.
    """
    if "-EncodedCommand" in command_line:
        return "utf16le"
    if "UTF8.GetString" in command_line:
        return "utf8"
    return "unknown"
