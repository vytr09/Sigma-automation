# src/detection/llm_decoder.py

import requests

def query_ollama_llm(command: str, model: str = "gemma3:4b") -> str:
    prompt = f"""
        "You are a decoding assistant. Decode this base64 or obfuscated command.\n"
        "Return ONLY the decoded command, no explanation, no formatting.\n"
        f"Command: {command}\n"
        "Decoded:"
    """

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get("response", "").strip()
        else:
            return f"❌ LLM Error: {response.text}"
    except Exception as e:
        return f"❌ Exception: {str(e)}"
