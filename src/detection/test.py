from llm_decoder import query_ollama_llm

sample_command = 'powershell.exe -EncodedCommand cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAARABhAHQAYQBFAHgAYwBoAGEAbgBnAGUALgBkAGwAbAA='

# Gửi lệnh qua LLM
result = query_ollama_llm(sample_command)

# In ra kết quả
print("=== LLM OUTPUT ===")
print(result)
