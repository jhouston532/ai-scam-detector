import requests
import json

def prompt_ollama_stream(prompt: str, model: str = "qwen2.5-coder:14b") -> str:
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": prompt, "stream": True},
        stream=True,
        timeout=120,
    )
    response.raise_for_status()

    full_response = ""
    for line in response.iter_lines():
        if line:
            chunk = json.loads(line)
            print(chunk["response"], end="", flush=True)
            full_response += chunk["response"]
            if chunk.get("done"):
                break

    return full_response
    