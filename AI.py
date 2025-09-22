#!/usr/bin/env python3
import os
import requests
from collections import Counter

# === CONFIG ===
MODEL_NAME = "rohits/codellama_finetuned:latest"
INPUT_FOLDER = "./Broken-Vulnerable-Code-Snippets"
RESULTS_FOLDER = os.path.join(INPUT_FOLDER, "SCR-SCANNER-RESULT")
SKIP_EXTENSIONS = [
    ".html", ".css", ".md", ".txt", ".json",
    ".jpg", ".png", ".gif", ".ico", ".svg", ".git"
]
OLLAMA_API_URL = "http://127.0.0.1:11434/v1/chat/completions"

PROMPT = """
Review this code for vulnerabilities and list all the security issues with highlighted vulnerable code
with a separate issue title and vulnerable code.
"""

def should_skip(file_name):
    return any(file_name.lower().endswith(ext) for ext in SKIP_EXTENSIONS)

def get_code_files(folder):
    files_to_scan = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            full_path = os.path.join(root, file)
            if os.path.isfile(full_path) and not should_skip(file):
                files_to_scan.append(full_path)
    return files_to_scan

def sanitize_filename(file_path):
    # Convert relative path to filename with underscores
    relative_path = os.path.relpath(file_path, INPUT_FOLDER)
    return "RESULT__" + relative_path.replace(os.sep, "_")

def scan_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code_content = f.read()

        data = {
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": f"{code_content}\n{PROMPT}"}],
            "max_tokens": 2000
        }

        headers = {"Content-Type": "application/json"}
        response = requests.post(OLLAMA_API_URL, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]

    except Exception as e:
        return f"Error scanning {file_path}: {str(e)}\n"

def main():
    # Ensure results folder exists
    os.makedirs(RESULTS_FOLDER, exist_ok=True)

    files = get_code_files(INPUT_FOLDER)
    
    if not files:
        print("[!] No files found for scanning.")
        return

    # Count extensions
    exts = [os.path.splitext(f)[1] for f in files]
    ext_counter = Counter(exts)
    ext_list = ','.join(ext_counter.keys())
    print(f"[+] Total {len(files)} file(s) identified with extensions: {ext_list}")

    for idx, file_path in enumerate(files, 1):
        print(f"[+] Started scanning on file {idx}/{len(files)}: {file_path}")
        output = scan_file(file_path)

        # Save individual result
        result_filename = sanitize_filename(file_path)
        result_path = os.path.join(RESULTS_FOLDER, result_filename)
        with open(result_path, "w", encoding="utf-8") as f:
            f.write(output)

    print(f"[+] Vulnerability scan completed. Individual results saved in {RESULTS_FOLDER}")

if __name__ == "__main__":
    main()
