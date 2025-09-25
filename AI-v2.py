#!/usr/bin/env python3
import os
import requests
import argparse
import json
from collections import Counter

# === CONFIG ===
MODEL_NAME = "rohits/codellama_finetuned:latest"
SKIP_EXTENSIONS = [
    ".html", ".css", ".md", ".txt", ".json",
    ".jpg", ".png", ".gif", ".ico", ".svg", ".git"
]
OLLAMA_API_URL = "http://127.0.0.1:11434/api/generate"


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


def sanitize_filename(base_folder, file_path):
    relative_path = os.path.relpath(file_path, base_folder)
    return "RESULT__" + relative_path.replace(os.sep, "_") + ".json"


def call_ollama(prompt):
    """Send prompt to Ollama model and stream JSON response"""
    payload = {"model": MODEL_NAME, "prompt": prompt, "stream": True}
    response_text = ""
    try:
        with requests.post(OLLAMA_API_URL, json=payload, stream=True) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line.decode("utf-8"))
                    if "response" in data:
                        response_text += data["response"]
        return response_text.strip()
    except Exception as e:
        print(f"[!] Ollama API call error: {e}")
        return ""


def scan_file(base_folder, results_folder, file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code_content = f.read()

        # Build structured prompt
        prompt = (
            "You are a cybersecurity expert specializing in automated source code vulnerability detection.\n"
            "Analyze the following source code and determine if it contains any security vulnerabilities.\n"
            "Answer strictly in ONE of the two formats ONLY, with NO extra explanation:\n\n"
            "IF VULNERABLE:\n"
            "Issue Title: <VULNERABILITY_NAME>\n"
            "Vulnerable code path: <FILE_PATH>\n"
            "**Vulnerable code**\n"
            "<EXACT_CODE_LINES_CAUSING_ISSUE>\n"
            "Severity: <CRITICAL/HIGH/MEDIUM/LOW>\n"
            "Remediation: <Brief fix advice>\n\n"
            "IF NOT VULNERABLE:\n"
            "No issues found.\n\n"
            f"Analyze this code from file '{file_path}':\n\n"
            f"{code_content}\n"
        )

        output = call_ollama(prompt)

        # Save individual result as JSON
        result_filename = sanitize_filename(base_folder, file_path)
        result_path = os.path.join(results_folder, result_filename)
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump({"file": file_path, "result": output}, f, indent=2)

    except Exception as e:
        print(f"[!] Error scanning {file_path}: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description="AI-based source code vulnerability scanner")
    parser.add_argument("--folder", required=True, help="Path to source code folder")
    args = parser.parse_args()

    input_folder = os.path.abspath(args.folder)
    results_folder = os.path.join(input_folder, "SCR-SCANNER-RESULT")
    os.makedirs(results_folder, exist_ok=True)

    files = get_code_files(input_folder)

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
        scan_file(input_folder, results_folder, file_path)

    print(f"[+] Vulnerability scan completed. Results saved in {results_folder}")


if __name__ == "__main__":
    main()
