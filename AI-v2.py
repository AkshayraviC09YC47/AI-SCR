#!/usr/bin/env python3
"""
scan_to_json.py

Scans a folder recursively, sends each source file to the Ollama model via CLI,
and requests strict JSON output describing vulnerabilities.

Outputs:
 - Per-file JSON results saved to <INPUT_FOLDER>/SCR-SCANNER-RESULT/RESULT__<path>.json
 - Combined pretty JSON report: <INPUT_FOLDER>/vulnerability_report.json
"""

import os
import argparse
import subprocess
import json
import re
from collections import Counter

# === CONFIG ===
MODEL_NAME = "rohits/codellama_finetuned:latest"
SKIP_EXTENSIONS = [
    ".html", ".css", ".md", ".txt", ".json",
    ".jpg", ".png", ".gif", ".ico", ".svg", ".git"
]
RESULTS_SUBFOLDER = "SCR-SCANNER-RESULT"
CHUNK_SIZE = 16000  # chars per chunk (if you want chunking; kept for future use)
# ==================


def should_skip(file_name: str) -> bool:
    return any(file_name.lower().endswith(ext) for ext in SKIP_EXTENSIONS)


def get_code_files(folder: str):
    files_to_scan = []
    for root, dirs, files in os.walk(folder):
        # skip hidden dirs like .git
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            if should_skip(file):
                continue
            full = os.path.join(root, file)
            if os.path.isfile(full):
                files_to_scan.append(full)
    return files_to_scan


def sanitize_filename(base_folder: str, file_path: str) -> str:
    relative_path = os.path.relpath(file_path, base_folder)
    # replace path separators and problematic characters
    safe = re.sub(r'[^0-9A-Za-z._-]', '_', relative_path)
    return f"RESULT__{safe}.json"


def build_prompt(file_path: str, code: str) -> str:
    """
    Prompt asks the model to produce a strict JSON array of vulnerability objects.
    Each object must include the fields:
      - file
      - Vulnerability Title
      - Vulnerable Code line number
      - Mitigation
    If no issues are found, return an empty array [].
    """
    prompt = f"""
You are a cybersecurity expert specializing in automated source code vulnerability detection.
Analyze the following source code in file: "{file_path}"

REPLY STRICTLY in JSON ONLY — nothing else (no prose).
Return a JSON ARRAY. Each element must be an object with these exact keys:
  - "file" : full path to the file (string)
  - "Vulnerability Title" : short title (string)
  - "Vulnerable Code line number" : a line range string like "27-39" or a single line "42" (string)
  - "Mitigation" : brief mitigation steps (string)

If there are multiple vulnerabilities, include one object per vulnerability.
If there are NO vulnerabilities, return an empty JSON array: []

EXAMPLE output (exact schema):
[
  {{
    "file": "{file_path}",
    "Vulnerability Title": "SQL Injection",
    "Vulnerable Code line number": "27-39",
    "Mitigation": "Use parameterized queries and input validation."
  }}
]

Now analyze and produce the JSON array for this file's code. Do NOT include any extra text before or after the JSON.

--- FILE START ---
{code}
--- FILE END ---
"""
    return prompt.strip()


def run_ollama_cli(prompt: str) -> str:
    """Run 'ollama run <model> "<prompt>"' via subprocess and capture stdout."""
    try:
        # Note: passing prompt as an argument; ensure it's not too huge for the shell.
        # For extremely large files, consider writing prompt to a temp file and piping.
        proc = subprocess.run(
            ["ollama", "run", MODEL_NAME, prompt],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode != 0:
            # return stderr for debugging
            return f"[ERROR_CLI] returncode={proc.returncode} stderr={proc.stderr.strip()}"
        return proc.stdout.strip()
    except FileNotFoundError:
        return "[ERROR_CLI] 'ollama' CLI not found. Ensure ollama is installed and on PATH."
    except Exception as e:
        return f"[ERROR_CLI] Exception running ollama: {e}"


def extract_json_from_text(text: str):
    """
    Try to find JSON array/object in text. Return Python object or None.
    Best-effort: locate first '[' ... ']' and parse, else locate first '{' ... '}'.
    """
    text = text.strip()
    # Direct parse attempt
    try:
        return json.loads(text)
    except Exception:
        pass

    # Find JSON array
    m = re.search(r'(\[.*\])', text, flags=re.S)
    if m:
        candidate = m.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Find first JSON object
    m2 = re.search(r'(\{.*\})', text, flags=re.S)
    if m2:
        candidate = m2.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            pass

    return None


def scan_file_and_save(base_folder: str, results_folder: str, file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            code = fh.read()
    except Exception as e:
        print(f"[!] Unable to read {file_path}: {e}")
        return None

    prompt = build_prompt(file_path, code)
    print(f"[INFO] Running model for: {file_path}")
    raw_out = run_ollama_cli(prompt)

    # Try to parse JSON
    parsed = extract_json_from_text(raw_out)

    if parsed is None:
        # fallback: if the model returned "No issues found." or similar, treat as empty array
        if re.search(r'no (issues|vulnerabilities) found', raw_out, flags=re.I):
            parsed = []
        else:
            # As last resort, write the raw text into the 'result' field
            parsed = [{
                "file": file_path,
                "Vulnerability Title": "PARSING_FAILED",
                "Vulnerable Code line number": "",
                "Mitigation": f"Model output could not be parsed as JSON. Raw output captured under 'raw_output'.",
                "raw_output": raw_out
            }]

    # Ensure result is always a list
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        # unexpected type, wrap
        parsed = [{"file": file_path, "Vulnerability Title": "INVALID_FORMAT", "Vulnerable Code line number": "", "Mitigation": "", "raw_output": str(parsed)}]

    # Normalize each entry to have the required keys; fill file if missing
    normalized = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        normalized_item = {
            "file": item.get("file", file_path),
            "Vulnerability Title": item.get("Vulnerability Title", item.get("title", "") or "UNKNOWN"),
            "Vulnerable Code line number": item.get("Vulnerable Code line number", item.get("lines", "") or ""),
            "Mitigation": item.get("Mitigation", item.get("mitigation", "") or "")
        }
        # preserve extras if present
        for k in item:
            if k not in normalized_item:
                normalized_item[k] = item[k]
        normalized.append(normalized_item)

    # Save per-file JSON
    result_filename = sanitize_filename(base_folder, file_path)
    out_path = os.path.join(results_folder, result_filename)
    try:
        with open(out_path, "w", encoding="utf-8") as outf:
            json.dump(normalized, outf, indent=2)
    except Exception as e:
        print(f"[!] Failed to write result for {file_path}: {e}")

    return normalized


def main():
    parser = argparse.ArgumentParser(description="AI scanner -> JSON output")
    parser.add_argument("--folder", required=True, help="Path to source folder to scan")
    args = parser.parse_args()

    input_folder = os.path.abspath(args.folder)
    if not os.path.isdir(input_folder):
        print(f"[FATAL] folder not found: {input_folder}")
        return

    results_folder = os.path.join(input_folder, RESULTS_SUBFOLDER)
    os.makedirs(results_folder, exist_ok=True)

    files = get_code_files(input_folder)
    if not files:
        print("[!] No files found for scanning.")
        return

    # Report summary of extensions
    exts = [os.path.splitext(f)[1] for f in files]
    ext_counter = Counter(exts)
    print(f"[+] Found {len(files)} files. Extensions: {', '.join(ext_counter.keys())}")

    combined_results = []

    for idx, fpath in enumerate(files, start=1):
        print(f"[+] ({idx}/{len(files)}) scanning: {fpath}")
        res = scan_file_and_save(input_folder, results_folder, fpath)
        if res:
            combined_results.extend(res)

    # Write combined pretty JSON
    combined_path = os.path.join(input_folder, "vulnerability_report.json")
    try:
        with open(combined_path, "w", encoding="utf-8") as cf:
            json.dump(combined_results, cf, indent=2)
        print(f"[+] Combined report written to: {combined_path}")
    except Exception as e:
        print(f"[!] Failed to write combined report: {e}")


if __name__ == "__main__":
    main()
