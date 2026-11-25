import os
import re
from pathlib import Path
from typing import Any

LANG_EXTENSIONS = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++ Header",
    ".cs": "C#",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".phtml": "PHP",
    ".sh": "Shell Script",
    ".bash": "Shell Script",
    ".zsh": "Shell Script",
    ".ps1": "PowerShell",
    ".bat": "Batch Script",
    ".cmd": "Batch Script",
    ".rb": "Ruby",
    ".html": "HTML",
    ".htm": "HTML",
    ".sql": "SQL",
    ".sol": "Solidity",
    ".env": "Env Config",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".toml": "TOML",
    ".ini": "INI Config",
}

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".idea", ".vscode", "dist", "build", "target", "vendor"
}

# Security rules definition
SECURITY_RULES: list[dict[str, Any]] = [
    # 1. Hardcoded Secrets & Credentials
    {
        "id": "SEC-001",
        "title": "Hardcoded Private Key",
        "category": "Hardcoded Secrets",
        "severity": "CRITICAL",
        "description": "Found private cryptographic key in plaintext source code.",
        "regex": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", re.IGNORECASE),
    },
    {
        "id": "SEC-002",
        "title": "AWS Access Key",
        "category": "Hardcoded Secrets",
        "severity": "CRITICAL",
        "description": "Found hardcoded AWS Access Key ID.",
        "regex": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    },
    {
        "id": "SEC-003",
        "title": "Hardcoded API Key / Secret Token",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "description": "Detected hardcoded API secret, auth token or password assignment.",
        "regex": re.compile(r"""(?i)(?:api_key|apikey|secret_key|app_secret|auth_token|access_token|private_token|db_password|password)\s*[:=]\s*['"][a-zA-Z0-9_\-\.\$\!\#\%\^\&\*]{10,80}['"]"""),
    },
    {
        "id": "SEC-004",
        "title": "GitHub Token",
        "category": "Hardcoded Secrets",
        "severity": "CRITICAL",
        "description": "Detected hardcoded GitHub Personal Access Token or OAuth Secret.",
        "regex": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    },
    {
        "id": "SEC-005",
        "title": "Hardcoded JWT Token",
        "category": "Hardcoded Secrets",
        "severity": "MEDIUM",
        "description": "Found plaintext JSON Web Token (JWT) in source code.",
        "regex": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    },

    # 2. Dynamic Code Execution & Injection
    {
        "id": "INJ-001",
        "title": "Dangerous Dynamic Code Execution (eval/exec)",
        "category": "Code Injection",
        "severity": "HIGH",
        "description": "Use of eval(), exec(), or new Function() allows arbitrary code execution.",
        "regex": re.compile(r"\b(eval|exec|new\s+Function|compile)\s*\(", re.IGNORECASE),
    },
    {
        "id": "INJ-002",
        "title": "OS Command Execution",
        "category": "Command Injection",
        "severity": "HIGH",
        "description": "Spawning system shell commands directly (os.system, subprocess, shell_exec, exec).",
        "regex": re.compile(r"\b(os\.system|os\.popen|subprocess\.(call|Popen|run|check_output)|shell_exec|passthru|system|proc_open|Runtime\.getRuntime\(\)\.exec)\s*\(", re.IGNORECASE),
    },
    {
        "id": "INJ-003",
        "title": "Insecure Deserialization",
        "category": "Deserialization",
        "severity": "HIGH",
        "description": "Insecure deserialization of untrusted data (pickle, yaml without SafeLoader, unserialize).",
        "regex": re.compile(r"\b(pickle\.loads?|_pickle\.loads?|yaml\.load\s*\([^,)]+\)|unserialize)\s*\(", re.IGNORECASE),
    },

    # 3. Malware, Backdoors & Suspicious Network Activity
    {
        "id": "MAL-001",
        "title": "Reverse Shell / Interactive Shell Spawn",
        "category": "Backdoor / Malware",
        "severity": "CRITICAL",
        "description": "Interactive shell redirection commonly found in reverse shell payloads.",
        "regex": re.compile(r"(\/bin\/(ba)?sh\s+-i|pty\.spawn\s*\(\s*['\"]\/bin\/(ba)?sh['\"]|nc(\.traditional)?\s+-[a-zA-Z0-9]*e\s+\/bin\/(ba)?sh|socket\.socket.*connect.*\/bin\/(ba)?sh)", re.IGNORECASE),
    },
    {
        "id": "MAL-002",
        "title": "Obfuscated Base64 Execution",
        "category": "Obfuscation",
        "severity": "HIGH",
        "description": "Decoding Base64 data and immediately evaluating or executing it.",
        "regex": re.compile(r"(base64\.(b64)?decode.*(exec|eval)|(eval|exec).*base64\.(b64)?decode|eval\s*\(\s*Buffer\.from\(.*,\s*['\"]base64['\"]\)\.toString)", re.IGNORECASE),
    },
    {
        "id": "MAL-003",
        "title": "Suspicious Download and Execute",
        "category": "Malware Vector",
        "severity": "HIGH",
        "description": "Downloading remote content and piping directly into shell execution.",
        "regex": re.compile(r"(curl\s+-[sSL]*[^\n|]+\|\s*(ba)?sh|wget\s+-[qO\-]*[^\n|]+\|\s*(ba)?sh|urllib\.request\.urlretrieve|urllib\.request\.urlopen.*exec)", re.IGNORECASE),
    },
    {
        "id": "MAL-004",
        "title": "Sensitive System File Access",
        "category": "Information Disclosure",
        "severity": "MEDIUM",
        "description": "References to sensitive Linux or Windows credential files (/etc/shadow, /etc/passwd, SAM).",
        "regex": re.compile(r"(\/etc\/(shadow|passwd|sudoers)|\/var\/run\/docker\.sock|\.ssh\/id_rsa|C:\\Windows\\System32\\config\\SAM)", re.IGNORECASE),
    },
    {
        "id": "MAL-005",
        "title": "Raw Socket Connection / C2 Pattern",
        "category": "Network Backdoor",
        "severity": "MEDIUM",
        "description": "Creation of low-level sockets with hardcoded IP address or connection setup.",
        "regex": re.compile(r"(socket\.socket\s*\(.*AF_INET|s\.connect\s*\(\s*\(\s*['\"][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}['\"]\s*,\s*[0-9]+\s*\)\s*\))", re.IGNORECASE),
    },
]

def is_source_file(path: Path, filename: str | None = None) -> bool:
    target_name = filename if filename else path.name
    ext = Path(target_name).suffix.lower()
    name = Path(target_name).name.lower()
    return ext in LANG_EXTENSIONS or name in {".env", "dockerfile", "makefile"}

def get_language(path: Path, filename: str | None = None) -> str:
    target_name = filename if filename else path.name
    ext = Path(target_name).suffix.lower()
    name = Path(target_name).name.lower()
    if ext in LANG_EXTENSIONS:
        return LANG_EXTENSIONS[ext]
    if name == ".env":
        return "Env Config"
    if name in {"dockerfile", "makefile"}:
        return "Build Script"
    return "Unknown"

def evaluate_source_file(
    file_path: Path,
    rel_path: str,
    max_file_size: int = 1024 * 1024, # 1 MB limit per file
    filename: str | None = None
) -> dict[str, Any]:
    """Scan a single source file for LOC and security findings."""
    lang = get_language(file_path, filename=filename or rel_path)
    findings = []
    line_count = 0


    try:
        size = file_path.stat().st_size
        if size > max_file_size:
            return {"language": lang, "lines": 0, "findings": [], "skipped": "File too large"}

        # Read text, ignoring decode errors for binary/mixed files
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                line_count += 1
                clean_line = line.strip()
                if not clean_line or len(clean_line) > 1000:
                    continue

                # Ignore pure comment lines to avoid false alarms on docs or explanations
                if clean_line.startswith(("#", "//", "/*", "*")):
                    continue
                # Support inline SAST false-positive suppression markers
                if any(tag in clean_line for tag in ("# nosec", "# safe", "// nosec", "// safe", "/* nosec")):
                    continue

                for rule in SECURITY_RULES:
                    match = rule["regex"].search(clean_line)
                    if match:
                        snippet = clean_line[:120]
                        findings.append({
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "category": rule["category"],
                            "severity": rule["severity"],
                            "file": rel_path.replace("\\", "/"),
                            "line": idx,
                            "snippet": snippet,
                            "description": rule["description"]
                        })
    except Exception:
        pass

    return {
        "language": lang,
        "lines": line_count,
        "findings": findings
    }

def evaluate_source_directory(
    root_dir: Path,
    max_files: int = 500
) -> dict[str, Any]:
    """
    Evaluate all source code files inside a directory (e.g. extracted archive).
    Computes LOC, language breakdown, security findings, risk score and summary.
    """
    total_files = 0
    total_lines = 0
    languages: dict[str, dict[str, int]] = {}
    all_findings: list[dict[str, Any]] = []

    for path in root_dir.rglob("*"):
        if not path.is_file():
            continue

        # Check ignored directories
        rel_parts = path.relative_to(root_dir).parts
        if any(part in IGNORE_DIRS for part in rel_parts[:-1]):
            continue

        if not is_source_file(path):
            continue

        total_files += 1
        if total_files > max_files:
            break

        rel_path = str(path.relative_to(root_dir))
        eval_res = evaluate_source_file(path, rel_path)

        lang = eval_res["language"]
        lines = eval_res["lines"]
        total_lines += lines

        if lang not in languages:
            languages[lang] = {"files": 0, "lines": 0}
        languages[lang]["files"] += 1
        languages[lang]["lines"] += lines

        all_findings.extend(eval_res["findings"])

    # Calculate language percentages
    lang_stats = []
    for lang_name, data in sorted(languages.items(), key=lambda x: x[1]["lines"], reverse=True):
        pct = round((data["lines"] / total_lines * 100), 1) if total_lines > 0 else 0
        lang_stats.append({
            "name": lang_name,
            "files": data["files"],
            "lines": data["lines"],
            "percentage": pct
        })

    # Findings summary
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: (severity_order.get(x["severity"], 4), x["file"], x["line"]))

    summary_counts = {
        "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
    }

    # Risk score calculation (0 - 100)
    raw_score = (
        summary_counts["critical"] * 25 +
        summary_counts["high"] * 15 +
        summary_counts["medium"] * 5 +
        summary_counts["low"] * 1
    )
    risk_score = min(100, raw_score)

    if risk_score == 0:
        risk_level = "CLEAN"
        summary_text = f"An toàn: Đã đánh giá {total_files} file mã nguồn ({total_lines} dòng code), không phát hiện rủi ro bảo mật đáng ngờ."
    elif risk_score <= 20:
        risk_level = "LOW"
        summary_text = f"Rủi ro Thấp: Phát hiện {len(all_findings)} vấn đề cần lưu ý trong {total_files} file mã nguồn."
    elif risk_score <= 50:
        risk_level = "MEDIUM"
        summary_text = f"Rủi ro Trung bình: Phát hiện {summary_counts['high']} rủi ro cao và {summary_counts['medium']} cảnh báo trong source code."
    elif risk_score <= 80:
        risk_level = "HIGH"
        summary_text = f"Rủi ro Cao: Phát hiện {summary_counts['critical']} điểm nghiêm trọng và {summary_counts['high']} rủi ro cao (chứa secrets hoặc lệnh thực thi nguy hiểm)."
    else:
        risk_level = "CRITICAL"
        summary_text = f"Rủi ro Nghiêm trọng: Mã nguồn có dấu hiệu backdoor, reverse shell hoặc lộ lọt thông tin xác thực tối mật ({summary_counts['critical']} critical, {summary_counts['high']} high)."

    return {
        "is_source_project": total_files > 0,
        "total_source_files": total_files,
        "total_lines": total_lines,
        "languages": lang_stats,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "summary": summary_text,
        "findings_count": summary_counts,
        "total_findings": len(all_findings),
        "findings": all_findings[:200]  # Cap at 200 findings for UI responsiveness
    }

def evaluate_single_file(path: Path, filename: str) -> dict[str, Any] | None:
    """Evaluate a standalone source file."""
    if not is_source_file(path, filename=filename):
        return None

    res = evaluate_source_file(path, filename, filename=filename)
    lang = res["language"]

    lines = res["lines"]
    findings = res["findings"]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (severity_order.get(x["severity"], 4), x["line"]))

    summary_counts = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }

    raw_score = (
        summary_counts["critical"] * 25 +
        summary_counts["high"] * 15 +
        summary_counts["medium"] * 5 +
        summary_counts["low"] * 1
    )
    risk_score = min(100, raw_score)

    if risk_score == 0:
        risk_level = "CLEAN"
        summary_text = f"An toàn: File {filename} ({lines} dòng) không phát hiện lỗ hổng hay mã độc."
    elif risk_score <= 20:
        risk_level = "LOW"
        summary_text = f"Rủi ro Thấp: File {filename} có {len(findings)} điểm cần lưu ý."
    elif risk_score <= 50:
        risk_level = "MEDIUM"
        summary_text = f"Rủi ro Trung bình: File {filename} chứa {summary_counts['high']} hàm rủi ro cao hoặc {summary_counts['medium']} cảnh báo."
    elif risk_score <= 80:
        risk_level = "HIGH"
        summary_text = f"Rủi ro Cao: File {filename} chứa hàm nguy hiểm hoặc thông tin xác thực hardcoded."
    else:
        risk_level = "CRITICAL"
        summary_text = f"Rủi ro Nghiêm trọng: File {filename} có dấu hiệu backdoor hoặc mã độc thực thi nguy hiểm."

    return {
        "is_source_project": True,
        "total_source_files": 1,
        "total_lines": lines,
        "languages": [{"name": lang, "files": 1, "lines": lines, "percentage": 100.0}],
        "risk_level": risk_level,
        "risk_score": risk_score,
        "summary": summary_text,
        "findings_count": summary_counts,
        "total_findings": len(findings),
        "findings": findings
    }
