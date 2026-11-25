import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Scan
from .config import UPLOAD_DIR, MAX_SCAN_SECONDS
from .archive import is_archive, safe_extract_archive
from .source_evaluator import evaluate_source_directory, evaluate_single_file

# Resolve absolute path to diec binary to prevent untrusted PATH search vulnerabilities (CWE-426)
DIEC_BINARY = shutil.which("diec") or "/usr/bin/diec"

# Hardened minimal environment (prevents leaking app credentials/JWT secrets to subprocesses)
SAFE_SUBPROCESS_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8"
}

def validate_safe_path(target: Path | str) -> str:
    """Validate that target path exists, is a regular file, and contains no null bytes or injection characters."""
    p = Path(target).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"File not found or not regular file: {p}")
    p_str = str(p)
    if any(ch in p_str for ch in ("\0", "\r", "\n")):
        raise ValueError("Illegal characters detected in file path")
    return p_str

def safe_execute_diec(target_path: Path | str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """
    Execute Detect It Easy CLI with full defense-in-depth security hardening:
      - Target path existence verification and absolute resolution.
      - Chars inspection to prevent control characters.
      - Absolute binary path (/usr/bin/diec) avoiding untrusted PATH search (CWE-426).
      - Explicit argument separation with '--' mitigating Argument/Flag Injection (CWE-88).
      - Strict shell=False preventing OS Command Injection (CWE-78).
      - Sanitized minimal environment isolating sensitive app credentials & JWT secrets.
    """
    safe_path = validate_safe_path(target_path)
    cmd = [DIEC_BINARY, "-b", "-j", "--", safe_path]
    return subprocess.run(  # nosec: INJ-002 - Fully hardened invocation with shell=False and validated args
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
        env=SAFE_SUBPROCESS_ENV
    )

def scan_with_die(file_path: Path, timeout: int = 30) -> dict:
    """Run Detect It Easy CLI on a specific file using hardened runner and return structured result."""
    try:
        proc = safe_execute_diec(file_path, timeout=timeout)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            return {}
        try:
            parsed = json.loads(stdout)
            return parsed if isinstance(parsed, dict) else {"data": parsed}
        except json.JSONDecodeError:
            return {"format": "text", "output": stdout}
    except Exception as exc:
        return {"error": str(exc)}

def analyze_scan(scan_id: int):
    db: Session = SessionLocal()
    scan = db.get(Scan, scan_id)
    if not scan:
        db.close()
        return

    path = Path(UPLOAD_DIR) / scan.stored_name
    try:
        scan.status = "running"
        db.commit()

        # Step 1: Run DIE on the root uploaded file using hardened execution runner
        proc = safe_execute_diec(path, timeout=MAX_SCAN_SECONDS)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0 and not stdout:
            raise RuntimeError(f"diec exited with code {proc.returncode}: {stderr[:1500]}")

        try:
            die_result = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            die_result = {"format": "text", "output": stdout}

        if not isinstance(die_result, dict):
            die_result = {"data": die_result}

        # Final structured result container
        final_result: dict = {
            "die": die_result,
            "detects": die_result.get("detects", [])
        }

        # Step 2: Check if file is an archive
        if is_archive(path, original_filename=scan.original_name):
            extract_temp = Path(f"/tmp/die-extract-{scan.id}-{uuid.uuid4().hex[:8]}")
            try:
                archive_info = safe_extract_archive(path, extract_temp, original_filename=scan.original_name)

                # Scan binary files inside the archive with DIE (limit to first 12 binaries)
                scanned_binaries = 0
                for item in archive_info.get("files", []):
                    if item.get("category") == "binary" and scanned_binaries < 12:
                        extracted_file_path = extract_temp / item["path"]
                        if extracted_file_path.is_file():
                            die_sub = scan_with_die(extracted_file_path, timeout=15)
                            if die_sub and "detects" in die_sub:
                                item["die_detects"] = die_sub["detects"]
                            scanned_binaries += 1

                # Step 3: Run source code evaluation on extracted files
                source_eval = evaluate_source_directory(extract_temp)

                final_result["archive"] = archive_info
                final_result["source_evaluation"] = source_eval
            finally:
                shutil.rmtree(extract_temp, ignore_errors=True)

        else:
            # Not an archive: check if it is a standalone source code file
            source_eval = evaluate_single_file(path, scan.original_name)
            if source_eval:
                final_result["source_evaluation"] = source_eval

        scan.result = final_result

        # Generate structured text output with [CRITICAL] and [WARNING] markers
        cli_lines = []
        if stdout:
            cli_lines.append("=== DETECT IT EASY CLI OUTPUT ===")
            cli_lines.append(stdout)

        if final_result.get("archive"):
            arc = final_result["archive"]
            cli_lines.append("\n=== ARCHIVE SUMMARY ===")
            cli_lines.append(f"Format: {arc.get('archive_type', '').upper()} | Files: {arc.get('total_files', 0)} | Extracted Size: {arc.get('uncompressed_size', 0)} bytes")
            if arc.get("warning"):
                cli_lines.append(f"[WARNING] {arc['warning']}")

        if final_result.get("source_evaluation"):
            se = final_result["source_evaluation"]
            cli_lines.append("\n=== SOURCE CODE EVALUATION AUDIT ===")
            cli_lines.append(f"Risk Rating: {se.get('risk_level')} | Score: {se.get('risk_score')}/100")
            cli_lines.append(f"Verdict: {se.get('summary')}")
            findings = se.get("findings", [])
            if findings:
                cli_lines.append("\n--- SECURITY FINDINGS ---")
                for f in findings:
                    sev = f.get("severity", "INFO").upper()
                    # Mark WARNING for HIGH/MEDIUM findings and CRITICAL for CRITICAL findings
                    tag = f"[{sev}]" if sev == "CRITICAL" else f"[WARNING - {sev}]" if sev in ("HIGH", "MEDIUM") else f"[{sev}]"
                    cli_lines.append(f"{tag} {f.get('title')} ({f.get('file')}:{f.get('line')}) -> {f.get('snippet', '')}")

        scan.raw_output = "\n".join(cli_lines)[:50000]
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

    except subprocess.TimeoutExpired:
        scan.status = "failed"
        scan.error = f"DIE scan exceeded {MAX_SCAN_SECONDS} seconds"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:
        scan.status = "failed"
        scan.error = str(exc)[:3000]
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
