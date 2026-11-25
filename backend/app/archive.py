import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

# Binary extensions commonly analyzed by DIE
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr", ".com",
    ".elf", ".so", ".bin", ".dylib", ".o", ".a",
    ".class", ".dex", ".pyc"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
    ".jar", ".war", ".apk", ".rar"
}

SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".cs",
    ".java", ".kt", ".go", ".rs", ".php", ".phtml",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".rb", ".html", ".htm", ".sql", ".sol",
    ".env", ".yml", ".yaml", ".json", ".xml", ".ini", ".conf", ".toml"
}

def detect_archive_type(path: Path, original_filename: str | None = None) -> str | None:
    """Detect if a file is an archive by magic bytes or extension."""
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as f:
            header = f.read(512)
    except Exception:
        return None

    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        return "zip"
    if header.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if header.startswith(b"\x1f\x8b"):
        return "tar.gz"
    if header.startswith(b"BZh"):
        return "tar.bz2"
    if header.startswith(b"\xfd7zXZ\x00"):
        return "tar.xz"
    if len(header) >= 262 and header[257:262] == b"ustar":
        return "tar"

    # Fallback to extension of original_filename or path
    target = Path(original_filename) if original_filename else path
    suffix = "".join(target.suffixes).lower()
    for ext in [".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip", ".tar", ".jar", ".war", ".apk", ".rar"]:
        if suffix.endswith(ext):
            if ext == ".rar":
                return "rar"
            if ext in [".tar.gz", ".tgz"]:
                return "tar.gz"
            if ext in [".tar.bz2", ".tbz2"]:
                return "tar.bz2"
            if ext in [".tar.xz", ".txz"]:
                return "tar.xz"
            if ext in [".tar"]:
                return "tar"
            return "zip"
    return None

def is_archive(path: Path, original_filename: str | None = None) -> bool:
    return detect_archive_type(path, original_filename=original_filename) is not None

def classify_extension(ext: str) -> str:
    ext = ext.lower()
    if ext in SOURCE_EXTENSIONS:
        return "source"
    if ext in BINARY_EXTENSIONS:
        return "binary"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    if ext in {".txt", ".md", ".rst", ".pdf", ".doc", ".docx"}:
        return "document"
    return "other"

def safe_extract_archive(
    archive_path: Path,
    dest_dir: Path,
    original_filename: str | None = None,
    max_files: int = 1000,
    max_total_size: int = 100 * 1024 * 1024  # 100 MB
) -> dict[str, Any]:
    """
    Safely extract archive guarding against Zip Slip, symlink traversal,
    and decompression bombs.
    """
    archive_type = detect_archive_type(archive_path, original_filename=original_filename)
    if not archive_type:
        return {"is_archive": False, "error": "Not a supported archive format"}

    dest_dir.mkdir(parents=True, exist_ok=True)
    abs_dest = dest_dir.resolve()

    files_info: list[dict[str, Any]] = []
    total_size = 0
    extracted_count = 0
    warning: str | None = None

    try:
        if archive_type == "zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    extracted_count += 1
                    if extracted_count > max_files:
                        warning = f"Reached maximum file limit ({max_files} files). Remaining files skipped."
                        break

                    total_size += member.file_size
                    if total_size > max_total_size:
                        warning = f"Reached maximum uncompressed size limit ({max_total_size // (1024 * 1024)} MB)."
                        break

                    # Check for path traversal / zip slip
                    member_path = Path(member.filename)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        continue

                    target_file = (dest_dir / member_path).resolve()
                    if not target_file.is_relative_to(abs_dest):
                        continue

                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, open(target_file, "wb") as target:
                        # Copy in chunks
                        while chunk := source.read(64 * 1024):
                            target.write(chunk)

                    ext = target_file.suffix.lower()
                    files_info.append({
                        "path": str(member_path).replace("\\", "/"),
                        "size": member.file_size,
                        "extension": ext,
                        "category": classify_extension(ext)
                    })

        elif archive_type.startswith("tar"):
            mode = "r:*"
            if archive_type == "tar.gz":
                mode = "r:gz"
            elif archive_type == "tar.bz2":
                mode = "r:bz2"
            elif archive_type == "tar.xz":
                mode = "r:xz"
            elif archive_type == "tar":
                mode = "r:"

            with tarfile.open(archive_path, mode) as tf:
                for member in tf.getmembers():
                    if not member.isreg():
                        continue
                    extracted_count += 1
                    if extracted_count > max_files:
                        warning = f"Reached maximum file limit ({max_files} files). Remaining files skipped."
                        break

                    total_size += member.size
                    if total_size > max_total_size:
                        warning = f"Reached maximum uncompressed size limit ({max_total_size // (1024 * 1024)} MB)."
                        break

                    member_path = Path(member.name)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        continue

                    target_file = (dest_dir / member_path).resolve()
                    if not target_file.is_relative_to(abs_dest):
                        continue

                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    f_obj = tf.extractfile(member)
                    if f_obj is not None:
                        with open(target_file, "wb") as target:
                            while chunk := f_obj.read(64 * 1024):
                                target.write(chunk)

                    ext = target_file.suffix.lower()
                    files_info.append({
                        "path": str(member_path).replace("\\", "/"),
                        "size": member.size,
                        "extension": ext,
                        "category": classify_extension(ext)
                    })

        elif archive_type == "rar":
            staging_dir = dest_dir / "__staging_rar__"
            staging_dir.mkdir(parents=True, exist_ok=True)
            tool = "7z" if shutil.which("7z") else "unrar" if shutil.which("unrar") else "unrar-free" if shutil.which("unrar-free") else None
            if not tool:
                return {
                    "is_archive": True,
                    "archive_type": "rar",
                    "error": "Công cụ giải nén RAR (7z/unrar) chưa được cài đặt trong hệ thống.",
                    "total_files": 0,
                    "uncompressed_size": 0,
                    "files": []
                }

            tool_binary = shutil.which(tool)
            if not tool_binary:
                return {
                    "is_archive": True,
                    "archive_type": "rar",
                    "error": f"Không tìm thấy binary {tool} trong hệ thống.",
                    "total_files": 0,
                    "uncompressed_size": 0,
                    "files": []
                }

            if tool == "7z":
                cmd = [tool_binary, "x", "-y", "-p", f"-o{staging_dir}", "--", str(archive_path.resolve())]
            else:
                cmd = [tool_binary, "x", "-y", "--", str(archive_path.resolve()), str(staging_dir) + "/"]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)  # nosec: INJ-002 - Hardened archive extraction
            if proc.returncode != 0 and not any(staging_dir.iterdir()):
                return {
                    "is_archive": True,
                    "archive_type": "rar",
                    "error": f"Lỗi giải nén tệp RAR: {(proc.stderr or proc.stdout).strip()[:1000]}",
                    "total_files": 0,
                    "uncompressed_size": 0,
                    "files": []
                }

            for root, dirs, files_in_dir in os.walk(staging_dir):
                for f_name in files_in_dir:
                    src_file = Path(root) / f_name
                    rel_p = src_file.relative_to(staging_dir)

                    if ".." in rel_p.parts:
                        continue

                    target_file = (dest_dir / rel_p).resolve()
                    if not target_file.is_relative_to(abs_dest):
                        continue

                    extracted_count += 1
                    if extracted_count > max_files:
                        warning = f"Reached maximum file limit ({max_files} files). Remaining files skipped."
                        break

                    file_sz = src_file.stat().st_size
                    total_size += file_sz
                    if total_size > max_total_size:
                        warning = f"Reached maximum uncompressed size limit ({max_total_size // (1024 * 1024)} MB)."
                        break

                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(src_file, target_file)

                    ext = target_file.suffix.lower()
                    files_info.append({
                        "path": str(rel_p).replace("\\", "/"),
                        "size": file_sz,
                        "extension": ext,
                        "category": classify_extension(ext)
                    })
                if extracted_count > max_files or total_size > max_total_size:
                    break

            shutil.rmtree(staging_dir, ignore_errors=True)
    except Exception as exc:
        return {
            "is_archive": True,
            "archive_type": archive_type,
            "error": f"Failed extracting archive: {exc}",
            "total_files": len(files_info),
            "uncompressed_size": total_size,
            "files": files_info
        }

    return {
        "is_archive": True,
        "archive_type": archive_type,
        "total_files": len(files_info),
        "uncompressed_size": total_size,
        "warning": warning,
        "files": files_info
    }
