
import math
import json
import hashlib
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone




def analyze_file(path):
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB

    try:
        path = Path(path)

        # Do not follow symbolic links.
        if path.is_symlink():
            return {
                "file_name": path.name,
                "status": "Skipped: symbolic link"
            }

        if not path.is_file():
            return {
                "file_name": path.name,
                "status": "Skipped: not a regular file"
            }

        # Check the file size before reading.
        if path.stat().st_size > MAX_FILE_SIZE:
            return {
                "file_name": path.name,
                "file_size_bytes": path.stat().st_size,
                "status": "Skipped: file exceeds 50 MiB limit"
            }

        # Read at most one byte beyond the limit.
        with path.open("rb") as file:
            data = file.read(MAX_FILE_SIZE + 1)

        if len(data) > MAX_FILE_SIZE:
            return {
                "file_name": path.name,
                "status": "Skipped: file exceeds 50 MiB limit"
            }

        if not data:
            return {
                "file_name": path.name,
                "file_size_bytes": 0,
                "status": "Skipped: empty file"
            }

        total = len(data)
        counts = Counter(data)

        entropy = -sum(
            (count / total) * math.log2(count / total)
            for count in counts.values()
        )

        file_hash = hashlib.sha256(data).hexdigest()

        detected_type, expected_extensions = identify_file_type(data)
        extension = path.suffix.lower()

        mismatch = (
            expected_extensions is not None
            and extension not in expected_extensions
        )

        if entropy > 7.2:
            entropy_note = "High entropy: further review may be useful."
        else:
            entropy_note = "Entropy is not especially high."

        if mismatch:
            review_note = "Extension differs from detected type. Review manually."
        else:
            review_note = "No extension mismatch detected by this check."

        return {
            "file_name": path.name,
            "file_size_bytes": total,
            "sha256": file_hash,
            "unique_byte_values": len(counts),
            "entropy_score": round(entropy, 4),
            "detected_type": detected_type,
            "extension_mismatch": mismatch,
            "analysis_note": entropy_note,
            "review_note": review_note,
            "status": "Analyzed"
        }

    except OSError as error:
        return {
            "file_name": Path(path).name,
            "status": "Error",
            "error": str(error)
        }



def identify_file_type(data):
    """Identify common file formats using their byte signatures."""
    signatures = [
        (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
        (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
        (b"GIF87a", "GIF image", {".gif"}),
        (b"GIF89a", "GIF image", {".gif"}),
        (b"%PDF-", "PDF document", {".pdf"}),
        (b"PK\x03\x04", "ZIP-based archive", {".zip", ".docx", ".xlsx", ".pptx", ".jar"}),
        (b"\x1f\x8b", "GZIP archive", {".gz", ".tgz"}),
        (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
        (b"SQLite format 3\x00", "SQLite database", {".db", ".sqlite", ".sqlite3"}),
        (b"\x7fELF", "ELF executable", {".elf", ".so"}),
        (b"MZ", "Windows PE/DOS executable candidate", {".exe", ".dll", ".sys"}),
    ]

    for signature, file_type, expected_extensions in signatures:
        if data.startswith(signature):
            return file_type, expected_extensions

    # A simple heuristic, not a definitive file-type detector.
    sample = data[:4096]
    if sample:
        printable = sum(
            byte in (9, 10, 13) or 32 <= byte <= 126
            for byte in sample
        )
        if printable / len(sample) > 0.90:
            return "Text-like data", None

    return "Unknown binary data", None

def scan_folder(folder_name):
    folder = Path(folder_name)

    if not folder.is_dir():
        print("Error: Folder not found.")
        return

    results = []

    # Scan files in this folder only, not subfolders
    for path in sorted(folder.iterdir()):
        if path.is_file():
            results.append(analyze_file(path))

    report = {
        "tool": "CyberEntropy-AI",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "folder": str(folder.resolve()),
        "total_files_found": len(results),
        "analyzed_files": sum(
            1 for item in results
            if item["status"] == "Analyzed"
        ),
        "results": results
    }

    report_path = folder / "cyberentropy_report.json"

    try:
        report_path.write_text(
            json.dumps(report, indent=4, ensure_ascii=False),
            encoding="utf-8"
        )
    except OSError as error:
        print(f"Could not save report: {error}")
        return

    print("\n===== CyberEntropy-AI Folder Report =====")
    print(f"Folder: {folder.resolve()}")
    print(f"Files found: {len(results)}")
    print(f"Files analyzed: {report['analyzed_files']}")

    for item in results:
        print(f"\nFile: {item['file_name']}")
        print(f"Status: {item['status']}")

        if item["status"] == "Analyzed":
            print(f"Size: {item['file_size_bytes']} bytes")
            print(f"SHA-256: {item['sha256']}")
            print(f"Entropy: {item['entropy_score']}")
            print(f"Note: {item['analysis_note']}")

    print(f"\nReport saved to: {report_path.resolve()}")
    print("Reminder: Entropy alone cannot determine whether a file is malicious.")


if __name__ == "__main__":
    folder_name = input(
        "Enter the path of a folder to scan: "
    ).strip().strip('"')

    scan_folder(folder_name)
