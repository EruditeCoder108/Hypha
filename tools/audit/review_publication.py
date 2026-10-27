# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read-only, redacted publication inventory. This is not a secret-free certificate.

Run from any directory: python tools/audit/review_publication.py
Reports stay in ignored artifacts/. No matched values or database rows are printed.
"""

from __future__ import annotations

import collections
import io
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts/publication-review-2026-10-27"
MAX_BLOB = 24 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024
MAX_ARCHIVE_TEXT = 32 * 1024 * 1024

PATTERNS = {
    "credential_token_candidate": re.compile(
        rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|"
        rb"(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|"
        rb"xox[baprs]-[A-Za-z0-9-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{32,})"
    ),
    "private_key_material_candidate": re.compile(
        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{24,}"
    ),
    "embedded_url_credential_candidate": re.compile(
        rb"(?:https?|postgres(?:ql)?|mysql|mongodb)://[^\s/:@]{2,}:[^\s/@]{4,}@"
    ),
    "personal_email_candidate": re.compile(
        rb"[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|protonmail|icloud)\.[A-Za-z]{2,}"
    ),
    "local_user_path": re.compile(rb"[A-Z]:[/\\]+Users[/\\]+[^\s/\\<>\"']+", re.I),
    "radio_address_candidate": re.compile(rb"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
}
SECRET_CATEGORIES = {
    "credential_token_candidate", "private_key_material_candidate",
    "embedded_url_credential_candidate",
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def summarize(data: bytes) -> dict[str, int]:
    return {name: len(matches) for name, pattern in PATTERNS.items()
            if (matches := pattern.findall(data))}


def archive_summary(data: bytes) -> dict:
    result = {"members_scanned": 0, "members_skipped": 0, "findings": []}
    consumed = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                if member.file_size > MAX_MEMBER or consumed + member.file_size > MAX_ARCHIVE_TEXT:
                    result["members_skipped"] += 1
                    continue
                if Path(member.filename).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}:
                    result["members_skipped"] += 1
                    continue
                raw = archive.read(member)
                consumed += len(raw)
                result["members_scanned"] += 1
                if found := summarize(raw):
                    result["findings"].append({"member": member.filename, "categories": found})
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        result["error"] = type(error).__name__
    return result


def inspect_database_copy() -> dict:
    source = ROOT / ".diagnostics/a001_mesh/relay_mesh.db"
    if not source.is_file():
        return {"present": False}
    destination = OUT / "private-db-copy"
    destination.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        candidate = source.with_name(source.name + suffix)
        if candidate.is_file():
            shutil.copy2(candidate, destination / candidate.name)
    # SQLite may update only the disposable copy's shared-memory sidecar.
    connection = sqlite3.connect((destination / source.name).as_uri() + "?mode=ro", uri=True)
    try:
        names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )]
        tables = []
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            count = connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0]
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({quoted})")]
            tables.append({"table": name, "rows": count, "columns": columns})
        return {"present": True, "method": "copied DB/WAL/SHM; schema and counts only", "tables": tables}
    finally:
        connection.close()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    head_entries = git("ls-tree", "-r", "-z", "HEAD").split(b"\0")
    current = collections.defaultdict(list)
    for entry in head_entries:
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        _mode, kind, oid = meta.decode().split()
        if kind == "blob":
            current[oid].append(path.decode("utf-8", errors="replace"))

    objects = {}
    for record in git("rev-list", "--objects", "--all").decode().splitlines():
        oid, _, path = record.partition(" ")
        objects[oid] = path
    metadata = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=ROOT, input=("\n".join(objects) + "\n").encode(), capture_output=True, check=True,
    )
    blobs = []
    skipped = []
    for record in metadata.stdout.decode().splitlines():
        oid, kind, size = record.split()
        if kind != "blob":
            continue
        if int(size) > MAX_BLOB:
            skipped.append({"oid": oid, "path": objects[oid], "bytes": int(size)})
        else:
            blobs.append(oid)
    findings = []
    archives = []
    total_bytes = 0
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=ROOT,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        for oid in blobs:
            process.stdin.write((oid + "\n").encode())
            process.stdin.flush()
            header = process.stdout.readline().decode().split()
            data = process.stdout.read(int(header[2]))
            if process.stdout.read(1) != b"\n":
                raise RuntimeError("Unexpected Git batch framing")
            total_bytes += len(data)
            if found := summarize(data):
                findings.append({
                    "oid": oid, "historical_path": objects[oid],
                    "head_paths": current.get(oid, []), "categories": found,
                })
            if data.startswith(b"PK\x03\x04"):
                archives.append({"oid": oid, "path": objects[oid], **archive_summary(data)})
    finally:
        process.stdin.close()
        process.wait()
    if process.returncode != 0:
        raise RuntimeError("Git batch reader failed")
    categories = collections.Counter()
    for finding in findings:
        categories.update(finding["categories"])
    secret_findings = [finding for finding in findings if SECRET_CATEGORIES & finding["categories"].keys()]
    authors = git("log", "--all", "--format=%ae%n%ce").decode().splitlines()
    personal_author_count = len({email for email in authors
                                if PATTERNS["personal_email_candidate"].search(email.encode())})
    tracked = sorted(path for paths in current.values() for path in paths)
    report = {
        "head": git("rev-parse", "HEAD").decode().strip(),
        "local_refs_only": True,
        "commits": int(git("rev-list", "--all", "--count")),
        "tracked_files": len(tracked), "unique_blobs_scanned": len(blobs),
        "bytes_scanned": total_bytes, "skipped_blobs": skipped,
        "redaction": "Matched values and database rows omitted; paths and category counts only.",
        "category_occurrences_across_unique_blobs": dict(categories),
        "credential_candidates": secret_findings,
        "personal_author_email_count": personal_author_count,
        "tracked_private_data_paths": [path for path in tracked if path.startswith(
            (".diagnostics/", "evidence/screens/", ".codex-pptx-"))],
        "findings": findings, "archives": archives,
        "device_database": inspect_database_copy(),
        "limits": [
            "Pattern scan, not an exhaustive secret detector or security audit.",
            "Only locally reachable refs; no GitHub PR caches, forks, dangling objects, or external copies.",
            "Image/OCR and compressed PDF contents are not scanned by these patterns.",
            "Binary matches may be incidental; source fixtures may deliberately include test-only keys.",
            "Ignored/untracked files are excluded; database copy is inspected separately without decryption.",
            "Archive members are bounded; skipped members and nested archives need manual review.",
        ],
    }
    (OUT / "publication-inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "commits": report["commits"], "uniqueBlobsScanned": len(blobs),
        "credentialCandidateBlobs": len(secret_findings),
        "personalAuthorEmails": personal_author_count,
        "trackedPrivateDataPaths": len(report["tracked_private_data_paths"]),
        "databaseTableCounts": {table["table"]: table["rows"] for table in report["device_database"].get("tables", [])},
        "archiveCount": len(archives), "skippedBlobs": len(skipped),
        "report": str((OUT / "publication-inventory.json").relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
