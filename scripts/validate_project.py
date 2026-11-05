#!/usr/bin/env python3
"""Validate the repository's portable deployment artifacts."""

from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ERRORS = []


def fail(message: str) -> None:
    ERRORS.append(message)


dashboard = ROOT / "05-Dashboards" / "SOC-L1-dashboard.xml"
try:
    ET.parse(dashboard)
except (ET.ParseError, OSError) as exc:
    fail(f"dashboard XML is invalid: {exc}")

spl_files = sorted((ROOT / "03-Detection-Rules").rglob("*.spl"))
if not spl_files:
    fail("no SPL detection files found")

for path in spl_files:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        fail(f"{path.relative_to(ROOT)} is empty")
    if not re.search(r"\bindex=blue\b", text):
        fail(f"{path.relative_to(ROOT)} does not use index=blue")

for path in ROOT.rglob("*"):
    if path.is_file() and ".git" not in path.parts and path.suffix.lower() in {".spl", ".md", ".xml"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"(?i)(password|api[_ -]?key|secret)\s*[:=]\s*\S+", text):
            fail(f"possible credential in {path.relative_to(ROOT)}")

if ERRORS:
    print("Project validation failed:")
    print("\n".join(f"- {error}" for error in ERRORS))
    sys.exit(1)

print(f"Validated {len(spl_files)} SPL rules and dashboard XML successfully.")
