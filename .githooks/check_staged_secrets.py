#!/usr/bin/env python3
"""Fail-closed staged diff guard for obvious and context-rich secrets."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import math
import re
import subprocess
import sys
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


MAX_FILES = 1000
MAX_TOTAL_DIFF_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_FINDINGS = 100
MAX_SECONDS = 5.0
SYNTHETIC_MARKERS = ("SYNTHETIC", "NOT-REAL", "PLACEHOLDER", "REDACTED", "TEST-ONLY")

SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|authorization|private[_-]?key)"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
)

SENSITIVE_CONTEXT = re.compile(
    r"(?i)(?:token|secret|credential|authorization|private[_-]?key|api[_-]?key|password)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{20,})"
)


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    line: int = 0
    length: int = 0
    fingerprint: str = ""


def fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    return f"sha256:{digest}"


def synthetic_value(value: str) -> bool:
    upper = value.upper()
    return any(marker in upper for marker in SYNTHETIC_MARKERS)


def variants(value: str) -> list[str]:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = re.sub(r"[\u0000\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]", "", normalized)
    normalized = re.sub(r"([\"'])\s*\+\s*([\"'])", "", normalized)
    values = [normalized]
    current = normalized
    for _ in range(2):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        values.append(decoded)
        current = decoded
    escaped = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), normalized)
    if escaped != normalized:
        values.append(escaped)
    for candidate in list(values):
        for match in re.finditer(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", candidate):
            encoded = match.group(0)
            try:
                decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded and sum(char.isprintable() for char in decoded) / len(decoded) >= 0.85:
                values.append(decoded)
    return list(dict.fromkeys(values))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def sensitive_filename(path: str) -> bool:
    base = Path(path).name.lower()
    if base == ".env.example":
        return False
    if base == ".env" or base.startswith(".env."):
        return True
    if base in {"credentials.json", "service-account.json", "kubeconfig", "id_rsa", "id_ed25519"}:
        return True
    return any(
        fnmatch.fnmatch(base, pattern)
        for pattern in ("*.pem", "*.key", "*.p12", "*.pfx", "*.jks")
    )


def scan_added_line(path: str, line: str, line_number: int) -> list[Finding]:
    if len(line.encode("utf-8", "replace")) > MAX_LINE_BYTES:
        return [Finding("line_limit", path, line_number)]
    found: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for candidate in variants(line):
        for kind, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(candidate):
                key = (kind, match.start())
                if key in seen:
                    continue
                seen.add(key)
                value = match.group(0)
                if synthetic_value(value):
                    continue
                found.append(Finding(kind, path, line_number, len(value), fingerprint(value)))
        for match in SENSITIVE_CONTEXT.finditer(candidate):
            value = match.group(1)
            if synthetic_value(value):
                continue
            if shannon_entropy(value) < 4.2:
                continue
            found.append(Finding("high_entropy_secret_context", path, line_number, len(value), fingerprint(value)))
    unique: dict[tuple[str, str, int], Finding] = {}
    for item in found:
        unique[(item.kind, item.path, item.line)] = item
    return list(unique.values())


def run_git(root: Path, args: list[str], limit: int | None = None) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=MAX_SECONDS,
    )
    if limit is not None and len(process.stdout) > limit:
        raise RuntimeError("git output exceeds staged scan limit")
    return process.stdout


def staged_paths(root: Path) -> list[tuple[str, str]]:
    raw = run_git(root, ["diff", "--cached", "--binary", "--name-status", "-z", "--diff-filter=ACMRTUXB"])
    tokens = raw.split(b"\0")
    result: list[tuple[str, str]] = []
    index = 0
    while index < len(tokens) and tokens[index]:
        status = tokens[index].decode("utf-8", "replace")
        index += 1
        if status[:1] in {"R", "C"}:
            if index + 1 >= len(tokens):
                raise RuntimeError("malformed staged rename record")
            index += 1
            path = tokens[index].decode("utf-8", "replace")
            index += 1
        else:
            if index >= len(tokens):
                raise RuntimeError("malformed staged path record")
            path = tokens[index].decode("utf-8", "replace")
            index += 1
        result.append((status, path))
    return result


def staged_modes(root: Path, paths: list[tuple[str, str]]) -> dict[str, str]:
    modes: dict[str, str] = {}
    for _, path in paths:
        raw = run_git(root, ["ls-files", "--stage", "-z", "--", path])
        for record in raw.split(b"\0"):
            if not record:
                continue
            header, _, stored_path = record.partition(b"\t")
            fields = header.decode("ascii", "replace").split()
            if len(fields) >= 1:
                modes[stored_path.decode("utf-8", "replace")] = fields[0]
    return modes


def validate_paths(root: Path, paths: list[tuple[str, str]], modes: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    root_real = root.resolve()
    for status, path in paths:
        path_obj = Path(path)
        if path_obj.is_absolute() or ".." in path_obj.parts or "\x00" in path:
            findings.append(Finding("unsafe_staged_path", path))
            continue
        resolved = (root / path_obj).resolve()
        try:
            resolved.relative_to(root_real)
        except ValueError:
            findings.append(Finding("path_outside_repository", path))
        if sensitive_filename(path):
            findings.append(Finding("sensitive_filename", path))
        if modes.get(path) == "120000":
            findings.append(Finding("staged_symlink", path))
        if status[:1] in {"R", "C"} and sensitive_filename(path):
            findings.append(Finding("sensitive_renamed_filename", path))
    return findings


def scan_diff(root: Path, path_set: set[str]) -> list[Finding]:
    raw = run_git(
        root,
        ["diff", "--cached", "--binary", "--unified=0", "--no-ext-diff", "--", ".", ":!*.lock"],
        MAX_TOTAL_DIFF_BYTES,
    )
    findings: list[Finding] = []
    current_path = ""
    current_line = 0
    for raw_line in raw.splitlines():
        line = raw_line.decode("utf-8", "replace")
        if line.startswith("diff --git ") and " b/" in line:
            current_path = line.rsplit(" b/", 1)[1]
            current_line = 0
            continue
        if line.startswith("+++ b/"):
            current_path = line[6:]
            continue
        if line.startswith("Binary files ") and current_path in path_set:
            yield_finding = Finding("binary_not_scanned", current_path)
            findings.append(yield_finding)
            continue
        if line.startswith("@@"):
            match = re.search(r"\+([0-9]+)", line)
            current_line = int(match.group(1)) if match else 0
            continue
        if not line.startswith("+") or line.startswith("+++") or current_path not in path_set:
            continue
        findings.extend(scan_added_line(current_path, line[1:], current_line))
        current_line += 1
    return findings


def validate_config(path: Path) -> list[Finding]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        return [Finding("config_unreadable", str(path))]
    if len(content.encode("utf-8")) > 64 * 1024:
        return [Finding("config_size_limit", str(path))]
    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        findings.extend(scan_added_line(str(path), line, line_number))
    list_key = ""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            value = line[1:].strip().strip("\"'")
            if list_key in {"approved_providers", "approved_mcp_servers"} and any(char in value for char in "*?"):
                findings.append(Finding("policy_wildcard", str(path)))
            continue
        key, separator, value = line.partition(":")
        if not separator:
            continue
        list_key = key.strip().lower().replace("-", "_")
        if list_key in {"approved_providers", "approved_mcp_servers"} and any(char in value for char in "*?"):
            findings.append(Finding("policy_wildcard", str(path)))
    return findings


def describe(item: Finding) -> str:
    details = f" length={item.length}" if item.length else ""
    suffix = f" {item.fingerprint}" if item.fingerprint else ""
    location = f"{item.path}:{item.line}" if item.line else item.path
    return f"staged guard: {item.kind} at {location}{details}{suffix}"


def main(argv: list[str]) -> int:
    root = Path.cwd()
    if "--root" in argv:
        index = argv.index("--root")
        if index + 1 >= len(argv):
            print("staged guard: --root requires a path", file=sys.stderr)
            return 2
        root = Path(argv[index + 1]).resolve()
    if "--check-config" in argv:
        index = argv.index("--check-config")
        if index + 1 >= len(argv):
            print("staged guard: --check-config requires a path", file=sys.stderr)
            return 2
        findings = validate_config(Path(argv[index + 1]))
        for item in findings:
            print(describe(item), file=sys.stderr)
        if findings:
            print(f"staged guard: blocked {len(findings)} config finding(s)", file=sys.stderr)
            return 1
        print("staged guard: scanner config passed")
        return 0
    started = time.monotonic()
    try:
        paths = staged_paths(root)
        if len(paths) > MAX_FILES:
            raise RuntimeError("staged file count exceeds limit")
        modes = staged_modes(root, paths)
        findings = validate_paths(root, paths, modes)
        findings.extend(scan_diff(root, {path for _, path in paths}))
        config = root / ".agentctl" / "config.yaml"
        if config.exists():
            findings.extend(validate_config(config))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"staged guard: blocked ({error})", file=sys.stderr)
        return 1
    if time.monotonic() - started > MAX_SECONDS:
        findings.append(Finding("time_limit"))
    unique: dict[tuple[str, str, int], Finding] = {}
    for item in findings:
        unique[(item.kind, item.path, item.line)] = item
    findings = list(unique.values())
    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]
        findings.append(Finding("finding_limit"))
    for item in findings:
        print(describe(item), file=sys.stderr)
    if findings:
        print(f"staged guard: blocked {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print(f"staged guard: checked {len(paths)} staged path(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
