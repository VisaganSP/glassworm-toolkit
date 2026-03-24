#!/usr/bin/env python3
"""
GlassWorm Detection Scanner
============================
Scans files for invisible Unicode payloads used by the GlassWorm
supply chain malware campaign. Safe defensive tool for security
engineers and pentesters.

Usage:
    python3 glassworm_scanner.py <path>          # Scan a file or directory
    python3 glassworm_scanner.py <path> --json    # JSON output for CI/CD
    python3 glassworm_scanner.py <path> --verbose # Show character positions

References:
    - Koi Security initial disclosure (Oct 2025)
    - CVE-2021-42574 (Trojan Source)
    - Snyk anti-trojan-source project
"""

import os
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ─── Detection Ranges ────────────────────────────────────────────────
# GlassWorm encodes payloads using these Unicode ranges that render
# as invisible / zero-width in virtually all editors and terminals.

VARIATION_SELECTORS = (0xFE00, 0xFE0F)           # VS1–VS16
VARIATION_SELECTORS_SUPP = (0xE0100, 0xE01EF)    # VS17–VS256
ZERO_WIDTH_CHARS = (0x200B, 0x200F)              # ZWSP, ZWNJ, ZWJ, etc.
LINE_SEPARATORS = (0x2028, 0x2029)               # Line/Para separators
BOM = (0xFEFF, 0xFEFF)                           # BOM (suspicious mid-file)
SOFT_HYPHEN = (0x00AD, 0x00AD)                   # Soft hyphen
PUA_BASIC = (0xE000, 0xF8FF)                     # Private Use Area (Basic)
PUA_SUPP_A = (0xF0000, 0xFFFFF)                  # Supplementary PUA-A
PUA_SUPP_B = (0x100000, 0x10FFFD)                # Supplementary PUA-B
TAG_CHARS = (0xE0001, 0xE007F)                   # Tag characters (deprecated)

SUSPICIOUS_RANGES = [
    VARIATION_SELECTORS,
    VARIATION_SELECTORS_SUPP,
    ZERO_WIDTH_CHARS,
    LINE_SEPARATORS,
    BOM,
    SOFT_HYPHEN,
]

# Extended ranges — higher false-positive rate but catches PUA abuse
EXTENDED_RANGES = SUSPICIOUS_RANGES + [
    PUA_BASIC,
    PUA_SUPP_A,
    PUA_SUPP_B,
    TAG_CHARS,
]

# Known GlassWorm decoder signatures (patterns found in the JS decoder)
DECODER_SIGNATURES = [
    "0xFE00",
    "0xE0100",
    "fromCodePoint",
    "codePointAt",
    "charCodeAt",
    # Decoder loop pattern: extracting bytes from invisible chars
    "String.fromCharCode",
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".json", ".py", ".rb", ".sh", ".bash",
    ".yml", ".yaml", ".toml", ".xml",
    ".md", ".txt", ".html", ".css", ".scss",
    ".vue", ".svelte",
}

# Known malicious extension IDs (partial list from public IoCs)
KNOWN_MALICIOUS_EXTENSIONS = [
    "codejoy",
    "reditorsupporter.r-vscode",
    "quartz.quartz-markdown-editor",
]


@dataclass
class Finding:
    file: str
    line: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    rule: str
    description: str
    details: Optional[str] = None


@dataclass
class ScanResult:
    path: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == "HIGH")


def is_suspicious(cp: int, extended: bool = False) -> bool:
    """Check if a Unicode code point falls in a suspicious range."""
    ranges = EXTENDED_RANGES if extended else SUSPICIOUS_RANGES
    return any(lo <= cp <= hi for lo, hi in ranges)


def classify_char(cp: int) -> str:
    """Classify a suspicious character by its Unicode range."""
    if VARIATION_SELECTORS[0] <= cp <= VARIATION_SELECTORS[1]:
        return "Variation Selector"
    if VARIATION_SELECTORS_SUPP[0] <= cp <= VARIATION_SELECTORS_SUPP[1]:
        return "Variation Selector Supplement"
    if ZERO_WIDTH_CHARS[0] <= cp <= ZERO_WIDTH_CHARS[1]:
        return "Zero-Width Character"
    if LINE_SEPARATORS[0] <= cp <= LINE_SEPARATORS[1]:
        return "Line/Paragraph Separator"
    if cp == 0xFEFF:
        return "BOM (mid-file)"
    if cp == 0x00AD:
        return "Soft Hyphen"
    if PUA_BASIC[0] <= cp <= PUA_BASIC[1]:
        return "Private Use Area"
    if PUA_SUPP_A[0] <= cp <= PUA_SUPP_A[1]:
        return "Supplementary PUA-A"
    if PUA_SUPP_B[0] <= cp <= PUA_SUPP_B[1]:
        return "Supplementary PUA-B"
    if TAG_CHARS[0] <= cp <= TAG_CHARS[1]:
        return "Tag Character"
    return "Unknown Suspicious"


def scan_file(filepath: str, extended: bool = False, verbose: bool = False) -> List[Finding]:
    """Scan a single file for GlassWorm indicators."""
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, PermissionError) as e:
        return [Finding(filepath, 0, "INFO", "FILE_ERROR", str(e))]

    lines = content.split("\n")
    is_js_ts = Path(filepath).suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

    # ── Rule 1: Variation Selector Clusters (CORE DETECTION) ──────────
    for lineno, line in enumerate(lines, 1):
        vs_count = sum(
            1 for c in line
            if (VARIATION_SELECTORS[0] <= ord(c) <= VARIATION_SELECTORS[1])
            or (VARIATION_SELECTORS_SUPP[0] <= ord(c) <= VARIATION_SELECTORS_SUPP[1])
        )

        if vs_count >= 10 and is_js_ts:
            detail = f"{vs_count} variation selectors found" if verbose else None
            findings.append(Finding(
                filepath, lineno, "CRITICAL",
                "GLASSWORM_PAYLOAD",
                f"High-density invisible Unicode cluster ({vs_count} variation selectors) — "
                f"strong GlassWorm payload indicator",
                detail
            ))
        elif vs_count >= 3:
            findings.append(Finding(
                filepath, lineno, "MEDIUM",
                "SUSPICIOUS_VS_CLUSTER",
                f"Variation selector cluster ({vs_count} chars) — unusual, possibly malicious",
            ))

    # ── Rule 2: Invisible Character Density ───────────────────────────
    for lineno, line in enumerate(lines, 1):
        invisible = [
            (i, ord(c), classify_char(ord(c)))
            for i, c in enumerate(line)
            if is_suspicious(ord(c), extended)
        ]

        if len(invisible) > 5:
            detail = None
            if verbose:
                detail = "; ".join(
                    f"col {col}: U+{cp:04X} ({cls})"
                    for col, cp, cls in invisible[:10]
                )
                if len(invisible) > 10:
                    detail += f" ... and {len(invisible) - 10} more"

            severity = "HIGH" if len(invisible) > 20 else "MEDIUM"
            findings.append(Finding(
                filepath, lineno, severity,
                "INVISIBLE_CHAR_DENSITY",
                f"{len(invisible)} invisible/suspicious Unicode characters on single line",
                detail
            ))

    # ── Rule 3: Decoder Pattern Detection ─────────────────────────────
    if is_js_ts:
        for lineno, line in enumerate(lines, 1):
            for sig in DECODER_SIGNATURES:
                if sig in line:
                    # Check if it's near invisible chars (within 5 lines)
                    nearby_invisible = False
                    for check_line in range(max(0, lineno - 6), min(len(lines), lineno + 5)):
                        if any(is_suspicious(ord(c)) for c in lines[check_line]):
                            nearby_invisible = True
                            break

                    if nearby_invisible:
                        findings.append(Finding(
                            filepath, lineno, "CRITICAL",
                            "DECODER_NEAR_PAYLOAD",
                            f"Decoder signature '{sig}' found near invisible Unicode — "
                            f"likely GlassWorm decoder function",
                        ))
                    elif sig in ("0xFE00", "0xE0100"):
                        findings.append(Finding(
                            filepath, lineno, "HIGH",
                            "DECODER_SIGNATURE",
                            f"GlassWorm decoder constant '{sig}' detected",
                        ))

    # ── Rule 4: eval() with String Construction ──────────────────────
    if is_js_ts:
        for lineno, line in enumerate(lines, 1):
            if "eval(" in line:
                # Check for string reconstruction patterns nearby
                nearby_construction = any(
                    pattern in line
                    for pattern in ["fromCharCode", "fromCodePoint", "join(", "reduce("]
                )
                if nearby_construction:
                    findings.append(Finding(
                        filepath, lineno, "HIGH",
                        "EVAL_STRING_CONSTRUCTION",
                        "eval() combined with string construction — common malware pattern",
                    ))
                else:
                    findings.append(Finding(
                        filepath, lineno, "MEDIUM",
                        "EVAL_USAGE",
                        "eval() usage detected — review manually",
                    ))

    # ── Rule 5: Solana / Blockchain C2 Indicators ─────────────────────
    solana_indicators = [
        "solana", "api.mainnet-beta.solana.com",
        "getSignaturesForAddress", "getParsedTransaction",
        "memo program", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    ]
    for lineno, line in enumerate(lines, 1):
        lower_line = line.lower()
        for indicator in solana_indicators:
            if indicator.lower() in lower_line:
                # Only flag in non-blockchain projects
                if not any(
                    bc in filepath.lower()
                    for bc in ["solana", "blockchain", "web3", "dapp", "defi"]
                ):
                    findings.append(Finding(
                        filepath, lineno, "MEDIUM",
                        "BLOCKCHAIN_C2",
                        f"Solana/blockchain reference in non-blockchain context — "
                        f"possible C2 indicator ('{indicator}')",
                    ))
                break

    # ── Rule 6: Google Calendar C2 Backup ─────────────────────────────
    gcal_indicators = ["calendar.google.com/calendar", "googleapis.com/calendar"]
    for lineno, line in enumerate(lines, 1):
        for indicator in gcal_indicators:
            if indicator in line and is_js_ts:
                findings.append(Finding(
                    filepath, lineno, "LOW",
                    "GCAL_C2_POSSIBLE",
                    "Google Calendar API reference — GlassWorm uses this as backup C2",
                ))
                break

    # ── Rule 7: Mid-file BOM ──────────────────────────────────────────
    for lineno, line in enumerate(lines, 1):
        if lineno > 1 and "\ufeff" in line:
            findings.append(Finding(
                filepath, lineno, "MEDIUM",
                "MID_FILE_BOM",
                "BOM character found mid-file — possible invisible code injection marker",
            ))

    # ── Rule 8: Suspicious package.json fields ────────────────────────
    if Path(filepath).name == "package.json":
        try:
            pkg = json.loads(content)
            # Check for suspicious lifecycle scripts
            scripts = pkg.get("scripts", {})
            for hook in ["preinstall", "postinstall", "preuninstall"]:
                if hook in scripts:
                    script_val = scripts[hook]
                    if any(
                        sus in script_val
                        for sus in ["curl", "wget", "node -e", "eval", "exec("]
                    ):
                        findings.append(Finding(
                            filepath, 0, "HIGH",
                            "SUSPICIOUS_LIFECYCLE_SCRIPT",
                            f"Suspicious '{hook}' script: {script_val[:100]}",
                        ))
        except json.JSONDecodeError:
            pass

    return findings


def scan_directory(dirpath: str, extended: bool = False, verbose: bool = False) -> ScanResult:
    """Recursively scan a directory."""
    result = ScanResult(path=dirpath)

    for root, dirs, files in os.walk(dirpath):
        # Skip common non-essential directories
        dirs[:] = [
            d for d in dirs
            if d not in {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
        ]

        for filename in files:
            filepath = os.path.join(root, filename)

            if Path(filename).suffix not in SCANNABLE_EXTENSIONS:
                continue

            try:
                file_findings = scan_file(filepath, extended, verbose)
                result.findings.extend(file_findings)
                result.files_scanned += 1
            except Exception as e:
                result.errors.append(f"{filepath}: {str(e)}")

    return result


def print_findings(result: ScanResult, use_json: bool = False):
    """Pretty-print scan results."""
    if use_json:
        output = {
            "path": result.path,
            "files_scanned": result.files_scanned,
            "summary": {
                "critical": result.critical_count,
                "high": result.high_count,
                "total": len(result.findings),
            },
            "findings": [asdict(f) for f in result.findings],
            "errors": result.errors,
        }
        print(json.dumps(output, indent=2))
        return

    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[33m",    # Orange
        "LOW": "\033[36m",       # Cyan
        "INFO": "\033[37m",      # White
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    print(f"\n{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   GlassWorm Detection Scanner — Results      ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")
    print(f"  Scanned: {result.files_scanned} files in {result.path}")
    print(f"  Findings: {len(result.findings)} "
          f"({SEVERITY_COLORS['CRITICAL']}CRITICAL: {result.critical_count}{RESET}, "
          f"{SEVERITY_COLORS['HIGH']}HIGH: {result.high_count}{RESET})\n")

    if not result.findings:
        print(f"  \033[92m✓ No GlassWorm indicators detected.{RESET}\n")
        return

    for f in sorted(result.findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)):
        color = SEVERITY_COLORS.get(f.severity, RESET)
        print(f"  {color}[{f.severity}]{RESET} {f.rule}")
        print(f"    File: {f.file}:{f.line}")
        print(f"    {f.description}")
        if f.details:
            print(f"    Details: {f.details}")
        print()

    if result.errors:
        print(f"  Errors ({len(result.errors)}):")
        for err in result.errors:
            print(f"    - {err}")

    # Exit code guidance
    if result.critical_count > 0:
        print(f"\n  {SEVERITY_COLORS['CRITICAL']}{BOLD}⚠  CRITICAL findings detected — likely GlassWorm infection.{RESET}")
        print(f"  {BOLD}ACTION REQUIRED:{RESET}")
        print(f"    1. Do NOT run or install this code")
        print(f"    2. Rotate all NPM, GitHub, OpenVSX, and Git credentials")
        print(f"    3. Check for unauthorized extension updates")
        print(f"    4. Scan workstation for SOCKS proxies / VNC servers")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Scan files for GlassWorm invisible Unicode payloads"
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON (for CI/CD)")
    parser.add_argument("--verbose", action="store_true", help="Show character-level details")
    parser.add_argument("--extended", action="store_true",
                        help="Include PUA ranges (higher false-positive rate)")
    args = parser.parse_args()

    target = args.path

    if os.path.isfile(target):
        result = ScanResult(path=target, files_scanned=1)
        result.findings = scan_file(target, args.extended, args.verbose)
    elif os.path.isdir(target):
        result = scan_directory(target, args.extended, args.verbose)
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(2)

    print_findings(result, use_json=args.json)

    # Exit codes for CI/CD integration
    if result.critical_count > 0:
        sys.exit(1)
    elif result.high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
