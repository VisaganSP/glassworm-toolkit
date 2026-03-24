#!/bin/bash
# ─────────────────────────────────────────────────────────────
# GlassWorm Pre-Commit Hook
# ─────────────────────────────────────────────────────────────
# Install: cp pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
#
# Blocks commits containing invisible Unicode characters commonly
# used by GlassWorm to encode malicious payloads.
# ─────────────────────────────────────────────────────────────

SUSPICIOUS=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "🔍 Scanning staged files for invisible Unicode payloads..."

for file in $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|ts|jsx|tsx|mjs|cjs|json|py)$'); do
    if [ ! -f "$file" ]; then
        continue
    fi

    # Check for variation selectors (GlassWorm's primary encoding method)
    result=$(python3 -c "
import sys
with open('$file', 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()
vs_count = sum(1 for c in text if 0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF)
zw_count = sum(1 for c in text if 0x200B <= ord(c) <= 0x200F)
pua_count = sum(1 for c in text if 0xE000 <= ord(c) <= 0xF8FF)
if vs_count > 2:
    print(f'VS:{vs_count}')
    sys.exit(1)
elif zw_count > 10:
    print(f'ZW:{zw_count}')
    sys.exit(1)
elif pua_count > 50:
    print(f'PUA:{pua_count}')
    sys.exit(1)
sys.exit(0)
" 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo -e "${RED}🚨 BLOCKED: Invisible Unicode detected in $file ($result)${NC}"
        SUSPICIOUS=1
    fi
done

if [ $SUSPICIOUS -eq 1 ]; then
    echo ""
    echo -e "${RED}══════════════════════════════════════════════════${NC}"
    echo -e "${RED}  Commit BLOCKED: GlassWorm-style payload detected${NC}"
    echo -e "${RED}══════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Run 'python3 glassworm_scanner.py .' for details."
    echo "  If this is a false positive, use: git commit --no-verify"
    echo ""
    exit 1
else
    echo -e "${GREEN}✓ No invisible Unicode payloads detected.${NC}"
fi
