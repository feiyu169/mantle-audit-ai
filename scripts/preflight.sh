#!/bin/bash
# Pre-flight check: validate external dependencies before execution.
# Exit code 0 = all checks passed, non-zero = blocked.
set -e

echo "🔍 Pre-flight checks..."
echo ""

ERRORS=0

# ── 1. Python environment ──
if ! command -v python3 &> /dev/null; then
    echo "  ❌ Python3 not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ Python3: $(python3 --version)"
fi

# ── 2. solc ──
SOLC_PATH="${HOME}/.local/bin/solc"
if [ -f "$SOLC_PATH" ]; then
    echo "  ✅ solc: $($SOLC_PATH --version | head -1)"
elif command -v solc &> /dev/null; then
    echo "  ✅ solc: $(solc --version | head -1)"
else
    echo "  ⚠️  solc not found (some features will be limited)"
fi

# ── 3. .env file ──
if [ -f ".env" ]; then
    echo "  ✅ .env exists"
else
    echo "  ❌ .env not found — copy .env.example to .env and fill in values"
    ERRORS=$((ERRORS + 1))
fi

# ── 4. ANTHROPIC_API_KEY ──
if [ -f ".env" ]; then
    if grep -q "^ANTHROPIC_API_KEY=.\+" .env 2>/dev/null; then
        echo "  ✅ ANTHROPIC_API_KEY configured"
    else
        echo "  ⚠️  ANTHROPIC_API_KEY not set (LLM analysis will be skipped)"
    fi
fi

# ── 5. MANTLE_RPC_URL ──
if [ -f ".env" ]; then
    RPC_URL=$(grep "^MANTLE_RPC_URL=" .env 2>/dev/null | cut -d= -f2-)
    if [ -n "$RPC_URL" ]; then
        # Quick connectivity check (5s timeout)
        if timeout 5 curl -s -o /dev/null -w "%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
            "$RPC_URL" 2>/dev/null | grep -q "200"; then
            echo "  ✅ MANTLE_RPC_URL reachable ($RPC_URL)"
        else
            echo "  ⚠️  MANTLE_RPC_URL unreachable ($RPC_URL)"
        fi
    else
        echo "  ⚠️  MANTLE_RPC_URL not set"
    fi
fi

# ── 6. PRIVATE_KEY ──
if [ -f ".env" ]; then
    if grep -q "^PRIVATE_KEY=0x.\+" .env 2>/dev/null; then
        echo "  ✅ PRIVATE_KEY configured"
        # Check wallet balance (requires curl + RPC)
        RPC_URL=$(grep "^MANTLE_RPC_URL=" .env 2>/dev/null | cut -d= -f2-)
        ADDR=$(python3 -c "
try:
    from eth_account import Account
    with open('.env') as f:
        for line in f:
            if line.startswith('PRIVATE_KEY='):
                key = line.strip().split('=',1)[1]
                print(Account.from_key(key).address)
                break
except ImportError:
    pass
" 2>/dev/null)
        if [ -n "$ADDR" ] && [ -n "$RPC_URL" ]; then
            BALANCE=$(timeout 5 curl -s -X POST \
                -H "Content-Type: application/json" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$ADDR\",\"latest\"],\"id\":1}" \
                "$RPC_URL" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    hex_val = data.get('result', '0x0')
    wei = int(hex_val, 16)
    eth = wei / 1e18
    print(f'{eth:.4f}')
except:
    print('unknown')
" 2>/dev/null)
            if [ "$BALANCE" = "0.0000" ]; then
                echo "  ❌ Wallet balance: 0 MNT — on-chain operations will fail"
                ERRORS=$((ERRORS + 1))
            else
                echo "  ✅ Wallet balance: $BALANCE MNT"
            fi
        fi
    else
        echo "  ⚠️  PRIVATE_KEY not set (on-chain operations will be skipped)"
    fi
fi

# ── 7. PINATA_API_KEY ──
if [ -f ".env" ]; then
    if grep -q "^PINATA_API_KEY=.\+" .env 2>/dev/null; then
        echo "  ✅ PINATA_API_KEY configured"
    else
        echo "  ⚠️  PINATA_API_KEY not set (IPFS upload will be skipped)"
    fi
fi

# ── Summary ──
echo ""
if [ $ERRORS -gt 0 ]; then
    echo "❌ Pre-flight FAILED: $ERRORS blocking issue(s)"
    echo "   Fix the issues above before proceeding."
    exit 1
else
    echo "✅ Pre-flight PASSED: all critical checks OK"
    exit 0
fi
