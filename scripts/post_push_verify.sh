#!/bin/bash
# Post-push verification: verify that `git push` succeeded.
# Checks: remote HEAD matches local, diff stats, remote file existence.
# Exit 0 = all OK, exit 1 = something is wrong.
set -e

echo "🔍 Post-push verification..."
echo ""

ERRORS=0

# ── 1. Remote HEAD vs local HEAD ──
echo "  ◆ Checking remote HEAD matches local..."

REMOTE_SHA=$(git ls-remote origin main 2>/dev/null | awk '{print $1}')
LOCAL_SHA=$(git rev-parse HEAD)

if [ -z "$REMOTE_SHA" ]; then
    echo "    ❌ Could not fetch remote HEAD (git ls-remote failed)"
    ERRORS=$((ERRORS + 1))
elif [ "$REMOTE_SHA" != "$LOCAL_SHA" ]; then
    echo "    ❌ Remote HEAD ($REMOTE_SHA) does NOT match local HEAD ($LOCAL_SHA)"
    ERRORS=$((ERRORS + 1))
else
    echo "    ✅ Remote HEAD matches local HEAD ($LOCAL_SHA)"
fi

# ── 2. Files changed in latest commit ──
echo ""
echo "  ◆ Files changed in latest commit:"
echo ""
git diff --stat HEAD~1 HEAD 2>/dev/null || echo "    (no previous commit or diff unavailable)"
echo ""

# ── 3. Verify changed .py files exist and are non-empty on remote ──
echo "  ◆ Checking .py files on remote..."

CHANGED_PY_FILES=$(git diff --name-only HEAD~1 HEAD 2>/dev/null | grep '\.py$' || true)

if [ -z "$CHANGED_PY_FILES" ]; then
    echo "    ℹ️  No .py files changed in this commit — skipping file checks"
else
    while IFS= read -r f; do
        # Use git show to check file content from the committed tree (HEAD)
        FILE_SIZE=$(git show HEAD:"$f" 2>/dev/null | wc -c)
        if [ "$FILE_SIZE" -eq 0 ]; then
            echo "    ❌ $f — empty (0 bytes) on remote"
            ERRORS=$((ERRORS + 1))
        else
            echo "    ✅ $f — $FILE_SIZE bytes"
        fi
    done <<< "$CHANGED_PY_FILES"
fi

# ── Summary ──
echo ""
echo "═══ Post-push Summary ═══"
echo "  Commit SHA : $LOCAL_SHA"
echo "  Files pushed: $(git diff --name-only HEAD~1 HEAD 2>/dev/null | wc -l)"
echo "  Status: "

if [ $ERRORS -gt 0 ]; then
    echo "    ❌ VERIFICATION FAILED — $ERRORS issue(s) found"
    exit 1
else
    echo "    ✅ VERIFICATION PASSED — all checks OK"
    exit 0
fi
