#!/usr/bin/env bash
# Verify the @injectshield/mcp publish + MCP Registry submission landed.
# Run this AFTER the publish-mcp GitHub Actions workflow has gone green.
set -euo pipefail
PKG="@injectshield/mcp"
EXPECTED_VERSION="${EXPECTED_VERSION:-0.1.0}"
REG_NAME="io.github.bch1212/injectshield"

red() { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
PASS=0; FAIL=0
ok()   { green "  ✓ $1"; PASS=$((PASS+1)); }
fail() { red   "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "── npm registry ──"
ver=$(curl -sS "https://registry.npmjs.org/${PKG}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('dist-tags',{}).get('latest','none'))" 2>/dev/null || echo "none")
[[ "$ver" == "$EXPECTED_VERSION" ]] && ok "npm latest = $ver" || fail "npm latest = $ver (want $EXPECTED_VERSION)"

echo
echo "── tarball install + execute ──"
TMP=$(mktemp -d)
pushd "$TMP" >/dev/null
if npm install --silent --no-audit --no-fund --prefix "$TMP" "${PKG}@${EXPECTED_VERSION}" >/dev/null 2>&1; then
  ok "npm install succeeded"
  if [[ -x "$TMP/node_modules/.bin/injectshield-mcp" ]]; then
    ok "binary present at node_modules/.bin/injectshield-mcp"
  else
    fail "binary missing"
  fi
else
  fail "npm install failed"
fi
popd >/dev/null

echo
echo "── MCP Registry ──"
hits=$(curl -sS "https://registry.modelcontextprotocol.io/v0/servers?search=injectshield" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('servers') or []))" 2>/dev/null || echo "0")
if [[ "$hits" -ge 1 ]]; then
  ok "MCP Registry listing exists ($hits server)"
else
  fail "MCP Registry not listed yet"
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[[ "$FAIL" == "0" ]]
