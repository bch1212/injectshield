#!/usr/bin/env bash
# Deploy the InjectShield landing page to Cloudflare Pages.
# Sources the Pages-scoped CF token from sibling fishing-seo project.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Pages-scoped token (Pages:Edit on Brett's gmail account).
PAGES_TOKEN_FILE="$(cd "$ROOT/.." && pwd)/fishing-seo/.cloudflare_env"
if [[ -f "$PAGES_TOKEN_FILE" ]]; then
  set -a; source "$PAGES_TOKEN_FILE"; set +a
fi
: "${CLOUDFLARE_TOKEN:?Pages-scoped CLOUDFLARE_TOKEN not found}"
ACCOUNT_ID="654f33a1338a52c1bd59916d59f95c8f"
PROJECT="promptshield"
API_BASE="${API_BASE_URL:-https://promptshield-api-production.up.railway.app}"

# Stamp version + API base into HTML.
VERSION="$(date +%s)"
WORK="$(mktemp -d -t promptshield-XXXX)"
cp -r public/* "$WORK"/
# Replace placeholders.
for f in "$WORK"/*.html "$WORK"/js/*.js; do
  [[ -f "$f" ]] || continue
  sed -i "s|__VERSION__|$VERSION|g; s|__API_BASE__|$API_BASE|g" "$f" 2>/dev/null || true
done

# Use wrangler from a sandboxed install (avoids polluting the API node_modules).
WR_DIR="/tmp/wrangler-only"
if [[ ! -x "$WR_DIR/node_modules/wrangler/bin/wrangler.js" ]]; then
  mkdir -p "$WR_DIR" && cd "$WR_DIR"
  npm init -y >/dev/null && npm install wrangler --no-audit --no-fund --loglevel=error >/dev/null
  cd "$ROOT"
fi
WR="node $WR_DIR/node_modules/wrangler/bin/wrangler.js"

# Ensure project exists. Pages has its own project create endpoint.
echo "→ ensuring project $PROJECT exists…"
exists=$(curl -sS -H "authorization: Bearer $CLOUDFLARE_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/pages/projects/$PROJECT" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('yes' if d.get('success') else 'no')")
if [[ "$exists" != "yes" ]]; then
  curl -sS -X POST -H "authorization: Bearer $CLOUDFLARE_TOKEN" -H "content-type: application/json" \
    "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/pages/projects" \
    -d "{\"name\":\"$PROJECT\",\"production_branch\":\"main\"}" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print('created:', d.get('success'), d.get('errors'))"
fi

echo "→ deploying via wrangler…"
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_TOKEN" \
CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID" \
$WR pages deploy "$WORK" --project-name="$PROJECT" --branch=main --commit-dirty=true 2>&1 | tail -20

rm -rf "$WORK"
echo "Done. Visit https://$PROJECT.pages.dev/"
