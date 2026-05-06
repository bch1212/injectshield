#!/usr/bin/env bash
# Autonomous Railway deploy for InjectShield.
#
# - Reuses the shared deploy-secrets file at the workspace parent.
# - Creates the Railway project + Postgres service + API service via GraphQL.
# - Sets all env vars (Stripe live, SendGrid, Anthropic, Discord, etc.).
# - Deploys the source via `railway up`.
#
# Idempotent: re-running on an existing project re-uses IDs from
# .railway-deploy.json (stamped on first success).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Load workspace-level secrets.
SECRETS_FILE="$(cd "$ROOT/.." && pwd)/.deploy-secrets.env"
if [[ -f "$SECRETS_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$SECRETS_FILE"; set +a
fi
# Load Stripe price IDs created earlier.
if [[ -f .stripe-prices.env ]]; then
  set -a; source .stripe-prices.env; set +a
fi

: "${RAILWAY_TOKEN:?RAILWAY_TOKEN missing — set in deploy-secrets.env}"
: "${STRIPE_SECRET_KEY:?STRIPE_SECRET_KEY missing}"
: "${STRIPE_WEBHOOK_SECRET:?STRIPE_WEBHOOK_SECRET missing}"
: "${STRIPE_PRICE_HOBBY:?STRIPE_PRICE_HOBBY missing — run scripts/setup-stripe.mjs first}"
: "${SENDGRID_API_KEY:?SENDGRID_API_KEY missing}"
: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY missing}"

export RAILWAY_API_TOKEN="$RAILWAY_TOKEN"

GQL="https://backboard.railway.com/graphql/v2"

gql() {
  local query="$1" vars="${2:-{\}}"
  curl -sS -X POST "$GQL" \
    -H "authorization: Bearer $RAILWAY_API_TOKEN" \
    -H "content-type: application/json" \
    -d "$(jq -nc --arg q "$query" --argjson v "$vars" '{query:$q,variables:$v}')"
}

STATE=.railway-deploy.json
[[ -f "$STATE" ]] || echo '{}' > "$STATE"
get() { jq -r --arg k "$1" '.[$k] // empty' "$STATE"; }
put() { content=$(jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$STATE"); echo "$content" > "$STATE"; }

# 1. Project
WORKSPACE_ID="$(get workspace_id)"
if [[ -z "$WORKSPACE_ID" ]]; then
  resp=$(gql 'query{me{workspaces{id name}}}' '{}')
  WORKSPACE_ID=$(echo "$resp" | jq -r '.data.me.workspaces[0].id // empty')
  [[ -z "$WORKSPACE_ID" ]] && { echo "no workspaces visible: $resp"; exit 1; }
  put workspace_id "$WORKSPACE_ID"
fi
echo "→ workspace_id=$WORKSPACE_ID"

PROJECT_ID="$(get project_id)"
if [[ -z "$PROJECT_ID" ]]; then
  echo "→ creating Railway project 'promptshield'…"
  resp=$(gql 'mutation($n:String!,$d:String!,$w:String!){projectCreate(input:{name:$n,description:$d,workspaceId:$w}){id name environments{edges{node{id name}}}}}' "$(jq -nc --arg n "promptshield" --arg d "InjectShield — prompt-injection firewall API" --arg w "$WORKSPACE_ID" '{n:$n,d:$d,w:$w}')")
  PROJECT_ID=$(echo "$resp" | jq -r '.data.projectCreate.id // empty')
  ENV_ID=$(echo "$resp" | jq -r '[.data.projectCreate.environments.edges[].node | select(.name=="production")] | .[0].id // empty')
  [[ -z "$ENV_ID" ]] && ENV_ID=$(echo "$resp" | jq -r '.data.projectCreate.environments.edges[0].node.id // empty')
  [[ -z "$PROJECT_ID" ]] && { echo "$resp"; exit 1; }
  put project_id "$PROJECT_ID"
  put env_id "$ENV_ID"
  echo "  project_id=$PROJECT_ID  env=$ENV_ID"
else
  ENV_ID="$(get env_id)"
  echo "→ reusing project $PROJECT_ID env $ENV_ID"
fi

# 2. Postgres service (Railway's official postgres-ssl image)
PG_SERVICE="$(get pg_service_id)"
PG_PASSWORD="$(get pg_password)"
if [[ -z "$PG_SERVICE" ]]; then
  echo "→ creating Postgres service from postgres-ssl image…"
  resp=$(gql 'mutation($p:String!,$n:String!,$src:ServiceSourceInput){serviceCreate(input:{projectId:$p,name:$n,source:$src}){id name}}' \
    "$(jq -nc --arg p "$PROJECT_ID" --arg n "postgres" '{p:$p,n:$n,src:{image:"ghcr.io/railwayapp-templates/postgres-ssl:latest"}}')")
  PG_SERVICE=$(echo "$resp" | jq -r '.data.serviceCreate.id // empty')
  [[ -z "$PG_SERVICE" ]] && { echo "$resp"; exit 1; }
  PG_PASSWORD="$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p)"
  # Postgres image expects POSTGRES_USER/PASSWORD/DB.
  gql 'mutation($i:VariableUpsertInput!){variableUpsert(input:$i)}' \
    "$(jq -nc --arg p "$PROJECT_ID" --arg e "$ENV_ID" --arg s "$PG_SERVICE" '{i:{projectId:$p,environmentId:$e,serviceId:$s,name:"POSTGRES_USER",value:"postgres"}}')" >/dev/null
  gql 'mutation($i:VariableUpsertInput!){variableUpsert(input:$i)}' \
    "$(jq -nc --arg p "$PROJECT_ID" --arg e "$ENV_ID" --arg s "$PG_SERVICE" --arg v "$PG_PASSWORD" '{i:{projectId:$p,environmentId:$e,serviceId:$s,name:"POSTGRES_PASSWORD",value:$v}}')" >/dev/null
  gql 'mutation($i:VariableUpsertInput!){variableUpsert(input:$i)}' \
    "$(jq -nc --arg p "$PROJECT_ID" --arg e "$ENV_ID" --arg s "$PG_SERVICE" '{i:{projectId:$p,environmentId:$e,serviceId:$s,name:"POSTGRES_DB",value:"promptshield"}}')" >/dev/null
  # Trigger an initial deploy of the postgres service so it materializes.
  gql 'mutation($s:String!,$e:String!){serviceInstanceDeployV2(serviceId:$s,environmentId:$e)}' \
    "$(jq -nc --arg s "$PG_SERVICE" --arg e "$ENV_ID" '{s:$s,e:$e}')" >/dev/null || true
  put pg_service_id "$PG_SERVICE"
  put pg_password "$PG_PASSWORD"
  echo "  pg_service_id=$PG_SERVICE"
else
  echo "→ reusing postgres service $PG_SERVICE"
fi

# 3. API service
API_SERVICE="$(get api_service_id)"
if [[ -z "$API_SERVICE" ]]; then
  echo "→ creating API service 'promptshield-api'…"
  resp=$(gql 'mutation($p:String!,$n:String!){serviceCreate(input:{projectId:$p,name:$n}){id}}' "$(jq -nc --arg p "$PROJECT_ID" --arg n "promptshield-api" '{p:$p,n:$n}')")
  API_SERVICE=$(echo "$resp" | jq -r '.data.serviceCreate.id // empty')
  [[ -z "$API_SERVICE" ]] && { echo "$resp"; exit 1; }
  put api_service_id "$API_SERVICE"
  echo "  api_service_id=$API_SERVICE"
else
  echo "→ reusing api service $API_SERVICE"
fi

# 4. Set env vars on the API service
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-https://promptshield.pages.dev}"
DISCORD_URL="${INJECTSHIELD_DISCORD_WEBHOOK_URL:-${DISCORD_WEBHOOK_URL:-}}"

echo "→ setting env vars on API service…"
set_var() {
  local name="$1" value="$2"
  gql 'mutation($i:VariableUpsertInput!){variableUpsert(input:$i)}' \
    "$(jq -nc --arg p "$PROJECT_ID" --arg e "$ENV_ID" --arg s "$API_SERVICE" --arg n "$name" --arg v "$value" '{i:{projectId:$p,environmentId:$e,serviceId:$s,name:$n,value:$v}}')" >/dev/null
}
set_var DATABASE_URL "postgres://postgres:${PG_PASSWORD}@postgres.railway.internal:5432/promptshield?sslmode=disable"
set_var ENVIRONMENT production
set_var PORT 8080
set_var PUBLIC_BASE_URL "$PUBLIC_BASE_URL"
set_var ALERT_THRESHOLD 0.8
set_var SIGNUP_FROM_EMAIL "noreply@halversonco.com"
set_var SIGNUP_FROM_NAME "InjectShield"
set_var ADMIN_EMAIL "brett.halverson@gmail.com"
set_var STRIPE_SECRET_KEY "$STRIPE_SECRET_KEY"
set_var STRIPE_WEBHOOK_SECRET "$STRIPE_WEBHOOK_SECRET"
set_var STRIPE_PRICE_HOBBY "$STRIPE_PRICE_HOBBY"
set_var STRIPE_PRICE_TEAM "$STRIPE_PRICE_TEAM"
set_var STRIPE_PRICE_PRO "$STRIPE_PRICE_PRO"
set_var SENDGRID_API_KEY "$SENDGRID_API_KEY"
set_var ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY"
[[ -n "$DISCORD_URL" ]] && set_var DISCORD_WEBHOOK_URL "$DISCORD_URL"
ADMIN_TOK="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | xxd -p)"
set_var ADMIN_TOKEN "$ADMIN_TOK"

# 5. Generate domain
DOMAIN="$(get api_domain)"
if [[ -z "$DOMAIN" ]]; then
  echo "→ generating Railway domain…"
  resp=$(gql 'mutation($s:String!,$e:String!){serviceDomainCreate(input:{serviceId:$s,environmentId:$e,targetPort:8080}){domain}}' \
    "$(jq -nc --arg s "$API_SERVICE" --arg e "$ENV_ID" '{s:$s,e:$e}')")
  DOMAIN=$(echo "$resp" | jq -r '.data.serviceDomainCreate.domain // empty')
  [[ -z "$DOMAIN" ]] && { echo "$resp"; exit 1; }
  put api_domain "$DOMAIN"
fi
echo "  domain=$DOMAIN"

# Update API_BASE_URL once we know the domain.
set_var API_BASE_URL "https://$DOMAIN"

# 6. Deploy via railway CLI (uses RAILWAY_API_TOKEN).
echo "→ deploying source via railway up…"
RAILWAY_BIN="$ROOT/node_modules/@railway/cli/bin/railway"
[[ -x "$RAILWAY_BIN" ]] || RAILWAY_BIN="railway"
"$RAILWAY_BIN" link --project "$PROJECT_ID" --environment production --service "promptshield-api" 2>&1 | tail -5 || true
"$RAILWAY_BIN" up --service "promptshield-api" --ci 2>&1 | tail -25

echo
echo "Deploy complete:"
echo "  API: https://$DOMAIN"
echo "  Health: https://$DOMAIN/healthz"
echo "  Stripe webhook should point at: https://$DOMAIN/webhooks/stripe"
