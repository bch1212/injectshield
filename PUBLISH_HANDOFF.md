# Publish handoff: @injectshield/mcp + MCP Registry

Everything else is staged. Here's the single one-time action that unlocks
both `npm publish` and the Anthropic MCP Registry listing.

## What I (Claude) already did

- Built `packages/injectshield-mcp/` and verified it builds + e2e-tests against the live Railway API (5/5 pass).
- Confirmed `@injectshield/mcp` is **available** on npm (404 — not yet registered).
- Verified `npm pack --dry-run` produces a 5.1 KB tarball with the right files (LICENSE, README, dist/index.{js,d.ts}, package.json).
- Wired `.github/workflows/publish-mcp.yml` to do the whole sequence on a `mcp-v*` tag push:
  1. `npm publish --provenance --access public`
  2. Wait for npm to index the new version
  3. Request a GitHub OIDC token for audience `mcp-registry`
  4. Exchange it at `https://registry.modelcontextprotocol.io/v0/auth/oidc` for a registry token
  5. POST `server.json` to `/v0/publish` — listing appears at `https://registry.modelcontextprotocol.io/v0/servers?search=injectshield`
- Validated `packages/injectshield-mcp/server.json` — name `io.github.bch1212/injectshield`, registry npm, env vars documented.
- Set repo description, homepage `https://injectshield.dev`, and 13 discoverability topics on `bch1212/injectshield`.

## The one-time human step

You need an npm Automation Token because the package doesn't exist yet, so npm-side OIDC trusted-publisher can't be configured until *after* the first publish.

1. Go to <https://www.npmjs.com/settings/{your-username}/tokens> while signed in to the npm account that should own `@injectshield`.
2. Click **Generate New Token** → **Classic Token** → **Automation** (scoped tokens require an org plan).
3. Copy the token. It starts with `npm_`.
4. Add it as a GitHub Actions secret named `NPM_TOKEN`:
   ```bash
   gh secret set NPM_TOKEN --repo bch1212/injectshield
   ```
   (or via the web UI: https://github.com/bch1212/injectshield/settings/secrets/actions/new)

   Optional: also append it to `.deploy-secrets.env` as `NPM_TOKEN=npm_…` so future agentic runs can replicate it to other repos automatically.

## Trigger the publish

```bash
cd "Build Prompts from OpenClaw/promptshield"
git tag mcp-v0.1.0
git push origin mcp-v0.1.0
```

Watch the run: <https://github.com/bch1212/injectshield/actions>

## What to expect

- npm: `https://www.npmjs.com/package/@injectshield/mcp` should return 200 within ~30 seconds of the workflow's "Publish to npm" step succeeding.
- MCP Registry: `curl -sS https://registry.modelcontextprotocol.io/v0/servers?search=injectshield` should return 1 server within ~10 seconds of the "Submit server.json" step.

## After-publish smoke

A smoke script is at `scripts/smoke-publish.sh` — runs after the workflow completes:

```bash
bash scripts/smoke-publish.sh
```

Checks:
1. `@injectshield/mcp` is on npm with version 0.1.0
2. The package installs from npm and prints help
3. `io.github.bch1212/injectshield` appears in the MCP Registry

## Future versions

After v0.1.0 ships, configure **trusted publishers** at <https://www.npmjs.com/package/@injectshield/mcp/settings>:

- Repository: `bch1212/injectshield`
- Workflow filename: `publish-mcp.yml`
- Environment: (leave blank)

Once configured, you can drop the `NPM_TOKEN` secret entirely — subsequent
`mcp-v*` tag pushes publish via OIDC trust, no token round-trip.
