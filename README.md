# tripwire-feed

Public IoC feed for [agent-tripwire](https://github.com/jmaleonard/agent-tripwire).
A daily GitHub Actions job fetches Aikido's npm + PyPI malware lists, merges them
(~130K IoCs), and publishes them here for tripwire daemons to pull. Free to host,
no AWS.

## Layout

```
Release `feed` tag:
  snapshot-YYYY-MM-DD.json   full snapshot, 3 newest retained ← release asset (manifest points here)
  latest.json                clobbered mirror of newest        ← human convenience only

feed/v1/:
  manifest.json              index clients read first
  delta-YYYY-MM-DD.json      daily diff, last 30 retained      ← committed (small, audit trail)
```

The snapshot is date-stamped (never a reused filename), so its CDN URL is always
fresh — clobbering one `latest.json` would let Fastly serve a stale copy.

### Consume

```bash
# the index — start here; it points at the current snapshot + deltas
curl -s https://raw.githubusercontent.com/jmaleonard/tripwire-feed/main/feed/v1/manifest.json
# newest full snapshot (mirror; clients follow manifest.full.url instead)
curl -sL https://github.com/jmaleonard/tripwire-feed/releases/download/feed/latest.json
```

A tripwire daemon does this automatically on startup and every 6h
(`tripwire ioc sync` to force it): reads the manifest, downloads only the deltas
it's missing, and SHA-256-verifies every body before applying. Format and client
are documented in
[agent-tripwire `spec/docs/feed.md`](https://github.com/jmaleonard/agent-tripwire/blob/main/spec/docs/feed.md).

## Publish

`.github/workflows/seed-feed.yml` runs daily at 06:00 UTC (or via
**Run workflow**). It executes the self-contained `scripts/publish-feed.mjs`
bundle and publishes to this repo with the built-in `GITHUB_TOKEN` — no secrets
to configure.

The bundle is generated from
[agent-tripwire](https://github.com/jmaleonard/agent-tripwire)
(`packages/feeds` + `scripts/publish-feed.mjs`). To update it:

```bash
# in an agent-tripwire checkout
pnpm --filter @tripwire/shared --filter @tripwire/feeds build
npx esbuild scripts/publish-feed.mjs --bundle --platform=node --format=esm \
  --outfile=/path/to/tripwire-feed/scripts/publish-feed.mjs
```
