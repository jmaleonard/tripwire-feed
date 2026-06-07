// scripts/build-site.mjs
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

// packages/feeds/dist/delta.js
var FEED_VERSION = 1;

// packages/feeds/dist/manifest.js
import { createHash } from "node:crypto";
function sha256Hex(body) {
  return createHash("sha256").update(body, "utf-8").digest("hex");
}
var FeedParseError = class extends Error {
};
function asObject(v, what) {
  if (typeof v !== "object" || v === null) {
    throw new FeedParseError(`${what}: expected object`);
  }
  return v;
}
function asString(v, what) {
  if (typeof v !== "string")
    throw new FeedParseError(`${what}: expected string`);
  return v;
}
function asNumber(v, what) {
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new FeedParseError(`${what}: expected number`);
  }
  return v;
}
function asArray(v, what) {
  if (!Array.isArray(v))
    throw new FeedParseError(`${what}: expected array`);
  return v;
}
function parseManifest(json) {
  const o = asObject(json, "manifest");
  const version = asNumber(o.feed_version, "manifest.feed_version");
  if (version !== FEED_VERSION) {
    throw new FeedParseError(`manifest.feed_version ${version} unsupported (client expects ${FEED_VERSION})`);
  }
  const fullObj = asObject(o.full, "manifest.full");
  const full = {
    date: asString(fullObj.date, "manifest.full.date"),
    url: asString(fullObj.url, "manifest.full.url"),
    sha256: asString(fullObj.sha256, "manifest.full.sha256"),
    count: asNumber(fullObj.count, "manifest.full.count"),
    bytes: asNumber(fullObj.bytes, "manifest.full.bytes")
  };
  const deltas = asArray(o.deltas, "manifest.deltas").map((d, i) => {
    const dObj = asObject(d, `manifest.deltas[${i}]`);
    return {
      date: asString(dObj.date, `manifest.deltas[${i}].date`),
      base_date: asString(dObj.base_date, `manifest.deltas[${i}].base_date`),
      url: asString(dObj.url, `manifest.deltas[${i}].url`),
      sha256: asString(dObj.sha256, `manifest.deltas[${i}].sha256`),
      added: asNumber(dObj.added, `manifest.deltas[${i}].added`),
      removed: asNumber(dObj.removed, `manifest.deltas[${i}].removed`)
    };
  });
  return {
    feed_version: version,
    generated_at: asString(o.generated_at, "manifest.generated_at"),
    latest_date: asString(o.latest_date, "manifest.latest_date"),
    full,
    deltas
  };
}
function parseSnapshot(json) {
  const o = asObject(json, "snapshot");
  return {
    generated_at: asString(o.generated_at, "snapshot.generated_at"),
    date: asString(o.date, "snapshot.date"),
    entries: asArray(o.entries, "snapshot.entries")
  };
}

// packages/feeds/dist/top-offenders.js
function computeTopOffenders(entries, opts = {}) {
  const limit = opts.limit ?? 25;
  const exampleCount = opts.campaignExamples ?? 5;
  const now = opts.now ?? /* @__PURE__ */ new Date();
  const byPackage = /* @__PURE__ */ new Map();
  const ecosystems = {};
  for (const e of entries) {
    const key = `${e.ecosystem}:${e.package}`;
    let agg = byPackage.get(key);
    if (!agg) {
      agg = {
        ecosystem: e.ecosystem,
        package: e.package,
        versions: /* @__PURE__ */ new Set(),
        sources: /* @__PURE__ */ new Set(),
        campaign: e.campaign ?? null,
        firstSeen: e.first_seen,
        lastSeen: e.last_seen
      };
      byPackage.set(key, agg);
    }
    agg.versions.add(e.version_spec);
    for (const s of e.sources)
      agg.sources.add(s.name);
    if (!agg.campaign && e.campaign)
      agg.campaign = e.campaign;
    if (e.first_seen < agg.firstSeen)
      agg.firstSeen = e.first_seen;
    if (e.last_seen > agg.lastSeen)
      agg.lastSeen = e.last_seen;
  }
  const packages = [...byPackage.values()];
  for (const p of packages)
    ecosystems[p.ecosystem] = (ecosystems[p.ecosystem] ?? 0) + 1;
  const toEntry = (p) => ({
    ecosystem: p.ecosystem,
    package: p.package,
    versions: p.versions.size,
    sources: [...p.sources].sort(),
    campaign: p.campaign,
    firstSeen: p.firstSeen,
    lastSeen: p.lastSeen
  });
  const newest = [...packages].sort((a, b) => cmp(b.firstSeen, a.firstSeen) || cmp(b.lastSeen, a.lastSeen)).slice(0, limit).map(toEntry);
  const mostSourced = [...packages].filter((p) => p.sources.size > 0).sort((a, b) => b.sources.size - a.sources.size || b.versions.size - a.versions.size || cmp(b.lastSeen, a.lastSeen)).slice(0, limit).map(toEntry);
  const campaignMap = /* @__PURE__ */ new Map();
  for (const p of packages) {
    if (!p.campaign)
      continue;
    const list = campaignMap.get(p.campaign) ?? [];
    list.push(p);
    campaignMap.set(p.campaign, list);
  }
  const campaigns = [...campaignMap.entries()].map(([campaign, pkgs]) => ({
    campaign,
    packages: pkgs.length,
    ecosystems: [...new Set(pkgs.map((p) => p.ecosystem))].sort(),
    examples: pkgs.slice().sort((a, b) => cmp(b.lastSeen, a.lastSeen)).slice(0, exampleCount).map((p) => p.package)
  })).sort((a, b) => b.packages - a.packages || a.campaign.localeCompare(b.campaign)).slice(0, limit);
  return {
    generatedAt: now.toISOString(),
    totalIocs: entries.length,
    totalPackages: packages.length,
    ecosystems,
    newest,
    campaigns,
    mostSourced
  };
}
function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// packages/feeds/dist/top-offenders-html.js
function renderTopOffendersHtml(report, meta = {}) {
  const project = meta.projectUrl ?? "https://github.com/jmaleonard/agent-tripwire";
  const ecoLine = Object.entries(report.ecosystems).sort((a, b) => b[1] - a[1]).map(([eco, n]) => `${esc(eco)} ${fmtInt(n)}`).join(" \xB7 ");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="index,follow">
<title>tripwire \u2014 top offenders</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1rem 4rem;
  background: #0d1117; color: #e6edf3;
  font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
main { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2.5rem 0 .75rem; border-bottom: 1px solid #30363d; padding-bottom: .35rem; }
a { color: #58a6ff; }
.sub { color: #8b949e; margin: 0 0 1.5rem; }
.stats { display: flex; flex-wrap: wrap; gap: .5rem 1.25rem; margin: 1rem 0; color: #8b949e; }
.stats b { color: #e6edf3; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #21262d; vertical-align: top; }
th { color: #8b949e; font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.pkg { color: #ffa657; }
.eco { color: #8b949e; }
.camp { color: #ff7b72; }
.src { color: #7ee787; }
.muted { color: #8b949e; }
footer { margin-top: 3rem; color: #8b949e; font-size: .85rem; }
.empty { color: #8b949e; font-style: italic; }
</style>
</head>
<body>
<main>
  <h1>tripwire \xB7 top offenders</h1>
  <p class="sub">Packages on the public malware feed tripwire enriches events against.
  Detection-only awareness \u2014 not an accusation of any maintainer.</p>

  <div class="stats">
    <span><b>${fmtInt(report.totalPackages)}</b> packages</span>
    <span><b>${fmtInt(report.totalIocs)}</b> flagged versions</span>
    <span><b>${report.campaigns.length}</b> campaigns shown</span>
    ${ecoLine ? `<span>${ecoLine}</span>` : ""}
  </div>

  <h2>\u{1F195} Most recently flagged</h2>
  ${entriesTable(report.newest, "first seen")}

  <h2>\u{1F3AF} Biggest campaigns</h2>
  ${campaignsTable(report.campaigns)}

  ${// Only meaningful once entries are corroborated by more than one feed.
  // With a single-source feed this ranking is noise, so omit it entirely.
  report.mostSourced.some((e) => e.sources.length >= 2) ? `<h2>\u{1F6E1}\uFE0F Highest confidence (flagged by the most sources)</h2>
  ${entriesTable(report.mostSourced, "last seen")}` : ""}

  <footer>
    Generated ${esc(report.generatedAt)}${meta.feedDate ? ` from snapshot ${esc(meta.feedDate)}` : ""}.
    Source: <a href="${esc(project)}">agent-tripwire</a> \xB7
    feed data from Aikido / OSV / GitHub Advisory.
  </footer>
</main>
</body>
</html>
`;
}
function entriesTable(rows, dateLabel) {
  if (rows.length === 0)
    return `<p class="empty">Nothing to show.</p>`;
  const body = rows.map((r) => `<tr>
      <td><span class="eco">${esc(r.ecosystem)}</span> <span class="pkg">${esc(r.package)}</span></td>
      <td class="num">${fmtInt(r.versions)}</td>
      <td><span class="src">${r.sources.map(esc).join(", ") || "\u2014"}</span></td>
      <td>${r.campaign ? `<span class="camp">${esc(r.campaign)}</span>` : '<span class="muted">\u2014</span>'}</td>
      <td class="muted">${esc(dateOnly(dateLabel === "first seen" ? r.firstSeen : r.lastSeen))}</td>
    </tr>`).join("\n");
  return `<table>
    <thead><tr>
      <th>package</th><th class="num">versions</th><th>sources</th><th>campaign</th><th>${esc(dateLabel)}</th>
    </tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}
function campaignsTable(rows) {
  if (rows.length === 0)
    return `<p class="empty">No campaign-attributed packages yet.</p>`;
  const body = rows.map((r) => `<tr>
      <td><span class="camp">${esc(r.campaign)}</span></td>
      <td class="num">${fmtInt(r.packages)}</td>
      <td class="eco">${r.ecosystems.map(esc).join(", ")}</td>
      <td class="muted">${r.examples.map(esc).join(", ")}</td>
    </tr>`).join("\n");
  return `<table>
    <thead><tr>
      <th>campaign</th><th class="num">packages</th><th>ecosystems</th><th>examples</th>
    </tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}
function dateOnly(iso) {
  return iso.length >= 10 ? iso.slice(0, 10) : iso;
}
function fmtInt(n) {
  return n.toLocaleString("en-US");
}
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// scripts/build-site.mjs
var log = (msg) => console.log(`[build-site] ${msg}`);
var MANIFEST_URL = process.env.MANIFEST_URL || "https://raw.githubusercontent.com/jmaleonard/tripwire-feed/main/feed/v1/manifest.json";
var SITE_DIR = process.env.SITE_DIR || join(process.cwd(), "site");
var PROJECT_URL = process.env.PROJECT_URL || "https://github.com/jmaleonard/agent-tripwire";
async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} \u2192 HTTP ${res.status}`);
  return res.text();
}
var SNAPSHOT_FILE = process.env.SNAPSHOT_FILE || "";
async function main() {
  let body;
  if (SNAPSHOT_FILE) {
    // Local mode: consume the snapshot the publisher just built (passed as a
    // workflow artifact). Avoids the GitHub release CDN, whose cache lags the
    // freshly re-clobbered asset and breaks the integrity check on same-day
    // re-runs. The local file is the authoritative source, so no hash check.
    log(`snapshot (local): ${SNAPSHOT_FILE}`);
    body = readFileSync(SNAPSHOT_FILE, "utf-8");
  } else {
    log(`manifest: ${MANIFEST_URL}`);
    const manifest = parseManifest(JSON.parse(await fetchText(MANIFEST_URL)));
    log(`snapshot: ${manifest.full.url}`);
    body = await fetchText(manifest.full.url);
    const actual = sha256Hex(body);
    if (actual !== manifest.full.sha256) {
      throw new Error(`snapshot integrity check failed: ${actual} != ${manifest.full.sha256}`);
    }
  }
  const snapshot = parseSnapshot(JSON.parse(body));
  const report = computeTopOffenders(snapshot.entries);
  const html = renderTopOffendersHtml(report, { feedDate: snapshot.date, projectUrl: PROJECT_URL });
  mkdirSync(SITE_DIR, { recursive: true });
  writeFileSync(join(SITE_DIR, "index.html"), html);
  writeFileSync(join(SITE_DIR, "top-offenders.json"), `${JSON.stringify(report, null, 2)}
`);
  log(
    `wrote ${SITE_DIR}/ \u2014 ${report.totalPackages} packages, ${report.campaigns.length} campaigns, snapshot ${snapshot.date}`
  );
}
main().catch((err) => {
  console.error(`[build-site] ${err.message}`);
  process.exit(1);
});
