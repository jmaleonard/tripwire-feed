// scripts/publish-feed.mjs
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// packages/feeds/dist/aikido.js
var AIKIDO_NPM_URL = "https://malware-list.aikido.dev/malware_predictions.json";
var AIKIDO_PYPI_URL = "https://malware-list.aikido.dev/malware_pypi.json";
var AikidoFeed = class {
  id = "aikido";
  npmUrl;
  pypiUrl;
  fetchImpl;
  constructor(opts = {}) {
    this.npmUrl = opts.npmUrl ?? AIKIDO_NPM_URL;
    this.pypiUrl = opts.pypiUrl ?? AIKIDO_PYPI_URL;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }
  async *refresh(opts = {}) {
    const fetchImpl = opts.fetch ?? this.fetchImpl;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const targets = [
      { url: this.npmUrl, ecosystem: "npm" },
      { url: this.pypiUrl, ecosystem: "pypi" }
    ];
    for (const { url, ecosystem } of targets) {
      const res = await fetchImpl(url, opts.signal ? { signal: opts.signal } : {});
      if (!res.ok) {
        throw new Error(`Aikido feed ${url} returned HTTP ${res.status}`);
      }
      const data = await res.json();
      if (!Array.isArray(data)) {
        throw new Error(`Aikido feed ${url} did not return an array`);
      }
      for (const record of data) {
        yield {
          ecosystem,
          package: record.package_name,
          version_spec: record.version,
          sources: [
            {
              name: "aikido",
              metadata: { reason: record.reason }
            }
          ],
          first_seen: now,
          last_seen: now
        };
      }
    }
  }
  async healthCheck() {
    const lastChecked = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const res = await this.fetchImpl(this.npmUrl, { method: "HEAD" });
      return res.ok ? { ok: true, lastChecked } : { ok: false, message: `HTTP ${res.status}`, lastChecked };
    } catch (err) {
      return { ok: false, message: err.message, lastChecked };
    }
  }
};

// packages/feeds/dist/github.js
function githubHeaders(token) {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "tripwire-feed"
  };
  if (token)
    h.Authorization = `Bearer ${token}`;
  return h;
}
function nextLink(link) {
  if (!link)
    return null;
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (m)
      return m[1] ?? null;
  }
  return null;
}

// packages/feeds/dist/ghsa.js
var GHSA_ADVISORIES_URL = "https://api.github.com/advisories";
var ECOSYSTEMS = [
  { slug: "npm", ecosystem: "npm" },
  { slug: "pip", ecosystem: "pypi" }
];
var GhsaFeed = class {
  id = "ghsa";
  token;
  fetchImpl;
  baseUrl;
  maxPages;
  constructor(opts = {}) {
    this.token = opts.token;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.baseUrl = opts.baseUrl ?? GHSA_ADVISORIES_URL;
    this.maxPages = opts.maxPages ?? 100;
  }
  async *refresh(opts = {}) {
    const fetchImpl = opts.fetch ?? this.fetchImpl;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    for (const { slug, ecosystem } of ECOSYSTEMS) {
      let url = `${this.baseUrl}?type=malware&ecosystem=${slug}&per_page=100`;
      let pages = 0;
      while (url && pages < this.maxPages) {
        const res = await fetchImpl(url, {
          headers: githubHeaders(this.token),
          ...opts.signal ? { signal: opts.signal } : {}
        });
        if (!res.ok) {
          throw new Error(`GHSA advisories ${url} returned HTTP ${res.status}`);
        }
        const data = await res.json();
        if (!Array.isArray(data)) {
          throw new Error(`GHSA advisories ${url} did not return an array`);
        }
        for (const adv of data) {
          const seen = adv.published_at ?? now;
          for (const vuln of adv.vulnerabilities ?? []) {
            if (!vuln.package || vuln.package.ecosystem !== slug)
              continue;
            yield {
              ecosystem,
              package: vuln.package.name,
              version_spec: normalizeRange(vuln.vulnerable_version_range),
              sources: [{ name: "ghsa", metadata: { id: adv.ghsa_id } }],
              first_seen: seen,
              last_seen: seen
            };
          }
        }
        url = nextLink(res.headers.get("link"));
        pages++;
      }
    }
  }
  async healthCheck() {
    const lastChecked = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const res = await this.fetchImpl(`${this.baseUrl}?type=malware&ecosystem=npm&per_page=1`, {
        headers: githubHeaders(this.token)
      });
      return res.ok ? { ok: true, lastChecked } : { ok: false, message: `HTTP ${res.status}`, lastChecked };
    } catch (err) {
      return { ok: false, message: err.message, lastChecked };
    }
  }
};
function normalizeRange(range) {
  if (!range || range.trim() === ">= 0")
    return "*";
  return range.trim();
}

// packages/feeds/dist/community.js
var CommunityFeed = class {
  id = "community";
  repo;
  token;
  fetchImpl;
  baseUrl;
  reportLabel;
  approvedLabel;
  ingestedLabel;
  maxPages;
  constructor(opts = {}) {
    this.repo = opts.repo ?? "jmaleonard/tripwire-feed";
    this.token = opts.token;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.github.com";
    this.reportLabel = opts.reportLabel ?? "ioc-report";
    this.approvedLabel = opts.approvedLabel ?? "approved";
    this.ingestedLabel = opts.ingestedLabel ?? "ingested";
    this.maxPages = opts.maxPages ?? 50;
  }
  async *refresh(opts = {}) {
    const fetchImpl = opts.fetch ?? this.fetchImpl;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const labels = `${this.reportLabel},${this.approvedLabel}`;
    let url = `${this.baseUrl}/repos/${this.repo}/issues?state=open&labels=${encodeURIComponent(labels)}&per_page=100`;
    let pages = 0;
    while (url && pages < this.maxPages) {
      const res = await fetchImpl(url, {
        headers: githubHeaders(this.token),
        ...opts.signal ? { signal: opts.signal } : {}
      });
      if (!res.ok) {
        throw new Error(`Community issues ${url} returned HTTP ${res.status}`);
      }
      const issues = await res.json();
      if (!Array.isArray(issues)) {
        throw new Error(`Community issues ${url} did not return an array`);
      }
      for (const issue of issues) {
        if (issue.pull_request)
          continue;
        const names = (issue.labels ?? []).map((l) => typeof l === "string" ? l : l.name);
        if (names.includes(this.ingestedLabel))
          continue;
        const fields = parseIssueForm(issue.body ?? "");
        const pkg = (fields["Package name"] ?? "").trim();
        if (!pkg)
          continue;
        const seen = issue.created_at ?? now;
        yield {
          ecosystem: normalizeEcosystem(fields["Ecosystem"] ?? ""),
          package: pkg,
          version_spec: normalizeVersion(fields["Affected version(s)"] ?? ""),
          sources: [
            {
              name: "community-report",
              metadata: { issue: issue.number, url: issue.html_url }
            }
          ],
          first_seen: seen,
          last_seen: seen
        };
      }
      url = nextLink(res.headers.get("link"));
      pages++;
    }
  }
  async healthCheck() {
    const lastChecked = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/repos/${this.repo}`, {
        headers: githubHeaders(this.token)
      });
      return res.ok ? { ok: true, lastChecked } : { ok: false, message: `HTTP ${res.status}`, lastChecked };
    } catch (err) {
      return { ok: false, message: err.message, lastChecked };
    }
  }
};
function parseIssueForm(body) {
  const out = {};
  for (const part of body.split(/^### /m)) {
    const nl = part.indexOf("\n");
    if (nl === -1)
      continue;
    const heading = part.slice(0, nl).trim();
    if (!heading)
      continue;
    const value = part.slice(nl + 1).trim();
    out[heading] = value === "_No response_" ? "" : value;
  }
  return out;
}
function normalizeEcosystem(s) {
  const v = s.trim().toLowerCase();
  if (v === "npm")
    return "npm";
  if (v === "pypi" || v === "pip")
    return "pypi";
  return "other";
}
function normalizeVersion(s) {
  const v = s.trim();
  if (!v || v.toLowerCase() === "all" || v === "*")
    return "*";
  return v;
}

// packages/feeds/dist/merger.js
function mergeFeeds(entries) {
  const map = /* @__PURE__ */ new Map();
  for (const incoming of entries) {
    const key = `${incoming.ecosystem}\0${incoming.package}\0${incoming.version_spec}`;
    const existing = map.get(key);
    if (existing === void 0) {
      map.set(key, { ...incoming, sources: [...incoming.sources] });
      continue;
    }
    mergeInto(existing, incoming);
  }
  return [...map.values()];
}
function mergeInto(existing, incoming) {
  for (const src of incoming.sources) {
    if (!hasSource(existing.sources, src)) {
      existing.sources.push(src);
    }
  }
  if (incoming.first_seen < existing.first_seen) {
    existing.first_seen = incoming.first_seen;
  }
  if (incoming.last_seen > existing.last_seen) {
    existing.last_seen = incoming.last_seen;
  }
  if (existing.campaign === void 0 && incoming.campaign !== void 0) {
    existing.campaign = incoming.campaign;
  }
}
function hasSource(haystack, needle) {
  return haystack.some((s) => s.name === needle.name);
}

// packages/feeds/dist/seeder.js
async function runSeeder(sources, opts = {}) {
  const collected = [];
  const sourceStats = [];
  for (const source of sources) {
    let count = 0;
    try {
      for await (const entry of source.refresh(opts)) {
        collected.push(entry);
        count++;
      }
      sourceStats.push({ id: source.id, count, ok: true });
    } catch (err) {
      sourceStats.push({
        id: source.id,
        count,
        ok: false,
        error: err.message
      });
    }
  }
  return {
    entries: mergeFeeds(collected),
    sourceStats,
    generatedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}

// packages/feeds/dist/delta.js
var FEED_VERSION = 1;
function iocKey(e) {
  return `${e.ecosystem}\0${e.package}\0${e.version_spec}`;
}
function fingerprint(e) {
  return JSON.stringify({
    s: e.sources,
    c: e.campaign ?? null,
    f: e.first_seen,
    l: e.last_seen
  });
}
function computeDelta(prev, next, opts) {
  const prevMap = /* @__PURE__ */ new Map();
  for (const e of prev)
    prevMap.set(iocKey(e), e);
  const added = [];
  const nextKeys = /* @__PURE__ */ new Set();
  for (const e of next) {
    const key = iocKey(e);
    nextKeys.add(key);
    const before = prevMap.get(key);
    if (before === void 0 || fingerprint(before) !== fingerprint(e)) {
      added.push(e);
    }
  }
  const removed = [];
  for (const e of prev) {
    if (!nextKeys.has(iocKey(e))) {
      removed.push({
        ecosystem: e.ecosystem,
        package: e.package,
        version_spec: e.version_spec
      });
    }
  }
  return {
    feed_version: FEED_VERSION,
    base_date: opts.baseDate,
    date: opts.date,
    generated_at: opts.generatedAt,
    added,
    removed
  };
}

// packages/feeds/dist/manifest.js
import { createHash } from "node:crypto";
function sha256Hex(body) {
  return createHash("sha256").update(body, "utf-8").digest("hex");
}
function buildManifest(input) {
  const deltas = [...input.deltas].sort((a, b) => a.date.localeCompare(b.date));
  const latest_date = deltas.length > 0 ? deltas[deltas.length - 1].date : input.full.date;
  return {
    feed_version: FEED_VERSION,
    generated_at: input.generatedAt,
    latest_date,
    full: input.full,
    deltas
  };
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

// packages/feeds/dist/publish.js
var DEFAULT_KEEP_DELTAS = 30;
function planPublish(input) {
  const keep = input.keepDeltas ?? DEFAULT_KEEP_DELTAS;
  const snapshot = {
    generated_at: input.generatedAt,
    date: input.date,
    entries: [...input.nextEntries]
  };
  const snapshotBody = JSON.stringify(snapshot);
  let delta = null;
  let deltaBody = null;
  let newRef = null;
  if (input.prevManifest !== null && input.prevManifest.latest_date !== input.date) {
    delta = computeDelta(input.prevEntries, input.nextEntries, {
      baseDate: input.prevManifest.latest_date,
      date: input.date,
      generatedAt: input.generatedAt
    });
    deltaBody = JSON.stringify(delta);
    newRef = {
      date: input.date,
      base_date: input.prevManifest.latest_date,
      url: input.deltaUrl(input.date),
      sha256: sha256Hex(deltaBody),
      added: delta.added.length,
      removed: delta.removed.length
    };
  }
  const priorRefs = input.prevManifest?.deltas ?? [];
  const allRefs = newRef ? [...priorRefs, newRef] : [...priorRefs];
  const sorted = [...allRefs].sort((a, b) => a.date.localeCompare(b.date));
  const kept = sorted.slice(-keep);
  const keptDates = new Set(kept.map((d) => d.date));
  const prunedDeltaDates = priorRefs.map((d) => d.date).filter((d) => !keptDates.has(d));
  const manifest = buildManifest({
    generatedAt: input.generatedAt,
    full: {
      date: input.date,
      url: input.fullUrl,
      sha256: sha256Hex(snapshotBody),
      count: snapshot.entries.length,
      bytes: Buffer.byteLength(snapshotBody, "utf-8")
    },
    deltas: kept
  });
  return {
    snapshot,
    snapshotBody,
    delta,
    deltaBody,
    manifest,
    manifestBody: JSON.stringify(manifest),
    prunedDeltaDates
  };
}

// scripts/publish-feed.mjs
var log = (msg) => console.log(`[publish-feed] ${msg}`);
function loadConfig(env = process.env) {
  const repo = env.FEED_REPO || "jmaleonard/tripwire-feed";
  const tag = env.FEED_TAG || "feed";
  const feedDir = env.FEED_DIR || join(process.cwd(), "feed-repo");
  const feedV1 = join(feedDir, "feed", "v1");
  const date = env.PUBLISH_DATE || (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  const snapshotName = `snapshot-${date}.json`;
  return {
    repo,
    date,
    snapshotName,
    keepDeltas: Number(env.KEEP_DELTAS || 30),
    outDir: env.OUT_DIR || join(process.cwd(), "feed-out"),
    feedV1,
    manifestPath: join(feedV1, "manifest.json"),
    fullUrl: `https://github.com/${repo}/releases/download/${tag}/${snapshotName}`,
    deltaUrl: (date2) => `https://raw.githubusercontent.com/${repo}/main/feed/v1/delta-${date2}.json`,
    deltaPath: (date2) => join(feedV1, `delta-${date2}.json`)
  };
}
async function fetchJson(url) {
  const res = await fetch(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GET ${url} \u2192 HTTP ${res.status}`);
  return res.json();
}
function readJson(path) {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}
async function seedToday() {
  const seed = await runSeeder([
    new AikidoFeed(),
    // GITHUB_TOKEN lifts the advisories API from 60/hr to 5000/hr; the malware
    // corpus needs it. A failing source is logged but won't abort the run.
    new GhsaFeed({ token: process.env.GITHUB_TOKEN }),
    // Approved community reports (moderated): GitHub issues labeled
    // ioc-report + approved, not yet ingested. The workflow marks them ingested
    // after publish so they are not re-added.
    new CommunityFeed({ repo: process.env.FEED_REPO, token: process.env.GITHUB_TOKEN })
  ]);
  if (!seed.sourceStats.some((s) => s.ok)) {
    throw new Error(`all feed sources failed: ${JSON.stringify(seed.sourceStats)}`);
  }
  log(`seeded ${seed.entries.length} IoCs`);
  return seed;
}
async function loadPrevious(cfg) {
  const manifestJson = readJson(cfg.manifestPath);
  if (!manifestJson) {
    log("no previous manifest; baseline run");
    return { prevManifest: null, prevEntries: [] };
  }
  const prevManifest = parseManifest(manifestJson);
  const snapshotJson = await fetchJson(prevManifest.full.url);
  const prevEntries = snapshotJson ? parseSnapshot(snapshotJson).entries : [];
  log(`previous snapshot: ${prevEntries.length} IoCs`);
  return { prevManifest, prevEntries };
}
function writeOutputs(cfg, plan) {
  mkdirSync(cfg.outDir, { recursive: true });
  mkdirSync(cfg.feedV1, { recursive: true });
  writeFileSync(join(cfg.outDir, cfg.snapshotName), plan.snapshotBody);
  writeFileSync(join(cfg.outDir, "latest.json"), plan.snapshotBody);
  writeFileSync(cfg.manifestPath, plan.manifestBody);
  if (plan.deltaBody) {
    writeFileSync(cfg.deltaPath(cfg.date), plan.deltaBody);
    log(`delta-${cfg.date}: +${plan.delta.added.length} \u2212${plan.delta.removed.length}`);
  } else {
    log("no delta (baseline run)");
  }
  for (const date of plan.prunedDeltaDates) {
    rmSync(cfg.deltaPath(date), { force: true });
    log(`pruned delta-${date}.json`);
  }
}
async function main() {
  const cfg = loadConfig();
  log(`publishing ${cfg.date} \u2192 ${cfg.repo}`);
  const seed = await seedToday();
  const { prevManifest, prevEntries } = await loadPrevious(cfg);
  const plan = planPublish({
    nextEntries: seed.entries,
    prevEntries,
    prevManifest,
    date: cfg.date,
    generatedAt: seed.generatedAt,
    fullUrl: cfg.fullUrl,
    deltaUrl: cfg.deltaUrl,
    keepDeltas: cfg.keepDeltas
  });
  writeOutputs(cfg, plan);
  const { full, deltas, latest_date } = plan.manifest;
  log(`done: full=${full.count} IoCs, ${deltas.length} deltas, latest=${latest_date}`);
}
main().catch((err) => {
  console.error("[publish-feed] failed:", err);
  process.exit(1);
});
