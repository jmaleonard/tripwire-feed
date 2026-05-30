// scripts/publish-feed.mjs
import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
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
var FEED_REPO = process.env.FEED_REPO ?? "jmaleonard/tripwire-feed";
var FEED_DIR = process.env.FEED_DIR ?? join(process.cwd(), "feed-repo");
var FEED_TAG = process.env.FEED_TAG ?? "feed";
var OUT_DIR = process.env.OUT_DIR ?? join(process.cwd(), "feed-out");
var KEEP_DELTAS = Number(process.env.KEEP_DELTAS ?? "30");
var DATE = process.env.PUBLISH_DATE || (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
var FEED_V1 = join(FEED_DIR, "feed", "v1");
var MANIFEST_PATH = join(FEED_V1, "manifest.json");
var FULL_URL = `https://github.com/${FEED_REPO}/releases/download/${FEED_TAG}/latest.json`;
var deltaUrl = (date) => `https://raw.githubusercontent.com/${FEED_REPO}/main/feed/v1/delta-${date}.json`;
async function fetchJson(url) {
  const res = await fetch(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GET ${url} \u2192 HTTP ${res.status}`);
  return res.json();
}
function readJsonFile(path) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf-8"));
}
async function main() {
  console.log(`[publish-feed] date=${DATE} repo=${FEED_REPO}`);
  const seed = await runSeeder([new AikidoFeed()]);
  const okSources = seed.sourceStats.filter((s) => s.ok);
  if (okSources.length === 0) {
    throw new Error(`all feed sources failed: ${JSON.stringify(seed.sourceStats)}`);
  }
  console.log(`[publish-feed] seeded ${seed.entries.length} IoCs`);
  const prevManifestJson = readJsonFile(MANIFEST_PATH);
  const prevManifest = prevManifestJson ? parseManifest(prevManifestJson) : null;
  let prevEntries = [];
  if (prevManifest) {
    const prevSnapshotJson = await fetchJson(FULL_URL);
    if (prevSnapshotJson) {
      prevEntries = parseSnapshot(prevSnapshotJson).entries;
      console.log(`[publish-feed] previous snapshot: ${prevEntries.length} IoCs`);
    } else {
      console.log("[publish-feed] no previous latest.json found; treating as baseline");
    }
  }
  const plan = planPublish({
    nextEntries: seed.entries,
    date: DATE,
    generatedAt: seed.generatedAt,
    prevEntries,
    prevManifest,
    fullUrl: FULL_URL,
    deltaUrl,
    keepDeltas: KEEP_DELTAS
  });
  mkdirSync(OUT_DIR, { recursive: true });
  mkdirSync(FEED_V1, { recursive: true });
  writeFileSync(join(OUT_DIR, "latest.json"), plan.snapshotBody);
  writeFileSync(MANIFEST_PATH, plan.manifestBody);
  if (plan.deltaBody) {
    writeFileSync(join(FEED_V1, `delta-${DATE}.json`), plan.deltaBody);
    console.log(
      `[publish-feed] delta-${DATE}: +${plan.delta.added.length} \u2212${plan.delta.removed.length}`
    );
  } else {
    console.log("[publish-feed] no delta (baseline run)");
  }
  for (const date of plan.prunedDeltaDates) {
    const stale = join(FEED_V1, `delta-${date}.json`);
    rmSync(stale, { force: true });
    console.log(`[publish-feed] pruned delta-${date}.json`);
  }
  console.log(
    `[publish-feed] manifest: full=${plan.manifest.full.count} IoCs, ${plan.manifest.deltas.length} deltas, latest=${plan.manifest.latest_date}`
  );
  console.log(`[publish-feed] wrote ${join(OUT_DIR, "latest.json")} (for release upload)`);
}
main().catch((err) => {
  console.error("[publish-feed] failed:", err);
  process.exit(1);
});
