import assert from "node:assert/strict";
import test from "node:test";
import { getOverview, USE_FIXTURES } from "../src/lib/api";

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: { setTimeout: (callback: () => void) => globalThis.setTimeout(callback, 0) },
});

test("fixture switch defaults on until overview API is ready", () => {
  assert.equal(USE_FIXTURES, true);
});

test("full fixture builds a deterministic score, breakdown and finding list", async () => {
  const overview = await getOverview("fixture-full");
  assert.equal(overview.status, "COMPLETED");
  assert.equal(overview.source, "fixture");
  assert.equal(overview.risk.score, 40);
  assert.equal(overview.risk.rating, "Medium");
  assert.deepEqual(overview.risk.breakdown.map(({ label, points }) => [label, points]), [
    ["G_INJECTION", 25], ["G_REG_PERSIST", 15],
  ]);
  assert.equal(overview.findings.length, 2);
  assert.ok(overview.findings.every((finding) => finding.evidence.length > 0));
});

test("partial fixture keeps timeout state and empty indicators", async () => {
  const overview = await getOverview("fixture-partial");
  assert.equal(overview.status, "PARTIAL");
  assert.equal(overview.decompStatus, "TIMEOUT");
  assert.equal(overview.source, "fixture");
  assert.equal(overview.counts.functions, 0);
  assert.equal(overview.findings.length, 0);
  assert.equal(overview.risk.score, 0);
});
