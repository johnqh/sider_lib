import { test, expect } from "bun:test";
import { evaluateGates } from "./gates";
import { secretSentinel } from "./recipe";
import type { CompiledRequest, SecretSlot } from "@sudobility/sider_types";

const ORIGIN = "https://resale.fifa.com";

function slot(overrides: Partial<SecretSlot> = {}): SecretSlot {
  return {
    id: "slot:resale.fifa.com:auth_bearer",
    siteId: "site1",
    kind: "bearer",
    role: "active_inject",
    injectionLocation: { at: "header", name: "authorization" },
    allowedDestination: ORIGIN,
    resolverHints: [],
    confidence: 1,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function req(overrides: Partial<CompiledRequest> = {}): CompiledRequest {
  const sen = secretSentinel("slot:resale.fifa.com:auth_bearer");
  return {
    method: "GET",
    url: `${ORIGIN}/api/seats`,
    headers: { authorization: `Bearer ${sen}` },
    body: undefined,
    credentials: "include",
    referencedSlotIds: ["slot:resale.fifa.com:auth_bearer"],
    safetyClass: "read",
    ...overrides,
  };
}

const ctx = (extra: Partial<Parameters<typeof evaluateGates>[1]> = {}) => ({
  siteOrigin: ORIGIN,
  slotsById: { "slot:resale.fifa.com:auth_bearer": slot() },
  ...extra,
});

test("Gate A: passes a same-origin read with a confined header secret", () => {
  expect(evaluateGates(req(), ctx())).toEqual({ ok: true });
});

test("Gate A: refuses a cross-origin destination", () => {
  const out = evaluateGates(req({ url: "https://evil.com/api/seats" }), ctx());
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("same_origin");
});

test("Gate A: refuses when the slot's allowedDestination differs", () => {
  const s = slot({ allowedDestination: "https://other.com" });
  const out = evaluateGates(req(), ctx({ slotsById: { [s.id]: s } }));
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("same_origin");
});

test("Gate B: refuses a sentinel relocated into the URL", () => {
  const sen = secretSentinel("slot:resale.fifa.com:auth_bearer");
  const out = evaluateGates(
    req({ url: `${ORIGIN}/api/seats?t=${sen}`, headers: { authorization: `Bearer ${sen}` } }),
    ctx(),
  );
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("injection_location");
});

test("Gate B: refuses when the sentinel is absent from its declared location", () => {
  const out = evaluateGates(req({ headers: { authorization: "Bearer plain" } }), ctx());
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("injection_location");
});

test("Gate C: a POST (method-bound) requires confirmation even if labeled read", () => {
  const out = evaluateGates(req({ method: "POST", safetyClass: "read" }), ctx());
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("safety");
});

test("Gate C: a confirmed POST passes", () => {
  expect(evaluateGates(req({ method: "POST" }), ctx({ confirmed: true }))).toEqual({ ok: true });
});

test("Gate C: allowMutations=false blocks a mutation outright", () => {
  const out = evaluateGates(req({ method: "POST" }), ctx({ confirmed: true, allowMutations: false }));
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("safety");
});

test("cookie-borne slot is refused (must be auto-attached, never injected)", () => {
  const s = slot({ role: "auto_cookie", injectionLocation: { at: "cookie", name: "sid" } });
  const out = evaluateGates(req(), ctx({ slotsById: { [s.id]: s } }));
  expect(out.ok).toBe(false);
  if (!out.ok) expect(out.gate).toBe("injection_location");
});
