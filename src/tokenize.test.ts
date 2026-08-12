import { test, expect } from "bun:test";
import { tokenizeObservation } from "./tokenize";
import type { RawObservation, KnownSecret } from "./tokenize";

function raw(overrides: Partial<RawObservation> = {}): RawObservation {
  return {
    method: "GET",
    url: "https://resale.fifa.com/api/seats",
    requestHeaders: {},
    requestBody: undefined,
    status: 200,
    responseBody: undefined,
    timingMs: 10,
    context: { route: "/seats" },
    ...overrides,
  };
}

test("masks a credential-named request header", () => {
  const { observation, slots } = tokenizeObservation(
    raw({ requestHeaders: { authorization: "Bearer abc.def.ghi" } }),
    [],
  );
  expect(JSON.stringify(observation.requestHeaders)).not.toContain("abc.def.ghi");
  expect(slots.length).toBeGreaterThan(0);
});

test("masks a known cookie/storage value wherever it appears in a body", () => {
  const known: KnownSecret[] = [
    {
      value: "SUPERSECRETVALUE123",
      slotId: "slot:resale.fifa.com:session",
      kind: "session",
      role: "active_inject",
      resolverHint: { from: "cookie", name: "sid" },
    },
  ];
  const { observation } = tokenizeObservation(
    raw({ responseBody: { echoed: "SUPERSECRETVALUE123", ok: true } }),
    known,
  );
  expect(JSON.stringify(observation.responseBody)).not.toContain("SUPERSECRETVALUE123");
});

test("masks a JWT-shaped string in a body", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123signature";
  const { observation } = tokenizeObservation(raw({ responseBody: { token: jwt } }), []);
  expect(JSON.stringify(observation.responseBody)).not.toContain(jwt);
});

test("leaves non-secret data untouched", () => {
  const { observation } = tokenizeObservation(raw({ responseBody: { price: 400, section: "A1" } }), []);
  expect(observation.responseBody).toEqual({ price: 400, section: "A1" });
});

// --- where a secret goes is observed, never assumed ------------------------

const analyticsCookie = (value = "GA1.2.9876"): KnownSecret => ({
  value,
  slotId: "slot:www.usfca.edu:cookie_ga",
  kind: "unknown",
  role: "active_inject",
  resolverHint: { from: "cookie", name: "_ga" },
});

test("proposes no slot for a page secret the request never carries", () => {
  // Every cookie and storage entry on the page is offered as `known`, not the
  // ones this request uses. Defaulting the absent ones to an Authorization
  // header gave a public GET 21 headers all named `authorization`, each holding
  // a different analytics cookie.
  const { slots } = tokenizeObservation(raw(), [analyticsCookie()]);
  expect(slots).toEqual([]);
});

test("still masks a value it proposes no slot for", () => {
  // Absent from the REQUEST is not absent from the observation: the same value
  // echoed in a response body must not be uploaded in the clear.
  const { observation, slots } = tokenizeObservation(
    raw({ responseBody: { tracker: "GA1.2.9876" } }),
    [analyticsCookie()],
  );
  expect(JSON.stringify(observation.responseBody)).not.toContain("GA1.2.9876");
  expect(slots).toEqual([]);
});

test("proposes a slot where the value is actually found", () => {
  const { slots } = tokenizeObservation(
    raw({ requestHeaders: { "x-session": "GA1.2.9876" } }),
    [analyticsCookie()],
  );
  expect(slots).toHaveLength(1);
  expect(slots[0]!.injectionLocation).toEqual({ at: "header", name: "x-session" });
  expect(slots[0]!.role).toBe("active_inject");
});

test("finds a value in a query parameter", () => {
  const { slots } = tokenizeObservation(
    raw({ url: "https://resale.fifa.com/api/seats?sid=GA1.2.9876" }),
    [analyticsCookie()],
  );
  expect(slots[0]!.injectionLocation).toEqual({ at: "query", param: "sid" });
});

test("finds a value in the request body", () => {
  const { slots } = tokenizeObservation(
    raw({ method: "POST", requestBody: { auth: { token: "GA1.2.9876" } } }),
    [analyticsCookie()],
  );
  expect(slots[0]!.injectionLocation).toEqual({ at: "body", jsonPath: "auth.token" });
});

test("a value found in the Cookie header is attached by the browser, not injected", () => {
  const { slots } = tokenizeObservation(
    raw({ requestHeaders: { cookie: "_ga=GA1.2.9876" } }),
    [analyticsCookie()],
  );
  const slot = slots.find((s) => s.id === "slot:www.usfca.edu:cookie_ga");
  expect(slot!.role).toBe("auto_cookie");
  expect(slot!.injectionLocation.at).toBe("cookie");
});
