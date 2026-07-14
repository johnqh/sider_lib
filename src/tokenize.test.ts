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
