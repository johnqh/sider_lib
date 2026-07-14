// Tokenizer (browser-side, but PURE here — the caller supplies the secret
// values it discovered in the user's own cookie jar / storage). Replaces secrets
// in a raw observation with a readable placeholder "{{secret:<slotId>}}" and
// emits SecretSlot proposals — so nothing with a real secret leaves the browser.
//
// Coverage (defense in depth, because storage cross-reference alone misses
// secrets minted this session or carried in bodies / non-standard headers):
//   1. Known values gathered from the user's own cookies/storage (exact match).
//   2. Any request header whose NAME looks credential-bearing.
//   3. Body fields whose KEY looks credential-bearing (e.g. access_token).
//   4. JWT-shaped strings anywhere in a body.
// Bias is conservative-for-privacy: over-mask rather than leak.

import type {
  HttpMethod,
  InjectionLocation,
  Observation,
  RequestContext,
  ResolverHint,
  SecretKind,
  SecretRole,
  SecretSlot,
} from "@sudobility/sider_types";

export interface RawObservation {
  method: HttpMethod;
  url: string;
  requestHeaders: Record<string, string>;
  requestBody?: unknown;
  status: number;
  responseBody?: unknown;
  timingMs: number;
  context: RequestContext;
}

/** A secret value the browser found in THIS user's session (value stays local). */
export interface KnownSecret {
  value: string;
  slotId: string; // stable placeholder, e.g. "slot:example.com:auth_bearer"
  kind: SecretKind;
  role: SecretRole;
  resolverHint: ResolverHint;
}

export type SecretSlotProposal = Omit<SecretSlot, "siteId" | "createdAt" | "updatedAt">;
export type TokenizedObservation = Omit<Observation, "id" | "batchId" | "createdAt">;

export interface TokenizeResult {
  observation: TokenizedObservation;
  slots: SecretSlotProposal[];
}

export function samplePlaceholder(slotId: string): string {
  return `{{secret:${slotId}}}`;
}

// Header NAME looks credential-bearing (conservative-for-privacy: any "key",
// "token", "auth", "secret", "session", etc. in the name).
const SECRET_HEADER_RE = /authorization|cookie|token|key|secret|session|auth|xsrf|csrf|bearer/i;
// Body property KEY looks credential-bearing.
const SECRET_KEY_RE =
  /(^|[_-])(access_token|refresh_token|id_token|token|api[-_]?key|apikey|client_secret|secret|password|passwd|session_?(id|token)|jwt|bearer|credential|auth_?token)($|[_-])/i;
// JWT-shaped string.
const JWT_RE = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}/g;
const MIN_MASK_LEN = 6;

export function tokenizeObservation(raw: RawObservation, known: KnownSecret[]): TokenizeResult {
  const origin = originOf(raw.url);
  const host = hostOf(origin);
  const slots = new Map<string, SecretSlotProposal>();

  let url = raw.url;
  const headers: Record<string, string> = { ...raw.requestHeaders };
  let requestBody = raw.requestBody;
  let responseBody = raw.responseBody;

  const ensure = (slotId: string, kind: SecretKind, role: SecretRole, loc: InjectionLocation, hint?: ResolverHint) => {
    if (slots.has(slotId)) return;
    slots.set(slotId, {
      id: slotId,
      kind,
      role,
      injectionLocation: loc,
      allowedDestination: origin,
      resolverHints: hint ? [hint] : [],
      confidence: 0.6,
    });
  };

  // 1. Known values (exact substring match everywhere).
  for (const s of known) {
    if (!s.value) continue;
    const loc = locate(raw, s.value) ?? { at: "header" as const, name: "authorization" };
    const ph = samplePlaceholder(s.slotId);
    url = url.split(s.value).join(ph);
    for (const k of Object.keys(headers)) headers[k] = headers[k]!.split(s.value).join(ph);
    requestBody = replaceInJson(requestBody, s.value, ph);
    responseBody = replaceInJson(responseBody, s.value, ph);
    ensure(s.slotId, s.kind, s.role, loc, s.resolverHint);
  }

  // 2. Credential-bearing headers (by name), even when the value wasn't in storage.
  for (const name of Object.keys(headers)) {
    const val = headers[name];
    if (typeof val !== "string" || !val || val.startsWith("{{secret:")) continue;
    if (!SECRET_HEADER_RE.test(name)) continue;
    const lname = name.toLowerCase();
    const slotId = `slot:${host}:${normalize(name)}`;
    headers[name] = samplePlaceholder(slotId);
    ensure(
      slotId,
      guessKind(name),
      lname === "cookie" ? "auto_cookie" : "active_inject",
      lname === "cookie" ? { at: "cookie", name } : { at: "header", name },
    );
  }

  // 3 + 4. Body fields by key + JWTs anywhere.
  requestBody = maskBody(requestBody, host, origin, slots, ensure, "");
  responseBody = maskBody(responseBody, host, origin, slots, ensure, "");

  return {
    observation: {
      method: raw.method,
      url,
      requestHeaders: headers,
      requestBody,
      status: raw.status,
      responseBody,
      timingMs: raw.timingMs,
      context: raw.context,
    },
    slots: [...slots.values()],
  };
}

type Ensure = (
  slotId: string,
  kind: SecretKind,
  role: SecretRole,
  loc: InjectionLocation,
  hint?: ResolverHint,
) => void;

function maskBody(node: unknown, host: string, origin: string, slots: Map<string, SecretSlotProposal>, ensure: Ensure, path: string, key?: string): unknown {
  if (node === undefined || node === null) return node;
  if (typeof node === "string") {
    if (key && node.length >= MIN_MASK_LEN && SECRET_KEY_RE.test(key)) {
      const slotId = `slot:${host}:${normalize(key)}`;
      ensure(slotId, guessKind(key), "active_inject", { at: "body", jsonPath: path });
      return samplePlaceholder(slotId);
    }
    if (JWT_RE.test(node)) {
      JWT_RE.lastIndex = 0;
      const slotId = `slot:${host}:jwt`;
      ensure(slotId, "bearer", "active_inject", { at: "body", jsonPath: path });
      return node.replace(JWT_RE, samplePlaceholder(slotId));
    }
    return node;
  }
  if (Array.isArray(node)) return node.map((n, i) => maskBody(n, host, origin, slots, ensure, `${path}[${i}]`, key));
  if (typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) out[k] = maskBody(v, host, origin, slots, ensure, path ? `${path}.${k}` : k, k);
    return out;
  }
  return node;
}

// --- helpers ---------------------------------------------------------------

function guessKind(name: string): SecretKind {
  const n = name.toLowerCase();
  if (n.includes("csrf") || n.includes("xsrf")) return "csrf";
  if (n.includes("cookie") || n.includes("session")) return "session";
  if (n.includes("auth") || n.includes("bearer") || n.includes("token") || n.includes("jwt")) return "bearer";
  if (n.includes("api") && n.includes("key")) return "api_key";
  return "unknown";
}

function locate(raw: RawObservation, value: string): InjectionLocation | null {
  for (const [name, v] of Object.entries(raw.requestHeaders)) {
    if (typeof v === "string" && v.includes(value)) return { at: "header", name };
  }
  try {
    const u = new URL(raw.url, "http://sider.local");
    for (const [param, v] of u.searchParams) if (v.includes(value)) return { at: "query", param };
  } catch {
    /* ignore */
  }
  const bodyPath = findInJson(raw.requestBody, value);
  if (bodyPath) return { at: "body", jsonPath: bodyPath };
  return null;
}

function findInJson(node: unknown, value: string, prefix = ""): string | null {
  if (typeof node === "string") return node.includes(value) ? prefix.replace(/^\./, "") : null;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const p = findInJson(node[i], value, `${prefix}[${i}]`);
      if (p) return p;
    }
    return null;
  }
  if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      const p = findInJson(v, value, `${prefix}.${k}`);
      if (p) return p;
    }
  }
  return null;
}

function replaceInJson(node: unknown, value: string, ph: string): unknown {
  if (node === undefined) return node;
  if (typeof node === "string") return node.split(value).join(ph);
  if (Array.isArray(node)) return node.map((n) => replaceInJson(n, value, ph));
  if (node && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) out[k] = replaceInJson(v, value, ph);
    return out;
  }
  return node;
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
function hostOf(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}
function normalize(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "_");
}
