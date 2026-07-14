// Deterministic clustering & path templating. Runs BEFORE any AI: groups raw
// observations into endpoint templates so the brain infers semantics once per
// endpoint, not once per request. (This is the logic distill.ts inlined.)

import type { Observation } from "@sudobility/sider_types";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONGHEX_RE = /^[0-9a-f]{16,}$/i;

/** Replace id-like path segments with `{id}`: /sections/120/seats → /sections/{id}/seats */
export function templatePath(rawUrl: string): string {
  let pathname = rawUrl;
  try {
    pathname = new URL(rawUrl, "http://sider.local").pathname;
  } catch {
    /* keep raw */
  }
  return pathname
    .split("/")
    .map((seg) => {
      if (seg === "") return seg;
      if (/^\d+$/.test(seg)) return "{id}";
      if (UUID_RE.test(seg)) return "{id}";
      if (LONGHEX_RE.test(seg)) return "{id}";
      return seg;
    })
    .join("/");
}

/**
 * GraphQL keying: one URL serves many operations, so cluster on operation name,
 * not path. Returns undefined for non-GraphQL requests.
 */
export function graphqlOperationOf(url: string, body: unknown): string | undefined {
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    if (typeof b["operationName"] === "string" && b["operationName"]) {
      return b["operationName"];
    }
    if (typeof b["query"] === "string") {
      const m = /\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)/.exec(b["query"]);
      if (m && m[2]) return m[2];
    }
  }
  if (/\/graphql\b/i.test(url)) return "anonymous";
  return undefined;
}

type Clusterable = Pick<Observation, "method" | "url" | "requestBody">;

/** Stable key identifying the endpoint template an observation belongs to. */
export function endpointKey(o: Clusterable): string {
  const op = graphqlOperationOf(o.url, o.requestBody);
  return `${o.method} ${templatePath(o.url)}${op ? ` #${op}` : ""}`;
}

export function clusterObservations<T extends Clusterable>(
  observations: T[],
): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const o of observations) {
    const key = endpointKey(o);
    const g = groups.get(key);
    if (g) g.push(o);
    else groups.set(key, [o]);
  }
  return groups;
}
