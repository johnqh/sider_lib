// The three egress gates. This is the security core: tokenization is only safe
// BECAUSE a secret cannot leave for the wrong destination (Gate A), cannot be
// relocated out of its declared slot (Gate B), and cannot ride a mutation
// without confirmation (Gate C). Run on a CompiledRequest whose secrets are
// still sentinels — never on values.

import type { CompiledRequest, GateOutcome, SecretSlot } from "@sudobility/sider_types";
import { getByPath, secretSentinel } from "./recipe";

export interface GateContext {
  /** The site's origin. The request destination MUST equal this. */
  siteOrigin: string;
  /** Every secret slot the request may reference, keyed by slot id (placeholder). */
  slotsById: Record<string, SecretSlot>;
  /** True once the user has confirmed a write/financial step. */
  confirmed?: boolean;
  /** Site policy: whether mutations are permitted here at all. */
  allowMutations?: boolean;
}

export function evaluateGates(req: CompiledRequest, ctx: GateContext): GateOutcome {
  // --- Gate A: same-origin destination ------------------------------------
  let originHost: string;
  try {
    originHost = new URL(req.url).origin;
  } catch {
    return { ok: false, gate: "same_origin", reason: `invalid url: ${req.url}` };
  }
  if (originHost !== ctx.siteOrigin) {
    return {
      ok: false,
      gate: "same_origin",
      reason: `destination ${originHost} != site ${ctx.siteOrigin}`,
    };
  }

  for (const slotId of req.referencedSlotIds) {
    const slot = ctx.slotsById[slotId];
    if (!slot) {
      return { ok: false, gate: "injection_location", reason: `unknown secret slot ${slotId}` };
    }
    if (slot.allowedDestination !== originHost) {
      return {
        ok: false,
        gate: "same_origin",
        reason: `slot ${slotId} allows ${slot.allowedDestination}, not ${originHost}`,
      };
    }
    if (slot.role === "auto_cookie" || slot.injectionLocation.at === "cookie") {
      return {
        ok: false,
        gate: "injection_location",
        reason: `slot ${slotId} is cookie-borne (auto-attached); it must not be injected`,
      };
    }

    // --- Gate B: sentinel appears ONLY in its declared location ------------
    const b = injectionCheck(req, slot);
    if (!b.ok) return b;
  }

  // --- Gate C: mutations require confirmation -----------------------------
  // Bind to the HTTP method, not just the server-declared (and therefore
  // untrusted) safetyClass — a recipe labeled "read" with a POST/PUT/PATCH/
  // DELETE still mutates and must not run unconfirmed.
  const idempotent = req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS";
  if (req.safetyClass !== "read" || !idempotent) {
    if (ctx.allowMutations === false) {
      return { ok: false, gate: "safety", reason: `mutations disabled for ${ctx.siteOrigin}` };
    }
    if (!ctx.confirmed) {
      return { ok: false, gate: "safety", reason: `mutating request requires confirmation` };
    }
  }

  return { ok: true };
}

function injectionCheck(req: CompiledRequest, slot: SecretSlot): GateOutcome {
  const sen = secretSentinel(slot.id);
  const bodyStr = req.body !== undefined ? JSON.stringify(req.body) : "";

  const total =
    count(req.url, sen) +
    Object.values(req.headers).reduce((n, v) => n + count(v, sen), 0) +
    count(bodyStr, sen);

  let allowed = 0;
  const loc = slot.injectionLocation;
  if (loc.at === "header") {
    allowed = count(req.headers[loc.name] ?? "", sen);
  } else if (loc.at === "query") {
    let qv = "";
    try {
      qv = new URL(req.url).searchParams.get(loc.param) ?? "";
    } catch {
      /* invalid url already caught in Gate A */
    }
    allowed = count(qv, sen);
  } else if (loc.at === "body") {
    allowed = count(String(getByPath(req.body, loc.jsonPath) ?? ""), sen);
  }

  if (allowed < 1) {
    return {
      ok: false,
      gate: "injection_location",
      reason: `slot ${slot.id} absent from its declared ${loc.at} location`,
    };
  }
  if (total !== allowed) {
    return {
      ok: false,
      gate: "injection_location",
      reason: `slot ${slot.id} appears outside its declared ${loc.at} location`,
    };
  }
  return { ok: true };
}

function count(hay: string, needle: string): number {
  if (!needle) return 0;
  return hay.split(needle).length - 1;
}
