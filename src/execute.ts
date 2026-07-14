// Detokenization (the last mile, browser-side) + the single prepareRequest
// entry point. Detokenization runs ONLY after the gates pass; it reads each
// secret's current value from the caller's resolver (backed by the browser
// TokenMap) and substitutes it into the sentinel positions the gates already
// proved are confined to the declared location.

import type { CompiledRequest, SecretSlot } from "@sudobility/sider_types";
import { compileRecipe, secretSentinel } from "./recipe";
import { evaluateGates } from "./gates";
import type { ToolSpec } from "@sudobility/sider_types";
import type { CompileContext } from "./recipe";
import type { GateContext } from "./gates";

export interface ResolvedRequest {
  method: CompiledRequest["method"];
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  credentials: "include";
}

/** Resolve a slot's current value from the caller's live session (never stored). */
export type SecretResolver = (slotId: string) => string | undefined;

export function detokenizeRequest(
  req: CompiledRequest,
  resolve: SecretResolver,
  slotsById: Record<string, SecretSlot>,
): ResolvedRequest {
  let url = req.url;
  const headers: Record<string, string> = { ...req.headers };
  let bodyStr = req.body !== undefined ? JSON.stringify(req.body) : undefined;

  for (const slotId of req.referencedSlotIds) {
    const slot = slotsById[slotId];
    // auto_cookie secrets are attached by the browser; never substituted.
    if (slot && (slot.role === "auto_cookie" || slot.injectionLocation.at === "cookie")) continue;

    const value = resolve(slotId);
    if (value === undefined) throw new Error(`Unresolved secret slot at egress: ${slotId}`);

    const sen = secretSentinel(slotId);
    url = url.split(sen).join(value);
    for (const k of Object.keys(headers)) headers[k] = headers[k]!.split(sen).join(value);
    if (bodyStr !== undefined) {
      const innerEscaped = JSON.stringify(value).slice(1, -1); // JSON-string-safe
      bodyStr = bodyStr.split(sen).join(innerEscaped);
    }
  }

  return {
    method: req.method,
    url,
    headers,
    body: bodyStr !== undefined ? JSON.parse(bodyStr) : undefined,
    credentials: "include",
  };
}

export type PrepareResult =
  | { ok: true; request: ResolvedRequest }
  | { ok: false; gate: "compile" | "same_origin" | "injection_location" | "safety"; reason: string };

/**
 * compile → gate → detokenize, in one call. The browser executor should issue
 * `result.request` only when `result.ok`.
 */
export function prepareRequest(
  tool: ToolSpec,
  compileCtx: CompileContext,
  gateCtx: GateContext,
  resolve: SecretResolver,
): PrepareResult {
  let compiled: CompiledRequest;
  try {
    compiled = compileRecipe(tool, compileCtx);
  } catch (e) {
    return { ok: false, gate: "compile", reason: (e as Error).message };
  }

  const gate = evaluateGates(compiled, gateCtx);
  if (!gate.ok) return gate;

  try {
    return { ok: true, request: detokenizeRequest(compiled, resolve, gateCtx.slotsById) };
  } catch (e) {
    return { ok: false, gate: "injection_location", reason: (e as Error).message };
  }
}
