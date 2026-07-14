// Recipe compiler: ToolSpec + args → CompiledRequest (secrets still placeholders).
//
// Secrets are compiled to an internal SENTINEL (a Private-Use-Area delimited
// token that cannot occur in real data), NOT to their values. The sentinel
// survives through the egress gates and is only replaced with a real value at
// detokenization (see execute.ts), after all three gates pass.

import type {
  CompiledRequest,
  InvocationRecipe,
  ParamBinding,
  ToolSpec,
} from "@sudobility/sider_types";

const S = ""; // sentinel delimiter (PUA)

export function secretSentinel(slotId: string): string {
  return `${S}${slotId}${S}`;
}

export class RecipeCompileError extends Error {}

export interface CompileContext {
  /** Origin the recipe runs against (path templates are relative to it). */
  siteOrigin: string;
  /** User/LLM-supplied tool arguments. */
  args?: Record<string, unknown>;
  /** Prior tool results this run, keyed by ComposeStep.ref (for priorOutput bindings). */
  priorOutputs?: Record<string, unknown>;
}

export function compileRecipe(tool: ToolSpec, ctx: CompileContext): CompiledRequest {
  const recipe = tool.recipe;
  const referenced = new Set<string>();

  const resolveKey = (key: string): string => {
    const b = recipe.bindings[key];
    if (!b) throw new RecipeCompileError(`Unbound placeholder {${key}} in tool "${tool.name}"`);
    return resolveBinding(key, b, ctx, referenced);
  };

  const path = fillTemplate(recipe.urlTemplate, resolveKey);
  const url = joinOrigin(ctx.siteOrigin, path);

  const headers: Record<string, string> = {};
  for (const h of recipe.headers) headers[h.name] = fillTemplate(h.valueTemplate, resolveKey);

  const body =
    recipe.bodyTemplate !== undefined ? resolveDeep(recipe.bodyTemplate, resolveKey) : undefined;

  return {
    method: recipe.method,
    url,
    headers,
    body,
    credentials: "include",
    referencedSlotIds: [...referenced],
    safetyClass: tool.safetyClass,
  };
}

function resolveBinding(
  key: string,
  b: ParamBinding,
  ctx: CompileContext,
  referenced: Set<string>,
): string {
  switch (b.kind) {
    case "literal":
      return b.value;
    case "arg": {
      const v = ctx.args?.[b.argName];
      if (v === undefined) throw new RecipeCompileError(`Missing arg "${b.argName}" for {${key}}`);
      return String(v);
    }
    case "secret":
      referenced.add(b.slotId);
      return secretSentinel(b.slotId);
    case "priorOutput": {
      const v = getByPath(ctx.priorOutputs?.[b.stepRef], b.jsonPath);
      if (v === undefined) {
        throw new RecipeCompileError(`priorOutput ${b.stepRef}.${b.jsonPath} unresolved for {${key}}`);
      }
      return String(v);
    }
  }
}

function fillTemplate(tmpl: string, resolve: (key: string) => string): string {
  return tmpl.replace(/\{([^{}]+)\}/g, (_m, key: string) => resolve(key));
}

function resolveDeep(node: unknown, resolve: (key: string) => string): unknown {
  if (typeof node === "string") return fillTemplate(node, resolve);
  if (Array.isArray(node)) return node.map((n) => resolveDeep(n, resolve));
  if (node && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) out[k] = resolveDeep(v, resolve);
    return out;
  }
  return node;
}

function joinOrigin(origin: string, path: string): string {
  if (/^https?:\/\//i.test(path)) return path; // absolute (still same-origin-gated)
  return `${origin.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

/** Read a dotted/bracketed path from an object: "data.sections[0].id". */
export function getByPath(obj: unknown, path: string): unknown {
  const parts = path
    .replace(/\[(\d+)\]/g, ".$1")
    .split(".")
    .filter(Boolean);
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

// --- Recipe canonicalization for corroboration hashing --------------------

/** Stable stringify (sorted keys) so two users' equivalent recipes hash equal. */
export function canonicalizeRecipe(recipe: InvocationRecipe): string {
  return stableStringify(recipe);
}

export function hashRecipe(recipe: InvocationRecipe): string {
  const s = canonicalizeRecipe(recipe);
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16);
}

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}
