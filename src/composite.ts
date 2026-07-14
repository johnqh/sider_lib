// Composite/fan-out tool execution. A ToolSpec whose recipe has `compose` steps
// chains or fans out over other tools — e.g. "list sections → for each, fetch
// seats". This is PURE orchestration: the caller injects `run` (which applies
// the three gates + issues the actual request for one tool), and this threads
// prior outputs, resolves bindings, and parallelizes fan-out.

import type { ComposeStep, ParamBinding, ToolSpec } from "@sudobility/sider_types";
import { getByPath } from "./recipe";

export interface RunStepResult {
  ok: boolean;
  status?: number;
  body?: unknown;
  error?: string;
  gate?: string;
}

/** Runs ONE tool by id with resolved args. The caller applies gates + fetch. */
export type StepRunner = (toolId: string, args: Record<string, unknown>) => Promise<RunStepResult>;

/** Reference, in a priorOutput binding, to the current element during a fan-out. */
const ITEM_REF = "$item";

export async function executeComposite(
  tool: ToolSpec,
  ctx: { args?: Record<string, unknown> },
  run: StepRunner,
): Promise<RunStepResult> {
  const steps = tool.recipe.compose ?? [];
  if (steps.length === 0) return run(tool.id, ctx.args ?? {});

  const priorOutputs: Record<string, unknown> = {};
  let last: RunStepResult | undefined;

  for (const step of steps) {
    if (step.forEachJsonPath) {
      // Fan out: run the step once per element of the referenced array (parallel).
      const arr = getByPath(priorOutputs, step.forEachJsonPath);
      const items = Array.isArray(arr) ? arr : [];
      const results = await Promise.all(
        items.map((item) => run(step.toolId, resolveArgs(step.argBindings, ctx, priorOutputs, item))),
      );
      priorOutputs[step.ref] = results.map((r) => r.body);
      last = { ok: results.every((r) => r.ok), body: results.map((r) => r.body) };
      if (!last.ok) break; // don't thread a failed fan-out into later steps
    } else {
      const r = await run(step.toolId, resolveArgs(step.argBindings, ctx, priorOutputs, undefined));
      priorOutputs[step.ref] = r.body;
      last = r;
      if (!r.ok) break; // stop the chain on the first failure
    }
  }

  return last ?? { ok: false, error: "empty compose" };
}

function resolveArgs(
  bindings: Record<string, ParamBinding>,
  ctx: { args?: Record<string, unknown> },
  priorOutputs: Record<string, unknown>,
  item: unknown,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, b] of Object.entries(bindings)) {
    switch (b.kind) {
      case "literal":
        out[key] = b.value;
        break;
      case "arg":
        out[key] = ctx.args?.[b.argName];
        break;
      case "priorOutput":
        out[key] =
          b.stepRef === ITEM_REF ? getByPath(item, b.jsonPath) : getByPath(priorOutputs[b.stepRef], b.jsonPath);
        break;
      case "secret":
        // Secrets belong to the sub-tool's own recipe (resolved at egress by
        // the runner), never to compose-level args.
        break;
    }
  }
  return out;
}

// keep the fan-out sentinel discoverable to callers/authors of recipes.
export { ITEM_REF };
