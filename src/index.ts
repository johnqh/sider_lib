// @sudobility/sider_lib — pure Sider business logic.
//
//   templating  — cluster raw observations into endpoint templates
//   tokenize    — replace known secret values with placeholders (browser-side)
//   recipe      — compile a ToolSpec + args into a CompiledRequest (secrets = sentinels)
//   gates       — the three egress gates (same-origin / injection-location / safety)
//   execute     — detokenize after gates pass; prepareRequest = compile→gate→detokenize
//
// No Chrome/DOM/server dependencies — safe to import from sider_api,
// sider_extension, and sider_app alike.

// Clustering/templating + recipe hashing moved to sider_types (shared with the
// backend); re-exported here so sider_lib's public API stays stable.
export {
  templatePath,
  graphqlOperationOf,
  endpointKey,
  clusterObservations,
  hashRecipe,
  canonicalizeRecipe,
} from "@sudobility/sider_types";
export * from "./tokenize";
export * from "./recipe";
export * from "./gates";
export * from "./execute";
export * from "./composite";
